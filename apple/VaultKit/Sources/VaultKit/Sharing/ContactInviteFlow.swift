import Foundation

/// The remote contact invitation (sharing spec 5.3.2, 13.9): asynchronous over 72 hours through the
/// drops of the server the link names. The inviter makes a link and shares it (system share sheet);
/// the invitee opens it, writes its sealed reply and waits; the inviter makes the pair's mailbox
/// (decision 16), writes its answer; both end with a contact at `Link` (Read only, decision 1) and
/// the app offers "Comparer le numéro de sécurité" to reach `Verified`.
///
/// A link opened while the app is locked waits in the Keychain until the unlock; the invitee's
/// pending secret waits there too, for an answer that lands after a restart.
@MainActor
public final class ContactInviteFlow: ObservableObject {
    public enum State: Equatable, Sendable {
        case idle
        /// Share `link` (expires at `expiresAt`); the reply is awaited.
        case sharing(link: String, expiresAt: Date)
        /// A link waits for the unlock.
        case waitingForUnlock
        /// Reply written, the inviter's answer is awaited.
        case waitingForAnswer
        /// The contact, at `Link`: offer the safety number comparison.
        case done(FfiContact)
        case failed(String)
    }

    @Published public private(set) var state: State = .idle

    static let linkKey = "contact.invite.link"
    static func pendingKey(_ rdv: Data) -> String {
        "contact.invite.pending.\(rdv.map { String(format: "%02x", $0) }.joined())"
    }

    private var session: Session?
    private let myName: String
    private let keychain: any KeychainStore
    private let drops: any InviteDrops
    private let creator: any ContactZoneCreating
    private let hosted: URL
    private let pollInterval: Duration
    private let sleep: @Sendable (Duration) async throws -> Void
    private let now: @Sendable () -> Date
    private var task: Task<Void, Never>?

    public init(
        session: Session?, myName: String, keychain: any KeychainStore, drops: any InviteDrops,
        creator: any ContactZoneCreating, hosted: URL, pollInterval: Duration = .seconds(10),
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.session = session
        self.myName = myName
        self.keychain = keychain
        self.drops = drops
        self.creator = creator
        self.hosted = hosted
        self.pollInterval = pollInterval
        self.sleep = sleep
        self.now = now
    }

    private var stamp: Int64 { Int64(now().timeIntervalSince1970) }

    // MARK: - Inviter

    /// A new invitation on `server` (the Soma instance by default); waits for the reply.
    public func createInvite(server: URL? = nil) {
        guard let session else { return state = .waitingForUnlock }
        let server = server ?? hosted
        let host = InviteServer.linkHost(for: server, hosted: hosted)
        task?.cancel()
        task = Task {
            do {
                let t = stamp
                let invite = try await CoreThread.run { try session.createContactInvite(host: host, now: t) }
                state = .sharing(link: invite.link, expiresAt: Date(timeIntervalSince1970: TimeInterval(invite.expiresAt)))
                let reply = try await poll(rdv: invite.rdvId, part: .reply, server: server, until: invite.expiresAt)
                let t2 = stamp
                let card = try await CoreThread.run {
                    try session.inviteReplyCard(inviteId: invite.inviteId, reply: reply, now: t2)
                }
                let offer = try await creator.offer(for: card, session: session)
                let name = myName
                let answer = try await CoreThread.run {
                    try session.acceptInviteReply(inviteId: invite.inviteId, reply: reply, myName: name, zoneOffer: offer, now: t2)
                }
                try await drops.put(rdv: invite.rdvId, part: .answer, bytes: answer.answer, server: server)
                try? await drops.delete(rdv: invite.rdvId, part: .reply, server: server)
                state = .done(answer.contact)
            } catch {
                fail(error)
            }
        }
    }

    // MARK: - Invitee

    /// A link was opened (`onepass://contact/...`). Locked: kept in the Keychain for the unlock.
    public func open(link: String) {
        guard let session else {
            try? keychain.write(Self.linkKey, Data(link.utf8))
            state = .waitingForUnlock
            return
        }
        task?.cancel()
        task = Task { await self.reply(link: link, session: session) }
    }

    /// The app unlocked: a link kept while locked is opened now.
    public func unlocked(_ session: Session) {
        self.session = session
        guard let data = try? keychain.read(Self.linkKey), let link = String(data: data, encoding: .utf8) else { return }
        try? keychain.delete(Self.linkKey)
        open(link: link)
    }

    private func reply(link: String, session: Session) async {
        let server = InviteServer.url(forLink: link, hosted: hosted)
        do {
            let (name, t) = (myName, stamp)
            let reply = try await CoreThread.run { try session.contactInviteReply(link: link, myName: name, now: t) }
            try keychain.write(Self.pendingKey(reply.rdvId), reply.pending.toBytes())
            try await drops.put(rdv: reply.rdvId, part: .reply, bytes: reply.bytes, server: server)
            state = .waitingForAnswer
            try await awaitAnswer(pending: reply.pending, server: server, session: session)
        } catch {
            fail(error)
        }
    }

    /// After a restart: the pending reply kept in the Keychain for `rdv`, awaited again.
    public func resume(rdv: Data, server: URL) {
        guard let session,
              let bytes = try? keychain.read(Self.pendingKey(rdv)),
              let pending = try? pendingInviteFromBytes(bytes: bytes)
        else { return }
        state = .waitingForAnswer
        task?.cancel()
        task = Task {
            do {
                try await awaitAnswer(pending: pending, server: server, session: session)
            } catch {
                fail(error)
            }
        }
    }

    private func awaitAnswer(pending: FfiPendingInvite, server: URL, session: Session) async throws {
        let rdv = pending.rdvId()
        let answer = try await poll(rdv: rdv, part: .answer, server: server, until: stamp + 72 * 3600)
        let t = stamp
        let contact = try await CoreThread.run { try session.finishInvite(pending: pending, answer: answer, now: t) }
        try? keychain.delete(Self.pendingKey(rdv))
        try? await drops.delete(rdv: rdv, part: .answer, server: server)
        state = .done(contact)
    }

    // MARK: - Shared

    private func poll(rdv: Data, part: FfiInvitePart, server: URL, until expiresAt: Int64) async throws -> Data {
        while true {
            try Task.checkCancellation()
            if let bytes = try? await drops.get(rdv: rdv, part: part, server: server) { return bytes }
            if stamp >= expiresAt { throw ContactInviteError.expired }
            try await sleep(pollInterval)
        }
    }

    public func cancel() {
        task?.cancel()
        task = nil
        state = .idle
    }

    private func fail(_ error: any Error) {
        if error is CancellationError { return }
        switch error {
        case ContactInviteError.expired:
            state = .failed(String(localized: "sharing.invite.expired", bundle: VaultKitStrings.bundle))
        case ContactZoneError.offline:
            state = .failed(String(localized: "sharing.invite.offline", bundle: VaultKitStrings.bundle))
        default:
            state = .failed(VaultError(error).localizedMessage)
        }
    }
}

public enum ContactInviteError: Error, Equatable, Sendable {
    case expired
}
