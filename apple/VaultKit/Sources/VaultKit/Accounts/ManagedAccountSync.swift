import Foundation
import os

/// The sync of a managed account (OnePass Business): its own account mailbox on the organisation's
/// server. The mailbox exists only once the managed setup ran, so the coordinator arrives later
/// (`attach`); until then writes stay on this device and an erase is refused as offline, as
/// `AccountSync` does before its coordinator exists.
public actor ManagedAccountSync: SyncTrigger {
    /// The mailbox coordinator, once attached.
    public private(set) var current: MailboxSyncCoordinator?
    /// What calls are forwarded to (the coordinator; tests attach a recorder).
    private var target: (any SyncTrigger)?
    /// The last unlocked session, replayed to a coordinator attached later (it syncs only unlocked).
    private var unlocked: Session?

    public init() {}

    public nonisolated var syncsWithServer: Bool { true }

    /// Takes `coordinator` as this account's sync: hands it the unlocked session, if any, and starts a
    /// round. A second attach replaces the first.
    public func attach(_ coordinator: MailboxSyncCoordinator) async {
        current = coordinator
        await attach(trigger: coordinator)
        await coordinator.enterForeground()
    }

    /// `attach` without the coordinator's own calls (tests).
    func attach(trigger: any SyncTrigger) async {
        target = trigger
        if let unlocked { await trigger.sessionUnlocked(unlocked) }
        await trigger.syncNow()
    }

    public func localChangesWritten() async {
        await target?.localChangesWritten()
    }

    public func sessionUnlocked(_ session: Session) async {
        unlocked = session
        await target?.sessionUnlocked(session)
    }

    public func sessionLocked() async {
        unlocked = nil
        await target?.sessionLocked()
    }

    public func resetStore(with reset: @escaping @Sendable () throws -> Void) async throws {
        if let target {
            try await target.resetStore(with: reset)
        } else {
            try await CoreThread.run(reset)
        }
    }

    /// No mailbox yet: the server copy cannot be reached, so nothing is erased.
    public func eraseAccount(with reset: @escaping @Sendable () throws -> Void) async throws {
        guard let target else { throw VaultError.other(SyncTriggerMessages.offline) }
        try await target.eraseAccount(with: reset)
    }

    public func safeExitIssued(_ exit: SafeExit) async {
        await target?.safeExitIssued(exit)
    }

    public func syncNow() async {
        await target?.syncNow()
    }
}

/// The keychain items of a managed slot besides its device keys (R33):
/// - `org.link.<slot>`: the join link's credential seed, while the member is not accepted yet;
/// - `org.memberToken.<slot>`: the one-use `managed` token of the account mailbox, until that mailbox
///   exists (a setup cut off resumes with it);
/// - the member's own org mailbox credential seed (`FfiJoinPosted.credentialSeed`, or the creator's
///   `FfiOrgCreated.credentialSeed`), in `MailboxCredentialStore` under the org mailbox id.
/// Seeds come back as `SecretBytes` for the caller to wipe.
public struct ManagedOrgCredentials: Sendable {
    public static func linkKey(slot: String) -> String { "org.link.\(slot)" }
    public static func tokenKey(slot: String) -> String { "org.memberToken.\(slot)" }

    private let keychain: any KeychainStore
    private let slot: String

    public init(keychain: any KeychainStore, slot: String) {
        self.keychain = keychain
        self.slot = slot
    }

    public func linkSeed() throws -> SecretBytes? { try read(Self.linkKey(slot: slot)) }
    public func storeLinkSeed(_ seed: SecretBytes) throws { try write(seed, Self.linkKey(slot: slot)) }
    public func deleteLinkSeed() throws { try keychain.delete(Self.linkKey(slot: slot)) }

    public func memberToken() throws -> SecretBytes? { try read(Self.tokenKey(slot: slot)) }
    public func storeMemberToken(_ token: SecretBytes) throws { try write(token, Self.tokenKey(slot: slot)) }
    public func deleteMemberToken() throws { try keychain.delete(Self.tokenKey(slot: slot)) }

    public func ownSeed(orgMailboxID: String) throws -> SecretBytes? {
        try MailboxCredentialStore(keychain: keychain).seed(mailboxID: orgMailboxID)
    }

    public func storeOwnSeed(_ seed: SecretBytes, orgMailboxID: String) throws {
        try MailboxCredentialStore(keychain: keychain).store(seed: seed, mailboxID: orgMailboxID)
    }

    /// Every item of the slot (the account leaves this device). Quiet: a missing item is fine.
    public func deleteAll(orgMailboxID: String?) {
        try? deleteLinkSeed()
        try? deleteMemberToken()
        if let orgMailboxID { try? MailboxCredentialStore(keychain: keychain).delete(mailboxID: orgMailboxID) }
    }

    private func read(_ key: String) throws -> SecretBytes? {
        guard var data = try keychain.read(key) else { return nil }
        return SecretBytes(taking: &data)
    }

    private func write(_ value: SecretBytes, _ key: String) throws {
        try value.withData { try keychain.write(key, $0) }
    }
}

/// The org client of a managed account, opened with the right credential (R27, R33): the member's
/// own once it works (after acceptance), else the join link's. While on the link's, each `refresh`
/// first tries the member's own; on success the link's credential is revoked (best effort) and its
/// seed deleted. The creator (no link seed) always uses its own.
public actor ManagedOrgBackend: OrgBackend {
    /// An org client holding the credential of `seed` (the app: `OrgClient.open`; tests: the
    /// in-process server).
    public typealias Open = @Sendable (_ seed: Data) throws -> OrgClient

    private let credentials: ManagedOrgCredentials
    private let orgMailboxID: String
    private let open: Open
    private var current: FfiOrgBackend?
    private var onLink = false

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "org")

    public init(credentials: ManagedOrgCredentials, orgMailboxID: String, open: @escaping Open) {
        self.credentials = credentials
        self.orgMailboxID = orgMailboxID
        self.open = open
    }

    /// The client uses the member's own credential (false before the first call or while on the link's).
    public var usesOwnCredential: Bool { current != nil && !onLink }

    private func make(_ seed: SecretBytes) throws -> FfiOrgBackend {
        defer { seed.wipe() }
        return FfiOrgBackend(client: try seed.withData { try open($0) })
    }

    private func client() throws -> FfiOrgBackend {
        if let current { return current }
        let link = try credentials.linkSeed()
        if let link {
            current = try make(link)
            onLink = true
        } else if let own = try credentials.ownSeed(orgMailboxID: orgMailboxID) {
            current = try make(own)
            onLink = false
        } else {
            throw OnePassError.NotFound
        }
        return current!
    }

    /// While on the link's credential: the member's own, if the server takes it now.
    private func switchToOwn() async -> FfiOrgState? {
        guard onLink, let own = try? credentials.ownSeed(orgMailboxID: orgMailboxID),
            let candidate = try? make(own), let state = try? await candidate.refresh()
        else { return nil }
        do {
            try await current?.revokeOwnCredential()
        } catch {
            // The inviting device revokes it on accept too (R29): usually gone already.
            Self.log.info("link credential not revoked here")
        }
        try? credentials.deleteLinkSeed()
        current = candidate
        onLink = false
        return state
    }

    public func state() async throws -> FfiOrgState? { try await client().state() }

    public func pin(source: FfiPinSource, expected: Data?, now: Int64) async throws -> FfiOrgState {
        try await client().pin(source: source, expected: expected, now: now)
    }

    public func refresh() async throws -> FfiOrgState {
        let opened = try client()
        if let state = await switchToOwn() { return state }
        return try await (current ?? opened).refresh()
    }

    public func markVerified() async throws -> FfiOrgState { try await client().markVerified() }

    public func joinRequests() async throws -> [FfiJoinRequest] { try await client().joinRequests() }

    public func postJoinRequest(
        session: Session, keys: DeviceKeyPair, invite: FfiOrgInvite, displayName: String, now: Int64
    ) async throws -> FfiJoinPosted {
        try await client().postJoinRequest(
            session: session, keys: keys, invite: invite, displayName: displayName, now: now)
    }

    public func revokeOwnCredential() async throws { try await client().revokeOwnCredential() }

    public func declineJoinRequest(accountID: String) async throws {
        try await client().declineJoinRequest(accountID: accountID)
    }

    public func summarize(session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit) async throws -> FfiEditSummary {
        try await client().summarize(session: session, keys: keys, edit: edit)
    }

    public func edit(
        session: Session, keys: DeviceKeyPair, edit: FfiRosterEdit, now: Int64
    ) async throws -> FfiEditOutcome {
        try await client().edit(session: session, keys: keys, edit: edit, now: now)
    }

    public func createInvite(
        session: Session, keys: DeviceKeyPair, label: String, domain: String?, roles: [FfiOrgRole], now: Int64
    ) async throws -> FfiInviteLink {
        try await client().createInvite(
            session: session, keys: keys, label: label, domain: domain, roles: roles, now: now)
    }

    public func ownerKeysAvailable(session: Session, keys: DeviceKeyPair) async throws -> Bool {
        try await client().ownerKeysAvailable(session: session, keys: keys)
    }

    public func setOwners(session: Session, keys: DeviceKeyPair, owners: [String], now: Int64) async throws -> FfiOrgState {
        try await client().setOwners(session: session, keys: keys, owners: owners, now: now)
    }

    /// A one-use `managed` token for this account's own mailbox (the creator's, R32).
    public func mintMemberToken() async throws -> SecretBytes {
        var token = try await client().mintMemberToken()
        return SecretBytes(taking: &token)
    }
}

/// What a managed account resumes at unlock, without the app (plan deviation 15): an interrupted
/// creation is not resumed (the org shows `.unfinishedCreation`); a join cut off before its request
/// reached the server posts it once, rebuilt from the pinned org and the settings.
public enum ManagedAccountResume {
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "org")

    /// The org session of a managed account: an account that created its org and holds no pin shows
    /// its creation as unfinished.
    @MainActor
    public static func session(
        vault: VaultSession, backend: any OrgBackend, keys: any DeviceKeySource
    ) -> OrgSession {
        OrgSession(vault: vault, backend: backend, keys: keys, creating: vault.settings.orgCreator)
    }

    /// Loads `org`, then posts the join request when one is pending and not posted yet. The member's
    /// own org credential seed goes to `credentials` before `orgJoinPosted` is set. `password`: the
    /// presence check when biometrics cannot answer (R31); without either the request waits for the
    /// next unlock. Returns whether a request was posted now.
    @MainActor
    @discardableResult
    public static func run(
        settings: VaultSettings, org: OrgSession, credentials: ManagedOrgCredentials, displayName: String,
        password: SecretBytes? = nil
    ) async -> Bool {
        await org.load()
        guard !settings.orgCreator, let nonceHex = settings.orgJoinNonce else { return false }
        if settings.orgJoinPosted {
            // Accepted: the nonce has done its job.
            if org.me?.state == .active { settings.orgJoinNonce = nil }
            return false
        }
        guard org.phase == .ready, let state = org.state, let accountID = settings.accountID,
            let mailboxID = settings.orgMailboxID, let nonce = Data(orgHex: nonceHex), nonce.count == 32
        else { return false }
        // `post_join_request` reads the org, the account and the nonce; the link's secrets stay in the
        // keychain (the backend holds the link's credential).
        let invite = FfiOrgInvite(
            serverUrl: "", mailboxId: mailboxID, orgId: state.orgId, accountId: accountID,
            fingerprint: state.fingerprint, nonce: nonce, credentialSeed: Data(), memberToken: Data(), domain: nil)
        do {
            let posted = try await org.requestToJoin(invite: invite, displayName: displayName, password: password)
            var seed = posted.credentialSeed
            try credentials.storeOwnSeed(SecretBytes(taking: &seed), orgMailboxID: mailboxID)
            settings.orgJoinPosted = true
            return true
        } catch {
            log.error("join request not posted, retried at the next unlock")
            return false
        }
    }
}

extension Data {
    /// Bytes of an even-length hex string (any case), nil otherwise.
    init?(orgHex text: String) {
        let utf8 = Array(text.utf8)
        guard utf8.count.isMultiple(of: 2) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(utf8.count / 2)
        var index = 0
        while index < utf8.count {
            guard let high = Self.nibble(utf8[index]), let low = Self.nibble(utf8[index + 1]) else { return nil }
            bytes.append(high << 4 | low)
            index += 2
        }
        self.init(bytes)
    }

    /// Lowercase hex.
    var orgHex: String { map { String(format: "%02x", $0) }.joined() }

    private static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: c - 0x30
        case 0x61...0x66: c - 0x61 + 10
        case 0x41...0x46: c - 0x41 + 10
        default: nil
        }
    }
}
