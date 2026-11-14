import Foundation
import Observation
import OnePassCore

/// Where the organisation of a managed account stands on this device.
public enum OrgPhase: Equatable, Sendable {
    case loading
    /// No pin yet: the account has not joined (or not pinned) its organisation.
    case notJoined
    /// This device started creating the organisation and the publish never finished.
    case unfinishedCreation
    case ready
    /// The local pin could not be read (`OrgSession.refreshError` says why). `load()` again to retry.
    case unavailable
    /// The server showed something the pin refuses. The last good state stays shown.
    case refused(OrgRefusal)
}

/// What the core refused in the server's answer. Nothing local changed.
public enum OrgRefusal: Equatable, Sendable {
    case pinMismatch, rollback, fork, quorum, unreadable

    public var message: String {
        let key: String.LocalizationValue =
            switch self {
            case .pinMismatch: "org.error.pinMismatch"
            case .rollback: "org.error.rollback"
            case .fork: "org.error.fork"
            case .quorum: "org.error.quorum"
            case .unreadable: "org.error.unreadable"
            }
        return String(localized: key, bundle: VaultKitStrings.bundle)
    }
}

/// Why an org action did not happen.
public enum OrgActionError: Error, Equatable, Sendable {
    /// No biometrics (or the user declined them): ask the master password and call again.
    case passwordRequired
    /// This account's role can't make this change (local check or the core rules).
    case notAllowed
    /// Someone else changed the roster at the same time.
    case conflict
    /// This device's keys can't be read (keychain locked, item missing).
    case keysUnavailable
    /// The vault is locked: nothing can be signed.
    case locked
    case refused(OrgRefusal)
    case other(String)

    /// Maps a core, vault or keychain error.
    public init(_ error: any Error) {
        switch error {
        case let error as OrgActionError:
            self = error
        case OnePassError.Locked:
            self = .locked
        case OnePassError.OrgPinMismatch:
            self = .refused(.pinMismatch)
        case OnePassError.Validation(let field, let reason):
            self = Self.validation(field: field, reason: reason)
        default:
            self = Self.vault(VaultError(error))
        }
    }

    private static func vault(_ error: VaultError) -> OrgActionError {
        switch error {
        case .passwordRequired: .passwordRequired
        case .conflict: .conflict
        case .integrity(let kind): integrity(kind)
        case .validation(let field, let reason): validation(field: field, reason: reason)
        default: .other(error.localizedMessage)
        }
    }

    private static func integrity(_ kind: String) -> OrgActionError {
        switch kind {
        case "org_pin_mismatch": .refused(.pinMismatch)
        case "org_quorum": .refused(.quorum)
        case "org_role_denied": .notAllowed
        case _ where kind.hasPrefix("org_") && kind.hasSuffix("_rollback"): .refused(.rollback)
        case _ where kind.hasPrefix("org_") && kind.hasSuffix("_fork"): .refused(.fork)
        default: .refused(.unreadable)
        }
    }

    private static func validation(field: String, reason: String) -> OrgActionError {
        switch (field, reason) {
        case ("owners", "quorum"): .refused(.quorum)
        case ("owners", "pending change"):
            .other(String(localized: "org.error.ownersPending", bundle: VaultKitStrings.bundle))
        case ("owners", "keeps this account"):
            .other(String(localized: "org.error.ownersKeepSelf", bundle: VaultKitStrings.bundle))
        case ("roles", "owner via lineage"), ("roles", "recovery officer via lineage"): .notAllowed
        default: .other(VaultError.validationMessage(reason))
        }
    }

    public var message: String {
        switch self {
        case .passwordRequired, .locked: VaultError.passwordRequired.localizedMessage
        case .notAllowed: String(localized: "org.error.notAllowed", bundle: VaultKitStrings.bundle)
        case .conflict: String(localized: "org.error.conflict", bundle: VaultKitStrings.bundle)
        case .keysUnavailable: String(localized: "org.error.keysUnavailable", bundle: VaultKitStrings.bundle)
        case .refused(let refusal): refusal.message
        case .other(let message): message
        }
    }
}

/// A managed account's organisation on this device: the pinned state, the join requests, and the
/// signed changes. Every change that signs asks for presence (biometrics, else the master password)
/// after the local checks and the summary, and before anything is written.
@MainActor
@Observable
public final class OrgSession {
    public private(set) var phase: OrgPhase = .loading
    /// The last state the pin verified. Kept when a later answer is refused.
    public private(set) var state: FfiOrgState?
    /// Pending join requests (read only when this account can manage members).
    public private(set) var joinRequests: [FfiJoinRequest] = []
    /// The last refresh failed without a refusal (offline, server down). Nil after a good one.
    public private(set) var refreshError: OrgActionError?

    @ObservationIgnored private let vault: VaultSession
    @ObservationIgnored private let backend: any OrgBackend
    @ObservationIgnored private let keys: any DeviceKeySource
    @ObservationIgnored private let creating: Bool
    @ObservationIgnored private let now: @Sendable () -> Date

    public init(
        vault: VaultSession, backend: any OrgBackend, keys: any DeviceKeySource, creating: Bool = false,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.vault = vault
        self.backend = backend
        self.keys = keys
        self.creating = creating
        self.now = now
    }

    // MARK: - Who I am

    /// This account in the pinned roster.
    public var me: FfiOrgMember? {
        guard let accountID = vault.settings.accountID else { return nil }
        return state?.members.first { $0.accountId == accountID }
    }

    public var myRoles: Set<FfiOrgRole> { Set(me?.roles ?? []) }

    /// Owner, Admin or UserManager, and Active (R6: the creator holds Owner only).
    public var canManageMembers: Bool {
        me?.state == .active && !myRoles.isDisjoint(with: [.owner, .admin, .userManager])
    }

    /// An owner of the pinned head, and Active.
    public var isOwner: Bool {
        guard let me, me.state == .active else { return false }
        return state?.owners.contains(me.accountId) ?? false
    }

    /// Pinned on first use and not yet compared with an admin's words.
    public var needsVerification: Bool { state?.source == .tofu(verified: false) }

    // MARK: - Reading

    /// The local pin, then a refresh from the server.
    public func load() async {
        do {
            state = try await backend.state()
        } catch {
            let error = OrgActionError(error)
            settle(error)
            if case .loading = phase {
                refreshError = error
                phase = .unavailable
            }
            return
        }
        refreshError = nil
        guard state != nil else {
            phase = creating ? .unfinishedCreation : .notJoined
            return
        }
        phase = .ready
        await refresh()
    }

    /// Moves the pin forward and rereads the join requests. A refusal sets `phase` to `.refused`
    /// and keeps `state`; any other failure only sets `refreshError`.
    public func refresh() async {
        guard state != nil else { return }
        do {
            state = try await backend.refresh()
            joinRequests = canManageMembers ? try await backend.joinRequests() : []
            phase = .ready
            refreshError = nil
        } catch {
            settle(OrgActionError(error))
        }
    }

    private func settle(_ error: OrgActionError) {
        if case .refused(let refusal) = error {
            phase = .refused(refusal)
        } else {
            refreshError = error
        }
    }

    // MARK: - Joining

    /// Pins the organisation the server shows, as `plan` says (Task 6's `OrgPinResolver`).
    public func pin(_ plan: OrgPinPlan) async throws(OrgActionError) {
        switch plan {
        case .refuse(.mdmInvalid):
            throw .other(String(localized: "org.error.mdmInvalid", bundle: VaultKitStrings.bundle))
        case .refuse(.mdmMismatch), .refuse(.dnsMismatch):
            throw .refused(.pinMismatch)
        case .pin(let source, let expected):
            let at = timestamp
            state = try await mapped { try await backend.pin(source: source, expected: expected, now: at) }
            phase = .ready
            refreshError = nil
        }
    }

    /// The user compared the fingerprint words with an admin's and they match.
    public func markVerified() async throws(OrgActionError) {
        state = try await mapped { try await backend.markVerified() }
    }

    /// Posts this account's join request, signed by this device after a presence check (R31). The
    /// returned seed is the member's own org mailbox credential (R27): the caller keeps it in the
    /// keychain, this session does not.
    public func requestToJoin(
        invite: FfiOrgInvite, displayName: String, password: SecretBytes?
    ) async throws(OrgActionError) -> FfiJoinPosted {
        let (session, pair) = try signer()
        try await confirmPresence(password: password, prompt: "org.presence.joinPrompt")
        let at = timestamp
        let posted = try await mapped {
            try await backend.postJoinRequest(
                session: session, keys: pair, invite: invite, displayName: displayName, now: at)
        }
        await refresh()
        return posted
    }

    // MARK: - Signed changes

    /// What `edit` would do, from the pinned roster, before anything is signed.
    public func summary(for edit: FfiRosterEdit) async throws(OrgActionError) -> FfiEditSummary {
        let (session, pair) = try signer()
        return try await mapped { try await backend.summarize(session: session, keys: pair, edit: edit) }
    }

    public func apply(_ edit: FfiRosterEdit, password: SecretBytes?) async throws(OrgActionError) -> FfiEditOutcome {
        guard canManageMembers else { throw .notAllowed }
        let (session, pair) = try signer()
        let summary = try await mapped { try await backend.summarize(session: session, keys: pair, edit: edit) }
        guard summary.allowed else { throw .notAllowed }
        try await confirmPresence(password: password)
        let at = timestamp
        let outcome = try await mapped {
            try await backend.edit(session: session, keys: pair, edit: edit, now: at)
        }
        state = outcome.state
        await refresh()
        return outcome
    }

    public func decline(_ request: FfiJoinRequest, password: SecretBytes?) async throws(OrgActionError) {
        guard canManageMembers else { throw .notAllowed }
        try await confirmPresence(password: password)
        try await mapped { try await backend.declineJoinRequest(accountID: request.accountId) }
        await refresh()
    }

    /// A join link for a new member with `roles` (none by default). Signs a roster edit (R4).
    public func invite(
        label: String, domain: String?, roles: [FfiOrgRole] = [], password: SecretBytes?
    ) async throws(OrgActionError) -> FfiInviteLink {
        guard canManageMembers else { throw .notAllowed }
        let (session, pair) = try signer()
        try await confirmPresence(password: password)
        let at = timestamp
        let link = try await mapped {
            try await backend.createInvite(
                session: session, keys: pair, label: label, domain: domain, roles: roles, now: at)
        }
        await refresh()
        return link
    }

    /// The owner keyset opens on this device. False on any failure.
    public func ownerKeysAvailable() async -> Bool {
        guard let (session, pair) = try? signer() else { return false }
        return (try? await backend.ownerKeysAvailable(session: session, keys: pair)) ?? false
    }

    public func setOwners(_ accountIDs: [String], password: SecretBytes?) async throws(OrgActionError) {
        guard isOwner else { throw .notAllowed }
        let (session, pair) = try signer()
        try await confirmPresence(password: password)
        let at = timestamp
        state = try await mapped {
            try await backend.setOwners(session: session, keys: pair, owners: accountIDs, now: at)
        }
        await refresh()
    }

    // MARK: - Support

    private var timestamp: Int64 { Int64(now().timeIntervalSince1970) }

    /// The unlocked core session and this device's keys.
    private func signer() throws(OrgActionError) -> (Session, DeviceKeyPair) {
        guard let session = vault.coreSession else { throw .locked }
        do {
            return (session, try keys.deviceKeys())
        } catch {
            throw .keysUnavailable
        }
    }

    private func confirmPresence(
        password: SecretBytes?, prompt key: String.LocalizationValue = "org.presence.prompt"
    ) async throws(OrgActionError) {
        let prompt = String(localized: key, bundle: VaultKitStrings.bundle)
        try await mapped { try await vault.confirmPresence(password: password, prompt: prompt) }
    }

    private func mapped<T>(_ work: () async throws -> T) async throws(OrgActionError) -> T {
        do {
            return try await work()
        } catch {
            throw OrgActionError(error)
        }
    }
}
