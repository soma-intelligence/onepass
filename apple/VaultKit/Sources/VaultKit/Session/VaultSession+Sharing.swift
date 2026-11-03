import Foundation
import OnePassCore
import os

/// What the sharing screens show (sharing plan 4, Task 8), read again by `refreshSharing`. Every
/// name is the contact book's `name_local` (core), never one read from a mailbox; every role and
/// right comes from the core, never recomputed here.
public struct SharingSnapshot: Equatable, Sendable {
    public var contacts: [FfiContact] = []
    public var sharedVaults: [FfiSharedVault] = []
    public var shareInvites: [FfiShareInvite] = []
    public var identityChanges: [FfiIdentityChange] = []
    public var family: FfiFamily?
    public var familyInvites: [FfiFamilyInvite] = []
    public var recoveryEnrollment: FfiRecoveryEnrollment?
    /// The members who chose this account as their organizer (spec 11.4).
    public var helpers: [FfiHelper] = []
    public var receivedItems: [FfiReceivedItem] = []
    /// Ids of the items a removed member could read (Watchtower "Vus par un ancien membre").
    public var seenByFormerMembers: Set<String> = []

    public init() {}
}

/// What "Retirer" says after a removal (spec 9.3): the member kept what they saw.
public struct RemovalPrompt: Equatable, Sendable {
    public let memberName: String
    public let vaultName: String
    public let seenItems: UInt32

    /// "<nom> ne verra plus rien de nouveau dans <coffre>. Il a pu garder ce qu'il a déjà vu : <n>
    /// mots de passe. Les changer ?"
    public var message: String {
        String(
            localized: "sharing.removal.prompt \(memberName) \(vaultName) \(Int(seenItems))",
            bundle: VaultKitStrings.bundle)
    }
}

/// What the screens offer for a member's new keys (spec 12.3, decision 6, ruling C-2): a reader is
/// confirmed with the code shown on their iPhone; a writer or a manager only in person (QR).
public enum IdentityChangeOffer: Equatable, Sendable {
    case code(message: String)
    case inPerson(message: String)
    /// Two devices of the member removed each other: ask which one they still hold.
    case forked(message: String)

    public var message: String {
        switch self {
        case .code(let m), .inPerson(let m), .forked(let m): m
        }
    }
}

/// Posts a local notification. The app's implementation uses `UNUserNotificationCenter`.
public protocol LocalNotifying: Sendable {
    func post(id: String, title: String, body: String)
}

/// No notification (tests, extensions).
public struct NoLocalNotifier: LocalNotifying {
    public init() {}
    public func post(id: String, title: String, body: String) {}
}

extension VaultSession {
    nonisolated static let sharingLog = Logger(subsystem: "me.somalabs.onepass", category: "sharing")

    static func unix(_ date: Date) -> Int64 { Int64(date.timeIntervalSince1970) }

    // MARK: - State

    /// Reads contacts, shared vaults, invitations, identity changes, family, recovery helpers and
    /// received items again. A part that cannot be read (a legacy account without device keys) is
    /// left empty: display only.
    public func refreshSharing(at now: Date = Date()) async throws {
        if sharingPinned { return }
        let t = Self.unix(now)
        let snapshot = try await read { session in
            var s = SharingSnapshot()
            s.contacts = (try? session.contacts()) ?? []
            s.sharedVaults = (try? session.sharedVaults()) ?? []
            s.shareInvites = (try? session.shareInvites()) ?? []
            s.identityChanges = (try? session.refreshMemberIdentities(now: t)) ?? []
            s.family = (try? session.family()) ?? nil
            s.familyInvites = (try? session.familyInvites()) ?? []
            s.recoveryEnrollment = (try? session.recoveryEnrollment()) ?? nil
            s.helpers = (try? session.recoveryEnrollmentsForMe()) ?? []
            s.receivedItems = (try? session.receivedItems(now: t)) ?? []
            s.seenByFormerMembers = Set(((try? session.seenByFormerMembers()) ?? []).map(\.itemId))
            return s
        }
        sharing = snapshot
    }

    /// After a sync round brought changes (private or zone): answers the members' key requests, then
    /// reads the sharing state again. The app calls it on `remoteChanges` of both coordinators.
    @discardableResult
    public func afterSyncRound(at now: Date = Date()) async throws -> [FfiRekeyNotice] {
        let notices = try await processRekeyRequests(at: now)
        try await refreshSharing(at: now)
        return notices
    }

    /// A manager's device answers the leave and rotation requests with a new vault key (spec 9.2,
    /// 12.4) and posts one local notification per key changed ("Clé du coffre <nom> renouvelée",
    /// copie provisoire). The lists are reloaded and the sync layer told only when a key changed.
    @discardableResult
    public func processRekeyRequests(at now: Date = Date()) async throws -> [FfiRekeyNotice] {
        let t = Self.unix(now)
        let (notices, vaults) = try await read { session in
            let notices = try session.processRekeyRequests(now: t)
            let vaults = notices.isEmpty ? [] : ((try? session.sharedVaults()) ?? [])
            return (notices, vaults)
        }
        guard !notices.isEmpty else { return [] }
        await refresh()
        notifySync { await $0.localChangesWritten() }
        let title = String(localized: "sharing.rekey.title", bundle: VaultKitStrings.bundle)
        for n in notices {
            let name = vaults.first { $0.vaultId == n.vaultId }?.name ?? ""
            // copie provisoire
            let body = String(localized: "sharing.rekey.notice \(name)", bundle: VaultKitStrings.bundle)
            environment.notifier.post(id: "rekey.\(n.vaultId).\(n.generation)", title: title, body: body)
        }
        Self.sharingLog.notice("vault keys renewed: \(notices.count, privacy: .public)")
        return notices
    }

    #if DEBUG
    /// Demo data and UI tests (`-OnePassDemoSharing YES`): shows `snapshot` and `alerts` as if the
    /// core had read them; `refreshSharing` keeps them.
    public func showDemoSharing(_ snapshot: SharingSnapshot, alerts: [FfiRecoveryAlert] = []) {
        sharing = snapshot
        recoveryAlerts = alerts
        sharingPinned = true
    }
    #endif

    /// This account's role in a shared vault (the core's), nil for a personal vault.
    public func sharedRole(of vaultID: String) -> FfiRole? {
        sharing.sharedVaults.first { $0.vaultId == vaultID }?.role
            ?? allVaults.first { $0.id == vaultID }?.shared?.role
    }

    // MARK: - Contacts

    /// An in-person verification on the unlocked session; nil while locked.
    public func contactVerificationFlow(
        myName: String, keys: any DeviceKeySource, creator: any ContactZoneCreating
    ) -> ContactVerificationFlow? {
        guard let session = coreSession else { return nil }
        return ContactVerificationFlow(session: session, myName: myName, keys: keys, creator: creator)
    }

    /// A remote invitation; while locked, an opened link waits in the Keychain for `unlocked`.
    public func contactInviteFlow(
        myName: String, drops: any InviteDrops, creator: any ContactZoneCreating, hosted: URL
    ) -> ContactInviteFlow {
        ContactInviteFlow(
            session: coreSession, myName: myName, keychain: environment.keychain, drops: drops, creator: creator,
            hosted: hosted)
    }

    /// The organizer's side of a recovery for `member`; nil while locked.
    public func recoveryReleaseFlow(member: String) -> RecoveryReleaseFlow? {
        guard let session = coreSession else { return nil }
        return RecoveryReleaseFlow(session: session, member: member)
    }

    /// "Comparer le numéro de sécurité" (spec 5.3.2): a `Link` contact whose number matches becomes
    /// `Verified`.
    @discardableResult
    public func confirmSafetyNumber(of accountID: String, shown: String, at now: Date = Date()) async throws -> FfiContact {
        let t = Self.unix(now)
        let contact = try await write { try $0.confirmSafetyNumber(accountId: accountID, shown: shown, now: t) }
        try await refreshSharing(at: now)
        return contact
    }

    public func renameContact(_ accountID: String, name: String) async throws {
        try await write { try $0.renameContact(accountId: accountID, name: name) }
        try await refreshSharing()
    }

    // MARK: - Shared vaults

    /// Shares a personal vault: it moves to a zone of its own, this account its owner. The zone
    /// round makes its mailbox.
    @discardableResult
    public func shareVault(_ vaultID: String, at now: Date = Date()) async throws -> FfiSharedVault {
        let t = Self.unix(now)
        let shared = try await write { try $0.shareVault(vaultId: vaultID, now: t) }
        try await refreshSharing(at: now)
        return shared
    }

    /// Invites a contact with `role` (a `Link` contact gets Read only: the core refuses more with
    /// `ContactNotVerified`).
    @discardableResult
    public func addMember(_ contactID: String, to vaultID: String, role: FfiRole, at now: Date = Date()) async throws -> FfiSharedVault {
        let t = Self.unix(now)
        let shared = try await write { try $0.addMember(vaultId: vaultID, contact: contactID, role: role, now: t) }
        try await refreshSharing(at: now)
        return shared
    }

    @discardableResult
    public func setRole(_ role: FfiRole, of accountID: String, in vaultID: String, at now: Date = Date()) async throws -> FfiSharedVault {
        let t = Self.unix(now)
        let shared = try await write { try $0.setRole(vaultId: vaultID, accountId: accountID, role: role, now: t) }
        try await refreshSharing(at: now)
        return shared
    }

    /// Removes a member with a new key; the prompt of spec 9.3 counts what they could read.
    public func removeMember(_ accountID: String, from vaultID: String, at now: Date = Date()) async throws -> RemovalPrompt {
        let t = Self.unix(now)
        let before = sharing.sharedVaults.first { $0.vaultId == vaultID }
        let removal = try await write { try $0.removeMember(vaultId: vaultID, accountId: accountID, now: t) }
        try await refreshSharing(at: now)
        let vault = before ?? sharing.sharedVaults.first { $0.vaultId == vaultID }
        let name = before?.members.first { $0.accountId == accountID }?.nameLocal
            ?? sharing.contacts.first { $0.accountId == accountID }?.nameLocal ?? ""
        return RemovalPrompt(memberName: name, vaultName: vault?.name ?? "", seenItems: removal.seenItems)
    }

    public func leaveSharedVault(_ vaultID: String, at now: Date = Date()) async throws {
        let t = Self.unix(now)
        try await write { try $0.leaveSharedVault(vaultId: vaultID, now: t) }
        try await refreshSharing(at: now)
    }

    @discardableResult
    public func stopSharing(_ vaultID: String, at now: Date = Date()) async throws -> FfiVault {
        let t = Self.unix(now)
        let vault = try await write { try $0.stopSharing(vaultId: vaultID, now: t) }
        try await refreshSharing(at: now)
        return vault
    }

    /// "Réparer le coffre partagé" (spec 13.2, A19) and a vault whose owner is gone: a copy under a
    /// new id, this account its owner.
    @discardableResult
    public func transferByCopy(_ vaultID: String, at now: Date = Date()) async throws -> FfiSharedVault {
        let t = Self.unix(now)
        let shared = try await write { try $0.transferByCopy(vaultId: vaultID, now: t) }
        try await refreshSharing(at: now)
        return shared
    }

    public func setSharedVaultMcpHidden(_ vaultID: String, hidden: Bool) async throws {
        try await write { try $0.setSharedVaultMcpHidden(vaultId: vaultID, hidden: hidden) }
        try await refreshSharing()
    }

    @discardableResult
    public func acceptShareInvite(_ inviteID: String, at now: Date = Date()) async throws -> FfiSharedVault {
        let t = Self.unix(now)
        let shared = try await write { try $0.acceptShareInvite(inviteId: inviteID, now: t) }
        try await refreshSharing(at: now)
        return shared
    }

    public func declineShareInvite(_ inviteID: String) async throws {
        try await write { try $0.declineShareInvite(inviteId: inviteID) }
        try await refreshSharing()
    }

    /// The members that have not confirmed this account's new keys yet (spec 12.4).
    public func membersNotConfirmed(in vaultID: String) async throws -> [String] {
        try await read { try $0.membersNotConfirmed(vaultId: vaultID) }
    }

    // MARK: - Identity changes

    /// What to offer for `change` (decision 6, C-2): the code when every vault this account manages
    /// with the member gives them Read, in person otherwise. The role is the core's.
    public func identityChangeOffer(for change: FfiIdentityChange) -> IdentityChangeOffer {
        let name = change.nameLocal
        if change.forked {
            return .forked(message: String(localized: "sharing.identity.forked \(name)", bundle: VaultKitStrings.bundle))
        }
        let roles = sharing.sharedVaults
            .filter { change.vaults.contains($0.vaultId) }
            .compactMap { v in v.members.first { $0.accountId == change.accountId }?.role }
        let date = Self.longDate(Date(timeIntervalSince1970: TimeInterval(change.issuedAt)))
        if roles.contains(where: { $0 != .read }) {
            // copie provisoire (C-2)
            return .inPerson(message: String(localized: "sharing.identity.writer \(name) \(date)", bundle: VaultKitStrings.bundle))
        }
        if let rotator = change.rotatorName, !change.revokedNames.isEmpty {
            let removed = change.revokedNames.formatted(.list(type: .and).locale(Locale(identifier: VaultKitStrings.language)))
            return .code(message: String(
                localized: "sharing.identity.reader \(name) \(date) \(rotator) \(removed)", bundle: VaultKitStrings.bundle))
        }
        return .code(message: String(localized: "sharing.identity.readerShort \(name) \(date)", bundle: VaultKitStrings.bundle))
    }

    /// Confirms a member's new keys in every vault this account manages with them.
    @discardableResult
    public func adoptMemberIdentity(
        _ change: FfiIdentityChange, proof: FfiAdoptionProof, at now: Date = Date()
    ) async throws -> [FfiSharedVault] {
        let t = Self.unix(now)
        let (account, child) = (change.accountId, change.child)
        let vaults = try await write { try $0.adoptMemberIdentity(accountId: account, child: child, proof: proof, now: t) }
        try await refreshSharing(at: now)
        return vaults
    }

    // MARK: - Formatting

    static func longDate(_ date: Date) -> String {
        date.formatted(Date.FormatStyle(date: .long, time: .omitted).locale(Locale(identifier: VaultKitStrings.language)))
    }

    static func shortTime(_ date: Date) -> String {
        date.formatted(Date.FormatStyle(date: .omitted, time: .shortened).locale(Locale(identifier: VaultKitStrings.language)))
    }
}
