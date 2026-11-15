import Foundation
import Testing

@testable import VaultKit

/// Managed accounts on the organisation's server: the server check, the sync handed over once the
/// mailbox exists, the cleanup of a slot, and what an unlock resumes (Task 8).
@MainActor
@Suite("Managed accounts")
struct ManagedAccountTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    private static let orgID = String(repeating: "ab", count: 16)
    private static func now() -> Int64 { Int64(Date().timeIntervalSince1970) }

    // MARK: - Server check

    @Test func orgServerMustBeHttpsWithAnOrgID() {
        let https = "https://onepass.example.org/functions/v1/mailbox"
        #expect(OrgServers.isUsable(.managed(serverUrl: https, orgId: Self.orgID), allowHTTP: false))
        #expect(OrgServers.isUsable(.managed(serverUrl: https, orgId: Self.orgID.uppercased()), allowHTTP: false))
        #expect(!OrgServers.isUsable(.managed(serverUrl: "", orgId: ""), allowHTTP: false))
        #expect(!OrgServers.isUsable(.managed(serverUrl: "", orgId: Self.orgID), allowHTTP: false))
        #expect(!OrgServers.isUsable(.managed(serverUrl: "http://onepass.example.org", orgId: Self.orgID), allowHTTP: false))
        #expect(!OrgServers.isUsable(.managed(serverUrl: https, orgId: String(repeating: "ab", count: 15)), allowHTTP: false))
        #expect(!OrgServers.isUsable(.managed(serverUrl: https, orgId: String(repeating: "zz", count: 16)), allowHTTP: false))
        #expect(!OrgServers.isUsable(.personal, allowHTTP: false))
        #expect(!OrgServers.isUsable(.business, allowHTTP: false))
    }

    @Test func managedAccountAddedWhenServerIsUsable() throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        h.accounts.serverAvailable = { OrgServers.isUsable($0, allowHTTP: false) }
        #expect(throws: AccountsError.serverUnavailable) {
            try h.accounts.beginAdding(kind: .managed(serverUrl: "", orgId: ""), label: "Org", color: .indigo)
        }
        let kind = FfiAccountKind.managed(serverUrl: "https://onepass.example.org", orgId: Self.orgID)
        let slot = try h.accounts.beginAdding(kind: kind, label: "Org", color: .indigo)
        #expect(h.accounts.profile(slot)?.isManaged == true)
        #expect(h.accounts.profiles.count == 2)
    }

    // MARK: - Sync

    /// A real core session (a sync trigger only passes it on).
    private static func coreSession() throws -> (Session, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-managed-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let created = try createAccountOnCoreStack(
            dbPath: dir.appendingPathComponent("v.db").path, password: testPassword, kdf: SessionHarness.fastKdf)
        return (created.session, dir)
    }

    @Test func syncForwardsOnlyAfterAttach() async throws {
        let (session, dir) = try Self.coreSession()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sync = ManagedAccountSync()
        #expect(sync.syncsWithServer)
        await sync.sessionUnlocked(session)
        await sync.localChangesWritten()
        let recorder = RecordingSync()
        await sync.attach(trigger: recorder)
        // The unlocked session is replayed on attach, then writes go through.
        #expect(recorder.events == [.unlocked])
        await sync.localChangesWritten()
        await sync.sessionLocked()
        #expect(recorder.events == [.unlocked, .written, .locked])
        #expect(await sync.current == nil)
    }

    @Test func aLockedAccountReplaysNothingOnAttach() async throws {
        let (session, dir) = try Self.coreSession()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sync = ManagedAccountSync()
        await sync.sessionUnlocked(session)
        await sync.sessionLocked()
        let recorder = RecordingSync()
        await sync.attach(trigger: recorder)
        #expect(recorder.events.isEmpty)
    }

    @Test func eraseBeforeAttachIsOffline() async throws {
        let sync = ManagedAccountSync()
        await #expect(throws: VaultError.other(SyncTriggerMessages.offline)) {
            try await sync.eraseAccount { Issue.record("erased without a mailbox") }
        }
        // A reset of the local store needs no server.
        let reset = ResetCount()
        try await sync.resetStore { reset.bump() }
        #expect(reset.value == 1)
    }

    // MARK: - Cleanup

    @Test func removingAManagedAccountDropsItsDeviceKeysAndOrgCredential() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        h.accounts.serverAvailable = { OrgServers.isUsable($0, allowHTTP: false) }
        let kind = FfiAccountKind.managed(serverUrl: "https://onepass.example.org", orgId: Self.orgID)
        let mailboxID = String(repeating: "cd", count: 16)

        // Cancelled before the account exists: the pending keys and the link's seed go.
        let cancelled = try h.accounts.beginAdding(kind: kind, label: "Org", color: .indigo)
        _ = try ManagedDeviceKeys.createPending(keychain: h.keychain, slot: cancelled, secureEnclave: false)
        let early = ManagedOrgCredentials(keychain: h.keychain, slot: cancelled)
        try early.storeLinkSeed(SecretBytes(copying: Data(repeating: 1, count: 32)))
        try early.storeMemberToken(SecretBytes(copying: Data(repeating: 2, count: 32)))
        h.accounts.cancelAdding(cancelled)
        #expect(try h.keychain.read(ManagedDeviceKeys.pendingKey(slot: cancelled)) == nil)
        #expect(try early.linkSeed() == nil)
        #expect(try early.memberToken() == nil)

        // Removed once made: its device keys and its own org credential go, the other accounts' stay.
        let slot = try h.accounts.beginAdding(kind: kind, label: "Org", color: .indigo)
        try await h.createAccount(in: slot, name: "Bob")
        let session = try #require(h.accounts.session(for: slot))
        let accountID = try #require(session.environment.settings.accountID)
        _ = try ManagedDeviceKeys.createPending(keychain: h.keychain, slot: slot, secureEnclave: false)
        try ManagedDeviceKeys.adoptPending(keychain: h.keychain, slot: slot, accountID: accountID)
        session.environment.settings.orgMailboxID = mailboxID
        let credentials = ManagedOrgCredentials(keychain: h.keychain, slot: slot)
        try credentials.storeOwnSeed(SecretBytes(copying: Data(repeating: 3, count: 32)), orgMailboxID: mailboxID)
        try credentials.storeLinkSeed(SecretBytes(copying: Data(repeating: 4, count: 32)))
        let unrelated = MailboxCredentialStore.key(mailboxID: String(repeating: "ef", count: 16))
        try h.keychain.write(unrelated, Data([9]))

        try h.accounts.remove(slot)
        #expect(try h.keychain.read(ManagedDeviceKeys.key(accountID: accountID)) == nil)
        #expect(try credentials.ownSeed(orgMailboxID: mailboxID) == nil)
        #expect(try credentials.linkSeed() == nil)
        #expect(try h.keychain.read(unrelated) == Data([9]))
        #expect(h.accounts.profiles.count == 1)
    }

    /// Removed at a launch that never opened the slot: its settings and every keychain item still go,
    /// read from the slot's scoped settings and its store (backend state, setup progress).
    @Test func removingAManagedAccountWithNoSessionDropsEverything() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        h.accounts.serverAvailable = { OrgServers.isUsable($0, allowHTTP: false) }
        let kind = FfiAccountKind.managed(serverUrl: "https://onepass.example.org", orgId: Self.orgID)
        let slot = try h.accounts.beginAdding(kind: kind, label: "Org", color: .indigo)
        try await h.createAccount(in: slot, name: "Bob")
        let session = try #require(h.accounts.session(for: slot))
        let accountID = try #require(session.environment.settings.accountID)
        _ = try ManagedDeviceKeys.createPending(keychain: h.keychain, slot: slot, secureEnclave: false)
        try ManagedDeviceKeys.adoptPending(keychain: h.keychain, slot: slot, accountID: accountID)
        _ = try ManagedDeviceKeys.createPending(keychain: h.keychain, slot: slot, secureEnclave: false)

        let (orgMailbox, homeMailbox, setupMailbox) =
            (String(repeating: "cd", count: 16), String(repeating: "aa", count: 16), String(repeating: "bb", count: 16))
        session.environment.settings.orgMailboxID = orgMailbox
        let credentials = ManagedOrgCredentials(keychain: h.keychain, slot: slot)
        try credentials.storeOwnSeed(SecretBytes(copying: Data(repeating: 3, count: 32)), orgMailboxID: orgMailbox)
        try credentials.storeLinkSeed(SecretBytes(copying: Data(repeating: 4, count: 32)))
        try credentials.storeMemberToken(SecretBytes(copying: Data(repeating: 5, count: 32)))
        let mailboxes = MailboxCredentialStore(keychain: h.keychain)
        let pendingID = MailboxSetup.pendingCredentialID(slot: slot)
        for id in [homeMailbox, setupMailbox, pendingID, MailboxSetup.pendingID] {
            try mailboxes.store(seed: SecretBytes(copying: Data(repeating: 6, count: 32)), mailboxID: id)
        }
        let dbURL = try h.store.databaseURL(slot: slot)
        do {
            let store = try openSyncStore(dbPath: dbURL.path)
            let home = MailboxHome(
                baseURL: URL(string: "https://onepass.example.org")!, mailboxID: homeMailbox, extraCAPEM: nil)
            try await SyncBackendState.write(.mailbox(home), store: store)
            let progress = MailboxSetup.Progress(
                step: .created, baseURL: home.baseURL, extraCAPEM: nil, mailboxID: setupMailbox, managed: true)
            try store.setMeta(key: MailboxSetup.metaKey, value: try JSONEncoder().encode(progress))
        }
        h.accounts.lockAll()

        let relaunched = h.relaunched()
        try relaunched.remove(slot)
        #expect(try h.keychain.read(ManagedDeviceKeys.key(accountID: accountID)) == nil)
        #expect(try h.keychain.read(ManagedDeviceKeys.pendingKey(slot: slot)) == nil)
        #expect(try credentials.ownSeed(orgMailboxID: orgMailbox) == nil)
        #expect(try credentials.linkSeed() == nil)
        #expect(try credentials.memberToken() == nil)
        for id in [homeMailbox, setupMailbox, pendingID] { #expect(try mailboxes.seed(mailboxID: id) == nil) }
        // The primary account's pending seed is not the slot's.
        #expect(try mailboxes.seed(mailboxID: MailboxSetup.pendingID) != nil)
        #expect(VaultSettings(defaults: h.defaults, scope: slot).orgMailboxID == nil)
        #expect(!FileManager.default.fileExists(atPath: dbURL.path))
    }

    // MARK: - Resume

    /// A managed account for `orgID` in `h`, its software keys adopted under the new account id.
    private static func managedAccount(
        _ h: SessionHarness, _ vault: VaultSession, name: String, orgID: String, accountID: String?
    ) async throws -> ManagedDeviceKeys {
        let slot = UUID().uuidString
        let pending = try ManagedDeviceKeys.createPending(keychain: h.keychain, slot: slot, secureEnclave: false)
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        let secretKey = try await vault.createManagedAccount(
            password: password, displayName: name, mode: .personal, orgID: orgID, accountID: accountID,
            keys: pending)
        secretKey.wipe()
        let account = try #require(h.settings.accountID)
        try ManagedDeviceKeys.adoptPending(keychain: h.keychain, slot: slot, accountID: account)
        return ManagedDeviceKeys(keychain: h.keychain, accountID: account)
    }

    @Test func interruptedJoinPostsOnceAfterUnlock() async throws {
        let server = TestOrgServer()
        let ownerHarness = try SessionHarness()
        defer { ownerHarness.cleanUp() }
        let joinerHarness = try SessionHarness()
        defer { joinerHarness.cleanUp() }
        let ownerDir = ownerHarness.dir.appendingPathComponent("org").path
        let joinerDir = joinerHarness.dir.appendingPathComponent("org").path

        // The owner's org, its seed kept as the creator's own credential.
        let draft = try OrgDraft()
        let orgID = draft.orgId()
        let ownerVault = ownerHarness.makeSession()
        let ownerKeys = try await Self.managedAccount(ownerHarness, ownerVault, name: "Alice", orgID: orgID, accountID: nil)
        try await ownerVault.enrollBiometrics(password: testPassword)
        let pair = try ownerKeys.deviceKeys()
        let created = try server.draftPublish(
            draft: draft, session: try #require(ownerVault.coreSession), classical: pair.classical, pq: pair.pq,
            name: "Acme", stateDir: ownerDir, now: Self.now())
        ownerHarness.settings.orgCreator = true
        ownerHarness.settings.orgMailboxID = created.mailboxId
        let ownerCredentials = ManagedOrgCredentials(keychain: ownerHarness.keychain, slot: "owner")
        try ownerCredentials.storeOwnSeed(SecretBytes(copying: created.credentialSeed), orgMailboxID: created.mailboxId)
        let ownerBackend = ManagedOrgBackend(credentials: ownerCredentials, orgMailboxID: created.mailboxId) { seed in
            try server.client(mailboxId: created.mailboxId, credentialSeed: seed, orgId: orgID, stateDir: ownerDir)
        }
        let owner = ManagedAccountResume.session(vault: ownerVault, backend: ownerBackend, keys: ownerKeys)
        #expect(await ManagedAccountResume.run(
            settings: ownerHarness.settings, org: owner, credentials: ownerCredentials, displayName: "Alice") == false)
        #expect(owner.phase == .ready)
        let link = try await owner.invite(label: "Bob", domain: nil, password: nil)
        let invite = try orgInviteParse(link: link.link, allowLoopbackHttp: true)

        // The joiner keeps the link's seed, pins, makes its account, then is cut off before posting.
        let credentials = ManagedOrgCredentials(keychain: joinerHarness.keychain, slot: "joiner")
        try credentials.storeLinkSeed(SecretBytes(copying: invite.credentialSeed))
        let backend = ManagedOrgBackend(credentials: credentials, orgMailboxID: invite.mailboxId) { seed in
            try server.client(mailboxId: invite.mailboxId, credentialSeed: seed, orgId: invite.orgId, stateDir: joinerDir)
        }
        let settings = joinerHarness.settings
        settings.orgMailboxID = invite.mailboxId
        settings.orgJoinNonce = invite.nonce.orgHex
        let joinerVault = joinerHarness.makeSession()
        let joinerKeys = ManagedDeviceKeys(keychain: joinerHarness.keychain, accountID: invite.accountId)
        let joiner = ManagedAccountResume.session(vault: joinerVault, backend: backend, keys: joinerKeys)
        try await joiner.pin(.pin(source: .tofu(verified: false), expected: invite.fingerprint))
        _ = try await Self.managedAccount(
            joinerHarness, joinerVault, name: "Bob", orgID: invite.orgId, accountID: invite.accountId)
        #expect(!settings.orgJoinPosted)

        // Next unlock, no biometrics: nothing posted, no error shown, the join waits for the password (R34).
        #expect(await ManagedAccountResume.run(
            settings: settings, org: joiner, credentials: credentials, displayName: "Bob") == false)
        #expect(settings.orgJoinWaiting)
        #expect(!settings.orgJoinPosted)

        // A wrong password posts nothing, but the member's own seed is already kept (R35).
        let wrong = SecretBytes(utf8: "not the password at all 12 !")
        defer { wrong.wipe() }
        await #expect(throws: OrgActionError.self) {
            try await ManagedAccountResume.sendJoinRequest(
                settings: settings, org: joiner, credentials: credentials, displayName: "Bob", password: wrong)
        }
        #expect(!settings.orgJoinPosted)
        let kept = try #require(try credentials.ownSeed(orgMailboxID: invite.mailboxId))
        let keptSeed = kept.withData { Data($0) }

        // The password: posted once, with the same seed (a repost names the same credential).
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        #expect(try await ManagedAccountResume.sendJoinRequest(
            settings: settings, org: joiner, credentials: credentials, displayName: "Bob", password: password))
        #expect(settings.orgJoinPosted)
        #expect(!settings.orgJoinWaiting)
        // The join code stays on the slot for the Organisation page (the member reads it out).
        let code = try #require(settings.orgJoinCode)
        #expect(code.count == 5)
        let own = try #require(try credentials.ownSeed(orgMailboxID: invite.mailboxId))
        #expect(own.withData { Data($0) } == keptSeed)
        #expect(await ManagedAccountResume.run(
            settings: settings, org: joiner, credentials: credentials, displayName: "Bob") == false)
        await owner.refresh()
        #expect(owner.joinRequests.map(\.displayName) == ["Bob"])
        #expect(owner.joinRequests.first?.codeWords == code)
        #expect(await backend.usesOwnCredential == false)

        // Accepted: the next refresh moves to the member's own credential and drops the link's (R33).
        let request = try #require(owner.joinRequests.first)
        _ = try await owner.apply(.accept(accountId: request.accountId, roles: []), password: nil)
        await ManagedAccountResume.run(settings: settings, org: joiner, credentials: credentials, displayName: "Bob")
        #expect(joiner.me?.state == .active)
        #expect(joiner.refreshError == nil)
        #expect(await backend.usesOwnCredential)
        #expect(try credentials.linkSeed() == nil)
        #expect(settings.orgJoinNonce == nil)
        #expect(settings.orgJoinCode == nil)
    }

    /// A creation cut off before its publish: no org mailbox is known, so the org backend of the slot
    /// is the unfinished one and the session shows it (the path the app takes).
    @Test func interruptedCreationShowsUnfinished() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let vault = h.makeSession()
        let credentials = ManagedOrgCredentials(keychain: h.keychain, slot: "creator")
        let open: ManagedOrgBackend.Open = { _ in throw OnePassError.NotFound }
        // A slot with no org yet has no org backend.
        #expect(ManagedAccountResume.backend(settings: h.settings, credentials: credentials, open: open) == nil)

        h.settings.orgCreator = true
        let backend = try #require(
            ManagedAccountResume.backend(settings: h.settings, credentials: credentials, open: open))
        #expect(backend is UnfinishedOrgBackend)
        let org = ManagedAccountResume.session(
            vault: vault, backend: backend, keys: ManagedDeviceKeys(keychain: h.keychain, accountID: "none"))
        let posted = await ManagedAccountResume.run(
            settings: h.settings, org: org, credentials: credentials, displayName: "Alice")
        #expect(!posted)
        #expect(org.phase == .unfinishedCreation)

        // Once published, the org mailbox is known: the slot's backend is the managed one.
        h.settings.orgMailboxID = String(repeating: "cd", count: 16)
        let published = ManagedAccountResume.backend(settings: h.settings, credentials: credentials, open: open)
        #expect(published is ManagedOrgBackend)
    }
}

/// A count bumped from a `@Sendable` closure.
private final class ResetCount: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    func bump() { lock.withLock { count += 1 } }
}
