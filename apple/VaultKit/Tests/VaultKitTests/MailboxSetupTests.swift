import Foundation
import Testing
@testable import VaultKit

/// X1b Task 6: a new account on the mailbox (cross-platform spec D.2, D.4).
@Suite("Mailbox setup")
struct MailboxSetupTests {
    static let hosted = URL(string: "https://mailbox.somalabs.me/functions/v1/mailbox")!

    /// A fresh account, its sync store and a keychain, in a temporary directory.
    final class Fixture {
        let dir: URL
        let store: SyncStoreHandle
        let session: Session
        let secretKey: SecretBytes
        let keychain = InMemoryKeychain()
        let provisioning = FakeMailboxProvisioning()

        init() throws {
            dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-setup-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let db = dir.appendingPathComponent("v.db").path
            let created = try createAccountOnCoreStack(
                dbPath: db, password: "Lanterne vive 77 sur le quai !", kdf: FfiKdfParams(mKib: 8192, t: 1, p: 1))
            session = created.session
            secretKey = SecretBytes(copying: Data(created.secretKey.utf8))
            store = try openSyncStore(dbPath: db)
        }

        var credentials: MailboxCredentialStore { MailboxCredentialStore(keychain: keychain) }

        func setup() -> MailboxSetup {
            MailboxSetup(provisioning: provisioning, credentials: credentials, store: store, hosted: MailboxSetupTests.hosted)
        }

        deinit { try? FileManager.default.removeItem(at: dir) }
    }

    @Test func defaultChoiceIsHosted() {
        #expect(SyncChoice.default == .hosted)
    }

    @Test func setupRunsAllStepsOnce() async throws {
        let f = try Fixture()
        let outcome = await f.setup().run(session: f.session, choice: .hosted, secretKey: f.secretKey)
        guard case .ready(let home) = outcome else { Issue.record("\(outcome)"); return }
        #expect(home.baseURL == Self.hosted)
        #expect(f.provisioning.calls == ["credential", "create", "open"])
        #expect(f.provisioning.sync.calls == ["grant", "locator"])
        #expect(f.provisioning.sync.grantedKeys.count == 1)
        #expect(f.provisioning.sync.locators.count == 1)
        let signed = try f.session.syncHome()
        #expect(signed?.backend == home.backend)
        #expect(try await SyncBackendState.read(store: f.store) == .mailbox(home))
        // Run again: nothing is created twice.
        let again = await f.setup().run(session: f.session, choice: .hosted, secretKey: f.secretKey)
        #expect(again == .ready(home))
        #expect(f.provisioning.mailboxesCreated == 1)
        #expect(f.provisioning.sync.grantedKeys.count == 1)
    }

    @Test(arguments: [
        MailboxSetup.Step.credential, .created, .recoveryGranted, .locatorSet, .homeAdopted,
    ])
    func setupResumesAfterCutAtEachStep(_ step: MailboxSetup.Step) async throws {
        let f = try Fixture()
        let first = f.setup()
        await first.setInterruptAfter(step)
        #expect(await first.run(session: f.session, choice: .hosted, secretKey: f.secretKey) == .failed("interrupted"))
        // A relaunch: a new setup on the same store.
        let outcome = await f.setup().run(session: f.session, choice: .hosted, secretKey: f.secretKey)
        guard case .ready = outcome else { Issue.record("\(outcome)"); return }
        #expect(f.provisioning.mailboxesCreated == 1)
        #expect(f.provisioning.sync.grantedKeys.count == 1)
        #expect(f.provisioning.sync.locators.count >= 1)
    }

    @Test func offlineLeavesAccountLocalAndRetries() async throws {
        let f = try Fixture()
        f.provisioning.failNext("create", OnePassError.MailboxUnavailable(reason: "unreachable"))
        #expect(await f.setup().run(session: f.session, choice: .hosted, secretKey: f.secretKey) == .offline)
        #expect(try await SyncBackendState.read(store: f.store) == .pendingSetup(.hosted))
        #expect(try f.session.syncHome() == nil)
        let outcome = await f.setup().run(session: f.session, choice: .hosted, secretKey: f.secretKey)
        guard case .ready = outcome else { Issue.record("\(outcome)"); return }
        #expect(f.provisioning.mailboxesCreated == 1)

        // Offline at the locator: the step reached is kept.
        let g = try Fixture()
        g.provisioning.sync.failNextLocator(OnePassError.MailboxUnavailable(reason: "unreachable"))
        #expect(await g.setup().run(session: g.session, choice: .hosted, secretKey: g.secretKey) == .offline)
        let resumed = await g.setup().run(session: g.session, choice: .hosted, secretKey: g.secretKey)
        guard case .ready = resumed else { Issue.record("\(resumed)"); return }
        #expect(g.provisioning.mailboxesCreated == 1)
        #expect(g.provisioning.sync.grantedKeys.count == 1)
    }

    @Test func iCloudChoiceTouchesNoServer() async throws {
        let f = try Fixture()
        #expect(await f.setup().run(session: f.session, choice: .iCloud, secretKey: f.secretKey) == .iCloud)
        #expect(f.provisioning.calls.isEmpty)
        #expect(f.provisioning.sync.calls.isEmpty)
        #expect(try await SyncBackendState.read(store: f.store) == .iCloud)
    }

    @Test func recoverySeedNeverStored() async throws {
        let f = try Fixture()
        let outcome = await f.setup().run(session: f.session, choice: .hosted, secretKey: f.secretKey)
        guard case .ready(let home) = outcome else { Issue.record("\(outcome)"); return }
        #expect(f.keychain.keys == [MailboxCredentialStore.key(mailboxID: home.mailboxID)])
        // The device seed is not the recovery one.
        let key = f.secretKey.withData { String(decoding: $0, as: UTF8.self) }
        let recovery = try mailboxRecoveryCredential(secretKey: key, mailboxId: home.mailboxID)
        #expect(try f.credentials.seed(mailboxID: home.mailboxID)?.withData { $0 } != recovery.seed)
        #expect(f.provisioning.sync.grantedKeys == [recovery.publicKey])
    }

    @Test func selfHostKitCarriesServerLine() throws {
        let key = "A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-R"
        let server = URL(string: "https://vault.example.org/functions/v1/mailbox")!
        let payload = EmergencyKit.qrPayload(secretKey: key, server: server)
        let parsed = EmergencyKit.parseKit(payload)
        #expect(parsed?.server == server)
        #expect(parsed?.secretKey == EmergencyKit.parsePayload(payload))
        let pdf = try EmergencyKit.pdf(
            secretKey: key, accountID: "acc", displayName: "Léa", createdAt: Date(timeIntervalSince1970: 0),
            server: server)
        #expect(!pdf.isEmpty)
        // A payload whose server is not https keeps the key and drops the server.
        let http = EmergencyKit.qrPayload(secretKey: key, server: URL(string: "http://vault.example.org")!)
        #expect(EmergencyKit.parseKit(http)?.server == nil)
        #expect(EmergencyKit.parseKit(http)?.secretKey != nil)
    }

    @Test func hostedKitUnchanged() {
        let key = "A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-R"
        #expect(EmergencyKit.qrPayload(secretKey: key, server: nil) == EmergencyKit.qrPayload(secretKey: key))
        #expect(EmergencyKit.qrPayload(secretKey: key) == "onepass-kit:1:" + key.replacingOccurrences(of: "-", with: ""))
    }

    // MARK: - Managed accounts (R32, R36)

    static let org = URL(string: "https://onepass.example.org/functions/v1/mailbox")!
    static let orgChoice = SyncChoice.selfHost(url: org, extraCAPEM: nil)

    /// A managed setup of slot `s1` (its own pending seed slot).
    static func managedSetup(_ f: Fixture, token: Data?) -> MailboxSetup {
        MailboxSetup(
            provisioning: f.provisioning, credentials: f.credentials, store: f.store, hosted: nil,
            memberToken: token.map { SecretBytes(copying: $0) }, managed: true,
            pendingCredentialID: MailboxSetup.pendingCredentialID(slot: "s1"))
    }

    @Test func managedSetupSpendsTheTokenOnTheOrgServer() async throws {
        let f = try Fixture()
        let token = Data(repeating: 7, count: 32)
        let outcome = await Self.managedSetup(f, token: token).run(
            session: f.session, choice: Self.orgChoice, secretKey: f.secretKey)
        guard case .ready(let home) = outcome else { Issue.record("\(outcome)"); return }
        #expect(home.baseURL == Self.org)
        #expect(f.provisioning.calls == ["credential", "createManaged", "checkManaged", "open"])
        #expect(f.provisioning.tokens == [token])
        #expect(f.provisioning.checked == [home.mailboxID])
    }

    @Test func managedSetupKeepsItsPendingSeedApartFromThePrimary() async throws {
        let f = try Fixture()
        let primary = SecretBytes(copying: Data(repeating: 1, count: 32))
        try f.credentials.store(seed: primary, mailboxID: MailboxSetup.pendingID)
        let setup = Self.managedSetup(f, token: Data(repeating: 7, count: 32))
        await setup.setInterruptAfter(.credential)
        _ = await setup.run(session: f.session, choice: Self.orgChoice, secretKey: f.secretKey)
        let managed = try #require(try f.credentials.seed(mailboxID: MailboxSetup.pendingCredentialID(slot: "s1")))
        let kept = try #require(try f.credentials.seed(mailboxID: MailboxSetup.pendingID))
        #expect(kept.withData { $0 } == Data(repeating: 1, count: 32))
        #expect(managed.withData { $0 } != kept.withData { $0 })
    }

    @Test func aSpentTokenIsRefusedAndItsSeedDropped() async throws {
        let f = try Fixture()
        f.provisioning.failNext(
            "createManaged", OnePassError.Validation(field: "member token", reason: "spent"))
        let outcome = await Self.managedSetup(f, token: Data(repeating: 7, count: 32)).run(
            session: f.session, choice: Self.orgChoice, secretKey: f.secretKey)
        #expect(outcome == .tokenRefused)
        #expect(try f.credentials.seed(mailboxID: MailboxSetup.pendingCredentialID(slot: "s1")) == nil)
        #expect(MailboxSetup.progressMailboxIDNow(store: f.store) == nil)
        // A new token starts over on a new credential.
        let again = await Self.managedSetup(f, token: Data(repeating: 8, count: 32)).run(
            session: f.session, choice: Self.orgChoice, secretKey: f.secretKey)
        guard case .ready = again else { Issue.record("\(again)"); return }
        #expect(f.provisioning.calls.filter { $0 == "credential" }.count == 2)
    }

    @Test func aMailboxOffTheManagedPlanIsRefused() async throws {
        let f = try Fixture()
        f.provisioning.failNext(
            "checkManaged", OnePassError.Validation(field: "mailbox plan", reason: "not the managed plan"))
        let outcome = await Self.managedSetup(f, token: Data(repeating: 7, count: 32)).run(
            session: f.session, choice: Self.orgChoice, secretKey: f.secretKey)
        #expect(outcome == .tokenRefused)
        let made = try #require(f.provisioning.checked.first)
        #expect(try f.credentials.seed(mailboxID: made) == nil)
        #expect(!f.provisioning.calls.contains("open"))
    }

    /// The mailbox is recorded before its plan check: a cut there, or an offline check, resumes on the
    /// same mailbox (no second token spent).
    @Test func aCutAfterCreationChecksTheSameMailboxAgain() async throws {
        let f = try Fixture()
        let first = Self.managedSetup(f, token: Data(repeating: 7, count: 32))
        await first.setInterruptAfter(.created)
        #expect(await first.run(session: f.session, choice: Self.orgChoice, secretKey: f.secretKey)
            == .failed("interrupted"))
        let made = try #require(MailboxSetup.progressMailboxIDNow(store: f.store))
        #expect(try f.credentials.seed(mailboxID: made) != nil)
        f.provisioning.failNext("checkManaged", OnePassError.MailboxUnavailable(reason: "unreachable"))
        // The token is gone by now: none is needed past the creation.
        #expect(await Self.managedSetup(f, token: nil).run(
            session: f.session, choice: Self.orgChoice, secretKey: f.secretKey) == .offline)
        let outcome = await Self.managedSetup(f, token: nil).run(
            session: f.session, choice: Self.orgChoice, secretKey: f.secretKey)
        guard case .ready(let home) = outcome else { Issue.record("\(outcome)"); return }
        #expect(home.mailboxID == made)
        #expect(f.provisioning.calls.filter { $0 == "createManaged" }.count == 1)
        #expect(f.provisioning.checked == [made, made])
    }

    // MARK: - Member token policy (ManagedMailboxSetup)

    private static func settings() -> VaultSettings {
        VaultSettings(defaults: UserDefaults(suiteName: "onepass-managed-\(UUID().uuidString)")!, scope: "s1")
    }

    @MainActor
    @Test func aCreatorMintsAgainOnceAfterARefusedToken() async throws {
        let f = try Fixture()
        let settings = Self.settings()
        settings.orgCreator = true
        let credentials = ManagedOrgCredentials(keychain: f.keychain, slot: "s1")
        try credentials.storeMemberToken(SecretBytes(copying: Data(repeating: 7, count: 32)))
        f.provisioning.failNext("createManaged", OnePassError.Validation(field: "member token", reason: "spent"))
        var mints = 0
        let outcome = await ManagedMailboxSetup.run(
            settings: settings, credentials: credentials,
            mint: {
                mints += 1
                return SecretBytes(copying: Data(repeating: 9, count: 32))
            },
            makeSetup: { token in
                MailboxSetup(
                    provisioning: f.provisioning, credentials: f.credentials, store: f.store, hosted: nil,
                    memberToken: token, managed: true, pendingCredentialID: MailboxSetup.pendingCredentialID(slot: "s1"))
            },
            perform: { await $0.run(session: f.session, choice: Self.orgChoice, secretKey: f.secretKey) })
        guard case .ready? = outcome else { Issue.record("\(String(describing: outcome))"); return }
        #expect(mints == 1)
        // The stored token was tried and refused, then the minted one made the mailbox.
        #expect(f.provisioning.calls.filter { $0 == "createManaged" }.count == 2)
        #expect(f.provisioning.tokens == [Data(repeating: 9, count: 32)])
        #expect(try credentials.memberToken() == nil)
        #expect(!settings.orgMemberTokenRefused)
    }

    @MainActor
    @Test func aJoinerWithARefusedTokenWaitsForANewLink() async throws {
        let f = try Fixture()
        let settings = Self.settings()
        let credentials = ManagedOrgCredentials(keychain: f.keychain, slot: "s1")
        try credentials.storeMemberToken(SecretBytes(copying: Data(repeating: 7, count: 32)))
        f.provisioning.failNext("createManaged", OnePassError.Validation(field: "member token", reason: "spent"))
        var runs = 0
        let makeSetup: @MainActor (SecretBytes?) -> MailboxSetup = { token in
            MailboxSetup(
                provisioning: f.provisioning, credentials: f.credentials, store: f.store, hosted: nil,
                memberToken: token, managed: true, pendingCredentialID: MailboxSetup.pendingCredentialID(slot: "s1"))
        }
        let perform: @MainActor (MailboxSetup) async -> MailboxSetupOutcome? = { setup in
            runs += 1
            return await setup.run(session: f.session, choice: Self.orgChoice, secretKey: f.secretKey)
        }
        let first = await ManagedMailboxSetup.run(
            settings: settings, credentials: credentials, mint: nil, makeSetup: makeSetup, perform: perform)
        #expect(first == .tokenRefused)
        #expect(settings.orgMemberTokenRefused)
        #expect(try credentials.memberToken() == nil)
        // The next unlock stops at the flag: nothing is retried.
        let second = await ManagedMailboxSetup.run(
            settings: settings, credentials: credentials, mint: nil, makeSetup: makeSetup, perform: perform)
        #expect(second == .tokenRefused)
        #expect(runs == 1)
        #expect(f.provisioning.calls.filter { $0 == "createManaged" }.count == 1)
    }

    @Test func selfHostURLValidated() async throws {
        let f = try Fixture()
        let bad = URL(string: "ftp://vault.example.org")!
        let outcome = await f.setup().run(session: f.session, choice: .selfHost(url: bad, extraCAPEM: nil), secretKey: f.secretKey)
        #expect(outcome == .failed(MailboxSetup.badURLMessage))
        #expect(f.provisioning.calls.isEmpty)
        #expect(!MailboxEndpoints.validate(URL(string: "https://user@vault.example.org")!, allowHTTP: false))
        #expect(MailboxEndpoints.validate(URL(string: "https://vault.example.org/functions/v1/mailbox")!, allowHTTP: false))
    }
}
