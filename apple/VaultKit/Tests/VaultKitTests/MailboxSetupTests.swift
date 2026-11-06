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
