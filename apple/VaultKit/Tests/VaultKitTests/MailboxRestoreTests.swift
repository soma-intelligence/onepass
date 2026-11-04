import Foundation
import Testing
@testable import VaultKit

/// X1b Task 7: restore a mailbox account from the Emergency Kit (cross-platform spec D.4).
@Suite("Mailbox restore")
struct MailboxRestoreTests {
    static let hosted = URL(string: "https://mailbox.somalabs.me/functions/v1/mailbox")!
    static let selfHost = URL(string: "https://vault.example.org/functions/v1/mailbox")!
    static let key = "A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-R"
    static let mailboxID = String(repeating: "ab", count: 16)

    let keychain = InMemoryKeychain()
    let provisioning = FakeMailboxProvisioning()

    var secretKey: SecretBytes { SecretBytes(copying: Data(Self.key.utf8)) }

    func restorer() -> MailboxRestore {
        MailboxRestore(provisioning: provisioning, credentials: MailboxCredentialStore(keychain: keychain), hosted: Self.hosted)
    }

    @Test func kitServerWins() async {
        provisioning.register([Self.mailboxID], at: Self.selfHost)
        provisioning.register(["cd" + String(repeating: "0", count: 30)], at: Self.hosted)
        let found = await restorer().locate(secretKey: secretKey, kitServer: Self.selfHost) { true }
        #expect(found == .mailbox(MailboxHome(baseURL: Self.selfHost, mailboxID: Self.mailboxID)))
        #expect(provisioning.calls == ["locate \(Self.selfHost.absoluteString)"])
    }

    @Test func locatorFoundOnHosted() async {
        provisioning.register([Self.mailboxID], at: Self.hosted)
        let found = await restorer().locate(secretKey: secretKey, kitServer: nil) { true }
        #expect(found == .mailbox(MailboxHome(baseURL: Self.hosted, mailboxID: Self.mailboxID)))
    }

    @Test func fallsBackToICloud() async {
        let found = await restorer().locate(secretKey: secretKey, kitServer: nil) { true }
        #expect(found == .iCloud)
    }

    @Test func notFoundSaysSo() async {
        let found = await restorer().locate(secretKey: secretKey, kitServer: nil) { false }
        #expect(found == .notFound)
    }

    @Test func offlineDuringLocateIsOffline() async {
        provisioning.failNext("locate \(Self.hosted.absoluteString)", OnePassError.MailboxUnavailable(reason: "unreachable"))
        let found = await restorer().locate(secretKey: secretKey, kitServer: nil) { false }
        #expect(found == .offline)
    }

    private func store() throws -> (SyncStoreHandle, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-restore-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let created = try createAccountOnCoreStack(
            dbPath: dir.appendingPathComponent("v.db").path, password: "Lanterne vive 77 sur le quai !",
            kdf: FfiKdfParams(mKib: 8192, t: 1, p: 1))
        _ = created
        return (try openSyncStore(dbPath: dir.appendingPathComponent("v.db").path), dir)
    }

    @Test func restoredDeviceUsesOwnCredential() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let session = try createAccountOnCoreStack(
            dbPath: dir.appendingPathComponent("other.db").path, password: "Lanterne vive 77 sur le quai !",
            kdf: FfiKdfParams(mKib: 8192, t: 1, p: 1)).session
        let home = MailboxHome(baseURL: Self.hosted, mailboxID: Self.mailboxID)
        _ = try await restorer().restore(home: home, secretKey: secretKey, store: store) { session }
        let recovery = try mailboxRecoveryCredential(secretKey: Self.key, mailboxId: Self.mailboxID)
        let stored = try MailboxCredentialStore(keychain: keychain).seed(mailboxID: Self.mailboxID)?.withData { $0 }
        #expect(stored != nil && stored != recovery.seed)
        #expect(provisioning.openedSeeds == [recovery.seed, stored!])
        #expect(provisioning.sync.grantedKeys.count == 1)
        // The rounds after the restore are the device's: one without a session (the recovery
        // fetch), then one with it.
        #expect(provisioning.sync.sessions == [false, true])
        #expect(try await SyncBackendState.read(store: store) == .mailbox(home))
        #expect(keychain.keys == [MailboxCredentialStore.key(mailboxID: Self.mailboxID)])
    }

    @Test func wrongPasswordLeavesNoCredential() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let home = MailboxHome(baseURL: Self.hosted, mailboxID: Self.mailboxID)
        await #expect(throws: OnePassError.WrongPassword) {
            _ = try await restorer().restore(home: home, secretKey: secretKey, store: store) {
                throw OnePassError.WrongPassword
            }
        }
        #expect(keychain.keys.isEmpty)
        #expect(provisioning.sync.grantedKeys.isEmpty)
        #expect(try await SyncBackendState.read(store: store) == .iCloud)
    }
}
