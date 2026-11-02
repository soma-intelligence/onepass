import Foundation
import Testing

@testable import VaultKit

/// X1b Task 5: where the account lives, and the router that hands the session from one
/// coordinator to the other.
@Suite struct SyncRouterTests {
    private func mailboxCoordinator(_ fake: FakeMailboxSync) -> MailboxSyncCoordinator {
        MailboxSyncCoordinator(sync: fake, serverName: "Serveur OnePass", sleep: { _ in try await Task.sleep(for: .seconds(3600)) })
    }

    private func tempStore() throws -> (SyncStoreHandle, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-router-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (try openSyncStore(dbPath: dir.appendingPathComponent("v.db").path), dir)
    }

    private func session(in dir: URL) throws -> Session {
        try createAccountWithKdf(
            dbPath: dir.appendingPathComponent("s.db").path, password: "Lanterne vive 77 sur le quai !",
            kdf: FfiKdfParams(mKib: 8192, t: 1, p: 1)
        ).session
    }

    @Test func routerForwardsToCurrent() async {
        let fake = FakeMailboxSync()
        let router = SyncRouter(current: mailboxCoordinator(fake))
        await router.syncNow()
        #expect(fake.rounds == 1)
    }

    @Test func serverFlagFollowsCurrent() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let local = SyncCoordinator(store: store, remote: nil)
        let router = SyncRouter(current: local)
        #expect(!router.syncsWithServer)
        await router.switchTo(mailboxCoordinator(FakeMailboxSync()))
        #expect(router.syncsWithServer)
    }

    @Test func switchWaitsForRoundInProgress() async throws {
        let old = FakeMailboxSync()
        let new = FakeMailboxSync()
        let router = SyncRouter(current: mailboxCoordinator(old))
        old.holdNextRound()
        let first = Task { await router.syncNow() }
        try await waitUntil { old.rounds == 1 }
        let switching = Task { await router.switchTo(self.mailboxCoordinator(new)) }
        try await Task.sleep(for: .milliseconds(50))
        #expect(new.rounds == 0)
        old.release()
        await first.value
        await switching.value
        #expect(new.rounds >= 1)
    }

    @Test func switchHandsOverSession() async throws {
        let (_, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let old = FakeMailboxSync()
        let new = FakeMailboxSync()
        let router = SyncRouter(current: mailboxCoordinator(old))
        await router.sessionUnlocked(try session(in: dir))
        try await waitUntil { old.rounds >= 1 }
        await router.switchTo(mailboxCoordinator(new))
        #expect(new.sessions.allSatisfy { $0 })
        #expect(!new.sessions.isEmpty)
        await router.syncNow()
        let oldRounds = old.rounds
        await router.localChangesWritten()
        #expect(old.rounds == oldRounds)
    }

    @Test func switchKeepsStatusStream() async throws {
        let old = FakeMailboxSync()
        let new = FakeMailboxSync()
        new.script([FakeMailboxSync.report(.offline)])
        let router = SyncRouter(current: mailboxCoordinator(old))
        let statuses = await router.statusUpdates()
        await router.switchTo(mailboxCoordinator(new))
        var seenOffline = false
        for await s in statuses {
            if s == .offline {
                seenOffline = true
                break
            }
        }
        #expect(seenOffline)
    }

    @Test func resolverDefaultsToICloudForExistingStore() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(try await SyncBackendState.read(store: store) == .iCloud)
    }

    @Test func resolverReadsMailboxHome() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let home = MailboxHome(baseURL: URL(string: "https://mailbox.somalabs.me/functions/v1/mailbox")!, mailboxID: String(repeating: "ab", count: 16))
        try await SyncBackendState.write(.mailbox(home), store: store)
        #expect(try await SyncBackendState.read(store: store) == .mailbox(home))
        try await SyncBackendState.write(.pendingSetup(.hosted), store: store)
        #expect(try await SyncBackendState.read(store: store) == .pendingSetup(.hosted))
        #expect(SyncBackendState.mailbox(home).displayName(hosted: home.baseURL) == "Serveur OnePass")
        let selfHost = MailboxHome(baseURL: URL(string: "https://coffre.exemple.fr/mailbox")!, mailboxID: home.mailboxID)
        #expect(SyncBackendState.mailbox(selfHost).displayName(hosted: home.baseURL) == "coffre.exemple.fr")
        #expect(SyncBackendState.iCloud.displayName(hosted: nil) == "iCloud")
    }

    @Test func hostedURLFromInfoPlist() {
        // The test bundle carries no `OnePassMailboxURL`: no hosted instance, never a guess.
        #expect(MailboxEndpoints.hosted(bundle: Bundle(for: FakeMailboxSync.self)) == nil)
        #expect(MailboxEndpoints.validate(URL(string: "https://mailbox.somalabs.me/functions/v1/mailbox")!, allowHTTP: false))
    }

    @Test func releaseRefusesHTTP() {
        let local = MailboxEndpoints.localDebugURL
        #expect(!MailboxEndpoints.validate(local, allowHTTP: false))
        #expect(MailboxEndpoints.validate(local, allowHTTP: true))
        #expect(!MailboxEndpoints.validate(URL(string: "http://mailbox.somalabs.me/x")!, allowHTTP: true))
        #expect(!MailboxEndpoints.validate(URL(string: "https://u@mailbox.somalabs.me/x")!, allowHTTP: false))
        #expect(!MailboxEndpoints.validate(URL(string: "https://mailbox.somalabs.me/x?a=1")!, allowHTTP: false))
    }

    private func waitUntil(_ condition: @escaping () -> Bool) async throws {
        for _ in 0..<500 {
            if condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("condition not met")
    }
}
