import Foundation
import Testing
@testable import VaultKit

/// X1b Task 10: silent APNs wakes (cross-platform spec 4.10).
@Suite("Push registration")
struct PushRegistrationTests {
    private func store() throws -> (SyncStoreHandle, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-push-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (try openSyncStore(dbPath: dir.appendingPathComponent("v.db").path), dir)
    }

    @Test func pushTokenSentOnce() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = FakeMailboxSync()
        let push = PushRegistration(sync: fake, store: store)
        await push.didRegister(token: Data([1, 2, 3]))
        await push.didRegister(token: Data([1, 2, 3]))
        // A relaunch: same store, same token.
        await PushRegistration(sync: fake, store: store).didRegister(token: Data([1, 2, 3]))
        #expect(fake.pushes.count == 1)
        #expect(fake.pushes.first?.0 == .apns)
        // The store keeps a digest, never the token.
        #expect(try store.meta(key: PushRegistration.metaKey) != Data([1, 2, 3]))
    }

    @Test func pushTokenChangeSentAgain() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = FakeMailboxSync()
        let push = PushRegistration(sync: fake, store: store)
        await push.didRegister(token: Data([1]))
        await push.didRegister(token: Data([2]))
        #expect(fake.pushes.map(\.1) == [Data([1]), Data([2])])
    }

    @Test func pushDeniedFallsBackToOpenFetch() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = FakeMailboxSync()
        let push = PushRegistration(sync: fake, store: store)
        let coordinator = MailboxSyncCoordinator(sync: fake, serverName: "test")
        await push.didFail()
        #expect(await coordinator.status == .idle(lastSync: nil))
        // The opening still syncs.
        await coordinator.enterForeground()
        await coordinator.syncNow()
        #expect(fake.rounds >= 1)
        if case .idle = await coordinator.status {} else { Issue.record("status") }
        #expect(fake.pushes.isEmpty)
    }

    @Test func silentPushRunsRound() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = FakeMailboxSync()
        let coordinator = MailboxSyncCoordinator(sync: fake, serverName: "test")
        let push = PushRegistration(sync: fake, store: store)
        #expect(await push.didReceiveSilent { await coordinator.syncNow() })
        #expect(fake.rounds == 1)
    }

    @Test(.tags(.slow)) func silentPushBudgetRespected() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = FakeMailboxSync()
        let push = PushRegistration(sync: fake, store: store, budget: .milliseconds(50))
        let started = ContinuousClock.now
        let finished = await push.didReceiveSilent {
            try? await Task.sleep(for: .seconds(5))
        }
        #expect(!finished)
        #expect(ContinuousClock.now - started < .seconds(4))
    }
}
