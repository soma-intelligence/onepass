import Foundation
import Testing

@testable import VaultKit

/// X1b Task 4: the scheduler of the mailbox rounds. The round is the core's; a scripted
/// `FakeMailboxSync` stands for it.
@Suite struct MailboxSyncCoordinatorTests {
    private func coordinator(_ fake: FakeMailboxSync, sleeper: ManualSleeper = ManualSleeper()) -> MailboxSyncCoordinator {
        MailboxSyncCoordinator(sync: fake, serverName: "Serveur OnePass", sleep: { try await sleeper.sleep($0) })
    }

    @Test func roundStatusMapping() async {
        let cases: [(FfiRoundStatus, (SyncStatus) -> Bool)] = [
            (.idle, { if case .idle(let d) = $0 { d != nil } else { false } }),
            (.offline, { $0 == .offline }),
            (.retrying, { $0 == .error(MailboxSyncCoordinator.retryingMessage) }),
            (.clockSkew, { $0 == .error(MailboxSyncCoordinator.clockSkewMessage) }),
            (.waitingForServer, { $0 == .waitingForMailbox }),
            (.refused(kind: "Rollback"), { $0 == .refused(kind: "Rollback") }),
            (.unsettled, { $0 == .syncing }),
            (.unreadable, { $0 == .error(MailboxSyncCoordinator.unreadableMessage) }),
            (.homeMoved(baseUrl: "https://boite.exemple.fr/functions/v1/mailbox"), { $0 == .homeMoved(server: "boite.exemple.fr") }),
            (.homeMoved(baseUrl: nil), { $0 == .homeMoved(server: "iCloud") }),
        ]
        for (ffi, check) in cases {
            let fake = FakeMailboxSync()
            fake.script([FakeMailboxSync.report(ffi)])
            let c = coordinator(fake)
            await c.syncNow()
            let status = await c.status
            #expect(check(status), "\(ffi) gave \(status)")
        }
    }

    @Test func retryAfterHonoured() async throws {
        let fake = FakeMailboxSync()
        let sleeper = ManualSleeper()
        fake.script([FakeMailboxSync.report(.retrying, retryAfter: 42), FakeMailboxSync.report(.offline)])
        let c = coordinator(fake, sleeper: sleeper)
        await c.syncNow()
        #expect(sleeper.requests == [.seconds(42)])
        sleeper.fire()
        try await waitUntil { fake.rounds == 2 }
        try await waitUntil { sleeper.requests.count == 2 }
        // No server delay: the backoff's first step.
        #expect(sleeper.requests.last == SyncCoordinator.retryDelays[0])
    }

    @Test func rerunRunsImmediately() async {
        let fake = FakeMailboxSync()
        fake.script([FakeMailboxSync.report(.idle, rerun: true)])
        let c = coordinator(fake)
        await c.syncNow()
        #expect(fake.rounds == 2)
    }

    @Test func clockSkewShowsMessage() async {
        let fake = FakeMailboxSync()
        fake.script([FakeMailboxSync.report(.clockSkew)])
        let c = coordinator(fake)
        await c.syncNow()
        #expect(await c.status.label == MailboxSyncCoordinator.clockSkewMessage)
    }

    @Test func homeMovedStopsRounds() async {
        let fake = FakeMailboxSync()
        fake.script([FakeMailboxSync.report(.homeMoved(baseUrl: nil), rerun: true)])
        let c = coordinator(fake)
        await c.enterForeground()
        await c.syncNow()
        let before = fake.rounds
        await c.syncNow()
        await c.localChangesWritten()
        await c.enterForeground()
        #expect(fake.rounds == before)
        #expect(await c.homeMoved)
        #expect(fake.wakeListeners == 0)
    }

    @Test func lockedRoundPassesNilSession() async throws {
        let fake = FakeMailboxSync()
        let c = coordinator(fake)
        await c.syncNow()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-mbx-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let created = try createAccountWithKdf(
            dbPath: dir.appendingPathComponent("v.db").path, password: "Lanterne vive 77 sur le quai !",
            kdf: FfiKdfParams(mKib: 8192, t: 1, p: 1))
        await c.sessionUnlocked(created.session)
        await c.syncNow()
        await c.sessionLocked()
        await c.syncNow()
        #expect(fake.sessions.first == false)
        #expect(fake.sessions.contains(true))
        #expect(fake.sessions.last == false)
    }

    @Test func wakeKicksARound() async throws {
        let fake = FakeMailboxSync()
        let c = coordinator(fake)
        await c.enterForeground()
        try await waitUntil { fake.rounds == 1 }
        #expect(fake.wakeListeners == 1)
        fake.wake()
        try await waitUntil { fake.rounds == 2 }
    }

    @Test func backgroundStopsWake() async throws {
        let fake = FakeMailboxSync()
        let c = coordinator(fake)
        await c.enterForeground()
        try await waitUntil { fake.rounds == 1 }
        await c.enterBackground()
        #expect(fake.wakeStops == 1)
        #expect(fake.wakeListeners == 0)
    }

    @Test func oneRoundAtATime() async throws {
        let fake = FakeMailboxSync()
        let c = coordinator(fake)
        fake.holdNextRound()
        async let first: Void = c.syncNow()
        try await waitUntil { fake.rounds == 1 }
        async let second: Void = c.syncNow()
        try await Task.sleep(for: .milliseconds(50))
        #expect(fake.rounds == 1)
        fake.release()
        _ = await (first, second)
        #expect(fake.rounds == 2)
        #expect(fake.maxRunning == 1)
    }

    @Test func changedRoundsAreAnnounced() async throws {
        let fake = FakeMailboxSync()
        fake.script([FakeMailboxSync.report(.idle, changed: true)])
        let c = coordinator(fake)
        let changes = await c.remoteChanges()
        await c.syncNow()
        var it = changes.makeAsyncIterator()
        #expect(await it.next() != nil)
    }

    @Test func credentialSeedStoredAfterFirstUnlock() throws {
        let keychain = InMemoryKeychain()
        let store = MailboxCredentialStore(keychain: keychain)
        let id = String(repeating: "ab", count: 16)
        try store.store(seed: SecretBytes(copying: Data(repeating: 7, count: 32)), mailboxID: id)
        #expect(keychain.isAfterFirstUnlock("mailbox.credential.\(id)"))
        #expect(try store.seed(mailboxID: id)?.withData { $0 } == Data(repeating: 7, count: 32))
        try store.delete(mailboxID: id)
        #expect(try store.seed(mailboxID: id) == nil)
    }

    private func waitUntil(_ condition: @escaping () -> Bool) async throws {
        for _ in 0..<500 {
            if condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("condition not met")
    }
}
