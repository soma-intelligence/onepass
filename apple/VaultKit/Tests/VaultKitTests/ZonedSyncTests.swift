import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// Sharing plan 4, Task 5: the zone rounds after the private round (sharing spec 13.3 to 13.8).
/// A scripted `FakeZoneSync` stands for the core's `ZoneSyncHandle`.
@Suite struct ZonedSyncTests {
    private func store() throws -> (SyncStoreHandle, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-zones-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (try openSyncStore(dbPath: dir.appendingPathComponent("v.db").path), dir)
    }

    private func waitUntil(_ condition: @escaping () async -> Bool) async throws {
        for _ in 0..<500 {
            if await condition() { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("condition never met")
    }

    @Test func zonedRoundRunsAfterPrivate() async {
        let mailbox = FakeMailboxSync()
        let seen = Mutex<[Int]>([])
        let zones = FakeZoneSync(onRound: { seen.withLock { $0.append(mailbox.rounds) } })
        let sleeper = ManualSleeper()
        let c = MailboxSyncCoordinator(
            sync: mailbox, serverName: "Serveur OnePass", sleep: { try await sleeper.sleep($0) }, zones: zones)
        await c.syncNow()
        #expect(mailbox.rounds == 1)
        #expect(zones.rounds == 1)
        // The zone round saw the private round done.
        #expect(seen.withLock { $0 } == [1])
        // Locked: the zones round without a session too.
        #expect(zones.sessions == [false])
    }

    @Test func grantBeforeInviteShowsNothing() async throws {
        // The manager's grant reached the server, the invitation not yet: the round syncs the zone
        // and reports nothing for the screens.
        let zones = FakeZoneSync()
        let vault = FakeZoneSync.zone(.vault)
        zones.script([FakeZoneSync.report(zones: [(vault, .idle)])])
        let c = MailboxSyncCoordinator(sync: FakeMailboxSync(), serverName: "Serveur OnePass", zones: zones)
        await c.syncNow()
        let scheduler = try #require(c.zoneRounds)
        #expect(await scheduler.refusals.isEmpty)
        #expect(await scheduler.quotaFull.isEmpty)
        #expect(await c.status != .syncing)
    }

    @Test @MainActor func icloudAccountSharesThroughAnchor() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let remote = ProbeRemote(InMemoryRemote())
        let seen = Mutex<[Int]>([])
        let zones = FakeZoneSync(onRound: { seen.withLock { $0.append(remote.fetches) } })
        let sleeper = ManualSleeper()
        let c = SyncCoordinator(store: store, remote: remote, sleep: { try await sleeper.sleep($0) }, zones: zones)
        await c.syncNow()
        #expect(zones.rounds == 1)
        #expect(seen.withLock { $0.first ?? 0 } >= 1)
        sleeper.fire()
    }

    @Test func quotaExceededDuringRemovalRetries() async throws {
        let zones = FakeZoneSync()
        let vault = FakeZoneSync.zone(.vault)
        zones.script([
            FakeZoneSync.report(zones: [(vault, .retrying)], quotaFull: [vault], retryAfter: 60),
            FakeZoneSync.report(zones: [(vault, .idle)], actions: 1),
        ])
        let sleeper = ManualSleeper()
        let c = MailboxSyncCoordinator(
            sync: FakeMailboxSync(), serverName: "Serveur OnePass", sleep: { try await sleeper.sleep($0) }, zones: zones)
        await c.syncNow()
        let scheduler = try #require(c.zoneRounds)
        #expect(await scheduler.quotaFull == [vault])
        #expect(sleeper.requests.contains(.seconds(60)))
        sleeper.fire()
        try await waitUntil { zones.rounds == 2 }
        try await waitUntil { await scheduler.quotaFull.isEmpty }
    }

    @Test func unreachableZoneDoesNotStopOthers() async throws {
        let zones = FakeZoneSync()
        let (a, b) = (FakeZoneSync.zone(.vault, 1), FakeZoneSync.zone(.contact, 2))
        zones.script([FakeZoneSync.report(zones: [(a, .offline), (b, .idle)], changed: true)])
        let c = MailboxSyncCoordinator(sync: FakeMailboxSync(), serverName: "Serveur OnePass", zones: zones)
        let scheduler = try #require(c.zoneRounds)
        let changes = await scheduler.remoteChanges()
        await c.syncNow()
        // The private status stays the private round's.
        if case .idle = await c.status {} else { Issue.record("private status changed") }
        let report = try #require(await scheduler.lastReport)
        #expect(report.zones.map(\.status) == [.offline, .idle])
        var it = changes.makeAsyncIterator()
        #expect(await it.next() != nil)
    }

    @Test func unconfirmedRefusalShowsServerRefused() async throws {
        let zones = FakeZoneSync()
        let vault = FakeZoneSync.zone(.vault)
        zones.script([FakeZoneSync.report(refusals: [FfiZoneRefusal(zone: vault, removed: false)])])
        let c = MailboxSyncCoordinator(sync: FakeMailboxSync(), serverName: "Serveur OnePass", zones: zones)
        await c.syncNow()
        let scheduler = try #require(c.zoneRounds)
        #expect(await scheduler.refusals == [ZoneRefusal(zone: vault, removed: false)])
    }

    @Test func wakeOnZoneTopicRunsZoneRound() async throws {
        let zones = FakeZoneSync()
        let wake = FakeZoneSync.wake(9, zone: FakeZoneSync.zone(.vault))
        zones.setTopics([wake])
        let sleeper = ManualSleeper()
        let c = MailboxSyncCoordinator(
            sync: FakeMailboxSync(), serverName: "Serveur OnePass", sleep: { try await sleeper.sleep($0) }, zones: zones)
        await c.enterForeground()
        try await waitUntil { zones.wakeListeners == 1 }
        let before = zones.rounds
        zones.wake(mailbox: wake.wake.topic)
        try await waitUntil { zones.rounds > before }
        await c.enterBackground()
        #expect(zones.wakeListeners == 0)
    }

    @Test func pushTargetRegisteredPerZone() async throws {
        let (store, dir) = try store()
        defer { try? FileManager.default.removeItem(at: dir) }
        let zones = FakeZoneSync()
        let (w1, w2) = (FakeZoneSync.wake(1, zone: FakeZoneSync.zone(.vault, 1)),
                        FakeZoneSync.wake(2, zone: FakeZoneSync.zone(.contact, 2)))
        zones.setTopics([w1, w2])
        let push = PushRegistration(sync: FakeMailboxSync(), store: store, zones: zones)
        await push.didRegister(token: Data([1, 2, 3]))
        await push.didRegister(token: Data([1, 2, 3]))
        let targets = zones.targets
        #expect(targets.map(\.0) == [w1.mailboxId, w2.mailboxId])
        // One random tag per mailbox, kept: never the same for two mailboxes.
        #expect(targets.allSatisfy { $0.1.count == 16 })
        #expect(targets[0].1 != targets[1].1)
        #expect(try store.meta(key: PushRegistration.zoneTagKey(w1.mailboxId)) == targets[0].1)
        // A new token goes to every zone again, under the same tags.
        await push.didRegister(token: Data([4]))
        #expect(zones.targets.count == 4)
        #expect(zones.targets[2].1 == targets[0].1)
        // An iCloud account (no mailbox of its own) still registers its zones.
        let (store2, dir2) = try self.store()
        defer { try? FileManager.default.removeItem(at: dir2) }
        let zones2 = FakeZoneSync()
        zones2.setTopics([w1])
        await PushRegistration(sync: nil, store: store2, zones: zones2).didRegister(token: Data([1]))
        #expect(zones2.targets.count == 1)
    }

    @Test func seedCachedAfterFirstUnlock() throws {
        let keychain = InMemoryKeychain()
        let seeds = ZoneSeedKeychain(keychain: keychain)
        let id = Data(repeating: 0xAB, count: 16)
        seeds.put(mailboxId: id, seed: Data(repeating: 7, count: 32))
        let key = "mailbox.zone." + String(repeating: "ab", count: 16)
        #expect(ZoneSeedKeychain.key(mailboxID: id) == key)
        #expect(keychain.isAfterFirstUnlock(key))
        #expect(seeds.get(mailboxId: id) == Data(repeating: 7, count: 32))
        seeds.delete(mailboxId: id)
        #expect(seeds.get(mailboxId: id) == nil)
    }
}
