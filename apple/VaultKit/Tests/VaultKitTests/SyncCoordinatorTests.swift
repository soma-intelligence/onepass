import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// Sleeps that only end when the test says so. Every requested duration is recorded.
final class ManualSleeper: Sendable {
    private struct State {
        var requests: [Duration] = []
        var waiting: [CheckedContinuation<Void, Never>] = []
    }
    private let state = Mutex(State())

    var requests: [Duration] { state.withLock { $0.requests } }

    func sleep(_ duration: Duration) async throws {
        await withCheckedContinuation { continuation in
            state.withLock {
                $0.requests.append(duration)
                $0.waiting.append(continuation)
            }
        }
        try Task.checkCancellation()
    }

    /// Ends every sleep in progress.
    func fire() {
        let waiting = state.withLock { s -> [CheckedContinuation<Void, Never>] in
            defer { s.waiting = [] }
            return s.waiting
        }
        for continuation in waiting { continuation.resume() }
    }

    deinit { fire() }
}

/// One simulated device: its own store file, keychain, settings, coordinator and session,
/// talking to a shared `InMemoryRemote` through its own client (own change cursor).
@MainActor
final class SyncDevice {
    let dir: URL
    let suite: String
    let keychain = InMemoryKeychain()
    let settings: VaultSettings
    let store: SyncStoreHandle
    let coordinator: SyncCoordinator
    let session: VaultSession
    let sleeper: ManualSleeper

    convenience init(remote: InMemoryRemote?, name: String) throws {
        try self.init(name: name, client: remote.map { $0.client(name) })
    }

    init(name: String, client: (any RemoteRecordStore)?, sleeper: ManualSleeper = ManualSleeper()) throws {
        self.sleeper = sleeper
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-sync-\(name)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        suite = "onepass.tests.sync.\(UUID().uuidString)"
        settings = VaultSettings(defaults: UserDefaults(suiteName: suite)!)
        let databaseURL = dir.appendingPathComponent("vault.sqlite")
        store = try openSyncStore(dbPath: databaseURL.path)
        coordinator = SyncCoordinator(
            store: store, remote: client,
            sleep: { try await sleeper.sleep($0) })
        let clock = FakeClock()
        let environment = VaultEnvironment(
            databaseURL: databaseURL,
            keychain: keychain,
            biometrics: BiometricUnlock(keyring: FakeEnclaveKeyring(), keychain: keychain, clock: clock),
            settings: settings,
            sync: coordinator,
            clock: clock,
            pasteboard: FakePasteboard(),
            accountKdf: SessionHarness.fastKdf)
        session = VaultSession(environment: environment)
    }

    var secretKey: String? {
        guard let accountID = settings.accountID else { return nil }
        return try? SecretKeyVault(keychain: keychain).load(accountID: accountID)
    }

    var titles: Set<String> { Set(session.summaries.map(\.title)) }

    func pendingChanges() async throws -> [FfiRecordChange] {
        let store = store
        return try await CoreThread.run { try store.pendingChanges() }
    }

    /// Delivers the session's sync notifications, then runs a full round.
    func sync() async {
        await session.waitForSyncNotifications()
        await coordinator.syncNow()
    }

    func cleanUp() {
        sleeper.fire()
        UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: dir)
    }
}

/// Wraps a remote: counts calls and concurrent fetches, runs a hook before the first send.
final class ProbeRemote: RemoteRecordStore {
    private struct State {
        var fetches = 0
        var sends = 0
        var inFlight = 0
        var maxInFlight = 0
        var results: [[SendResult]] = []
        var hook: (@Sendable () async -> Void)?
    }
    let inner: any RemoteRecordStore
    let fetchDelay: Duration
    private let state = Mutex(State())

    init(_ inner: any RemoteRecordStore, fetchDelay: Duration = .zero) {
        self.inner = inner
        self.fetchDelay = fetchDelay
    }

    var fetches: Int { state.withLock { $0.fetches } }
    var sends: Int { state.withLock { $0.sends } }
    var maxInFlight: Int { state.withLock { $0.maxInFlight } }
    var results: [[SendResult]] { state.withLock { $0.results } }
    func beforeFirstSend(_ hook: @escaping @Sendable () async -> Void) { state.withLock { $0.hook = hook } }

    func fetchChanges() async throws -> RemoteBatch {
        state.withLock {
            $0.fetches += 1
            $0.inFlight += 1
            $0.maxInFlight = max($0.maxInFlight, $0.inFlight)
        }
        defer { state.withLock { $0.inFlight -= 1 } }
        if fetchDelay > .zero { try await Task.sleep(for: fetchDelay) }
        return try await inner.fetchChanges()
    }

    func send(_ changes: [RemoteRecord]) async throws -> [SendResult] {
        let hook = state.withLock { s -> (@Sendable () async -> Void)? in
            s.sends += 1
            defer { s.hook = nil }
            return s.hook
        }
        await hook?()
        let results = try await inner.send(changes)
        state.withLock { $0.results.append(results) }
        return results
    }

    func accountAvailable() async -> Bool { await inner.accountAvailable() }
}

/// Polls `condition` for up to 10 s.
@MainActor
func eventually(_ condition: () async -> Bool) async -> Bool {
    for _ in 0..<1000 {
        if await condition() { return true }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return await condition()
}

extension SyncStatus {
    var isIdle: Bool {
        if case .idle = self { true } else { false }
    }
}

@MainActor
@discardableResult
func rename(_ session: VaultSession, itemID: String, vaultID: String, to title: String) async throws -> FfiItem {
    var item = try await session.loadItem(vaultID: vaultID, itemID: itemID)
    item.title = title
    return try await session.save(item)
}

/// Device A creates the account with one item and syncs; device B fetches and restores with A's Secret Key.
@MainActor
func twoSyncedDevices(remote: InMemoryRemote) async throws -> (SyncDevice, SyncDevice, FfiItem) {
    let a = try SyncDevice(remote: remote, name: "A")
    let b = try SyncDevice(remote: remote, name: "B")
    _ = try await a.session.createAccount(password: testPassword, displayName: "Camille Durand", mode: .personal)
    let atlas = try await addItem(a.session, title: "Projet Atlas")
    await a.sync()
    #expect(try await b.coordinator.remoteHasAccount())
    await b.session.reload()
    let key = try #require(a.secretKey)
    try await b.session.restore(secretKey: key, password: testPassword)
    await b.sync()
    return (a, b, atlas)
}

@MainActor
@Suite("Sync coordinator", .timeLimit(.minutes(2)))
struct SyncCoordinatorTests {
    @Test func secondDeviceRestoresThroughRemote() async throws {
        let remote = InMemoryRemote(pageSize: 2)  // several pages per fetch
        let a = try SyncDevice(remote: remote, name: "A")
        let b = try SyncDevice(remote: remote, name: "B")
        defer { a.cleanUp(); b.cleanUp() }

        _ = try await a.session.createAccount(password: testPassword, displayName: "Camille Durand", mode: .personal)
        try await addItem(a.session, title: "Projet Atlas")
        try await addItem(a.session, title: "Camille Durand")
        await a.sync()
        #expect(await a.coordinator.status.isIdle)
        #expect(try await a.pendingChanges().isEmpty)

        #expect(b.session.state == .noAccount)
        var changes = await b.coordinator.remoteChanges().makeAsyncIterator()
        #expect(try await b.coordinator.remoteHasAccount())
        #expect(await changes.next() != nil)
        await b.session.reload()
        #expect(b.session.state == .locked)
        #expect(b.session.needsSecretKey)

        let key = try #require(a.secretKey)
        try await b.session.restore(secretKey: key, password: testPassword)
        #expect(b.session.state == .unlocked)
        #expect(b.titles == ["Projet Atlas", "Camille Durand"])
        #expect(b.session.vaults.map(\.meta.name) == ["Personnel"])
        await b.sync()
        #expect(try await b.pendingChanges().isEmpty)
    }

    @Test func concurrentEditsConvergeOnBothDevices() async throws {
        let remote = InMemoryRemote()
        let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }

        // Both devices write to the same vault before seeing each other's change.
        try await addItem(a.session, title: "Note A")
        try await rename(a.session, itemID: atlas.id, vaultID: atlas.vaultId, to: "Projet Atlas (A)")
        try await addItem(b.session, title: "Note B")
        try await rename(b.session, itemID: atlas.id, vaultID: atlas.vaultId, to: "Projet Atlas (B)")

        await a.sync()
        await b.sync()  // fetches A's manifest, rebases (unlocked), sends
        await a.sync()
        await a.session.reload()
        await b.session.reload()

        #expect(a.session.state == .unlocked && b.session.state == .unlocked)
        #expect(a.titles == b.titles)
        #expect(a.titles.isSuperset(of: ["Note A", "Note B"]))
        #expect(a.titles.count == 3)
        #expect(a.titles.contains("Projet Atlas (A)") != a.titles.contains("Projet Atlas (B)"))
        #expect(try await a.pendingChanges().isEmpty)
        #expect(try await b.pendingChanges().isEmpty)
        #expect(await a.coordinator.status.isIdle)
        #expect(await b.coordinator.status.isIdle)
    }

    @Test func conflictOnSendIsRestagedAndResent() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        let probe = ProbeRemote(remote.client("B"))
        let b = try SyncDevice(name: "B", client: probe)
        defer { a.cleanUp(); b.cleanUp() }

        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        #expect(try await b.coordinator.remoteHasAccount())
        await b.session.reload()
        try await b.session.restore(secretKey: try #require(a.secretKey), password: testPassword)
        await b.sync()
        let sendsBefore = probe.sends
        try await addItem(b.session, title: "Note B")
        try await addItem(a.session, title: "Note A")
        await a.session.waitForSyncNotifications()

        // A pushes between B's fetch and B's send: B's batch fails as a whole on the manifest tag,
        // the server manifest is staged, B rebases (unlocked) and sends again.
        probe.beforeFirstSend { await a.coordinator.syncNow() }
        await b.sync()
        #expect(probe.sends - sendsBefore == 2)
        let first = try #require(probe.results.dropLast().last)
        #expect(first.contains { if case .conflict = $0 { true } else { false } })
        #expect(!first.contains { if case .saved = $0 { true } else { false } })
        #expect(probe.results.last?.allSatisfy { if case .saved = $0 { true } else { false } } == true)
        #expect(try await b.pendingChanges().isEmpty)

        await a.sync()
        await a.session.reload()
        await b.session.reload()
        #expect(a.titles == ["Note A", "Note B"])
        #expect(b.titles == ["Note A", "Note B"])
    }

    @Test func lockedDeviceFetchesButHoldsConflictingVault() async throws {
        let remote = InMemoryRemote()
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }

        try await addItem(b.session, title: "Note B")
        b.session.lock()
        await b.session.waitForSyncNotifications()

        try await addItem(a.session, title: "Note A")
        await a.sync()
        let pushedByA = await remote.tags()

        // Locked: the fetch applies A's manifest, B's vault is held, nothing at all is sent.
        await b.coordinator.syncNow()
        #expect(await b.coordinator.status.isIdle)
        #expect(await remote.tags() == pushedByA)
        let vaultID = try #require(a.session.allVaults.first?.id)
        let store = b.store
        let manifestMeta = try await CoreThread.run { try store.serverMeta(kind: 6, id: vaultID) }
        #expect(manifestMeta == InMemoryRemote.serverMeta(tag: pushedByA[RecordName(kind: 6, id: vaultID)]!))
        #expect(try await b.pendingChanges().isEmpty)

        // Unlocked: the session reaches the coordinator, the vault is rebased and sent.
        try await b.session.unlock(password: testPassword)
        await b.sync()
        #expect(await remote.tags() != pushedByA)
        #expect(try await b.pendingChanges().isEmpty)
        await b.session.reload()
        #expect(b.titles == ["Projet Atlas", "Note A", "Note B"])

        await a.sync()
        await a.session.reload()
        #expect(a.titles == ["Projet Atlas", "Note A", "Note B"])
    }

    @Test func tamperedBlobFailsSessionWithIntegrity() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        let b = try SyncDevice(remote: remote, name: "B")
        defer { a.cleanUp(); b.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(a.session, title: "Projet Atlas")
        await a.sync()

        let item = try #require(await remote.tags().keys.first { $0.kind == 5 })
        await remote.tamper(name: item)

        // New device: the restore refuses the store.
        #expect(try await b.coordinator.remoteHasAccount())
        await b.session.reload()
        await #expect {
            try await b.session.restore(secretKey: try #require(a.secretKey), password: testPassword)
        } throws: { error in
            if case .integrity = error as? VaultError { true } else { false }
        }
        guard case .failed(.integrity) = b.session.state else {
            Issue.record("state \(b.session.state)")
            return
        }
        #expect(b.session.summaries.isEmpty && b.session.allVaults.isEmpty)

        // Unlocked device: the tampered record comes in as a remote change, the reload refuses it.
        var changes = await a.coordinator.remoteChanges().makeAsyncIterator()
        await a.coordinator.syncNow()
        #expect(await changes.next() != nil)
        await a.session.reload()
        guard case .failed(.integrity) = a.session.state else {
            Issue.record("state \(a.session.state)")
            return
        }
        #expect(a.session.summaries.isEmpty && a.session.allVaults.isEmpty)
        if case .integrity = a.session.lastError {} else { Issue.record("lastError \(String(describing: a.session.lastError))") }
    }

    @Test func withheldItemFailsSessionWithIntegrity() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        let b = try SyncDevice(remote: remote, name: "B")
        defer { a.cleanUp(); b.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(a.session, title: "Projet Atlas")
        await a.sync()

        let item = try #require(await remote.tags().keys.first { $0.kind == 5 })
        await remote.withhold(name: item)
        #expect(try await b.coordinator.remoteHasAccount())
        await b.session.reload()
        await #expect(throws: VaultError.integrity(kind: "manifest_missing_item")) {
            try await b.session.restore(secretKey: try #require(a.secretKey), password: testPassword)
        }
        #expect(b.session.state == .failed(.integrity(kind: "manifest_missing_item")))
        #expect(b.session.summaries.isEmpty)
    }

    @Test func replayedManifestFailsSessionWithIntegrity() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        let vaultID = try #require(a.session.allVaults.first?.id)
        let manifest = RecordName(kind: 6, id: vaultID)
        let oldVersion = try #require(await remote.record(manifest)?.version)
        try await addItem(a.session, title: "Projet Atlas")
        await a.sync()
        #expect(await remote.record(manifest)?.version != oldVersion)

        await remote.replay(name: manifest, version: oldVersion)
        await a.coordinator.syncNow()
        await a.session.reload()
        #expect(a.session.state == .failed(.integrity(kind: "manifest_rollback")))
        #expect(a.session.summaries.isEmpty)
    }

    @Test func offlineThenOnlineSendsEverything() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        let b = try SyncDevice(remote: remote, name: "B")
        defer { a.cleanUp(); b.cleanUp() }

        await remote.setOffline(true)
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        for title in ["Projet Atlas", "Camille Durand", "Note"] { try await addItem(a.session, title: title) }
        await a.sync()
        #expect(await a.coordinator.status == .offline)
        #expect(a.sleeper.requests.contains(.seconds(30)))
        #expect(await remote.tags().isEmpty)

        // Each failed round pushes the next retry further: 30 s, 2 min, then 10 min.
        #expect(await eventually {
            a.sleeper.fire()
            return a.sleeper.requests.contains(.seconds(600))
        })
        #expect(a.sleeper.requests.contains(.seconds(120)))
        #expect(await remote.tags().isEmpty)

        // Back online: the scheduled retry sends everything.
        await remote.setOffline(false)
        #expect(await eventually {
            a.sleeper.fire()
            return await a.coordinator.status.isIdle
        })
        #expect(try await a.pendingChanges().isEmpty)

        #expect(try await b.coordinator.remoteHasAccount())
        await b.session.reload()
        try await b.session.restore(secretKey: try #require(a.secretKey), password: testPassword)
        #expect(b.titles == ["Projet Atlas", "Camille Durand", "Note"])
    }

    @Test func writeIsSentAfterTheDebounce() async throws {
        let remote = InMemoryRemote()
        let device = try SyncDevice(remote: remote, name: "A")
        defer { device.cleanUp() }
        _ = try await device.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await device.sync()
        let before = await remote.tags()

        try await addItem(device.session, title: "Projet Atlas")
        await device.session.waitForSyncNotifications()
        #expect(device.sleeper.requests.contains(.seconds(2)))
        #expect(await remote.tags() == before)
        device.sleeper.fire()
        #expect(await eventually { (try? await device.pendingChanges().isEmpty) ?? false })
        #expect(await remote.tags() != before)
    }

    @Test func noRemoteMeansDisabled() async throws {
        let device = try SyncDevice(remote: nil, name: "solo")
        defer { device.cleanUp() }
        #expect(await device.coordinator.status == .disabled)
        var updates = await device.coordinator.statusUpdates().makeAsyncIterator()
        #expect(await updates.next() == .disabled)

        _ = try await device.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(device.session, title: "Projet Atlas")
        await device.sync()
        #expect(await device.coordinator.status == .disabled)
        #expect(try await device.coordinator.remoteHasAccount() == false)
        #expect(device.sleeper.requests.isEmpty)
        #expect(try await device.pendingChanges().isEmpty == false)
    }

    @Test func remoteHasAccountDetectsExistingAccount() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        let b = try SyncDevice(remote: remote, name: "B")
        defer { a.cleanUp(); b.cleanUp() }

        #expect(try await b.coordinator.remoteHasAccount() == false)
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        #expect(try await b.coordinator.remoteHasAccount() == false)  // not pushed yet
        await a.sync()
        #expect(try await b.coordinator.remoteHasAccount())

        await remote.setOffline(true)
        let c = try SyncDevice(remote: remote, name: "C")
        defer { c.cleanUp() }
        await #expect(throws: RemoteStoreError.offline) { try await c.coordinator.remoteHasAccount() }
    }

    @Test func triggersDuringARoundCoalesce() async throws {
        let remote = InMemoryRemote()
        let probe = ProbeRemote(remote.client("A"), fetchDelay: .milliseconds(200))
        let device = try SyncDevice(name: "A", client: probe)
        defer { device.cleanUp() }
        let coordinator = device.coordinator

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<6 { group.addTask { await coordinator.syncNow() } }
        }
        #expect(probe.maxInFlight == 1)
        #expect(probe.fetches <= 2)
        #expect(await coordinator.status.isIdle)
    }

    @Test func statusUpdatesFollowARound() async throws {
        let remote = InMemoryRemote()
        let device = try SyncDevice(remote: remote, name: "A")
        defer { device.cleanUp() }
        var updates = await device.coordinator.statusUpdates().makeAsyncIterator()
        #expect(await updates.next() == .idle(lastSync: nil))
        await device.coordinator.syncNow()
        #expect(await updates.next() == .syncing)
        #expect(await updates.next()?.isIdle == true)
        #expect(SyncStatus.refused(kind: "aead").label == "Données refusées : Des données chiffrées ont été modifiées.")
        #expect(SyncStatus.offline.label == "Hors ligne")
    }
}

@Suite("In-memory remote")
struct InMemoryRemoteTests {
    static func name(_ n: Int) -> RecordName {
        RecordName(kind: 5, id: String(format: "%032x", n))
    }

    static func record(_ n: Int, version: UInt64 = 1, meta: Data? = nil) -> RemoteRecord {
        RemoteRecord(name: name(n), version: version, data: Data([UInt8(n), 1, 2, 3]), serverMeta: meta)
    }

    @Test func staleTagFailsTheWholeBatch() async throws {
        let remote = InMemoryRemote()
        let x = remote.client("X")
        let y = remote.client("Y")

        let saved = try await x.send([Self.record(1)])
        guard case .saved(let name, let meta?) = saved.first, name == Self.name(1) else {
            Issue.record("\(saved)")
            return
        }
        #expect(meta.count == 8)

        // Y did not see record 1: its save of 1 conflicts, its new record 2 fails with it.
        let results = try await y.send([Self.record(1, version: 2), Self.record(2)])
        #expect(results.count == 2)
        guard case .conflict(let server) = results[0] else {
            Issue.record("\(results)")
            return
        }
        #expect(server.name == Self.name(1) && server.serverMeta == meta && server.version == 1)
        #expect(results[1] == .failed(name: Self.name(2)))
        #expect(await remote.tags().keys.sorted { $0.string < $1.string } == [Self.name(1)])

        // With the current tag the save goes through; a deletion needs no tag.
        let retried = try await y.send([
            Self.record(1, version: 2, meta: meta), Self.record(2),
            RemoteRecord(name: Self.name(3), version: 1, data: nil, serverMeta: nil),
        ])
        #expect(retried.allSatisfy { if case .saved = $0 { true } else { false } })
        let deleted = try await x.send([RemoteRecord(name: Self.name(1), version: 2, data: nil, serverMeta: nil)])
        #expect(deleted == [.saved(name: Self.name(1), serverMeta: nil)])
        #expect(Set(await remote.tags().keys) == [Self.name(2)])
    }

    @Test func fetchPagesPerClient() async throws {
        let remote = InMemoryRemote(pageSize: 2)
        let x = remote.client("X")
        _ = try await x.send([Self.record(1), Self.record(2), Self.record(3)])

        var seen: [RecordName] = []
        var pages = 0
        while true {
            let batch = try await x.fetchChanges()
            pages += 1
            seen += batch.changes.map(\.name)
            if !batch.moreComing { break }
        }
        #expect(pages == 2)
        #expect(Set(seen) == [Self.name(1), Self.name(2), Self.name(3)])
        #expect(try await x.fetchChanges().changes.isEmpty)

        // Another client has its own cursor; a deletion is a change too.
        let y = remote.client("Y")
        #expect(try await y.fetchChanges().changes.count == 2)
        _ = try await x.send([RemoteRecord(name: Self.name(2), version: 2, data: nil, serverMeta: nil)])
        let x2 = try await x.fetchChanges()
        #expect(x2.changes.map(\.name) == [Self.name(2)] && x2.changes[0].data == nil)

        await remote.setOffline(true)
        await #expect(throws: RemoteStoreError.offline) { try await y.fetchChanges() }
    }
}
