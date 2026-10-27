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
        try self.init(name: name, client: remote)
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
        var failingFetch: Int?
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
    var maxBatchRecords: Int { inner.maxBatchRecords }
    var maxBatchBytes: Int { inner.maxBatchBytes }
    /// The `number`th fetch (counting from the first one ever) throws `.offline`.
    func failFetch(number: Int) { state.withLock { $0.failingFetch = number } }
    func beforeFirstSend(_ hook: @escaping @Sendable () async -> Void) { state.withLock { $0.hook = hook } }

    func fetchChanges(since token: Data?) async throws -> RemoteBatch {
        let failing = state.withLock { s -> Bool in
            s.fetches += 1
            return s.fetches == s.failingFetch
        }
        if failing { throw RemoteStoreError.offline }
        state.withLock {
            $0.inFlight += 1
            $0.maxInFlight = max($0.maxInFlight, $0.inFlight)
        }
        defer { state.withLock { $0.inFlight -= 1 } }
        if fetchDelay > .zero { try await Task.sleep(for: fetchDelay) }
        return try await inner.fetchChanges(since: token)
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
    func accountIdentity() async throws -> String? { try await inner.accountIdentity() }
}

/// Wraps a remote and records the token of every fetch.
final class TokenRecorder: RemoteRecordStore {
    let inner: any RemoteRecordStore
    private let state = Mutex<[Data?]>([])

    init(_ inner: any RemoteRecordStore) { self.inner = inner }

    var tokens: [Data?] { state.withLock { $0 } }
    var maxBatchRecords: Int { inner.maxBatchRecords }
    var maxBatchBytes: Int { inner.maxBatchBytes }

    func fetchChanges(since token: Data?) async throws -> RemoteBatch {
        state.withLock { $0.append(token) }
        return try await inner.fetchChanges(since: token)
    }

    func send(_ changes: [RemoteRecord]) async throws -> [SendResult] { try await inner.send(changes) }
    func accountAvailable() async -> Bool { await inner.accountAvailable() }
    func accountIdentity() async throws -> String? { try await inner.accountIdentity() }
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
@Suite("Sync coordinator", .timeLimit(.minutes(4)))
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

    @Test func lostZoneIsUploadedAgainAndOtherDeviceConverges() async throws {
        let remote = InMemoryRemote(omitsTombstonesOnFullFetch: true)
        let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        await b.sync()
        let before = await remote.tags().keys.sorted { $0.string < $1.string }
        #expect(!before.isEmpty)

        await remote.simulateReset()
        #expect(await remote.tags().isEmpty)
        await a.sync()
        #expect(await a.coordinator.status.isIdle)
        #expect(try await a.pendingChanges().isEmpty)
        // The server holds every record again.
        #expect(await remote.tags().keys.sorted { $0.string < $1.string } == before)

        // The other device converges on a change made after the reset.
        try await rename(a.session, itemID: atlas.id, vaultID: atlas.vaultId, to: "Projet Atlas v2")
        await a.sync()
        await b.sync()
        await b.session.reload()
        #expect(b.titles == a.titles)
        #expect(b.titles.contains("Projet Atlas v2"))
        #expect(await b.coordinator.status.isIdle)
    }

    @Test func staleDeviceResetKeepsNewerServerVersions() async throws {
        let remote = InMemoryRemote(omitsTombstonesOnFullFetch: true)
        let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        await b.sync()

        // The zone is lost; A uploads again, then renames the vault and the item. B has not seen any of it.
        await remote.simulateReset()
        await a.sync()
        let vault = try #require(a.session.allVaults.first { $0.id == atlas.vaultId })
        var meta = vault.meta
        meta.name = "Renommé par A"
        try await a.session.updateVault(id: vault.id, meta: meta)
        try await rename(a.session, itemID: atlas.id, vaultID: atlas.vaultId, to: "Atlas renommé par A")
        await a.sync()
        #expect(try await a.pendingChanges().isEmpty)
        let serverBefore = await remote.tags()

        // B goes through its own reset path: it must not overwrite A's newer versions.
        await remote.failNext(with: .zoneReset)
        await b.sync()
        #expect(await b.coordinator.status.isIdle)
        #expect(await remote.tags() == serverBefore)
        #expect(try await b.pendingChanges().isEmpty)
        await b.session.reload()
        await a.sync()
        await a.session.reload()
        #expect(b.titles == a.titles)
        #expect(b.titles.contains("Atlas renommé par A"))
        #expect(b.session.allVaults.contains { $0.meta.name == "Renommé par A" })
        #expect(a.session.allVaults.contains { $0.meta.name == "Renommé par A" })
    }

    @Test func pendingDeletionSurvivesAZoneReset() async throws {
        let remote = InMemoryRemote(omitsTombstonesOnFullFetch: true)
        let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        try await a.session.deletePermanently(itemID: atlas.id, vaultID: atlas.vaultId)
        #expect(try await a.pendingChanges().contains { $0.data == nil })

        await remote.simulateReset()
        await a.sync()
        #expect(await a.coordinator.status.isIdle)
        #expect(try await a.pendingChanges().isEmpty)
        #expect(await remote.record(RecordName(kind: 5, id: atlas.id)) == nil)
        await b.sync()
        await b.session.reload()
        #expect(!b.titles.contains("Projet Atlas"))
        #expect(b.titles == a.titles)
    }

    /// A second item at version 2 on both devices, so a stale copy of it is a real integrity error once
    /// it is deleted on the server (an unlisted record that is not a leftover of a listed item).
    func syncedNote(_ a: SyncDevice, _ b: SyncDevice) async throws -> FfiItem {
        let note = try await addItem(a.session, title: "Note")
        try await rename(a.session, itemID: note.id, vaultID: note.vaultId, to: "Note v2")
        await a.sync()
        await b.sync()
        return note
    }

    @Test func staleDeviceDropsItsOldItemBlobAfterAReset() async throws {
        let remote = InMemoryRemote(omitsTombstonesOnFullFetch: true)
        let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        let note = try await syncedNote(a, b)
        let itemsBefore = Set(await remote.tags().keys.filter { $0.kind == 5 })

        // After the reset A deletes the note: its blob disappears from the server, and a fetch from
        // scratch does not report a deletion.
        await remote.simulateReset()
        await a.sync()
        try await a.session.deletePermanently(itemID: note.id, vaultID: note.vaultId)
        try await rename(a.session, itemID: atlas.id, vaultID: atlas.vaultId, to: "Atlas v3")
        await a.sync()
        let itemsAfter = Set(await remote.tags().keys.filter { $0.kind == 5 })
        let stale = try #require(itemsBefore.subtracting(itemsAfter).first)
        let serverBefore = await remote.tags()

        await remote.failNext(with: .zoneReset)
        await b.sync()
        #expect(await b.coordinator.status.isIdle)
        #expect(await remote.tags() == serverBefore)
        #expect(await remote.record(stale) == nil)
        #expect(try await b.pendingChanges().isEmpty)
        await b.session.reload()
        await a.sync()
        await a.session.reload()
        #expect(a.session.state == .unlocked && b.session.state == .unlocked)
        #expect(a.titles == b.titles && b.titles.contains("Atlas v3") && !b.titles.contains("Note v2"))
        // The vault passes the core's integrity check from a cold unlock.
        b.session.lock()
        try await b.session.unlock(password: testPassword)
        #expect(b.session.state == .unlocked && !b.titles.contains("Note v2"))
        #expect(await a.coordinator.status.isIdle)
    }

    @Test func expiredTokenFullFetchDropsRowsDeletedOnTheServer() async throws {
        let remote = InMemoryRemote(omitsTombstonesOnFullFetch: true)
        let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        let note = try await syncedNote(a, b)
        await b.session.reload()
        #expect(b.titles.contains("Note v2"))

        try await a.session.deletePermanently(itemID: note.id, vaultID: note.vaultId)
        try await rename(a.session, itemID: atlas.id, vaultID: atlas.vaultId, to: "Atlas v3")
        await a.sync()

        // B's token expires: the full fetch brings the live records and no deletion of the note.
        await remote.expireTokens()
        await b.sync()
        #expect(await b.coordinator.status.isIdle)
        #expect(try await b.pendingChanges().isEmpty)
        await b.session.reload()
        #expect(b.session.state == .unlocked)
        #expect(b.titles.contains("Atlas v3") && !b.titles.contains("Note v2"))
        // The vault passes the core's integrity check from a cold unlock.
        b.session.lock()
        try await b.session.unlock(password: testPassword)
        #expect(b.session.state == .unlocked && !b.titles.contains("Note v2"))
        await b.sync()
        #expect(await b.coordinator.status.isIdle)
    }

    @Test func refetchFromScratchStartsFromNoToken() async throws {
        let recorder = TokenRecorder(InMemoryRemote())
        let a = try SyncDevice(name: "A", client: recorder)
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "Camille Durand", mode: .personal)
        try await addItem(a.session, title: "Projet Atlas")
        await a.sync()
        await a.sync()
        #expect(recorder.tokens.last.flatMap { $0 } != nil)

        let before = recorder.tokens.count
        await a.coordinator.refetchFromScratch()
        #expect(recorder.tokens.count > before)
        #expect(recorder.tokens[before] == nil)
        #expect(await a.coordinator.status.isIdle)
        #expect(try await a.pendingChanges().isEmpty)
        await a.session.reload()
        #expect(a.session.state == .unlocked && a.titles == ["Projet Atlas"])
        // The next round is incremental again.
        await a.sync()
        #expect(recorder.tokens.last.flatMap { $0 } != nil)
    }

    @Test func conflictOnSendIsRestagedAndResent() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        let probe = ProbeRemote(remote)
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

    /// Spec 3.1: a server that serves an older manifest again is behind, not an attack. The device
    /// serves its verified copy, says it waits for iCloud, and pushes its copy back.
    @Test func replayedManifestIsServedFromTheLocalCopy() async throws {
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

        let newVersion = try #require(await remote.record(manifest)?.version)
        await remote.replay(name: manifest, version: oldVersion)
        await a.coordinator.syncNow()
        await a.session.reload()
        #expect(a.session.state == .unlocked)
        #expect(a.titles == ["Projet Atlas"])
        #expect(await a.coordinator.status == .waitingForServer)
        await a.coordinator.syncNow()
        #expect(await remote.record(manifest)?.version == newVersion)
    }

    /// C1: forged deletions of the account and of the vault a locked device has read change nothing
    /// locally: the device stays locked (never `noAccount`) and unlocks with its data.
    @Test func lockedDeviceIgnoresForgedDeletionsOfItsAccount() async throws {
        let remote = InMemoryRemote()
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        b.session.lock()
        await b.session.waitForReleasedSessions()
        for name in await remote.tags().keys where name.kind != 5 {
            await remote.forgeDeletion(name: name)
        }
        var changes = await b.coordinator.remoteChanges().makeAsyncIterator()
        await b.coordinator.syncNow()
        _ = await changes.next()
        await b.session.reload()
        #expect(b.session.state == .locked)
        try await b.session.unlock(password: testPassword)
        #expect(b.titles == ["Projet Atlas"])
    }

    /// C1: "Réessayer" against a zone that answers nothing keeps the local copy of a locked device.
    @Test func emptyZoneOnAFullFetchKeepsTheLocalCopy() async throws {
        let remote = InMemoryRemote()
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        b.session.lock()
        await b.session.waitForReleasedSessions()
        for name in await remote.tags().keys { await remote.withhold(name: name) }
        await b.coordinator.refetchFromScratch()
        await b.session.reload()
        #expect(b.session.state == .locked)
        if case .noAccount = b.session.state { Issue.record("no account") }
        try await b.session.unlock(password: testPassword)
        #expect(b.titles == ["Projet Atlas"])
    }

    /// I5: another Apple ID signs in. The coordinator neither fetches nor sends until the change is
    /// accepted, and says so.
    @Test func iCloudAccountSwitchStopsSyncUntilAccepted() async throws {
        let remote = InMemoryRemote()
        let probe = ProbeRemote(remote)
        let a = try SyncDevice(name: "A", client: probe)
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        #expect(await a.coordinator.status.isIdle)

        await remote.setAccountIdentity("utilisateur-icloud-b")
        try await addItem(a.session, title: "Projet Atlas")
        let (fetches, sends) = (probe.fetches, probe.sends)
        await a.sync()
        #expect(await a.coordinator.status == .accountChanged)
        #expect(SyncStatus.accountChanged.label == "Le compte iCloud a changé")
        #expect(probe.fetches == fetches && probe.sends == sends)
        await #expect(throws: RemoteStoreError.accountChanged) { _ = try await a.coordinator.remoteHasAccount() }
        #expect(probe.fetches == fetches)
        // Still stopped on the next round, and after a relaunch (the binding is in the store).
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .accountChanged)
        let relaunched = SyncCoordinator(store: a.store, remote: probe, sleep: { try await a.sleeper.sleep($0) })
        await relaunched.syncNow()
        #expect(await relaunched.status == .accountChanged)
        #expect(probe.sends == sends)

        await a.coordinator.acceptAccountChange(expected: .sameVault)
        #expect(await a.coordinator.status.isIdle)
        #expect(try await a.pendingChanges().isEmpty)
        #expect(probe.sends > sends)
    }

    /// M8: a record that stays unreadable is reported plainly after five rounds in a row.
    @Test func unreadableRecordIsReportedAfterFiveRounds() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        let busy = SyncStatus.error("Le serveur est momentanément indisponible, nouvel essai bientôt.")
        for round in 1...5 {
            await remote.failNext(with: .recordUnreadable)
            await a.coordinator.syncNow()
            let expected = round < 5 ? busy : .error(SyncCoordinator.unreadableMessage)
            #expect(await a.coordinator.status == expected, "round \(round)")
        }
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status.isIdle)
    }

    /// M9: a remote announcing more pages without a token does not loop forever.
    @Test func morePagesWithoutATokenEndTheRound() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        await remote.breakNextPageToken()
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .error("Le serveur est momentanément indisponible, nouvel essai bientôt."))
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status.isIdle)
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
        let probe = ProbeRemote(remote, fetchDelay: .seconds(1))
        let device = try SyncDevice(name: "A", client: probe)
        defer { device.cleanUp() }
        let coordinator = device.coordinator

        // A round is fetching (1 s, so the six triggers land during it even on a loaded machine);
        // six more triggers come in: one more round, not six.
        let first = Task { await coordinator.syncNow() }
        #expect(await eventually { probe.fetches == 1 })
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<6 { group.addTask { await coordinator.syncNow() } }
        }
        await first.value
        #expect(probe.maxInFlight == 1)
        #expect(probe.fetches == 2)
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

/// A remote that serves fixed pages (token = page index) and answers sends with a closure.
final class ScriptedRemote: RemoteRecordStore {
    private struct State {
        var sinces: [Data?] = []
        var sent: [[RemoteRecord]] = []
    }
    let pages: [[RemoteRecord]]
    let answer: @Sendable ([RemoteRecord]) -> [SendResult]
    private let state = Mutex(State())
    let maxBatchRecords = 400
    let maxBatchBytes = 1_572_864

    init(pages: [[RemoteRecord]], answer: @escaping @Sendable ([RemoteRecord]) -> [SendResult] = { _ in [] }) {
        self.pages = pages
        self.answer = answer
    }

    var sinces: [Data?] { state.withLock { $0.sinces } }
    var sent: [[RemoteRecord]] { state.withLock { $0.sent } }

    static func token(_ index: Int) -> Data { Data([UInt8(index)]) }

    func fetchChanges(since token: Data?) async throws -> RemoteBatch {
        state.withLock { $0.sinces.append(token) }
        let index = token.map { Int($0[0]) } ?? 0
        guard index < pages.count else { return RemoteBatch(changes: [], moreComing: false, token: token) }
        return RemoteBatch(changes: pages[index], moreComing: index + 1 < pages.count, token: Self.token(index + 1))
    }

    func send(_ changes: [RemoteRecord]) async throws -> [SendResult] {
        state.withLock { $0.sent.append(changes) }
        return answer(changes)
    }

    func accountAvailable() async -> Bool { true }
    func accountIdentity() async throws -> String? { nil }
}

struct StagingFailure: Error {}

@MainActor
@Suite("Sync coordinator, store safety", .timeLimit(.minutes(4)))
struct SyncCoordinatorStoreSafetyTests {
    static func hex(_ n: Int) -> String { String(format: "%032x", n) }

    static func readToken(_ store: SyncStoreHandle) async throws -> Data? {
        try await CoreThread.run { try store.meta(key: SyncCoordinator.tokenKey) }
    }

    static func serverMeta(_ store: SyncStoreHandle, _ name: RecordName) async throws -> Data? {
        try await CoreThread.run { try store.serverMeta(kind: name.kind, id: name.id) }
    }

    /// I1: a fetch interrupted after page 1 leaves rows in staging; the next complete fetch commits them
    /// before our deletion is pushed, so no later commit brings the deleted record back.
    @Test func interruptedFetchNeverResurrectsAPushedDeletion() async throws {
        let remote = InMemoryRemote(pageSize: 1)
        let probe = ProbeRemote(remote)
        let a = try SyncDevice(name: "A", client: probe)
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let item = try await addItem(a.session, title: "Projet Atlas")
        await a.sync()
        let blob = try #require(await remote.tags().keys.first { $0.kind == 5 })
        let manifest = RecordName(kind: 6, id: item.vaultId)

        // The server rewrites the blob then the manifest (same content, new tags): two pages.
        await remote.replay(name: blob, version: try #require(await remote.record(blob)?.version))
        await remote.replay(name: manifest, version: try #require(await remote.record(manifest)?.version))
        let tokenBefore = try await Self.readToken(a.store)
        probe.failFetch(number: probe.fetches + 2)
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .offline)
        let tokenAfterPage1 = try await Self.readToken(a.store)
        #expect(tokenAfterPage1 != nil && tokenAfterPage1 != tokenBefore)

        // Our deletion of the blob is pushed (unconditional), then more server changes come in.
        try await a.session.deletePermanently(itemID: item.id, vaultID: item.vaultId)
        await a.sync()
        #expect(await a.coordinator.status.isIdle)
        #expect(await remote.record(blob) == nil)
        #expect(try await Self.serverMeta(a.store, blob) == nil)

        await remote.replay(name: manifest, version: try #require(await remote.record(manifest)?.version))
        await a.coordinator.syncNow()
        #expect(try await Self.serverMeta(a.store, blob) == nil)
        #expect(try await a.pendingChanges().isEmpty)
        await a.session.reload()
        #expect(a.session.state == .unlocked)
        #expect(a.session.summaries.isEmpty)
    }

    /// I2: unknown kinds and malformed records are skipped (the rest of the page is staged).
    @Test func unknownRecordsAreSkipped() async throws {
        let meta = InMemoryRemote.serverMeta(tag: 7)
        let good = RemoteRecord(name: RecordName(kind: 4, id: Self.hex(1)), version: 1, data: Data([1, 2]), serverMeta: meta)
        let page = [
            RemoteRecord(name: RecordName(kind: 9, id: Self.hex(2)), version: 1, data: Data([1]), serverMeta: meta),
            RemoteRecord(name: RecordName(kind: 5, id: "pas-un-identifiant"), version: 1, data: Data([1]), serverMeta: meta),
            RemoteRecord(name: RecordName(kind: 5, id: Self.hex(3)), version: .max, data: Data([1]), serverMeta: meta),
            good,
        ]
        let remote = ScriptedRemote(pages: [page])
        let device = try SyncDevice(name: "A", client: remote)
        defer { device.cleanUp() }
        await device.coordinator.syncNow()
        #expect(await device.coordinator.status.isIdle)
        #expect(try await Self.serverMeta(device.store, good.name) == meta)
        #expect(try await Self.serverMeta(device.store, RecordName(kind: 5, id: Self.hex(3))) == nil)
        #expect(try await Self.readToken(device.store) == ScriptedRemote.token(1))
    }

    /// The restore epoch (kind 7) and the signed device and vault lists (kinds 8 and 9) are staged like the other kinds.
    @Test func signedListKindsAreValid() {
        let meta = InMemoryRemote.serverMeta(tag: 1)
        let record = { (kind: UInt8) in
            RemoteRecord(name: RecordName(kind: kind, id: Self.hex(1)), version: 1, data: Data([1]), serverMeta: meta)
        }
        for kind in UInt8(1)...9 {
            #expect(SyncCoordinator.isValid(record(kind)))
        }
        #expect(!SyncCoordinator.isValid(record(0)))
        #expect(!SyncCoordinator.isValid(record(10)))
    }

    /// I2: the token moves only once a page is staged; a crash in between fetches the page again.
    @Test func tokenIsNotAdvancedWhenStagingFails() async throws {
        let meta = InMemoryRemote.serverMeta(tag: 1)
        let pages = (1...2).map { n in
            [RemoteRecord(name: RecordName(kind: 4, id: Self.hex(n)), version: 1, data: Data([UInt8(n)]), serverMeta: meta)]
        }
        let remote = ScriptedRemote(pages: pages)
        let device = try SyncDevice(name: "A", client: remote)
        defer { device.cleanUp() }

        await device.coordinator.setAfterPageStaged { throw StagingFailure() }
        await device.coordinator.syncNow()
        if case .error = await device.coordinator.status {} else { Issue.record("status") }
        #expect(try await Self.readToken(device.store) == nil)

        await device.coordinator.setAfterPageStaged(nil)
        await device.coordinator.syncNow()
        #expect(await device.coordinator.status.isIdle)
        #expect(remote.sinces == [nil, nil, ScriptedRemote.token(1)])
        #expect(try await Self.readToken(device.store) == ScriptedRemote.token(2))
        for n in 1...2 {
            #expect(try await Self.serverMeta(device.store, RecordName(kind: 4, id: Self.hex(n))) == meta)
        }
    }

    /// I3: past the batch limit the send is split, a manifest never before the items it lists.
    @Test func largeSendIsSplitWithItemsBeforeTheirManifest() async throws {
        let remote = InMemoryRemote(maxBatchRecords: 3)
        let a = try SyncDevice(remote: remote, name: "A")
        let b = try SyncDevice(remote: remote, name: "B")
        defer { a.cleanUp(); b.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        #expect(await remote.sentBatches.count > 1)  // account records alone exceed 3
        let sentBefore = await remote.sentBatches.count
        let titles = ["Projet Atlas", "Camille Durand", "Note 1", "Note 2", "Note 3"]
        for title in titles { try await addItem(a.session, title: title) }
        await a.sync()
        #expect(await a.coordinator.status.isIdle)
        #expect(try await a.pendingChanges().isEmpty)

        // One round: five item records and the manifest, in two batches, the manifest last.
        let batches = Array(await remote.sentBatches.dropFirst(sentBefore))
        #expect(batches.count == 2)
        #expect(batches.flatMap { $0 }.filter { $0.kind == 6 }.count == 1)
        #expect(batches.allSatisfy { $0.count <= 3 })
        #expect(batches.flatMap { $0 }.last?.kind == 6)

        #expect(try await b.coordinator.remoteHasAccount())
        await b.session.reload()
        try await b.session.restore(secretKey: try #require(a.secretKey), password: testPassword)
        #expect(b.titles == Set(titles))
    }

    /// M4: a busy server's delay is honored.
    @Test func retryableErrorWaitsTheServerDelay() async throws {
        let remote = InMemoryRemote()
        let device = try SyncDevice(remote: remote, name: "A")
        defer { device.cleanUp() }
        await remote.failNext(with: .retryable(after: .seconds(7)))
        await device.coordinator.syncNow()
        if case .error = await device.coordinator.status {} else { Issue.record("status") }
        #expect(device.sleeper.requests == [.seconds(7)])
        #expect(await eventually {
            device.sleeper.fire()
            return await device.coordinator.status.isIdle
        })
    }

    /// M5: a save confirmed without server metadata is not marked pushed.
    @Test func saveWithoutServerMetaStaysPending() async throws {
        let remote = ScriptedRemote(pages: []) { changes in
            changes.map { .saved(name: $0.name, serverMeta: nil) }
        }
        let device = try SyncDevice(name: "A", client: remote)
        defer { device.cleanUp() }
        _ = try await device.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let before = try await device.pendingChanges().count
        #expect(before > 0)
        await device.sync()
        #expect(try await device.pendingChanges().count == before)
        if case .error = await device.coordinator.status {} else { Issue.record("status") }
    }

    /// M6: a locked round keeps the refusal; only a rebase can clear it.
    @Test func lockedRoundKeepsRefusal() async throws {
        let remote = InMemoryRemote()
        // The server forked from what B verified: an alert.
        let (a, b, c, _) = try await forkedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp(); c.cleanUp() }
        guard case .refused(let kind) = await b.coordinator.status else {
            Issue.record("status \(await b.coordinator.status)")
            return
        }
        b.session.lock()
        await b.session.waitForSyncNotifications()
        await b.coordinator.syncNow()
        #expect(await b.coordinator.status == .refused(kind: kind))
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

        let saved = try await remote.send([Self.record(1)])
        guard case .saved(let name, let meta?) = saved.first, name == Self.name(1) else {
            Issue.record("\(saved)")
            return
        }
        #expect(meta.count == 8)

        // A device that did not see record 1: its save of 1 conflicts, its new record 2 fails with it.
        let results = try await remote.send([Self.record(1, version: 2), Self.record(2)])
        #expect(results.count == 2)
        guard case .conflict(let server) = results[0] else {
            Issue.record("\(results)")
            return
        }
        #expect(server.name == Self.name(1) && server.serverMeta == meta && server.version == 1)
        #expect(results[1] == .failed(name: Self.name(2)))
        #expect(Set(await remote.tags().keys) == [Self.name(1)])

        // With the current tag the save goes through; a deletion needs no tag.
        let retried = try await remote.send([
            Self.record(1, version: 2, meta: meta), Self.record(2),
            RemoteRecord(name: Self.name(3), version: 1, data: nil, serverMeta: nil),
        ])
        #expect(retried.allSatisfy { if case .saved = $0 { true } else { false } })
        let deleted = try await remote.send([RemoteRecord(name: Self.name(1), version: 2, data: nil, serverMeta: nil)])
        #expect(deleted == [.saved(name: Self.name(1), serverMeta: nil)])
        #expect(Set(await remote.tags().keys) == [Self.name(2)])
    }

    @Test func fetchPagesFromTheCallersToken() async throws {
        let remote = InMemoryRemote(pageSize: 2)
        _ = try await remote.send([Self.record(1), Self.record(2), Self.record(3)])

        var seen: [RecordName] = []
        var token: Data?
        var pages = 0
        while true {
            let batch = try await remote.fetchChanges(since: token)
            pages += 1
            seen += batch.changes.map(\.name)
            token = batch.token
            if !batch.moreComing { break }
        }
        #expect(pages == 2)
        #expect(Set(seen) == [Self.name(1), Self.name(2), Self.name(3)])
        #expect(try await remote.fetchChanges(since: token).changes.isEmpty)

        // Another device starts from its own (nil) token; a deletion is a change too.
        #expect(try await remote.fetchChanges(since: nil).changes.count == 2)
        _ = try await remote.send([RemoteRecord(name: Self.name(2), version: 2, data: nil, serverMeta: nil)])
        let next = try await remote.fetchChanges(since: token)
        #expect(next.changes.map(\.name) == [Self.name(2)] && next.changes[0].data == nil)

        await remote.setOffline(true)
        await #expect(throws: RemoteStoreError.offline) { try await remote.fetchChanges(since: nil) }
    }

    @Test func oversizedBatchIsRefused() async throws {
        let remote = InMemoryRemote(maxBatchRecords: 2, maxBatchBytes: 100)
        await #expect(throws: RemoteStoreError.self) {
            _ = try await remote.send([Self.record(1), Self.record(2), Self.record(3)])
        }
        let big = RemoteRecord(name: Self.name(4), version: 1, data: Data(count: 200), serverMeta: nil)
        await #expect(throws: RemoteStoreError.self) { _ = try await remote.send([big]) }
        #expect(await remote.tags().isEmpty)
    }
}

/// Review I4: "Créer un nouveau coffre" on the Emergency Kit screen is only offered when iCloud holds
/// no account (the vault would come back with the next sync otherwise). No remote (unsigned
/// build): offered, as before.
@MainActor
@Suite("New vault offer", .timeLimit(.minutes(2)))
struct NewVaultOfferTests {
    @Test func offeredOnlyWhenTheRemoteHasNoAccount() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        let empty = try SyncDevice(remote: InMemoryRemote(), name: "empty")
        defer { empty.cleanUp() }
        let local = try SyncDevice(remote: nil, name: "local")
        defer { local.cleanUp() }

        #expect(await empty.coordinator.newVaultOffer() == .offered)
        #expect(await local.coordinator.newVaultOffer() == .offered)

        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        let b = try SyncDevice(remote: remote, name: "B")
        defer { b.cleanUp() }
        #expect(await b.coordinator.newVaultOffer() == .accountInICloud)
    }

    /// Round 3: the restore-only device already holds the account locally; only the remote zone
    /// decides. Empty zone: offered. Zone with an account: not offered. Offline or no iCloud
    /// account: unavailable (explained, nothing offered).
    @Test func localAccountDoesNotCountOnlyTheZone() async throws {
        let local = try SyncDevice(remote: nil, name: "local")
        defer { local.cleanUp() }
        _ = try await local.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        #expect(try local.store.hasAccount())

        let emptyZone = InMemoryRemote()
        #expect(await SyncCoordinator(store: local.store, remote: emptyZone).newVaultOffer() == .offered)

        let filled = InMemoryRemote()
        let other = try SyncDevice(remote: filled, name: "other")
        defer { other.cleanUp() }
        _ = try await other.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await other.sync()
        #expect(await SyncCoordinator(store: local.store, remote: filled).newVaultOffer() == .accountInICloud)

        let offline = InMemoryRemote()
        await offline.setOffline(true)
        #expect(await SyncCoordinator(store: local.store, remote: offline).newVaultOffer() == .unavailable)
        let signedOut = InMemoryRemote()
        await signedOut.setAccountAvailable(false)
        #expect(await SyncCoordinator(store: local.store, remote: signedOut).newVaultOffer() == .unavailable)
    }
}
