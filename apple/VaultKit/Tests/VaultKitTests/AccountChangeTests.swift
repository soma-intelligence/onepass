import Foundation
import SQLite3
import Synchronization
import Testing

@testable import VaultKit

/// One remote per iCloud account: each identity has its own zone, like CloudKit private databases.
final class AccountSwitchingRemote: RemoteRecordStore {
    private let zones: [String: InMemoryRemote]
    private let current: Mutex<String>
    private let changes = Mutex<UInt64>(0)

    init(_ zones: [String: InMemoryRemote], signedIn: String) {
        self.zones = zones
        current = Mutex(signedIn)
    }

    var zone: InMemoryRemote { zones[current.withLock { $0 }]! }
    var maxBatchRecords: Int { 400 }
    var maxBatchBytes: Int { 1_572_864 }

    private let pendingSwitch = Mutex<String?>(nil)

    /// Another Apple ID signs in (CloudKit posts `CKAccountChanged`).
    func signIn(_ identity: String) {
        current.withLock { $0 = identity }
        changes.withLock { $0 += 1 }
    }

    /// `identity` signs in right after the next fetch page is served.
    func switchDuringNextFetch(to identity: String) {
        pendingSwitch.withLock { $0 = identity }
    }

    func fetchChanges(since token: Data?) async throws -> RemoteBatch {
        let batch = try await zone.fetchChanges(since: token)
        if let next = pendingSwitch.withLock({ s -> String? in defer { s = nil }; return s }) { signIn(next) }
        return batch
    }
    func send(_ changes: [RemoteRecord]) async throws -> [SendResult] { try await zone.send(changes) }
    func accountAvailable() async -> Bool { true }
    func accountIdentity() async throws -> String? { current.withLock { $0 } }
    func accountChangeCount() async -> UInt64 { changes.withLock { $0 } }
}

/// Deletes the account params rows straight from the SQLite file (a damaged or emptied local copy),
/// keeping the device state and its pin: the store is then "pinned but missing".
func dropAccountParams(_ path: String) throws {
    var db: OpaquePointer?
    guard sqlite3_open(path, &db) == SQLITE_OK else { throw CocoaError(.fileReadUnknown) }
    defer { sqlite3_close(db) }
    sqlite3_busy_timeout(db, 5000)
    guard sqlite3_exec(db, "DELETE FROM base WHERE kind = 1; DELETE FROM pending WHERE kind = 1;", nil, nil, nil)
        == SQLITE_OK
    else { throw CocoaError(.fileWriteUnknown) }
}

@MainActor
@Suite("iCloud account change and recovery", .timeLimit(.minutes(4)))
struct AccountChangeTests {
    /// Device A synced with account "a", then "b" signs in. Returns A, the switching remote and the zones.
    func switchedDevice(zoneB: InMemoryRemote) async throws -> (SyncDevice, AccountSwitchingRemote, InMemoryRemote) {
        let zoneA = InMemoryRemote()
        let remote = AccountSwitchingRemote(["a": zoneA, "b": zoneB], signedIn: "a")
        let a = try SyncDevice(name: "A", client: remote)
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(a.session, title: "Projet Atlas")
        await a.sync()
        #expect(await a.coordinator.status.isIdle)
        remote.signIn("b")
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .accountChanged)
        return (a, remote, zoneA)
    }

    @Test func otherVaultInTheNewZoneIsRefused() async throws {
        // Zone "b" already holds another OnePass account.
        let zoneB = InMemoryRemote()
        let other = try SyncDevice(remote: zoneB, name: "Autre")
        defer { other.cleanUp() }
        _ = try await other.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await other.sync()
        let (a, _, _) = try await switchedDevice(zoneB: zoneB)
        defer { a.cleanUp() }
        let sentBefore = await zoneB.sentBatches.count

        #expect(try await a.coordinator.checkAccountChange() == .otherVault)
        #expect(await a.coordinator.acceptAccountChange(expected: .emptyZone) == .refusedOtherVault)
        #expect(await a.coordinator.acceptAccountChange(expected: .sameVault) == .refusedOtherVault)
        #expect(await a.coordinator.status == .accountChanged)
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .accountChanged)
        #expect(await zoneB.sentBatches.count == sentBefore)
        #expect(AccountChangeOutcome.otherVaultMessage.hasPrefix("Ce compte iCloud contient déjà un autre coffre OnePass."))
    }

    @Test func sameVaultInTheNewZoneIsAccepted() async throws {
        // Zone "b" holds a copy of our own account (same account id): accepted, nothing to upload twice.
        let zoneB = InMemoryRemote()
        let (a, _, zoneA) = try await switchedDevice(zoneB: zoneB)
        defer { a.cleanUp() }
        // Copy every live record of zone "a" into zone "b".
        let copy = try await zoneA.fetchChanges(since: nil).changes.filter { $0.data != nil }
            .map { RemoteRecord(name: $0.name, version: $0.version, data: $0.data, serverMeta: nil) }
        _ = try await zoneB.send(copy)

        #expect(try await a.coordinator.checkAccountChange() == .sameVault)
        #expect(await a.coordinator.acceptAccountChange(expected: .sameVault) == .accepted)
        #expect(await a.coordinator.status.isIdle)
        #expect(try await a.pendingChanges().isEmpty)
        try await addItem(a.session, title: "Camille Durand")
        await a.sync()
        #expect(await a.coordinator.status.isIdle)
        #expect(try await zoneB.accountRecordIDs() == [a.settings.accountID!])
    }

    @Test func emptyNewZoneReceivesTheVault() async throws {
        let zoneB = InMemoryRemote()
        let (a, _, _) = try await switchedDevice(zoneB: zoneB)
        defer { a.cleanUp() }
        #expect(await zoneB.sentBatches.isEmpty)

        #expect(try await a.coordinator.checkAccountChange() == .emptyZone)
        #expect(await a.coordinator.acceptAccountChange(expected: .emptyZone) == .accepted)
        #expect(await a.coordinator.status.isIdle)
        #expect(try await a.pendingChanges().isEmpty)
        // The whole vault went to the new zone: a new device restores from it.
        #expect(try await zoneB.accountRecordIDs() == [a.settings.accountID!])
        let fresh = try SyncDevice(remote: zoneB, name: "Nouveau")
        defer { fresh.cleanUp() }
        #expect(try await fresh.coordinator.remoteHasAccount())
        await fresh.session.reload()
        try await fresh.session.restore(secretKey: try #require(a.secretKey), password: testPassword)
        #expect(fresh.titles == ["Projet Atlas"])
    }

    /// The user confirmed "same vault" but the zone is empty now: the upload confirmation was never
    /// shown, so nothing is accepted. Same the other way round.
    @Test func zoneThatChangedSinceTheConfirmationIsRefused() async throws {
        let zoneB = InMemoryRemote()
        let (a, _, _) = try await switchedDevice(zoneB: zoneB)
        defer { a.cleanUp() }
        #expect(try await a.coordinator.checkAccountChange() == .emptyZone)
        #expect(await a.coordinator.acceptAccountChange(expected: .sameVault) == .changedDuringCheck)
        #expect(await a.coordinator.status == .accountChanged)
        #expect(await zoneB.sentBatches.isEmpty)
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .accountChanged)
        #expect(await zoneB.sentBatches.isEmpty)
    }

    /// Another Apple ID signs in while the zone is being inspected: refused, nothing stored.
    @Test func identityChangeDuringTheInspectionIsRefused() async throws {
        let zoneB = InMemoryRemote()
        let zoneC = InMemoryRemote()
        let zoneA = InMemoryRemote()
        let remote = AccountSwitchingRemote(["a": zoneA, "b": zoneB, "c": zoneC], signedIn: "a")
        let a = try SyncDevice(name: "A", client: remote)
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        remote.signIn("b")
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .accountChanged)

        // "c" signs in during the inspection of "b" (after its first page).
        remote.switchDuringNextFetch(to: "c")
        #expect(await a.coordinator.acceptAccountChange(expected: .emptyZone) == .changedDuringCheck)
        #expect(await zoneB.sentBatches.isEmpty)
        #expect(await zoneC.sentBatches.isEmpty)
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .accountChanged)
    }

    /// The same identity, but CloudKit signalled an account change during the inspection: refused.
    @Test func accountChangeSignalDuringTheInspectionIsRefused() async throws {
        let zoneB = InMemoryRemote()
        let (a, remote, _) = try await switchedDevice(zoneB: zoneB)
        defer { a.cleanUp() }
        remote.switchDuringNextFetch(to: "b")
        #expect(await a.coordinator.acceptAccountChange(expected: .emptyZone) == .changedDuringCheck)
        #expect(await zoneB.sentBatches.isEmpty)
        #expect(await a.coordinator.acceptAccountChange(expected: .emptyZone) == .accepted)
        #expect(await !zoneB.sentBatches.isEmpty)
    }

    /// A clock set back after the fetch: the check counts as stale and is done again before sending.
    @Test func clockSetBackMakesTheIdentityCheckStale() async throws {
        let remote = InMemoryRemote()
        let clock = Mutex(Date(timeIntervalSince1970: 2_000_000))
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-back-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("vault.sqlite").path
        try createAccountWithKdf(dbPath: path, password: testPassword, kdf: SessionHarness.fastKdf).session.lock()
        let store = try openSyncStore(dbPath: path)
        let ticking = ClockTickingRemote(remote) { clock.withLock { $0 = $0.addingTimeInterval(-3600) } }
        let coordinator = SyncCoordinator(store: store, remote: ticking, now: { clock.withLock { $0 } })
        await remote.changeIdentityAfterNextFetch(to: "utilisateur-icloud-b", announce: false)
        await coordinator.syncNow()
        #expect(await coordinator.status == .accountChanged)
        #expect(await remote.sentBatches.isEmpty)
    }

    // MARK: - Identity checked before the send

    /// Another Apple ID signs in between the fetch and the send, and CloudKit says so: nothing is sent.
    @Test func announcedAccountSwitchBetweenFetchAndSendSendsNothing() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        let requests = await remote.identityRequests
        try await addItem(a.session, title: "Projet Atlas")
        await a.session.waitForSyncNotifications()
        let sent = await remote.sentBatches.count

        await remote.changeIdentityAfterNextFetch(to: "utilisateur-icloud-b", announce: true)
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .accountChanged)
        #expect(await remote.sentBatches.count == sent)
        #expect(try await !a.pendingChanges().isEmpty)
        // One check for the fetch, one again before the send (the change was announced).
        #expect(await remote.identityRequests == requests + 2)
    }

    /// The normal round costs one identity call: the one checked by the fetch is reused for the send.
    @Test func usualRoundChecksTheIdentityOnce() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        try await addItem(a.session, title: "Projet Atlas")
        let requests = await remote.identityRequests
        let sent = await remote.sentBatches.count
        await a.sync()
        #expect(await remote.sentBatches.count == sent + 1)
        #expect(await remote.identityRequests == requests + 1)
    }

    /// A check older than 10 minutes is done again before the send, even without any signal.
    @Test func staleIdentityCheckIsRedoneBeforeSending() async throws {
        let remote = InMemoryRemote()
        let clock = Mutex(Date(timeIntervalSince1970: 2_000_000))
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("onepass-stale-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("vault.sqlite").path
        _ = try createAccountWithKdf(dbPath: path, password: testPassword, kdf: SessionHarness.fastKdf).session.lock()
        let store = try openSyncStore(dbPath: path)
        // Each fetch moves the clock 11 minutes forward: the identity is old when the send comes.
        let ticking = ClockTickingRemote(remote) { clock.withLock { $0 = $0.addingTimeInterval(660) } }
        let coordinator = SyncCoordinator(store: store, remote: ticking, now: { clock.withLock { $0 } })
        await remote.changeIdentityAfterNextFetch(to: "utilisateur-icloud-b", announce: false)
        // First round: binds to "a" during the fetch, then sees "b" before the send.
        await coordinator.syncNow()
        #expect(await coordinator.status == .accountChanged)
        #expect(await remote.sentBatches.isEmpty)
    }

    /// Without a signal and within 10 minutes, a switch between fetch and send is not seen (the
    /// accepted window of the cheap check); the next fetch stops the sync.
    @Test func unannouncedRecentSwitchIsCaughtByTheNextFetch() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        try await addItem(a.session, title: "Projet Atlas")
        await a.session.waitForSyncNotifications()
        await remote.changeIdentityAfterNextFetch(to: "utilisateur-icloud-b", announce: false)
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status.isIdle)
        await a.coordinator.syncNow()
        #expect(await a.coordinator.status == .accountChanged)
    }

    // MARK: - Refused deletions

    @Test func refusedDeletionsAreCountedAndCleared() async throws {
        let remote = InMemoryRemote()
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        #expect(await b.coordinator.ignoredDeletionCount == 0)
        let account = RecordName(kind: 1, id: try #require(a.settings.accountID))
        await remote.forgeDeletion(name: account)
        await remote.forgeDeletion(name: RecordName(kind: 2, id: account.id))
        await b.coordinator.syncNow()
        #expect(await b.coordinator.ignoredDeletionCount == 2)
        let log = try await b.coordinator.ignoredDeletions()
        #expect(log.map(\.kind) == [1, 2])
        #expect(log.allSatisfy { $0.id == account.id && $0.at > 0 })
        try await b.coordinator.clearIgnoredDeletions()
        #expect(await b.coordinator.ignoredDeletionCount == 0)
        #expect(try await b.coordinator.ignoredDeletions().isEmpty)
    }

    // MARK: - Account missing

    /// "Restaurer avec mon Emergency Kit": the local copy lost its account; after the reset, the data
    /// comes back from the remote and the restore ends unlocked, with a fresh pin.
    @Test func missingAccountRecoversThroughTheRestorePath() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "Camille Durand", mode: .personal)
        try await addItem(a.session, title: "Projet Atlas")
        await a.sync()
        let secretKey = try #require(a.secretKey)
        let accountID = try #require(a.settings.accountID)
        a.session.lock()
        await a.session.waitForReleasedSessions()

        let path = a.dir.appendingPathComponent("vault.sqlite").path
        try dropAccountParams(path)
        await a.session.reload()
        #expect(a.session.isAccountMissing)
        #expect(try a.store.storeState() == .pinnedButMissing)

        try await a.session.resetForRecovery()
        #expect(a.session.state == .noAccount)
        #expect(a.settings.accountID == nil)
        #expect(a.settings.displayName.isEmpty)
        #expect(try !SecretKeyVault(keychain: a.keychain).contains(accountID: accountID))
        #expect(try a.store.storeState() == .empty)

        // The restore flow: fetch from the remote, then the Emergency Kit and the master password.
        #expect(try await a.coordinator.remoteHasAccount())
        await a.session.reload()
        #expect(a.session.state == .locked)
        #expect(a.session.needsSecretKey)
        try await a.session.restore(secretKey: secretKey, password: testPassword)
        #expect(a.session.state == .unlocked)
        #expect(a.titles == ["Projet Atlas"])
        // Fresh pin: losing the account again is reported as missing, not as an empty store.
        a.session.lock()
        await a.session.waitForReleasedSessions()
        try dropAccountParams(path)
        #expect(try a.store.storeState() == .pinnedButMissing)
    }

    /// "Repartir de zéro": the store, the Secret Key and the enrollment go, the onboarding can create a
    /// new account. Nothing is deleted remotely.
    @Test func startingOverEndsWithNoAccount() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille Durand", mode: .personal)
        try await session.enrollBiometrics(password: testPassword)
        let accountID = try #require(h.settings.accountID)
        #expect(h.environment.biometrics.isEnrolled(accountID: accountID))
        session.lock()
        await session.waitForReleasedSessions()

        // Not missing: refused, nothing touched.
        await #expect(throws: VaultError.self) { try await session.resetForRecovery() }
        #expect(session.state == .locked)

        try dropAccountParams(h.environment.databaseURL.path)
        await session.reload()
        #expect(session.isAccountMissing)
        h.settings.lockoutUntil = h.clock.now.addingTimeInterval(300)
        try await session.resetForRecovery()
        #expect(session.state == .noAccount)
        #expect(session.lastError == nil)
        #expect(h.settings.accountID == nil)
        #expect(h.settings.lockoutUntil == nil)
        #expect(!h.environment.biometrics.isEnrolled(accountID: accountID))
        #expect(try !SecretKeyVault(keychain: h.keychain).contains(accountID: accountID))
        #expect(h.makeSession().state == .noAccount)

        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        #expect(session.state == .unlocked)
        #expect(h.settings.accountID != accountID)
    }
}

/// Runs `tick` after every fetch (moves an injected clock).
final class ClockTickingRemote: RemoteRecordStore {
    let inner: InMemoryRemote
    let tick: @Sendable () -> Void
    init(_ inner: InMemoryRemote, tick: @escaping @Sendable () -> Void) {
        self.inner = inner
        self.tick = tick
    }
    var maxBatchRecords: Int { inner.maxBatchRecords }
    var maxBatchBytes: Int { inner.maxBatchBytes }
    func fetchChanges(since token: Data?) async throws -> RemoteBatch {
        defer { tick() }
        return try await inner.fetchChanges(since: token)
    }
    func send(_ changes: [RemoteRecord]) async throws -> [SendResult] { try await inner.send(changes) }
    func accountAvailable() async -> Bool { await inner.accountAvailable() }
    func accountIdentity() async throws -> String? { try await inner.accountIdentity() }
    func accountChangeCount() async -> UInt64 { await inner.accountChangeCount() }
}
