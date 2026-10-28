import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// Every status a coordinator publishes, in order.
final class StatusLog: Sendable {
    private let state = Mutex<[SyncStatus]>([])

    var all: [SyncStatus] { state.withLock { $0 } }
    var refusals: [SyncStatus] { all.filter { if case .refused = $0 { true } else { false } } }

    fileprivate func append(_ status: SyncStatus) { state.withLock { $0.append(status) } }

    static func watching(_ coordinator: SyncCoordinator) async -> StatusLog {
        let log = StatusLog()
        let stream = await coordinator.statusUpdates()
        Task { for await status in stream { log.append(status) } }
        return log
    }

    /// Lets the stream deliver what was yielded so far.
    func settle() async {
        try? await Task.sleep(for: .milliseconds(50))
    }
}

extension SyncCoordinator {
    var healthIsOk: Bool { health.allSatisfy { $0.state == .ok } }
    var alertKinds: [String] { health.compactMap { if case .alert(let kind) = $0.state { kind } else { nil } } }
}

/// Rounds on every device, in order, until each one is `Ok` everywhere and idle (12 rounds at most),
/// then one more pass so the first devices fetch what the last ones sent.
@MainActor
func syncUntilHealthy(_ devices: [SyncDevice], rounds: Int = 12) async -> Bool {
    for _ in 0..<rounds {
        for device in devices { await device.sync() }
        var healthy = true
        for device in devices {
            let coordinator = device.coordinator
            if !(await coordinator.healthIsOk), device.session.state == .unlocked { healthy = false }
            if !(await coordinator.status.isIdle) { healthy = false }
        }
        if healthy {
            for device in devices { await device.sync() }
            return true
        }
    }
    return false
}

/// A, B and C share one vault. C writes offline while A writes and syncs, B sees A's write; then the
/// server serves the old manifest again and C pushes its own next version: the server forked from
/// what B verified. B ends unlocked (its copy is served for reading) with a `manifest_rollback` alert.
@MainActor
func forkedDevices(remote: InMemoryRemote) async throws -> (a: SyncDevice, b: SyncDevice, c: SyncDevice, atlas: FfiItem) {
    let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
    let c = try SyncDevice(remote: remote, name: "C")
    _ = try await c.coordinator.remoteHasAccount()
    await c.session.reload()
    try await c.session.restore(secretKey: try #require(a.secretKey), password: testPassword)
    await c.sync()
    let manifest = RecordName(kind: 6, id: atlas.vaultId)
    let base = try #require(await remote.record(manifest)?.version)
    try await addItem(c.session, title: "Note C")
    try await addItem(a.session, title: "Note A")
    await a.sync()
    await b.sync()
    await remote.replay(name: manifest, version: base)
    await c.sync()
    await b.sync()
    return (a, b, c, atlas)
}

/// Spec 3.2 and 3.3 with `InMemoryRemote`: the normal CloudKit behaviours never refuse a vault, and the
/// safe exits of an alert converge.
@MainActor
@Suite("Sync health and safe exits", .serialized, .timeLimit(.minutes(4)))
struct SyncHealthTests {
    static let fastKdfPassphrase = "Lanterne vive 77 sur le quai !"

    /// Readable (unlocked after a reload, the item there) and writable (a new item saves).
    func expectUsable(_ device: SyncDevice, contains title: String, write: String) async throws {
        await device.session.reload()
        #expect(device.session.state == .unlocked)
        #expect(device.titles.contains(title))
        try await addItem(device.session, title: write)
    }

    /// Lagging replica: the server serves the manifest before the one B verified.
    @Test func propagationDelayNeverRefuses() async throws {
        let remote = InMemoryRemote()
        let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        let manifest = RecordName(kind: 6, id: atlas.vaultId)
        let older = try #require(await remote.record(manifest)?.version)
        try await addItem(a.session, title: "Note A")
        await a.sync()
        await b.sync()
        let (logA, logB) = (await StatusLog.watching(a.coordinator), await StatusLog.watching(b.coordinator))

        await remote.replay(name: manifest, version: older)
        await b.sync()
        let behind = await b.coordinator.status
        #expect(behind == .waitingForServer || behind.isIdle)
        try await expectUsable(b, contains: "Note A", write: "Note B")

        #expect(await syncUntilHealthy([b, a]))
        await a.session.reload()
        #expect(a.titles == b.titles)
        #expect(a.titles.isSuperset(of: ["Note A", "Note B"]))
        await logA.settle()
        #expect(logA.refusals.isEmpty && logB.refusals.isEmpty)
    }

    /// A round cut between two batches: the item is saved, the manifest is not.
    @Test func partialSendRetryNeverRefuses() async throws {
        let remote = InMemoryRemote(maxBatchRecords: 1)
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        let (logA, logB) = (await StatusLog.watching(a.coordinator), await StatusLog.watching(b.coordinator))
        try await addItem(a.session, title: "Note A")
        await remote.failSend(afterBatches: 1)
        await a.sync()
        #expect(await a.coordinator.status == .offline)
        #expect(!(try await a.pendingChanges().isEmpty))

        await b.sync()
        try await expectUsable(b, contains: "Projet Atlas", write: "Note B")
        try await expectUsable(a, contains: "Note A", write: "Note A2")

        #expect(await syncUntilHealthy([a, b]))
        await a.session.reload()
        await b.session.reload()
        #expect(a.titles == b.titles)
        #expect(a.titles.isSuperset(of: ["Note A", "Note A2", "Note B"]))
        await logA.settle()
        #expect(logA.refusals.isEmpty && logB.refusals.isEmpty)
    }

    /// A fetch cut between two pages (`moreComing`), then completed by the next round.
    @Test func partialFetchNeverRefuses() async throws {
        let remote = InMemoryRemote(pageSize: 1)
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        let (logA, logB) = (await StatusLog.watching(a.coordinator), await StatusLog.watching(b.coordinator))
        try await addItem(a.session, title: "Note A")
        try await addItem(a.session, title: "Note A2")
        await a.sync()

        await remote.failFetch(afterPages: 1)
        await b.sync()
        #expect(await b.coordinator.status == .offline)
        try await expectUsable(b, contains: "Projet Atlas", write: "Note B")

        #expect(await syncUntilHealthy([b, a]))
        await a.session.reload()
        await b.session.reload()
        #expect(a.titles == b.titles)
        #expect(a.titles.isSuperset(of: ["Note A", "Note A2", "Note B"]))
        await logA.settle()
        #expect(logA.refusals.isEmpty && logB.refusals.isEmpty)
    }

    /// An expired change token: the next fetch restarts from scratch.
    @Test func expiredTokenNeverRefuses() async throws {
        let remote = InMemoryRemote(omitsTombstonesOnFullFetch: true)
        let (a, b, atlas) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        let (logA, logB) = (await StatusLog.watching(a.coordinator), await StatusLog.watching(b.coordinator))
        try await addItem(a.session, title: "Note A")
        try await a.session.trash(itemID: atlas.id, vaultID: atlas.vaultId)
        await a.sync()

        await remote.expireTokens()
        await b.sync()
        try await expectUsable(b, contains: "Note A", write: "Note B")

        #expect(await syncUntilHealthy([b, a]))
        await a.session.reload()
        await b.session.reload()
        #expect(a.titles == b.titles)
        await logA.settle()
        #expect(logA.refusals.isEmpty && logB.refusals.isEmpty)
    }

    /// The user deleted the zone; it comes back empty and the devices fill it again.
    @Test func recreatedEmptyZoneNeverRefuses() async throws {
        let remote = InMemoryRemote(omitsTombstonesOnFullFetch: true)
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        try await addItem(a.session, title: "Note A")
        await a.sync()
        await b.sync()
        let (logA, logB) = (await StatusLog.watching(a.coordinator), await StatusLog.watching(b.coordinator))

        await remote.simulateReset()
        await b.sync()
        try await expectUsable(b, contains: "Note A", write: "Note B")
        try await expectUsable(a, contains: "Note A", write: "Note A2")

        #expect(await syncUntilHealthy([a, b]))
        await a.session.reload()
        await b.session.reload()
        #expect(a.titles == b.titles)
        #expect(a.titles.isSuperset(of: ["Note A", "Note A2", "Note B"]))
        await logA.settle()
        #expect(logA.refusals.isEmpty && logB.refusals.isEmpty)
    }

    /// A's items reach the server one batch before their manifest; B syncs between the two.
    @Test func batchSeenBetweenItsHalvesNeverRefuses() async throws {
        let remote = InMemoryRemote(maxBatchRecords: 1)
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        let (logA, logB) = (await StatusLog.watching(a.coordinator), await StatusLog.watching(b.coordinator))
        try await addItem(a.session, title: "Note A")
        let between = Mutex(false)
        await remote.afterNextSave {
            await b.sync()
            between.withLock { $0 = true }
        }
        await a.sync()
        #expect(between.withLock { $0 })
        try await expectUsable(b, contains: "Projet Atlas", write: "Note B")

        #expect(await syncUntilHealthy([b, a]))
        await a.session.reload()
        await b.session.reload()
        #expect(a.titles == b.titles)
        #expect(a.titles.isSuperset(of: ["Note A", "Note B"]))
        await logA.settle()
        #expect(logA.refusals.isEmpty && logB.refusals.isEmpty)
    }

    // MARK: - Safe exits

    @Test func forkIsAnAlertShownAsARefusal() async throws {
        let remote = InMemoryRemote()
        let (a, b, c, _) = try await forkedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp(); c.cleanUp() }
        #expect(await b.coordinator.status == .refused(kind: "manifest_rollback"))
        #expect(await b.coordinator.alertKinds == ["manifest_rollback"])
        #expect(b.session.safeExitAvailable)
    }

    @Test func safeExitKeepThisDevice() async throws {
        let remote = InMemoryRemote()
        let (a, b, c, _) = try await forkedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp(); c.cleanUp() }
        let wrong = SecretBytes(utf8: "pas le bon mot de passe")
        await #expect(throws: VaultError.wrongPassword) { try await b.session.runSafeExit(.keepThisDevice, password: wrong) }

        let password = SecretBytes(utf8: testPassword)
        try await b.session.runSafeExit(.keepThisDevice, password: password)
        password.wipe()
        await b.session.waitForSyncNotifications()
        let log = await StatusLog.watching(b.coordinator)
        #expect(await syncUntilHealthy([b, a, c]))
        await log.settle()
        // After the exit: never the refusal again, and idle only once every vault is `Ok`.
        let statuses = Array(log.all.drop { $0 != .syncing })
        #expect(statuses.allSatisfy { if case .refused = $0 { false } else { true } })
        #expect(await b.coordinator.healthIsOk)
        for device in [a, b, c] { await device.session.reload() }
        // B's version won: A's write it had verified stays, C's forked write is gone.
        #expect(b.titles == ["Projet Atlas", "Note A"])
        #expect(a.titles == b.titles && c.titles == b.titles)
    }

    @Test func safeExitTakeServer() async throws {
        let remote = InMemoryRemote()
        let (a, b, c, _) = try await forkedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp(); c.cleanUp() }
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        try await b.session.runSafeExit(.takeServer, password: password)
        await b.session.waitForSyncNotifications()
        #expect(await syncUntilHealthy([b, a, c]))
        for device in [a, b, c] { await device.session.reload() }
        #expect(b.titles.contains("Note C"))
        #expect(a.titles == b.titles && c.titles == b.titles)
    }

    @Test func safeExitExportFirst() async throws {
        let remote = InMemoryRemote()
        let (a, b, c, _) = try await forkedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp(); c.cleanUp() }
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        let weak = SecretBytes(utf8: "azerty")
        await #expect(throws: VaultError.validation(field: "passphrase", reason: "too weak")) {
            _ = try await b.session.exportEncryptedBackup(password: password, passphrase: weak)
        }
        let passphrase = SecretBytes(utf8: Self.fastKdfPassphrase)
        defer { passphrase.wipe() }
        let archive = try await b.session.exportEncryptedBackup(password: password, passphrase: passphrase)
        #expect(archive.count > 64)
        #expect(archive.prefix(6) == Data("OPARCH".utf8))
        // Exporting changes nothing: the alert is still there and the exit still runs afterwards.
        await b.sync()
        #expect(await b.coordinator.status == .refused(kind: "manifest_rollback"))
        try await b.session.runSafeExit(.takeServer, password: password)
        await b.session.waitForSyncNotifications()
        #expect(await syncUntilHealthy([b, a, c]))
    }

    /// After "keep this device", C writes the vault before B's epoch ships (B's first send fails): B's
    /// next rebase withdraws the epoch (`Conflict`). B keeps syncing, issues it again while the alert
    /// remains, and converges; it never shows the refusal again, nor idle before every vault is `Ok`.
    @Test func keepThenConflictThenConverge() async throws {
        let remote = InMemoryRemote()
        let (a, b, c, _) = try await forkedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp(); c.cleanUp() }
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        let log = await StatusLog.watching(b.coordinator)

        await remote.setSendsOffline(true)
        try await b.session.runSafeExit(.keepThisDevice, password: password)
        await b.sync()
        #expect(await b.coordinator.status == .offline)
        await remote.setSendsOffline(false)
        try await addItem(c.session, title: "Note C2")
        await c.sync()

        await b.sync()
        await log.settle()
        #expect(log.all.contains(.waitingForServer))
        #expect(await syncUntilHealthy([b, a, c]))
        await log.settle()
        // From the first round after the exit (the stream starts with the refusal it answers).
        let statuses = Array(log.all.drop { $0 != .syncing })
        #expect(statuses.allSatisfy { if case .refused = $0 { false } else { true } })
        let idleIndex = statuses.firstIndex { $0.isIdle }
        let firstIdle = try #require(idleIndex)
        #expect(statuses[..<firstIdle].allSatisfy { !$0.isIdle })
        #expect(statuses[..<firstIdle].contains(.waitingForServer))
        #expect(await b.coordinator.withdrawnEpochs >= 1)
        #expect(await b.coordinator.keepReissues >= 1)
        for device in [a, b, c] { await device.session.reload() }
        #expect(a.titles == b.titles && c.titles == b.titles)
    }

    /// "Données refusées" (session failed): a tampered item this device never kept a verified copy of.
    /// The exits need the master password, refuse what the core cannot do (no verified copy, no valid
    /// server state) and leave the screen as it was; a wrong password counts toward the throttle.
    @Test func safeExitFromTheFailedScreenAsksThePasswordAndKeepsTheScreenOnRefusal() async throws {
        let remote = InMemoryRemote()
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        let item = try #require(await remote.tags().keys.first { $0.kind == 5 })
        await remote.tamper(name: item)
        await a.sync()
        await a.session.reload()
        let failed = a.session.state
        guard case .failed(.integrity(let kind)) = failed else {
            Issue.record("state \(failed)")
            return
        }
        #expect(await a.coordinator.status == .refused(kind: kind))
        #expect(a.session.safeExitAvailable)

        let wrong = SecretBytes(utf8: "pas le bon mot de passe")
        await #expect(throws: VaultError.wrongPassword) { try await a.session.runSafeExit(.keepThisDevice, password: wrong) }
        #expect(a.settings.failedUnlocks == 1)
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        await #expect(throws: VaultError.integrity(kind: kind)) {
            try await a.session.runSafeExit(.keepThisDevice, password: password)
        }
        #expect(a.session.state == failed)
        #expect(a.session.summaries.isEmpty && a.session.allVaults.isEmpty)
        #expect(a.settings.failedUnlocks == 0)
    }
}

@Suite("Encrypted backup file and safe exit texts")
struct EncryptedBackupFileTests {
    /// Messages are compared in French, the source language, whatever the machine's language.
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func fileNameCarriesTheDay() {
        let date = Date(timeIntervalSince1970: 1_793_000_000)  // 2026-10-26 in UTC
        let utc = TimeZone(identifier: "UTC")!
        #expect(EncryptedBackupFile.fileName(for: date, timeZone: utc) == "OnePass sauvegarde 2026-10-26.onepass")
    }

    @Test func temporaryCopyIsWrittenThenRemoved() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-backup-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        let data = Data("OPARCH test".utf8)
        let url = try EncryptedBackupFile.write(data, named: "OnePass sauvegarde 2026-10-26.onepass", under: parent)
        #expect(try Data(contentsOf: url) == data)
        #expect(url.deletingLastPathComponent().lastPathComponent.hasPrefix("backup-"))
        // A file outside a backup folder of `parent` is never removed.
        let stranger = parent.appendingPathComponent("autre.onepass")
        try data.write(to: stranger)
        EncryptedBackupFile.remove(stranger, under: parent)
        #expect(FileManager.default.fileExists(atPath: stranger.path))
        EncryptedBackupFile.remove(url, under: parent)
        #expect(!FileManager.default.fileExists(atPath: url.deletingLastPathComponent().path))
        #expect(throws: (any Error).self) {
            _ = try EncryptedBackupFile.write(data, named: "../evasion.onepass", under: parent)
        }
        #expect(throws: (any Error).self) {
            _ = try EncryptedBackupFile.write(data, named: "sauvegarde.pdf", under: parent)
        }
    }

    @Test func sweepRemovesLeftovers() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-backup-sweep-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        let url = try EncryptedBackupFile.write(Data([1]), named: "a.onepass", under: parent)
        EncryptedBackupFile.sweep(in: parent)
        #expect(!FileManager.default.fileExists(atPath: url.path))
    }

    @Test func newErrorKindsHaveFrenchTexts() {
        // French source, or its English translation when the test runs in English.
        #expect(["Une ancienne restauration du coffre a été rejouée.", "An old restore of the vault was replayed."]
            .contains(VaultError.integrityLabel("epoch_rollback")))
        let weak = VaultError.validationMessage("too weak")
        #expect(weak.hasPrefix("Trop facile à deviner") || weak.hasPrefix("Too easy to guess"))
        #expect(["Synchronisation en attente d'iCloud", "Sync waiting for iCloud"].contains(SyncStatus.waitingForServer.label))
        for text in [VaultError.integrityLabel("epoch_rollback"), VaultError.validationMessage("too weak"),
                     SyncStatus.waitingForServer.label] {
            #expect(!text.contains("\u{2014}"))
        }
    }
}
