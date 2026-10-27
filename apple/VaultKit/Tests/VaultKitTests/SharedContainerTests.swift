import Foundation
import Testing

@testable import VaultKit

@Suite("Shared container and migration")
struct SharedContainerTests {
    /// A temporary legacy folder, a temporary shared root and two throwaway defaults suites.
    final class Sandbox {
        let base: URL
        let legacyDatabase: URL
        let legacyDefaults: UserDefaults
        let sharedSuite: String
        let legacySuite: String
        let shared: SharedContainer

        init(isShared: Bool = true) throws {
            base = FileManager.default.temporaryDirectory
                .appendingPathComponent("onepass-shared-\(UUID().uuidString)", isDirectory: true)
            let legacyFolder = base.appendingPathComponent("legacy/OnePass", isDirectory: true)
            try FileManager.default.createDirectory(at: legacyFolder, withIntermediateDirectories: true)
            legacyDatabase = legacyFolder.appendingPathComponent("vault.sqlite")
            legacySuite = "onepass.tests.legacy.\(UUID().uuidString)"
            sharedSuite = "onepass.tests.shared.\(UUID().uuidString)"
            legacyDefaults = UserDefaults(suiteName: legacySuite)!
            shared = SharedContainer(
                root: base.appendingPathComponent("group", isDirectory: true),
                isShared: isShared, defaultsSuite: sharedSuite)
        }

        func write(_ url: URL, _ text: String) throws {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(text.utf8).write(to: url)
        }

        func read(_ url: URL) -> String? {
            (try? Data(contentsOf: url)).flatMap { String(data: $0, encoding: .utf8) }
        }

        func exists(_ url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }

        func sidecar(_ url: URL, _ suffix: String) -> URL {
            URL(fileURLWithPath: url.path + suffix)
        }

        func makeLegacy() throws {
            try write(legacyDatabase, "db")
            try write(sidecar(legacyDatabase, "-wal"), "wal")
            try write(sidecar(legacyDatabase, "-shm"), "shm")
        }

        deinit {
            try? FileManager.default.removeItem(at: base)
            UserDefaults(suiteName: legacySuite)?.removePersistentDomain(forName: legacySuite)
            UserDefaults(suiteName: sharedSuite)?.removePersistentDomain(forName: sharedSuite)
        }
    }

    @Test func sharedDatabasePathIsUnderLibraryApplicationSupport() throws {
        let box = try Sandbox()
        #expect(
            box.shared.databaseURL.path
                == box.shared.root.path + "/Library/Application Support/OnePass/vault.sqlite")
        let local = SharedContainer(root: box.base, isShared: false, defaultsSuite: nil)
        #expect(local.databaseURL.path == box.base.path + "/OnePass/vault.sqlite")
    }

    @Test func migratesDatabaseAndSidecars() throws {
        let box = try Sandbox()
        try box.makeLegacy()
        try SharedContainerMigration.run(
            from: box.legacyDatabase, legacyDefaults: box.legacyDefaults, to: box.shared)
        let target = box.shared.databaseURL
        #expect(box.read(target) == "db")
        #expect(box.read(box.sidecar(target, "-wal")) == "wal")
        #expect(box.read(box.sidecar(target, "-shm")) == "shm")
        #expect(!box.exists(box.legacyDatabase))
        #expect(!box.exists(box.sidecar(box.legacyDatabase, "-wal")))
        #expect(!box.exists(box.sidecar(box.legacyDatabase, "-shm")))
    }

    @Test func keepsSharedDatabaseWhenBothExist() throws {
        let box = try Sandbox()
        try box.makeLegacy()
        try box.write(box.shared.databaseURL, "shared")
        try SharedContainerMigration.run(
            from: box.legacyDatabase, legacyDefaults: box.legacyDefaults, to: box.shared)
        #expect(box.read(box.shared.databaseURL) == "shared")
        #expect(!box.exists(box.sidecar(box.shared.databaseURL, "-wal")))
        #expect(box.read(box.legacyDatabase) == "db")
        #expect(box.read(box.sidecar(box.legacyDatabase, "-wal")) == "wal")
    }

    @Test func isIdempotent() throws {
        let box = try Sandbox()
        try box.makeLegacy()
        box.legacyDefaults.set("fiveMinutes", forKey: "onepass.autoLockDelay")
        for _ in 0..<2 {
            try SharedContainerMigration.run(
                from: box.legacyDatabase, legacyDefaults: box.legacyDefaults, to: box.shared)
        }
        #expect(box.read(box.shared.databaseURL) == "db")
        #expect(box.read(box.sidecar(box.shared.databaseURL, "-wal")) == "wal")
        #expect(!box.exists(box.legacyDatabase))
        #expect(box.shared.defaults.string(forKey: "onepass.autoLockDelay") == "fiveMinutes")
    }

    @Test func interruptedMoveLeavesOldDatabaseWhole() throws {
        let box = try Sandbox()
        // Sidecars were moved, the main file was not: the old database is still complete.
        try box.write(box.legacyDatabase, "db")
        try box.write(box.sidecar(box.shared.databaseURL, "-wal"), "wal")
        try box.write(box.sidecar(box.shared.databaseURL, "-shm"), "shm")
        #expect(!box.exists(box.shared.databaseURL))
        try SharedContainerMigration.run(
            from: box.legacyDatabase, legacyDefaults: box.legacyDefaults, to: box.shared)
        #expect(box.read(box.shared.databaseURL) == "db")
        #expect(box.read(box.sidecar(box.shared.databaseURL, "-wal")) == "wal")
        #expect(box.read(box.sidecar(box.shared.databaseURL, "-shm")) == "shm")
        #expect(!box.exists(box.legacyDatabase))
    }

    /// The testable `run`, with a fixed clock and an injected probe and move.
    private func migrate(
        _ box: Sandbox, holdsAccount: @escaping (URL) throws -> Bool = { try hasAccount(dbPath: $0.path) },
        move: ((URL, URL) throws -> Void)? = nil
    ) throws {
        try SharedContainerMigration.run(
            from: box.legacyDatabase, legacyDefaults: box.legacyDefaults, to: box.shared,
            fileManager: .default, now: Date(timeIntervalSince1970: 1_800_000_000),
            holdsAccount: holdsAccount,
            move: move ?? { try FileManager.default.moveItem(at: $0, to: $1) })
    }

    @Test func failedDatabaseMoveRestoresLegacyStore() throws {
        let box = try Sandbox()
        try box.makeLegacy()
        let target = box.shared.databaseURL
        #expect(throws: CocoaError.self) {
            try migrate(
                box,
                move: { from, to in
                    // `-shm` and `-wal` go through, the database move fails.
                    if to.path == target.path { throw CocoaError(.fileWriteNoPermission) }
                    try FileManager.default.moveItem(at: from, to: to)
                })
        }
        #expect(box.read(box.legacyDatabase) == "db")
        #expect(box.read(box.sidecar(box.legacyDatabase, "-wal")) == "wal")
        #expect(box.read(box.sidecar(box.legacyDatabase, "-shm")) == "shm")
        #expect(!box.exists(target))
        #expect(!box.exists(box.sidecar(target, "-wal")))
        #expect(!box.exists(box.sidecar(target, "-shm")))
        // Settings are not copied by a failed run: the fallback keeps the legacy ones.
        #expect(!box.shared.defaults.bool(forKey: SharedContainerMigration.settingsMarker))

        // The next launch completes the move.
        try migrate(box)
        #expect(box.read(target) == "db")
        #expect(box.read(box.sidecar(target, "-wal")) == "wal")
        #expect(box.read(box.sidecar(target, "-shm")) == "shm")
    }

    /// The database move fails, then putting back `-wal` fails too: a distinct error, never the plain
    /// move error that lets the app fall back to a legacy database without its WAL. The next run
    /// moves the stray sidecars back and completes the move.
    @Test func failedRollbackIsReportedAsSplitStore() throws {
        let box = try Sandbox()
        try box.makeLegacy()
        let target = box.shared.databaseURL
        let legacyWal = box.sidecar(box.legacyDatabase, "-wal")
        #expect(throws: SharedContainerMigrationError.rollbackFailed) {
            try migrate(
                box,
                move: { from, to in
                    if to.path == target.path { throw CocoaError(.fileWriteNoPermission) }
                    if to.path == legacyWal.path { throw CocoaError(.fileWriteNoPermission) }
                    try FileManager.default.moveItem(at: from, to: to)
                })
        }
        // `-shm` went back, `-wal` is stranded in the shared folder, the database stayed behind.
        #expect(box.read(box.legacyDatabase) == "db")
        #expect(!box.exists(legacyWal))
        #expect(box.read(box.sidecar(target, "-wal")) == "wal")
        #expect(!box.exists(target))
        #expect(!box.shared.defaults.bool(forKey: SharedContainerMigration.settingsMarker))

        // The next launch brings the stray `-wal` home, then moves the whole store.
        try migrate(box)
        #expect(box.read(target) == "db")
        #expect(box.read(box.sidecar(target, "-wal")) == "wal")
        #expect(box.read(box.sidecar(target, "-shm")) == "shm")
        #expect(!box.exists(box.legacyDatabase))
    }

    @Test func orphanSidecarIsNeverDeleted() throws {
        let box = try Sandbox()
        // An old cut-short move left a `-wal` in the shared folder; the legacy store has a newer one.
        try box.makeLegacy()
        let target = box.shared.databaseURL
        try box.write(box.sidecar(target, "-wal"), "old-wal")
        try migrate(box)
        #expect(box.read(target) == "db")
        #expect(box.read(box.sidecar(target, "-wal")) == "wal")
        #expect(box.read(URL(fileURLWithPath: target.path + ".orphan-1800000000-wal")) == "old-wal")
    }

    @Test func emptySharedStoreIsSetAsideForTheLegacyOne() throws {
        let box = try Sandbox()
        try box.makeLegacy()
        let target = box.shared.databaseURL
        // What the extension used to do before the first migration: an empty store, created by the core.
        try FileManager.default.createDirectory(
            at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        #expect(try storeState(dbPath: target.path) == .empty)
        #expect(box.exists(target))
        try migrate(box)
        #expect(box.read(target) == "db")
        #expect(box.read(box.sidecar(target, "-wal")) == "wal")
        #expect(!box.exists(box.legacyDatabase))
        // Renamed, never deleted.
        let aside = URL(fileURLWithPath: target.path + ".empty-1800000000")
        #expect(box.exists(aside))
        #expect(try hasAccount(dbPath: aside.path) == false)
    }

    @Test func sharedStoreWithAccountWins() throws {
        let box = try Sandbox()
        try box.makeLegacy()
        try box.write(box.shared.databaseURL, "shared")
        try migrate(box, holdsAccount: { _ in true })
        #expect(box.read(box.shared.databaseURL) == "shared")
        #expect(box.read(box.legacyDatabase) == "db")
        #expect(box.read(box.sidecar(box.legacyDatabase, "-wal")) == "wal")
    }

    @Test func unreadableSharedStoreIsKept() throws {
        let box = try Sandbox()
        try box.makeLegacy()
        try box.write(box.shared.databaseURL, "shared")
        try migrate(box, holdsAccount: { _ in throw CocoaError(.fileReadCorruptFile) })
        #expect(box.read(box.shared.databaseURL) == "shared")
        #expect(box.read(box.legacyDatabase) == "db")
    }

    @Test func copiesSettingsOnce() throws {
        let box = try Sandbox()
        box.legacyDefaults.set("oneHour", forKey: "onepass.autoLockDelay")
        box.legacyDefaults.set(true, forKey: "onepass.biometricsWanted")
        box.legacyDefaults.set("keep-out", forKey: "other.key")
        try SharedContainerMigration.run(
            from: box.legacyDatabase, legacyDefaults: box.legacyDefaults, to: box.shared)
        let defaults = box.shared.defaults
        #expect(defaults.string(forKey: "onepass.autoLockDelay") == "oneHour")
        #expect(defaults.bool(forKey: "onepass.biometricsWanted"))
        #expect(defaults.object(forKey: "other.key") == nil)

        defaults.set("fiveMinutes", forKey: "onepass.autoLockDelay")
        try SharedContainerMigration.run(
            from: box.legacyDatabase, legacyDefaults: box.legacyDefaults, to: box.shared)
        #expect(defaults.string(forKey: "onepass.autoLockDelay") == "fiveMinutes")
    }

    @Test func unsharedContainerSkipsMigration() throws {
        let box = try Sandbox(isShared: false)
        try box.makeLegacy()
        box.legacyDefaults.set("oneHour", forKey: "onepass.autoLockDelay")
        try SharedContainerMigration.run(
            from: box.legacyDatabase, legacyDefaults: box.legacyDefaults, to: box.shared)
        #expect(box.read(box.legacyDatabase) == "db")
        #expect(!box.exists(box.shared.databaseURL))
        #expect(!box.exists(box.shared.root))
    }

    @Test func resolveWithoutGroupFallsBackToLocalLocations() {
        let result = SharedContainer.resolve(bundle: Bundle(for: BundleToken.self))
        #expect(!result.isShared)
        #expect(result.databaseURL.lastPathComponent == "vault.sqlite")
        #expect(result.databaseURL.path.hasSuffix("/OnePass/vault.sqlite"))
    }

    @Test func newSettingsDefaults() {
        let suite = "onepass.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let settings = VaultSettings(defaults: defaults)
        #expect(settings.quickTypeSuggestions)
        #expect(!settings.autofillTipDismissed)
        settings.quickTypeSuggestions = false
        settings.autofillTipDismissed = true
        #expect(!settings.quickTypeSuggestions)
        #expect(settings.autofillTipDismissed)
    }

    private final class BundleToken {}
}
