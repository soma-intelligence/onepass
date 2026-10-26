import Foundation

/// One-time move of the milestone 2 store and settings into the shared container (ruling A3).
/// Run at app launch, before anything opens the database. Safe to call on every launch.
public enum SharedContainerMigration {
    /// Marker written in the shared defaults once the settings were copied.
    static let settingsMarker = "onepass.settingsMigratedToSharedContainer"

    /// The store sidecars, in move order: `-shm`, `-wal`, then the database itself.
    static let suffixes = ["-shm", "-wal", ""]

    /// Does nothing without a shared container. Moves `-shm`, `-wal`, then the database. Any failure
    /// during the move puts the files already moved back where they were, so the legacy store stays
    /// whole (database and WAL together) for the fallback. A shared store holding an account always
    /// wins and the old files are left alone; a shared store without an account (created empty by the
    /// AutoFill extension before this move, for instance) is renamed aside, never deleted, when a
    /// legacy store exists. Then copies the `onepass.*` settings once.
    public static func run(
        from legacyDatabase: URL, legacyDefaults: UserDefaults, to container: SharedContainer,
        fileManager: FileManager = .default
    ) throws {
        try run(
            from: legacyDatabase, legacyDefaults: legacyDefaults, to: container, fileManager: fileManager,
            now: Date(), holdsAccount: { try hasAccount(dbPath: $0.path) },
            move: { try fileManager.moveItem(at: $0, to: $1) })
    }

    /// Testable form: the clock, the account probe and the file move are injected.
    static func run(
        from legacyDatabase: URL, legacyDefaults: UserDefaults, to container: SharedContainer,
        fileManager: FileManager, now: Date, holdsAccount: (URL) throws -> Bool,
        move: (URL, URL) throws -> Void
    ) throws {
        guard container.isShared else { return }
        let target = container.databaseURL
        let stamp = String(Int(now.timeIntervalSince1970))
        if fileManager.fileExists(atPath: target.path) {
            // Probed only when a legacy store waits (the probe opens the shared store). A probe failure
            // (unreadable store) keeps the shared store: nothing is moved on a guess.
            if fileManager.fileExists(atPath: legacyDatabase.path),
                (try? holdsAccount(target)) == false
            {
                try setAside(target, label: "empty", stamp: stamp, fileManager: fileManager, move: move)
                try moveDatabase(
                    from: legacyDatabase, to: target, container: container, stamp: stamp,
                    fileManager: fileManager, move: move)
            }
        } else {
            try moveDatabase(
                from: legacyDatabase, to: target, container: container, stamp: stamp,
                fileManager: fileManager, move: move)
        }
        copySettings(from: legacyDefaults, to: container.defaults)
    }

    /// Renames the store and its sidecars to `vault.sqlite.<label>-<stamp>` (and `-wal`, `-shm`).
    /// A failure puts back what was renamed.
    private static func setAside(
        _ database: URL, label: String, stamp: String, fileManager: FileManager, move: (URL, URL) throws -> Void
    ) throws {
        var done: [(from: URL, to: URL)] = []
        do {
            for suffix in suffixes {
                let from = URL(fileURLWithPath: database.path + suffix)
                guard fileManager.fileExists(atPath: from.path) else { continue }
                let to = URL(fileURLWithPath: database.path + ".\(label)-\(stamp)" + suffix)
                try move(from, to)
                done.append((from, to))
            }
        } catch {
            rollBack(done, move: move)
            throw error
        }
    }

    private static func moveDatabase(
        from source: URL, to target: URL, container: SharedContainer, stamp: String,
        fileManager: FileManager, move: (URL, URL) throws -> Void
    ) throws {
        guard container.prepareFolder(fileManager: fileManager, probe: false) else {
            throw CocoaError(.fileWriteUnknown)
        }
        // Sidecars left at the destination without their database: a move cut short (process killed)
        // by an earlier version. They hold the legacy store's last writes, never deleted: back to the
        // legacy folder when it has none, else renamed aside.
        for suffix in ["-shm", "-wal"] {
            let orphan = URL(fileURLWithPath: target.path + suffix)
            guard fileManager.fileExists(atPath: orphan.path) else { continue }
            let home = URL(fileURLWithPath: source.path + suffix)
            if fileManager.fileExists(atPath: source.path), !fileManager.fileExists(atPath: home.path) {
                try move(orphan, home)
            } else {
                try move(orphan, URL(fileURLWithPath: target.path + ".orphan-\(stamp)" + suffix))
            }
        }
        guard fileManager.fileExists(atPath: source.path) else { return }
        var done: [(from: URL, to: URL)] = []
        do {
            for suffix in suffixes {
                let from = URL(fileURLWithPath: source.path + suffix)
                let to = URL(fileURLWithPath: target.path + suffix)
                guard fileManager.fileExists(atPath: from.path) else { continue }
                try move(from, to)
                done.append((from, to))
                #if os(iOS) || os(visionOS)
                try? fileManager.setAttributes(
                    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                    ofItemAtPath: to.path)
                #endif
            }
        } catch {
            rollBack(done, move: move)
            throw error
        }
    }

    /// Moves back, last first, the files a failed step already moved.
    private static func rollBack(_ done: [(from: URL, to: URL)], move: (URL, URL) throws -> Void) {
        for step in done.reversed() {
            try? move(step.to, step.from)
        }
    }

    private static func copySettings(from legacy: UserDefaults, to shared: UserDefaults) {
        guard !shared.bool(forKey: settingsMarker) else { return }
        for (key, value) in legacy.dictionaryRepresentation() where key.hasPrefix("onepass.") {
            if shared.object(forKey: key) == nil { shared.set(value, forKey: key) }
        }
        shared.set(true, forKey: settingsMarker)
    }
}
