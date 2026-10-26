import Foundation

/// One-time move of the milestone 2 store and settings into the shared container (ruling A3).
/// Run at app launch, before anything opens the database. Safe to call on every launch.
public enum SharedContainerMigration {
    /// Marker written in the shared defaults once the settings were copied.
    static let settingsMarker = "onepass.settingsMigratedToSharedContainer"

    /// Does nothing without a shared container. Moves `-shm`, `-wal`, then the database, so that a stop
    /// in the middle leaves the old database complete; an existing shared database always wins and the
    /// old files are left alone. Then copies the `onepass.*` settings once.
    public static func run(
        from legacyDatabase: URL, legacyDefaults: UserDefaults, to container: SharedContainer,
        fileManager: FileManager = .default
    ) throws {
        guard container.isShared else { return }
        let target = container.databaseURL
        if !fileManager.fileExists(atPath: target.path) {
            try moveDatabase(from: legacyDatabase, to: target, container: container, fileManager: fileManager)
        }
        copySettings(from: legacyDefaults, to: container.defaults)
    }

    private static func moveDatabase(
        from source: URL, to target: URL, container: SharedContainer, fileManager: FileManager
    ) throws {
        guard fileManager.fileExists(atPath: source.path) else { return }
        guard container.prepareFolder(fileManager: fileManager, probe: false) else {
            throw CocoaError(.fileWriteUnknown)
        }
        for suffix in ["-shm", "-wal", ""] {
            let from = URL(fileURLWithPath: source.path + suffix)
            let to = URL(fileURLWithPath: target.path + suffix)
            guard fileManager.fileExists(atPath: from.path) else { continue }
            // A leftover at the destination would be a stale sidecar of another store: replace it.
            if fileManager.fileExists(atPath: to.path) { try fileManager.removeItem(at: to) }
            try fileManager.moveItem(at: from, to: to)
            #if os(iOS) || os(visionOS)
            try? fileManager.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: to.path)
            #endif
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
