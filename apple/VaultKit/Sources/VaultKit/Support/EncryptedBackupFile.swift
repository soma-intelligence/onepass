import Foundation

/// The encrypted backup of a safe exit ("Exporter une sauvegarde chiffrée", spec 3.3) as a file: its
/// name, and a temporary copy for the share sheet only (the Mac writes the bytes straight to the place
/// the user chose). Same handling as the Emergency Kit file: one `backup-<UUID>` folder per export,
/// excluded from backups, complete file protection where the platform has it, removed when the sheet
/// closes and swept at launch.
public enum EncryptedBackupFile {
    public static let fileExtension = "onepass"
    static let folderPrefix = "backup-"

    /// "OnePass sauvegarde 2026-10-26.onepass" (the day in the device's time zone).
    public static func fileName(for date: Date, timeZone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        let day = String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
        return "OnePass sauvegarde \(day).\(fileExtension)"
    }

    /// Writes `data` to `<parent>/backup-<UUID>/<name>` and returns the file URL. On failure nothing is
    /// left behind. `name` must be a plain file name ending in `.onepass`.
    public static func write(_ data: Data, named name: String, under parent: URL) throws -> URL {
        guard isPlainName(name) else { throw CocoaError(.fileWriteInvalidFileName) }
        let folder = parent.appendingPathComponent(folderPrefix + UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try excludeFromBackup(folder)
            let url = folder.appendingPathComponent(name)
            #if os(iOS) || os(visionOS) || os(watchOS)
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            #else
            try data.write(to: url, options: .atomic)
            #endif
            try excludeFromBackup(url)
            return url
        } catch {
            try? FileManager.default.removeItem(at: folder)
            throw error
        }
    }

    /// Removes the folder holding `file`, only when `file` was written by `write` under `parent`.
    public static func remove(_ file: URL, under parent: URL) {
        let folder = file.deletingLastPathComponent()
        guard isPlainName(file.lastPathComponent),
            folder.lastPathComponent.hasPrefix(folderPrefix),
            canonical(folder.deletingLastPathComponent()) == canonical(parent)
        else { return }
        try? FileManager.default.removeItem(at: folder)
    }

    /// Removes every backup folder left in `parent` by a previous run.
    public static func sweep(in parent: URL) {
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: parent.path)) ?? []
        for name in entries where name.hasPrefix(folderPrefix) {
            try? FileManager.default.removeItem(at: parent.appendingPathComponent(name, isDirectory: true))
        }
    }

    static func isPlainName(_ name: String) -> Bool {
        !name.isEmpty && !name.contains("/") && name != "." && name != ".."
            && name.hasSuffix("." + fileExtension)
    }

    private static func canonical(_ url: URL) -> String {
        url.standardizedFileURL.resolvingSymlinksInPath().path
    }

    private static func excludeFromBackup(_ url: URL) throws {
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var target = url
        try target.setResourceValues(values)
    }
}
