import Foundation

/// The Emergency Kit PDF as a temporary file, only for the share sheet (printing works from
/// memory). Each kit gets its own `kit-<UUID>` folder; folder and file are excluded from
/// backups, and the file has complete protection where the platform supports it. The caller
/// removes it when the screen goes away; `sweep` removes leftovers at launch.
public enum EmergencyKitFile {
    public static let fileName = "Emergency Kit OnePass.pdf"
    static let folderPrefix = "kit-"

    /// Writes `data` to `<parent>/kit-<UUID>/Emergency Kit OnePass.pdf` and returns the file URL.
    /// On failure nothing is left behind.
    public static func write(_ data: Data, under parent: URL) throws -> URL {
        let folder = parent.appendingPathComponent(
            folderPrefix + UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try excludeFromBackup(folder)
            let url = folder.appendingPathComponent(fileName)
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

    /// Removes the kit folder holding `file`, only when `file` is a kit written by `write` under
    /// `parent`: named `fileName`, in a `kit-*` folder directly inside `parent`.
    public static func remove(_ file: URL, under parent: URL) {
        let folder = file.deletingLastPathComponent()
        guard file.lastPathComponent == fileName,
              folder.lastPathComponent.hasPrefix(folderPrefix),
              canonical(folder.deletingLastPathComponent()) == canonical(parent)
        else { return }
        try? FileManager.default.removeItem(at: folder)
    }

    private static func canonical(_ url: URL) -> String {
        url.standardizedFileURL.resolvingSymlinksInPath().path
    }

    /// Removes every kit folder left in `parent` by a previous run.
    public static func sweep(in parent: URL) {
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: parent.path)) ?? []
        for name in entries where name.hasPrefix(folderPrefix) {
            try? FileManager.default.removeItem(
                at: parent.appendingPathComponent(name, isDirectory: true))
        }
    }

    private static func excludeFromBackup(_ url: URL) throws {
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var target = url
        try target.setResourceValues(values)
    }
}

/// What the share sheet may offer for the kit. Raw `UIActivity.ActivityType` values, so the
/// list is testable without UIKit: Photos, pasteboard, contacts, reading list, messaging, mail,
/// social networks and collaboration links all copy the Secret Key off the device. "Enregistrer
/// dans Fichiers", AirDrop and printing stay available.
public enum EmergencyKitSharing {
    public static let excludedActivityTypes: [String] = [
        "com.apple.UIKit.activity.SaveToCameraRoll",
        "com.apple.UIKit.activity.CopyToPasteboard",
        "com.apple.UIKit.activity.AssignToContact",
        "com.apple.UIKit.activity.AddToReadingList",
        "com.apple.UIKit.activity.Message",
        "com.apple.UIKit.activity.Mail",
        "com.apple.UIKit.activity.PostToFacebook",
        "com.apple.UIKit.activity.PostToTwitter",
        "com.apple.UIKit.activity.PostToWeibo",
        "com.apple.UIKit.activity.TencentWeibo",
        "com.apple.UIKit.activity.PostToFlickr",
        "com.apple.UIKit.activity.PostToVimeo",
        "com.apple.UIKit.activity.CollaborationCopyLink",
        "com.apple.UIKit.activity.CollaborationInviteWithLink",
    ]
}

/// Where a saved kit would end up.
public enum KitDestination {
    /// Whether `url` lies in a synced cloud folder: its path contains `/Library/Mobile Documents/`
    /// (iCloud Drive) or `/Library/CloudStorage/` (File Provider clouds: Dropbox, Google Drive,
    /// OneDrive...), also after resolving symbolic links, or it or its nearest existing ancestor
    /// is a ubiquitous item (Desktop and Documents synced with iCloud). Non file URLs are not
    /// cloud synced.
    public static func isCloudSynced(_ url: URL) -> Bool {
        guard url.isFileURL else { return false }
        let markers = ["/Library/Mobile Documents/", "/Library/CloudStorage/"]
        let standardized = url.standardizedFileURL
        for path in [standardized.path, standardized.resolvingSymlinksInPath().path] {
            if markers.contains(where: path.contains) { return true }
        }
        var current = standardized
        while true {
            if FileManager.default.fileExists(atPath: current.path) {
                let values = try? current.resourceValues(forKeys: [.isUbiquitousItemKey])
                return values?.isUbiquitousItem == true
            }
            let parent = current.deletingLastPathComponent()
            if parent.path == current.path { return false }
            current = parent
        }
    }
}
