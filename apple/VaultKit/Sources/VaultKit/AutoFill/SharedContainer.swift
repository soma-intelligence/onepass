import Foundation

/// Where the store and the settings live. The app and the AutoFill extension both open the App Group
/// container; a build without that entitlement (unsigned Mac build) keeps the milestone 2 locations.
public struct SharedContainer: Sendable {
    /// The App Group container, or the app's `Application Support` folder when `isShared` is false.
    public let root: URL
    /// True only when the group container exists and was proven writable.
    public let isShared: Bool
    /// Name of the shared `UserDefaults` suite (the group identifier); nil means `UserDefaults.standard`.
    public let defaultsSuite: String?

    /// Info.plist key holding the App Group identifier.
    public static let groupInfoKey = "OnePassAppGroup"

    public init(root: URL, isShared: Bool, defaultsSuite: String?) {
        self.root = root
        self.isShared = isShared
        self.defaultsSuite = defaultsSuite
    }

    /// `<root>/Library/Application Support/OnePass/vault.sqlite` in the group container,
    /// `<Application Support>/OnePass/vault.sqlite` otherwise.
    public var databaseURL: URL {
        databaseFolder.appendingPathComponent("vault.sqlite")
    }

    /// The folder that holds the store and its `-wal` and `-shm` files.
    public var databaseFolder: URL {
        let base =
            isShared
            ? root.appendingPathComponent("Library/Application Support", isDirectory: true) : root
        return base.appendingPathComponent("OnePass", isDirectory: true)
    }

    /// The settings store: the shared suite, or `UserDefaults.standard` without a shared container.
    public var defaults: UserDefaults {
        defaultsSuite.flatMap { UserDefaults(suiteName: $0) } ?? .standard
    }

    /// Resolves the container for the running process. The group identifier comes from the
    /// `OnePassAppGroup` Info.plist key. On macOS `containerURL(forSecurityApplicationGroupIdentifier:)`
    /// can return a URL without the entitlement, so the container only counts as shared once the store
    /// folder can be created and written; otherwise the milestone 2 locations are used.
    public static func resolve(
        bundle: Bundle = .main, fileManager: FileManager = .default
    ) -> SharedContainer {
        if let group = groupIdentifier(bundle: bundle),
            let url = fileManager.containerURL(forSecurityApplicationGroupIdentifier: group)
        {
            let candidate = SharedContainer(root: url, isShared: true, defaultsSuite: group)
            if candidate.prepareFolder(fileManager: fileManager, probe: true) { return candidate }
        }
        let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let local = SharedContainer(root: support, isShared: false, defaultsSuite: nil)
        _ = local.prepareFolder(fileManager: fileManager, probe: false)
        return local
    }

    static func groupIdentifier(bundle: Bundle) -> String? {
        guard let value = bundle.object(forInfoDictionaryKey: groupInfoKey) as? String else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty || trimmed.contains("$(") ? nil : trimmed
    }

    /// Creates the store folder (protected until first unlock on iOS). With `probe`, also writes and
    /// removes a tiny file to prove the folder is usable. Returns false on any failure.
    @discardableResult
    func prepareFolder(fileManager: FileManager, probe: Bool) -> Bool {
        let folder = databaseFolder
        var attributes: [FileAttributeKey: Any] = [:]
        #if os(iOS) || os(visionOS)
        attributes[.protectionKey] = FileProtectionType.completeUntilFirstUserAuthentication
        #endif
        do {
            try fileManager.createDirectory(
                at: folder, withIntermediateDirectories: true, attributes: attributes)
            #if os(iOS) || os(visionOS)
            try? fileManager.setAttributes(attributes, ofItemAtPath: folder.path)
            #endif
            if probe {
                let file = folder.appendingPathComponent(".probe-\(UUID().uuidString)")
                try Data([0]).write(to: file)
                try fileManager.removeItem(at: file)
            }
            return true
        } catch {
            return false
        }
    }
}
