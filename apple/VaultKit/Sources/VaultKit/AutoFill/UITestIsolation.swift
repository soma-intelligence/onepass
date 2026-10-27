import Foundation

#if DEBUG
/// UI test isolation shared by the app and the AutoFill extension, Debug builds only.
///
/// An app launched with `-OnePassTestIsolation YES` uses its own store, settings suite and keychain
/// service, never the user's. With an App Group container the isolated store lives in it
/// (`<group>/OnePassUITest/vault.sqlite`) and the isolated launch leaves a marker beside it: the
/// AutoFill extension, which receives no launch argument, then opens that store with the same
/// keychain service. The next ordinary launch of the app removes the marker, and the extension goes
/// back to the user's store. Without an App Group the store stays in the app's temporary folder and
/// the extension never sees it.
public enum UITestIsolation {
    public static let keychainService = "me.somalabs.onepass.uitest"
    public static let suiteName = "me.somalabs.onepass.uitest"
    /// The extension's settings suite: the app's suite is not readable from the extension. Emptied
    /// at every request, so a stale account id never lingers (the account is adopted from the store
    /// and the keychain, `VaultSession`).
    static let extensionSuiteName = "me.somalabs.onepass.uitest.autofill"
    static let folderName = "OnePassUITest"
    static let markerName = "isolation-active"

    /// `<group>/OnePassUITest` with an App Group container, else `<tmp>/OnePassUITest`.
    public static func folder(container: SharedContainer) -> URL {
        container.isShared
            ? container.root.appendingPathComponent(folderName, isDirectory: true)
            : FileManager.default.temporaryDirectory.appendingPathComponent(folderName, isDirectory: true)
    }

    /// The isolated store; its folder is created.
    public static func databaseURL(container: SharedContainer) -> URL {
        let folder = folder(container: container)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder.appendingPathComponent("vault.sqlite")
    }

    static func markerURL(container: SharedContainer) -> URL {
        folder(container: container).appendingPathComponent(markerName)
    }

    /// An isolated launch of the app: the extension follows it (App Group only).
    public static func markActive(container: SharedContainer) {
        guard container.isShared else { return }
        try? FileManager.default.createDirectory(at: folder(container: container), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: markerURL(container: container).path, contents: Data())
    }

    /// An ordinary launch of the app: the extension uses the user's store again.
    public static func clearMarker(container: SharedContainer) {
        guard container.isShared else { return }
        try? FileManager.default.removeItem(at: markerURL(container: container))
    }

    public static func isMarked(container: SharedContainer) -> Bool {
        container.isShared && FileManager.default.fileExists(atPath: markerURL(container: container).path)
    }

    /// The extension's environment while the last launch of the app was isolated: the isolated store
    /// (never created here) and keychain service, an emptied settings suite, no system identity store.
    /// Nil otherwise.
    public static func extensionEnvironment(container: SharedContainer = .resolve()) -> VaultEnvironment? {
        guard isMarked(container: container) else { return nil }
        UserDefaults(suiteName: extensionSuiteName)?.removePersistentDomain(forName: extensionSuiteName)
        guard let defaults = UserDefaults(suiteName: extensionSuiteName) else { return nil }
        var environment = VaultEnvironment.live(
            sync: NoSync(), container: container,
            databaseURL: folder(container: container).appendingPathComponent("vault.sqlite"),
            settings: VaultSettings(defaults: defaults), keychainService: keychainService)
        environment.identityStore = NoIdentityStore()
        return environment
    }
}
#endif
