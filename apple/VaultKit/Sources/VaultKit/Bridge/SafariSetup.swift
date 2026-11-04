import Foundation

/// Turning the OnePass Safari extension on (MS-02, IOSSAF-13): what the apps know about it and when
/// the one-time setup card shows. Safari itself asks for the website access; the apps only point there.
///
/// - macOS reads the state from `SFSafariExtensionManager` (the app does, with this identifier).
/// - iOS has no such API: the one signal is a bridge pairing in the shared keychain, which only the
///   Safari extension's own process writes, after it ran on a page (`SafariExtensionVault`). No
///   pairing means "not seen yet", never "off".
public enum SafariSetup {
    /// The Safari extension's bundle identifier: the containing app's own plus `.safari`
    /// (`project.yml`, both platforms). Nil without an app bundle id.
    public static func extensionIdentifier(appBundleID: String? = Bundle.main.bundleIdentifier) -> String? {
        guard let id = appBundleID, !id.isEmpty else { return nil }
        return id + ".safari"
    }

    /// iOS: the Safari extension paired with this device's vault at least once. Reads the presence
    /// of the pairing list only (never a key is used or returned). False when the keychain cannot
    /// answer (device locked): the card may show once too often, never hides wrongly for good.
    public static func extensionHasPaired(keychain: (any KeychainStore)? = nil) -> Bool {
        let store =
            keychain
            ?? SystemKeychain(service: BridgePairingStore.service, accessGroup: VaultEnvironment.sharedAccessGroup())
        guard let data = try? store.read(BridgePairingStore.key),
            let list = try? JSONSerialization.jsonObject(with: data) as? [Any]
        else { return false }
        return !list.isEmpty
    }

    /// The setup card shows while the extension is known off (Mac) or not seen yet (iPhone, iPad),
    /// until the user closes it. `extensionOn` nil: the state is being read, nothing shows.
    public static func showsCard(dismissed: Bool, extensionOn: Bool?) -> Bool {
        !dismissed && extensionOn == false
    }
}
