import Foundation
import OnePassCore

/// Open and sign in (spec `docs/superpowers/specs/2026-11-04-open-and-sign-in-design.md`): a tap on a
/// login's website records a single-use pending sign-in (the item id and the site, 60 s, never a
/// secret, 0600) in the App Group container's database folder, then the app opens the page in the
/// browser. The bridge host there (the Mac app's `BrowserBridge`, the iOS Safari extension's
/// `SafariExtensionVault`, both `setPendingDir` on that folder) gives the item to the OnePass
/// extension once, on an https page of that site; the extension signs in with its sign-in chain,
/// fetching each value through the usual `fill_login`.
public enum OpenAndSignIn {
    /// Life of a pending sign-in, in seconds (the Rust `PENDING_TTL`).
    public static let ttl: TimeInterval = 60

    /// What a tap on a website does.
    public enum Outcome: Equatable, Sendable {
        /// Recorded: the extension signs in when the page loads.
        case signIn(URL)
        /// Opened without sign in (an `http` site, or the entry could not be written).
        case openOnly(URL)
    }

    /// The page to open for a stored website: as written when it has a scheme (`https` or
    /// `http`), else read as `https`. Nil for anything else (no `javascript:`, no `file:`).
    public static func pageURL(_ raw: String) -> URL? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        let candidate = text.contains("://") ? text : "https://" + text
        guard let url = URL(string: candidate), let scheme = url.scheme?.lowercased(),
            scheme == "https" || scheme == "http", let host = url.host(), !host.isEmpty
        else { return nil }
        return url
    }

    /// The folder the bridge reads pending sign-ins from (the store's folder in the App Group).
    public static func pendingFolder(_ container: SharedContainer = .resolve()) -> URL {
        container.databaseFolder
    }

    /// Record the pending sign-in of `itemID` (hex) for `rawURL` in `folder`, and say what to open.
    /// Nil when `rawURL` is not a web page. `http` pages and write failures open without sign in.
    public static func prepare(
        itemID: String, rawURL: String, folder: URL = pendingFolder(),
        record: (String, String, String) throws -> UInt64 = recordPendingSignIn
    ) -> Outcome? {
        guard let url = pageURL(rawURL) else { return nil }
        guard url.scheme?.lowercased() == "https" else { return .openOnly(url) }
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        do {
            _ = try record(folder.path, itemID, url.absoluteString)
            return .signIn(url)
        } catch {
            return .openOnly(url)
        }
    }

    /// Drop a pending sign-in (the user chose "Ouvrir" only, or the open failed).
    public static func cancel(folder: URL = pendingFolder()) {
        clearPendingSignIn(dir: folder.path)
    }

    /// The bridge's id of the Safari extension (`SAFARI_EXTENSION_ID` in Rust).
    static let safariExtensionID = "safari"

    /// iPhone and iPad: true once the OnePass Safari extension has paired with this device (it
    /// pairs by itself the first time it runs in Safari, ruling I2). iOS has no API that tells
    /// whether an extension is turned on, so a missing pairing is the sign to show the hint.
    public static func safariExtensionPaired(keychain: (any KeychainStore)? = nil) -> Bool {
        let keychain =
            keychain
            ?? SystemKeychain(service: BridgePairingStore.service, accessGroup: VaultEnvironment.sharedAccessGroup())
        return BridgePairingStore(keychain: keychain).load().contains { $0.extensionId == safariExtensionID }
    }
}
