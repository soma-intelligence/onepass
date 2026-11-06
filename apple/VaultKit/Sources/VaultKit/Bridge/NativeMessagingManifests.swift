#if os(macOS)
import Foundation

/// The native messaging manifests that let Chrome, Edge, Brave and Firefox launch
/// `OnePass.app/Contents/Helpers/onepass-relay` (spec 2026-11-02-browser-auto-pairing 5). The app
/// writes them itself, at start and whenever it comes forward, so that installing the app and the
/// extension is enough.
///
/// Only browsers that are installed and were launched at least once (their support folder exists)
/// get one: the app never creates a browser's profile folder. The sandboxed app may write only the
/// `NativeMessagingHosts` folders listed here (entitlement `home-relative-path`), never the rest of
/// a browser profile.
public enum NativeMessagingManifests {
    /// The host name the extension connects to (`connectNative`).
    public static let hostName = "me.somalabs.onepass"

    enum Family {
        case chromium
        case gecko
    }

    struct Target {
        /// Under `~/Library/Application Support`.
        let folder: String
        let bundleIDs: [String]
        let family: Family
    }

    /// Every folder here has its entitlement exception in the signed macOS entitlements.
    static let targets: [Target] = [
        Target(folder: "Google/Chrome", bundleIDs: ["com.google.Chrome"], family: .chromium),
        Target(folder: "Google/Chrome Beta", bundleIDs: ["com.google.Chrome.beta"], family: .chromium),
        Target(folder: "Google/Chrome Dev", bundleIDs: ["com.google.Chrome.dev"], family: .chromium),
        Target(folder: "Google/Chrome Canary", bundleIDs: ["com.google.Chrome.canary"], family: .chromium),
        Target(folder: "Chromium", bundleIDs: ["org.chromium.Chromium"], family: .chromium),
        Target(folder: "Microsoft Edge", bundleIDs: ["com.microsoft.edgemac"], family: .chromium),
        Target(folder: "Microsoft Edge Beta", bundleIDs: ["com.microsoft.edgemac.Beta"], family: .chromium),
        Target(folder: "Microsoft Edge Dev", bundleIDs: ["com.microsoft.edgemac.Dev"], family: .chromium),
        Target(folder: "Microsoft Edge Canary", bundleIDs: ["com.microsoft.edgemac.Canary"], family: .chromium),
        Target(folder: "BraveSoftware/Brave-Browser", bundleIDs: ["com.brave.Browser"], family: .chromium),
        Target(
            folder: "BraveSoftware/Brave-Browser-Beta", bundleIDs: ["com.brave.Browser.beta"], family: .chromium),
        Target(
            folder: "BraveSoftware/Brave-Browser-Nightly", bundleIDs: ["com.brave.Browser.nightly"],
            family: .chromium),
        Target(folder: "Vivaldi", bundleIDs: ["com.vivaldi.Vivaldi"], family: .chromium),
        Target(
            folder: "Mozilla",
            bundleIDs: ["org.mozilla.firefox", "org.mozilla.firefoxdeveloperedition", "org.mozilla.nightly"],
            family: .gecko),
    ]

    /// A Chrome extension id: 32 letters `a` to `p`.
    static func isChromiumID(_ id: String) -> Bool {
        id.utf8.count == 32 && id.utf8.allSatisfy { (0x61...0x70).contains($0) }
    }

    /// A Firefox add-on id: `name@domain` or a braced GUID, printable ASCII without quotes.
    static func isGeckoID(_ id: String) -> Bool {
        guard !isChromiumID(id), (1...128).contains(id.utf8.count) else { return false }
        let ok = id.utf8.allSatisfy { $0 > 0x20 && $0 < 0x7F && $0 != 0x22 && $0 != 0x5C }
        return ok && (id.contains("@") || (id.hasPrefix("{") && id.hasSuffix("}")))
    }

    /// The manifest for `family`, or nil when no served id belongs to it.
    static func manifest(_ family: Family, relay: URL, extensionIDs: [String]) -> Data? {
        var object: [String: Any] = [
            "name": hostName, "description": "OnePass", "path": relay.path, "type": "stdio",
        ]
        switch family {
        case .chromium:
            let ids = extensionIDs.filter(isChromiumID)
            guard !ids.isEmpty else { return nil }
            object["allowed_origins"] = ids.map { "chrome-extension://\($0)/" }
        case .gecko:
            let ids = extensionIDs.filter(isGeckoID)
            guard !ids.isEmpty else { return nil }
            object["allowed_extensions"] = ids
        }
        return try? JSONSerialization.data(
            withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }

    /// Write the manifest of every installed browser that needs one and differs from what is on
    /// disk. Returns the files written. Nothing without an executable relay (a build not signed
    /// by a team has none).
    @discardableResult
    public static func install(
        home: URL, relay: URL, extensionIDs: [String], isInstalled: (String) -> Bool,
        fileManager: FileManager = .default
    ) -> [URL] {
        guard fileManager.isExecutableFile(atPath: relay.path) else { return [] }
        let support = home.appendingPathComponent("Library/Application Support")
        var written: [URL] = []
        for target in targets where target.bundleIDs.contains(where: isInstalled) {
            guard let data = manifest(target.family, relay: relay, extensionIDs: extensionIDs) else { continue }
            let hosts = support.appendingPathComponent(target.folder).appendingPathComponent("NativeMessagingHosts")
            // Created only inside an existing browser folder: never a profile of our own making.
            if !fileManager.fileExists(atPath: hosts.path) {
                guard (try? fileManager.createDirectory(at: hosts, withIntermediateDirectories: false)) != nil
                else { continue }
            }
            let file = hosts.appendingPathComponent("\(hostName).json")
            if let current = try? Data(contentsOf: file), current == data { continue }
            if (try? data.write(to: file, options: .atomic)) != nil { written.append(file) }
        }
        return written
    }

    /// The user's real home from the password database: in the sandbox, `NSHomeDirectory()` is the
    /// app's container.
    public static func userHome() -> URL? {
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { return nil }
        let path = String(cString: dir)
        return path.hasPrefix("/") ? URL(fileURLWithPath: path, isDirectory: true) : nil
    }
}
#endif
