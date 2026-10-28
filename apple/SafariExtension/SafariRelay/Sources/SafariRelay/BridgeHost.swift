import Foundation

/// Where the Safari extension finds its bridge host.
///
/// Signed builds reach the Mac app over its socket in the App Group
/// container (`AppSocket`, spec 2026-10-27-release-bridge-design): the app
/// serves the bridge from the vault the user unlocked. Debug builds also
/// carry the development native host (`core/onepass-native-host`) in
/// `Contents/MacOS` and prefer it, starting one per connection as a browser
/// does for each `connectNative` port. A build with neither (ad hoc Release)
/// answers `unavailable` to every `open`.
public enum BridgeHost {
    public static let executableName = "onepass-native-host"

    /// The host's arguments, in the Firefox form (`<manifest> <extension id>`)
    /// that `onepass-native-host` already parses: the extension id is checked
    /// against `allowed_extensions` of the host's configuration.
    public static func arguments(config: URL, bundlePath: String, extensionId: String) -> [String] {
        ["--config", config.path, bundlePath, extensionId]
    }

    /// The configuration the host reads: `~/.onepass-dev/native-host.json`,
    /// where `~` is the extension's sandbox container
    /// (`~/Library/Containers/<extension bundle id>/Data`) once it is signed
    /// with the App Sandbox, and the user's home otherwise.
    public static func defaultConfig(home: String = NSHomeDirectory()) -> URL {
        URL(fileURLWithPath: home).appendingPathComponent(".onepass-dev/native-host.json")
    }

    /// The development host when this build embeds one, else the app's
    /// socket when this build is signed by a team, else nil.
    public static func launcher(in bundle: Bundle = .main) -> (any HostLauncher)? {
        if let dev = devLauncher(in: bundle) { return dev }
        return AppSocket.launcher()
    }

    /// The launcher for the development host embedded in `bundle`, or nil
    /// when this build has none.
    public static func devLauncher(in bundle: Bundle = .main) -> ProcessHostLauncher? {
        guard let dir = bundle.executableURL?.deletingLastPathComponent(),
            let id = bundle.bundleIdentifier
        else { return nil }
        let exe = dir.appendingPathComponent(executableName)
        guard FileManager.default.isExecutableFile(atPath: exe.path) else { return nil }
        return ProcessHostLauncher(
            executable: exe,
            arguments: arguments(config: defaultConfig(), bundlePath: bundle.bundlePath, extensionId: id))
    }
}
