import Foundation

/// Where the Safari extension finds its bridge host.
///
/// The product path of the spec (milestone 4, R-02 and R-17) is an XPC relay
/// to the Mac app, which embeds `onepass-bridge`. Until the app serves the
/// bridge, Debug builds of the extension carry the development native host
/// (`core/onepass-native-host`, the binary Chrome and Firefox launch) in
/// `Contents/MacOS` and start one per connection, exactly as a browser does
/// for each `connectNative` port. Release builds carry no host: every `open`
/// answers `unavailable`.
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

    /// The launcher for the host embedded in `bundle`, or nil when this build
    /// has none.
    public static func launcher(in bundle: Bundle = .main) -> ProcessHostLauncher? {
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
