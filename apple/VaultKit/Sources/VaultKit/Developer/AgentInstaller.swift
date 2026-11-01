#if os(macOS)
import Foundation
import Observation

/// The MCP clients the bundled relay installs into (`onepass-mcp install --client`, spec 8).
public enum AgentClient: String, CaseIterable, Identifiable, Sendable {
    case claudeCode = "claude-code"
    case claudeDesktop = "claude-desktop"
    case codex
    case cursor

    public var id: String { rawValue }

    /// Product names, the same in every language.
    public var title: String {
        switch self {
        case .claudeCode: "Claude Code"
        case .claudeDesktop: "Claude Desktop"
        case .codex: "Codex"
        case .cursor: "Cursor"
        }
    }
}

/// What a helper run printed (standard output and error, in order) and its exit status.
public struct HelperResult: Equatable, Sendable {
    public var status: Int32
    public var output: String

    public init(status: Int32, output: String) {
        self.status = status
        self.output = output
    }

    public var succeeded: Bool { status == 0 }

    /// The app's sandbox stopped the helper reading or writing the client's file (the helper
    /// inherits it): the terminal is the way then.
    public var blockedBySandbox: Bool {
        !succeeded && (output.contains("Operation not permitted") || output.contains("Permission denied"))
    }
}

/// Runs a helper of the app's bundle. The tests and the demo pass a fake: no test ever writes a real
/// client configuration.
public protocol HelperRunner: Sendable {
    func run(_ executable: URL, arguments: [String]) async -> HelperResult
}

/// `Process`, off the main actor; output capped so a runaway helper cannot fill the memory.
public struct ProcessHelperRunner: HelperRunner {
    static let outputLimit = 256 * 1024

    public init() {}

    public func run(_ executable: URL, arguments: [String]) async -> HelperResult {
        await Task.detached(priority: .userInitiated) { () -> HelperResult in
            let process = Process()
            process.executableURL = executable
            process.arguments = arguments
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            process.standardInput = FileHandle.nullDevice
            do {
                try process.run()
            } catch {
                return HelperResult(status: -1, output: ErrorText.describe(error)?.text ?? VaultError(error).localizedMessage)
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let text = String(decoding: data.prefix(Self.outputLimit), as: UTF8.self)
            return HelperResult(status: process.terminationStatus, output: text.trimmingCharacters(in: .whitespacesAndNewlines))
        }.value
    }
}

/// "Installer dans un agent" (agent-ready spec 8): runs the bundled relay's `install` for the chosen
/// client, with the app's real socket, a `--dry-run` preview (the diff) first, then the real install.
/// The relay prints what it did and asks to quit the client first; both are shown as they are.
@MainActor
@Observable
public final class AgentInstaller {
    /// Changing it starts over (no preview, no result).
    public var client: AgentClient = .claudeCode {
        didSet {
            guard client != oldValue else { return }
            preview = nil
            result = nil
        }
    }
    /// The `--dry-run` output for `client`.
    public private(set) var preview: HelperResult?
    /// The install's output for `client`.
    public private(set) var result: HelperResult?
    public private(set) var running = false

    @ObservationIgnored private let paths: DeveloperPaths
    @ObservationIgnored private let home: URL
    @ObservationIgnored private let runner: any HelperRunner

    /// `home`: the user's real home (the sandbox's `HOME` is the container, so it is passed with
    /// `--home`). `runner`: the tests and the demo pass a fake.
    public init(paths: DeveloperPaths, home: URL = AgentInstaller.userHome, runner: any HelperRunner = ProcessHelperRunner()) {
        self.paths = paths
        self.home = home
        self.runner = runner
    }

    /// The account's home folder, not the sandbox container `NSHomeDirectory()` returns.
    public nonisolated static var userHome: URL {
        if let entry = getpwuid(getuid()), let dir = entry.pointee.pw_dir {
            return URL(fileURLWithPath: String(cString: dir), isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    /// The preview succeeded and nothing was installed since.
    public var canInstall: Bool { preview?.succeeded == true && result == nil && !running }

    func arguments(dryRun: Bool) -> [String] {
        ["install", "--client", client.rawValue, "--home", home.path, "--socket", paths.mcpSocket.path]
            + (dryRun ? ["--dry-run"] : [])
    }

    /// The same install for a terminal (its `HOME` is the real one).
    public var terminalCommand: String {
        "\(Self.quoted(paths.relay.path)) install --client \(client.rawValue) --socket \(Self.quoted(paths.mcpSocket.path))"
    }

    /// `--dry-run`: what would change, nothing written.
    public func previewInstall() async {
        guard !running else { return }
        running = true
        defer { running = false }
        let asked = client
        result = nil
        let out = await runner.run(paths.relay, arguments: arguments(dryRun: true))
        guard client == asked else { return }
        preview = out
    }

    /// The real install, after a preview.
    public func install() async {
        guard canInstall else { return }
        running = true
        defer { running = false }
        let asked = client
        let out = await runner.run(paths.relay, arguments: arguments(dryRun: false))
        guard client == asked else { return }
        result = out
    }

    /// POSIX single quotes.
    static func quoted(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
#endif
