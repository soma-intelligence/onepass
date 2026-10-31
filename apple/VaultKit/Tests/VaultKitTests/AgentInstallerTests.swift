#if os(macOS)
import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// Stands for the bundled relay: records each call, answers from a script. Never runs anything, so
/// no test writes a real client configuration.
final class FakeHelperRunner: HelperRunner {
    private struct State {
        var calls: [[String]] = []
        var results: [HelperResult]
    }
    private let state: Mutex<State>

    init(_ results: [HelperResult]) {
        state = Mutex(State(results: results))
    }

    var calls: [[String]] { state.withLock { $0.calls } }

    func run(_ executable: URL, arguments: [String]) async -> HelperResult {
        state.withLock { s in
            s.calls.append([executable.path] + arguments)
            return s.results.isEmpty ? HelperResult(status: 0, output: "") : s.results.removeFirst()
        }
    }
}

/// "Installer dans un agent" (agent-ready spec 8): the bundled relay's `install`, previewed with
/// `--dry-run` first, against the app's own socket.
@MainActor
@Suite("Agent installer")
struct AgentInstallerTests {
    let paths = DeveloperPaths(
        dataDirectory: URL(fileURLWithPath: "/Users/camille/Library/Containers/me.somalabs.onepass/Data/.onepass"),
        relay: URL(fileURLWithPath: "/Applications/OnePass.app/Contents/Helpers/onepass-mcp"))

    @Test func previewThenInstallWithTheAppSocket() async {
        let runner = FakeHelperRunner([
            HelperResult(status: 0, output: "--- config.toml\n+++ config.toml\n+[mcp_servers.onepass]\n"),
            HelperResult(status: 0, output: "OnePass added to Codex. Quit Codex first, then open it again."),
        ])
        let installer = AgentInstaller(paths: paths, home: URL(fileURLWithPath: "/Users/camille"), runner: runner)
        installer.client = .codex
        #expect(!installer.canInstall)

        await installer.previewInstall()
        let base = [
            paths.relay.path, "install", "--client", "codex", "--home", "/Users/camille",
            "--socket", paths.mcpSocket.path,
        ]
        #expect(runner.calls == [base + ["--dry-run"]])
        #expect(installer.preview?.succeeded == true)
        #expect(installer.preview?.output.contains("+[mcp_servers.onepass]") == true)
        #expect(installer.canInstall)

        await installer.install()
        #expect(runner.calls.last == base)
        #expect(installer.result?.succeeded == true)
        #expect(installer.result?.output.contains("Quit Codex first") == true)
        #expect(!installer.canInstall)

        // Another client starts over.
        installer.client = .cursor
        #expect(installer.preview == nil)
        #expect(installer.result == nil)
    }

    @Test func failureKeepsTheHelpersMessageAndOffersTheTerminal() async {
        let runner = FakeHelperRunner([HelperResult(status: 1, output: "error: onepass already points elsewhere, pass --force")])
        let installer = AgentInstaller(paths: paths, home: URL(fileURLWithPath: "/Users/camille"), runner: runner)
        installer.client = .claudeCode
        await installer.previewInstall()
        #expect(installer.preview?.succeeded == false)
        #expect(installer.preview?.output.contains("--force") == true)
        #expect(!installer.canInstall)
        // The same command for a terminal (its own HOME): no --home.
        #expect(installer.terminalCommand
            == "'\(paths.relay.path)' install --client claude-code --socket '\(paths.mcpSocket.path)'")
    }

    /// The sandbox stops the helper reading the client's file: a plain sentence, not the raw error.
    @Test func sandboxRefusalIsRecognized() async {
        let runner = FakeHelperRunner([HelperResult(
            status: 1, output: "onepass-mcp: cannot read /Users/camille/.claude.json: Operation not permitted (os error 1)")])
        let installer = AgentInstaller(paths: paths, home: URL(fileURLWithPath: "/Users/camille"), runner: runner)
        await installer.previewInstall()
        #expect(installer.preview?.blockedBySandbox == true)
        #expect(!installer.canInstall)
        #expect(HelperResult(status: 1, output: "cannot write /x: Permission denied (os error 13)").blockedBySandbox)
        #expect(!HelperResult(status: 1, output: "already has an onepass entry, pass --force").blockedBySandbox)
        #expect(!HelperResult(status: 0, output: "Operation not permitted").blockedBySandbox)
    }

    @Test func clientsMatchTheRelay() {
        #expect(AgentClient.allCases.map(\.rawValue) == ["claude-code", "claude-desktop", "codex", "cursor"])
    }
}
#endif
