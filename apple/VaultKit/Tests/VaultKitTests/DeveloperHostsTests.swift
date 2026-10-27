import Foundation
import Testing

@testable import VaultKit

/// The Mac app's SSH agent through `DeveloperHosts`: started by the settings, stopped on lock, and its
/// questions answered through `prompts`.
@MainActor
@Suite("Developer hosts", .timeLimit(.minutes(3)))
struct DeveloperHostsTests {
    /// A short folder: socket paths must fit `sun_path` (104 bytes).
    private func shortDirectory() throws -> URL {
        let url = URL(fileURLWithPath: "/tmp/op-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func agentStartsWithTheSettingAndStopsOnLock() async throws {
        let harness = try SessionHarness()
        defer { harness.cleanUp() }
        let session = harness.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let dir = try shortDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let suite = "onepass.tests.dev.\(UUID().uuidString)"
        defer { UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite) }
        let hosts = DeveloperHosts(
            paths: DeveloperPaths(dataDirectory: dir, relay: dir.appending(path: "onepass-mcp")),
            defaults: UserDefaults(suiteName: suite)!, presence: harness.presence)

        try await session.generateSSHKey(type: .ed25519, FfiNewSshKey(
            vaultId: session.allVaults[0].id, title: "Github", hosts: ["github.com"],
            useInAgent: true, confirmEachUse: false, comment: nil))
        #expect(try await session.agentKeys().map(\.title) == ["Github"])

        await hosts.update({ $0.sshEnabled = true }, session: session)
        #expect(hosts.sshRunning)
        #expect(hosts.sshError == nil)
        #expect(FileManager.default.fileExists(atPath: hosts.paths.sshSocket.path))
        #expect(hosts.paths.identityAgentLine.contains(hosts.paths.sshSocket.path))

        // The setting persists for the next launch.
        #expect(DeveloperSettings.load(from: UserDefaults(suiteName: suite)!).sshEnabled)

        hosts.sessionLocked()
        #expect(!hosts.sshRunning)
    }

    @Test func aQuestionWaitsForTheUsersAnswer() async throws {
        let hosts = DeveloperHosts(
            paths: DeveloperPaths(dataDirectory: try shortDirectory(), relay: URL(fileURLWithPath: "/x")),
            defaults: UserDefaults(suiteName: "onepass.tests.dev.\(UUID().uuidString)")!,
            presence: FakePresence())
        let bridge = PromptBridge(owner: hosts, presence: FakePresence())
        let request = FfiApprovalRequest(
            surface: "ssh", client: "/usr/bin/ssh", clientVerified: false, action: "ssh_sign",
            details: [], targets: [FfiTarget(vault: "Personnel", item: "Github", field: nil)],
            rememberAllowed: true)
        let answer = Task.detached { bridge.approve(request: request) }
        while hosts.prompts.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let prompt = try #require(hosts.prompts.first)
        hosts.answer(prompt.id, with: .allowForMinutes(minutes: 15))
        #expect(await answer.value == .allowForMinutes(minutes: 15))
        #expect(hosts.prompts.isEmpty)
        // Pairing needs the answer and the presence check.
        #expect(bridge.verifyPresence(reason: "test"))
    }

    @Test func pathsAndSnippets() {
        let paths = DeveloperPaths(
            dataDirectory: URL(fileURLWithPath: "/Users/camille/Library/Containers/me.somalabs.onepass/Data/.onepass"),
            relay: URL(fileURLWithPath: "/Applications/OnePass.app/Contents/Helpers/onepass-mcp"))
        #expect(paths.sshSocket.path.utf8.count < 104)
        #expect(paths.exportLine == "export SSH_AUTH_SOCK=\"\(paths.sshSocket.path)\"")
        #expect(paths.mcpClientConfig.contains("\"--socket\", \"\(paths.mcpSocket.path)\""))
        #expect(paths.mcpClientConfig.contains(paths.relay.path))
    }
}
