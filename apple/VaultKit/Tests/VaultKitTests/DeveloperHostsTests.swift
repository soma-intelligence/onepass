import Foundation
import Testing

@testable import VaultKit

/// Runs `work` on its own thread, like the core's server threads: the bridge blocks its caller, and a
/// blocked thread of the shared pool would starve every other test of the run.
func onServerThread(_ work: @escaping @Sendable () -> FfiAnswer) -> Task<FfiAnswer, Never> {
    Task {
        await withCheckedContinuation { continuation in
            Thread { continuation.resume(returning: work()) }.start()
        }
    }
}

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
        let bridge = PromptBridge(owner: hosts, presence: FakePresence(), timeout: 600)
        let request = FfiApprovalRequest(
            surface: "ssh", client: "/usr/bin/ssh", clientVerified: false, action: "ssh_sign",
            details: [], targets: [FfiTarget(vault: "Personnel", item: "Github", field: nil)],
            rememberAllowed: true, strongRequired: false, confirmCode: "kq")
        let answer = onServerThread { bridge.approve(request: request) }
        while hosts.prompts.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let prompt = try #require(hosts.prompts.first)
        hosts.answer(prompt.id, with: .allowForMinutes(minutes: 15))
        #expect(await answer.value.decision == .allowForMinutes(minutes: 15))
        #expect(hosts.prompts.isEmpty)
        // Pairing needs the answer and the presence check.
        #expect(bridge.verifyPresence(reason: "test"))
    }

    // MARK: - Mac and iPhone race

    /// The bridge waits longer than the spec's 60 s here: a loaded machine can stall the main actor
    /// past it. `timeoutAfterSixtySecondsDenies` checks the real value.
    private func raceHosts(phones: [String], timeout: TimeInterval = 600)
        throws -> (DeveloperHosts, PromptBridge, InMemoryRemoteChannel)
    {
        let hosts = DeveloperHosts(
            paths: DeveloperPaths(dataDirectory: try shortDirectory(), relay: URL(fileURLWithPath: "/x")),
            defaults: UserDefaults(suiteName: "onepass.tests.dev.\(UUID().uuidString)")!,
            presence: FakePresence())
        let channel = InMemoryRemoteChannel()
        let approver = RemoteApprover(
            channel: channel, session: FakeRemoteSession(phones: phones), keys: testApproverKeys,
            timeout: .seconds(timeout), mailbox: RemoteMailbox(channel: channel, device: "mac-1"))
        let bridge = PromptBridge(owner: hosts, presence: FakePresence(), timeout: timeout)
        bridge.remote = approver
        return (hosts, bridge, channel)
    }

    @Test func macAnswerWinsAndPhoneRequestDeleted() async throws {
        let (hosts, bridge, channel) = try raceHosts(phones: ["phone-a"])
        let request = approvalRequest()
        let answer = onServerThread { bridge.approve(request: request) }
        try await waitUntil { channel.stored().contains { $0.to == "phone-a" } }
        while hosts.prompts.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let prompt = try #require(hosts.prompts.first)
        try await waitUntil { @MainActor in hosts.prompts.first?.phoneStatus == .sent(["iPhone phone-a"]) }
        hosts.answer(prompt.id, with: .allowOnce)

        let result = await answer.value
        #expect(result.decision == .allowOnce)
        #expect(result.approvedOn == "mac")
        // The phone's request is withdrawn.
        try await waitUntil { channel.stored().isEmpty }
        #expect(hosts.prompts.isEmpty)
    }

    @Test func phoneAnswerWinsAndPanelCloses() async throws {
        let (hosts, bridge, channel) = try raceHosts(phones: ["phone-a"])
        let request = approvalRequest(strong: true)
        let answer = onServerThread { bridge.approve(request: request) }
        try await waitUntil { channel.stored().contains { $0.to == "phone-a" } }
        while hosts.prompts.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let prompt = try #require(hosts.prompts.first)

        try await phoneAnswers(channel, phone: "phone-a", decision: "once")
        let result = await answer.value
        #expect(result.decision == .allowOnce)
        #expect(result.approvedOn == "phone:phone-a")
        // The panel closed by itself: its prompt is gone without any click.
        try await waitUntil { @MainActor in hosts.prompts.isEmpty }
        #expect(!hosts.prompts.contains { $0.id == prompt.id })
        try await waitUntil { channel.stored().isEmpty }
    }

    @Test func noPhoneFallsBackToPanelWithNotice() async throws {
        let (hosts, bridge, channel) = try raceHosts(phones: [])
        let request = approvalRequest()
        let answer = onServerThread { bridge.approve(request: request) }
        while hosts.prompts.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        try await waitUntil { @MainActor in hosts.prompts.first?.phoneStatus == .unavailable }
        let prompt = try #require(hosts.prompts.first)
        #expect(prompt.phoneNotice != nil)
        #expect(channel.stored().isEmpty)

        hosts.answer(prompt.id, with: .allowOnce)
        let result = await answer.value
        #expect(result.decision == .allowOnce)
        #expect(result.approvedOn == "mac")

        // CloudKit unreachable: the same notice.
        let (hosts2, bridge2, channel2) = try raceHosts(phones: ["phone-a"])
        channel2.reachable = false
        let answer2 = onServerThread { bridge2.approve(request: request) }
        while hosts2.prompts.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        try await waitUntil { @MainActor in hosts2.prompts.first?.phoneStatus == .unavailable }
        hosts2.answer(try #require(hosts2.prompts.first).id, with: .deny)
        #expect(await answer2.value == FfiAnswer(decision: .deny, approvedOn: "mac"))
    }

    @Test func timeoutAfterSixtySecondsDenies() async throws {
        // The request lifetime of the spec; the test waits a fraction of it.
        #expect(PromptBridge.timeout == 60)
        let (hosts, bridge, channel) = try raceHosts(phones: ["phone-a"], timeout: 0.5)
        let request = approvalRequest()
        let result = await onServerThread { bridge.approve(request: request) }.value
        #expect(result == FfiAnswer(decision: .deny, approvedOn: nil))
        try await waitUntil { @MainActor in hosts.prompts.isEmpty }
        try await waitUntil { channel.stored().isEmpty }
    }

    /// The panel says where the answer was given (spec 7): the phone by its name, or this Mac.
    @Test(.tags(.slow)) func panelTellsWhereTheAnswerCameFrom() async throws {
        VaultKitStrings.pinSourceLanguage()
        for (decision, expected) in [("once", "Approuvé sur iPhone de Camille"), ("denied", "Refusé sur iPhone de Camille")] {
            let (hosts, bridge, channel) = try raceHosts(phones: ["phone-a"])
            hosts.setPhoneNames(["phone-a": "iPhone de Camille"])
            let request = approvalRequest()
            let answer = onServerThread { bridge.approve(request: request) }
            try await waitUntil { channel.stored().contains { $0.to == "phone-a" } }
            try await phoneAnswers(channel, phone: "phone-a", decision: decision)
            _ = await answer.value
            try await waitUntil { @MainActor in hosts.lastOutcome != nil }
            #expect(hosts.lastOutcome?.text == expected)
        }

        let (hosts, bridge, channel) = try raceHosts(phones: ["phone-a"])
        let request = approvalRequest()
        let answer = onServerThread { bridge.approve(request: request) }
        try await waitUntil { channel.stored().contains { $0.to == "phone-a" } }
        while hosts.prompts.isEmpty { try await Task.sleep(for: .milliseconds(10)) }
        let prompt = try #require(hosts.prompts.first)
        hosts.answer(prompt.id, with: .allowOnce)
        // Set with the click itself, before the panel's prompt goes.
        #expect(hosts.lastOutcome == ApprovalOutcome(promptID: prompt.id, text: "Approuvé sur ce Mac", approved: true))
        _ = await answer.value
    }

    /// The audit log's origin column: `mac`, `phone:<id>` by the phone's name, nothing for older lines.
    @Test func auditOriginNamesThePhone() throws {
        VaultKitStrings.pinSourceLanguage()
        let (hosts, _, _) = try raceHosts(phones: [])
        hosts.setPhoneNames(["7f3a": "iPhone de Camille"])
        #expect(hosts.originLabel("mac") == "Ce Mac")
        #expect(hosts.originLabel("phone:7f3a") == "iPhone de Camille")
        #expect(hosts.originLabel("phone:0000") == "iPhone")
        #expect(hosts.originLabel(nil) == "")
        #expect(hosts.originLabel("") == "")
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
