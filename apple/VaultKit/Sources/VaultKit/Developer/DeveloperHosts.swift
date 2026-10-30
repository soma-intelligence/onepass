import Foundation
import Observation
import OnePassCore
import os

/// Where the milestone 7 servers of the Mac app keep their files. In the sandbox `NSHomeDirectory()` is
/// the container's `Data` folder: the sockets live there, like Secretive's (spec 2026-10-27-m7-app,
/// section 3). `sun_path` holds 104 bytes: the paths stay short.
public struct DeveloperPaths: Sendable, Equatable {
    public var dataDirectory: URL
    public var sshSocket: URL { dataDirectory.appending(path: "ssh.sock") }
    public var mcpSocket: URL { dataDirectory.appending(path: "mcp.sock") }
    /// The relay MCP clients launch (`Contents/Helpers/onepass-mcp`).
    public var relay: URL

    public init(dataDirectory: URL, relay: URL) {
        self.dataDirectory = dataDirectory
        self.relay = relay
    }

    public static var app: DeveloperPaths {
        DeveloperPaths(
            dataDirectory: URL(fileURLWithPath: NSHomeDirectory()).appending(path: ".onepass", directoryHint: .isDirectory),
            relay: Bundle.main.bundleURL.appending(path: "Contents/Helpers/onepass-mcp"))
    }

    /// The `~/.ssh/config` line that sends `ssh` to this agent.
    public var identityAgentLine: String { "IdentityAgent \"\(sshSocket.path)\"" }
    /// The shell line for tools that read `SSH_AUTH_SOCK`.
    public var exportLine: String { "export SSH_AUTH_SOCK=\"\(sshSocket.path)\"" }

    /// The block to paste into an MCP client's configuration (OnePass never writes it for you).
    public var mcpClientConfig: String {
        """
        {
          "mcpServers": {
            "onepass": {
              "command": "\(relay.path)",
              "args": ["--socket", "\(mcpSocket.path)"]
            }
          }
        }
        """
    }
}

/// The local, non secret settings of the servers (one `UserDefaults`, own keys).
public struct DeveloperSettings: Sendable, Equatable {
    public var sshEnabled = false
    /// Touch ID (or the session password) on top of every approved signature.
    public var sshRequirePresence = true
    public var sshAllowForwarded = false
    public var mcpEnabled = false
    /// Security-scoped bookmark of the `known_hosts` file the user chose.
    public var knownHostsBookmark: Data?

    public init() {}

    private enum Key {
        static let ssh = "onepass.dev.sshEnabled"
        static let presence = "onepass.dev.sshRequirePresence"
        static let forwarded = "onepass.dev.sshAllowForwarded"
        static let mcp = "onepass.dev.mcpEnabled"
        static let knownHosts = "onepass.dev.knownHostsBookmark"
    }

    public static func load(from defaults: UserDefaults) -> DeveloperSettings {
        var s = DeveloperSettings()
        s.sshEnabled = defaults.bool(forKey: Key.ssh)
        s.sshRequirePresence = defaults.object(forKey: Key.presence) as? Bool ?? true
        s.sshAllowForwarded = defaults.bool(forKey: Key.forwarded)
        s.mcpEnabled = defaults.bool(forKey: Key.mcp)
        s.knownHostsBookmark = defaults.data(forKey: Key.knownHosts)
        return s
    }

    public func save(to defaults: UserDefaults) {
        defaults.set(sshEnabled, forKey: Key.ssh)
        defaults.set(sshRequirePresence, forKey: Key.presence)
        defaults.set(sshAllowForwarded, forKey: Key.forwarded)
        defaults.set(mcpEnabled, forKey: Key.mcp)
        if let knownHostsBookmark {
            defaults.set(knownHostsBookmark, forKey: Key.knownHosts)
        } else {
            defaults.removeObject(forKey: Key.knownHosts)
        }
    }
}

/// A question a server asks the user, shown by the app's approval panel.
public struct DeveloperPrompt: Identifiable, Sendable {
    public enum Kind: Sendable {
        case approval(FfiApprovalRequest)
        case pairing(FfiMcpClient)
    }

    /// Where the iPhone stands in the race of an approval (spec 5.3).
    public enum PhoneStatus: Sendable, Equatable {
        /// No iPhone approval for this question (setting off, or a pairing).
        case off
        /// The requests are being sent.
        case asking
        /// The names of the phones that got the request.
        case sent([String])
        /// No phone enrolled, or CloudKit unreachable: the panel alone answers.
        case unavailable
    }

    public let id = UUID()
    public let kind: Kind
    public let askedAt: Date
    public internal(set) var phoneStatus: PhoneStatus = .off

    /// The line the panel shows about the iPhone, if any.
    public var phoneNotice: String? {
        switch phoneStatus {
        case .off, .asking:
            nil
        case .sent(let names):
            String(localized: "Envoyé à \(names.formatted(.list(type: .and)))", bundle: VaultKitStrings.bundle)
        case .unavailable:
            String(localized: "iPhone indisponible : approuve ici", bundle: VaultKitStrings.bundle)
        }
    }
}

/// Runs the SSH agent and the MCP server of the Mac app on the unlocked session, and relays their
/// questions to the UI (`prompts`). Every server stops on lock: no key or secret is served locked.
@MainActor
@Observable
public final class DeveloperHosts {
    public private(set) var settings: DeveloperSettings
    public private(set) var sshRunning = false
    public private(set) var mcpRunning = false
    /// The last start failure, shown by the settings (nil once a start works).
    public private(set) var sshError: String?
    public private(set) var mcpError: String?
    /// Questions waiting for the user, oldest first.
    public private(set) var prompts: [DeveloperPrompt] = []
    /// Bumped when the files the settings list (clients, grants, audit log) may have changed.
    public private(set) var revision = 0

    public let paths: DeveloperPaths
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let presence: any PresenceChecker
    @ObservationIgnored private var ssh: SshAgentHost?
    @ObservationIgnored private var mcp: McpHost?
    @ObservationIgnored private var answers: [UUID: AnswerBox] = [:]
    @ObservationIgnored private lazy var bridge = PromptBridge(owner: self, presence: presence)
    @ObservationIgnored private var knownHostsURL: URL?
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "developer")

    public init(paths: DeveloperPaths = .app, defaults: UserDefaults = .standard,
                presence: any PresenceChecker = SystemPresenceChecker()) {
        self.paths = paths
        self.defaults = defaults
        self.presence = presence
        settings = DeveloperSettings.load(from: defaults)
    }

    public var dataDirectory: String { paths.dataDirectory.path }

    // MARK: - Lifecycle

    /// After an unlock: starts what the settings enable.
    public func sessionUnlocked(_ session: VaultSession) async {
        if settings.sshEnabled { await startSSH(session) }
        if settings.mcpEnabled { await startMCP(session) }
    }

    /// On lock: every server stops and every pending question is refused.
    public func sessionLocked() {
        stopSSH()
        stopMCP()
        // No iPhone request leaves a locked Mac; Task 10 sets the approver again after an unlock.
        bridge.remote = nil
        // Refused by the lock, not by anyone: no origin.
        for prompt in prompts { settle(prompt.id, with: FfiAnswer(decision: .deny, approvedOn: nil)) }
    }

    public func update(_ change: (inout DeveloperSettings) -> Void, session: VaultSession) async {
        let before = settings
        change(&settings)
        settings.save(to: defaults)
        let sshChanged = before.sshEnabled != settings.sshEnabled
            || before.sshRequirePresence != settings.sshRequirePresence
            || before.sshAllowForwarded != settings.sshAllowForwarded
            || before.knownHostsBookmark != settings.knownHostsBookmark
        if sshChanged {
            stopSSH()
            if settings.sshEnabled { await startSSH(session) }
        }
        if before.mcpEnabled != settings.mcpEnabled {
            stopMCP()
            if settings.mcpEnabled { await startMCP(session) }
        }
    }

    private func startSSH(_ session: VaultSession) async {
        guard ssh == nil, let core = session.coreSession else { return }
        let knownHosts = resolveKnownHosts()
        let config = FfiSshAgentConfig(
            dataDir: dataDirectory, socketPath: paths.sshSocket.path,
            allowForwarded: settings.sshAllowForwarded,
            knownHosts: knownHosts.map { [$0.path] } ?? [],
            requirePresence: settings.sshRequirePresence)
        let ui = bridge
        do {
            let host = try await CoreThread.run { try SshAgentHost.start(session: core, config: config, ui: ui) }
            ssh = host
            sshRunning = true
            sshError = nil
        } catch {
            sshError = VaultError(error).localizedMessage
            Self.log.error("SSH agent did not start")
        }
    }

    private func stopSSH() {
        if let host = ssh {
            ssh = nil
            Task.detached { host.stop() }
        }
        sshRunning = false
        if let knownHostsURL {
            knownHostsURL.stopAccessingSecurityScopedResource()
            self.knownHostsURL = nil
        }
    }

    private func startMCP(_ session: VaultSession) async {
        guard mcp == nil, let core = session.coreSession else { return }
        // The store's folder: no tool may read or write it through the relay.
        let store = session.environment.databaseURL.deletingLastPathComponent().path
        let config = FfiMcpHostConfig(
            dataDir: dataDirectory, socketPath: paths.mcpSocket.path, relayPath: paths.relay.path,
            protectedDirs: [store])
        let ui = bridge
        do {
            let host = try await CoreThread.run { try McpHost.start(session: core, config: config, ui: ui) }
            mcp = host
            mcpRunning = true
            mcpError = nil
        } catch {
            mcpError = VaultError(error).localizedMessage
            Self.log.error("MCP server did not start")
        }
    }

    private func stopMCP() {
        if let host = mcp {
            mcp = nil
            Task.detached { host.stop() }
        }
        mcpRunning = false
    }

    /// The `known_hosts` file the user chose, opened for the agent's lifetime.
    private func resolveKnownHosts() -> URL? {
        guard let data = settings.knownHostsBookmark else { return nil }
        var stale = false
        #if os(macOS)
        let options: URL.BookmarkResolutionOptions = [.withSecurityScope]
        #else
        let options: URL.BookmarkResolutionOptions = []
        #endif
        guard let url = try? URL(resolvingBookmarkData: data, options: options, bookmarkDataIsStale: &stale)
        else { return nil }
        if url.startAccessingSecurityScopedResource() { knownHostsURL = url }
        return url
    }

    // MARK: - Prompts

    /// The user's answer to a prompt. Unknown ids (already timed out) are ignored.
    public func answer(_ id: UUID, with decision: FfiDecision) {
        settle(id, with: FfiAnswer(decision: decision, approvedOn: "mac"))
    }

    /// The iPhone approver the next approvals race against the panel (nil: the panel alone). Set
    /// after an unlock, cleared on lock.
    public func useRemoteApprover(_ approver: RemoteApprover?) {
        bridge.remote = approver
    }

    private func settle(_ id: UUID, with answer: FfiAnswer) {
        prompts.removeAll { $0.id == id }
        answers.removeValue(forKey: id)?.resolve(answer)
        revision &+= 1
    }

    /// The race moved on: what the panel says about the iPhone. Unknown ids are ignored.
    fileprivate func setPhoneStatus(_ id: UUID, _ status: DeveloperPrompt.PhoneStatus) {
        guard let index = prompts.firstIndex(where: { $0.id == id }) else { return }
        prompts[index].phoneStatus = status
    }

    /// Called by the bridge on the main actor: shows the prompt and keeps its answer box.
    fileprivate func enqueue(_ prompt: DeveloperPrompt, box: AnswerBox) {
        answers[prompt.id] = box
        prompts.append(prompt)
    }

    /// The question is settled (answered anywhere, or given up): the prompt goes away.
    fileprivate func expire(_ id: UUID) {
        prompts.removeAll { $0.id == id }
        answers.removeValue(forKey: id)
    }

    /// A server answered something the settings list (a grant, an audit entry).
    fileprivate func touched() {
        revision &+= 1
    }
}

/// One answer, handed to a waiting server thread. The first answer wins; any later one (a second
/// phone, a click on a closed panel) is refused, and so is any answer after the wait ended.
final class AnswerBox: @unchecked Sendable {
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var answer: FfiAnswer?
    private var closed = false

    /// False when the question was already settled: the answer is ignored.
    @discardableResult
    func resolve(_ a: FfiAnswer) -> Bool {
        let first = lock.withLock { () -> Bool in
            guard answer == nil, !closed else { return false }
            answer = a
            return true
        }
        if first { semaphore.signal() }
        return first
    }

    /// Waits for the answer; a question nobody answers in time is refused (nil).
    func wait(timeout: DispatchTime) -> FfiAnswer? {
        _ = semaphore.wait(timeout: timeout)
        return lock.withLock {
            closed = true
            return answer
        }
    }
}

/// `FfiDeveloperUi` for the core: called on server threads, it posts to the main actor and blocks
/// until the user answers (at most `timeout`, then refuses). An approval races the Mac panel against
/// the iPhone (`remote`): the first valid answer wins, the other side is withdrawn (spec 5.3).
final class PromptBridge: FfiDeveloperUi, @unchecked Sendable {
    weak var owner: DeveloperHosts?
    let presence: any PresenceChecker
    /// The request lifetime of the spec (60 s): a question nobody answers is refused.
    static let timeout: TimeInterval = 60
    let timeout: TimeInterval
    private let remoteApprover = OSAllocatedUnfairLock<RemoteApprover?>(initialState: nil)
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "developer")

    @MainActor init(owner: DeveloperHosts, presence: any PresenceChecker, timeout: TimeInterval = PromptBridge.timeout) {
        self.owner = owner
        self.presence = presence
        self.timeout = timeout
    }

    var remote: RemoteApprover? {
        get { remoteApprover.withLock { $0 } }
        set { remoteApprover.withLock { $0 = newValue } }
    }

    func approve(request: FfiApprovalRequest) -> FfiAnswer {
        let remote = self.remote
        let box = AnswerBox()
        let prompt = DeveloperPrompt(
            kind: .approval(request), askedAt: Date(), phoneStatus: remote == nil ? .off : .asking)
        show(prompt, box: box)
        var phone: Task<Void, Never>?
        if let remote {
            let id = prompt.id
            phone = Task.detached { [weak owner] in
                let answer = await remote.ask(request) { names in
                    Task { @MainActor in owner?.setPhoneStatus(id, .sent(names)) }
                }
                if let answer {
                    if !box.resolve(answer) { Self.log.notice("late iPhone answer ignored") }
                } else if !Task.isCancelled {
                    await MainActor.run { owner?.setPhoneStatus(id, .unavailable) }
                }
            }
        }
        let answer = box.wait(timeout: .now() + timeout)
        // The Mac answered or time ran out: the iPhone requests are withdrawn.
        phone?.cancel()
        close(prompt.id)
        return answer ?? FfiAnswer(decision: .deny, approvedOn: nil)
    }

    func pairRequest(client: FfiMcpClient) -> Bool {
        let box = AnswerBox()
        let prompt = DeveloperPrompt(kind: .pairing(client), askedAt: Date())
        show(prompt, box: box)
        let answer = box.wait(timeout: .now() + timeout)
        close(prompt.id)
        guard let answer, answer.decision != .deny else { return false }
        return verifyPresence(reason: String(localized: "Appairer \(client.label) avec OnePass", bundle: VaultKitStrings.bundle))
    }

    func verifyPresence(reason: String) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: false)
        let checker = presence
        Task.detached {
            let ok = await checker.confirm(prompt: reason)
            result.withLock { $0 = ok }
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + timeout) == .success else { return false }
        return result.withLock { $0 }
    }

    private func show(_ prompt: DeveloperPrompt, box: AnswerBox) {
        Task { @MainActor [weak owner] in
            guard let owner else { box.resolve(FfiAnswer(decision: .deny, approvedOn: nil)); return }
            owner.enqueue(prompt, box: box)
        }
    }

    /// The panel closes, however the question ended.
    private func close(_ id: UUID) {
        Task { @MainActor [weak owner] in
            owner?.expire(id)
            owner?.touched()
        }
    }
}
