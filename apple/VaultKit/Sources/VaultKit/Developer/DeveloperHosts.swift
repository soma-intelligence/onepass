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
    /// "Approuver aussi sur l'iPhone": the panel races the enrolled phones (spec 5.3). On by default:
    /// the spec asks the phones whenever one is enrolled.
    public var approveOnPhone = true
    /// Length of an agents-only window opened from the iPhone (spec 6.3): 1 h by default, 15 min
    /// to 8 h.
    public var agentWindowMinutes = DeveloperSettings.defaultAgentWindowMinutes {
        didSet { agentWindowMinutes = Self.clampWindow(agentWindowMinutes) }
    }

    public static let defaultAgentWindowMinutes = 60
    public static let agentWindowRange = 15...480

    static func clampWindow(_ minutes: Int) -> Int {
        min(max(minutes, agentWindowRange.lowerBound), agentWindowRange.upperBound)
    }

    public init() {}

    private enum Key {
        static let ssh = "onepass.dev.sshEnabled"
        static let presence = "onepass.dev.sshRequirePresence"
        static let forwarded = "onepass.dev.sshAllowForwarded"
        static let mcp = "onepass.dev.mcpEnabled"
        static let knownHosts = "onepass.dev.knownHostsBookmark"
        static let agentWindow = "onepass.dev.agentWindowMinutes"
        static let approveOnPhone = "onepass.dev.approveOnPhone"
    }

    public static func load(from defaults: UserDefaults) -> DeveloperSettings {
        var s = DeveloperSettings()
        s.sshEnabled = defaults.bool(forKey: Key.ssh)
        s.sshRequirePresence = defaults.object(forKey: Key.presence) as? Bool ?? true
        s.sshAllowForwarded = defaults.bool(forKey: Key.forwarded)
        s.mcpEnabled = defaults.bool(forKey: Key.mcp)
        s.knownHostsBookmark = defaults.data(forKey: Key.knownHosts)
        s.agentWindowMinutes = defaults.object(forKey: Key.agentWindow) as? Int ?? defaultAgentWindowMinutes
        s.approveOnPhone = defaults.object(forKey: Key.approveOnPhone) as? Bool ?? true
        return s
    }

    public func save(to defaults: UserDefaults) {
        defaults.set(sshEnabled, forKey: Key.ssh)
        defaults.set(sshRequirePresence, forKey: Key.presence)
        defaults.set(sshAllowForwarded, forKey: Key.forwarded)
        defaults.set(mcpEnabled, forKey: Key.mcp)
        defaults.set(agentWindowMinutes, forKey: Key.agentWindow)
        defaults.set(approveOnPhone, forKey: Key.approveOnPhone)
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

/// Where a settled approval was answered, shown by the panel a moment after it closes (spec 7):
/// "Approuvé sur iPhone de Camille", "Refusé sur iPhone de Camille", "Approuvé sur ce Mac".
public struct ApprovalOutcome: Equatable, Sendable {
    public let promptID: UUID
    public let text: String
    public let approved: Bool

    public init(promptID: UUID, text: String, approved: Bool) {
        self.promptID = promptID
        self.text = text
        self.approved = approved
    }
}

/// Runs the SSH agent and the MCP server of the Mac app on the unlocked session, and relays their
/// questions to the UI (`prompts`). Every server stops on lock: no key or secret is served locked.
///
/// With remote unlock enrolled (`RemoteUnlockCoordinator`), a locked Mac keeps an `McpGate` on the
/// MCP socket: an agent that connects is held while the iPhone is asked, and an agents-only window
/// (agent-ready spec 6.3) runs the servers on the session the phone opened. While a gate runs, the
/// MCP server always starts through `McpGate.handOver` (full unlock or agents-only window).
@MainActor
@Observable
public final class DeveloperHosts {
    public private(set) var settings: DeveloperSettings
    public private(set) var sshRunning = false
    public private(set) var mcpRunning = false
    /// The gate holds the MCP socket while the Mac is locked (remote unlock enrolled).
    public private(set) var gateRunning = false
    /// The last start failure, shown by the settings (nil once a start works).
    public private(set) var sshError: String?
    public private(set) var mcpError: String?
    /// Questions waiting for the user, oldest first.
    public private(set) var prompts: [DeveloperPrompt] = []
    /// Bumped when the files the settings list (clients, grants, audit log) may have changed.
    public private(set) var revision = 0
    /// Where the last settled approval was answered (nil: refused by the lock or the timeout).
    public private(set) var lastOutcome: ApprovalOutcome?
    /// Device id to name of the approving phones, for the panel and the audit log.
    @ObservationIgnored private var phoneNames: [String: String] = [:]

    public let paths: DeveloperPaths
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let presence: any PresenceChecker
    @ObservationIgnored private var ssh: SshAgentHost?
    @ObservationIgnored private var mcp: McpHost?
    @ObservationIgnored private var answers: [UUID: AnswerBox] = [:]
    @ObservationIgnored private lazy var bridge = PromptBridge(owner: self, presence: presence)
    @ObservationIgnored private var knownHostsURL: URL?
    @ObservationIgnored private var gate: McpGate?
    /// The last word between `armGate` and `disarmGate`: a start still queued after a disarm is dropped.
    @ObservationIgnored private var gateWanted = false
    @ObservationIgnored private lazy var gateBridge = GateBridge(owner: self)
    /// Answers the gate (set by `RemoteUnlockCoordinator` while remote unlock is enrolled; nil: no
    /// gate, a lock stops MCP as before).
    @ObservationIgnored private(set) var lockedRequestHandler: (@MainActor (FfiMcpClient) async -> Bool)?
    /// Server stops and gate starts, in order: a socket is free before the next listener binds it.
    @ObservationIgnored private var work: Task<Void, Never>?
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

    /// After an unlock: starts what the settings enable (MCP through the gate when one runs).
    public func sessionUnlocked(_ session: VaultSession) async {
        guard let core = session.coreSession else { return }
        let store = Self.storeFolder(session)
        if settings.sshEnabled { await startSSH(core) }
        if settings.mcpEnabled { await startMCP(core, store: store) }
        // Unlocked: nothing is held any more.
        disarmGate()
    }

    /// On lock: every server stops and every pending question is refused. With remote unlock
    /// enrolled, the gate then holds the MCP socket.
    public func sessionLocked() {
        stopServers()
        armGate()
    }

    /// An agents-only window opened (spec 6.3): the servers run on `core`, the first tool request
    /// races the panel and the iPhone through `approver`.
    func agentWindowOpened(_ core: Session, store: String, approver: RemoteApprover?) async {
        bridge.remote = approver
        if settings.sshEnabled { await startSSH(core) }
        if settings.mcpEnabled { await startMCP(core, store: store) }
    }

    /// The agents-only window ended: everything stops as on a lock; `rearm` puts the gate back
    /// (still locked and enrolled).
    func agentWindowEnded(rearm: Bool) {
        stopServers()
        if rearm { armGate() }
    }

    /// Set by the coordinator: who answers the gate (nil stops it).
    func setLockedRequestHandler(_ handler: (@MainActor (FfiMcpClient) async -> Bool)?) {
        lockedRequestHandler = handler
        if handler == nil { disarmGate() }
    }

    /// The iPhone approver of the next approvals is set (tests).
    var remoteApproverSet: Bool { bridge.remote != nil }
    /// The iPhone approver of the next approvals (tests).
    var remoteApprover: RemoteApprover? { bridge.remote }

    /// Waits for the pending server stops and gate starts (tests, and before a start).
    func settle() async {
        var last: Task<Void, Never>?
        while let current = work, current != last {
            last = current
            await current.value
        }
    }

    private func stopServers() {
        stopSSH()
        stopMCP()
        // No iPhone request leaves a locked Mac; Task 10 sets the approver again after an unlock.
        bridge.remote = nil
        // Refused by the lock, not by anyone: no origin.
        for prompt in prompts { settle(prompt.id, with: FfiAnswer(decision: .deny, approvedOn: nil)) }
    }

    private func enqueue(_ op: @escaping @MainActor () async -> Void) {
        let previous = work
        work = Task { @MainActor in
            await previous?.value
            await op()
        }
    }

    // MARK: - Gate

    /// Starts the gate on the MCP socket when remote unlock is enrolled and MCP is on.
    func armGate() {
        gateWanted = true
        enqueue { [weak self] in await self?.startGate() }
    }

    private func startGate() async {
        guard gateWanted, gate == nil, mcp == nil, lockedRequestHandler != nil, settings.mcpEnabled else { return }
        let socket = paths.mcpSocket.path
        let relay = paths.relay.path
        let ui = gateBridge
        do {
            gate = try await CoreThread.run { try McpGate.start(socketPath: socket, relayPath: relay, ui: ui) }
            gateRunning = true
        } catch {
            mcpError = VaultError(error).localizedMessage
            Self.log.error("MCP gate did not start")
        }
    }

    /// Stops the gate (held connections are refused).
    func disarmGate() {
        gateWanted = false
        guard let gate else { return }
        self.gate = nil
        gateRunning = false
        enqueue { _ = try? await CoreThread.run { gate.stop() } }
    }

    /// Called by the gate bridge on the main actor.
    fileprivate func answerLockedRequest(_ client: FfiMcpClient) async -> Bool {
        guard let lockedRequestHandler else { return false }
        return await lockedRequestHandler(client)
    }

    /// The store's folder: no tool may read or write it through the relay.
    private static func storeFolder(_ session: VaultSession) -> String {
        session.environment.databaseURL.deletingLastPathComponent().path
    }

    public func update(_ change: (inout DeveloperSettings) -> Void, session: VaultSession) async {
        let before = settings
        change(&settings)
        settings.save(to: defaults)
        let sshChanged = before.sshEnabled != settings.sshEnabled
            || before.sshRequirePresence != settings.sshRequirePresence
            || before.sshAllowForwarded != settings.sshAllowForwarded
            || before.knownHostsBookmark != settings.knownHostsBookmark
        // The full session, else the agents-only one, else nothing (locked).
        let core = session.coreSession ?? session.agentSession
        if sshChanged {
            stopSSH()
            if settings.sshEnabled, let core { await startSSH(core) }
        }
        if before.mcpEnabled != settings.mcpEnabled {
            stopMCP()
            disarmGate()
            if settings.mcpEnabled {
                if let core {
                    await startMCP(core, store: Self.storeFolder(session))
                } else {
                    armGate()
                }
            }
        }
    }

    private func startSSH(_ core: Session) async {
        guard ssh == nil else { return }
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

    /// `store`: the store's folder, which no tool may read or write through the relay. With a gate
    /// on the socket the server starts through `handOver` (held connections go to it); if that
    /// fails the gate stops and the server starts alone.
    private func startMCP(_ core: Session, store: String) async {
        // A server or a gate being stopped frees the socket first.
        await settle()
        guard mcp == nil else { return }
        let config = FfiMcpHostConfig(
            dataDir: dataDirectory, socketPath: paths.mcpSocket.path, relayPath: paths.relay.path,
            protectedDirs: [store])
        let ui = bridge
        if let gate {
            self.gate = nil
            gateRunning = false
            gateWanted = false
            do {
                let host = try await CoreThread.run { try gate.handOver(session: core, config: config, ui: ui) }
                mcp = host
                mcpRunning = true
                mcpError = nil
                return
            } catch {
                Self.log.error("MCP gate did not hand over")
                _ = try? await CoreThread.run { gate.stop() }
            }
        }
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
            enqueue { _ = try? await CoreThread.run { host.stop() } }
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
        guard let prompt = prompts.first(where: { $0.id == id }) else { return }
        let answer = FfiAnswer(decision: decision, approvedOn: "mac")
        // This click counts only if the phone did not answer first. The outcome is set before the
        // prompt goes: the panel shows it in place of the question.
        if answers[id]?.resolve(answer) == true, case .approval = prompt.kind { recordOutcome(id, answer) }
        settle(id, with: answer)
    }

    /// The names of the phones that approve (set from the signed approver list).
    public func setPhoneNames(_ names: [String: String]) {
        phoneNames = names
    }

    /// The audit log's origin column: "Ce Mac", the phone's name, "iPhone" for a phone no longer
    /// listed, nothing for older lines (no `approved_on`).
    public func originLabel(_ approvedOn: String?) -> String {
        guard let approvedOn, !approvedOn.isEmpty else { return "" }
        if approvedOn == "mac" { return String(localized: "Ce Mac", bundle: VaultKitStrings.bundle) }
        if approvedOn.hasPrefix("phone:") { return phoneName(String(approvedOn.dropFirst("phone:".count))) }
        return ""
    }

    private func phoneName(_ id: String) -> String {
        phoneNames[id] ?? "iPhone"
    }

    /// Keeps where `answer` was given for the panel, once per prompt. Nothing for a timeout or a lock
    /// (no origin), nor for a refusal clicked on this Mac.
    fileprivate func recordOutcome(_ id: UUID, _ answer: FfiAnswer) {
        guard lastOutcome?.promptID != id, let origin = answer.approvedOn else { return }
        let approved = answer.decision != .deny
        let text: String
        if origin == "mac" {
            guard approved else { return }
            text = String(localized: "Approuvé sur ce Mac", bundle: VaultKitStrings.bundle)
        } else if origin.hasPrefix("phone:") {
            let name = phoneName(String(origin.dropFirst("phone:".count)))
            text = approved
                ? String(localized: "Approuvé sur \(name)", bundle: VaultKitStrings.bundle)
                : String(localized: "Refusé sur \(name)", bundle: VaultKitStrings.bundle)
        } else {
            return
        }
        lastOutcome = ApprovalOutcome(promptID: id, text: text, approved: approved)
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
        close(prompt.id, answer: answer)
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

    /// The panel closes, however the question ended; with an answer, it says where it was given.
    private func close(_ id: UUID, answer: FfiAnswer? = nil) {
        Task { @MainActor [weak owner] in
            if let answer { owner?.recordOutcome(id, answer) }
            owner?.expire(id)
            owner?.touched()
        }
    }
}

/// `FfiGateUi` for the core: called on a gate thread when an agent connects to a locked Mac. It asks
/// the main actor (`RemoteUnlockCoordinator.handleLockedRequest`) without blocking it, and blocks
/// only its own thread, at most `timeout`: the coordinator answers within 60 s, the grace covers a
/// busy main actor. No answer refuses.
final class GateBridge: FfiGateUi, @unchecked Sendable {
    weak var owner: DeveloperHosts?
    let timeout: TimeInterval
    static let timeout: TimeInterval = PromptBridge.timeout + 5

    @MainActor init(owner: DeveloperHosts, timeout: TimeInterval = GateBridge.timeout) {
        self.owner = owner
        self.timeout = timeout
    }

    func lockedRequest(client: FfiMcpClient) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: false)
        let task = Task { @MainActor [weak owner] in
            let ok = await owner?.answerLockedRequest(client) ?? false
            result.withLock { $0 = ok }
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + timeout) == .success else {
            task.cancel()
            return false
        }
        return result.withLock { $0 }
    }
}
