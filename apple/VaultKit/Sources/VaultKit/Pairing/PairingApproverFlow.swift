import Foundation
import Observation
import Synchronization
import os

/// One line of a public session's journal, as the approver shows it. Memory only.
public struct PairingAuditEntry: Equatable, Identifiable, Sendable {
    public let id: Int
    public let at: Date
    public let itemID: String
    /// The item's title as this device knows it, empty if it cannot tell.
    public let title: String
    public let action: FfiAuditAction
}

/// The unlocked device's side of a pairing (spec 2b 5.1). Two ways in: `begin(qrText:)` scans the new
/// device's QR, `startHosting()` shows a code (QR and `XXXX-XXXX`) for the new device to scan or type.
/// `begin(qrText:)` connects to the service
/// named in the scanned QR, reads the Hello and answers the key exchange; both screens then show the
/// 6-digit code. Nothing more leaves this device before the user here confirms, a fresh presence check
/// passes (Face ID, else the master password, ruling A8) and the new device confirmed too.
@MainActor
@Observable
public final class PairingApproverFlow {
    public enum State: Equatable {
        case idle
        case connecting
        /// Hosting: show `code` (its QR text and the typed form) until it expires; a newer one replaces it
        /// every 30 s. The new device scans or types it.
        case hosting(code: FfiHostCode)
        /// Compare `sas` with the new device's screen; `peer` and `requestedMode` are what it asks for.
        case comparing(sas: String, peer: FfiPeerDevice, requestedMode: FfiDeviceMode)
        /// Approved here; waiting for the new device's confirmation.
        case waitingForPeer
        /// The grant is being built and sent. `cancel()` is ignored from here: the grant may already
        /// be out, so nothing may claim that nothing was sent.
        case granting
        /// A public session runs: its journal and end, on this device's clock.
        case publicRunning(journal: [PairingAuditEntry], expiresAt: Date)
        case done
        case failed(PairingFailure)
    }

    public private(set) var state: State = .idle
    /// Seconds left in a running public session (refreshed every second).
    public private(set) var remaining: TimeInterval = 0
    /// The last refusal of `approve` that keeps the comparison open (password needed, wrong password).
    public private(set) var approvalError: VaultError?

    @ObservationIgnored private let vault: VaultSession
    @ObservationIgnored private let connector: (any PairingConnector)?
    @ObservationIgnored private let listener: (any PairingListener)?
    @ObservationIgnored private let renewEvery: Duration
    @ObservationIgnored private let handshakeTimeout: Duration
    @ObservationIgnored private var host: PairingHost?
    @ObservationIgnored private var hostTask: Task<Void, Never>?
    @ObservationIgnored private let now: @Sendable () -> Date
    @ObservationIgnored private var approver: PairingApprover?
    @ObservationIgnored private var transport: (any PairingTransport)?
    @ObservationIgnored private var receiver: Task<Void, Never>?
    @ObservationIgnored private var ticker: Task<Void, Never>?
    @ObservationIgnored private var peerConfirmed = false
    @ObservationIgnored private var peerWaiters: [CheckedContinuation<Bool, Never>] = []
    @ObservationIgnored private var journal: [PairingAuditEntry] = []
    @ObservationIgnored private var nextAuditID = 0
    @ObservationIgnored private var publicExpiresAt: Date?
    @ObservationIgnored private var acked = false
    /// An approval runs (presence, wait, grant): a second one is refused, set before the first await.
    @ObservationIgnored private var approving = false
    @ObservationIgnored private let peerTimeout: Duration

    /// How long the approver waits for the new device's confirmation once presence passed (L5).
    public static let peerTimeout: Duration = .seconds(60)
    /// Entries a public session's journal keeps: the oldest go first (L3).
    public static let maxJournalEntries = 500
    /// Longest field label the journal keeps from the guest (L3).
    public static let maxAuditLabelLength = 128

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "pairing")

    /// How often a new code replaces the one on screen while hosting.
    public static let renewInterval: Duration = .seconds(30)
    /// How long a connection has to send its Hello while hosting (nothing is authenticated yet).
    public static let handshakeTimeout: Duration = .seconds(10)
    /// Connections checked at the same time while hosting; more are closed at once.
    static let maxPendingHandshakes = 4

    public init(
        vault: VaultSession, connector: any PairingConnector, peerTimeout: Duration = PairingApproverFlow.peerTimeout,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.vault = vault
        self.connector = connector
        self.listener = nil
        self.peerTimeout = peerTimeout
        self.renewEvery = Self.renewInterval
        self.handshakeTimeout = Self.handshakeTimeout
        self.now = now
    }

    /// An approver that shows a code (`startHosting()`): `listener` publishes one service per code
    /// (`LocalNetworkPairingListener` in the apps).
    public init(
        vault: VaultSession, listener: any PairingListener, peerTimeout: Duration = PairingApproverFlow.peerTimeout,
        renewEvery: Duration = PairingApproverFlow.renewInterval,
        handshakeTimeout: Duration = PairingApproverFlow.handshakeTimeout,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.vault = vault
        self.connector = nil
        self.listener = listener
        self.peerTimeout = peerTimeout
        self.renewEvery = renewEvery
        self.handshakeTimeout = handshakeTimeout
        self.now = now
    }

    isolated deinit {
        hostTask?.cancel()
        host?.close()
        receiver?.cancel()
        ticker?.cancel()
        transport?.close()
    }

    /// Connects to the new device named in the scanned QR and starts the code comparison. An expired
    /// QR, or a Hello the QR does not commit to, is refused before anything is sent.
    public func begin(qrText: String) async {
        guard state == .idle else { return }
        guard vault.state == .unlocked else {
            state = .failed(.other(VaultError.passwordRequired.localizedMessage))
            return
        }
        guard let connector else {
            state = .failed(.refused)
            return
        }
        state = .connecting
        do {
            let service = try pairingServiceName(qrText: qrText)
            let transport = try await connector.connect(serviceName: service)
            guard state == .connecting else {
                transport.close()
                return
            }
            self.transport = transport
            // Before the key exchange nothing is authenticated: a Hello is small (M2).
            let hello = try await transport.receive(maxBytes: PairingFrame.maxHandshakeBytes)
            let nowUnix = Int64(now().timeIntervalSince1970)
            let approver = try await CoreThread.run {
                try PairingApprover.begin(qrText: qrText, hello: hello, now: nowUnix)
            }
            guard state == .connecting else { return }
            self.approver = approver
            try await transport.send(approver.keyExchange())
            state = .comparing(sas: approver.sas(), peer: approver.peer(), requestedMode: approver.requestedMode())
            startReceiving(approver: approver, transport: transport)
        } catch {
            fail(PairingFailure(error))
        }
    }

    // MARK: - Hosting (the code is shown here)

    private enum HostEvent: Sendable {
        case renew
        case connection(any PairingTransport)
        case hello(id: Int, Data)
        case failed(id: Int)
    }

    /// Shows a code and waits for the new device (rendezvous direction). A new code every
    /// `renewEvery`; each stays valid for 120 s. The first connection that sends a Hello proving a
    /// live code goes to the code comparison; the codes are spent then, the services withdrawn.
    public func startHosting() {
        guard state == .idle else { return }
        guard vault.state == .unlocked, listener != nil else {
            state = .failed(.other(VaultError.passwordRequired.localizedMessage))
            return
        }
        do {
            host = try PairingHost()
        } catch {
            state = .failed(PairingFailure(error))
            return
        }
        state = .connecting
        hostTask = Task { [weak self] in await self?.runHost() }
    }

    private func runHost() async {
        guard let host, let listener else { return }
        let (events, sink) = AsyncStream<HostEvent>.makeStream()
        /// Connections accepted and not handed over yet, by id.
        let open = Mutex<[Int: any PairingTransport]>([:])
        var services: [(expiresAt: Int64, task: Task<Void, Never>)] = []
        var nextID = 0
        let timeout = handshakeTimeout
        let renew = renewEvery
        let renewal = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: renew)
                if Task.isCancelled { return }
                sink.yield(.renew)
            }
        }
        defer {
            renewal.cancel()
            for s in services { s.task.cancel() }
            sink.finish()
            for t in open.withLock({ o in defer { o = [:] }; return Array(o.values) }) { t.close() }
        }

        /// A new code on screen and its service published.
        func issue() async -> Bool {
            let nowUnix = Int64(now().timeIntervalSince1970)
            do {
                let code = try await CoreThread.run { try host.issue(now: nowUnix) }
                services.removeAll { s in
                    guard s.expiresAt < nowUnix else { return false }
                    s.task.cancel()
                    return true
                }
                let connections = listener.connections(serviceName: code.serviceName)
                let task = Task {
                    do {
                        for try await transport in connections { sink.yield(.connection(transport)) }
                    } catch {}
                }
                services.append((code.expiresAt, task))
                state = .hosting(code: code)
                return true
            } catch {
                fail(PairingFailure(error))
                return false
            }
        }

        guard await issue() else { return }
        for await event in events {
            switch event {
            case .renew:
                guard await issue() else { return }
            case .connection(let transport):
                let id = nextID
                nextID += 1
                let admitted = open.withLock { o -> Bool in
                    guard o.count < Self.maxPendingHandshakes else { return false }
                    o[id] = transport
                    return true
                }
                guard admitted else {
                    transport.close()
                    continue
                }
                Task {
                    do {
                        // Nothing is authenticated yet: a Hello is small.
                        let hello = try await Self.receiveWithin(
                            transport, maxBytes: PairingFrame.maxHandshakeBytes, deadline: timeout)
                        sink.yield(.hello(id: id, hello))
                    } catch {
                        sink.yield(.failed(id: id))
                    }
                }
            case .failed(let id):
                open.withLock { $0.removeValue(forKey: id) }?.close()
            case .hello(let id, let hello):
                guard let transport = open.withLock({ $0.removeValue(forKey: id) }) else { continue }
                let nowUnix = Int64(now().timeIntervalSince1970)
                let approver: PairingApprover
                do {
                    approver = try await CoreThread.run { try host.accept(joinHello: hello, now: nowUnix) }
                } catch {
                    // Wrong code or a malformed Hello: that connection is dropped. Too many close the host.
                    transport.close()
                    if !host.isOpen() { fail(.refused); return }
                    continue
                }
                guard state != .idle, !isFinished else {
                    transport.close()
                    return
                }
                self.approver = approver
                self.transport = transport
                do {
                    try await transport.send(approver.keyExchange())
                } catch {
                    fail(PairingFailure(error))
                    return
                }
                guard !isFinished else { return }
                state = .comparing(sas: approver.sas(), peer: approver.peer(), requestedMode: approver.requestedMode())
                startReceiving(approver: approver, transport: transport)
                // The `defer` withdraws the services and closes the other connections.
                return
            }
        }
    }

    private var isFinished: Bool {
        switch state {
        case .done, .failed: true
        default: false
        }
    }

    /// One frame, at most `maxBytes` long, within `deadline`.
    nonisolated private static func receiveWithin(
        _ transport: any PairingTransport, maxBytes: Int, deadline: Duration
    ) async throws -> Data {
        try await withThrowingTaskGroup(of: Data?.self) { group in
            group.addTask { try await transport.receive(maxBytes: maxBytes) }
            group.addTask {
                try await Task.sleep(for: deadline)
                return nil
            }
            defer { group.cancelAll() }
            guard let first = try await group.next(), let frame = first else { throw PairingTransportError.closed }
            return frame
        }
    }

    /// "Les codes sont identiques" for a personal or shared device: fresh presence (or `password`),
    /// then, once the new device confirmed, the grant. With a sync server this device syncs first and
    /// seals the server's view (refused when the account is not on the server yet); without one, its
    /// full local view (ruling A10). The device list it signs is sent to the server after.
    public func approve(mode: FfiDeviceMode, password: SecretBytes? = nil) async {
        guard !approving, case .comparing(_, _, let requested) = state, let approver, mode != .public,
            mode == requested
        else { return }
        // Set before the first await: a second tap, or a cancel meanwhile, is seen at once (M1, L1).
        approving = true
        defer { approving = false }
        guard await presenceConfirmed(password: password), isComparing, transport != nil else { return }
        guard await waitForPeer(), state == .waitingForPeer || isComparing, transport != nil else { return }
        state = .granting
        let sync = vault.environment.sync
        let hasServer = sync.syncsWithServer
        if hasServer { await sync.syncNow() }
        // `cancel()` is ignored while granting, but the connection may have closed meanwhile.
        guard state == .granting, let transport else {
            if state == .granting { fail(.connectionLost) }
            return
        }
        do {
            let secretKey = try vault.loadSecretKey()
            defer { secretKey.secretKey.wipe() }
            let key = secretKey.secretKey
            let frame = try await vault.readUnmapped { session in
                guard let text = key.string() else { throw VaultError.passwordRequired }
                return try approver.sealFullGrant(session: session, secretKey: text, mode: mode, includePending: !hasServer)
            }
            try await transport.send(frame)
        } catch {
            fail(PairingFailure(error))
            // A grant sealed but not sent still listed the device: the list is refreshed.
            try? await vault.refreshDevices()
            return
        }
        // The device list changed: tell the sync layer, and push it now when there is a server.
        vault.notifySync { await $0.localChangesWritten() }
        if hasServer { await sync.syncNow() }
        try? await vault.refreshDevices()
        // The new device acknowledges, then closes: the receiver cleans up then.
        if state == .granting { state = .done }
    }

    /// `approve(mode:password:)` with a typed `String` password (tests).
    public func approve(mode: FfiDeviceMode, password: String) async {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        await approve(mode: mode, password: bytes)
    }

    /// Public request: lends `items` read only for `minutes` (1 to 60, 15 by default), after fresh
    /// presence (or `password`) and the new device's confirmation. Then the journal fills in.
    public func approvePublic(items: [FfiItemRef], minutes: UInt32 = 15, password: SecretBytes? = nil) async {
        guard !approving, case .comparing(_, _, .public) = state, let approver else { return }
        approving = true
        defer { approving = false }
        guard await presenceConfirmed(password: password), isComparing, transport != nil else { return }
        guard await waitForPeer(), state == .waitingForPeer || isComparing, let transport else { return }
        state = .granting
        do {
            let frame = try await vault.readUnmapped { session in
                try approver.sealPublicGrant(session: session, items: items, minutes: minutes)
            }
            try await transport.send(frame)
        } catch {
            fail(PairingFailure(error))
            return
        }
        guard state == .granting else { return }
        let expires = vault.environment.clock.now.addingTimeInterval(TimeInterval(minutes) * 60)
        publicExpiresAt = expires
        remaining = TimeInterval(minutes) * 60
        state = .publicRunning(journal: journal, expiresAt: expires)
        startTicker()
    }

    /// `approvePublic(items:minutes:password:)` with a typed `String` password (tests).
    public func approvePublic(items: [FfiItemRef], minutes: UInt32 = 15, password: String) async {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        await approvePublic(items: items, minutes: minutes, password: bytes)
    }

    /// "Terminer la session": tells the new device, then closes.
    public func endPublicSession() async {
        guard case .publicRunning = state, let approver, let transport else { return }
        if let frame = try? await CoreThread.run({ try approver.sealEnd() }) {
            try? await transport.send(frame)
        }
        finish()
    }

    /// Stops before the grant ("Ils sont différents", or leaving the screen): nothing is granted.
    /// Ignored while the grant is being built and sent (`granting`): it may already be out.
    public func cancel() {
        switch state {
        case .done, .failed, .granting: return
        case .publicRunning:
            Task { await endPublicSession() }
            return
        default: break
        }
        fail(.codeRejected)
    }

    // MARK: - Steps

    private var isComparing: Bool {
        if case .comparing = state { true } else { false }
    }

    private func presenceConfirmed(password: SecretBytes?) async -> Bool {
        approvalError = nil
        do {
            try await vault.confirmPresence(password: password, prompt: VaultSession.approvePrompt)
            return true
        } catch {
            // A refusal keeps the comparison open, unless the pairing stopped meanwhile.
            if isComparing { approvalError = VaultError(error) }
            return false
        }
    }

    /// The new device's confirmation, at most `peerTimeout` after presence passed (L5): a fresh
    /// presence must not stay valid while nobody answers. Then the pairing fails.
    private func waitForPeer() async -> Bool {
        if peerConfirmed { return true }
        state = .waitingForPeer
        let timeout = peerTimeout
        let timer = Task { [weak self] in
            try? await Task.sleep(for: timeout)
            guard !Task.isCancelled, let self, self.state == .waitingForPeer else { return }
            self.fail(.peerTimedOut)
        }
        defer { timer.cancel() }
        return await withCheckedContinuation { peerWaiters.append($0) }
    }

    private func startReceiving(approver: PairingApprover, transport: any PairingTransport) {
        receiver = Task { [weak self] in
            while true {
                let message: FfiPairingMessage
                do {
                    let frame = try await transport.receive()
                    message = try await CoreThread.run { try approver.onFrame(frame: frame) }
                } catch is CancellationError {
                    return
                } catch {
                    self?.peerGone(PairingFailure(error))
                    return
                }
                guard let self else { return }
                self.handle(message)
            }
        }
    }

    private func handle(_ message: FfiPairingMessage) {
        switch message {
        case .confirmed:
            peerConfirmed = true
            let waiters = peerWaiters
            peerWaiters = []
            for w in waiters { w.resume(returning: true) }
        case .ack:
            acked = true
        case .audit(let at, let itemID, let action):
            let title = vault.summaries.first { $0.id == itemID }?.title ?? ""
            // What the guest sends is bounded (L3): a cut label, the last entries only.
            let bounded: FfiAuditAction =
                switch action {
                case .copied(let label): .copied(label: String(label.prefix(Self.maxAuditLabelLength)))
                default: action
                }
            journal.append(
                PairingAuditEntry(
                    id: nextAuditID, at: Date(timeIntervalSince1970: TimeInterval(at)), itemID: itemID,
                    title: title, action: bounded))
            nextAuditID += 1
            if journal.count > Self.maxJournalEntries { journal.removeFirst(journal.count - Self.maxJournalEntries) }
            if case .publicRunning(_, let expires) = state { state = .publicRunning(journal: journal, expiresAt: expires) }
        case .end:
            if case .publicRunning = state { finish() } else { peerGone(.cancelledByPeer) }
        case .fullGrant, .publicGrant:
            // Never sent to an approver.
            peerGone(.refused)
        }
    }

    /// The new device left or the connection closed. A running public session simply ends there.
    private func peerGone(_ failure: PairingFailure) {
        switch state {
        case .publicRunning, .done: finish()
        case .granting:
            // The grant may already be out; the result decides.
            break
        case .failed:
            // Already stopped (the codes differed, a refusal): the first reason stays.
            break
        default: fail(failure)
        }
    }

    private func startTicker() {
        ticker?.cancel()
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, case .publicRunning = self.state else { return }
                self.tick()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// Re-reads the clock for a running public session; at expiry the session ends (the new device
    /// ends it on its side too). Tests call it after moving the clock.
    public func tick() {
        guard case .publicRunning = state, let publicExpiresAt else { return }
        remaining = max(0, publicExpiresAt.timeIntervalSince(vault.environment.clock.now))
        if remaining <= 0 { finish() }
    }

    private func finish() {
        if state == .done, transport == nil { return }
        stopHosting()
        receiver?.cancel()
        ticker?.cancel()
        transport?.close()
        transport = nil
        resumeWaiters(false)
        remaining = 0
        state = .done
    }

    /// Spends the codes and withdraws the services (idempotent).
    private func stopHosting() {
        hostTask?.cancel()
        hostTask = nil
        host?.close()
    }

    private func fail(_ failure: PairingFailure) {
        stopHosting()
        receiver?.cancel()
        ticker?.cancel()
        transport?.close()
        transport = nil
        resumeWaiters(false)
        state = .failed(failure)
    }

    private func resumeWaiters(_ value: Bool) {
        let waiters = peerWaiters
        peerWaiters = []
        for w in waiters { w.resume(returning: value) }
    }
}
