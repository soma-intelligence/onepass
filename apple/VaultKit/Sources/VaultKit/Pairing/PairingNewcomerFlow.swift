import Foundation
import Observation
import os
import Synchronization

/// The new device's side of a pairing (spec 2b 5.1, ruling A1: the new device shows the QR, the
/// unlocked device scans it). While no approver completed the key exchange, the QR is renewed every
/// 30 s (new session, new key, new service). The service stays published while connections are
/// checked (M2): each one gets the Hello and must answer a key exchange of at most 16 KiB within
/// `handshakeTimeout` (and before the QR expires), else it is closed; a key exchange the core refuses
/// ends that QR and a new one is published. Then: the 6-digit code on both screens, the user's
/// confirmation (`confirmCode`), the approver's grant. A full grant ends with `importAndUnlock`; a
/// public one hands over a `PublicSession`. A full grant waits at most `grantLifetime` without an
/// attempt and `maxImportAttempts` wrong passwords, then it is dropped (M3).
@MainActor
@Observable
public final class PairingNewcomerFlow {
    public enum State: Equatable {
        case idle
        /// Show `qrText` as a QR code until `expiresAt` (a new one replaces it before).
        case showingCode(qrText: String, expiresAt: Date)
        /// Compare `sas` with the approver's screen.
        case comparing(sas: String)
        /// Confirmed here; the approver confirms and grants.
        case waitingForApproval
        /// The account arrived: ask the master password, then `importAndUnlock`.
        case receivedFull
        /// The snapshot is being imported and unlocked.
        case importing
        /// Unlocked: the session is open.
        case done
        /// A guest session runs.
        case receivedPublic(PublicSession)
        case cancelled
        case failed(PairingFailure)

        public static func == (a: State, b: State) -> Bool {
            switch (a, b) {
            case (.idle, .idle), (.waitingForApproval, .waitingForApproval), (.receivedFull, .receivedFull),
                (.importing, .importing), (.done, .done), (.cancelled, .cancelled):
                true
            case (.showingCode(let q1, let e1), .showingCode(let q2, let e2)): q1 == q2 && e1 == e2
            case (.comparing(let a), .comparing(let b)): a == b
            case (.receivedPublic(let a), .receivedPublic(let b)): a === b
            case (.failed(let a), .failed(let b)): a == b
            default: false
            }
        }
    }

    public static let renewInterval: Duration = .seconds(30)
    /// How long a connection has to send its key exchange after the Hello (M2).
    public static let handshakeTimeout: Duration = .seconds(10)
    /// Connections checked at the same time; more are closed at once (M2).
    static let maxPendingHandshakes = 4
    /// Wrong master passwords before the received account is dropped: the count at which the
    /// unlock lockout starts (M3).
    public static let maxImportAttempts = VaultSession.lockoutThreshold
    /// How long a received account waits for the master password without an attempt (M3).
    public static let grantLifetime: Duration = .seconds(300)

    public private(set) var state: State = .idle
    /// The mode asked for (first question of "J'ai déjà OnePass sur un autre appareil").
    public let mode: FfiDeviceMode
    /// The last error of `importAndUnlock` (wrong password), the grant stays for a retry.
    public private(set) var importError: VaultError?

    @ObservationIgnored private let vault: VaultSession
    @ObservationIgnored private let listener: any PairingListener
    @ObservationIgnored private let deviceName: String
    @ObservationIgnored private let deviceKind: FfiDeviceKind
    @ObservationIgnored private let renewEvery: Duration
    @ObservationIgnored private let handshakeTimeout: Duration
    @ObservationIgnored private let grantLifetime: Duration
    @ObservationIgnored private var failedImports = 0
    @ObservationIgnored private var grantTimer: Task<Void, Never>?
    @ObservationIgnored private let now: @Sendable () -> Date
    @ObservationIgnored private var newcomer: PairingNewcomer?
    @ObservationIgnored private var transport: (any PairingTransport)?
    @ObservationIgnored private var run: Task<Void, Never>?
    @ObservationIgnored private var grantedMode: DeviceMode?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "pairing")

    /// `vault` is the session the account lands in (it must have no account); `listener` publishes the
    /// pairing service (`LocalNetworkPairingListener` in the apps). Name and type default to this
    /// device's.
    public init(
        vault: VaultSession, mode: FfiDeviceMode, listener: any PairingListener,
        deviceName: String? = nil, deviceKind: FfiDeviceKind? = nil,
        renewEvery: Duration = PairingNewcomerFlow.renewInterval,
        handshakeTimeout: Duration = PairingNewcomerFlow.handshakeTimeout,
        grantLifetime: Duration = PairingNewcomerFlow.grantLifetime,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.vault = vault
        self.mode = mode
        self.listener = listener
        self.deviceName = String((deviceName ?? VaultSession.currentDeviceName()).prefix(VaultSession.maxDeviceNameLength))
        self.deviceKind = deviceKind ?? VaultSession.currentDeviceKind
        self.renewEvery = renewEvery
        self.handshakeTimeout = handshakeTimeout
        self.grantLifetime = grantLifetime
        self.now = now
    }

    isolated deinit {
        run?.cancel()
        grantTimer?.cancel()
        transport?.close()
        if case .receivedFull = state { newcomer?.discardGrant() }
    }

    /// Shows a first QR and waits for the approver.
    public func start() {
        guard state == .idle else { return }
        if vault.state != .noAccount, mode != .public {
            state = .failed(.accountExists)
            return
        }
        run = Task { [weak self] in await self?.pair() }
    }

    /// The user saw the same code on both screens: tells the approver.
    public func confirmCode() async {
        guard case .comparing = state, let newcomer, let transport else { return }
        do {
            let frame = try await CoreThread.run { try newcomer.confirm() }
            try await transport.send(frame)
            if case .comparing = state { state = .waitingForApproval }
        } catch {
            stop(.failed(PairingFailure(error)))
        }
    }

    /// The codes differ: nothing is sent, the connection closes.
    public func rejectCode() {
        guard case .comparing = state else { return }
        stop(.failed(.codeRejected))
    }

    /// Stops the pairing. After the code exchange, the approver is told (`End`). A received account
    /// not imported yet is dropped (leaving the screen, the app going to the background on iOS).
    public func cancel() {
        switch state {
        case .done, .receivedPublic, .cancelled, .failed: return
        default: break
        }
        if let newcomer, let transport {
            // Best effort: the core refuses an End before the key exchange, then nothing is sent.
            self.transport = nil
            Task {
                if let frame = try? await CoreThread.run({ try newcomer.sealEnd() }) {
                    try? await transport.send(frame)
                }
                transport.close()
            }
        }
        stop(.cancelled)
    }

    /// Full grant: imports the snapshot with the master password, stores the received Secret Key and
    /// unlocks `vault`. A wrong password keeps the grant (`importError`, state `receivedFull`) for
    /// another try, up to `maxImportAttempts`: then the grant is dropped (`tooManyAttempts`). Wrong
    /// passwords count toward this device's unlock lockout. The caller wipes `password`.
    public func importAndUnlock(password: SecretBytes) async {
        guard state == .receivedFull, let newcomer, let mode = grantedMode else { return }
        state = .importing
        importError = nil
        grantTimer?.cancel()
        do {
            try await vault.importPaired(newcomer, password: password, mode: mode)
            state = .done
            self.newcomer = nil
            close()
        } catch {
            let failure = VaultError(error)
            guard state == .importing else { return }
            if failure == .wrongPassword { failedImports += 1 }
            if failedImports >= Self.maxImportAttempts {
                stop(.failed(.tooManyAttempts))
                return
            }
            importError = failure
            state = .receivedFull
            startGrantTimer()
        }
    }

    /// `importAndUnlock(password:)` with a typed `String` (tests).
    public func importAndUnlock(password: String) async {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        await importAndUnlock(password: bytes)
    }

    // MARK: - Steps

    private func pair() async {
        let connection: (newcomer: PairingNewcomer, transport: any PairingTransport, sas: String)
        do {
            connection = try await waitForApprover()
        } catch is CancellationError {
            return
        } catch {
            stop(.failed(PairingFailure(error)))
            return
        }
        guard !Task.isCancelled else {
            connection.transport.close()
            return
        }
        newcomer = connection.newcomer
        transport = connection.transport
        state = .comparing(sas: connection.sas)
        await receiveGrant(newcomer: connection.newcomer, transport: connection.transport)
    }

    /// Publishes a QR until an approver's key exchange is validated, a new QR every `renewEvery`
    /// (or after a refused key exchange).
    private func waitForApprover() async throws -> (PairingNewcomer, any PairingTransport, String) {
        while true {
            try Task.checkCancellation()
            let nowUnix = Int64(now().timeIntervalSince1970)
            let (name, kind, mode) = (deviceName, deviceKind, mode)
            let newcomer = try await CoreThread.run {
                try PairingNewcomer(name: name, kind: kind, mode: mode, now: nowUnix)
            }
            if let found = try await publish(newcomer) { return found }
        }
    }

    private enum HandshakeEvent: Sendable {
        case keyExchange(id: Int, Data)
        case failed(id: Int)
        case renew
    }

    /// One QR on screen and its service published. Every connection gets the Hello and must send a
    /// key exchange (16 KiB at most) before its deadline; the first one the core accepts wins, the
    /// others are closed and the service is withdrawn. Nil: renew the QR (time, or a refused key
    /// exchange, which ends this session in the core).
    private func publish(_ newcomer: PairingNewcomer) async throws -> (PairingNewcomer, any PairingTransport, String)? {
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(newcomer.expiresAt()))
        state = .showingCode(qrText: newcomer.qrText(), expiresAt: expiresAt)
        let hello = newcomer.hello()
        let connections = listener.connections(serviceName: newcomer.serviceName())
        let (events, sink) = AsyncStream<HandshakeEvent>.makeStream()
        /// Connections of this QR not handed over yet, by id.
        let open = Mutex<[Int: any PairingTransport]>([:])
        let closeAll: @Sendable () -> Void = {
            for t in open.withLock({ o in defer { o = [:] }; return Array(o.values) }) { t.close() }
        }
        let timeout = handshakeTimeout
        let clock = self.now
        let accepting = Task {
            var next = 0
            do {
                for try await transport in connections {
                    let id = next
                    next += 1
                    let admitted = open.withLock { o -> Bool in
                        guard o.count < Self.maxPendingHandshakes else { return false }
                        o[id] = transport
                        return true
                    }
                    guard admitted else {
                        transport.close()
                        continue
                    }
                    // Never past the QR's expiry: the core refuses a late key exchange anyway.
                    let left = Duration.seconds(max(0, expiresAt.timeIntervalSince(clock())))
                    let deadline = min(timeout, left)
                    Task {
                        do {
                            let exchange = try await Self.handshake(transport, hello: hello, within: deadline)
                            sink.yield(.keyExchange(id: id, exchange))
                        } catch {
                            sink.yield(.failed(id: id))
                        }
                    }
                }
            } catch {
                // The listener stopped: the renewal publishes again.
            }
        }
        let renew = renewEvery
        let renewal = Task {
            try? await Task.sleep(for: renew)
            sink.yield(.renew)
        }
        defer {
            // Withdraws the service and closes every connection not handed over.
            accepting.cancel()
            renewal.cancel()
            sink.finish()
            closeAll()
        }
        var renewDue = false
        for await event in events {
            switch event {
            case .renew:
                // A connection being checked keeps this QR until its deadline.
                if open.withLock({ $0.isEmpty }) { return nil }
                renewDue = true
            case .failed(let id):
                open.withLock { $0.removeValue(forKey: id) }?.close()
                if renewDue, open.withLock({ $0.isEmpty }) { return nil }
            case .keyExchange(let id, let exchange):
                guard let transport = open.withLock({ $0.removeValue(forKey: id) }) else { continue }
                let nowUnix = Int64(clock().timeIntervalSince1970)
                do {
                    let sas = try await CoreThread.run { try newcomer.onKeyExchange(bytes: exchange, now: nowUnix) }
                    try Task.checkCancellation()
                    return (newcomer, transport, sas)
                } catch is CancellationError {
                    transport.close()
                    throw CancellationError()
                } catch {
                    // Refused (or late): this QR is spent in the core. A new one is published.
                    Self.log.notice("pairing key exchange refused, new code")
                    transport.close()
                    return nil
                }
            }
        }
        throw CancellationError()
    }

    /// Sends the Hello and reads the key exchange, both within `deadline`. Throws on a frame above
    /// `PairingFrame.maxHandshakeBytes`, a closed connection or the deadline; the caller closes.
    nonisolated private static func handshake(
        _ transport: any PairingTransport, hello: Data, within deadline: Duration
    ) async throws -> Data {
        try await withThrowingTaskGroup(of: Data?.self) { group in
            group.addTask {
                try await transport.send(hello)
                return try await transport.receive(maxBytes: PairingFrame.maxHandshakeBytes)
            }
            group.addTask {
                try await Task.sleep(for: deadline)
                return nil
            }
            defer { group.cancelAll() }
            guard let first = try await group.next(), let exchange = first else {
                throw PairingTransportError.closed
            }
            return exchange
        }
    }

    private func receiveGrant(newcomer: PairingNewcomer, transport: any PairingTransport) async {
        while true {
            let message: FfiPairingMessage
            do {
                let frame = try await transport.receive()
                message = try await CoreThread.run { try newcomer.open(frame: frame) }
            } catch is CancellationError {
                return
            } catch {
                stop(.failed(PairingFailure(error)))
                return
            }
            switch message {
            case .fullGrant(_, let mode, _, _):
                guard let mode = DeviceMode(mode) else {
                    stop(.failed(.refused))
                    return
                }
                grantedMode = mode
                do {
                    let ack = try await CoreThread.run { try newcomer.sealAck() }
                    try await transport.send(ack)
                } catch {
                    Self.log.notice("pairing ack not sent")
                }
                // The account is in the grant: the connection is no longer needed.
                transport.close()
                self.transport = nil
                state = .receivedFull
                startGrantTimer()
                return
            case .publicGrant(let expiresAt, let items):
                do {
                    let ack = try await CoreThread.run { try newcomer.sealAck() }
                    try await transport.send(ack)
                } catch {
                    stop(.failed(PairingFailure(error)))
                    return
                }
                let environment = vault.environment
                let session = PublicSession(
                    items: items, grantExpiresAt: expiresAt, newcomer: newcomer, transport: transport,
                    clock: environment.clock, pasteboard: environment.pasteboard)
                // The public session owns the connection from now on.
                self.transport = nil
                state = .receivedPublic(session)
                session.start()
                return
            case .end:
                stop(.failed(.cancelledByPeer))
                return
            case .confirmed, .ack, .audit:
                // Not sent to a newcomer: ignored.
                continue
            }
        }
    }

    private func stop(_ final: State) {
        // A flow that already stopped keeps its first reason (its own close reads as a lost connection).
        switch state {
        case .failed, .cancelled: return
        default: break
        }
        run?.cancel()
        run = nil
        close()
        dropGrant()
        state = final
    }

    /// The received account waits at most `grantLifetime` for the next attempt (M3).
    private func startGrantTimer() {
        grantTimer?.cancel()
        let lifetime = grantLifetime
        grantTimer = Task { [weak self] in
            try? await Task.sleep(for: lifetime)
            guard !Task.isCancelled, let self, self.state == .receivedFull else { return }
            self.stop(.failed(.grantExpired))
        }
    }

    /// Forgets a full grant not imported: the Secret Key and the snapshot leave memory (M3). On the
    /// core thread: an import holding the grant may still run.
    private func dropGrant() {
        grantTimer?.cancel()
        grantTimer = nil
        guard grantedMode != nil, let newcomer else { return }
        self.newcomer = nil
        grantedMode = nil
        Task { _ = try? await CoreThread.run { newcomer.discardGrant() } }
    }

    private func close() {
        transport?.close()
        transport = nil
    }
}
