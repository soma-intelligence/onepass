import Foundation
import Observation
import os

/// The new device's side of a pairing (spec 2b 5.1, ruling A1: the new device shows the QR, the
/// unlocked device scans it). While no approver connects, the QR is renewed every 30 s (new session,
/// new key, new service). Then: Hello, KeyExchange, the 6-digit code on both screens, the user's
/// confirmation (`confirmCode`), the approver's grant. A full grant ends with `importAndUnlock`; a
/// public one hands over a `PublicSession`.
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
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.vault = vault
        self.mode = mode
        self.listener = listener
        self.deviceName = String((deviceName ?? VaultSession.currentDeviceName()).prefix(VaultSession.maxDeviceNameLength))
        self.deviceKind = deviceKind ?? VaultSession.currentDeviceKind
        self.renewEvery = renewEvery
        self.now = now
    }

    isolated deinit {
        run?.cancel()
        transport?.close()
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

    /// Stops the pairing. After the code exchange, the approver is told (`End`).
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
    /// another try. The caller wipes `password`.
    public func importAndUnlock(password: SecretBytes) async {
        guard state == .receivedFull, let newcomer, let mode = grantedMode else { return }
        state = .importing
        importError = nil
        do {
            try await vault.importPaired(newcomer, password: password, mode: mode)
            state = .done
            close()
        } catch {
            importError = VaultError(error)
            state = .receivedFull
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
        let connection: (newcomer: PairingNewcomer, transport: any PairingTransport)
        do {
            connection = try await waitForApprover()
        } catch is CancellationError {
            return
        } catch {
            stop(.failed(PairingFailure(error)))
            return
        }
        newcomer = connection.newcomer
        transport = connection.transport
        let (newcomer, transport) = connection
        let nowUnix = Int64(now().timeIntervalSince1970)
        do {
            try await transport.send(newcomer.hello())
            let exchange = try await transport.receive()
            let sas = try await CoreThread.run { try newcomer.onKeyExchange(bytes: exchange, now: nowUnix) }
            guard !Task.isCancelled else { return }
            state = .comparing(sas: sas)
        } catch is CancellationError {
            return
        } catch {
            stop(.failed(PairingFailure(error)))
            return
        }
        await receiveGrant(newcomer: newcomer, transport: transport)
    }

    /// Publishes a QR, renewed every `renewEvery` until an approver connects.
    private func waitForApprover() async throws -> (PairingNewcomer, any PairingTransport) {
        let listener = listener
        while true {
            try Task.checkCancellation()
            let nowUnix = Int64(now().timeIntervalSince1970)
            let (name, kind, mode) = (deviceName, deviceKind, mode)
            let newcomer = try await CoreThread.run {
                try PairingNewcomer(name: name, kind: kind, mode: mode, now: nowUnix)
            }
            state = .showingCode(
                qrText: newcomer.qrText(), expiresAt: Date(timeIntervalSince1970: TimeInterval(newcomer.expiresAt())))
            let service = newcomer.serviceName()
            let renew = renewEvery
            let connected: (any PairingTransport)? = try await withThrowingTaskGroup(
                of: (any PairingTransport)?.self
            ) { group in
                group.addTask { try await listener.listen(serviceName: service) }
                group.addTask {
                    try await Task.sleep(for: renew)
                    return nil
                }
                defer { group.cancelAll() }
                return try await group.next() ?? nil
            }
            if let connected { return (newcomer, connected) }
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
        run?.cancel()
        run = nil
        close()
        state = final
    }

    private func close() {
        transport?.close()
        transport = nil
    }
}
