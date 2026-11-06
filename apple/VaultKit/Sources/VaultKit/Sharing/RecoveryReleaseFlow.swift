import Foundation
import os

/// The organizer's side of an assisted recovery (sharing spec 11.5): face to face with the member's
/// new device, the organizer scans its QR, both compare the code, then the organizer's device hands
/// the share over. The core refuses before the delay is over (`recoveryStatus` is `ready`).
///
/// Frames over the `_onepass-contact._tcp` service (plan 4 ruling: the recovery handshake is the
/// contact handshake): the new device's Hello, the organizer's KeyExchange, then the share frame.
@MainActor
public final class RecoveryReleaseFlow: ObservableObject {
    public enum State: Equatable, Sendable {
        case idle
        case scanning
        /// Both screens show `sas`.
        case comparing(sas: String)
        case releasing
        case done
        case failed(PairingFailure)
    }

    @Published public private(set) var state: State = .idle

    private let session: Session
    private let member: String
    private let connector: any PairingConnector
    private let now: @Sendable () -> Date
    private var transport: (any PairingTransport)?
    private var initiator: FfiContactInitiator?
    private var task: Task<Void, Never>?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "recovery")

    /// `member`: the account to recover (an enrolled member of this organizer).
    public init(
        session: Session, member: String,
        connector: any PairingConnector = LocalNetworkPairingConnector(serviceType: LocalNetworkPairingTransport.contactServiceType),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.session = session
        self.member = member
        self.connector = connector
        self.now = now
    }

    private var stamp: Int64 { Int64(now().timeIntervalSince1970) }

    /// The organizer scanned the new device's QR.
    public func scan(qrText: String) {
        task?.cancel()
        task = Task { await self.runScan(qrText) }
    }

    private func runScan(_ qrText: String) async {
        state = .scanning
        do {
            let service = try pairingServiceName(qrText: qrText)
            let transport = try await connector.connect(serviceName: service)
            self.transport = transport
            let hello = try await transport.receive(maxBytes: PairingFrame.maxHandshakeBytes)
            let t = stamp
            let begin = try await CoreThread.run { try contactInitiatorBegin(qr: qrText, hello: hello, now: t) }
            initiator = begin.initiator
            try await transport.send(begin.keyExchange)
            state = .comparing(sas: begin.sas)
        } catch {
            fail(error)
        }
    }

    /// Both screens show the same code: the share goes to the new device.
    public func confirm() {
        guard case .comparing = state, let initiator, let transport else { return }
        state = .releasing
        let (session, member, t) = (session, member, stamp)
        task = Task {
            do {
                let frame = try await CoreThread.run {
                    try initiator.confirmSasForRecovery()
                    return try session.releaseRecoveryShare(member: member, initiator: initiator, now: t)
                }
                try await transport.send(frame)
                transport.close()
                self.clear()
                Self.log.notice("recovery share released")
                self.state = .done
            } catch {
                self.fail(error)
            }
        }
    }

    /// The codes differ: nothing is released.
    public func reject() {
        task?.cancel()
        transport?.close()
        clear()
        state = .failed(.codeRejected)
    }

    public func cancel() {
        task?.cancel()
        transport?.close()
        clear()
        state = .idle
    }

    private func clear() {
        transport = nil
        initiator = nil
    }

    private func fail(_ error: any Error) {
        if error is CancellationError { return }
        transport?.close()
        clear()
        state = .failed(RecoverWithHelpFlow.failure(error))
    }
}

/// The member's side on a new device (spec 11.5, "J'ai perdu mon mot de passe ou ma Secret Key",
/// "Demander l'aide de <organisateur>"): the device shows a QR, both compare the code, the member
/// picks a new password, the organizer's share opens the account (a rotation with reason Recover)
/// and a new Secret Key goes into a new Emergency Kit.
///
/// The store at `dbPath` holds the account's private base, fetched and not unlocked. The new Secret
/// Key waits in the Keychain (`pendingSecretKeyKey`) before the core call, so a crash in between
/// does not lose it.
@MainActor
public final class RecoverWithHelpFlow: ObservableObject {
    public enum State: Equatable, Sendable {
        case idle
        case showingQR(qrText: String)
        case comparing(sas: String)
        /// The code matched: waiting for the organizer's share.
        case waitingForOrganizer
        /// Recovered: `newSecretKey` goes into the new Emergency Kit.
        case done(newSecretKey: String)
        case failed(PairingFailure)
    }

    public static let pendingSecretKeyKey = "recovery.secretKey.pending"

    @Published public private(set) var state: State = .idle
    /// The recovered, unlocked session once `done`.
    public private(set) var session: Session?

    private let dbPath: String
    private let keychain: any KeychainStore
    private let listener: any PairingListener
    private let now: @Sendable () -> Date
    private var transport: (any PairingTransport)?
    private var responder: FfiRecoveryResponder?
    private var task: Task<Void, Never>?

    public init(
        dbPath: String, keychain: any KeychainStore,
        listener: any PairingListener = LocalNetworkPairingListener(serviceType: LocalNetworkPairingTransport.contactServiceType),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.dbPath = dbPath
        self.keychain = keychain
        self.listener = listener
        self.now = now
    }

    private var stamp: Int64 { Int64(now().timeIntervalSince1970) }

    /// Shows the QR for the organizer to scan.
    public func start() {
        task?.cancel()
        task = Task { await self.runStart() }
    }

    private func runStart() async {
        do {
            let t = stamp
            let start = try await CoreThread.run { try recoveryResponderStart(now: t) }
            responder = start.responder
            state = .showingQR(qrText: start.qr)
            let transport = try await listener.listen(serviceName: try pairingServiceName(qrText: start.qr))
            self.transport = transport
            try await transport.send(start.hello)
            let kx = try await transport.receive(maxBytes: PairingFrame.maxHandshakeBytes)
            let r = start.responder
            let sas = try await CoreThread.run { try r.onKeyExchange(kx: kx, now: t) }
            state = .comparing(sas: sas)
        } catch {
            fail(error)
        }
    }

    /// The codes match and the member chose `newPassword`. `kitSecretKey`: the Emergency Kit's
    /// Secret Key, needed only when the account syncs through a mailbox (spec 11.7).
    public func confirm(
        newPassword: String, kitSecretKey: String?, keys: any DeviceKeySource,
        deviceName: String, kind: FfiDeviceKind, mode: FfiDeviceMode
    ) {
        guard case .comparing = state, let responder, let transport else { return }
        state = .waitingForOrganizer
        let (path, keychain, t) = (dbPath, keychain, stamp)
        task = Task {
            do {
                let pair = try keys.deviceKeys()
                let frame = try await transport.receive()
                let newKey = try await CoreThread.run { try generateSecretKey() }
                try keychain.write(Self.pendingSecretKeyKey, Data(newKey.utf8))
                let session = try await CoreThread.run {
                    try responder.recover(
                        dbPath: path, frame: frame, kitSecretKey: kitSecretKey, newPassword: newPassword,
                        newSecretKey: newKey, classical: pair.classical, pq: pair.pq, deviceName: deviceName,
                        kind: kind, mode: mode, now: t)
                }
                transport.close()
                self.clear()
                self.session = session
                self.state = .done(newSecretKey: newKey)
            } catch {
                self.fail(error)
            }
        }
    }

    public func reject() {
        task?.cancel()
        transport?.close()
        clear()
        state = .failed(.codeRejected)
    }

    public func cancel() {
        task?.cancel()
        transport?.close()
        clear()
        state = .idle
    }

    private func clear() {
        transport = nil
        responder = nil
    }

    private func fail(_ error: any Error) {
        if error is CancellationError { return }
        transport?.close()
        clear()
        state = .failed(Self.failure(error))
    }

    static func failure(_ error: any Error) -> PairingFailure {
        switch error {
        case let f as PairingFailure: f
        case PairingTransportError.notFound: .notFound
        case PairingTransportError.closed: .connectionLost
        case OnePassError.Integrity, OnePassError.InvalidInput, OnePassError.Crypto: .refused
        default: .other(VaultError(error).localizedMessage)
        }
    }
}
