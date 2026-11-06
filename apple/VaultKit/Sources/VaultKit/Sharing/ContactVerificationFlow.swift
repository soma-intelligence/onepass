import Foundation
import os

/// This device's keys for the proofs of possession a contact card carries: the classical half the
/// app keeps in its Keychain and the post-quantum half (Secure Enclave on a device).
public struct DeviceKeyPair: @unchecked Sendable {
    public let classical: Data
    public let pq: any FfiPqDeviceHalf

    public init(classical: Data, pq: any FfiPqDeviceHalf) {
        self.classical = classical
        self.pq = pq
    }
}

/// Where the flows get this device's keys. A failure (a locked Secure Enclave key) sends nothing.
public protocol DeviceKeySource: Sendable {
    func deviceKeys() throws -> DeviceKeyPair
}

/// The contact verification in person (sharing spec 5.3.1), on one device: either side shows the QR
/// (`showCode`) or scans the other's (`scan`), both compare the same code and confirm it, the cards
/// cross, then the side the core names makes the pair's mailbox and sends its offer (decision 16).
/// Nothing is pinned before the offer exists; a mismatch or a failure pins nothing.
///
/// Frames: the shower sends its Hello, the scanner its KeyExchange, then the shower's card, the
/// scanner's card and the creator's zone offer, over the `_onepass-contact._tcp` service.
@MainActor
public final class ContactVerificationFlow: ObservableObject {
    public enum State: Equatable, Sendable {
        case idle
        /// Show `qrText` for the other device to scan.
        case showingQR(qrText: String)
        /// Waiting for the other device after a scan.
        case scanning
        /// Both screens show `sas`: the user compares and confirms.
        case comparing(sas: String)
        /// Cards and the pair's mailbox are being exchanged.
        case exchanging
        case done(FfiContact)
        case failed(PairingFailure)
    }

    @Published public private(set) var state: State = .idle

    private let session: Session
    private let myName: String
    private let keys: any DeviceKeySource
    private let listener: any PairingListener
    private let connector: any PairingConnector
    private let creator: any ContactZoneCreating
    private let now: @Sendable () -> Date

    private var transport: (any PairingTransport)?
    private var responder: FfiContactResponder?
    private var initiator: FfiContactInitiator?
    private var task: Task<Void, Never>?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "contact-verification")

    /// `listener` and `connector`: the `_onepass-contact._tcp` service (never the pairing one).
    public init(
        session: Session, myName: String, keys: any DeviceKeySource,
        listener: any PairingListener = LocalNetworkPairingListener(serviceType: LocalNetworkPairingTransport.contactServiceType),
        connector: any PairingConnector = LocalNetworkPairingConnector(serviceType: LocalNetworkPairingTransport.contactServiceType),
        creator: any ContactZoneCreating,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.session = session
        self.myName = myName
        self.keys = keys
        self.listener = listener
        self.connector = connector
        self.creator = creator
        self.now = now
    }

    private var stamp: Int64 { Int64(now().timeIntervalSince1970) }

    // MARK: - Shower

    /// Shows a QR and waits for the other device.
    public func showCode() {
        task?.cancel()
        task = Task { await self.runShower() }
    }

    private func runShower() async {
        do {
            let t = stamp
            let start = try await CoreThread.run { try contactResponderStart(now: t) }
            responder = start.responder
            state = .showingQR(qrText: start.qr)
            let service = try pairingServiceName(qrText: start.qr)
            let transport = try await listener.listen(serviceName: service)
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

    // MARK: - Scanner

    /// The user scanned the other device's QR.
    public func scan(qrText: String) {
        task?.cancel()
        task = Task { await self.runScanner(qrText: qrText) }
    }

    private func runScanner(qrText: String) async {
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

    // MARK: - Comparison

    /// The user says both screens show the same code.
    public func confirm() {
        guard case .comparing = state else { return }
        task = Task { await self.exchange() }
    }

    /// The user says the codes differ: the session ends, nothing is sent or pinned.
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

    private func exchange() async {
        guard let transport else { return fail(PairingTransportError.closed) }
        state = .exchanging
        let (session, name, t) = (session, myName, stamp)
        do {
            let pair = try keys.deviceKeys()
            let peer: FfiVerifiedPeer
            if let r = responder {
                let mine = try await CoreThread.run {
                    try r.confirmAndSendCard(session: session, myName: name, classical: pair.classical, pq: pair.pq, now: t)
                }
                try await transport.send(mine)
                let theirs = try await transport.receive()
                guard case .peerCard(let p) = try await CoreThread.run({ try r.onFrame(frame: theirs, now: t) }) else {
                    throw PairingFailure.refused
                }
                peer = p
            } else if let i = initiator {
                // The scanner reads the shower's card first; its peer is verified once its own card
                // is sent (the core's order).
                let theirs = try await transport.receive()
                _ = try await CoreThread.run { try i.onFrame(frame: theirs, now: t) }
                let mine = try await CoreThread.run {
                    try i.confirmAndSendCard(session: session, myName: name, classical: pair.classical, pq: pair.pq, now: t)
                }
                try await transport.send(mine)
                guard let p = i.verifiedPeer() else { throw PairingFailure.refused }
                peer = p
            } else {
                throw PairingFailure.refused
            }
            let contact = try await finish(peer: peer, transport: transport, now: t)
            transport.close()
            clear()
            state = .done(contact)
        } catch {
            fail(error)
        }
    }

    /// Decision 16: the creator makes the pair's mailbox and sends the offer, then pins; the other
    /// side pins with the offer it got.
    private func finish(peer: FfiVerifiedPeer, transport: any PairingTransport, now t: Int64) async throws -> FfiContact {
        let session = session
        let creates = try await CoreThread.run { try session.createsContactZone(peer: peer) }
        if creates {
            do {
                return try await ContactZoneStep.offerThenPin(creator: creator, peerCard: peer.card(), session: session) { offer in
                    let frame = try await self.sendZoneOffer(offer, now: t)
                    try await transport.send(frame)
                    return try await CoreThread.run { try session.finishContactSession(peer: peer, zoneOffer: nil, now: t) }
                }
            } catch ContactZoneError.offline {
                throw PairingFailure.other(ContactZoneError.offline.message(name: peer.name()))
            }
        }
        let frame = try await transport.receive()
        let outcome = try await onFrame(frame, now: t)
        guard case .peerZoneOffer(let offer) = outcome else { throw PairingFailure.refused }
        return try await CoreThread.run { try session.finishContactSession(peer: peer, zoneOffer: offer, now: t) }
    }

    private func sendZoneOffer(_ offer: Data, now t: Int64) async throws -> Data {
        if let r = responder { return try await CoreThread.run { try r.sendZoneOffer(offer: offer, now: t) } }
        if let i = initiator { return try await CoreThread.run { try i.sendZoneOffer(offer: offer, now: t) } }
        throw PairingFailure.refused
    }

    private func onFrame(_ frame: Data, now t: Int64) async throws -> FfiContactOutcome {
        if let r = responder { return try await CoreThread.run { try r.onFrame(frame: frame, now: t) } }
        if let i = initiator { return try await CoreThread.run { try i.onFrame(frame: frame, now: t) } }
        throw PairingFailure.refused
    }

    private func clear() {
        transport = nil
        responder = nil
        initiator = nil
    }

    private func fail(_ error: any Error) {
        if error is CancellationError { return }
        transport?.close()
        clear()
        let failure: PairingFailure
        switch error {
        case let f as PairingFailure: failure = f
        case PairingTransportError.notFound: failure = .notFound
        case PairingTransportError.closed: failure = .connectionLost
        case OnePassError.Integrity, OnePassError.InvalidInput, OnePassError.Crypto: failure = .refused
        default: failure = .other(VaultError(error).localizedMessage)
        }
        Self.log.notice("contact verification stopped")
        state = .failed(failure)
    }
}
