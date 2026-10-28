import Foundation
import Network
import Synchronization

/// Pairing over the local network, without a server (spec 2b 5.5): the new device publishes a Bonjour
/// service `_onepass-pair._tcp` named by the session id in hex, the approver finds it by the session id
/// of the scanned QR and connects over TCP. Peer-to-peer links are allowed (`includePeerToPeer`: Wi-Fi
/// or AWDL when the two devices are close). Frames carry a 4-byte big-endian length prefix and are
/// refused above the reader's cap (64 MiB, 16 KiB before the key exchange) before their body is
/// read. Closing cancels the connection.
public final class LocalNetworkPairingTransport: PairingTransport, @unchecked Sendable {
    public static let serviceType = "_onepass-pair._tcp"

    private let connection: NWConnection
    private let queue: DispatchQueue

    init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    static func parameters() -> NWParameters {
        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = true
        return parameters
    }

    public func send(_ frame: Data) async throws {
        guard frame.count <= PairingFrame.maxBytes else {
            close()
            throw PairingTransportError.frameTooLarge
        }
        var length = UInt32(frame.count).bigEndian
        var packet = Data(bytes: &length, count: 4)
        packet.append(frame)
        let connection = connection
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
            connection.send(
                content: packet,
                completion: .contentProcessed { error in
                    if error != nil { c.resume(throwing: PairingTransportError.closed) } else { c.resume() }
                })
        }
    }

    public func receive(maxBytes: Int) async throws -> Data {
        let header = try await read(count: 4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length <= min(maxBytes, PairingFrame.maxBytes) else {
            close()
            throw PairingTransportError.frameTooLarge
        }
        return length == 0 ? Data() : try await read(count: length)
    }

    public func close() {
        connection.cancel()
    }

    /// Exactly `count` bytes, or `closed`. Cancelling the task cancels the connection and throws
    /// `CancellationError` (the `PairingTransport` contract): the flows tell their own stop from the
    /// other device leaving by that.
    private func read(count: Int) async throws -> Data {
        let connection = connection
        let cancelled = Atomic<Bool>(false)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, any Error>) in
                connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                    if let data, data.count == count, error == nil {
                        c.resume(returning: data)
                    } else if cancelled.load(ordering: .acquiring) {
                        c.resume(throwing: CancellationError())
                    } else {
                        c.resume(throwing: PairingTransportError.closed)
                    }
                }
            }
        } onCancel: {
            cancelled.store(true, ordering: .releasing)
            connection.cancel()
        }
    }

    /// Waits until `connection` is ready (`notFound` after `timeout`, `closed` if it fails).
    static func start(_ connection: NWConnection, queue: DispatchQueue, timeout: Duration?) async throws
        -> LocalNetworkPairingTransport
    {
        let once = Mutex<CheckedContinuation<Void, any Error>?>(nil)
        let finish: @Sendable (Result<Void, any Error>) -> Void = { result in
            once.withLock { c in
                c?.resume(with: result)
                c = nil
            }
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, any Error>) in
                once.withLock { $0 = c }
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: finish(.success(()))
                    case .failed, .cancelled: finish(.failure(PairingTransportError.closed))
                    default: break
                    }
                }
                connection.start(queue: queue)
                if let timeout {
                    queue.asyncAfter(deadline: .now() + timeout.timeInterval) {
                        guard once.withLock({ $0 != nil }) else { return }
                        connection.cancel()
                        finish(.failure(PairingTransportError.notFound))
                    }
                }
            }
        } onCancel: {
            connection.cancel()
            finish(.failure(CancellationError()))
        }
        // Later failures surface through `send` and `receive`.
        connection.stateUpdateHandler = nil
        return LocalNetworkPairingTransport(connection: connection, queue: queue)
    }
}

/// The new device's side: a Bonjour listener that stays published while the flow checks the
/// connections it hands over (M2: a silent or hostile first connection does not take the service
/// away from the approver). The service is withdrawn when the consumer stops.
public struct LocalNetworkPairingListener: PairingListener {
    /// How long a new connection may take to become ready.
    static let readyTimeout: Duration = .seconds(15)

    public init() {}

    public func connections(serviceName: String) -> AsyncThrowingStream<any PairingTransport, any Error> {
        let (stream, continuation) = AsyncThrowingStream<any PairingTransport, any Error>.makeStream(
            bufferingPolicy: .bufferingNewest(4))
        let queue = DispatchQueue(label: "me.somalabs.onepass.pairing.listener")
        let listener: NWListener
        do {
            listener = try NWListener(using: LocalNetworkPairingTransport.parameters())
        } catch {
            continuation.finish(throwing: error)
            return stream
        }
        listener.service = NWListener.Service(name: serviceName, type: LocalNetworkPairingTransport.serviceType)
        /// Connections accepted but not ready yet, cancelled when the stream ends.
        let starting = Mutex<(ended: Bool, connections: [ObjectIdentifier: NWConnection])>((false, [:]))
        listener.newConnectionHandler = { connection in
            let id = ObjectIdentifier(connection)
            let accepted = starting.withLock { s -> Bool in
                guard !s.ended else { return false }
                s.connections[id] = connection
                return true
            }
            guard accepted else {
                connection.cancel()
                return
            }
            Task {
                let transport = try? await LocalNetworkPairingTransport.start(
                    connection, queue: queue, timeout: Self.readyTimeout)
                starting.withLock { _ = $0.connections.removeValue(forKey: id) }
                guard let transport else { return }
                switch continuation.yield(transport) {
                case .enqueued: break
                case .dropped(let older): older.close()
                case .terminated: transport.close()
                @unknown default: transport.close()
                }
            }
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .failed: continuation.finish(throwing: PairingTransportError.closed)
            case .cancelled: continuation.finish()
            default: break
            }
        }
        continuation.onTermination = { _ in
            listener.cancel()
            let pending = starting.withLock { s -> [NWConnection] in
                s.ended = true
                defer { s.connections = [:] }
                return Array(s.connections.values)
            }
            for connection in pending { connection.cancel() }
        }
        listener.start(queue: queue)
        return stream
    }
}

/// The approver's side: connects to the Bonjour service named in the QR.
public struct LocalNetworkPairingConnector: PairingConnector {
    /// How long the service may take to appear before "Rapproche les deux appareils".
    public var timeout: Duration

    public init(timeout: Duration = .seconds(20)) {
        self.timeout = timeout
    }

    public func connect(serviceName: String) async throws -> any PairingTransport {
        let queue = DispatchQueue(label: "me.somalabs.onepass.pairing.connector")
        let endpoint = NWEndpoint.service(
            name: serviceName, type: LocalNetworkPairingTransport.serviceType, domain: "local.", interface: nil)
        let connection = NWConnection(to: endpoint, using: LocalNetworkPairingTransport.parameters())
        return try await LocalNetworkPairingTransport.start(connection, queue: queue, timeout: timeout)
    }
}

extension Duration {
    var timeInterval: TimeInterval {
        let (seconds, attoseconds) = components
        return TimeInterval(seconds) + TimeInterval(attoseconds) / 1e18
    }
}
