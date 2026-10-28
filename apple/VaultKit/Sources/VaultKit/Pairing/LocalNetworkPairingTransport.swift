import Foundation
import Network
import Synchronization

/// Pairing over the local network, without a server (spec 2b 5.5): the new device publishes a Bonjour
/// service `_onepass-pair._tcp` named by the session id in hex, the approver finds it by the session id
/// of the scanned QR and connects over TCP. Peer-to-peer links are allowed (`includePeerToPeer`: Wi-Fi
/// or AWDL when the two devices are close). Frames carry a 4-byte big-endian length prefix and are
/// refused above 64 MiB. One connection per session; closing cancels it.
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

    public func receive() async throws -> Data {
        let header = try await read(count: 4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length <= PairingFrame.maxBytes else {
            close()
            throw PairingTransportError.frameTooLarge
        }
        return length == 0 ? Data() : try await read(count: length)
    }

    public func close() {
        connection.cancel()
    }

    /// Exactly `count` bytes, or `closed`. Cancelling the task cancels the connection.
    private func read(count: Int) async throws -> Data {
        let connection = connection
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, any Error>) in
                connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                    if let data, data.count == count, error == nil {
                        c.resume(returning: data)
                    } else {
                        c.resume(throwing: PairingTransportError.closed)
                    }
                }
            }
        } onCancel: {
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

/// The new device's side: a Bonjour listener that keeps the first connection and refuses the others.
public struct LocalNetworkPairingListener: PairingListener {
    public init() {}

    public func listen(serviceName: String) async throws -> any PairingTransport {
        let queue = DispatchQueue(label: "me.somalabs.onepass.pairing.listener")
        let listener = try NWListener(using: LocalNetworkPairingTransport.parameters())
        listener.service = NWListener.Service(name: serviceName, type: LocalNetworkPairingTransport.serviceType)
        let once = Mutex<CheckedContinuation<NWConnection, any Error>?>(nil)
        let finish: @Sendable (Result<NWConnection, any Error>) -> Void = { result in
            let c = once.withLock { c -> CheckedContinuation<NWConnection, any Error>? in
                defer { c = nil }
                return c
            }
            if let c {
                c.resume(with: result)
            } else if case .success(let late) = result {
                late.cancel()
            }
        }
        let connection = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<NWConnection, any Error>) in
                once.withLock { $0 = c }
                listener.newConnectionHandler = { connection in
                    // One connection only: the service goes away with the first one.
                    listener.cancel()
                    finish(.success(connection))
                }
                listener.stateUpdateHandler = { state in
                    switch state {
                    case .failed, .cancelled: finish(.failure(PairingTransportError.closed))
                    default: break
                    }
                }
                listener.start(queue: queue)
            }
        } onCancel: {
            listener.cancel()
            finish(.failure(CancellationError()))
        }
        listener.newConnectionHandler = nil
        listener.stateUpdateHandler = nil
        return try await LocalNetworkPairingTransport.start(connection, queue: queue, timeout: .seconds(15))
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
