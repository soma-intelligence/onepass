import Foundation

/// One pairing connection, carrying opaque frames (spec 2b 5.5). The end-to-end encryption lives in
/// the core: a transport only moves bytes, in order, and says when the other side is gone.
public protocol PairingTransport: Sendable {
    /// Sends one frame. Throws `PairingTransportError.closed` once either side closed.
    func send(_ frame: Data) async throws
    /// The next frame from the other side, at most `maxBytes` long: a longer one closes the connection
    /// and throws `PairingTransportError.frameTooLarge` (before its body is read, on a network).
    /// Throws `PairingTransportError.closed` when the connection ends, and `CancellationError` when
    /// the calling task is cancelled.
    func receive(maxBytes: Int) async throws -> Data
    /// Closes the connection (both directions). A pending `receive` on either side ends.
    func close()
}

extension PairingTransport {
    /// The next frame, up to `PairingFrame.maxBytes` (after the key exchange).
    public func receive() async throws -> Data {
        try await receive(maxBytes: PairingFrame.maxBytes)
    }
}

/// The new device's side: publishes the pairing service and hands over the approvers that connect.
public protocol PairingListener: Sendable {
    /// Publishes `serviceName` (the session id in hex) and yields every connection, until the
    /// consumer stops iterating (or the stream is dropped): the service is withdrawn then. A
    /// connection is not authenticated yet: the flow checks its Hello and key exchange, and keeps
    /// listening meanwhile (M2). Connections never handed over are closed.
    func connections(serviceName: String) -> AsyncThrowingStream<any PairingTransport, any Error>
}

extension PairingListener {
    /// The first connection to `serviceName`; the service is withdrawn once it arrives. Cancelling
    /// the calling task withdraws it and throws `CancellationError`.
    public func listen(serviceName: String) async throws -> any PairingTransport {
        for try await connection in connections(serviceName: serviceName) { return connection }
        try Task.checkCancellation()
        throw PairingTransportError.closed
    }
}

/// The approver's side: finds the service named in the scanned QR and connects to it.
public protocol PairingConnector: Sendable {
    func connect(serviceName: String) async throws -> any PairingTransport
}

public enum PairingTransportError: Error, Equatable, Sendable {
    /// The connection ended (closed by either side, or lost).
    case closed
    /// A frame above `PairingFrame.maxBytes`: the connection is closed.
    case frameTooLarge
    /// No device published this service in time.
    case notFound
}

public enum PairingFrame {
    /// Largest frame accepted on any transport (64 MiB; a snapshot is 50 MiB at most).
    public static let maxBytes = 64 << 20
    /// Largest frame accepted before the key exchange is validated (the Hello, the key exchange):
    /// nothing is authenticated yet (M2).
    public static let maxHandshakeBytes = 16 << 10
}
