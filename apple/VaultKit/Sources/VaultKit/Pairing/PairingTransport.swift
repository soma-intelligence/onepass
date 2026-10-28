import Foundation

/// One pairing connection, carrying opaque frames (spec 2b 5.5). The end-to-end encryption lives in
/// the core: a transport only moves bytes, in order, and says when the other side is gone.
public protocol PairingTransport: Sendable {
    /// Sends one frame. Throws `PairingTransportError.closed` once either side closed.
    func send(_ frame: Data) async throws
    /// The next frame from the other side. Throws `PairingTransportError.closed` when the connection
    /// ends, and `CancellationError` when the calling task is cancelled.
    func receive() async throws -> Data
    /// Closes the connection (both directions). A pending `receive` on either side ends.
    func close()
}

/// The new device's side: publishes the pairing service and waits for the approver.
public protocol PairingListener: Sendable {
    /// Publishes `serviceName` (the session id in hex) and returns the first connection. Accepts one
    /// connection only. Cancelling the calling task withdraws the service and throws `CancellationError`.
    func listen(serviceName: String) async throws -> any PairingTransport
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
}
