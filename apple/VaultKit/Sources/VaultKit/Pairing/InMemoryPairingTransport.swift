import Foundation
import Synchronization

/// Frames waiting for one side of an in-memory connection.
final class PairingInbox: Sendable {
    private struct State {
        var frames: [Data] = []
        var waiter: (id: UUID, continuation: CheckedContinuation<Data, any Error>)?
        var closed = false
    }
    private let state = Mutex(State())

    func deliver(_ frame: Data) -> Bool {
        let waiter = state.withLock { s -> CheckedContinuation<Data, any Error>? in
            guard !s.closed else { return nil }
            if let w = s.waiter {
                s.waiter = nil
                return w.continuation
            }
            s.frames.append(frame)
            return nil
        }
        // `deliver` returns false only on a closed inbox.
        if let waiter {
            waiter.resume(returning: frame)
            return true
        }
        return !state.withLock { $0.closed }
    }

    /// Frames already delivered are still read after a close; then `closed`.
    func next() async throws -> Data {
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Data, any Error>) in
                let outcome = state.withLock { s -> Result<Data, any Error>? in
                    if !s.frames.isEmpty { return .success(s.frames.removeFirst()) }
                    if s.closed { return .failure(PairingTransportError.closed) }
                    if Task.isCancelled { return .failure(CancellationError()) }
                    s.waiter = (id, c)
                    return nil
                }
                if let outcome { c.resume(with: outcome) }
            }
        } onCancel: {
            let waiter = state.withLock { s -> CheckedContinuation<Data, any Error>? in
                guard let w = s.waiter, w.id == id else { return nil }
                s.waiter = nil
                return w.continuation
            }
            waiter?.resume(throwing: CancellationError())
        }
    }

    func close() {
        let waiter = state.withLock { s -> CheckedContinuation<Data, any Error>? in
            s.closed = true
            guard s.frames.isEmpty, let w = s.waiter else { return nil }
            s.waiter = nil
            return w.continuation
        }
        waiter?.resume(throwing: PairingTransportError.closed)
    }
}

/// One end of an in-memory connection (tests, previews).
public final class InMemoryPairingTransport: PairingTransport {
    private let inbox: PairingInbox
    private let outbox: PairingInbox
    private let onSend: @Sendable (Data) -> Void

    init(inbox: PairingInbox, outbox: PairingInbox, onSend: @escaping @Sendable (Data) -> Void) {
        self.inbox = inbox
        self.outbox = outbox
        self.onSend = onSend
    }

    /// Two connected ends.
    public static func pair() -> (InMemoryPairingTransport, InMemoryPairingTransport) {
        let (a, b) = (PairingInbox(), PairingInbox())
        return (
            InMemoryPairingTransport(inbox: a, outbox: b, onSend: { _ in }),
            InMemoryPairingTransport(inbox: b, outbox: a, onSend: { _ in })
        )
    }

    public func send(_ frame: Data) async throws {
        guard frame.count <= PairingFrame.maxBytes else {
            close()
            throw PairingTransportError.frameTooLarge
        }
        guard outbox.deliver(frame) else { throw PairingTransportError.closed }
        onSend(frame)
    }

    public func receive() async throws -> Data {
        try await inbox.next()
    }

    public func close() {
        inbox.close()
        outbox.close()
    }
}

/// An in-memory "local network": a listener publishes a service name, a connector reaches it. A
/// connector that comes before the listener is held until the name is published. Records every
/// frame each side sent (tests check what left a device).
public final class InMemoryPairingNetwork: PairingListener, PairingConnector {
    public enum Side: Sendable { case listener, connector }

    private struct State {
        var listeners: [String: (id: UUID, continuation: CheckedContinuation<any PairingTransport, any Error>)] = [:]
        var waiting: [String: InMemoryPairingTransport] = [:]
        var sent: [(service: String, side: Side, frame: Data)] = []
        var published: [String] = []
        var connections: [String: InMemoryPairingTransport] = [:]
    }
    private let state = Mutex(State())

    public init() {}

    /// Every service name published so far, in order.
    public var publishedServices: [String] { state.withLock { $0.published } }

    /// Cuts the connection to `service` (both ends see it closed), like a lost network.
    public func disconnect(service: String) {
        state.withLock { $0.connections[service] }?.close()
    }

    /// Frames sent by `side` on the connection to `service`.
    public func frames(service: String, from side: Side) -> [Data] {
        state.withLock { $0.sent.filter { $0.service == service && $0.side == side }.map(\.frame) }
    }

    public func listen(serviceName: String) async throws -> any PairingTransport {
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<any PairingTransport, any Error>) in
                let ready = state.withLock { s -> Result<any PairingTransport, any Error>? in
                    if Task.isCancelled { return .failure(CancellationError()) }
                    s.published.append(serviceName)
                    if let waiting = s.waiting.removeValue(forKey: serviceName) { return .success(waiting) }
                    s.listeners[serviceName] = (id, c)
                    return nil
                }
                if let ready { c.resume(with: ready) }
            }
        } onCancel: {
            let c = state.withLock { s -> CheckedContinuation<any PairingTransport, any Error>? in
                guard let l = s.listeners[serviceName], l.id == id else { return nil }
                s.listeners[serviceName] = nil
                return l.continuation
            }
            c?.resume(throwing: CancellationError())
        }
    }

    public func connect(serviceName: String) async throws -> any PairingTransport {
        let (a, b) = (PairingInbox(), PairingInbox())
        let record: @Sendable (Side) -> @Sendable (Data) -> Void = { side in
            { frame in self.state.withLock { $0.sent.append((serviceName, side, frame)) } }
        }
        let mine = InMemoryPairingTransport(inbox: a, outbox: b, onSend: record(.connector))
        let theirs = InMemoryPairingTransport(inbox: b, outbox: a, onSend: record(.listener))
        let listener = state.withLock { s -> CheckedContinuation<any PairingTransport, any Error>? in
            s.connections[serviceName] = mine
            if let l = s.listeners.removeValue(forKey: serviceName) { return l.continuation }
            s.waiting[serviceName] = theirs
            return nil
        }
        listener?.resume(returning: theirs)
        return mine
    }
}
