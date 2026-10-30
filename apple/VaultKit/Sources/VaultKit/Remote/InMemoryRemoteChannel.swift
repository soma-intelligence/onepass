import Foundation
import Synchronization

/// `RemoteChannel` in memory, for tests and previews: a fake CloudKit zone shared by the devices of
/// one test. `reachable = false` makes every post fail like an unreachable CloudKit.
public final class InMemoryRemoteChannel: RemoteChannel {
    private struct State {
        var records: [RemoteMessage] = []
        var subscribers: [UUID: (device: String, continuation: AsyncStream<RemoteMessage>.Continuation)] = [:]
        var reachable = true
    }

    private let state = Mutex(State())
    /// The fake server's clock: stamps `sentAt` on every post.
    private let now: @Sendable () -> Date

    public init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }

    public var reachable: Bool {
        get { state.withLock { $0.reachable } }
        set { state.withLock { $0.reachable = newValue } }
    }

    /// Every stored message, oldest first.
    public func stored() -> [RemoteMessage] {
        state.withLock { $0.records }
    }

    public func post(_ m: RemoteMessage) async throws {
        var m = m
        m.sentAt = now()
        let targets = try state.withLock { s -> [AsyncStream<RemoteMessage>.Continuation] in
            guard s.reachable else { throw RemoteChannelError.unreachable }
            s.records.removeAll { $0.id == m.id }
            s.records.append(m)
            return s.subscribers.values.filter { $0.device == m.to }.map(\.continuation)
        }
        for continuation in targets { continuation.yield(m) }
    }

    public func messages(for device: String) -> AsyncStream<RemoteMessage> {
        let (stream, continuation) = AsyncStream.makeStream(of: RemoteMessage.self)
        let id = UUID()
        // Registered and replayed under one lock: no message posted meanwhile is lost or doubled.
        state.withLock { s in
            for m in s.records where m.to == device { continuation.yield(m) }
            s.subscribers[id] = (device, continuation)
        }
        continuation.onTermination = { [weak self] _ in
            self?.state.withLock { _ = $0.subscribers.removeValue(forKey: id) }
        }
        return stream
    }

    public func delete(_ id: String) async {
        state.withLock { $0.records.removeAll { $0.id == id } }
    }

    public func purgeExpired(now: Date) async {
        state.withLock { $0.records.removeAll { $0.expiresAt < now } }
    }
}
