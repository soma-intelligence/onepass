import Foundation
import Synchronization

/// `RemoteChannel` in memory, for tests and previews: a fake CloudKit zone shared by the devices of
/// one test. `reachable = false` makes every post fail like an unreachable CloudKit.
/// `dropsExpiredUnread`: a record that expired before its recipient started reading is gone when it
/// does (CloudKit's expired records are purged, so nobody can count on reading them late).
public final class InMemoryRemoteChannel: RemoteChannel {
    private struct State {
        var records: [RemoteMessage] = []
        var subscribers: [UUID: (device: String, continuation: AsyncStream<RemoteMessage>.Continuation)] = [:]
        var reachable = true
    }

    private let state = Mutex(State())
    /// The fake server's clock: stamps `sentAt` on every post.
    private let now: @Sendable () -> Date
    private let dropsExpiredUnread: Bool

    public init(now: @escaping @Sendable () -> Date = { Date() }, dropsExpiredUnread: Bool = false) {
        self.now = now
        self.dropsExpiredUnread = dropsExpiredUnread
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
        m.isLive = false
        let targets = try state.withLock { s -> [AsyncStream<RemoteMessage>.Continuation] in
            guard s.reachable else { throw RemoteChannelError.unreachable }
            s.records.removeAll { $0.id == m.id }
            s.records.append(m)
            return s.subscribers.values.filter { $0.device == m.to }.map(\.continuation)
        }
        // Delivered as it arrives: live (the stored copy, replayed later, is backlog).
        var live = m
        live.isLive = true
        for continuation in targets { continuation.yield(live) }
    }

    public func messages(for device: String) -> AsyncStream<RemoteMessage> {
        let (stream, continuation) = AsyncStream.makeStream(of: RemoteMessage.self)
        let id = UUID()
        let current = now()
        let dropsExpired = dropsExpiredUnread
        // Registered and replayed under one lock: no message posted meanwhile is lost or doubled.
        state.withLock { s in
            if dropsExpired { s.records.removeAll { $0.to == device && $0.expiresAt < current } }
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
