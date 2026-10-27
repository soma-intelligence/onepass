import CoreFoundation
import Foundation
import Synchronization

/// Tells other OnePass processes (app, AutoFill extension) that the shared store changed, through the
/// Darwin notification `me.somalabs.onepass.store-changed`. No data travels with it: a receiver
/// re-reads the store.
///
/// The extension posts after a write; the app observes and reloads. A process also receives its own
/// posts, so a process that observes never posts in reaction to a notification.
public final class StoreChangeNotifier: Sendable {
    public static let name = "me.somalabs.onepass.store-changed"

    /// The Darwin notification name this notifier posts and observes.
    public let notificationName: String

    /// `name` is for tests (one name per test, so parallel tests do not see each other's posts).
    public init(name: String = StoreChangeNotifier.name) {
        notificationName = name
    }

    /// Posts `me.somalabs.onepass.store-changed` to every process.
    public static func post() {
        post(name: name)
    }

    /// Posts this notifier's name to every process.
    public func post() {
        Self.post(name: notificationName)
    }

    /// One element per notification received from now on (posts of this process included). Several
    /// notifications in a row may be merged into one element; ending the iteration unsubscribes.
    public func changes() -> AsyncStream<Void> {
        let (stream, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        let id = UUID()
        let name = notificationName
        Registry.add(continuation, id: id, name: name)
        continuation.onTermination = { _ in Registry.remove(id: id, name: name) }
        return stream
    }

    private static func post(name: String) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(), CFNotificationName(name as CFString), nil, nil, true)
    }

    /// Subscribers by notification name. The Darwin callback is a C function that cannot capture
    /// context: it looks its subscribers up here by name.
    private enum Registry {
        private struct State {
            var subscribers: [String: [UUID: AsyncStream<Void>.Continuation]] = [:]
            /// Names already registered with the Darwin center (one observer per name, kept for the
            /// life of the process).
            var observed: Set<String> = []
        }

        private static let state = Mutex(State())

        static func add(_ continuation: AsyncStream<Void>.Continuation, id: UUID, name: String) {
            // Registered under the lock: a post right after `changes()` returns is never missed.
            state.withLock { s in
                s.subscribers[name, default: [:]][id] = continuation
                guard s.observed.insert(name).inserted else { return }
                CFNotificationCenterAddObserver(
                    // Opaque observer token: any stable non-null pointer (never dereferenced).
                    CFNotificationCenterGetDarwinNotifyCenter(), UnsafeRawPointer(bitPattern: 0x6F6E_6570),
                    { _, _, name, _, _ in
                        guard let name else { return }
                        StoreChangeNotifier.Registry.deliver(name: name.rawValue as String)
                    },
                    name as CFString, nil, .deliverImmediately)
            }
        }

        static func remove(id: UUID, name: String) {
            state.withLock { _ = $0.subscribers[name]?.removeValue(forKey: id) }
        }

        static func deliver(name: String) {
            let targets = state.withLock { Array(($0.subscribers[name] ?? [:]).values) }
            for continuation in targets { continuation.yield() }
        }
    }
}
