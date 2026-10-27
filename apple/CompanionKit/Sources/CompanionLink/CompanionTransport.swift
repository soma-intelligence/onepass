import Foundation

/// Whether the other device can be reached.
public enum CompanionStatus: Sendable, Equatable {
    /// No WatchConnectivity on this device (iPad, Mac, Vision Pro).
    case unsupported
    /// No paired watch (or the session is not activated yet).
    case notPaired
    /// A watch is paired but the OnePass watch app is not installed on it.
    case appNotInstalled
    case ready
}

/// The link between the iPhone and the watch. `WatchConnectivityTransport` in the apps,
/// `InMemoryTransport` in tests and previews.
@MainActor
public protocol CompanionTransport: AnyObject {
    var status: CompanionStatus { get }
    /// Called on the main actor for every message received from the other device.
    var onMessage: ((CompanionMessage) -> Void)? { get set }
    func activate()
    /// Only the latest message counts and replaces any undelivered one (`updateApplicationContext`).
    func sendLatest(_ m: CompanionMessage) throws
    /// Queued and delivered in order, each one (`transferUserInfo`).
    func sendQueued(_ m: CompanionMessage)
}
