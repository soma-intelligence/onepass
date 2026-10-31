import Foundation

/// One record of the remote approval transport (agent-ready spec 5.2): a sealed and signed blob for
/// one device. Only `to` is readable by the transport; the rest of the message is in `blob`.
public struct RemoteMessage: Sendable, Equatable, Identifiable {
    /// The record name, chosen by the sender.
    public var id: String
    /// The device id of the recipient (clear, so the transport can route it).
    public var to: String
    public var blob: Data
    public var expiresAt: Date
    /// When the transport stored it, on the server's clock (CloudKit's creation date). Set by the
    /// channel, never by the sender; nil when unknown. A third clock for the phone's skew check.
    public var sentAt: Date?
    /// Delivered as it arrived (stored after the reader's stream started), not read from the
    /// backlog. Set by the channel on delivery only.
    public var isLive: Bool

    public init(id: String, to: String, blob: Data, expiresAt: Date, sentAt: Date? = nil, isLive: Bool = false) {
        self.id = id
        self.to = to
        self.blob = blob
        self.expiresAt = expiresAt
        self.sentAt = sentAt
        self.isLive = isLive
    }
}

/// The transport failed: no iCloud account, no network, or the service refused.
public enum RemoteChannelError: Error, Equatable, Sendable {
    case unreachable
}

/// Carries remote approval messages between this account's devices (CloudKit in the apps, memory in
/// the tests). It never sees anything but blobs.
public protocol RemoteChannel: Sendable {
    /// Stores `m` for its recipient. Throws `RemoteChannelError.unreachable` when the transport is down.
    func post(_ m: RemoteMessage) async throws
    /// The messages addressed to `device`: those already stored, then new ones as they arrive, each
    /// once. Ends when the consumer stops iterating (task cancelled).
    func messages(for device: String) -> AsyncStream<RemoteMessage>
    /// Removes one message; an unknown id or an unreachable transport is ignored.
    func delete(_ id: String) async
    /// Removes every message that expired before `now` (at launch, spec 5.2).
    func purgeExpired(now: Date) async
}
