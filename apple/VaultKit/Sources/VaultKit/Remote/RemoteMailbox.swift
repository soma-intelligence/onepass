import Foundation
import os

/// The one reader of a device's remote messages. CloudKit lets every reader see every record
/// until someone deletes it, so two readers that each delete what they cannot open lose each
/// other's messages. This mailbox holds the single `messages(for:)` subscription and routes each
/// message to its consumers in priority order (Mac: notices, then approval answers, then the
/// unlock answer). The first consumer that opens a message claims it, and only a claimed message
/// is deleted. An unclaimed message stays for whoever can open it later (the stream replays stored
/// records when it starts again), except an expired one, which goes.
///
/// The subscription runs only while a consumer is registered (CloudKit is polled only while
/// something waits).
public actor RemoteMailbox {
    /// Lower runs first.
    public enum Priority: Int, Sendable {
        case notice = 0
        case approval = 1
        case unlock = 2
    }

    /// Returns true when it opened (claimed) the message.
    public typealias Consumer = @Sendable (RemoteMessage) async -> Bool

    public let device: String
    private let channel: any RemoteChannel
    private let now: @Sendable () -> Date
    private var consumers: [UUID: (priority: Priority, open: Consumer)] = [:]
    private var reader: Task<Void, Never>?
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "remote")

    public init(channel: any RemoteChannel, device: String, now: @escaping @Sendable () -> Date = { Date() }) {
        self.channel = channel
        self.device = device
        self.now = now
    }

    /// Adds a consumer; the subscription starts if it was idle.
    @discardableResult
    public func register(_ priority: Priority, _ open: @escaping Consumer) -> UUID {
        let id = UUID()
        consumers[id] = (priority, open)
        if reader == nil {
            let stream = channel.messages(for: device)
            reader = Task { [weak self] in
                for await message in stream {
                    guard let self else { return }
                    await self.dispatch(message)
                }
            }
        }
        return id
    }

    /// Removes a consumer; the subscription stops with the last one.
    public func unregister(_ id: UUID) {
        consumers.removeValue(forKey: id)
        if consumers.isEmpty {
            reader?.cancel()
            reader = nil
        }
    }

    /// Removes every consumer of `priority` (the approvers of a window that ended).
    public func unregisterAll(_ priority: Priority) {
        for (id, consumer) in consumers where consumer.priority == priority { unregister(id) }
    }

    var isReading: Bool { reader != nil }
    var consumerCount: Int { consumers.count }

    private func dispatch(_ message: RemoteMessage) async {
        let ordered = consumers.values.sorted { $0.priority.rawValue < $1.priority.rawValue }
        for consumer in ordered where await consumer.open(message) {
            await channel.delete(message.id)
            return
        }
        if message.expiresAt < now() {
            await channel.delete(message.id)
        } else {
            Self.log.notice("remote message left for another reader")
        }
    }
}
