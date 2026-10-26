import Foundation

/// A transport whose peer lives in the same process: messages are delivered synchronously to the
/// peer's `onMessage` (dropped when the peer has no handler yet). For tests and previews.
@MainActor
public final class InMemoryTransport: CompanionTransport {
    public var status: CompanionStatus = .ready
    public var onMessage: ((CompanionMessage) -> Void)?
    /// Every message sent through this end, in order.
    public var sent: [CompanionMessage] = []
    /// When set, `sendLatest` throws it and delivers nothing (tests of send failures).
    public var sendLatestError: (any Error)?
    public private(set) var isActivated = false
    private weak var peer: InMemoryTransport?

    public init() {}

    public static func pair() -> (phone: InMemoryTransport, watch: InMemoryTransport) {
        let phone = InMemoryTransport()
        let watch = InMemoryTransport()
        phone.peer = watch
        watch.peer = phone
        return (phone, watch)
    }

    public func activate() {
        isActivated = true
    }

    public func sendLatest(_ m: CompanionMessage) throws {
        if let sendLatestError { throw sendLatestError }
        deliver(m)
    }

    public func sendQueued(_ m: CompanionMessage) {
        deliver(m)
    }

    private func deliver(_ m: CompanionMessage) {
        sent.append(m)
        peer?.onMessage?(m)
    }
}
