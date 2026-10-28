import Foundation
import Observation
import os

/// A public (guest) session on the new device (spec 2b 5.4): the lent items, read only, in memory
/// only. Nothing is ever written to disk. It ends at expiry, on the approver's `End`, when the
/// connection closes (fail closed), after 5 minutes without activity, and on `end()`; then the items
/// are dropped and the clipboard is cleared. Copies clear the clipboard after 30 s. The approver gets
/// an audit event for each item viewed and each field copied (the field label, never its value).
@MainActor
@Observable
public final class PublicSession {
    public enum EndReason: Equatable, Sendable {
        /// The time the approver granted ran out.
        case expired
        /// The approver ended the session.
        case endedByOwner
        /// The connection with the approver closed.
        case connectionLost
        /// 5 minutes without activity.
        case inactivity
        /// Ended on this device (`end()`, the app quitting or going to the background).
        case endedHere
    }

    public static let inactivityLimit: TimeInterval = 300
    public static let clipboardClearAfter: TimeInterval = 30
    /// The longest session the core grants: a longer one from a skewed clock is cut to this.
    static let maxDuration: TimeInterval = 60 * 60

    /// The lent items; empty once the session ended.
    public private(set) var items: [FfiItem]
    /// When the session ends, on this device's clock.
    public let expiresAt: Date
    /// Seconds left, refreshed every second while the session runs.
    public private(set) var remaining: TimeInterval
    /// Why the session ended; nil while it runs.
    public private(set) var endReason: EndReason?

    public var isActive: Bool { endReason == nil }

    @ObservationIgnored private let newcomer: PairingNewcomer
    @ObservationIgnored private let transport: any PairingTransport
    @ObservationIgnored private let clock: any BootClock
    @ObservationIgnored private let clipboard: Clipboard
    @ObservationIgnored private var lastActivity: Date
    @ObservationIgnored private var ticker: Task<Void, Never>?
    @ObservationIgnored private var receiver: Task<Void, Never>?
    @ObservationIgnored private var sendChain: Task<Void, Never>?

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "pairing")

    /// `grantExpiresAt` is the approver's Unix time: only the duration left is kept, measured on this
    /// device's clock, so a skewed clock cannot lengthen the session past an hour.
    init(
        items: [FfiItem], grantExpiresAt: Int64, newcomer: PairingNewcomer, transport: any PairingTransport,
        clock: any BootClock, pasteboard: any PasteboardWriter, wallClock: Date = Date()
    ) {
        self.items = items
        self.newcomer = newcomer
        self.transport = transport
        self.clock = clock
        clipboard = Clipboard(pasteboard: pasteboard, clock: clock, clearAfter: Self.clipboardClearAfter)
        let left = min(Self.maxDuration, max(0, TimeInterval(grantExpiresAt) - wallClock.timeIntervalSince1970))
        let now = clock.now
        expiresAt = now.addingTimeInterval(left)
        remaining = left
        lastActivity = now
    }

    isolated deinit {
        ticker?.cancel()
        receiver?.cancel()
    }

    /// Starts the countdown and the reading of the approver's frames.
    func start() {
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self, self.isActive else { return }
                self.tick()
            }
        }
        let transport = transport
        let newcomer = newcomer
        receiver = Task { [weak self] in
            while true {
                let message: FfiPairingMessage
                do {
                    let frame = try await transport.receive()
                    message = try await CoreThread.run { try newcomer.open(frame: frame) }
                } catch is CancellationError {
                    return
                } catch {
                    self?.finish(.connectionLost)
                    return
                }
                if case .end = message {
                    self?.finish(.endedByOwner)
                    return
                }
            }
        }
        tick()
    }

    /// Any user interaction: restarts the 5 minute inactivity delay.
    public func noteActivity() {
        guard isActive else { return }
        lastActivity = clock.now
    }

    /// Re-reads the clock: ends the session on expiry or inactivity (the timer calls it every second;
    /// tests call it after moving the clock).
    public func tick() {
        guard isActive else { return }
        let now = clock.now
        remaining = max(0, expiresAt.timeIntervalSince(now))
        clipboard.clearIfExpired()
        if remaining <= 0 {
            finish(.expired)
        } else if now.timeIntervalSince(lastActivity) >= Self.inactivityLimit {
            finish(.inactivity)
        }
    }

    /// The user opened an item: the approver's journal gets `opened`.
    public func viewed(itemID: String) {
        guard isActive, items.contains(where: { $0.id == itemID }) else { return }
        noteActivity()
        audit(itemID: itemID, action: .opened)
    }

    /// Copies a field value (local only, concealed, cleared after 30 s); the approver's journal gets
    /// the field's label.
    public func copy(_ value: String, label: String, itemID: String) {
        guard isActive, items.contains(where: { $0.id == itemID }) else { return }
        noteActivity()
        clipboard.copy(value, concealed: true)
        audit(itemID: itemID, action: .copied(label: label))
    }

    /// "Terminer": tells the approver, then ends.
    public func end() {
        guard isActive else { return }
        let newcomer = newcomer
        enqueue { transport in
            let frame = try await CoreThread.run { try newcomer.sealEnd() }
            try await transport.send(frame)
        }
        finish(.endedHere)
    }

    /// Tests: waits until every frame queued so far was sent.
    func waitForSends() async {
        await sendChain?.value
    }

    private func audit(itemID: String, action: FfiAuditAction) {
        let newcomer = newcomer
        let at = Int64(Date().timeIntervalSince1970)
        enqueue { transport in
            let frame = try await CoreThread.run { try newcomer.sealAudit(itemId: itemID, action: action, at: at) }
            try await transport.send(frame)
        }
    }

    /// Frames go out one after the other; a failed send ends the session (fail closed).
    private func enqueue(_ op: @escaping @Sendable (any PairingTransport) async throws -> Void) {
        let previous = sendChain
        let transport = transport
        sendChain = Task { [weak self] in
            await previous?.value
            do {
                try await op(transport)
            } catch {
                Self.log.notice("public session frame not sent")
                self?.finish(.connectionLost)
            }
        }
    }

    private func finish(_ reason: EndReason) {
        guard isActive else { return }
        endReason = reason
        items = []
        remaining = 0
        clipboard.clear()
        ticker?.cancel()
        receiver?.cancel()
        let transport = transport
        let pending = sendChain
        // The last frames (the End) leave before the connection closes.
        Task {
            await pending?.value
            transport.close()
        }
    }
}
