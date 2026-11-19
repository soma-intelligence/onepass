import Foundation

/// The pure toast state machine. Time is passed in as seconds, so tests drive
/// it without a clock.
///
/// Rules (UX-TOAST-02, UX-TOAST-03):
/// - one toast visible at a time, the rest wait in a short queue;
/// - a toast equal to the visible one restarts its timer instead of queueing;
/// - a toast equal to a waiting one is dropped;
/// - errors wait ahead of success and info toasts, never behind them;
/// - at most `maxPending` toasts wait; the oldest non-error one is dropped first;
/// - the timer pauses while the toast is touched or focused by VoiceOver.
public struct DBToastQueue: Sendable {
    public static let maxPending = 3

    public private(set) var current: DBToast?
    public private(set) var pending: [DBToast] = []

    private var shownAt: TimeInterval = 0
    private var pausedAt: TimeInterval?
    private var pausedTotal: TimeInterval = 0

    public init() {}

    public var isPaused: Bool { pausedAt != nil }

    /// When the visible toast expires, or nil when nothing is visible or the timer is paused.
    public var deadline: TimeInterval? {
        guard let current, pausedAt == nil else { return nil }
        return shownAt + pausedTotal + current.duration * DBToastTiming.uiTestingScale
    }

    /// Seconds left for the visible toast, or nil when paused or empty.
    public func remaining(now: TimeInterval) -> TimeInterval? {
        deadline.map { max(0, $0 - now) }
    }

    public mutating func enqueue(_ toast: DBToast, now: TimeInterval) {
        guard let current else {
            show(toast, now: now)
            return
        }
        if toast.isDuplicate(of: current) {
            restartTimer(now: now)
            return
        }
        if pending.contains(where: { toast.isDuplicate(of: $0) }) {
            return
        }
        if toast.kind == .error, let index = pending.firstIndex(where: { $0.kind != .error }) {
            pending.insert(toast, at: index)
        } else {
            pending.append(toast)
        }
        if pending.count > Self.maxPending {
            let index = pending.firstIndex(where: { $0.kind != .error }) ?? 0
            pending.remove(at: index)
        }
    }

    /// Dismisses the visible toast if its time is up. Returns true when it changed.
    @discardableResult
    public mutating func advance(now: TimeInterval) -> Bool {
        guard let deadline, now >= deadline else { return false }
        dismissCurrent(now: now)
        return true
    }

    /// Dismisses the visible toast (swipe, action tap, timer) and shows the next one.
    public mutating func dismissCurrent(now: TimeInterval) {
        current = nil
        pausedAt = nil
        pausedTotal = 0
        if !pending.isEmpty {
            show(pending.removeFirst(), now: now)
        }
    }

    public mutating func pause(now: TimeInterval) {
        guard current != nil, pausedAt == nil else { return }
        pausedAt = now
    }

    public mutating func resume(now: TimeInterval) {
        guard let pausedAt else { return }
        pausedTotal += max(0, now - pausedAt)
        self.pausedAt = nil
    }

    public mutating func removeAll() {
        current = nil
        pending.removeAll()
        pausedAt = nil
        pausedTotal = 0
    }

    private mutating func show(_ toast: DBToast, now: TimeInterval) {
        current = toast
        shownAt = now
        pausedAt = nil
        pausedTotal = 0
    }

    private mutating func restartTimer(now: TimeInterval) {
        shownAt = now
        pausedTotal = 0
        if pausedAt != nil {
            pausedAt = now
        }
    }
}
