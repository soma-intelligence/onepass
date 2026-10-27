import Foundation
import notify

/// Cross-process "lock now" request (widget/extension to app). The timestamp lives in
/// shared defaults; the Darwin notification wakes a running app immediately.
public struct LockSignal: @unchecked Sendable {
    public static let darwinName = "me.somalabs.onepass.lock-request"
    private static let key = "lockRequestedAt"

    // UserDefaults is documented thread-safe.
    private let defaults: UserDefaults

    public init(defaults: UserDefaults) {
        self.defaults = defaults
    }

    public func request(at date: Date = .now) {
        defaults.set(date.timeIntervalSince1970, forKey: Self.key)
        notify_post(Self.darwinName)
    }

    public var lastRequest: Date? {
        guard let value = defaults.object(forKey: Self.key) as? Double else { return nil }
        return Date(timeIntervalSince1970: value)
    }

    public func isPending(unlockedAt: Date?) -> Bool {
        guard let requested = lastRequest else { return false }
        guard let unlockedAt else { return true }
        return requested > unlockedAt
    }

    /// Whether the app should lock now: a request newer than both its last unlock and its
    /// launch. A request from before the launch is spent (an app that was not running held no
    /// key), so the first unlock after a relaunch is never undone by an old request.
    public static func shouldLock(request: Date?, unlockedAt: Date?, launchedAt: Date) -> Bool {
        guard let request else { return false }
        let baseline = max(unlockedAt ?? launchedAt, launchedAt)
        return request > baseline
    }

    public static func observe(_ handler: @escaping @Sendable () -> Void) -> LockSignalObservation {
        LockSignalObservation(handler: handler)
    }
}

public final class LockSignalObservation: Sendable {
    private let token: Int32
    private let state: CancelFlag

    fileprivate init(handler: @escaping @Sendable () -> Void) {
        var t: Int32 = 0
        let status = notify_register_dispatch(LockSignal.darwinName, &t, DispatchQueue.global()) { _ in
            handler()
        }
        token = status == NOTIFY_STATUS_OK ? t : NOTIFY_TOKEN_INVALID
        state = CancelFlag()
    }

    public func cancel() {
        guard token != NOTIFY_TOKEN_INVALID, state.firstCancel() else { return }
        notify_cancel(token)
    }

    deinit { cancel() }
}

/// Tracks whether the token was already cancelled.
private final class CancelFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func firstCancel() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if cancelled { return false }
        cancelled = true
        return true
    }
}
