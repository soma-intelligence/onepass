import Foundation

/// Scene phases as seen by `VaultSession` (mirrors SwiftUI `ScenePhase` without importing SwiftUI).
public enum ScenePhaseKind: Sendable {
    case active, inactive, background
}

/// Auto-lock bookkeeping, driven by an injected clock so tests can move time.
/// The delay comes from `VaultSettings.effectiveAutoLockSeconds` (nil = never).
struct AutoLock {
    private(set) var lastActivity: Date
    private(set) var backgroundedAt: Date?

    init(now: Date) { lastActivity = now }

    mutating func noteActivity(_ now: Date) { lastActivity = now }

    mutating func enterBackground(_ now: Date) {
        if backgroundedAt == nil { backgroundedAt = now }
    }

    /// Back in the foreground: true when the session must lock. Otherwise the activity clock restarts.
    mutating func becomeActive(_ now: Date, delay: TimeInterval?) -> Bool {
        defer { backgroundedAt = nil }
        if isExpired(now, delay: delay) { return true }
        lastActivity = now
        return false
    }

    func isExpired(_ now: Date, delay: TimeInterval?) -> Bool {
        guard let delay else { return false }
        let since = backgroundedAt.map { min($0, lastActivity) } ?? lastActivity
        return now.timeIntervalSince(since) >= delay
    }

    /// Seconds until expiry (for the timer); nil when never.
    func remaining(_ now: Date, delay: TimeInterval?) -> TimeInterval? {
        guard let delay else { return nil }
        return max(0, delay - now.timeIntervalSince(lastActivity))
    }
}
