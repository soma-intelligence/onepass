import Foundation
import Synchronization

public enum AutoLockDelay: String, Codable, Sendable, CaseIterable {
    case oneMinute, fiveMinutes, fifteenMinutes, oneHour, never

    public var seconds: TimeInterval? {
        switch self {
        case .oneMinute: 60
        case .fiveMinutes: 300
        case .fifteenMinutes: 900
        case .oneHour: 3600
        case .never: nil
        }
    }

    public var label: String {
        switch self {
        case .oneMinute: "1 minute"
        case .fiveMinutes: "5 minutes"
        case .fifteenMinutes: "15 minutes"
        case .oneHour: "1 heure"
        case .never: "Jamais"
        }
    }
}

/// Local, non secret settings on an injected `UserDefaults`.
public final class VaultSettings: @unchecked Sendable {
    private let defaults: UserDefaults
    private let counterLock = Mutex(())

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    private enum Key {
        static let deviceMode = "onepass.deviceMode"
        static let autoLock = "onepass.autoLockDelay"
        static let hidden = "onepass.hiddenVaultIDs"
        static let siteIcons = "onepass.siteIconsEnabled"
        static let wanted = "onepass.biometricsWanted"
        static let allowWatch = "onepass.allowWatchUnlock"
        static let failed = "onepass.failedUnlocks"
        static let lockout = "onepass.lockoutUntil"
        static let accountID = "onepass.accountID"
        static let displayName = "onepass.displayName"
        static let quickType = "onepass.quickTypeSuggestions"
        static let autofillTip = "onepass.autofillTipDismissed"
        static let revokedErase = "onepass.revokedErasePending"
    }

    /// This device was found revoked and its erase has not completed yet (L6): the app shows the
    /// revoked screen, never the lock screen, and tries the erase again.
    public var revokedErasePending: Bool {
        get { defaults.bool(forKey: Key.revokedErase) }
        set { defaults.set(newValue, forKey: Key.revokedErase) }
    }

    public var deviceMode: DeviceMode {
        get { defaults.string(forKey: Key.deviceMode).flatMap(DeviceMode.init(rawValue:)) ?? .personal }
        set { defaults.set(newValue.rawValue, forKey: Key.deviceMode) }
    }

    public var autoLockDelay: AutoLockDelay {
        get { defaults.string(forKey: Key.autoLock).flatMap(AutoLockDelay.init(rawValue:)) ?? .fifteenMinutes }
        set { defaults.set(newValue.rawValue, forKey: Key.autoLock) }
    }

    /// Delay actually applied: the chosen one, capped by the device mode.
    public var effectiveAutoLockSeconds: TimeInterval? {
        let chosen = autoLockDelay.seconds
        guard let forced = deviceMode.forcedAutoLock else { return chosen }
        return min(chosen ?? forced, forced)
    }

    public var hiddenVaultIDs: Set<String> {
        get { Set(defaults.stringArray(forKey: Key.hidden) ?? []) }
        set { defaults.set(newValue.sorted(), forKey: Key.hidden) }
    }

    public var siteIconsEnabled: Bool {
        get { defaults.object(forKey: Key.siteIcons) as? Bool ?? true }
        set { defaults.set(newValue, forKey: Key.siteIcons) }
    }

    public var allowWatchUnlock: Bool {
        get { defaults.bool(forKey: Key.allowWatch) }
        set { defaults.set(newValue, forKey: Key.allowWatch) }
    }

    /// The user asked for biometric unlock (set by the app when enrolling). Independent of `BiometricUnlock`.
    public var biometricsWanted: Bool {
        get { defaults.bool(forKey: Key.wanted) }
        set { defaults.set(newValue, forKey: Key.wanted) }
    }

    /// Failed master password attempts. The throttle built on it (`lockoutUntil`) is local to
    /// this device and only slows down casual guessing; the real protection is the KDF.
    public var failedUnlocks: Int {
        get { counterLock.withLock { _ in defaults.integer(forKey: Key.failed) } }
        set { counterLock.withLock { _ in defaults.set(newValue, forKey: Key.failed) } }
    }

    /// Atomic read-modify-write; returns the new count.
    @discardableResult
    public func recordFailedUnlock() -> Int {
        counterLock.withLock { _ in
            let next = defaults.integer(forKey: Key.failed) + 1
            defaults.set(next, forKey: Key.failed)
            return next
        }
    }

    public func resetFailedUnlocks() {
        counterLock.withLock { _ in defaults.set(0, forKey: Key.failed) }
    }

    public var lockoutUntil: Date? {
        get { defaults.object(forKey: Key.lockout) as? Date }
        set {
            if let newValue { defaults.set(newValue, forKey: Key.lockout) } else { defaults.removeObject(forKey: Key.lockout) }
        }
    }

    public var accountID: String? {
        get { defaults.string(forKey: Key.accountID) }
        set {
            if let newValue { defaults.set(newValue, forKey: Key.accountID) } else { defaults.removeObject(forKey: Key.accountID) }
        }
    }

    public var displayName: String {
        get { defaults.string(forKey: Key.displayName) ?? "" }
        set { defaults.set(newValue, forKey: Key.displayName) }
    }

    /// Offer logins as QuickType suggestions in the keyboard bar (default on).
    public var quickTypeSuggestions: Bool {
        get { defaults.object(forKey: Key.quickType) as? Bool ?? true }
        set { defaults.set(newValue, forKey: Key.quickType) }
    }

    /// The user closed the "turn on AutoFill" tip (default false).
    public var autofillTipDismissed: Bool {
        get { defaults.bool(forKey: Key.autofillTip) }
        set { defaults.set(newValue, forKey: Key.autofillTip) }
    }
}
