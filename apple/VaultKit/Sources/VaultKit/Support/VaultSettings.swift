import Foundation
import Synchronization

public enum AutoLockDelay: String, Codable, Sendable, CaseIterable {
    /// Locks as soon as the app leaves the screen (background, screen off); 5 minutes of inactivity
    /// while it is open.
    case immediately
    case oneMinute, fiveMinutes, fifteenMinutes, oneHour, never

    /// The default: immediately on iPhone and iPad (the app leaves the screen all the time), 15 minutes
    /// on the Mac.
    public static var platformDefault: AutoLockDelay {
        #if os(iOS)
        .immediately
        #else
        .fifteenMinutes
        #endif
    }

    /// Locks when the app goes to the background, whatever the time spent there.
    public var locksInBackground: Bool { self == .immediately }

    /// Inactivity before locking while the app is open (and time in the background, for the others).
    public var seconds: TimeInterval? {
        switch self {
        case .immediately: 300
        case .oneMinute: 60
        case .fiveMinutes: 300
        case .fifteenMinutes: 900
        case .oneHour: 3600
        case .never: nil
        }
    }

    public var label: String {
        switch self {
        case .immediately: String(localized: "Immédiatement", bundle: VaultKitStrings.bundle)
        case .oneMinute: String(localized: "1 minute", bundle: VaultKitStrings.bundle)
        case .fiveMinutes: String(localized: "5 minutes", bundle: VaultKitStrings.bundle)
        case .fifteenMinutes: String(localized: "15 minutes", bundle: VaultKitStrings.bundle)
        case .oneHour: String(localized: "1 heure", bundle: VaultKitStrings.bundle)
        case .never: String(localized: "Jamais", bundle: VaultKitStrings.bundle)
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
        static let profilePhoto = "onepass.profilePhoto"
        static let profilePending = "onepass.profilePending"
        static let quickType = "onepass.quickTypeSuggestions"
        static let autofillTip = "onepass.autofillTipDismissed"
        static let revokedErase = "onepass.revokedErasePending"
        static let revokedLocked = "onepass.revokedLocked"
    }

    /// This device was found revoked and its erase has not completed yet (L6): the app shows the
    /// revoked screen, never the lock screen, and tries the erase again.
    public var revokedErasePending: Bool {
        get { defaults.bool(forKey: Key.revokedErase) }
        set { defaults.set(newValue, forKey: Key.revokedErase) }
    }

    /// The signed device list marked this device revoked: the app shows the revoked screen, never the
    /// lock screen, until the user erases the device. The list alone never erases anything (a revoked
    /// device can sign one too).
    public var revokedLocked: Bool {
        get { defaults.bool(forKey: Key.revokedLocked) }
        set { defaults.set(newValue, forKey: Key.revokedLocked) }
    }

    public var deviceMode: DeviceMode {
        get { defaults.string(forKey: Key.deviceMode).flatMap(DeviceMode.init(rawValue:)) ?? .personal }
        set { defaults.set(newValue.rawValue, forKey: Key.deviceMode) }
    }

    public var autoLockDelay: AutoLockDelay {
        get { defaults.string(forKey: Key.autoLock).flatMap(AutoLockDelay.init(rawValue:)) ?? .platformDefault }
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

    /// The account's photo: a small square JPEG (no metadata). With `displayName`, this device's copy
    /// of the account profile the vault syncs (`VaultSession.setProfile`), read while locked too.
    public var profilePhoto: Data? {
        get { defaults.data(forKey: Key.profilePhoto) }
        set {
            if let newValue { defaults.set(newValue, forKey: Key.profilePhoto) } else { defaults.removeObject(forKey: Key.profilePhoto) }
        }
    }

    /// The name or photo changed here and has not reached the vault yet: written at the next unlock,
    /// before the vault's profile may replace this device's copy.
    public var profilePending: Bool {
        get { defaults.bool(forKey: Key.profilePending) }
        set { defaults.set(newValue, forKey: Key.profilePending) }
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
