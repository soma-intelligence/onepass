import Foundation

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

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    private enum Key {
        static let deviceMode = "onepass.deviceMode"
        static let autoLock = "onepass.autoLockDelay"
        static let hidden = "onepass.hiddenVaultIDs"
        static let siteIcons = "onepass.siteIconsEnabled"
        static let allowWatch = "onepass.allowWatchUnlock"
        static let failed = "onepass.failedUnlocks"
        static let lockout = "onepass.lockoutUntil"
        static let accountID = "onepass.accountID"
        static let displayName = "onepass.displayName"
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

    public var failedUnlocks: Int {
        get { defaults.integer(forKey: Key.failed) }
        set { defaults.set(newValue, forKey: Key.failed) }
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
}
