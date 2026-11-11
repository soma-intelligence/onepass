import Foundation

/// The last time an account was locked on this device, by whichever process did it.
public struct AccountLockStamp: Sendable, Equatable {
    public let lockedAt: Date
    /// Changes at every lock: comparing two readings needs no clock.
    public let mark: String

    public init(lockedAt: Date, mark: String) {
        self.lockedAt = lockedAt
        self.mark = mark
    }
}

/// Where the AutoFill provider reads the locks of an account made elsewhere (the app's Lock button,
/// its auto-lock, "lock everything", a revoked device, an erased account): its unlock window is live
/// only while no lock came after its grant.
public protocol AccountLockStamps: Sendable {
    /// The latest lock of the account `settings` belongs to, nil when none was ever recorded.
    func latest(for settings: VaultSettings) -> AccountLockStamp?
}

/// The stamps in the settings suite the app and the provider share, one per account. A date and a
/// random mark: nothing about the vault.
public struct SharedAccountLockStamps: AccountLockStamps {
    public init() {}

    private static func key(_ settings: VaultSettings) -> String {
        "onepass.autofill.lockedAt" + (settings.scope.map { ".\($0)" } ?? "")
    }

    public func latest(for settings: VaultSettings) -> AccountLockStamp? {
        // The writer is another process, and this one may have just resumed from a suspension:
        // read what the preferences daemon holds now, not what this process cached before.
        settings.baseDefaults.synchronize()
        guard let raw = settings.baseDefaults.string(forKey: Self.key(settings)) else { return nil }
        let parts = raw.split(separator: "|", maxSplits: 1).map(String.init)
        guard parts.count == 2, let seconds = TimeInterval(parts[0]) else {
            // Unreadable: still a stamp, and newer than anything (the window is refused or ended).
            return AccountLockStamp(lockedAt: .distantFuture, mark: raw)
        }
        return AccountLockStamp(lockedAt: Date(timeIntervalSinceReferenceDate: seconds), mark: parts[1])
    }

    /// Records a lock of the account of `settings` at `now` (`VaultSession`, on every path that
    /// drops the keys of an account outside the provider's own end of request).
    public static func record(for settings: VaultSettings, at now: Date) {
        settings.baseDefaults.set(
            "\(now.timeIntervalSinceReferenceDate)|\(UUID().uuidString)", forKey: key(settings))
        // Handed over now: iOS may suspend the app right after the lock that brought it here.
        settings.baseDefaults.synchronize()
    }
}
