import Foundation

public struct BiometricPolicy: Sendable {
    /// Maximum time since the last master password entry before it is asked again.
    public var passwordEvery: TimeInterval = 14 * 86400

    /// `kern.boottime` can drift by a few seconds when the clock is adjusted:
    /// a boot time further than this from the enrolled one means a reboot.
    public var bootTolerance: TimeInterval = 120

    public init(passwordEvery: TimeInterval = 14 * 86400, bootTolerance: TimeInterval = 120) {
        self.passwordEvery = passwordEvery
        self.bootTolerance = bootTolerance
    }
}

public struct BiometricEnrollment: Codable, Sendable, Equatable {
    public var accountID: String
    public var wrappedAUK: Data
    public var enrolledAt: Date
    public var lastPasswordAt: Date
    public var bootTime: Date

    public init(accountID: String, wrappedAUK: Data, enrolledAt: Date, lastPasswordAt: Date, bootTime: Date) {
        self.accountID = accountID
        self.wrappedAUK = wrappedAUK
        self.enrolledAt = enrolledAt
        self.lastPasswordAt = lastPasswordAt
        self.bootTime = bootTime
    }
}

public enum PasswordReason: Sendable, Equatable {
    case expired, rebooted, invalidated, notEnrolled

    /// French message for the unlock screen.
    public var message: String {
        switch self {
        case .expired: "Le mot de passe maître est demandé régulièrement."
        case .rebooted: "Le mot de passe maître est demandé après un redémarrage."
        case .invalidated: "La biométrie a changé : saisissez le mot de passe maître."
        case .notEnrolled: "Saisissez le mot de passe maître."
        }
    }
}

public enum BiometricError: Error, Equatable, Sendable {
    case passwordRequired(reason: PasswordReason)
    case unavailable
    case cancelled
    case failed(code: Int32)
}
