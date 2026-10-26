import Foundation

public struct BiometricPolicy: Sendable {
    /// Maximum time since the last master password entry before it is asked again.
    public var passwordEvery: TimeInterval = 14 * 86400

    /// Tolerated backwards jump of the wall clock before the password is required.
    public var clockSkew: TimeInterval = 300

    public init(passwordEvery: TimeInterval = 14 * 86400, clockSkew: TimeInterval = 300) {
        self.passwordEvery = passwordEvery
        self.clockSkew = clockSkew
    }
}

public struct BiometricEnrollment: Codable, Sendable, Equatable {
    public var accountID: String
    public var wrappedAUK: Data
    public var enrolledAt: Date
    public var lastPasswordAt: Date
    public var bootSessionID: String

    public init(accountID: String, wrappedAUK: Data, enrolledAt: Date, lastPasswordAt: Date, bootSessionID: String) {
        self.accountID = accountID
        self.wrappedAUK = wrappedAUK
        self.enrolledAt = enrolledAt
        self.lastPasswordAt = lastPasswordAt
        self.bootSessionID = bootSessionID
    }
}

public enum PasswordReason: Sendable, Equatable {
    case expired, rebooted, invalidated, notEnrolled
    /// The user chose "enter password" in the system sheet (enrollment kept).
    case userChosePassword
    /// Biometry temporarily locked out by the system (enrollment kept).
    case lockedOut

    /// French message for the unlock screen.
    public var message: String {
        switch self {
        case .expired: "Le mot de passe maître est demandé régulièrement."
        case .rebooted: "Le mot de passe maître est demandé après un redémarrage."
        case .invalidated: "La biométrie a changé : saisissez le mot de passe maître."
        case .notEnrolled: "Saisissez le mot de passe maître."
        case .userChosePassword: "Saisissez le mot de passe maître."
        case .lockedOut: "La biométrie est temporairement bloquée : saisissez le mot de passe maître."
        }
    }
}

public enum BiometricError: Error, Equatable, Sendable {
    case passwordRequired(reason: PasswordReason)
    case unavailable
    case cancelled
    case failed(code: Int32)
}
