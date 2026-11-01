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
    /// Boot time when the record was written (`kern.boottime`); nil in records of older builds.
    public var bootTime: Date?
    /// Set when a biometric unlock failed without proof of invalidation: the next password unlock
    /// enrolls again. Nil in records of older builds.
    public var needsRefresh: Bool?

    public init(
        accountID: String, wrappedAUK: Data, enrolledAt: Date, lastPasswordAt: Date, bootSessionID: String,
        bootTime: Date? = nil, needsRefresh: Bool? = nil
    ) {
        self.accountID = accountID
        self.wrappedAUK = wrappedAUK
        self.enrolledAt = enrolledAt
        self.lastPasswordAt = lastPasswordAt
        self.bootSessionID = bootSessionID
        self.bootTime = bootTime
        self.needsRefresh = needsRefresh
    }
}

public enum PasswordReason: Sendable, Equatable {
    case expired, rebooted, invalidated, notEnrolled
    /// The user chose "enter password" in the system sheet (enrollment kept).
    case userChosePassword
    /// Biometry temporarily locked out by the system (enrollment kept).
    case lockedOut
    /// Biometry could not be verified this time (failed match, unknown boot, unknown error); the
    /// enrollment is kept.
    case unverified

    /// French message for the unlock screen.
    public var message: String {
        switch self {
        case .expired: String(localized: "Le mot de passe maître est demandé régulièrement.", bundle: VaultKitStrings.bundle)
        case .rebooted: String(localized: "Le mot de passe maître est demandé après un redémarrage.", bundle: VaultKitStrings.bundle)
        case .invalidated: String(localized: "La biométrie a changé : saisis ton mot de passe maître.", bundle: VaultKitStrings.bundle)
        case .notEnrolled: String(localized: "Saisis ton mot de passe maître.", bundle: VaultKitStrings.bundle)
        case .userChosePassword: String(localized: "Saisis ton mot de passe maître.", bundle: VaultKitStrings.bundle)
        case .lockedOut: String(localized: "La biométrie est temporairement bloquée : saisis ton mot de passe maître.", bundle: VaultKitStrings.bundle)
        case .unverified: String(localized: "Saisis ton mot de passe maître.", bundle: VaultKitStrings.bundle)
        }
    }
}

public enum BiometricError: Error, Equatable, Sendable {
    case passwordRequired(reason: PasswordReason)
    case unavailable
    case cancelled
    case failed(code: Int32)
}
