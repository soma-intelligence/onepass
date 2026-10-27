import Foundation

/// What the onboarding types and keeps (spec 6.2), apart from the view so the clearing rules are
/// testable: typed fields are emptied as soon as they are submitted (success or failure), the new
/// Secret Key and, when the biometric step follows, the master password stay in wipeable buffers
/// until `clear()` (end of the onboarding, or lock).
///
/// The typed fields are `String` (SwiftUI text fields need one) and cannot be wiped (R5); what is
/// submitted goes into a wipeable buffer at once and crosses the FFI as bytes.
public struct OnboardingCredentials {
    public var password = ""
    public var confirmation = ""
    public var restoreKey = ""
    public var restorePassword = ""
    /// The new account's Secret Key (shown once, put in the Emergency Kit).
    public private(set) var secretKey: SecretBytes?
    /// The master password once submitted, for the biometric enrollment step only.
    public private(set) var enrollmentPassword: SecretBytes?

    public init() {}

    /// Account creation submitted: both fields are emptied now, the typed password is returned in a
    /// buffer the caller owns (and wipes after the call).
    public mutating func submitCreation() -> SecretBytes {
        let typed = SecretBytes(utf8: password)
        password = ""
        confirmation = ""
        return typed
    }

    /// The account exists: the Secret Key buffer is taken over (the caller drops its reference). The
    /// password is copied only when the biometric step will ask for it.
    public mutating func accountCreated(secretKey: SecretBytes, password: SecretBytes, keepPasswordForBiometrics: Bool) {
        self.secretKey?.wipe()
        self.secretKey = secretKey
        keepForEnrollment(password, keepPasswordForBiometrics)
    }

    /// Restore submitted: the password field is emptied now; the Secret Key field stays until
    /// `restored` (after a typo or a wrong password, the long key need not be typed again).
    public mutating func submitRestore() -> SecretBytes {
        let typed = SecretBytes(utf8: restorePassword)
        restorePassword = ""
        return typed
    }

    /// The restore unlocked: the Secret Key field is emptied.
    public mutating func restored(password: SecretBytes, keepPasswordForBiometrics: Bool) {
        restoreKey = ""
        keepForEnrollment(password, keepPasswordForBiometrics)
    }

    /// End of the onboarding or lock: every field is emptied, both buffers are wiped and dropped.
    public mutating func clear() {
        password = ""
        confirmation = ""
        restoreKey = ""
        restorePassword = ""
        secretKey?.wipe()
        secretKey = nil
        enrollmentPassword?.wipe()
        enrollmentPassword = nil
    }

    private mutating func keepForEnrollment(_ password: SecretBytes, _ keep: Bool) {
        enrollmentPassword?.wipe()
        enrollmentPassword = keep ? password.withUnsafeBytes { SecretBytes(copying: $0) } : nil
    }
}
