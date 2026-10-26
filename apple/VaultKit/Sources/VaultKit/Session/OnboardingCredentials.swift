import Foundation

/// What the onboarding types and keeps (spec 6.2), apart from the view so the clearing rules are
/// testable: typed fields are emptied as soon as they are submitted (success or failure), the new
/// Secret Key and, when the biometric step follows, the master password stay in wipeable buffers
/// until `clear()` (end of the onboarding, or lock).
///
/// The typed fields are `String` (SwiftUI text fields need one) and cannot be wiped (R5).
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

    /// Account creation submitted: both fields are emptied now, the typed password is returned for
    /// the call (keep it in a local only).
    public mutating func submitCreation() -> String {
        let typed = password
        password = ""
        confirmation = ""
        return typed
    }

    /// The account exists. The password is kept only when the biometric step will ask for it.
    public mutating func accountCreated(secretKey: String, password: String, keepPasswordForBiometrics: Bool) {
        self.secretKey?.wipe()
        self.secretKey = SecretBytes(utf8: secretKey)
        keepForEnrollment(password, keepPasswordForBiometrics)
    }

    /// Restore submitted: the password field is emptied now; the Secret Key field stays until
    /// `restored` (after a typo or a wrong password, the long key need not be typed again).
    public mutating func submitRestore() -> String {
        let typed = restorePassword
        restorePassword = ""
        return typed
    }

    /// The restore unlocked: the Secret Key field is emptied.
    public mutating func restored(password: String, keepPasswordForBiometrics: Bool) {
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

    private mutating func keepForEnrollment(_ password: String, _ keep: Bool) {
        enrollmentPassword?.wipe()
        enrollmentPassword = keep ? SecretBytes(utf8: password) : nil
    }
}
