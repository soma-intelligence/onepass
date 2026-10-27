import Foundation
import Testing

@testable import VaultKit

/// The onboarding's clearing rules (`OnboardingModel` keeps its fields in `OnboardingCredentials`).
@Suite("Onboarding credentials")
struct OnboardingCredentialsTests {
    static let password = "Cheval agrafe 42 !"
    static let secretKey = "A3-ABCDEF-GHJKLM-NPQRST-UVWXYZ-23456-789AB"
    static var keyBytes: SecretBytes { SecretBytes(utf8: secretKey) }
    static var passwordBytes: SecretBytes { SecretBytes(utf8: password) }

    @Test func creationEmptiesBothFieldsOnSubmit() {
        var c = OnboardingCredentials()
        c.password = Self.password
        c.confirmation = Self.password
        let typed = c.submitCreation()
        #expect(typed.string() == Self.password)
        #expect(c.password.isEmpty && c.confirmation.isEmpty)
        // Failure: nothing is kept.
        #expect(c.secretKey == nil && c.enrollmentPassword == nil)
    }

    @Test func creationKeepsThePasswordOnlyForTheBiometricStep() {
        var kept = OnboardingCredentials()
        kept.accountCreated(secretKey: Self.keyBytes, password: Self.passwordBytes, keepPasswordForBiometrics: true)
        #expect(kept.secretKey?.string() == Self.secretKey)
        #expect(kept.enrollmentPassword?.string() == Self.password)

        var notKept = OnboardingCredentials()
        notKept.accountCreated(secretKey: Self.keyBytes, password: Self.passwordBytes, keepPasswordForBiometrics: false)
        #expect(notKept.secretKey?.string() == Self.secretKey)
        #expect(notKept.enrollmentPassword == nil)
    }

    @Test func restoreEmptiesThePasswordOnSubmitAndTheKeyOnSuccess() {
        var c = OnboardingCredentials()
        c.restoreKey = Self.secretKey
        c.restorePassword = Self.password
        let typed = c.submitRestore()
        #expect(typed.string() == Self.password)
        #expect(c.restorePassword.isEmpty)
        // After a failure the key stays for another try.
        #expect(c.restoreKey == Self.secretKey)

        c.restored(password: typed, keepPasswordForBiometrics: true)
        #expect(c.restoreKey.isEmpty)
        #expect(c.enrollmentPassword?.string() == Self.password)

        var shared = OnboardingCredentials()
        shared.restored(password: typed, keepPasswordForBiometrics: false)
        #expect(shared.enrollmentPassword == nil)
        // The kept password is a copy: wiping the submitted buffer leaves it intact.
        typed.wipe()
        #expect(c.enrollmentPassword?.string() == Self.password)
    }

    /// `finish()` and `sessionLocked()` both call `clear()`: the kept buffers are wiped, not just
    /// dropped.
    @Test func clearWipesTheKeptSecretsAndEmptiesEveryField() throws {
        var c = OnboardingCredentials()
        c.accountCreated(secretKey: Self.keyBytes, password: Self.passwordBytes, keepPasswordForBiometrics: true)
        c.password = "x"
        c.confirmation = "x"
        c.restoreKey = "y"
        c.restorePassword = "z"
        let key = try #require(c.secretKey)
        let password = try #require(c.enrollmentPassword)

        c.clear()
        #expect(c.secretKey == nil && c.enrollmentPassword == nil)
        #expect(key.isEmpty && password.isEmpty)
        #expect(c.password.isEmpty && c.confirmation.isEmpty && c.restoreKey.isEmpty && c.restorePassword.isEmpty)
    }
}
