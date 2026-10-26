import Foundation
import Testing

@testable import VaultKit

/// The onboarding's clearing rules (`OnboardingModel` keeps its fields in `OnboardingCredentials`).
@Suite("Onboarding credentials")
struct OnboardingCredentialsTests {
    static let password = "Cheval agrafe 42 !"
    static let secretKey = "A3-ABCDEF-GHJKLM-NPQRST-UVWXYZ-23456-789AB"

    @Test func creationEmptiesBothFieldsOnSubmit() {
        var c = OnboardingCredentials()
        c.password = Self.password
        c.confirmation = Self.password
        let typed = c.submitCreation()
        #expect(typed == Self.password)
        #expect(c.password.isEmpty && c.confirmation.isEmpty)
        // Failure: nothing is kept.
        #expect(c.secretKey == nil && c.enrollmentPassword == nil)
    }

    @Test func creationKeepsThePasswordOnlyForTheBiometricStep() {
        var kept = OnboardingCredentials()
        kept.accountCreated(secretKey: Self.secretKey, password: Self.password, keepPasswordForBiometrics: true)
        #expect(kept.secretKey?.string() == Self.secretKey)
        #expect(kept.enrollmentPassword?.string() == Self.password)

        var notKept = OnboardingCredentials()
        notKept.accountCreated(secretKey: Self.secretKey, password: Self.password, keepPasswordForBiometrics: false)
        #expect(notKept.secretKey?.string() == Self.secretKey)
        #expect(notKept.enrollmentPassword == nil)
    }

    @Test func restoreEmptiesThePasswordOnSubmitAndTheKeyOnSuccess() {
        var c = OnboardingCredentials()
        c.restoreKey = Self.secretKey
        c.restorePassword = Self.password
        let typed = c.submitRestore()
        #expect(typed == Self.password)
        #expect(c.restorePassword.isEmpty)
        // After a failure the key stays for another try.
        #expect(c.restoreKey == Self.secretKey)

        c.restored(password: typed, keepPasswordForBiometrics: true)
        #expect(c.restoreKey.isEmpty)
        #expect(c.enrollmentPassword?.string() == Self.password)

        var shared = OnboardingCredentials()
        shared.restored(password: typed, keepPasswordForBiometrics: false)
        #expect(shared.enrollmentPassword == nil)
    }

    /// `finish()` and `sessionLocked()` both call `clear()`: the kept buffers are wiped, not just
    /// dropped.
    @Test func clearWipesTheKeptSecretsAndEmptiesEveryField() throws {
        var c = OnboardingCredentials()
        c.accountCreated(secretKey: Self.secretKey, password: Self.password, keepPasswordForBiometrics: true)
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
