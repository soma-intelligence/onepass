import Foundation
import Testing

@testable import VaultKit

@Suite("Biometric unlock")
struct BiometricPolicyTests {
    let account = "compte-1"
    let auk = Data((0..<32).map { UInt8($0) })

    func make(available: Bool = true) -> (BiometricUnlock, FakeEnclaveKeyring, InMemoryKeychain, FakeClock) {
        let keyring = FakeEnclaveKeyring(available: available)
        let keychain = InMemoryKeychain()
        let clock = FakeClock()
        return (BiometricUnlock(keyring: keyring, keychain: keychain, clock: clock, policy: BiometricPolicy()), keyring, keychain, clock)
    }

    func expectPassword(_ reason: PasswordReason, _ unlock: BiometricUnlock, sourceLocation: SourceLocation = #_sourceLocation) async {
        await #expect(throws: BiometricError.passwordRequired(reason: reason), sourceLocation: sourceLocation) {
            _ = try await unlock.unlock(accountID: account, prompt: "Déverrouiller OnePass")
        }
        #expect(!unlock.isEnrolled(accountID: account), sourceLocation: sourceLocation)
    }

    @Test func enrollThenUnlockReturnsAUK() async throws {
        let (unlock, _, keychain, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        #expect(unlock.isEnrolled(accountID: account))
        let stored = try #require(try keychain.read("biometric.enrollment.\(account)"))
        #expect(stored.range(of: auk) == nil)
        let out = try await unlock.unlock(accountID: account, prompt: "Déverrouiller OnePass")
        #expect(out == auk)
    }

    @Test func invalidatedKeyFallsBackToPassword() async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.invalidate()
        await expectPassword(.invalidated, unlock)
    }

    @Test func rebootRequiresPassword() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.reboot()
        await expectPassword(.rebooted, unlock)
    }

    @Test func fourteenDaysRequiresPassword() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.advance(14 * 86400)
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
        clock.advance(1)
        await expectPassword(.expired, unlock)
    }

    @Test func passwordUnlockResetsTheClock() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.advance(10 * 86400)
        try unlock.notePasswordUnlock(accountID: account)
        clock.advance(10 * 86400)
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
    }

    @Test func passwordUnlockAfterRebootUpdatesBootTime() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.reboot()
        try unlock.notePasswordUnlock(accountID: account)
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
    }

    @Test func unavailableEnclaveHidesOption() throws {
        let (unlock, _, _, _) = make(available: false)
        #expect(!unlock.isAvailable)
        #expect(throws: BiometricError.unavailable) {
            try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        }
        #expect(!unlock.isEnrolled(accountID: account))
    }

    @Test func notEnrolledRequiresPassword() async {
        let (unlock, _, _, _) = make()
        await #expect(throws: BiometricError.passwordRequired(reason: .notEnrolled)) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
    }

    @Test func cancelledKeepsEnrollment() async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.cancelNextDecrypt()
        await #expect(throws: BiometricError.cancelled) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
        #expect(unlock.isEnrolled(accountID: account))
    }

    @Test func disableRemovesEnrollmentAndKey() throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        unlock.disable(accountID: account)
        #expect(!unlock.isEnrolled(accountID: account))
        #expect(!keyring.hasKey(tag: "me.somalabs.onepass.auk.\(account)"))
    }

    @Test func enrollmentsArePerAccount() async throws {
        let (unlock, _, _, _) = make()
        try unlock.enroll(auk: auk, accountID: "a", allowWatch: false)
        #expect(!unlock.isEnrolled(accountID: "b"))
    }
}
