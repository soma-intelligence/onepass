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

    @Test func passwordDueDateFollowsLastPasswordEntry() throws {
        let (unlock, _, _, clock) = make()
        #expect(unlock.passwordDueDate(accountID: account) == nil)
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        let enrolledAt = clock.now
        #expect(unlock.passwordDueDate(accountID: account) == enrolledAt.addingTimeInterval(14 * 86400))
        clock.advance(86400)
        try unlock.notePasswordUnlock(accountID: account)
        #expect(unlock.passwordDueDate(accountID: account) == enrolledAt.addingTimeInterval(15 * 86400))
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

    @Test func unsignedBuildKeychainHidesOption() throws {
        let unlock = BiometricUnlock(
            keyring: FakeEnclaveKeyring(available: true, storesKeys: false), keychain: InMemoryKeychain(),
            clock: FakeClock())
        #expect(unlock.availability == .keychainRefused)
        #expect(!unlock.isAvailable)
        #expect(throws: BiometricError.unavailable) {
            try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        }
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
        keyring.failNextDecrypt(with: .cancelled)
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

    @Test(arguments: [EnclaveError.failed(code: -25293), .failed(code: -67712), .keyInvalidated])
    func anyDecryptFailureFallsBackToPassword(error: EnclaveError) async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.failNextDecrypt(with: error)
        await expectPassword(.invalidated, unlock)
    }

    @Test func userFallbackKeepsEnrollment() async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.failNextDecrypt(with: .userFallback)
        await #expect(throws: BiometricError.passwordRequired(reason: .userChosePassword)) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
        #expect(unlock.isEnrolled(accountID: account))
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
    }

    @Test func biometryNotEnrolledDropsEnrollment() async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.failNextDecrypt(with: .biometryNotEnrolled)
        await expectPassword(.invalidated, unlock)
    }

    @Test func lockoutKeepsEnrollmentAndAsksPassword() async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.failNextDecrypt(with: .biometryLockout)
        await #expect(throws: BiometricError.passwordRequired(reason: .lockedOut)) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
        #expect(unlock.isEnrolled(accountID: account))
    }

    @Test func unknownBootSessionFailsClosed() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.setBoot("")
        await expectPassword(.rebooted, unlock)
    }

    @Test func clockMovedBackRequiresPassword() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.advance(-200)
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
        clock.advance(-200)
        await expectPassword(.expired, unlock)
    }

    @Test func keychainReadErrorIsThrownNotNotEnrolled() async throws {
        let keychain = FailingReadKeychain()
        let unlock = BiometricUnlock(keyring: FakeEnclaveKeyring(), keychain: keychain, clock: FakeClock(), policy: BiometricPolicy())
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keychain.failReads(true)
        await #expect(throws: KeychainError.unexpectedStatus(-25308)) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
        keychain.failReads(false)
        #expect(unlock.isEnrolled(accountID: account))
    }

    @Test func corruptRecordIsDroppedAsNotEnrolled() async throws {
        let (unlock, keyring, keychain, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        try keychain.write("biometric.enrollment.\(account)", Data("pas du json".utf8))
        await #expect(throws: BiometricError.passwordRequired(reason: .notEnrolled)) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
        #expect(try keychain.read("biometric.enrollment.\(account)") == nil)
        #expect(!keyring.hasKey(tag: "me.somalabs.onepass.auk.\(account)"))
    }
}
