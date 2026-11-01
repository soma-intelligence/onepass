import Foundation
import LocalAuthentication
import Security
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

    @Test func invalidatedKeyDropsEnrollment() async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.failNextDecrypt(with: .keyInvalidated)
        await expectPassword(.invalidated, unlock)
    }

    /// An unknown error (errSecAuthFailed, a CryptoTokenKit code nobody listed...) is no proof that
    /// the key is gone: one password, the enrollment stays, and the next password unlock refreshes it.
    @Test(arguments: [EnclaveError.failed(code: -25293), .failed(code: -67712), .failed(code: -3), .authenticationFailed])
    func unprovenFailureKeepsEnrollment(error: EnclaveError) async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        #expect(!unlock.needsRefresh(accountID: account))
        keyring.failNextDecrypt(with: error)
        await #expect(throws: BiometricError.passwordRequired(reason: .unverified)) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
        #expect(unlock.isEnrolled(accountID: account))
        #expect(keyring.hasKey(tag: "me.somalabs.onepass.auk.\(account)"))
        #expect(unlock.needsRefresh(accountID: account))
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
    }

    /// Every failure that keeps the enrollment flags it for a refresh, except the user's own cancel.
    @Test(arguments: [
        (EnclaveError.interrupted, BiometricError.cancelled),
        (.userFallback, .passwordRequired(reason: .userChosePassword)),
        (.biometryLockout, .passwordRequired(reason: .lockedOut)),
        (.unavailable, .unavailable),
    ] as [(EnclaveError, BiometricError)])
    func keptFailureFlagsRefresh(error: EnclaveError, expected: BiometricError) async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.failNextDecrypt(with: error)
        await #expect(throws: expected) { _ = try await unlock.unlock(accountID: account, prompt: "x") }
        #expect(unlock.isEnrolled(accountID: account))
        #expect(unlock.needsRefresh(accountID: account))
    }

    @Test func userCancelDoesNotFlagRefresh() async throws {
        let (unlock, keyring, _, _) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        keyring.failNextDecrypt(with: .cancelled)
        await #expect(throws: BiometricError.cancelled) { _ = try await unlock.unlock(accountID: account, prompt: "x") }
        #expect(!unlock.needsRefresh(accountID: account))
    }

    /// While the Face ID sheet is up, the extension unlocks with the password (newer record): the
    /// refresh flag goes onto that record, never onto the one read before the sheet.
    @Test func refreshFlagKeepsANewerRecord() async throws {
        let keyring = FakeEnclaveKeyring()
        let keychain = InMemoryKeychain()
        let clock = FakeClock()
        let app = BiometricUnlock(keyring: keyring, keychain: keychain, clock: clock, policy: BiometricPolicy())
        let extensionSide = BiometricUnlock(keyring: keyring, keychain: keychain, clock: clock, policy: BiometricPolicy())
        try app.enroll(auk: auk, accountID: account, allowWatch: false)
        let enrolledAt = clock.now
        let accountID = account
        keyring.duringNextDecrypt {
            clock.advance(86400)
            try? extensionSide.notePasswordUnlock(accountID: accountID)
        }
        keyring.failNextDecrypt(with: .failed(code: -3))
        await #expect(throws: BiometricError.passwordRequired(reason: .unverified)) {
            _ = try await app.unlock(accountID: account, prompt: "x")
        }
        #expect(app.needsRefresh(accountID: account))
        #expect(app.passwordDueDate(accountID: account) == enrolledAt.addingTimeInterval(15 * 86400))
    }

    @Test func unknownNonEnclaveErrorKeepsEnrollment() async throws {
        let unlock = BiometricUnlock(
            keyring: ThrowingKeyring(error: NSError(domain: "com.apple.unknown", code: 42)),
            keychain: InMemoryKeychain(), clock: FakeClock())
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        await #expect(throws: BiometricError.passwordRequired(reason: .unverified)) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
        #expect(unlock.isEnrolled(accountID: account))
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

    /// An extension whose sandbox refuses `kern.bootsessionuuid` reads an empty id: the boot time
    /// decides instead, never "rebooted" by default.
    @Test func emptyBootSessionIsNotAReboot() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.setBoot("")
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
        #expect(unlock.isEnrolled(accountID: account))
    }

    @Test func enrollmentWrittenWithoutBootSessionIsReadByTheApp() async throws {
        let (unlock, _, _, clock) = make()
        clock.setBoot("")
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.setBoot("boot-1")
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
    }

    @Test func emptyBootSessionStillSeesARebootByBootTime() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.reboot()
        clock.setBoot("")
        await expectPassword(.rebooted, unlock)
    }

    @Test func bootTimeJitterIsTheSameBoot() async throws {
        let (unlock, _, _, clock) = make()
        clock.setBoot("")
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.setBootTime(clock.bootTime.map { $0.addingTimeInterval(2) })
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
    }

    /// Neither a boot session id nor a boot time: unknown, one password, enrollment kept; that
    /// password unlock records the boot again.
    @Test func unknownBootAsksPasswordAndKeepsEnrollment() async throws {
        let (unlock, _, _, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        clock.setBoot("")
        clock.setBootTime(nil)
        await #expect(throws: BiometricError.passwordRequired(reason: .unverified)) {
            _ = try await unlock.unlock(accountID: account, prompt: "x")
        }
        #expect(unlock.isEnrolled(accountID: account))
        clock.setBootTime(Date(timeIntervalSince1970: 1_990_000))
        try unlock.notePasswordUnlock(accountID: account)
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
    }

    @Test func recordOfAnOlderBuildStillDecodes() async throws {
        let (unlock, _, keychain, clock) = make()
        try unlock.enroll(auk: auk, accountID: account, allowWatch: false)
        let json = try #require(try keychain.read("biometric.enrollment.\(account)"))
        var object = try #require(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        object.removeValue(forKey: "bootTime")
        object.removeValue(forKey: "needsRefresh")
        try keychain.write("biometric.enrollment.\(account)", try JSONSerialization.data(withJSONObject: object))
        #expect(unlock.isEnrolled(accountID: account))
        #expect(try await unlock.unlock(accountID: account, prompt: "x") == auk)
        clock.reboot()
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

/// Keyring whose decryption throws an error that is not an `EnclaveError`.
private struct ThrowingKeyring: EnclaveKeyring {
    let inner = FakeEnclaveKeyring()
    let error: NSError
    var isAvailable: Bool { true }
    func createKey(tag: String, allowWatch: Bool) throws { try inner.createKey(tag: tag, allowWatch: allowWatch) }
    func encrypt(_ data: Data, tag: String) throws -> Data { try inner.encrypt(data, tag: tag) }
    func decrypt(_ data: Data, tag: String, prompt: String) async throws -> Data { throw error }
    func deleteKey(tag: String) throws { try inner.deleteKey(tag: tag) }
}

@Suite("Secure Enclave error classification")
struct EnclaveErrorClassificationTests {
    static let token = SecureEnclaveKeyring.tokenErrorDomain

    @Test(arguments: [
        (token, -4, EnclaveError.cancelled),
        (token, -9, .interrupted),
        (token, -5, .authenticationFailed),
        (token, -6, .keyInvalidated),
        (token, -10, .keyInvalidated),
        (token, -3, .failed(code: -3)),
        (token, -7, .failed(code: -7)),
        (LAError.errorDomain, LAError.Code.userCancel.rawValue, .cancelled),
        (LAError.errorDomain, LAError.Code.systemCancel.rawValue, .interrupted),
        (LAError.errorDomain, LAError.Code.appCancel.rawValue, .interrupted),
        (LAError.errorDomain, LAError.Code.notInteractive.rawValue, .interrupted),
        (LAError.errorDomain, LAError.Code.userFallback.rawValue, .userFallback),
        (LAError.errorDomain, LAError.Code.authenticationFailed.rawValue, .authenticationFailed),
        (LAError.errorDomain, LAError.Code.biometryLockout.rawValue, .biometryLockout),
        (LAError.errorDomain, LAError.Code.biometryNotEnrolled.rawValue, .biometryNotEnrolled),
        (LAError.errorDomain, LAError.Code.biometryNotAvailable.rawValue, .unavailable),
        (NSOSStatusErrorDomain, Int(errSecUserCanceled), .cancelled),
        (NSOSStatusErrorDomain, Int(errSecItemNotFound), .keyInvalidated),
        (NSOSStatusErrorDomain, Int(errSecAuthFailed), .authenticationFailed),
        (NSOSStatusErrorDomain, Int(errSecInteractionNotAllowed), .failed(code: errSecInteractionNotAllowed)),
        ("com.apple.unknown", 7, .failed(code: 7)),
    ] as [(String, Int, EnclaveError)])
    func mapsTopLevelError(domain: String, code: Int, expected: EnclaveError) {
        #expect(SecureEnclaveKeyring.classify(NSError(domain: domain, code: code)) == expected)
    }

    /// The Secure Enclave wraps the LocalAuthentication answer in a CryptoTokenKit or OSStatus error.
    @Test(arguments: [
        (LAError.Code.userCancel, EnclaveError.cancelled),
        (.userFallback, .userFallback),
        (.biometryLockout, .biometryLockout),
        (.authenticationFailed, .authenticationFailed),
    ] as [(LAError.Code, EnclaveError)])
    func followsNestedLAError(code: LAError.Code, expected: EnclaveError) {
        let inner = NSError(domain: LAError.errorDomain, code: code.rawValue)
        let middle = NSError(domain: "com.apple.unknown", code: -1, userInfo: [NSUnderlyingErrorKey: inner])
        let outer = NSError(domain: NSOSStatusErrorDomain, code: -26276, userInfo: [NSUnderlyingErrorKey: middle])
        #expect(SecureEnclaveKeyring.classify(outer) == expected)
    }

    @Test func unknownChainKeepsTheTopLevelCode() {
        let inner = NSError(domain: "com.apple.other", code: 3)
        let outer = NSError(domain: Self.token, code: -3, userInfo: [NSUnderlyingErrorKey: inner])
        #expect(SecureEnclaveKeyring.classify(outer) == .failed(code: -3))
    }
}
