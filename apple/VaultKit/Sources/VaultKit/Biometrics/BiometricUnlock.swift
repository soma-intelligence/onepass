import Foundation

public enum EnclaveError: Error, Equatable, Sendable {
    /// Key gone or invalidated (biometry set changed).
    case keyInvalidated
    case cancelled
    /// The user chose the password fallback in the system sheet.
    case userFallback
    case biometryNotEnrolled
    case biometryLockout
    case unavailable
    case failed(code: Int32)
}

/// Secure Enclave key operations. Real implementation: `SecureEnclaveKeyring`.
public protocol EnclaveKeyring: Sendable {
    var isAvailable: Bool { get }
    func createKey(tag: String, allowWatch: Bool) throws
    func encrypt(_ data: Data, tag: String) throws -> Data
    func decrypt(_ data: Data, tag: String, prompt: String) async throws -> Data
    func deleteKey(tag: String) throws
}

/// Wraps the 32-byte AUK with a Secure Enclave key so Face ID / Touch ID /
/// Apple Watch can unlock without the master password, within `BiometricPolicy`.
public final class BiometricUnlock: Sendable {
    private let keyring: any EnclaveKeyring
    private let keychain: any KeychainStore
    private let clock: any BootClock
    private let policy: BiometricPolicy

    public init(keyring: any EnclaveKeyring, keychain: any KeychainStore, clock: any BootClock, policy: BiometricPolicy = BiometricPolicy()) {
        self.keyring = keyring
        self.keychain = keychain
        self.clock = clock
        self.policy = policy
    }

    public var isAvailable: Bool { keyring.isAvailable }

    static func tag(_ accountID: String) -> String { "me.somalabs.onepass.auk.\(accountID)" }
    static func storeKey(_ accountID: String) -> String { "biometric.enrollment.\(accountID)" }

    /// nil when nothing is stored or the record is corrupt (corrupt records are dropped).
    /// A keychain read error (for example a locked keychain) is thrown, never read as "not enrolled".
    private func loadEnrollment(_ accountID: String) throws -> BiometricEnrollment? {
        guard let data = try keychain.read(Self.storeKey(accountID)) else { return nil }
        guard let enrollment = try? JSONDecoder().decode(BiometricEnrollment.self, from: data) else {
            disable(accountID: accountID)
            return nil
        }
        return enrollment
    }

    private func save(_ enrollment: BiometricEnrollment) throws {
        try keychain.write(Self.storeKey(enrollment.accountID), try JSONEncoder().encode(enrollment))
    }

    public func isEnrolled(accountID: String) -> Bool {
        ((try? loadEnrollment(accountID)) ?? nil) != nil
    }

    /// Creates a fresh Secure Enclave key (replacing any previous one) and stores the wrapped AUK.
    public func enroll(auk: Data, accountID: String, allowWatch: Bool) throws {
        guard keyring.isAvailable else { throw BiometricError.unavailable }
        let tag = Self.tag(accountID)
        try? keyring.deleteKey(tag: tag)
        try keyring.createKey(tag: tag, allowWatch: allowWatch)
        do {
            let wrapped = try keyring.encrypt(auk, tag: tag)
            let now = clock.now
            try save(BiometricEnrollment(
                accountID: accountID, wrappedAUK: wrapped, enrolledAt: now,
                lastPasswordAt: now, bootSessionID: clock.bootSessionID))
        } catch {
            try? keyring.deleteKey(tag: tag)
            throw error
        }
    }

    /// Call after every successful master password unlock: restarts the 14 day clock.
    public func notePasswordUnlock(accountID: String) throws {
        guard var enrollment = try loadEnrollment(accountID) else { return }
        enrollment.lastPasswordAt = clock.now
        enrollment.bootSessionID = clock.bootSessionID
        try save(enrollment)
    }

    /// Returns the AUK (the caller wipes it). Throws `passwordRequired` when the policy, a reboot,
    /// a biometry change or any decryption failure forbids biometric unlock; the enrollment is
    /// dropped except when the user merely chose the password or biometry is locked out.
    public func unlock(accountID: String, prompt: String) async throws -> Data {
        guard let enrollment = try loadEnrollment(accountID) else {
            throw BiometricError.passwordRequired(reason: .notEnrolled)
        }
        let boot = clock.bootSessionID
        if boot.isEmpty || boot != enrollment.bootSessionID {
            disable(accountID: accountID)
            throw BiometricError.passwordRequired(reason: .rebooted)
        }
        let elapsed = clock.now.timeIntervalSince(enrollment.lastPasswordAt)
        if elapsed > policy.passwordEvery || elapsed < -policy.clockSkew {
            disable(accountID: accountID)
            throw BiometricError.passwordRequired(reason: .expired)
        }
        do {
            return try await keyring.decrypt(enrollment.wrappedAUK, tag: Self.tag(accountID), prompt: prompt)
        } catch let error as EnclaveError {
            switch error {
            case .cancelled: throw BiometricError.cancelled
            case .unavailable: throw BiometricError.unavailable
            case .userFallback: throw BiometricError.passwordRequired(reason: .userChosePassword)
            case .biometryLockout: throw BiometricError.passwordRequired(reason: .lockedOut)
            case .biometryNotEnrolled, .keyInvalidated, .failed:
                disable(accountID: accountID)
                throw BiometricError.passwordRequired(reason: .invalidated)
            }
        } catch is CancellationError {
            throw BiometricError.cancelled
        } catch {
            // Any other decryption failure (errSecAuthFailed, CryptoTokenKit...) after a biometry change.
            disable(accountID: accountID)
            throw BiometricError.passwordRequired(reason: .invalidated)
        }
    }

    public func disable(accountID: String) {
        try? keychain.delete(Self.storeKey(accountID))
        try? keyring.deleteKey(tag: Self.tag(accountID))
    }
}
