import Foundation

public enum EnclaveError: Error, Equatable, Sendable {
    /// Key gone or invalidated (biometry set changed).
    case keyInvalidated
    case cancelled
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

    private func loadEnrollment(_ accountID: String) -> BiometricEnrollment? {
        guard let data = try? keychain.read(Self.storeKey(accountID)) else { return nil }
        return try? JSONDecoder().decode(BiometricEnrollment.self, from: data)
    }

    public func isEnrolled(accountID: String) -> Bool {
        loadEnrollment(accountID) != nil
    }

    /// Creates a fresh Secure Enclave key (replacing any previous one) and stores the wrapped AUK.
    public func enroll(auk: Data, accountID: String, allowWatch: Bool) throws {
        guard keyring.isAvailable else { throw BiometricError.unavailable }
        let tag = Self.tag(accountID)
        try? keyring.deleteKey(tag: tag)
        try keyring.createKey(tag: tag, allowWatch: allowWatch)
        let wrapped: Data
        do {
            wrapped = try keyring.encrypt(auk, tag: tag)
        } catch {
            try? keyring.deleteKey(tag: tag)
            throw error
        }
        let now = clock.now
        let enrollment = BiometricEnrollment(
            accountID: accountID, wrappedAUK: wrapped, enrolledAt: now,
            lastPasswordAt: now, bootTime: clock.bootTime)
        try keychain.write(Self.storeKey(accountID), try JSONEncoder().encode(enrollment))
    }

    /// Call after every successful master password unlock: restarts the 14 day clock.
    public func notePasswordUnlock(accountID: String) throws {
        guard var enrollment = loadEnrollment(accountID) else { return }
        enrollment.lastPasswordAt = clock.now
        enrollment.bootTime = clock.bootTime
        try keychain.write(Self.storeKey(accountID), try JSONEncoder().encode(enrollment))
    }

    /// Returns the AUK (the caller wipes it). Throws `passwordRequired` and drops the
    /// enrollment when the policy, a reboot or a biometry change forbids biometric unlock.
    public func unlock(accountID: String, prompt: String) async throws -> Data {
        guard let enrollment = loadEnrollment(accountID) else {
            throw BiometricError.passwordRequired(reason: .notEnrolled)
        }
        if abs(enrollment.bootTime.timeIntervalSince(clock.bootTime)) > policy.bootTolerance {
            disable(accountID: accountID)
            throw BiometricError.passwordRequired(reason: .rebooted)
        }
        if clock.now.timeIntervalSince(enrollment.lastPasswordAt) > policy.passwordEvery {
            disable(accountID: accountID)
            throw BiometricError.passwordRequired(reason: .expired)
        }
        do {
            return try await keyring.decrypt(enrollment.wrappedAUK, tag: Self.tag(accountID), prompt: prompt)
        } catch EnclaveError.keyInvalidated {
            disable(accountID: accountID)
            throw BiometricError.passwordRequired(reason: .invalidated)
        } catch EnclaveError.cancelled {
            throw BiometricError.cancelled
        } catch EnclaveError.unavailable {
            throw BiometricError.unavailable
        } catch EnclaveError.failed(let code) {
            throw BiometricError.failed(code: code)
        }
    }

    public func disable(accountID: String) {
        try? keychain.delete(Self.storeKey(accountID))
        try? keyring.deleteKey(tag: Self.tag(accountID))
    }
}
