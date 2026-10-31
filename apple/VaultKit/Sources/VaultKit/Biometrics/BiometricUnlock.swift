import Foundation
import os

public enum EnclaveError: Error, Equatable, Sendable {
    /// Key gone or invalidated (biometry set changed).
    case keyInvalidated
    case cancelled
    /// The user chose the password fallback in the system sheet.
    case userFallback
    /// The face or finger was not recognized (no invalidation).
    case authenticationFailed
    case biometryNotEnrolled
    case biometryLockout
    case unavailable
    case failed(code: Int32)
}

/// Secure Enclave key operations. Real implementation: `SecureEnclaveKeyring`.
public protocol EnclaveKeyring: Sendable {
    /// A Secure Enclave and an enrolled biometry (or an Apple Watch when allowed).
    var isAvailable: Bool { get }
    /// The keychain accepts Secure Enclave keys from this build. False for an unsigned or ad hoc
    /// signed build: without an application identifier the keychain refuses every key (`-34018`).
    var canStoreKeys: Bool { get }
    func createKey(tag: String, allowWatch: Bool) throws
    func encrypt(_ data: Data, tag: String) throws -> Data
    func decrypt(_ data: Data, tag: String, prompt: String) async throws -> Data
    func deleteKey(tag: String) throws
}

extension EnclaveKeyring {
    public var canStoreKeys: Bool { true }
}

/// Why biometric unlock can or cannot be offered on this device and build.
public enum BiometricAvailability: Sendable, Equatable {
    case available
    /// No Secure Enclave, or no fingerprint, face or Watch set up in the system.
    case noBiometry
    /// The hardware is there but this build cannot keep a Secure Enclave key (unsigned build).
    case keychainRefused
}

/// Wraps the 32-byte AUK with a Secure Enclave key so Face ID / Touch ID /
/// Apple Watch can unlock without the master password, within `BiometricPolicy`.
public final class BiometricUnlock: Sendable {
    private let keyring: any EnclaveKeyring
    private let keychain: any KeychainStore
    private let clock: any BootClock
    private let policy: BiometricPolicy
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "biometrics")
    /// Two readings of the boot time closer than this are the same boot (a reboot takes longer).
    static let bootTimeTolerance: TimeInterval = 5

    public init(keyring: any EnclaveKeyring, keychain: any KeychainStore, clock: any BootClock, policy: BiometricPolicy = BiometricPolicy()) {
        self.keyring = keyring
        self.keychain = keychain
        self.clock = clock
        self.policy = policy
    }

    public var availability: BiometricAvailability {
        guard keyring.isAvailable else { return .noBiometry }
        return keyring.canStoreKeys ? .available : .keychainRefused
    }

    /// Enrollment and biometric unlock can work: hardware, biometry set up and a usable keychain.
    public var isAvailable: Bool { availability == .available }

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

    /// When the master password is asked again (last password entry plus the policy delay), for the
    /// unlock screen. Nil when not enrolled or the keychain cannot answer.
    public func passwordDueDate(accountID: String) -> Date? {
        guard let enrollment = (try? loadEnrollment(accountID)) ?? nil else { return nil }
        return enrollment.lastPasswordAt.addingTimeInterval(policy.passwordEvery)
    }

    /// Creates a fresh Secure Enclave key (replacing any previous one) and stores the wrapped AUK.
    public func enroll(auk: Data, accountID: String, allowWatch: Bool) throws {
        guard isAvailable else { throw BiometricError.unavailable }
        let tag = Self.tag(accountID)
        try? keyring.deleteKey(tag: tag)
        try keyring.createKey(tag: tag, allowWatch: allowWatch)
        do {
            let wrapped = try keyring.encrypt(auk, tag: tag)
            let now = clock.now
            try save(BiometricEnrollment(
                accountID: accountID, wrappedAUK: wrapped, enrolledAt: now,
                lastPasswordAt: now, bootSessionID: clock.bootSessionID, bootTime: clock.bootTime))
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
        enrollment.bootTime = clock.bootTime
        try save(enrollment)
    }

    /// The last biometric unlock failed for a reason that kept the enrollment but may hide a stale
    /// key (unknown error, failed match): the next password unlock wraps the AUK again, silently.
    public func needsRefresh(accountID: String) -> Bool {
        ((try? loadEnrollment(accountID)) ?? nil)?.needsRefresh == true
    }

    private func markForRefresh(_ enrollment: BiometricEnrollment) {
        var enrollment = enrollment
        enrollment.needsRefresh = true
        try? save(enrollment)
    }

    enum BootMatch: Equatable { case same, rebooted, unknown }

    /// The boot session id when both readings have one, else the boot time. An empty id (a sandbox
    /// that refuses the sysctl) is never read as a reboot: without a boot time either, it is unknown.
    func bootMatch(_ enrollment: BiometricEnrollment) -> BootMatch {
        let id = clock.bootSessionID
        if !id.isEmpty, !enrollment.bootSessionID.isEmpty {
            return id == enrollment.bootSessionID ? .same : .rebooted
        }
        if let now = clock.bootTime, let then = enrollment.bootTime {
            return abs(now.timeIntervalSince(then)) <= Self.bootTimeTolerance ? .same : .rebooted
        }
        return .unknown
    }

    /// Returns the AUK (the caller wipes it). Throws `passwordRequired` when the policy, a reboot,
    /// a biometry change or a decryption failure forbids biometric unlock. The enrollment is dropped
    /// only on proof: a reboot, the 14 days, a key gone or a biometry no longer enrolled. A cancel, a
    /// fallback, a lockout, a failed match, an unknown boot or an unknown error keep it (one password).
    public func unlock(accountID: String, prompt: String) async throws -> Data {
        guard let enrollment = try loadEnrollment(accountID) else {
            throw BiometricError.passwordRequired(reason: .notEnrolled)
        }
        switch bootMatch(enrollment) {
        case .same:
            break
        case .rebooted:
            disable(accountID: accountID, reason: "rebooted")
            throw BiometricError.passwordRequired(reason: .rebooted)
        case .unknown:
            Self.log.notice("boot unknown (no boot session id, no boot time): password asked, enrollment kept")
            throw BiometricError.passwordRequired(reason: .unverified)
        }
        let elapsed = clock.now.timeIntervalSince(enrollment.lastPasswordAt)
        if elapsed > policy.passwordEvery || elapsed < -policy.clockSkew {
            disable(accountID: accountID, reason: "expired")
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
            case .authenticationFailed:
                markForRefresh(enrollment)
                throw BiometricError.passwordRequired(reason: .unverified)
            case .biometryNotEnrolled, .keyInvalidated:
                disable(accountID: accountID, reason: "invalidated")
                throw BiometricError.passwordRequired(reason: .invalidated)
            case .failed(let code):
                Self.log.error("biometric unlock failed \(code, privacy: .public): password asked, enrollment kept")
                markForRefresh(enrollment)
                throw BiometricError.passwordRequired(reason: .unverified)
            }
        } catch is CancellationError {
            throw BiometricError.cancelled
        } catch {
            let ns = error as NSError
            Self.log.error("biometric unlock failed \(ns.domain, privacy: .public) \(ns.code, privacy: .public): password asked, enrollment kept")
            markForRefresh(enrollment)
            throw BiometricError.passwordRequired(reason: .unverified)
        }
    }

    private func disable(accountID: String, reason: String) {
        Self.log.notice("biometric enrollment dropped: \(reason, privacy: .public)")
        disable(accountID: accountID)
    }

    public func disable(accountID: String) {
        try? keychain.delete(Self.storeKey(accountID))
        try? keyring.deleteKey(tag: Self.tag(accountID))
    }
}
