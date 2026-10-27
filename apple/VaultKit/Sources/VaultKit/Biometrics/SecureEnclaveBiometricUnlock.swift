import CryptoKit
import Foundation
import LocalAuthentication
import Security
import os

/// Real Secure Enclave keyring (P-256, ECIES cofactor X9.63 SHA-256 AES-GCM).
/// Exercised by the apps only: tests use `FakeEnclaveKeyring`.
public struct SecureEnclaveKeyring: EnclaveKeyring {
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    public let accessGroup: String?
    /// macOS: availability also accepts an Apple Watch (`allowWatchUnlock` setting).
    public let allowWatch: Bool

    public init(accessGroup: String?, allowWatch: Bool = false) {
        self.accessGroup = accessGroup
        self.allowWatch = allowWatch
    }

    public var isAvailable: Bool {
        guard SecureEnclave.isAvailable else { return false }
        var error: NSError?
        #if os(macOS)
        if allowWatch {
            return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometricsOrCompanion, error: &error)
        }
        #endif
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    /// Probed once per access group and process: whether the keychain takes items from this build.
    private static let storeProbes = OSAllocatedUnfairLock<[String: Bool]>(initialState: [:])

    public var canStoreKeys: Bool {
        let key = accessGroup ?? ""
        if let known = Self.storeProbes.withLock({ $0[key] }) { return known }
        let accepted = Self.keychainAcceptsItems(accessGroup: accessGroup)
        Self.storeProbes.withLock { $0[key] = accepted }
        return accepted
    }

    /// Adds then removes a throwaway item in the data protection keychain. Only a missing
    /// entitlement (`-34018`, unsigned or ad hoc build) answers false: any other refusal (a locked
    /// keychain for example) is left to the enrollment, which reports it.
    private static func keychainAcceptsItems(accessGroup: String?) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "me.somalabs.onepass.enclave-probe",
            kSecAttrAccount as String: "probe",
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        var add = query
        add[kSecValueData as String] = Data([0])
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecSuccess { SecItemDelete(query as CFDictionary) }
        return status != errSecMissingEntitlement
    }

    /// Data protection keychain on every query (macOS would otherwise use the file keychain).
    private func scoped(_ query: [String: Any]) -> [String: Any] {
        var query = query
        query[kSecUseDataProtectionKeychain as String] = true
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    public func createKey(tag: String, allowWatch: Bool) throws {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage, .biometryCurrentSet]
        #if os(macOS)
        if allowWatch { flags = [.privateKeyUsage, .or, .biometryCurrentSet, .companion] }
        #endif
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else { throw Self.map(error?.takeRetainedValue()) }
        let attributes = scoped([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: scoped([
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: access,
            ]),
        ])
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw Self.map(error?.takeRetainedValue())
        }
    }

    public func encrypt(_ data: Data, tag: String) throws -> Data {
        let key = try loadKey(tag: tag, context: nil)
        guard let publicKey = SecKeyCopyPublicKey(key) else { throw EnclaveError.keyInvalidated }
        var error: Unmanaged<CFError>?
        guard let out = SecKeyCreateEncryptedData(publicKey, Self.algorithm, data as CFData, &error) else {
            throw Self.map(error?.takeRetainedValue())
        }
        return out as Data
    }

    public func decrypt(_ data: Data, tag: String, prompt: String) async throws -> Data {
        let context = ContextBox(LAContext())
        context.value.localizedReason = prompt
        // SecKey decryption blocks while the system biometric sheet is up: run it off the
        // caller's thread, and dismiss the sheet if the calling task is cancelled.
        return try await withTaskCancellationHandler {
            try await Task.detached(priority: .userInitiated) {
                let key = try loadKey(tag: tag, context: context.value)
                var error: Unmanaged<CFError>?
                guard let out = SecKeyCreateDecryptedData(key, Self.algorithm, data as CFData, &error) else {
                    throw Self.map(error?.takeRetainedValue())
                }
                return out as Data
            }.value
        } onCancel: {
            context.value.invalidate()
        }
    }

    public func deleteKey(tag: String) throws {
        let query = scoped([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ])
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw EnclaveError.failed(code: status)
        }
    }

    private func loadKey(tag: String, context: LAContext?) throws -> SecKey {
        var query = scoped([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ])
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let item else { throw EnclaveError.keyInvalidated }
            return item as! SecKey  // SecItemCopyMatching with kSecReturnRef on a key class yields a SecKey
        case errSecItemNotFound: throw EnclaveError.keyInvalidated
        case errSecUserCanceled: throw EnclaveError.cancelled
        default: throw EnclaveError.failed(code: status)
        }
    }

    /// Maps Security / LocalAuthentication errors. Anything not listed here is reported as
    /// `.failed`, which `BiometricUnlock` treats as an invalidated key (password fallback).
    private static func map(_ error: CFError?) -> EnclaveError {
        guard let error else { return .failed(code: -1) }
        let ns = error as Error as NSError
        if ns.domain == LAError.errorDomain {
            switch LAError.Code(rawValue: ns.code) {
            case .userCancel, .appCancel, .systemCancel: return .cancelled
            case .userFallback: return .userFallback
            case .biometryNotEnrolled: return .biometryNotEnrolled
            case .biometryLockout: return .biometryLockout
            case .biometryNotAvailable: return .unavailable
            default: break
            }
        }
        if ns.domain == NSOSStatusErrorDomain {
            switch OSStatus(ns.code) {
            case errSecUserCanceled: return .cancelled
            case errSecItemNotFound: return .keyInvalidated
            default: break
            }
        }
        return .failed(code: Int32(truncatingIfNeeded: ns.code))
    }
}

/// LAContext is thread safe; this only carries it into the detached task and the cancel handler.
private final class ContextBox: @unchecked Sendable {
    let value: LAContext
    init(_ value: LAContext) { self.value = value }
}
