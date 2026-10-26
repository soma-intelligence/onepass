import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Real Secure Enclave keyring (P-256, ECIES cofactor X9.63 SHA-256 AES-GCM).
/// Exercised by the apps only: tests use `FakeEnclaveKeyring`.
public struct SecureEnclaveKeyring: EnclaveKeyring {
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    public init() {}

    public var isAvailable: Bool {
        guard SecureEnclave.isAvailable else { return false }
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    public func createKey(tag: String, allowWatch: Bool) throws {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage, .biometryCurrentSet]
        #if os(macOS)
        if allowWatch { flags = [.privateKeyUsage, .or, .biometryCurrentSet, .watch] }
        #endif
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else { throw Self.map(error?.takeRetainedValue()) }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
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
        // SecKey decryption blocks while the system biometric sheet is up.
        try await Task.detached(priority: .userInitiated) {
            let context = LAContext()
            context.localizedReason = prompt
            let key = try loadKey(tag: tag, context: context)
            var error: Unmanaged<CFError>?
            guard let out = SecKeyCreateDecryptedData(key, Self.algorithm, data as CFData, &error) else {
                throw Self.map(error?.takeRetainedValue())
            }
            return out as Data
        }.value
    }

    public func deleteKey(tag: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw EnclaveError.failed(code: status)
        }
    }

    private func loadKey(tag: String, context: LAContext?) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
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

    private static func map(_ error: CFError?) -> EnclaveError {
        guard let error else { return .failed(code: -1) }
        let ns = error as Error as NSError
        if ns.domain == LAError.errorDomain {
            switch LAError.Code(rawValue: ns.code) {
            case .userCancel, .appCancel, .systemCancel: return .cancelled
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout: return .unavailable
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
