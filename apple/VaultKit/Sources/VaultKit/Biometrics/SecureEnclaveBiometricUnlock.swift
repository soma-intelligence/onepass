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
        context.value.localizedFallbackTitle = String(localized: "biometrics.useMasterPassword", bundle: VaultKitStrings.bundle)
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

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "biometrics")

    /// `TKErrorDomain` (CryptoTokenKit), where Secure Enclave key operations report most refusals.
    static let tokenErrorDomain = "CryptoTokenKit"

    /// Logs the error (domain and code only, never data) and classifies it.
    private static func map(_ error: CFError?) -> EnclaveError {
        guard let error else { return .failed(code: -1) }
        let ns = error as Error as NSError
        let mapped = classify(ns)
        let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError
        log.notice(
            "enclave error \(ns.domain, privacy: .public) \(ns.code, privacy: .public) underlying \(underlying?.domain ?? "-", privacy: .public) \(underlying?.code ?? 0, privacy: .public) -> \(String(describing: mapped), privacy: .public)")
        return mapped
    }

    /// Security, CryptoTokenKit and LocalAuthentication errors, following `NSUnderlyingErrorKey`
    /// down to the first one that says something. Only a key that is gone (`errSecItemNotFound`,
    /// token object not found, invalidated device key) or a biometry no longer enrolled counts as an
    /// invalidation; a cancel, a fallback, a lockout or a failed match never does. Only the user's
    /// own cancel is `.cancelled`: one by the app or the system, a non-interactive context or a
    /// token asking for authentication again is `.interrupted`. Anything else is
    /// `.failed`, which `BiometricUnlock` answers with the password while keeping the enrollment.
    static func classify(_ error: NSError) -> EnclaveError {
        var current: NSError? = error
        var depth = 0
        while let ns = current, depth < 4 {
            if let known = classifyOne(ns) { return known }
            current = ns.userInfo[NSUnderlyingErrorKey] as? NSError
            depth += 1
        }
        return .failed(code: Int32(truncatingIfNeeded: error.code))
    }

    private static func classifyOne(_ ns: NSError) -> EnclaveError? {
        switch ns.domain {
        case LAError.errorDomain:
            switch LAError.Code(rawValue: ns.code) {
            case .userCancel: return .cancelled
            case .appCancel, .systemCancel, .notInteractive: return .interrupted
            case .userFallback: return .userFallback
            case .authenticationFailed: return .authenticationFailed
            case .biometryNotEnrolled: return .biometryNotEnrolled
            case .biometryLockout: return .biometryLockout
            case .biometryNotAvailable: return .unavailable
            default: return nil
            }
        case tokenErrorDomain:
            switch ns.code {
            case -4: return .cancelled  // canceled by user
            case -9: return .interrupted  // authentication needed
            case -5: return .authenticationFailed
            case -6, -10: return .keyInvalidated  // object not found, invalidated device key
            default: return nil
            }
        case NSOSStatusErrorDomain:
            switch OSStatus(ns.code) {
            case errSecUserCanceled: return .cancelled
            case errSecItemNotFound: return .keyInvalidated
            case errSecAuthFailed: return .authenticationFailed
            default: return nil
            }
        default:
            return nil
        }
    }
}

/// LAContext is thread safe; this only carries it into the detached task and the cancel handler.
private final class ContextBox: @unchecked Sendable {
    let value: LAContext
    init(_ value: LAContext) { self.value = value }
}
