#if DEBUG && targetEnvironment(simulator)
import Foundation
import LocalAuthentication
import Security
import os

/// Debug builds on the Simulator only: the Simulator has no Secure Enclave, so
/// `SecureEnclaveKeyring.isAvailable` is always false there and Face ID unlock could never be
/// exercised (UI tests, recordings). This keyring keeps a software P-256 key in the Simulator's
/// keychain and asks for Face ID with `LAContext` before every decryption, so the simulated
/// biometry (`notifyutil -p com.apple.BiometricKit_Sim.pearl.match`) drives the same
/// `BiometricUnlock` policy and screens as a device. Never compiled into a device or Release build.
public struct SimulatorBiometricKeyring: EnclaveKeyring {
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private static let service = "me.somalabs.onepass.simulator-biometric"
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "biometrics")

    public let accessGroup: String?

    public init(accessGroup: String?) {
        self.accessGroup = accessGroup
    }

    public var isAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    public func createKey(tag: String, allowWatch: Bool) throws {
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let raw = SecKeyCopyExternalRepresentation(key, &error) as Data?
        else { throw EnclaveError.failed(code: -1) }
        try deleteKey(tag: tag)
        var add = query(tag)
        add[kSecValueData as String] = raw
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw EnclaveError.failed(code: status) }
    }

    public func encrypt(_ data: Data, tag: String) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(try loadKey(tag: tag)) else { throw EnclaveError.keyInvalidated }
        var error: Unmanaged<CFError>?
        guard let out = SecKeyCreateEncryptedData(publicKey, Self.algorithm, data as CFData, &error) else {
            throw EnclaveError.failed(code: -1)
        }
        return out as Data
    }

    public func decrypt(_ data: Data, tag: String, prompt: String) async throws -> Data {
        let context = LAContext()
        context.localizedFallbackTitle = String(localized: "biometrics.useMasterPassword", bundle: VaultKitStrings.bundle)
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: prompt)
        } catch let error as NSError {
            let mapped = SecureEnclaveKeyring.classify(error)
            Self.log.notice("simulator biometric refused: \(String(describing: mapped), privacy: .public)")
            throw mapped
        }
        var error: Unmanaged<CFError>?
        guard let out = SecKeyCreateDecryptedData(try loadKey(tag: tag), Self.algorithm, data as CFData, &error) else {
            throw EnclaveError.keyInvalidated
        }
        return out as Data
    }

    public func deleteKey(tag: String) throws {
        let status = SecItemDelete(query(tag) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw EnclaveError.failed(code: status) }
    }

    private func query(_ tag: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: tag,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    private func loadKey(tag: String) throws -> SecKey {
        var read = query(tag)
        read[kSecReturnData as String] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(read as CFDictionary, &item)
        guard status == errSecSuccess, let raw = item as? Data else {
            throw status == errSecItemNotFound ? EnclaveError.keyInvalidated : EnclaveError.failed(code: status)
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(raw as CFData, attributes as CFDictionary, &error) else {
            throw EnclaveError.keyInvalidated
        }
        return key
    }
}
#endif
