import Foundation
import Security

/// Generic-password items in the data protection keychain,
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Exercised by the apps only.
///
/// Without the keychain entitlement (unsigned local build) the data protection
/// keychain answers `errSecMissingEntitlement` (-34018). Debug builds then fall
/// back to the classic keychain without access group; release builds never do.
public struct SystemKeychain: KeychainStore {
    public static let missingEntitlement: OSStatus = -34018

    public let service: String
    public let accessGroup: String?

    public init(service: String = "me.somalabs.onepass", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func read(_ key: String) throws -> Data? {
        try withFallback { legacy in
            var query = baseQuery(key, legacy: legacy)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess: return result as? Data
            case errSecItemNotFound: return nil
            default: throw KeychainError.unexpectedStatus(status)
            }
        }
    }

    public func write(_ key: String, _ data: Data) throws {
        try withFallback { legacy in
            let query = baseQuery(key, legacy: legacy)
            let update = [kSecValueData as String: data]
            var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            if status == errSecItemNotFound {
                var add = query
                add[kSecValueData as String] = data
                add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                status = SecItemAdd(add as CFDictionary, nil)
            }
            guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
        }
    }

    public func delete(_ key: String) throws {
        try withFallback { legacy in
            let status = SecItemDelete(baseQuery(key, legacy: legacy) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError.unexpectedStatus(status)
            }
        }
    }

    private func baseQuery(_ key: String, legacy: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        if !legacy {
            query[kSecUseDataProtectionKeychain as String] = true
            if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        }
        return query
    }

    private func withFallback<T>(_ body: (_ legacy: Bool) throws -> T) throws -> T {
        #if DEBUG
        do {
            return try body(false)
        } catch KeychainError.unexpectedStatus(let status) where status == Self.missingEntitlement {
            return try body(true)
        }
        #else
        return try body(false)
        #endif
    }
}
