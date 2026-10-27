import Foundation
import Security

/// Generic-password items in the data protection keychain,
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Exercised by the apps only.
///
/// Without the keychain entitlement (unsigned or ad hoc signed local build) the data
/// protection keychain refuses writes with `errSecMissingEntitlement` (-34018) but
/// answers lookups with `errSecItemNotFound` (-25300), never -34018. Debug builds then
/// write to the classic (file) keychain without access group, and every lookup that
/// finds nothing in the data protection keychain also looks there; deletes clear both.
/// Release builds only ever use the data protection keychain.
public struct SystemKeychain: KeychainStore {
    public static let missingEntitlement: OSStatus = -34018

    public let service: String
    public let accessGroup: String?

    /// The app's service. Tests use their own (`me.somalabs.onepass.uitest`, `me.somalabs.onepass.tests.*`).
    public static let defaultService = "me.somalabs.onepass"

    public init(service: String = SystemKeychain.defaultService, accessGroup: String?) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public func read(_ key: String) throws -> Data? {
        try lookup { legacy in
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

    /// Attributes only: the secret data is never loaded.
    public func contains(_ key: String) throws -> Bool {
        try lookup { legacy -> Bool? in
            var query = baseQuery(key, legacy: legacy)
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess: return true
            case errSecItemNotFound: return nil
            default: throw KeychainError.unexpectedStatus(status)
            }
        } ?? false
    }

    public func write(_ key: String, _ data: Data) throws {
        try withFallback { legacy in
            let query = baseQuery(key, legacy: legacy)
            let update: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            ]
            var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            if status == errSecItemNotFound {
                var add = query
                add.merge(update) { _, new in new }
                status = SecItemAdd(add as CFDictionary, nil)
                if status == errSecDuplicateItem {
                    // Lost a race with another writer: the item exists now.
                    status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
                }
            }
            guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
        }
    }

    public func delete(_ key: String) throws {
        let remove = { (legacy: Bool) throws in
            let status = SecItemDelete(baseQuery(key, legacy: legacy) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError.unexpectedStatus(status)
            }
        }
        #if DEBUG
        do {
            try remove(false)
        } catch KeychainError.unexpectedStatus(let status) where status == Self.missingEntitlement {}
        try remove(true)
        #else
        try remove(false)
        #endif
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

    /// A lookup: nil means not found. Debug builds look in the classic keychain when the data
    /// protection keychain has nothing (or refuses), since that is where `write` fell back.
    private func lookup<T>(_ body: (_ legacy: Bool) throws -> T?) throws -> T? {
        #if DEBUG
        do {
            if let found = try body(false) { return found }
        } catch KeychainError.unexpectedStatus(let status) where status == Self.missingEntitlement {}
        return try body(true)
        #else
        return try body(false)
        #endif
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
