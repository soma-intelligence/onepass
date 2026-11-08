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
/// Release builds write to the data protection keychain only, but a lookup that finds nothing in
/// the access group still looks without one: an item a Debug build of the same app left in another
/// group this app is entitled to is found, copied into the access group and removed from where it
/// was, so switching build never loses the Secret Key. The classic (file) keychain is searched for
/// the Secret Key only (`adoptsFromFileKeychain`): any process of the same user can add an item
/// there, so drafts, pairings and seeds found there are never trusted.
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
        let find = { (legacy: Bool) throws -> Data? in
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
        #if DEBUG
        return try lookup(find)
        #else
        if let found = try find(false) { return found }
        // An item a Debug build left outside the access group: copied into it, then removed from
        // its own group (named exactly, so the new copy is never matched).
        guard accessGroup != nil, let stray = try strayItem(key) else { return nil }
        try write(key, stray.data)
        var remove = strayQuery(key, fileKeychain: stray.fileKeychain)
        if let group = stray.group { remove[kSecAttrAccessGroup as String] = group }
        _ = SecItemDelete(remove as CFDictionary)
        return stray.data
        #endif
    }

    /// Keys a Release build may adopt from the classic (file) keychain: the Secret Key only, the item
    /// the migration exists for. A planted Secret Key gains an attacker nothing (it does not match the
    /// account's keys, so the unlock fails). Every other key (generated-password drafts, browser
    /// pairings, the RNG seed) is read from the data protection keychain only, whose access groups
    /// the system enforces.
    static func adoptsFromFileKeychain(_ key: String) -> Bool {
        key.hasPrefix("secretkey.")
    }

    /// The item for `key` outside `accessGroup`: first in the other data protection keychain groups
    /// this app is entitled to, then (Secret Key only) in the classic keychain.
    private func strayItem(_ key: String) throws -> (data: Data, group: String?, fileKeychain: Bool)? {
        if let found = try strayItem(key, fileKeychain: false) { return found }
        guard Self.adoptsFromFileKeychain(key) else { return nil }
        return try strayItem(key, fileKeychain: true)
    }

    private func strayItem(_ key: String, fileKeychain: Bool) throws -> (data: Data, group: String?, fileKeychain: Bool)? {
        // Attributes of every match first (data cannot be asked for all matches at once).
        var query = strayQuery(key, fileKeychain: fileKeychain)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: break
        case errSecItemNotFound: return nil
        default: throw KeychainError.unexpectedStatus(status)
        }
        let groups = ((result as? [[String: Any]]) ?? []).map { $0[kSecAttrAccessGroup as String] as? String }
        guard let found = groups.first(where: { $0 != accessGroup }) else { return nil }
        var one = strayQuery(key, fileKeychain: fileKeychain)
        if let found { one[kSecAttrAccessGroup as String] = found }
        one[kSecReturnData as String] = true
        one[kSecMatchLimit as String] = kSecMatchLimitOne
        var data: CFTypeRef?
        let read = SecItemCopyMatching(one as CFDictionary, &data)
        guard read == errSecSuccess, let bytes = data as? Data else {
            if read == errSecItemNotFound { return nil }
            throw KeychainError.unexpectedStatus(read)
        }
        return (bytes, found, fileKeychain)
    }

    /// No access group: the data protection keychain (every group this app is entitled to), or the
    /// classic keychain when `fileKeychain` is true.
    private func strayQuery(_ key: String, fileKeychain: Bool) -> [String: Any] {
        var query = baseQuery(key, legacy: true)
        if !fileKeychain { query[kSecUseDataProtectionKeychain as String] = true }
        return query
    }

    /// Attributes only: the secret data is never loaded.
    public func contains(_ key: String) throws -> Bool {
        #if !DEBUG
        // A Debug build's item outside the access group counts (`read` moves it).
        if accessGroup != nil, try strayItem(key) != nil { return true }
        #endif
        return try lookup { legacy -> Bool? in
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
        try write(key, data, accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    public func writeAfterFirstUnlock(_ key: String, _ data: Data) throws {
        try write(key, data, accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    }

    private func write(_ key: String, _ data: Data, accessible: CFString) throws {
        try withFallback { legacy in
            let query = baseQuery(key, legacy: legacy)
            let update: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessible,
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
