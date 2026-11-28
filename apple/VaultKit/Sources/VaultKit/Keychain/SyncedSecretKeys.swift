import Foundation
import Security
import Synchronization

/// The copy of an account's Secret Key that iCloud Keychain carries to the user's other devices
/// (spec 2026-11-25 onboarding iCloud join). A new device that finds the account in iCloud and its
/// key here asks for the master password only. The device-only copy (`SecretKeyVault`) stays the one
/// unlocks read; this one is written after an unlock or a creation on a personal device, and read
/// only to join.
///
/// Trade-off: whoever holds the Apple ID and the passcode of one of the user's devices (which open
/// iCloud Keychain) needs only the master password.
public protocol SyncedSecretKeyStore: Sendable {
    func read(accountID: String) throws -> Data?
    /// The account owner's first name, stored beside the key (not secret): the new device's first
    /// screen names the account it found before any unlock.
    func owner(accountID: String) throws -> String?
    func write(accountID: String, _ data: Data, owner: String?) throws
    func delete(accountID: String) throws
}

/// Synchronizable generic-password items in the data protection keychain, shared access group,
/// `kSecAttrAccessibleWhenUnlocked` (a synchronizable item cannot be "this device only").
public struct ICloudKeychainSecretKeys: SyncedSecretKeyStore {
    public static let service = "me.somalabs.onepass.icloud"

    public let accessGroup: String?

    public init(accessGroup: String?) {
        self.accessGroup = accessGroup
    }

    static func account(_ accountID: String) -> String { "secretkey.\(accountID)" }

    private func query(_ accountID: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account(accountID),
            kSecAttrSynchronizable as String: true,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    public func read(accountID: String) throws -> Data? {
        var query = query(accountID)
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

    public func owner(accountID: String) throws -> String? {
        var query = query(accountID)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let attributes = result as? [String: Any],
                let generic = attributes[kSecAttrGeneric as String] as? Data
            else { return nil }
            let name = String(decoding: generic, as: UTF8.self)
            return name.isEmpty ? nil : name
        case errSecItemNotFound: return nil
        default: throw KeychainError.unexpectedStatus(status)
        }
    }

    public func write(accountID: String, _ data: Data, owner: String?) throws {
        let query = query(accountID)
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecAttrLabel as String: "OnePass Secret Key",
            kSecAttrGeneric as String: Data((owner ?? "").utf8),
        ]
        var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add.merge(update) { _, new in new }
            status = SecItemAdd(add as CFDictionary, nil)
            if status == errSecDuplicateItem {
                status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            }
        }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    public func delete(accountID: String) throws {
        let status = SecItemDelete(query(accountID) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}

/// Test double: an iCloud Keychain shared by the `VaultEnvironment`s of two simulated devices.
public final class InMemorySyncedSecretKeys: SyncedSecretKeyStore {
    private let storage = Mutex<[String: (key: Data, owner: String?)]>([:])

    public init() {}

    public func read(accountID: String) throws -> Data? { storage.withLock { $0[accountID]?.key } }
    public func owner(accountID: String) throws -> String? { storage.withLock { $0[accountID]?.owner } }
    public func write(accountID: String, _ data: Data, owner: String?) throws {
        storage.withLock { $0[accountID] = (data, owner) }
    }
    public func delete(accountID: String) throws { storage.withLock { _ = $0.removeValue(forKey: accountID) } }

    /// Tests: the account ids held.
    public var accountIDs: Set<String> { storage.withLock { Set($0.keys) } }
}
