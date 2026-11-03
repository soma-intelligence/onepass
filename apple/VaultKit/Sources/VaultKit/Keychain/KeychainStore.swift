import Foundation

/// Minimal key to bytes store backed by the Keychain (or a test double).
public protocol KeychainStore: Sendable {
    func read(_ key: String) throws -> Data?
    func write(_ key: String, _ data: Data) throws
    func delete(_ key: String) throws
    /// Presence only (no secret data read). Throws when the keychain cannot answer
    /// (for example locked device), so "missing" and "unavailable" stay distinct.
    func contains(_ key: String) throws -> Bool
    /// Writes `data` readable after the first unlock since boot, this device only (a mailbox
    /// credential seed: a background wake syncs before the user unlocks).
    func writeAfterFirstUnlock(_ key: String, _ data: Data) throws
}

extension KeychainStore {
    /// Fallback for stores without a metadata query: reads the value.
    public func contains(_ key: String) throws -> Bool { try read(key) != nil }

    /// Default for stores without access classes: `write`.
    public func writeAfterFirstUnlock(_ key: String, _ data: Data) throws { try write(key, data) }
}

public enum KeychainError: Error, Equatable, Sendable {
    case unexpectedStatus(Int32)
    /// The write reported success but a lookup right after does not find the item.
    case notReadBack

    /// A sentence for the user (what happened, what to do); the status only as "(code N)" after it.
    public var message: String {
        switch self {
        case .unexpectedStatus(let status):
            return ErrorText.keychain(status).text
        case .notReadBack:
            return String(localized: "keychain.keychainDidntKeepData", bundle: VaultKitStrings.bundle)
        }
    }
}
