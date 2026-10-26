import Foundation

/// Minimal key to bytes store backed by the Keychain (or a test double).
public protocol KeychainStore: Sendable {
    func read(_ key: String) throws -> Data?
    func write(_ key: String, _ data: Data) throws
    func delete(_ key: String) throws
    /// Presence only (no secret data read). Throws when the keychain cannot answer
    /// (for example locked device), so "missing" and "unavailable" stay distinct.
    func contains(_ key: String) throws -> Bool
}

extension KeychainStore {
    /// Fallback for stores without a metadata query: reads the value.
    public func contains(_ key: String) throws -> Bool { try read(key) != nil }
}

public enum KeychainError: Error, Equatable, Sendable {
    case unexpectedStatus(Int32)

    public var message: String {
        switch self {
        case .unexpectedStatus(let status):
            return "Erreur du trousseau (code \(status))."
        }
    }
}
