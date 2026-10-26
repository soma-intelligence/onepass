import Foundation

/// Minimal key to bytes store backed by the Keychain (or a test double).
public protocol KeychainStore: Sendable {
    func read(_ key: String) throws -> Data?
    func write(_ key: String, _ data: Data) throws
    func delete(_ key: String) throws
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
