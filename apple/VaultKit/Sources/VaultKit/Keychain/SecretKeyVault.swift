import Foundation

/// Stores the account Secret Key (text form) in the Keychain, one entry per account.
public struct SecretKeyVault: Sendable {
    private let keychain: KeychainStore

    public init(keychain: KeychainStore) {
        self.keychain = keychain
    }

    static func key(for accountID: String) -> String { "secretkey.\(accountID)" }

    public func store(_ secretKey: String, accountID: String) throws {
        try keychain.write(Self.key(for: accountID), Data(secretKey.utf8))
    }

    public func load(accountID: String) throws -> String? {
        guard let data = try keychain.read(Self.key(for: accountID)) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Whether a Secret Key is stored, without loading it. Throws when the keychain is unavailable.
    public func contains(accountID: String) throws -> Bool {
        try keychain.contains(Self.key(for: accountID))
    }

    public func remove(accountID: String) throws {
        try keychain.delete(Self.key(for: accountID))
    }
}
