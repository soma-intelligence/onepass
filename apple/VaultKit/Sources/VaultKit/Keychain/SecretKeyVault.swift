import Foundation

/// Stores the account Secret Key (text form) in the Keychain, one entry per account.
public struct SecretKeyVault: Sendable {
    private let keychain: KeychainStore

    public init(keychain: KeychainStore) {
        self.keychain = keychain
    }

    static func key(for accountID: String) -> String { "secretkey.\(accountID)" }

    /// Writes, then checks that a lookup finds it: a key the next unlock could not read is not
    /// stored (`KeychainError.notReadBack`), so the caller undoes the creation or the restore.
    public func store(_ secretKey: String, accountID: String) throws {
        try keychain.write(Self.key(for: accountID), Data(secretKey.utf8))
        guard try keychain.read(Self.key(for: accountID)) == Data(secretKey.utf8) else {
            throw KeychainError.notReadBack
        }
    }

    public func load(accountID: String) throws -> String? {
        guard let data = try keychain.read(Self.key(for: accountID)) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Stores the Secret Key from a wipeable buffer (the temporary `Data` is overwritten after the write),
    /// then checks that a lookup finds it, as `store(_: String, accountID:)` does: a key the next unlock
    /// could not read is not stored (`KeychainError.notReadBack`). The read-back copy is wiped.
    public func store(_ secretKey: SecretBytes, accountID: String) throws {
        let key = Self.key(for: accountID)
        let readBack = try secretKey.withData { data -> Bool in
            try keychain.write(key, data)
            guard var stored = try keychain.read(key) else { return false }
            defer { stored.withUnsafeMutableBytes { SecretBytes.zero($0) } }
            return stored == data
        }
        guard readBack else { throw KeychainError.notReadBack }
    }

    /// The stored Secret Key in a wipeable buffer. The `Data` the keychain returned is overwritten once
    /// copied, but only that buffer: when it is backed by a `CFData` the Security framework shares or
    /// already copied, those other copies are out of reach (R5).
    public func loadBytes(accountID: String) throws -> SecretBytes? {
        guard var data = try keychain.read(Self.key(for: accountID)) else { return nil }
        return SecretBytes(taking: &data)
    }

    /// Whether a Secret Key is stored, without loading it. Throws when the keychain is unavailable.
    public func contains(accountID: String) throws -> Bool {
        try keychain.contains(Self.key(for: accountID))
    }

    public func remove(accountID: String) throws {
        try keychain.delete(Self.key(for: accountID))
    }
}
