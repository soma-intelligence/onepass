import Foundation

/// `G` as this device kept it, with the guard version it belongs to. The caller wipes `secret`.
public struct KeptGuard: Sendable {
    /// The guard version (`FfiGuardState.version`) `G` was handed back for.
    public let version: UInt32
    public let secret: SecretBytes

    public func wipe() { secret.wipe() }
}

/// Keeps `G`, the 32-byte guard secret of a guarded account (Guarded Kit spec 7.1 step 6), in the
/// Keychain, one entry per account, next to its Secret Key (`SecretKeyVault`), together with its
/// guard version. With a `G` whose version matches the store's, the device unlocks with the password
/// alone and a wrong password never reaches the realms; another version (renewed or password changed
/// on another device) sends the unlock to the realms. Erased when the guard is turned off, when an
/// unlock shows the account is no longer guarded, and with the account's other Keychain items.
///
/// Entry layout: the version as 4 bytes big-endian, then `G`.
public struct GuardVault: Sendable {
    /// Length of `G`.
    public static let length = 32
    static let entryLength = 4 + length

    private let keychain: KeychainStore

    public init(keychain: KeychainStore) {
        self.keychain = keychain
    }

    static func key(for accountID: String) -> String { "guard.\(accountID)" }

    /// Writes `G` with its `version`, then checks that a lookup finds it (`KeychainError.notReadBack`
    /// otherwise). The entry buffer and the read-back copy are wiped.
    public func store(_ secret: SecretBytes, version: UInt32, accountID: String) throws {
        let key = Self.key(for: accountID)
        var entry = Data(capacity: Self.entryLength)
        withUnsafeBytes(of: version.bigEndian) { entry.append(contentsOf: $0) }
        secret.withUnsafeBytes { entry.append(contentsOf: $0) }
        defer { entry.withUnsafeMutableBytes { SecretBytes.zero($0) } }
        try keychain.write(key, entry)
        guard var stored = try keychain.read(key) else { throw KeychainError.notReadBack }
        defer { stored.withUnsafeMutableBytes { SecretBytes.zero($0) } }
        guard stored == entry else { throw KeychainError.notReadBack }
    }

    /// The kept `G` and its version (the caller wipes it), nil when none is kept or the entry is not
    /// in the layout above.
    public func load(accountID: String) throws -> KeptGuard? {
        guard var data = try keychain.read(Self.key(for: accountID)) else { return nil }
        defer { data.withUnsafeMutableBytes { SecretBytes.zero($0) } }
        guard data.count == Self.entryLength else { return nil }
        let version = data.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let secret = data.withUnsafeBytes { SecretBytes(copying: UnsafeRawBufferPointer(rebasing: $0[4...])) }
        return KeptGuard(version: version, secret: secret)
    }

    /// Whether a `G` is kept, without loading it.
    public func contains(accountID: String) throws -> Bool {
        try keychain.contains(Self.key(for: accountID))
    }

    public func remove(accountID: String) throws {
        try keychain.delete(Self.key(for: accountID))
    }
}
