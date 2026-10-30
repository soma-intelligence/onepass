import Foundation
import OnePassCore

/// This device's private approval keys (agent-ready spec 4) in the keychain. `init()` uses
/// `SystemKeychain`: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` items, never synchronizable
/// (`kSecAttrSynchronizable` stays false, its default, and a ThisDeviceOnly item cannot sync), so the
/// keys never leave this device. The tests pass an `InMemoryKeychain`.
public struct ApproverKeyStore: Sendable {
    static let key = "onepass.remote.approver-keys"
    /// Its own service, in the app's default access group: no extension reads these keys.
    static let service = "me.somalabs.onepass.approver"

    private let keychain: any KeychainStore

    /// The system keychain of this device.
    public init() {
        self.init(keychain: SystemKeychain(service: Self.service, accessGroup: nil))
    }

    init(keychain: any KeychainStore) {
        self.keychain = keychain
    }

    public func load() throws -> FfiApproverKeys? {
        guard let data = try keychain.read(Self.key) else { return nil }
        return try Self.decode(data)
    }

    /// The stored keys, or new ones stored first (to register with `Session.registerApprover`).
    public func loadOrCreate() throws -> FfiApproverKeys {
        if let keys = try load() { return keys }
        let keys = try generateApproverKeys()
        try keychain.write(Self.key, Self.encode(keys))
        return keys
    }

    public func delete() throws {
        try keychain.delete(Self.key)
    }

    /// Two length-prefixed fields: signing key, KEM secret.
    static func encode(_ keys: FfiApproverKeys) -> Data {
        var out = Data()
        for field in [keys.signing, keys.kemSecret] {
            var length = UInt32(field.count).bigEndian
            out.append(Data(bytes: &length, count: 4))
            out.append(field)
        }
        return out
    }

    static func decode(_ data: Data) throws -> FfiApproverKeys {
        var rest = data[...]
        func field() throws -> Data {
            guard rest.count >= 4 else { throw VaultError.integrity(kind: "approver_keys") }
            let length = rest.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            rest = rest.dropFirst(4)
            guard rest.count >= length else { throw VaultError.integrity(kind: "approver_keys") }
            defer { rest = rest.dropFirst(length) }
            return Data(rest.prefix(length))
        }
        let signing = try field()
        let kem = try field()
        guard rest.isEmpty else { throw VaultError.integrity(kind: "approver_keys") }
        return FfiApproverKeys(signing: signing, kemSecret: kem)
    }
}
