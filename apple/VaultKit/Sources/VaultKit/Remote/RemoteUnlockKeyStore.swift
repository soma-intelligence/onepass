import Foundation
import OnePassCore

/// The Mac's half of the remote unlock (agent-ready spec 6.1): `C`, the AUK sealed under the `K_r`
/// only the enrolled iPhone holds, with the device ids it is bound to. `init()` uses
/// `SystemKeychain` (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, never synchronizable, like
/// `ApproverKeyStore`), so `C` never leaves this Mac. One enrollment at a time: a new one replaces
/// it. The tests pass an `InMemoryKeychain`.
public struct RemoteUnlockKeyStore: Sendable {
    public struct Entry: Sendable, Equatable {
        /// This Mac's device id (the core bound `C` to it).
        public var mac: String
        /// The enrolled phone's device id.
        public var phone: String
        public var c: Data

        public init(mac: String, phone: String, c: Data) {
            self.mac = mac
            self.phone = phone
            self.c = c
        }
    }

    static let key = "onepass.remote.unlock-envelope"
    /// Its own service, in the app's default access group: no extension reads it.
    static let service = "me.somalabs.onepass.remote-unlock"

    private let keychain: any KeychainStore

    /// The system keychain of this Mac.
    public init() {
        self.init(keychain: SystemKeychain(service: Self.service, accessGroup: nil))
    }

    init(keychain: any KeychainStore) {
        self.keychain = keychain
    }

    /// Nil when nothing is enrolled. A record that does not decode counts as nothing (and goes).
    public func load() throws -> Entry? {
        guard let data = try keychain.read(Self.key) else { return nil }
        guard let entry = Self.decode(data) else {
            try? keychain.delete(Self.key)
            return nil
        }
        return entry
    }

    public func save(_ entry: Entry) throws {
        try keychain.write(Self.key, Self.encode(entry))
    }

    public func delete() throws {
        try keychain.delete(Self.key)
    }

    /// Three length-prefixed fields: Mac id, phone id, `C`.
    static func encode(_ entry: Entry) -> Data {
        var out = Data()
        for field in [Data(entry.mac.utf8), Data(entry.phone.utf8), entry.c] {
            var length = UInt32(field.count).bigEndian
            out.append(Data(bytes: &length, count: 4))
            out.append(field)
        }
        return out
    }

    static func decode(_ data: Data) -> Entry? {
        var rest = data[...]
        func field() -> Data? {
            guard rest.count >= 4 else { return nil }
            let length = rest.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            rest = rest.dropFirst(4)
            guard rest.count >= length else { return nil }
            defer { rest = rest.dropFirst(length) }
            return Data(rest.prefix(length))
        }
        guard let mac = field().flatMap({ String(data: $0, encoding: .utf8) }),
            let phone = field().flatMap({ String(data: $0, encoding: .utf8) }),
            let c = field(), rest.isEmpty
        else { return nil }
        return Entry(mac: mac, phone: phone, c: c)
    }
}
