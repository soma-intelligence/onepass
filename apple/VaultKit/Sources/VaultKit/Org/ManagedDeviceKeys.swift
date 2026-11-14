import CryptoKit
import Foundation

/// The post-quantum half of a managed account's device keys, in CryptoKit: pure ML-DSA-87 (empty
/// context) and ML-KEM-1024, in the Secure Enclave where there is one, in memory otherwise. Every
/// failure reaches the core as `OnePassError.Crypto`. Never calls back into the FFI.
public final class CryptoKitPqHalf: FfiPqDeviceHalf, @unchecked Sendable {
    /// The first byte of `blob`: where the private keys live.
    public enum Backing: UInt8, Sendable {
        case secureEnclave = 1
        case software = 2
    }

    private enum Keys {
        case secureEnclave(SecureEnclave.MLDSA87.PrivateKey, SecureEnclave.MLKEM1024.PrivateKey)
        case software(MLDSA87.PrivateKey, MLKEM1024.PrivateKey)
    }

    public let backing: Backing
    private let keys: Keys

    private init(_ keys: Keys) {
        self.keys = keys
        switch keys {
        case .secureEnclave: backing = .secureEnclave
        case .software: backing = .software
        }
    }

    /// Fresh keys: in the Secure Enclave when `secureEnclave`, otherwise software keys (simulator,
    /// unsigned builds, tests).
    public static func generate(secureEnclave: Bool = SecureEnclave.isAvailable) throws -> CryptoKitPqHalf {
        do {
            if secureEnclave {
                return CryptoKitPqHalf(
                    .secureEnclave(try SecureEnclave.MLDSA87.PrivateKey(), try SecureEnclave.MLKEM1024.PrivateKey()))
            }
            return CryptoKitPqHalf(.software(try MLDSA87.PrivateKey(), try MLKEM1024.PrivateKey()))
        } catch {
            throw OnePassError.Crypto
        }
    }

    /// The half `blob` describes: the backing byte, then the ML-DSA and the ML-KEM representations,
    /// each after its u32 big-endian length (Secure Enclave `dataRepresentation`, software
    /// `seedRepresentation`). Anything else, trailing bytes included, is refused.
    public convenience init(blob: Data) throws {
        var reader = BlobReader(blob)
        guard let tag = reader.byte(), let backing = Backing(rawValue: tag),
            let mldsa = reader.prefixed(), let mlkem = reader.prefixed(), reader.isAtEnd
        else { throw OnePassError.Crypto }
        do {
            switch backing {
            case .secureEnclave:
                self.init(
                    .secureEnclave(
                        try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: mldsa),
                        try SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: mlkem)))
            case .software:
                self.init(
                    .software(
                        try MLDSA87.PrivateKey(seedRepresentation: mldsa, publicKey: nil),
                        try MLKEM1024.PrivateKey(seedRepresentation: mlkem, publicKey: nil)))
            }
        } catch {
            throw OnePassError.Crypto
        }
    }

    /// What `init(blob:)` reads back. A software blob holds the private seeds: keychain only.
    public var blob: Data {
        let (mldsa, mlkem): (Data, Data) =
            switch keys {
            case .secureEnclave(let s, let k): (s.dataRepresentation, k.dataRepresentation)
            case .software(let s, let k): (s.seedRepresentation, k.seedRepresentation)
            }
        var out = Data([backing.rawValue])
        out.appendPrefixed(mldsa)
        out.appendPrefixed(mlkem)
        return out
    }

    public func mldsaPublic() throws -> Data {
        switch keys {
        case .secureEnclave(let s, _): s.publicKey.rawRepresentation
        case .software(let s, _): s.publicKey.rawRepresentation
        }
    }

    public func mlkemPublic() throws -> Data {
        switch keys {
        case .secureEnclave(_, let k): k.publicKey.rawRepresentation
        case .software(_, let k): k.publicKey.rawRepresentation
        }
    }

    /// Pure ML-DSA-87: `signature(for:)` without a context is the empty context.
    public func mldsaSign(message: Data) throws -> Data {
        do {
            return switch keys {
            case .secureEnclave(let s, _): try s.signature(for: message)
            case .software(let s, _): try s.signature(for: message)
            }
        } catch {
            throw OnePassError.Crypto
        }
    }

    public func mlkemDecapsulate(ciphertext: Data) throws -> Data {
        do {
            let shared =
                switch keys {
                case .secureEnclave(_, let k): try k.decapsulate(ciphertext)
                case .software(_, let k): try k.decapsulate(ciphertext)
                }
            return shared.withUnsafeBytes { Data($0) }
        } catch {
            throw OnePassError.Crypto
        }
    }
}

/// A managed account's device keys in this device's Keychain: `device.<accountID>` once the account
/// exists, `device.pending.<slot>` from their creation (before the core gives the account its id)
/// until `adoptPending`. The item: u32 big-endian classical length, the classical halves
/// (`generateClassicalDeviceKeys`), then the `CryptoKitPqHalf` blob.
public struct ManagedDeviceKeys: DeviceKeySource {
    public static func key(accountID: String) -> String { "device.\(accountID)" }
    public static func pendingKey(slot: String) -> String { "device.pending.\(slot)" }

    private let keychain: any KeychainStore
    private let accountID: String

    public init(keychain: any KeychainStore, accountID: String) {
        self.keychain = keychain
        self.accountID = accountID
    }

    /// Fresh keys for the account the slot `slot` is about to create, stored under its pending name.
    public static func createPending(
        keychain: any KeychainStore, slot: String, secureEnclave: Bool = SecureEnclave.isAvailable
    ) throws -> DeviceKeyPair {
        let classical = try generateClassicalDeviceKeys()
        let pq = try CryptoKitPqHalf.generate(secureEnclave: secureEnclave)
        try keychain.write(pendingKey(slot: slot), item(classical: classical, pq: pq))
        return DeviceKeyPair(classical: classical, pq: pq)
    }

    /// Moves the pending keys of `slot` to the account `accountID`. Throws `NotFound` when nothing is
    /// pending; the pending item goes only once the account's is written.
    public static func adoptPending(keychain: any KeychainStore, slot: String, accountID: String) throws {
        guard let item = try keychain.read(pendingKey(slot: slot)) else { throw OnePassError.NotFound }
        try keychain.write(key(accountID: accountID), item)
        try keychain.delete(pendingKey(slot: slot))
    }

    /// Forgets the pending keys of `slot` (a creation cancelled or failed), quietly.
    public static func discardPending(keychain: any KeychainStore, slot: String) {
        try? keychain.delete(pendingKey(slot: slot))
    }

    /// The account's keys. `NotFound` without the item, `Crypto` when it does not read.
    public func deviceKeys() throws -> DeviceKeyPair {
        guard let item = try keychain.read(Self.key(accountID: accountID)) else { throw OnePassError.NotFound }
        var reader = BlobReader(item)
        guard let classical = reader.prefixed() else { throw OnePassError.Crypto }
        return DeviceKeyPair(classical: classical, pq: try CryptoKitPqHalf(blob: reader.rest()))
    }

    public func delete() throws {
        try keychain.delete(Self.key(accountID: accountID))
    }

    private static func item(classical: Data, pq: CryptoKitPqHalf) -> Data {
        var out = Data()
        out.appendPrefixed(classical)
        out.append(pq.blob)
        return out
    }
}

extension Data {
    fileprivate mutating func appendPrefixed(_ part: Data) {
        var length = UInt32(part.count).bigEndian
        Swift.withUnsafeBytes(of: &length) { append(contentsOf: $0) }
        append(part)
    }
}

/// Reads the managed key formats front to back; `nil` past the end.
private struct BlobReader {
    private let data: Data
    private var offset: Data.Index

    init(_ data: Data) {
        self.data = data
        offset = data.startIndex
    }

    var isAtEnd: Bool { offset == data.endIndex }

    mutating func byte() -> UInt8? {
        guard offset < data.endIndex else { return nil }
        defer { offset += 1 }
        return data[offset]
    }

    /// A part after its u32 big-endian length.
    mutating func prefixed() -> Data? {
        guard data.endIndex - offset >= 4 else { return nil }
        let length = data[offset..<offset + 4].reduce(0) { $0 << 8 | Int($1) }
        let start = offset + 4
        guard data.endIndex - start >= length else { return nil }
        offset = start + length
        return Data(data[start..<offset])
    }

    mutating func rest() -> Data {
        defer { offset = data.endIndex }
        return Data(data[offset...])
    }
}
