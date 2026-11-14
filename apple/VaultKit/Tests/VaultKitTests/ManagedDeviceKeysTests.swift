import CryptoKit
import Foundation
import Testing

@testable import VaultKit

@Suite("Managed device keys")
struct ManagedDeviceKeysTests {
    static let slot = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
    static let accountID = "cd0123456789abcdef0123456789abcd"

    @Test func softwareHalfRoundTripsThroughItsBlob() throws {
        let half = try CryptoKitPqHalf.generate(secureEnclave: false)
        let again = try CryptoKitPqHalf(blob: half.blob)
        #expect(try again.mldsaPublic() == half.mldsaPublic())
        #expect(try again.mlkemPublic() == half.mlkemPublic())
        #expect(again.backing == .software)
        #expect(half.blob.first == CryptoKitPqHalf.Backing.software.rawValue)
    }

    @Test func softwareHalfHasTheCoreSizes() throws {
        let half = try CryptoKitPqHalf.generate(secureEnclave: false)
        #expect(try half.mldsaPublic().count == 2592)
        #expect(try half.mlkemPublic().count == 1568)
        #expect(try half.mldsaSign(message: Data("genesis".utf8)).count == 4627)
    }

    @Test func softwareHalfSignsAndDecapsulates() throws {
        let half = try CryptoKitPqHalf.generate(secureEnclave: false)
        let message = Data("lineage".utf8)
        let signature = try half.mldsaSign(message: message)
        let mldsa = try MLDSA87.PublicKey(rawRepresentation: half.mldsaPublic())
        #expect(mldsa.isValidSignature(signature, for: message))

        let mlkem = try MLKEM1024.PublicKey(rawRepresentation: half.mlkemPublic())
        let sealed = try mlkem.encapsulate()
        let shared = try half.mlkemDecapsulate(ciphertext: sealed.encapsulated)
        #expect(shared == sealed.sharedSecret.withUnsafeBytes { Data($0) })
    }

    @Test func aDamagedBlobIsRefused() throws {
        let blob = try CryptoKitPqHalf.generate(secureEnclave: false).blob
        #expect(throws: OnePassError.self) { try CryptoKitPqHalf(blob: Data()) }
        #expect(throws: OnePassError.self) { try CryptoKitPqHalf(blob: blob.dropLast()) }
        var unknown = blob
        unknown[unknown.startIndex] = 9
        #expect(throws: OnePassError.self) { try CryptoKitPqHalf(blob: unknown) }
        #expect(throws: OnePassError.self) { try CryptoKitPqHalf(blob: blob + Data([0])) }
    }

    @Test func keychainNames() {
        #expect(ManagedDeviceKeys.key(accountID: Self.accountID) == "device.\(Self.accountID)")
        #expect(ManagedDeviceKeys.pendingKey(slot: Self.slot) == "device.pending.\(Self.slot)")
    }

    @Test func pendingKeysMoveToTheAccount() throws {
        let keychain = InMemoryKeychain()
        let pending = try ManagedDeviceKeys.createPending(keychain: keychain, slot: Self.slot, secureEnclave: false)
        let stored = try #require(try keychain.read(ManagedDeviceKeys.pendingKey(slot: Self.slot)))
        // u32-be classical length, the classical halves, then the PQ blob.
        #expect(stored.prefix(4) == Data([0, 0, 0, 65]))
        #expect(stored.dropFirst(4).prefix(65) == pending.classical)

        try ManagedDeviceKeys.adoptPending(keychain: keychain, slot: Self.slot, accountID: Self.accountID)
        #expect(try keychain.read(ManagedDeviceKeys.pendingKey(slot: Self.slot)) == nil)
        #expect(try keychain.read(ManagedDeviceKeys.key(accountID: Self.accountID)) == stored)

        let keys = try ManagedDeviceKeys(keychain: keychain, accountID: Self.accountID).deviceKeys()
        #expect(keys.classical == pending.classical)
        #expect(try keys.pq.mldsaPublic() == pending.pq.mldsaPublic())
        #expect(try keys.pq.mlkemPublic() == pending.pq.mlkemPublic())
    }

    @Test func adoptingWithoutPendingKeysFails() throws {
        let keychain = InMemoryKeychain()
        #expect(throws: OnePassError.self) {
            try ManagedDeviceKeys.adoptPending(keychain: keychain, slot: Self.slot, accountID: Self.accountID)
        }
        #expect(throws: OnePassError.self) {
            try ManagedDeviceKeys(keychain: keychain, accountID: Self.accountID).deviceKeys()
        }
    }

    @Test func oversizedAndEmptyPartsAreRefused() throws {
        let tag = CryptoKitPqHalf.Backing.software.rawValue
        // A length prefix of 0xFFFFFFFF runs past the end.
        #expect(throws: OnePassError.self) {
            try CryptoKitPqHalf(blob: Data([tag, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3]))
        }
        // Two zero-length parts parse but are no keys.
        #expect(throws: OnePassError.self) {
            try CryptoKitPqHalf(blob: Data([tag, 0, 0, 0, 0, 0, 0, 0, 0]))
        }
    }

    @Test func aDamagedKeychainItemIsRefused() throws {
        let keychain = InMemoryKeychain()
        let pending = try ManagedDeviceKeys.createPending(keychain: keychain, slot: Self.slot, secureEnclave: false)
        let good = try #require(try keychain.read(ManagedDeviceKeys.pendingKey(slot: Self.slot)))
        let keys = ManagedDeviceKeys(keychain: keychain, accountID: Self.accountID)
        let key = ManagedDeviceKeys.key(accountID: Self.accountID)

        // Classical half of 64 bytes instead of 65.
        var short = Data([0, 0, 0, 64])
        short.append(pending.classical.prefix(64))
        short.append(good.dropFirst(4 + 65))
        try keychain.write(key, short)
        #expect(throws: OnePassError.Crypto) { try keys.deviceKeys() }

        // Length prefix past the end.
        try keychain.write(key, Data([0xFF, 0xFF, 0xFF, 0xFF]) + good.dropFirst(4))
        #expect(throws: OnePassError.Crypto) { try keys.deviceKeys() }

        // PQ blob cut short.
        try keychain.write(key, good.dropLast(10))
        #expect(throws: OnePassError.Crypto) { try keys.deviceKeys() }

        try keychain.write(key, good)
        #expect(try keys.deviceKeys().classical == pending.classical)
    }

    @Test func adoptingNeverReplacesAnAccountsKeys() throws {
        let keychain = InMemoryKeychain()
        _ = try ManagedDeviceKeys.createPending(keychain: keychain, slot: Self.slot, secureEnclave: false)
        try ManagedDeviceKeys.adoptPending(keychain: keychain, slot: Self.slot, accountID: Self.accountID)
        let held = try #require(try keychain.read(ManagedDeviceKeys.key(accountID: Self.accountID)))

        _ = try ManagedDeviceKeys.createPending(keychain: keychain, slot: Self.slot, secureEnclave: false)
        #expect(throws: OnePassError.Conflict) {
            try ManagedDeviceKeys.adoptPending(keychain: keychain, slot: Self.slot, accountID: Self.accountID)
        }
        #expect(try keychain.read(ManagedDeviceKeys.key(accountID: Self.accountID)) == held)
        // The refused keys stay pending, for the caller to discard.
        #expect(try keychain.read(ManagedDeviceKeys.pendingKey(slot: Self.slot)) != nil)
    }

    @Test func adoptingTheSameKeysAgainIsQuiet() throws {
        let keychain = InMemoryKeychain()
        _ = try ManagedDeviceKeys.createPending(keychain: keychain, slot: Self.slot, secureEnclave: false)
        let item = try #require(try keychain.read(ManagedDeviceKeys.pendingKey(slot: Self.slot)))
        try keychain.write(ManagedDeviceKeys.key(accountID: Self.accountID), item)
        try ManagedDeviceKeys.adoptPending(keychain: keychain, slot: Self.slot, accountID: Self.accountID)
        #expect(try keychain.read(ManagedDeviceKeys.pendingKey(slot: Self.slot)) == nil)
    }

    @Test func discardAndDeleteRemoveTheItems() throws {
        let keychain = InMemoryKeychain()
        _ = try ManagedDeviceKeys.createPending(keychain: keychain, slot: Self.slot, secureEnclave: false)
        ManagedDeviceKeys.discardPending(keychain: keychain, slot: Self.slot)
        #expect(try keychain.read(ManagedDeviceKeys.pendingKey(slot: Self.slot)) == nil)
        // Nothing pending: discarding again is quiet.
        ManagedDeviceKeys.discardPending(keychain: keychain, slot: Self.slot)

        _ = try ManagedDeviceKeys.createPending(keychain: keychain, slot: Self.slot, secureEnclave: false)
        try ManagedDeviceKeys.adoptPending(keychain: keychain, slot: Self.slot, accountID: Self.accountID)
        try ManagedDeviceKeys(keychain: keychain, accountID: Self.accountID).delete()
        #expect(try keychain.read(ManagedDeviceKeys.key(accountID: Self.accountID)) == nil)
    }
}
