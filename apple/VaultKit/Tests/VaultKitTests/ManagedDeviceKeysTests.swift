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
