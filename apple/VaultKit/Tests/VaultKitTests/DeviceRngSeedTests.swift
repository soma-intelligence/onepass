import Foundation
import Testing

@testable import VaultKit

struct DeviceRngSeedTests {
    @Test func createsOnceThenKeepsTheSameSeed() throws {
        let keychain = InMemoryKeychain()
        #expect(DeviceRngSeed.install(keychain: keychain))
        let first = try #require(try keychain.read(DeviceRngSeed.key))
        #expect(first.count == 32)
        #expect(DeviceRngSeed.install(keychain: keychain))
        #expect(try keychain.read(DeviceRngSeed.key) == first)
    }

    @Test func lockedKeychainNeverReplacesTheSeed() throws {
        let keychain = FailingReadKeychain()
        try keychain.inner.write(DeviceRngSeed.key, Data(repeating: 7, count: 32))
        keychain.failReads(true)
        #expect(!DeviceRngSeed.install(keychain: keychain))
        #expect(try keychain.inner.read(DeviceRngSeed.key) == Data(repeating: 7, count: 32))
    }

    @Test func badStoredSeedIsRefusedNotOverwritten() throws {
        let keychain = InMemoryKeychain()
        try keychain.write(DeviceRngSeed.key, Data(count: 32))
        #expect(!DeviceRngSeed.install(keychain: keychain))
        #expect(try keychain.read(DeviceRngSeed.key) == Data(count: 32))
    }
}
