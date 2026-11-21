import Foundation
import Testing

@testable import VaultKit

/// Personal accounts on key rotation v2: created with device keys, an older account migrated after
/// its unlock once and only once, and the contact flows' transport available once the keys and the
/// zone handle exist.
@MainActor
@Suite("Account device keys and the v2 migration")
struct DeviceKeysMigrationTests {
    private static let slot = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
    private static let hosted = URL(string: "https://mailbox.example.org/functions/v1/mailbox")!

    /// A personal account from before key rotation v2 (`create_account_bytes`), unlocked.
    private func legacyAccount(_ h: SessionHarness) async throws -> (VaultSession, String) {
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille Durand", mode: .personal)
        let accountID = try #require(h.settings.accountID)
        return (session, accountID)
    }

    private func lineageState(_ session: VaultSession) throws -> FfiLineageState {
        try #require(session.coreSession).lineageStatus().state
    }

    private func zones(_ h: SessionHarness) throws -> AccountZones {
        let store = try openSyncStore(dbPath: h.environment.databaseURL.path)
        return try #require(AccountZones.make(store: store, keychain: h.keychain, hosted: Self.hosted))
    }

    @Test func legacyAccountMigratesOnceWithOneKeySet() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (session, accountID) = try await legacyAccount(h)
        let key = AccountDeviceKeys.key(accountID: accountID)
        #expect(try lineageState(session) == .legacy)
        #expect(try h.keychain.read(key) == nil)

        let first = try await session.migrateToV2IfNeeded(secureEnclave: false)
        guard case .genesis? = first else {
            Issue.record("expected this device's genesis, got \(String(describing: first))")
            return
        }
        #expect(try lineageState(session) == .current)
        let stored = try #require(try h.keychain.read(key))

        // Once v2: nothing runs again, the keys stay the same.
        #expect(try await session.migrateToV2IfNeeded(secureEnclave: false) == nil)
        #expect(try h.keychain.read(key) == stored)

        // The next unlock on this device: still nothing, still one key set.
        session.lock()
        #expect(try await session.migrateToV2IfNeeded(secureEnclave: false) == nil)
        try await session.unlock(password: testPassword)
        #expect(try await session.migrateToV2IfNeeded(secureEnclave: false) == nil)
        #expect(try h.keychain.read(key) == stored)
    }

    @Test func keysLeftByAFailedTryAreReused() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (session, accountID) = try await legacyAccount(h)
        let key = AccountDeviceKeys.key(accountID: accountID)
        // A try that stored its keys, then stopped before the core migrated.
        let made = try AccountDeviceKeys.existingOrCreate(keychain: h.keychain, accountID: accountID, secureEnclave: false)
        let stored = try #require(try h.keychain.read(key))
        #expect(try lineageState(session) == .legacy)

        _ = try await session.migrateToV2IfNeeded(secureEnclave: false)
        #expect(try lineageState(session) == .current)
        #expect(try h.keychain.read(key) == stored)
        let kept = try AccountDeviceKeys(keychain: h.keychain, accountID: accountID).deviceKeys()
        #expect(kept.classical == made.classical)
        #expect(try kept.pq.mldsaPublic() == made.pq.mldsaPublic())
    }

    @Test func unreadableKeysAreNeverReplaced() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (session, accountID) = try await legacyAccount(h)
        let key = AccountDeviceKeys.key(accountID: accountID)
        let damaged = Data([0, 0, 0, 1, 7])
        try h.keychain.write(key, damaged)

        await #expect(throws: OnePassError.self) { try await session.migrateToV2IfNeeded(secureEnclave: false) }
        #expect(try h.keychain.read(key) == damaged)
        #expect(try lineageState(session) == .legacy)
        // The app's call logs and leaves the unlock alone.
        await session.migrateToV2AfterUnlock()
        #expect(session.state == .unlocked)
    }

    @Test func concurrentTriesMigrateOnce() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (session, _) = try await legacyAccount(h)
        async let a = session.migrateToV2IfNeeded(secureEnclave: false)
        async let b = session.migrateToV2IfNeeded(secureEnclave: false)
        let outcomes = try await [a, b]
        #expect(outcomes.compactMap { $0 }.count == 1)
        #expect(try lineageState(session) == .current)
        #expect(LineageMigrationGate.running.isEmpty)
    }

    @Test func lockedSessionMigratesNothing() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (session, accountID) = try await legacyAccount(h)
        session.lock()
        #expect(try await session.migrateToV2IfNeeded(secureEnclave: false) == nil)
        #expect(try h.keychain.read(AccountDeviceKeys.key(accountID: accountID)) == nil)
    }

    @Test func newPersonalAccountStartsOnV2WithItsKeys() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        let password = SecretBytes(utf8: testPassword)
        defer { password.wipe() }
        let secretKey = try await session.createPersonalAccount(
            password: password, displayName: "Camille Durand", mode: .personal, slot: Self.slot, secureEnclave: false)
        secretKey.wipe()
        let accountID = try #require(h.settings.accountID)
        #expect(session.state == .unlocked)
        #expect(try lineageState(session) == .current)
        #expect(try h.keychain.read(AccountDeviceKeys.key(accountID: accountID)) != nil)
        #expect(try h.keychain.read(AccountDeviceKeys.pendingKey(slot: Self.slot)) == nil)
        #expect(try await session.migrateToV2IfNeeded(secureEnclave: false) == nil)

        // The password and Secret Key unlock it again.
        session.lock()
        try await session.unlock(password: testPassword)
        #expect(session.state == .unlocked)
    }

    @Test func contactTransportOnceKeysAndZonesExist() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let (session, _) = try await legacyAccount(h)
        let zones = try zones(h)
        #expect(session.readableDeviceKeys() == nil)
        #expect(session.contactTransport(zones: zones) == nil)

        _ = try await session.migrateToV2IfNeeded(secureEnclave: false)
        #expect(session.readableDeviceKeys() != nil)
        #expect(session.contactTransport(zones: nil) == nil)
        let transport = try #require(session.contactTransport(zones: zones))
        #expect(transport.zones.hosted == Self.hosted)
        #expect(try transport.keys.deviceKeys().classical.count == AccountDeviceKeys.classicalLength)
    }
}
