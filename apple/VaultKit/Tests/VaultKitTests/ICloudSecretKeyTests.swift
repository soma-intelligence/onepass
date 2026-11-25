import Foundation
import Testing

@testable import VaultKit

/// Spec 2026-11-25: the Secret Key copy in iCloud Keychain, and joining with the password only.
@MainActor
struct ICloudSecretKeyTests {
    /// The second device: the first one's store (what the iCloud fetch brings), its own keychain,
    /// the same iCloud Keychain.
    private func secondDevice(from first: SessionHarness, synced: InMemorySyncedSecretKeys) throws -> SessionHarness {
        let second = try SessionHarness(syncedSecretKeys: synced)
        for suffix in ["", "-wal", "-shm"] {
            let source = URL(fileURLWithPath: first.environment.databaseURL.path + suffix)
            guard FileManager.default.fileExists(atPath: source.path) else { continue }
            try FileManager.default.copyItem(
                at: source, to: URL(fileURLWithPath: second.environment.databaseURL.path + suffix))
        }
        return second
    }

    @Test func creationPublishesTheKey() async throws {
        let synced = InMemorySyncedSecretKeys()
        let h = try SessionHarness(syncedSecretKeys: synced)
        defer { h.cleanUp() }
        let session = h.makeSession()
        let key = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let accountID = try #require(h.settings.accountID)
        let stored = try #require(try synced.read(accountID: accountID))
        #expect(String(decoding: stored, as: UTF8.self) == key)
    }

    @Test func sharedDeviceNeverPublishes() async throws {
        let synced = InMemorySyncedSecretKeys()
        let h = try SessionHarness(syncedSecretKeys: synced)
        defer { h.cleanUp() }
        _ = try await h.makeSession().createAccount(password: testPassword, displayName: "", mode: .shared)
        #expect(synced.accountIDs.isEmpty)
    }

    @Test func settingOffNeverPublishesAndDeletes() async throws {
        let synced = InMemorySyncedSecretKeys()
        let h = try SessionHarness(syncedSecretKeys: synced)
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        #expect(synced.accountIDs.count == 1)
        session.setSecretKeyInICloud(false)
        #expect(synced.accountIDs.isEmpty)
        session.lock()
        await session.waitForReleasedSessions()
        try await h.makeSession().unlock(password: testPassword)
        #expect(synced.accountIDs.isEmpty)
        session.setSecretKeyInICloud(true)
        #expect(synced.accountIDs.count == 1)
    }

    /// An account from before this change publishes its key at the next password unlock.
    @Test func existingAccountPublishesAtUnlock() async throws {
        let synced = InMemorySyncedSecretKeys()
        let h = try SessionHarness(syncedSecretKeys: synced)
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let accountID = try #require(h.settings.accountID)
        try synced.delete(accountID: accountID)
        session.lock()
        await session.waitForReleasedSessions()
        try await h.makeSession().unlock(password: testPassword)
        #expect(synced.accountIDs == [accountID])
    }

    @Test func newDeviceJoinsWithThePasswordOnly() async throws {
        let synced = InMemorySyncedSecretKeys()
        let first = try SessionHarness(syncedSecretKeys: synced)
        defer { first.cleanUp() }
        let session = first.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(session, title: "Projet Atlas")
        session.lock()
        await session.waitForReleasedSessions()

        let second = try secondDevice(from: first, synced: synced)
        defer { second.cleanUp() }
        let joining = second.makeSession()
        #expect(joining.needsSecretKey)
        #expect(await joining.iCloudKeychainHasSecretKey())

        let wrong = SecretBytes(utf8: "faux")
        await #expect(throws: VaultError.wrongPassword) {
            try await joining.restoreFromICloudKeychain(password: wrong)
        }
        // A wrong password leaves nothing on this device.
        #expect(try SecretKeyVault(keychain: second.keychain).contains(accountID: #require(first.settings.accountID)) == false)

        try await joining.restoreFromICloudKeychain(password: SecretBytes(utf8: testPassword))
        #expect(joining.state == .unlocked)
        #expect(joining.summaries.map(\.title) == ["Projet Atlas"])
        // Stored device-only: the next launch asks for the password only.
        #expect(!joining.needsSecretKey)
    }

    @Test func noSyncedKeyMeansNoJoin() async throws {
        let first = try SessionHarness(syncedSecretKeys: InMemorySyncedSecretKeys())
        defer { first.cleanUp() }
        let session = first.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()
        await session.waitForReleasedSessions()

        let second = try secondDevice(from: first, synced: InMemorySyncedSecretKeys())
        defer { second.cleanUp() }
        let joining = second.makeSession()
        #expect(await joining.iCloudKeychainHasSecretKey() == false)
        await #expect(throws: VaultError.self) {
            try await joining.restoreFromICloudKeychain(password: SecretBytes(utf8: testPassword))
        }
    }
}
