import Foundation
import Testing

@testable import VaultKit

/// The order a real second device meets: iCloud delivers the account before the user pairs, so the
/// new device sits on the Emergency Kit screen (locked, no Secret Key) when the grant arrives.
@MainActor
@Suite("Pairing onto a synced store")
struct PairingSyncedStoreTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    /// Delivers the approver's account to the new device and reloads it.
    private func deliverAccount(_ f: PairingFixture) async throws {
        let server = try #require(f.server)
        try await server.deliver(to: f.newcomerPath)
        await f.newcomer.reload()
        #expect(f.newcomer.state == .locked)
        #expect(f.newcomer.needsSecretKey)
        #expect(f.newcomer.acceptsPairing)
    }

    @Test func pairingFinishesOnAStoreTheSyncFilled() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await deliverAccount(f)

        let n = try await f.grantFull()
        // A wrong password keeps what the sync brought: the account stays, still waiting for its key.
        await n.importAndUnlock(password: "faux mot de passe")
        #expect(n.state == .receivedFull)
        #expect(n.importError == .wrongPassword)
        #expect(try storeState(dbPath: f.newcomerPath) == .account)
        #expect(f.newcomer.state == .locked)
        #expect(f.newcomer.needsSecretKey)

        await n.importAndUnlock(password: testPassword)
        #expect(n.state == .done)
        #expect(f.newcomer.state == .unlocked)
        #expect(!f.newcomer.needsSecretKey)
        #expect(f.newcomer.summaries.map(\.title) == ["Messagerie exemple.fr"])
        let accountID = try #require(f.approverHarness.settings.accountID)
        #expect(f.newcomerHarness.settings.accountID == accountID)
        let stored = try SecretKeyVault(keychain: f.newcomerHarness.keychain).load(accountID: accountID)
        let original = try SecretKeyVault(keychain: f.approverHarness.keychain).load(accountID: accountID)
        #expect(stored != nil && stored == original)

        // The new device is the one the approver listed.
        try await f.newcomer.refreshDevices()
        let listed = try #require(f.approver.devices.first { !$0.isThisDevice })
        #expect(f.newcomer.thisDeviceID == listed.id)

        // A relaunch opens with the password alone: the Secret Key is in the keychain.
        f.newcomer.lock()
        await f.newcomer.waitForReleasedSessions()
        let relaunched = f.newcomerHarness.makeSession()
        #expect(relaunched.state == .locked)
        #expect(!relaunched.needsSecretKey)
        try await relaunched.unlock(password: testPassword)
        #expect(relaunched.summaries.map(\.title) == ["Messagerie exemple.fr"])
    }

    @Test func aSecondGrantIsRefusedOnceTheStoreWasOpened() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await deliverAccount(f)
        try await f.pairFull()
        f.newcomer.lock()
        #expect(f.newcomer.state == .locked)
        #expect(!f.newcomer.acceptsPairing)

        let again = PairingNewcomerFlow(
            vault: f.newcomer, mode: .personal, listener: f.network, deviceName: PairingFixture.newcomerName,
            deviceKind: .tablet)
        again.start()
        #expect(again.state == .failed(.accountExists))
    }

    /// iCloud brought another account (a different person's on a shared Apple ID, or a stale one):
    /// a grant for this account must not overwrite or merge into it.
    @Test func aGrantForAnotherAccountLeavesTheSyncedOneAlone() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }

        let otherHarness = try SessionHarness()
        defer { otherHarness.cleanUp() }
        var environment = otherHarness.environment
        let otherServer = PushingSync(dbPath: environment.databaseURL.path)
        environment.sync = otherServer
        let other = VaultSession(environment: environment)
        _ = try await other.createAccount(password: testPassword, displayName: "Dominique", mode: .personal)
        try await addItem(other, title: "Compte de Dominique")
        try await otherServer.deliver(to: f.newcomerPath)
        await f.newcomer.reload()
        #expect(f.newcomer.state == .locked)
        #expect(f.newcomer.needsSecretKey)
        let otherID = try #require(otherHarness.settings.accountID)

        let n = try await f.grantFull()
        await n.importAndUnlock(password: testPassword)
        #expect(n.state != .done)
        #expect(n.importError != nil)
        #expect(f.newcomer.state == .locked)
        #expect(f.newcomerHarness.settings.accountID == nil)
        #expect(try SecretKeyVault(keychain: f.newcomerHarness.keychain)
            .load(accountID: try #require(f.approverHarness.settings.accountID)) == nil)

        // The other account is still there, and still opens with its own Secret Key.
        let key = try #require(try SecretKeyVault(keychain: otherHarness.keychain).load(accountID: otherID))
        try await f.newcomer.restore(secretKey: key, password: testPassword)
        #expect(f.newcomer.summaries.map(\.title) == ["Compte de Dominique"])
    }
}
