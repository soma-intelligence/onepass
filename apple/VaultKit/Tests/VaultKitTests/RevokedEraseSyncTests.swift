import Foundation
import Testing

@testable import VaultKit

/// Erasing a revoked device empties that device only: the shared iCloud zone and every other device
/// keep the account, before and after the erased device syncs again.
@MainActor
@Suite("Revoked erase and the server")
struct RevokedEraseSyncTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    /// Every live record on the server, by name, with its bytes.
    private func live(_ remote: InMemoryRemote) async -> [RecordName: Data] {
        var out: [RecordName: Data] = [:]
        for name in await remote.tags().keys {
            if let data = await remote.record(name)?.data { out[name] = data }
        }
        return out
    }

    @Test func erasingARevokedDeviceLeavesTheServerAndTheOtherDeviceWhole() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        let b = try SyncDevice(remote: remote, name: "B")
        defer { a.cleanUp(); b.cleanUp() }

        _ = try await a.session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        try await addItem(a.session, title: "Projet Atlas")
        try await addItem(a.session, title: "Banque exemple")
        await a.sync()

        // B joins with the Secret Key, then A revokes it.
        _ = try await b.coordinator.remoteHasAccount()
        await b.session.reload()
        try await b.session.restore(secretKey: try #require(a.secretKey), password: testPassword)
        await b.sync()
        await a.sync()
        try await a.session.refreshDevices()
        let bID = try #require(a.session.devices.first { !$0.isThisDevice }?.id)
        try await a.session.revokeDevice(bID, password: testPassword)
        await a.sync()
        let before = await live(remote)
        #expect(!before.isEmpty)

        // B learns it is revoked: locked, data kept, nothing sent.
        await b.sync()
        await b.session.reload()
        #expect(b.session.state == .failed(.deviceRevoked))
        #expect(await live(remote) == before)

        // The user erases B, and B keeps syncing as an empty device.
        await b.session.eraseRevokedDevice()
        #expect(b.session.state == .noAccount)
        await b.sync()
        await b.sync()
        #expect(try await b.pendingChanges().isEmpty)
        #expect(await live(remote) == before, "an erased device must not delete or rewrite server records")

        // A still has everything, after its own sync.
        await a.sync()
        #expect(a.session.state == .unlocked)
        #expect(a.titles == ["Projet Atlas", "Banque exemple"])
        try await a.session.refreshDevices()
        #expect(a.session.devices.first { $0.id == bID }?.revokedAt != nil)
    }
}
