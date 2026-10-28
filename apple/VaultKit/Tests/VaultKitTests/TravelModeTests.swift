import Foundation
import Testing

@testable import VaultKit

/// Travel Mode through the session and the sync coordinator, over an in-memory iCloud: the vault
/// leaves the device without leaving iCloud, another device keeps writing to it, and it comes back
/// with those writes after a fetch from scratch.
@MainActor
@Suite("Travel Mode", .timeLimit(.minutes(4)))
struct TravelModeTests {
    private func atlasVault(_ device: SyncDevice) async throws -> String {
        try await device.session.createVault(
            FfiVaultMeta(name: "Projet Atlas", icon: "briefcase", color: "teal", travelSafe: false, mcpAccess: false))
        let id = try #require(device.session.allVaults.first { $0.meta.name == "Projet Atlas" }?.id)
        try await addItem(device.session, title: "Serveur Atlas", vaultID: id)
        await device.sync()
        return id
    }

    @Test func vaultLeavesAndComesBackWithTheOtherDevicesWrites() async throws {
        let remote = InMemoryRemote()
        let (a, b, _) = try await twoSyncedDevices(remote: remote)
        defer { a.cleanUp(); b.cleanUp() }
        // The personal vault stays.
        let personal = try #require(a.session.allVaults.first)
        var meta = personal.meta
        meta.travelSafe = true
        try await a.session.updateVault(id: personal.id, meta: meta)
        let atlas = try await atlasVault(a)
        await b.sync()
        await b.session.reload()

        let plan = try await a.session.travelPlan()
        #expect(plan.first { $0.vaultId == atlas }?.leaves == true)
        #expect(plan.first { $0.vaultId == personal.id }?.leaves == false)

        let status = try await a.session.enterTravel()
        #expect(status.active && status.hiddenCount == 1)
        #expect(!a.session.allVaults.contains { $0.id == atlas })
        #expect(!a.titles.contains("Serveur Atlas"))
        #expect(try await a.pendingChanges().isEmpty)

        // B writes into Atlas; A syncs and still has no Atlas.
        try await addItem(b.session, title: "Note de B", vaultID: atlas)
        await b.sync()
        await a.sync()
        await a.session.reload()
        #expect(!a.titles.contains("Note de B"))

        try await a.session.beginTravelExit()
        await a.coordinator.refetchFromScratch()
        let back = try await a.session.finishTravelExit()
        #expect(!back.active)
        #expect(a.titles.isSuperset(of: ["Serveur Atlas", "Note de B"]))
        #expect(try await a.pendingChanges().isEmpty)
    }

    @Test func unsyncedWritesKeepTheVaultOnTheDevice() async throws {
        let device = try SyncDevice(remote: nil, name: "seul")
        defer { device.cleanUp() }
        _ = try await device.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(device.session, title: "Pas dans iCloud")
        await #expect(throws: VaultError.self) { try await device.session.enterTravel() }
        #expect(device.titles.contains("Pas dans iCloud"))
        #expect(try await device.session.travelStatus().active == false)
    }

    @Test func refusalsHaveFrenchMessages() {
        #expect(VaultError.developerMessage("unsynced changes")?.contains("iCloud") == true)
        #expect(VaultError.developerMessage("SSH key: wrong passphrase") == "Phrase de passe incorrecte.")
        #expect(VaultError.developerMessage("anything else") == nil)
    }
}
