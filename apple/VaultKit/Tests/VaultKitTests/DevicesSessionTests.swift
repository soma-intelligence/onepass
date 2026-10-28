import Foundation
import Testing

@testable import VaultKit

@MainActor
@Suite("Devices and master password")
struct DevicesSessionTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    static let newPassword = "Nouveau mot de passe Atlas 7"

    @Test func changePasswordReenrollsAndOtherSessionAsksNewPassword() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await f.approver.enrollBiometrics(password: testPassword)
        #expect(f.approver.canUseBiometrics)
        try await f.pairFull()
        f.newcomer.lock()
        #expect(!f.newcomer.passwordChangedElsewhere)

        await #expect(throws: VaultError.wrongPassword) {
            try await f.approver.changePassword(current: "faux", new: Self.newPassword)
        }
        try await f.approver.changePassword(current: testPassword, new: Self.newPassword)
        #expect(f.approver.state == .unlocked)
        // Biometrics were enrolled again with the new key: Face ID still opens the vault.
        #expect(f.approver.canUseBiometrics)
        f.approver.lock()
        try await f.approver.unlockWithBiometrics()
        #expect(f.approver.state == .unlocked)
        f.approver.lock()
        await #expect(throws: VaultError.wrongPassword) { try await f.approver.unlock(password: testPassword) }
        try await f.approver.unlock(password: Self.newPassword)

        // The other device gets the new params through sync and says why the old password fails.
        try await #require(f.server).deliver(to: f.newcomerPath)
        await f.newcomer.refresh()
        #expect(f.newcomer.state == .locked)
        #expect(f.newcomer.passwordChangedElsewhere)
        await #expect(throws: VaultError.wrongPassword) { try await f.newcomer.unlock(password: testPassword) }
        try await f.newcomer.unlock(password: Self.newPassword)
        #expect(f.newcomer.state == .unlocked)
        #expect(!f.newcomer.passwordChangedElsewhere)
        f.newcomer.lock()
        await f.newcomer.refresh()
        #expect(!f.newcomer.passwordChangedElsewhere)
    }

    /// The core lists the account's first device under its default name and type ("Appareil",
    /// other); the session names it after this device right away, and again at unlock.
    @Test func newAccountListsThisDeviceByNameAndType() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        try await session.refreshDevices()
        let me = try #require(session.devices.first { $0.isThisDevice })
        #expect(session.devices.count == 1)
        #expect(me.name == VaultSession.currentDeviceName())
        #expect(me.kind == VaultSession.currentDeviceKind)
        #expect(me.mode == .personal)

        session.lock()
        try await session.unlock(password: testPassword)
        try await session.refreshDevices()
        #expect(session.devices.count == 1)
        #expect(session.devices.first?.name == VaultSession.currentDeviceName())
    }

    @Test func revokedDeviceWipes() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await f.pairFull()
        try await f.approver.refreshDevices()
        let me = try #require(f.approver.thisDeviceID)
        let other = try #require(f.approver.devices.first { !$0.isThisDevice })

        // This device cannot revoke itself (ruling A6); revoking asks for presence (ruling A8).
        await #expect(throws: VaultError.self) { try await f.approver.revokeDevice(me, password: testPassword) }
        await #expect(throws: VaultError.passwordRequired) { try await f.approver.revokeDevice(other.id) }
        try await f.approver.revokeDevice(other.id, password: testPassword)
        #expect(f.approver.devices.first { $0.id == other.id }?.revokedAt != nil)

        // The revoked device learns it at its next sync commit and erases everything.
        let accountID = try #require(f.newcomerHarness.settings.accountID)
        try await #require(f.server).deliver(to: f.newcomerPath)
        await f.newcomer.reload()
        #expect(f.newcomer.state == .failed(.deviceRevoked))
        #expect(VaultError.deviceRevoked.localizedMessage == "Cet appareil a été retiré de ton compte OnePass.")
        #expect(f.newcomer.summaries.isEmpty)
        #expect(f.newcomerHarness.settings.accountID == nil)
        #expect(try SecretKeyVault(keychain: f.newcomerHarness.keychain).load(accountID: accountID) == nil)
        #expect(try storeState(dbPath: f.newcomerPath) == .empty)
        await f.newcomer.refresh()
        #expect(f.newcomer.state == .noAccount)
    }

    @Test func revokedDeviceWipesAtUnlock() async throws {
        let f = try await PairingFixture(server: true)
        defer { f.cleanUp() }
        try await f.pairFull()
        f.newcomer.lock()
        try await f.approver.refreshDevices()
        let other = try #require(f.approver.devices.first { !$0.isThisDevice })
        try await f.approver.revokeDevice(other.id, password: testPassword)
        try await #require(f.server).deliver(to: f.newcomerPath)
        await #expect(throws: VaultError.deviceRevoked) { try await f.newcomer.unlock(password: testPassword) }
        #expect(f.newcomer.state == .failed(.deviceRevoked))
        #expect(try storeState(dbPath: f.newcomerPath) == .empty)
    }

    @Test func deleteVaultUpdatesList() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let personal = session.allVaults[0].id
        await #expect(throws: VaultError.other("Le dernier coffre ne peut pas être supprimé.")) {
            try await session.deleteVault(personal)
        }
        try await session.createVault(
            FfiVaultMeta(name: "Projets", icon: "folder", color: "blue", travelSafe: false, mcpAccess: false))
        let projects = try #require(session.allVaults.first { $0.meta.name == "Projets" }).id
        try await addItem(session, title: "Projet Atlas", vaultID: projects)
        await #expect(throws: VaultError.other("Vide ce coffre avant de le supprimer.")) {
            try await session.deleteVault(projects)
        }
        session.setVaultHidden(personal, hidden: true)
        try await session.deleteVault(personal)
        #expect(session.allVaults.map(\.id) == [projects])
        #expect(!session.hiddenVaultIDs.contains(personal))
    }
}
