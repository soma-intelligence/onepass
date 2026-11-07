import Foundation
import Testing

@testable import VaultKit

/// "Supprimer mon compte" (App Review 5.1.1(v)): the account's iCloud zone first, then the store, the
/// Secret Key and the settings of this device. When iCloud cannot be reached, or holds another Apple
/// ID, nothing is erased anywhere.
@MainActor
@Suite("Delete account")
struct DeleteAccountTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    private func live(_ remote: InMemoryRemote) async -> [RecordName: Data] {
        var out: [RecordName: Data] = [:]
        for name in await remote.tags().keys {
            if let data = await remote.record(name)?.data { out[name] = data }
        }
        return out
    }

    private func syncedAccount(_ remote: InMemoryRemote) async throws -> SyncDevice {
        let device = try SyncDevice(remote: remote, name: "A")
        _ = try await device.session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        try await addItem(device.session, title: "Projet Atlas")
        await device.sync()
        #expect(await !live(remote).isEmpty)
        return device
    }

    @Test func deletingTheAccountEmptiesICloudAndThisDevice() async throws {
        let remote = InMemoryRemote()
        let device = try await syncedAccount(remote)
        defer { device.cleanUp() }

        try await device.session.deleteAccount(password: testPassword)

        #expect(device.session.state == .noAccount)
        #expect(device.secretKey == nil)
        #expect(device.settings.accountID == nil)
        #expect(await live(remote).isEmpty)
        // The emptied device syncs again and sends nothing back.
        await device.sync()
        await device.sync()
        #expect(await live(remote).isEmpty)
        #expect(device.session.state == .noAccount)
    }

    @Test func iCloudOfflineErasesNothing() async throws {
        let remote = InMemoryRemote()
        let device = try await syncedAccount(remote)
        defer { device.cleanUp() }
        let before = await live(remote)
        let secretKey = device.secretKey

        await remote.setOffline(true)
        await #expect(throws: (any Error).self) {
            try await device.session.deleteAccount(password: testPassword)
        }

        #expect(device.secretKey == secretKey)
        #expect(device.settings.accountID != nil)
        await remote.setOffline(false)
        #expect(await live(remote) == before)
        if device.session.state != .unlocked { try await device.session.unlock(password: testPassword) }
        #expect(device.titles == ["Projet Atlas"])
    }

    @Test func aWrongPasswordErasesNothing() async throws {
        let remote = InMemoryRemote()
        let device = try await syncedAccount(remote)
        defer { device.cleanUp() }
        let before = await live(remote)

        await #expect(throws: (any Error).self) {
            try await device.session.deleteAccount(password: "pas le bon mot de passe")
        }

        #expect(device.session.state == .unlocked)
        #expect(device.secretKey != nil)
        #expect(await live(remote) == before)
        #expect(device.titles == ["Projet Atlas"])
    }

    @Test func anotherAppleIDKeepsItsZone() async throws {
        let remote = InMemoryRemote()
        let device = try await syncedAccount(remote)
        defer { device.cleanUp() }
        let before = await live(remote)

        await remote.setAccountIdentity("utilisateur-icloud-b")
        await #expect(throws: (any Error).self) {
            try await device.session.deleteAccount(password: testPassword)
        }

        #expect(device.secretKey != nil)
        #expect(await live(remote) == before)
    }

    @Test func withoutSyncOnlyThisDeviceIsErased() async throws {
        let device = try SyncDevice(remote: nil, name: "local")
        defer { device.cleanUp() }
        _ = try await device.session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        try await addItem(device.session, title: "Projet Atlas")

        try await device.session.deleteAccount(password: testPassword)

        #expect(device.session.state == .noAccount)
        #expect(device.secretKey == nil)
        #expect(device.settings.accountID == nil)
    }
}
