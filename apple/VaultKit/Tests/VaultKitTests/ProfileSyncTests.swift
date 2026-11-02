import Foundation
import Testing

@testable import VaultKit

/// The account profile syncs through the vault; the settings hold this device's copy.
@MainActor
@Suite struct ProfileSyncTests {
    @Test func newAccountPublishesItsName() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille Durand", mode: .personal)
        let profile = try #require(try session.coreSession?.profile())
        #expect(profile.name == "Camille Durand")
        #expect(session.summaries.isEmpty)
    }

    @Test func editShowsAtOnceThenReachesTheVault() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        session.profileWriteDelay = .zero
        let before = session.profileRevision

        session.setProfile(name: "Camille D.\u{7}", photo: Data([1, 2, 3]))
        #expect(h.settings.displayName == "Camille D.")
        #expect(h.settings.profilePending)
        #expect(session.profileRevision != before)
        await session.profileTask?.value

        let profile = try #require(try session.coreSession?.profile())
        #expect(profile.name == "Camille D.")
        #expect(profile.photo == Data([1, 2, 3]))
        #expect(!h.settings.profilePending)
        #expect(session.summaries.isEmpty)
    }

    @Test func vaultProfileReplacesTheLocalCopy() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        // Another device's edit, as a sync commit brings it.
        _ = try session.coreSession?.setProfile(name: "Dominique", photo: Data([9]))
        let before = session.profileRevision
        await session.reload()
        #expect(h.settings.displayName == "Dominique")
        #expect(h.settings.profilePhoto == Data([9]))
        #expect(session.profileRevision != before)
    }

    @Test func localProfileIsSeededWhenTheVaultHasNone() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        #expect(try session.coreSession?.profile() == nil)
        // A copy from before the profile synced.
        h.settings.displayName = "Camille"
        h.settings.profilePhoto = Data([4])
        await session.reload()
        await session.profileTask?.value
        let profile = try #require(try session.coreSession?.profile())
        #expect(profile.name == "Camille")
        #expect(profile.updatedAt == 0)
        #expect(h.settings.displayName == "Camille")
    }

    @Test func pendingEditSurvivesALock() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        session.profileWriteDelay = .seconds(60)
        session.setProfile(name: "Nouveau nom", photo: nil)
        session.lock()
        #expect(h.settings.profilePending)

        try await session.unlock(password: testPassword)
        #expect(h.settings.displayName == "Nouveau nom")
        await session.profileTask?.value
        #expect(try session.coreSession?.profile()?.name == "Nouveau nom")
        #expect(!h.settings.profilePending)
    }
}
