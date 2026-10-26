import Foundation
import Testing

@testable import VaultKit

@MainActor
struct CompanionSessionTests {
    static let seed = "JBSWY3DPEHPK3PXP"

    private func unlockedSession(_ h: SessionHarness) async throws -> VaultSession {
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        return session
    }

    @discardableResult
    private func addWatchLogin(_ session: VaultSession, favorite: Bool = false) async throws -> FfiItem {
        var item = try session.newItem(type: .login, vaultID: session.allVaults[0].id)
        item.title = "Exemple Atlas"
        item.onWatch = true
        item.favorite = favorite
        fillRequired(&item)
        var set = false
        for s in item.sections.indices {
            for f in item.sections[s].fields.indices where item.sections[s].fields[f].kind == .otp {
                item.sections[s].fields[f].value = .otp(value: Self.seed)
                set = true
            }
        }
        #expect(set)
        return try await session.save(item)
    }

    @Test func payloadOpensOnWatchSide() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        try await addWatchLogin(session)
        let keys = try companionGenerateKey()
        let sealed = try await session.companionPayload(recipientPublicKey: Data(keys.public), generation: 3)
        let vault = try CompanionVault.open(secret: keys.secret, sealed: sealed)
        #expect(vault.entries().count == 1)
        #expect(vault.generation() == 3)
        #expect(vault.entries()[0].hasTotp)
    }

    @Test func hiddenVaultIsExcluded() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        let item = try await addWatchLogin(session)
        try await session.createVault(
            FfiVaultMeta(name: "Famille", icon: "house", color: "blue", travelSafe: false, mcpAccess: false))
        session.setVaultHidden(item.vaultId, hidden: true)
        let keys = try companionGenerateKey()
        let sealed = try await session.companionPayload(recipientPublicKey: Data(keys.public), generation: 1)
        let vault = try CompanionVault.open(secret: keys.secret, sealed: sealed)
        #expect(vault.entries().isEmpty)
    }

    @Test func lockedSessionThrows() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        try await addWatchLogin(session)
        session.lock()
        let keys = try companionGenerateKey()
        await #expect(throws: (any Error).self) {
            _ = try await session.companionPayload(recipientPublicKey: Data(keys.public), generation: 1)
        }
    }

    @Test func glanceSnapshotListsFavoriteCodes() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlockedSession(h)
        let item = try await addWatchLogin(session, favorite: true)
        let snap = try await session.glanceSnapshot(window: 120)
        #expect(snap.favorites.map(\.itemId) == [item.id])
        #expect(snap.codes.count == 1)
        #expect(snap.codes[0].codes.isEmpty == false)
    }
}
