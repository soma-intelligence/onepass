import Foundation
import Testing

@testable import VaultKit

/// Récemment utilisés, Fréquemment utilisés and the main identity and card of the profile.
@MainActor
@Suite struct ItemUsageTests {
    private func unlocked(_ h: SessionHarness) async throws -> VaultSession {
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        session.profileWriteDelay = .zero
        return session
    }

    private func use(_ session: VaultSession, _ item: FfiItem, times: Int = 1) async throws {
        for _ in 0..<times { try await session.noteAppUse(vaultID: item.vaultId, itemID: item.id) }
    }

    private func card(_ session: VaultSession, _ title: String) async throws -> FfiItem {
        var item = try session.newItem(type: .creditCard, vaultID: session.allVaults[0].id)
        item.title = title
        for s in item.sections.indices {
            for f in item.sections[s].fields.indices {
                switch item.sections[s].fields[f].id {
                case "cardholder": item.sections[s].fields[f].value = .text(value: "Camille Durand")
                case "number": item.sections[s].fields[f].value = .concealed(value: "4111111111111111")
                case "expiry": item.sections[s].fields[f].value = .monthYear(year: 2030, month: 12)
                default: break
                }
            }
        }
        return try await session.save(item)
    }

    @Test func appUseCountsInTheSummaryWithoutAReload() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let item = try await addItem(session, title: "Atlas", type: .login)
        let revision = session.summariesRevision
        try await use(session, item, times: 2)
        let summary = try #require(session.summaries.first { $0.id == item.id })
        #expect(summary.useCount == 2)
        #expect(summary.lastUsedAt != nil)
        #expect(session.summariesRevision != revision)
        await session.waitForSyncNotifications()
        // Locked: nothing, no error.
        session.lock()
        try await session.noteAppUse(vaultID: item.vaultId, itemID: item.id)
        #expect(session.lastError == nil)
    }

    @Test func frequentlyUsedOrdersByCountThenLastUse() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let a = try await addItem(session, title: "A", type: .login)
        let b = try await addItem(session, title: "B", type: .login)
        let c = try await addItem(session, title: "C", type: .login)
        _ = try await addItem(session, title: "Jamais", type: .login)
        try await use(session, a)
        try await use(session, b, times: 3)
        try await use(session, c)  // As many as A, used after it (same second: then by title).
        let archived = try await addItem(session, title: "Archivé", type: .login)
        try await use(session, archived, times: 5)
        try await session.archive(itemID: archived.id, vaultID: archived.vaultId)

        let frequent = session.frequentlyUsed()
        #expect(frequent.map(\.title).first == "B")
        #expect(Set(frequent.map(\.title)) == ["A", "B", "C"])
        #expect(session.frequentlyUsed(limit: 1).map(\.title) == ["B"])
    }

    @Test func recentlyUsedMergesUsesAndOpenings() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let used = try await addItem(session, title: "Utilisé", type: .login)
        let opened = try await addItem(session, title: "Ouvert", type: .login)
        let trashed = try await addItem(session, title: "Corbeille", type: .login)
        _ = try await addItem(session, title: "Rien", type: .login)
        try await use(session, used)
        try await use(session, trashed)
        try await session.trash(itemID: trashed.id, vaultID: trashed.vaultId)
        // Opened, never used: listed, dated by the session's clock (the fake one, in 1970, before
        // the core's real date of the use).
        _ = try await session.loadItem(vaultID: opened.vaultId, itemID: opened.id)

        #expect(session.recentlyUsed().map(\.title) == ["Utilisé", "Ouvert"])
        #expect(session.recentlyUsed(limit: 1).map(\.title) == ["Utilisé"])
        #expect(session.frequentlyUsed().map(\.title) == ["Utilisé"])
        #expect(session.recents == [opened.id])
        // A lock forgets the openings, never the uses.
        session.lock()
        try await session.unlock(password: testPassword)
        #expect(session.recentlyUsed().map(\.title) == ["Utilisé"])
    }

    @Test func mainIdentityAndCardFallBackToTheFirstByTitle() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        #expect(session.mainIdentity == nil)
        #expect(session.mainCard == nil)
        let zoe = try await addItem(session, title: "Zoé", type: .identity)
        let anna = try await addItem(session, title: "Anna", type: .identity)
        let visa = try await card(session, "Visa")
        let amex = try await card(session, "Amex")
        #expect(session.mainIdentity?.id == anna.id)
        #expect(session.mainCard?.id == amex.id)

        try await session.setMainIdentity((vaultID: zoe.vaultId, itemID: zoe.id))
        try await session.setMainCard((vaultID: visa.vaultId, itemID: visa.id))
        #expect(session.mainIdentity?.id == zoe.id)
        #expect(session.mainCard?.id == visa.id)
        let profile = try #require(try session.coreSession?.profile())
        #expect(profile.mainIdentity?.itemId == zoe.id)
        #expect(profile.mainCard?.itemId == visa.id)
        #expect(profile.name == "Camille")

        // The chosen card gone: the first by title again, and choosing an identity still works.
        try await session.trash(itemID: visa.id, vaultID: visa.vaultId)
        #expect(session.mainCard?.id == amex.id)
        try await session.setMainIdentity(nil)
        #expect(session.mainIdentity?.id == anna.id)

        // A card is no identity.
        await #expect(throws: (any Error).self) {
            try await session.setMainIdentity((vaultID: amex.vaultId, itemID: amex.id))
        }
    }
}
