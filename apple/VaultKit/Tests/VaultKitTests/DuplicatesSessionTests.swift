import Foundation
import Testing

@testable import VaultKit

@Suite("Duplicate banner rule")
struct DuplicateBannerRuleTests {
    @Test func hiddenAtZeroAndAfterClosingUntilANewGroup() {
        var rule = DuplicateBannerRule()
        #expect(rule.visibleCount(of: []) == 0)
        #expect(rule.visibleCount(of: ["a", "b"]) == 2)
        rule.close(["a", "b"])
        #expect(rule.visibleCount(of: ["a", "b"]) == 0)
        // One handled: still hidden.
        #expect(rule.visibleCount(of: ["b"]) == 0)
        // A new group: the banner counts everything on screen again.
        #expect(rule.visibleCount(of: ["b", "c"]) == 2)
    }

    @Test func storedFormRoundTrips() {
        var rule = DuplicateBannerRule()
        rule.close(["f00", "0ba"])
        let back = DuplicateBannerRule(stored: rule.stored)
        #expect(back == rule)
        #expect(rule.stored == "0ba,f00")
        #expect(DuplicateBannerRule(stored: "").closed.isEmpty)
    }
}

@MainActor
@Suite("Duplicates through the session", .timeLimit(.minutes(4)))
struct DuplicatesSessionTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    private func unlocked() async throws -> (SessionHarness, VaultSession) {
        let h = try SessionHarness()
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        return (h, session)
    }

    private func login(_ session: VaultSession, _ title: String, user: String, password: String, vaultID: String? = nil)
        async throws -> FfiItem
    {
        var item = try session.newItem(type: .login, vaultID: vaultID ?? session.allVaults[0].id)
        item.title = title
        for s in item.sections.indices {
            for f in item.sections[s].fields.indices {
                switch item.sections[s].fields[f].id {
                case "username": item.sections[s].fields[f].value = .text(value: user)
                case "password": item.sections[s].fields[f].value = .password(value: password)
                default: break
                }
            }
        }
        item.urls = [FfiUrl(label: "", url: "https://github.com", rule: .domain, primary: true)]
        return try await session.save(item)
    }

    @Test func groupsMergeWithALocalizedNoteAndReloadTheLists() async throws {
        let (h, session) = try await unlocked()
        defer { h.cleanUp() }
        let a = try await login(session, "GitHub", user: "camille", password: "Premier-Mot-1")
        let b = try await login(session, "GitHub perso", user: "Camille", password: "Second-Mot-2")
        let groups = try await session.duplicateGroups()
        #expect(groups.count == 1)
        let group = try #require(groups.first)
        #expect(group.domain == "github.com")
        #expect(Set(group.copies.map(\.summary.id)) == [a.id, b.id])

        let primary = try #require(group.copies.first)
        let other = try #require(group.copies.last)
        let preview = try await session.duplicateMergePreview(primary: primary.key, others: [other.key])
        #expect(preview.archivedCount == 1)
        #expect(session.summaries.first { $0.id == other.summary.id }?.archived == false)

        try await session.mergeDuplicates(primary: primary.key, others: [other.key], primaryTitle: primary.summary.title)
        // The write reloaded the summaries: the other copy shows archived.
        #expect(session.summaries.first { $0.id == other.summary.id }?.archived == true)
        let archived = try await session.loadItem(vaultID: other.summary.vaultId, itemID: other.summary.id)
        #expect(archived.notes.hasSuffix("Fusionné dans « \(primary.summary.title) »"))
        #expect(try await session.duplicateGroups().isEmpty)
    }

    @Test func dismissTrashAndHiddenVaults() async throws {
        let (h, session) = try await unlocked()
        defer { h.cleanUp() }
        let a = try await login(session, "GitHub", user: "camille", password: "Premier-Mot-1")
        let b = try await login(session, "GitHub", user: "camille", password: "Second-Mot-2")
        try await session.dismissDuplicates([
            FfiItemKey(vaultId: a.vaultId, itemId: a.id), FfiItemKey(vaultId: b.vaultId, itemId: b.id),
        ])
        #expect(try await session.duplicateGroups().isEmpty)
        // The hidden marker never shows as a tag.
        #expect(session.summaries.allSatisfy { $0.tags.isEmpty })

        let c = try await login(session, "GH", user: "camille", password: "Troisieme-Mot-3")
        #expect(try await session.duplicateGroups().count == 1)
        try await session.trashDuplicates([FfiItemKey(vaultId: c.vaultId, itemId: c.id)])
        #expect(session.summaries.first { $0.id == c.id }?.trashedAt != nil)
        #expect(try await session.duplicateGroups().isEmpty)
    }
}
