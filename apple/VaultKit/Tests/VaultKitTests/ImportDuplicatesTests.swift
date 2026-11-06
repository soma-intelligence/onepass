import Foundation
import Testing

@testable import VaultKit

/// The "possible duplicates" section of the import sheet: the core's pairs, the per-row and bulk
/// choices, and what the import does with them. Invented data only.
@MainActor
struct ImportDuplicatesTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    static let first = Data("""
        name,url,username,password
        Exemple Atlas,https://atlas-fictif.fr,camille,motdepasse-fictif-1
        Exemple Borée,https://boree-fictif.fr,camille,motdepasse-fictif-2
        Exemple Cyan,https://cyan-fictif.fr,camille,motdepasse-fictif-3

        """.utf8)

    /// Atlas again (exact), Borée with another password (near), Cyan with another address (near),
    /// Delta new.
    static let second = Data("""
        name,url,username,password
        Exemple Atlas,https://atlas-fictif.fr,camille,motdepasse-fictif-1
        Exemple Borée,https://boree-fictif.fr,camille,motdepasse-fictif-9
        Exemple Cyan,https://www.cyan-fictif.fr/compte,camille,motdepasse-fictif-3
        Exemple Delta,https://delta-fictif.fr,camille,motdepasse-fictif-4

        """.utf8)

    private func seeded() async throws -> (SessionHarness, VaultSession, String) {
        let h = try SessionHarness()
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let vault = session.allVaults[0].id
        _ = try await session.importItems(format: "chrome-csv", data: Self.first, vaultID: vault)
        return (h, session, vault)
    }

    @Test func previewListsExactAndNearDuplicatesWithSuggestions() async throws {
        let (h, session, vault) = try await seeded()
        defer { h.cleanUp() }
        let preview = try await session.previewImport(format: "chrome-csv", data: Self.second, vaultID: vault)
        #expect(preview.duplicates.map(\.index) == [0, 1, 2])
        let rows = preview.duplicates
        #expect(rows[0].exact && rows[0].suggested == .skip)
        #expect(!rows[1].exact && rows[1].suggested == .merge)
        #expect(rows[1].differences.contains(.password))
        #expect(rows[2].differences == [.websites])
        #expect(rows.allSatisfy { $0.signals == [.sameLogin] })
        #expect(rows[1].existing.title == "Exemple Borée")
        #expect((preview.merged, preview.skippedDuplicates, preview.added) == (2, 1, 1))
        #expect(session.summaries.count == 3, "a preview writes nothing")
    }

    @Test func rowAndBulkChoicesSendOnlyWhatDiffersFromTheSuggestion() async throws {
        let (h, session, vault) = try await seeded()
        defer { h.cleanUp() }
        let preview = try await session.previewImport(format: "chrome-csv", data: Self.second, vaultID: vault)
        var choices = ImportDuplicateChoices(preview.duplicates)
        #expect(choices.count == 3 && choices.exactCount == 1)
        #expect(choices.decisions.isEmpty, "the suggestions need no decision")
        #expect((choices.count(of: .merge), choices.count(of: .skip)) == (2, 1))

        choices.set(.import, for: 1)
        #expect(choices.choice(for: 1) == .import)
        #expect(choices.decisions == [FfiImportDecision(index: 1, choice: .import)])
        choices.set(.merge, for: 1)
        #expect(choices.decisions.isEmpty, "back on the suggestion")

        choices.setAll(.merge)
        #expect(choices.all(.merge))
        #expect(choices.decisions == [FfiImportDecision(index: 0, choice: .merge)])
        choices.setAll(.skip)
        #expect(choices.all(.skip) && choices.count(of: .skip) == 3)
        #expect(choices.decisions.map(\.index) == [1, 2])
        choices.resetToSuggested()
        #expect(choices.decisions.isEmpty)

        // Another preview keeps the choices of the pairs still there.
        choices.set(.import, for: 2)
        choices.update(preview.duplicates)
        #expect(choices.choice(for: 2) == .import)
        choices.update(Array(preview.duplicates.prefix(2)))
        #expect(choices.decisions.isEmpty, "a pair that left takes its choice with it")
    }

    @Test func importAppliesTheChoices() async throws {
        let (h, session, vault) = try await seeded()
        defer { h.cleanUp() }
        let preview = try await session.previewImport(format: "chrome-csv", data: Self.second, vaultID: vault)
        var choices = ImportDuplicateChoices(preview.duplicates)
        choices.set(.import, for: 0)  // the exact Atlas, imported anyway
        choices.set(.skip, for: 1)  // Borée left out
        let done = try await session.importItems(
            format: "chrome-csv", data: Self.second, vaultID: vault, decisions: choices.decisions)
        #expect((done.separate, done.skippedDuplicates, done.merged) == (1, 1, 1))
        let titles = session.summaries.map(\.title).sorted()
        #expect(titles == ["Exemple Atlas", "Exemple Atlas", "Exemple Borée", "Exemple Cyan", "Exemple Delta"])
        let cyan = try #require(session.summaries.first { $0.title == "Exemple Cyan" })
        let item = try await session.loadItem(vaultID: vault, itemID: cyan.id)
        #expect(item.urls.count == 2, "Cyan merged: both addresses on the vault item")
    }

    @Test func bulkSkipWritesNothingForDuplicates() async throws {
        let (h, session, vault) = try await seeded()
        defer { h.cleanUp() }
        let preview = try await session.previewImport(format: "chrome-csv", data: Self.second, vaultID: vault)
        var choices = ImportDuplicateChoices(preview.duplicates)
        choices.setAll(.skip)
        let done = try await session.importItems(
            format: "chrome-csv", data: Self.second, vaultID: vault, decisions: choices.decisions)
        #expect((done.skippedDuplicates, done.added) == (3, 1))
        #expect(session.summaries.count == 4)
    }
}
