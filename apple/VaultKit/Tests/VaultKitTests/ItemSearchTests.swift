import Foundation
import Testing

@testable import VaultKit

func summary(
    _ title: String, subtitle: String = "", url: String? = nil, tags: [String] = [],
    type: FfiItemType = .login, vault: String = "v1", favorite: Bool = false,
    archived: Bool = false, trashedAt: Int64? = nil, updatedAt: Int64 = 0
) -> FfiItemSummary {
    FfiItemSummary(
        id: UUID().uuidString, vaultId: vault, itemType: type, title: title, subtitle: subtitle,
        favorite: favorite, tags: tags, primaryUrl: url, archived: archived, trashedAt: trashedAt,
        createdAt: 0, updatedAt: updatedAt)
}

@Suite("Item search and filters")
struct ItemSearchTests {
    @Test func searchIgnoresAccentsAndCase() {
        let items = [
            summary("Électricité Générale", subtitle: "camille.durand@exemple.fr"),
            summary("Mutuelle", url: "https://santé.exemple.fr", tags: ["Famille"]),
            summary("Projet Atlas"),
        ]
        func titles(_ q: String) -> [String] { ItemSearch.filter(items, query: q).map(\.title) }
        #expect(titles("electricite") == ["Électricité Générale"])
        #expect(titles("ÉLECTRICITÉ générale") == ["Électricité Générale"])
        #expect(titles("DURAND") == ["Électricité Générale"])
        #expect(titles("sante") == ["Mutuelle"])
        #expect(titles("famille mutuelle") == ["Mutuelle"])
        #expect(titles("famille atlas").isEmpty)
        #expect(titles("   ").count == 3)
        #expect(titles("").count == 3)
    }

    @Test func decomposedAccentsMatchComposed() {
        let items = [summary("Cafe\u{301} du coin")]
        #expect(ItemSearch.filter(items, query: "café").count == 1)
        #expect(ItemSearch.filter(items, query: "cafe").count == 1)
    }

    @Test func filtersExcludeArchiveAndTrash() {
        let active = summary("A", tags: ["t"], favorite: true)
        let archived = summary("B", favorite: true, archived: true)
        let trashed = summary("C", tags: ["t"], trashedAt: 10)
        let archivedTrashed = summary("D", archived: true, trashedAt: 10)
        let all = [active, archived, trashed, archivedTrashed]
        func ids(_ f: ItemFilter) -> [String] { all.filter(f.matches).map(\.id) }
        #expect(ids(.all) == [active.id])
        #expect(ids(.favorites) == [active.id])
        #expect(ids(.tag("t")) == [active.id])
        #expect(ids(.vault("v1")) == [active.id])
        #expect(ids(.category(.login)) == [active.id])
        #expect(ids(.archive) == [archived.id])
        #expect(ids(.trash) == [trashed.id, archivedTrashed.id])
    }

    @Test func sortByTitleThenUpdated() {
        let items = [summary("b", updatedAt: 1), summary("A", updatedAt: 3), summary("é", updatedAt: 2)]
        #expect(ItemSort.title.sorted(items).map(\.title) == ["A", "b", "é"])
        #expect(ItemSort.updated.sorted(items).map(\.title) == ["A", "é", "b"])
    }
}
