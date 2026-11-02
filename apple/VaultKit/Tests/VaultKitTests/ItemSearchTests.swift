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

@Suite("Search ranking and recent searches")
struct SearchRankingTests {
    @Test func bestAnswersComeFirst() {
        let items = [
            summary("Banque Populaire", subtitle: "camille@exemple.fr"),
            summary("Netflix", subtitle: "famille@exemple.fr"),
            summary("Compte Netflix famille"),
            summary("Mutuelle", tags: ["netflix"]),
            summary("Ma Banque en ligne"),
        ]
        func titles(_ q: String) -> [String] { ItemSearch.ranked(items, query: q).map(\.title) }
        // The title starting with the query, then a title word starting with it, then the rest.
        #expect(titles("netf") == ["Netflix", "Compte Netflix famille", "Mutuelle"])
        #expect(titles("banque") == ["Banque Populaire", "Ma Banque en ligne"])
        #expect(titles("famille") == ["Compte Netflix famille", "Netflix"])
        // Same rank: the given order stays.
        #expect(titles("exemple") == ["Banque Populaire", "Netflix"])
        #expect(titles("").count == items.count)
        #expect(titles("zzz").isEmpty)
    }

    @Test func recentSearchesKeepTheNewestOnce() {
        var list: [String] = []
        list = RecentSearches.adding("  netflix ", to: list)
        list = RecentSearches.adding("Banque", to: list)
        list = RecentSearches.adding("NETFLIX", to: list)
        #expect(list == ["NETFLIX", "Banque"])
        // Blank or a single character is not a search worth keeping.
        #expect(RecentSearches.adding(" ", to: list) == list)
        #expect(RecentSearches.adding("a", to: list) == list)
        for i in 0..<20 { list = RecentSearches.adding("recherche \(i)", to: list) }
        #expect(list.count == RecentSearches.limit)
        #expect(list.first == "recherche 19")
        // Accents do not make two searches.
        #expect(RecentSearches.adding("électricité", to: ["Electricite"]) == ["électricité"])
    }
}
