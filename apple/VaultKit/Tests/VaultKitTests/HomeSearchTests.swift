import Foundation
import Testing

@testable import VaultKit

/// The Mac Home's search field: `ItemSearch.top` over the account's items.
@Suite("Home search")
struct HomeSearchTests {
    private let items = [
        summary("GitHub", subtitle: "camille", url: "https://github.com", tags: ["dev"]),
        summary("Banque Populaire", subtitle: "camille.durand@exemple.fr", url: "https://www.banquepopulaire.fr"),
        summary("Netflix", subtitle: "famille@exemple.fr", tags: ["Streaming"]),
        summary("Mutuelle", url: "https://santé.exemple.fr", tags: ["Famille"]),
        summary("Ancien compte GitHub", subtitle: "camille", archived: true),
        summary("GitLab", subtitle: "camille", trashedAt: 10),
    ]

    private func titles(_ query: String, limit: Int = 10) -> [String] {
        ItemSearch.top(items, query: query, limit: limit).items.map(\.title)
    }

    @Test func blankQueryShowsNothing() {
        #expect(ItemSearch.top(items, query: "", limit: 10) == .none)
        #expect(ItemSearch.top(items, query: "   ", limit: 10) == .none)
    }

    @Test func matchesTitleUsernameURLAndTags() {
        // Title.
        #expect(titles("netflix") == ["Netflix"])
        // Username (the summary's subtitle).
        #expect(titles("durand") == ["Banque Populaire"])
        // URL.
        #expect(titles("banquepopulaire.fr") == ["Banque Populaire"])
        #expect(titles("github.com") == ["GitHub"])
        // Tags, case and accent insensitive.
        #expect(titles("streaming") == ["Netflix"])
        #expect(titles("sante") == ["Mutuelle"])
        // Every word must match somewhere.
        #expect(titles("famille netflix") == ["Netflix"])
        #expect(titles("famille github").isEmpty)
    }

    @Test func leavesOutArchivedAndTrashedItems() {
        #expect(titles("git") == ["GitHub"])
        #expect(titles("camille").contains("Ancien compte GitHub") == false)
        #expect(titles("gitlab").isEmpty)
    }

    @Test func bestAnswersFirstThenCapped() {
        // A title match beats a match on another field; equal answers keep the given order.
        #expect(titles("ban") == ["Banque Populaire"])
        #expect(titles("camille") == ["GitHub", "Banque Populaire"])
        #expect(titles("famille") == ["Netflix", "Mutuelle"])
        let capped = ItemSearch.top(items, query: "camille", limit: 1)
        #expect(capped.items.map(\.title) == ["GitHub"])
        #expect(capped.total == 2)
        #expect(ItemSearch.top(items, query: "camille", limit: 0) == .none)
    }
}
