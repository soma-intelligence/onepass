import Testing

@testable import VaultKit

@Suite("Empty list reason")
struct EmptyListReasonTests {
    @Test func onlyAnActiveQueryIsANoMatch() {
        #expect(EmptyListReason(filter: .all, query: "") == .emptyLibrary)
        #expect(EmptyListReason(filter: .all, query: "   ") == .emptyLibrary)
        #expect(EmptyListReason(filter: .vault("v"), query: "") == .emptyLibrary)
        #expect(EmptyListReason(filter: .all, query: "atlas") == .noMatch)
        #expect(EmptyListReason(filter: .trash, query: "atlas") == .noMatch)
        #expect(EmptyListReason(filter: .category(.login), query: "") == .emptyCategory)
        #expect(EmptyListReason(filter: .tag("Travail"), query: "") == .emptyTag)
        #expect(EmptyListReason(filter: .tag("Travail"), query: "atlas") == .noMatch)
        #expect(EmptyListReason(filter: .favorites, query: "") == .noFavorites)
        #expect(EmptyListReason(filter: .archive, query: "") == .emptyArchive)
        #expect(EmptyListReason(filter: .trash, query: "") == .emptyTrash)
        #expect(EmptyListReason(filter: .all, query: "").offersNewItem)
        #expect(!EmptyListReason(filter: .all, query: "x").offersNewItem)
    }
}
