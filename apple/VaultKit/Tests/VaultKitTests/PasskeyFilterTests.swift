import Testing

@testable import VaultKit

/// The "Passkeys" list: active items holding at least one passkey, whatever their type or vault.
@Suite("Passkey filter")
struct PasskeyFilterTests {
    private func summary(
        _ id: String, passkeys: UInt32, type: FfiItemType = .login, archived: Bool = false, trashed: Bool = false
    ) -> FfiItemSummary {
        FfiItemSummary(
            id: id, vaultId: "v", itemType: type, title: id, subtitle: "", favorite: false, tags: [],
            primaryUrl: nil, archived: archived, trashedAt: trashed ? 1 : nil, createdAt: 0, updatedAt: 0,
            passkeyCount: passkeys)
    }

    @Test func keepsActiveItemsWithAPasskey() {
        #expect(ItemFilter.passkeys.matches(summary("a", passkeys: 1)))
        #expect(ItemFilter.passkeys.matches(summary("b", passkeys: 3, type: .secureNote)))
        #expect(!ItemFilter.passkeys.matches(summary("c", passkeys: 0)))
        #expect(!ItemFilter.passkeys.matches(summary("d", passkeys: 1, archived: true)))
        #expect(!ItemFilter.passkeys.matches(summary("e", passkeys: 1, trashed: true)))
    }

    @Test func countsItemsNotPasskeys() {
        let counts = ItemCounts([
            summary("a", passkeys: 2), summary("b", passkeys: 1), summary("c", passkeys: 0),
            summary("d", passkeys: 1, trashed: true),
        ])
        #expect(counts.passkeys == 2)
    }

    @Test func emptyListSaysNoPasskeyYet() {
        #expect(EmptyListReason(filter: .passkeys, query: "") == .noPasskeys)
        #expect(EmptyListReason(filter: .passkeys, query: "atlas") == .noMatch)
        // A passkey is created by a site, never by hand: no "Nouvel élément" here.
        #expect(!EmptyListReason.noPasskeys.offersNewItem)
    }
}
