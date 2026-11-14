import Foundation
import Testing

@testable import VaultKit

private func main(_ item: FfiItem) -> FfiSection { item.sections.first { $0.id == "main" }! }

private func ids(_ section: FfiSection, _ indices: [Int]) -> [String] { indices.map { section.fields[$0].id } }

@Suite("Editor layout")
struct EditorLayoutTests {
    @Test func websitesSlotClamps() {
        #expect(EditorLayout.movableSlots(freeSectionIDs: ["custom", "imported"], websitesSlot: 7)
            == [.section("custom"), .section("imported"), .websites])
        #expect(EditorLayout.movableSlots(freeSectionIDs: ["custom"], websitesSlot: -1)
            == [.websites, .section("custom")])
        #expect(EditorLayout.movableSlots(freeSectionIDs: [], websitesSlot: 3) == [.websites])
    }

    @Test func slotRoundTrip() {
        let slots = EditorLayout.movableSlots(freeSectionIDs: ["a", "b"], websitesSlot: 1)
        #expect(slots == [.section("a"), .websites, .section("b")])
        #expect(EditorLayout.websitesSlot(after: slots) == 1)
    }

    @Test func loginShowsUsernameAndPasswordOnly() {
        let section = main(draftItem(.login))
        let shown = EditorLayout.shownFieldIndices(
            section: section, isLogin: true, isMain: true, pinned: [], errorFieldID: nil, waivedUsername: false)
        #expect(ids(section, shown) == ["username", "password"])
    }

    @Test func filledAndPinnedShow() {
        var section = main(draftItem(.login))
        let email = section.fields.firstIndex { $0.id == "email" }!
        section.fields[email].value = .email(value: "camille.durand@exemple.fr")
        let shown = EditorLayout.shownFieldIndices(
            section: section, isLogin: true, isMain: true, pinned: ["pin"], errorFieldID: nil, waivedUsername: false)
        #expect(Set(ids(section, shown)) == ["username", "password", "email", "pin"])
    }

    @Test func errorShows() {
        let section = main(draftItem(.login))
        let shown = EditorLayout.shownFieldIndices(
            section: section, isLogin: true, isMain: true, pinned: [], errorFieldID: "totp", waivedUsername: false)
        #expect(ids(section, shown).contains("totp"))
    }

    @Test func noFirstThreeRule() {
        let item = draftItem(.identity)
        for section in item.sections {
            let shown = EditorLayout.shownFieldIndices(
                section: section, isLogin: false, isMain: section.id == item.sections[0].id, pinned: [],
                errorFieldID: nil, waivedUsername: false)
            #expect(shown.allSatisfy { section.fields[$0].required })
        }
    }

    @Test func mainCardOrderLogin() {
        let section = main(draftItem(.login))
        let order = ids(section, EditorLayout.mainCardOrder(section))
        #expect(Array(order.prefix(4)) == ["username", "password", "totp", "passkeys"])
        #expect(order.count == section.fields.count)
    }
}
