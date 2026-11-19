import Foundation

/// A card of the editor that moves with a handle: the websites card or a free section's card.
public enum EditorSlot: Hashable, Sendable {
    case websites
    case section(String)
}

/// Layout rules of the item editor (spec 2026-11-13, item editor in cards), free of SwiftUI.
public enum EditorLayout {
    /// Per-device display preference: where the websites card sits among the movable cards.
    /// The item never carries layout.
    public static let websitesSlotKey = "onepass.editor.websitesSlot"

    /// The movable cards in order: the free sections in the item's order with the websites card at
    /// `websitesSlot`, clamped to the cards there are.
    public static func movableSlots(freeSectionIDs: [String], websitesSlot: Int) -> [EditorSlot] {
        var slots = freeSectionIDs.map(EditorSlot.section)
        slots.insert(.websites, at: min(max(websitesSlot, 0), slots.count))
        return slots
    }

    /// The movable cards the item page shows: placed among all the free sections as in the editor,
    /// then the sections the page hides (no value) left out.
    public static func shownSlots(freeSectionIDs: [String], shown: Set<String>, websitesSlot: Int) -> [EditorSlot] {
        movableSlots(freeSectionIDs: freeSectionIDs, websitesSlot: websitesSlot).filter { slot in
            if case .section(let id) = slot { shown.contains(id) } else { true }
        }
    }

    /// Where the websites card sits in `slots`, to store after a move.
    public static func websitesSlot(after slots: [EditorSlot]) -> Int {
        slots.firstIndex(of: .websites) ?? slots.count
    }

    /// The fields of a section the editor shows: required ones (unless the username is waived by a
    /// sign-in provider), filled ones, the ones shown during this edit (`pinned`) and the one in
    /// error. On a login's main card the username and the password always show.
    public static func shownFieldIndices(
        section: FfiSection, isLogin: Bool, isMain: Bool, pinned: Set<String>, errorFieldID: String?,
        waivedUsername: Bool
    ) -> [Int] {
        section.fields.indices.filter { i in
            let field = section.fields[i]
            if isLogin, isMain, field.id == "username" || field.id == "password" { return true }
            if field.required, !(waivedUsername && field.id == "username") { return true }
            return !field.value.isBlank || pinned.contains(field.id) || field.id == errorFieldID
        }
    }

    /// Order of a login's main card: username, password, one-time passwords, passkeys, then the
    /// other fields as stored. Other sections keep their stored order.
    public static func mainCardOrder(_ section: FfiSection) -> [Int] {
        func rank(_ field: FfiField) -> Int {
            switch (field.id, field.kind) {
            case ("username", _): 0
            case ("password", _): 1
            case (_, .otp): 2
            case (_, .passkey): 3
            default: 4
            }
        }
        return section.fields.indices.sorted { a, b in
            let (ra, rb) = (rank(section.fields[a]), rank(section.fields[b]))
            return ra == rb ? a < b : ra < rb
        }
    }
}
