import Foundation
import Observation
import VaultKit

/// The icon the person chose in the editor's icon menu, applied only when the item is saved
/// ("Annuler" drops it): a new picture (`mime` image/png or image/webp, at most 64 KB), or back to
/// the automatic icon.
enum PendingIcon: Equatable {
    case set(mime: String, bytes: Data)
    case clear
}

/// View state of the editor around `ItemDraft` (VaultKit, tested there): the vault chosen,
/// the validation error shown under its field, the save in flight.
@MainActor
@Observable
final class ItemEditorModel {
    var draft: ItemDraft
    let isNew: Bool
    /// The vault picker. A change is applied after the save, by a move (keys re-wrapped by the core).
    var targetVaultID: String
    /// Field id (or `title`) whose error is shown, and the French message.
    private(set) var errorFieldID: String?
    private(set) var errorMessage: String?
    /// Any other save failure (store, conflict...), shown at the top.
    private(set) var generalError: String?
    private(set) var saving = false
    /// Bumped on each failed save so the view scrolls to the faulty field again.
    private(set) var scrollRequest = 0

    /// Stable identity of each field row and website row, so a row's state (revealed, typed text)
    /// stays with its value when a neighbor is removed. Kept in step by the methods below, the only
    /// ones that add or remove rows.
    private(set) var fieldKeys: [String: [UUID]] = [:]
    private(set) var urlKeys: [UUID] = []
    /// Rows shown whatever their value: filled at opening or added during this edit. A row emptied
    /// while editing stays until the editor closes; its (−) hides it (`hideField`).
    var pinnedKeys: Set<UUID> = []
    /// "Tout afficher": every template field left empty shows.
    var showAllFields = false
    /// Where the websites card sits among the movable cards, per device (`EditorLayout`).
    private(set) var websitesSlot: Int
    /// The icon chosen in this edit (`IconLibrarySheet`) or reset, applied after the save.
    var pendingCustomIcon: PendingIcon?

    init(draft: ItemDraft, isNew: Bool, defaults: UserDefaults = .standard) {
        self.draft = draft
        self.isNew = isNew
        targetVaultID = draft.item.vaultId
        websitesSlot = defaults.object(forKey: EditorLayout.websitesSlotKey) as? Int ?? 0
        self.defaults = defaults
        for section in draft.item.sections {
            let keys = section.fields.map { _ in UUID() }
            fieldKeys[section.id] = keys
            for (key, field) in zip(keys, section.fields) where !field.value.isBlank { pinnedKeys.insert(key) }
        }
        urlKeys = draft.item.urls.map { _ in UUID() }
    }

    private let defaults: UserDefaults

    // MARK: - Cards

    /// The movable cards in order: websites and free sections.
    var slots: [EditorSlot] {
        EditorLayout.movableSlots(freeSectionIDs: draft.freeSectionIDs, websitesSlot: websitesSlot)
    }

    /// Moves a movable card; the websites card's place is stored on this device only.
    func moveSlot(from: Int, to: Int) {
        var slots = slots
        guard slots.indices.contains(from) else { return }
        let moving = slots.remove(at: from)
        slots.insert(moving, at: min(max(to, 0), slots.count))
        let order = slots.compactMap { if case .section(let id) = $0 { id } else { nil } }
        for (target, id) in order.enumerated() {
            if let current = draft.freeSectionIDs.firstIndex(of: id), current != target {
                draft.moveFreeSection(from: current, to: target)
            }
        }
        websitesSlot = EditorLayout.websitesSlot(after: slots)
        defaults.set(websitesSlot, forKey: EditorLayout.websitesSlotKey)
    }

    /// The rows of a section shown now, as (index in the section, stable key).
    func shownRows(_ section: FfiSection) -> [(position: Int, key: UUID)] {
        let keys = keys(sectionID: section.id)
        if showAllFields || draft.isFreeSection(section.id) {
            return keys.enumerated().map { ($0.offset, $0.element) }
        }
        let pinned = Set(zip(keys, section.fields).compactMap { pinnedKeys.contains($0) ? $1.id : nil })
        let isMain = section.id == draft.item.sections.first?.id
        var shown = EditorLayout.shownFieldIndices(
            section: section, isLogin: draft.item.itemType == .login, isMain: isMain, pinned: pinned,
            errorFieldID: errorFieldID, waivedUsername: draft.item.signInProvider != nil)
        // An empty passkey row says nothing until a site creates one; a file is shown elsewhere.
        shown.removeAll { section.fields[$0].kind == .passkey && section.fields[$0].value.isBlank }
        let order = isMain && draft.item.itemType == .login ? EditorLayout.mainCardOrder(section) : Array(section.fields.indices)
        let set = Set(shown)
        return order.filter { set.contains($0) && keys.indices.contains($0) }.map { ($0, keys[$0]) }
    }

    /// The (−) of a template row: empties it and folds it away.
    func hideField(sectionID: String, key: UUID) {
        guard let i = index(of: key, sectionID: sectionID) else { return }
        draft.setValue(.empty, sectionID: sectionID, fieldIndex: i)
        pinnedKeys.remove(key)
    }

    func pin(_ key: UUID) { pinnedKeys.insert(key) }

    func clearSignInProvider() { draft.clearSignInProvider() }

    // MARK: - Free sections

    @discardableResult
    func addSection() -> String {
        let id = draft.addSection()
        fieldKeys[id] = []
        return id
    }

    func renameSection(id: String, label: String) { draft.renameSection(id: id, label: label) }

    func removeSection(id: String) {
        guard draft.isFreeSection(id) else { return }
        draft.removeSection(id: id)
        fieldKeys[id] = nil
    }

    func moveField(sectionID: String, from: Int, to: Int) {
        guard draft.isFreeSection(sectionID), var keys = fieldKeys[sectionID], keys.indices.contains(from) else { return }
        draft.moveField(sectionID: sectionID, from: from, to: to)
        let key = keys.remove(at: from)
        keys.insert(key, at: min(max(to, 0), keys.count))
        fieldKeys[sectionID] = keys
    }

    func moveURL(from: Int, to: Int) {
        guard urlKeys.indices.contains(from) else { return }
        draft.moveURL(from: from, to: to)
        let key = urlKeys.remove(at: from)
        urlKeys.insert(key, at: min(max(to, 0), urlKeys.count))
    }

    // MARK: - Rows

    func keys(sectionID: String) -> [UUID] { fieldKeys[sectionID] ?? [] }

    func index(of key: UUID, sectionID: String) -> Int? { fieldKeys[sectionID]?.firstIndex(of: key) }

    func urlIndex(of key: UUID) -> Int? { urlKeys.firstIndex(of: key) }

    func addRepeat(of fieldID: String, in sectionID: String) {
        guard let fields = draft.item.sections.first(where: { $0.id == sectionID })?.fields,
            let last = fields.lastIndex(where: { $0.id == fieldID })
        else { return }
        let before = fields.count
        draft.addRepeat(of: fieldID, in: sectionID)
        if draft.item.sections.first(where: { $0.id == sectionID })?.fields.count == before + 1 {
            let key = UUID()
            fieldKeys[sectionID, default: []].insert(key, at: last + 1)
            pinnedKeys.insert(key)
        }
    }

    func removeField(sectionID: String, fieldIndex: Int) {
        guard draft.isRemovable(sectionID: sectionID, fieldIndex: fieldIndex) else { return }
        draft.removeField(sectionID: sectionID, fieldIndex: fieldIndex)
        fieldKeys[sectionID]?.remove(at: fieldIndex)
    }

    /// Removes a passkey (spec 6, after a confirmation in the view). The first occurrence of the
    /// field is not removable as a row: it takes the next passkey's value, or becomes empty when it
    /// was the only one.
    func removePasskey(sectionID: String, fieldIndex: Int) {
        if draft.isRemovable(sectionID: sectionID, fieldIndex: fieldIndex) {
            removeField(sectionID: sectionID, fieldIndex: fieldIndex)
            return
        }
        guard let fields = draft.item.sections.first(where: { $0.id == sectionID })?.fields,
            fields.indices.contains(fieldIndex)
        else { return }
        let id = fields[fieldIndex].id
        if let next = fields.indices.first(where: { $0 > fieldIndex && fields[$0].id == id }) {
            draft.setValue(fields[next].value, sectionID: sectionID, fieldIndex: fieldIndex)
            removeField(sectionID: sectionID, fieldIndex: next)
        } else {
            draft.setValue(.empty, sectionID: sectionID, fieldIndex: fieldIndex)
        }
    }

    /// Adds a custom field to a free section, or to "Champs perso" when `sectionID` is nil.
    func addCustomField(kind: FfiFieldType, sectionID: String? = nil) {
        let target = sectionID ?? ItemDraft.customSectionID
        let before = draft.item.sections.first { $0.id == target }?.fields.count ?? 0
        draft.addCustomField(kind: kind, label: ItemDraft.defaultLabel(kind), sectionID: sectionID)
        guard (draft.item.sections.first { $0.id == target }?.fields.count ?? 0) == before + 1 else { return }
        let key = UUID()
        fieldKeys[target, default: []].append(key)
        pinnedKeys.insert(key)
    }

    func addURL() {
        draft.addURL()
        urlKeys.append(UUID())
    }

    func removeURL(at index: Int) {
        guard urlKeys.indices.contains(index) else { return }
        draft.removeURL(at: index)
        urlKeys.remove(at: index)
    }

    var isDirty: Bool { draft.isDirty || targetVaultID != draft.item.vaultId || pendingCustomIcon != nil }

    /// The picture the header shows for a pending choice; nil when none is pending.
    var pendingIconBytes: Data? {
        if case .set(_, let bytes) = pendingCustomIcon { bytes } else { nil }
    }

    /// The item has a chosen icon once saved: the stored one unless reset, or a new one.
    var hasCustomIcon: Bool {
        switch pendingCustomIcon {
        case .set: true
        case .clear: false
        case nil: draft.item.customIconId?.isEmpty == false
        }
    }

    /// "Choisir une icône…": the picture replaces the automatic icon, and the category artwork
    /// choice, which would hide it.
    func chooseIcon(mime: String, bytes: Data) {
        pendingCustomIcon = .set(mime: mime, bytes: bytes)
        draft.item.iconCategory = false
    }

    /// "Réinitialiser l'icône": back to the automatic icon (nothing to do for an icon only pending).
    func resetIcon() {
        pendingCustomIcon = draft.item.customIconId?.isEmpty == false ? .clear : nil
    }

    /// Scroll anchor of a field: its section and index (several fields share an id when repeated).
    static func anchor(sectionID: String, fieldIndex: Int) -> String { "\(sectionID)#\(fieldIndex)" }
    static let titleAnchor = "title"

    /// Where the faulty field is: the first field carrying the error's id.
    var errorAnchor: String? {
        guard let id = errorFieldID else { return nil }
        if id == "title" { return Self.titleAnchor }
        for section in draft.item.sections {
            if let index = section.fields.firstIndex(where: { $0.id == id }) {
                return Self.anchor(sectionID: section.id, fieldIndex: index)
            }
        }
        return nil
    }

    func message(sectionID: String, fieldIndex: Int) -> String? {
        guard let anchor = errorAnchor, anchor == Self.anchor(sectionID: sectionID, fieldIndex: fieldIndex)
        else { return nil }
        return errorMessage
    }

    var titleMessage: String? { errorFieldID == "title" ? errorMessage : nil }

    /// Validates, saves, then moves when another vault was picked. Returns the stored item, or nil
    /// with the error shown under its field (the Save button stays enabled, spec 8).
    func save(with session: VaultSession) async -> FfiItem? {
        guard !saving else { return nil }
        generalError = nil
        if let problem = draft.validationError {
            show(field: problem.field, reason: problem.reason)
            return nil
        }
        errorFieldID = nil
        errorMessage = nil
        saving = true
        defer { saving = false }
        do {
            var saved = try await session.save(draft.preparedForSave())
            if targetVaultID != saved.vaultId {
                try await session.move(itemID: saved.id, from: saved.vaultId, to: targetVaultID)
                saved.vaultId = targetVaultID
            }
            // After the move: the icon is written in the vault the item now lives in. A new item
            // gets its icon right after it is created.
            if let pending = pendingCustomIcon {
                saved = await apply(pending, to: saved, with: session)
                pendingCustomIcon = nil
            }
            return saved
        } catch let error as VaultError {
            if case .validation(let field, let reason) = error {
                show(field: field, reason: reason)
            } else {
                generalError = error.localizedMessage
            }
            return nil
        } catch {
            generalError = VaultError(error).localizedMessage
            return nil
        }
    }

    /// Writes the pending icon. The item itself is already stored: a refused icon (the sheet
    /// checks size and type first, so this is rare) leaves the item as saved, with its previous
    /// icon, rather than keeping the editor open on a save that would run twice.
    private func apply(_ pending: PendingIcon, to saved: FfiItem, with session: VaultSession) async -> FfiItem {
        do {
            switch pending {
            case .set(let mime, let bytes):
                return try await session.setCustomIcon(itemID: saved.id, vaultID: saved.vaultId, mime: mime, bytes: bytes)
            case .clear:
                guard saved.customIconId != nil else { return saved }
                return try await session.clearCustomIcon(itemID: saved.id, vaultID: saved.vaultId)
            }
        } catch {
            return saved
        }
    }

    private func show(field: String, reason: String) {
        errorFieldID = field
        errorMessage = VaultError.validationMessage(reason)
        scrollRequest &+= 1
    }

    /// The error goes away once the field is edited.
    func clearError(for fieldID: String) {
        if errorFieldID == fieldID {
            errorFieldID = nil
            errorMessage = nil
        }
    }
}
