import Foundation
import Observation
import VaultKit

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

    init(draft: ItemDraft, isNew: Bool) {
        self.draft = draft
        self.isNew = isNew
        targetVaultID = draft.item.vaultId
    }

    var isDirty: Bool { draft.isDirty || targetVaultID != draft.item.vaultId }

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
