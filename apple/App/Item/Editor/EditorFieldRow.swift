import DesignKit
import SwiftUI
import VaultKit

/// One field row of the editor, in any card: the label (editable for a free field), the value's
/// control, its error, and the (−) that fits the row. Looks its field up by its stable key on every
/// access, so a row that went away reads `.empty` and writes nothing.
struct EditorFieldRow: View {
    @Environment(AppModel.self) private var model
    @Bindable var editor: ItemEditorModel
    let sectionID: String
    let key: UUID
    /// The ☰ handle of a free field in a section of two fields or more.
    var handle: ReorderHandle?
    /// A passkey row asks before it goes (the editor shows the confirmation).
    var onRemovePasskey: (UUID) -> Void = { _ in }

    private var item: FfiItem { editor.draft.item }
    private var index: Int? { editor.index(of: key, sectionID: sectionID) }
    private var field: FfiField? {
        index.flatMap { i in item.sections.first { $0.id == sectionID }?.fields[safe: i] }
    }

    var body: some View {
        if let field, let index {
            HStack(alignment: .center, spacing: Theme.Space.m) {
                if let handle { handle.padding(.leading, -Theme.Space.s) }
                content(field, index: index)
                removeButton(field, index: index)
            }
            .editorRowPadding()
            .id(ItemEditorModel.anchor(sectionID: sectionID, fieldIndex: index))
            // Its place in the keyboard chain (Return and "Suivant" move to the next row).
            .environment(\.editorFocusID, Self.focusID(sectionID: sectionID, key: key))
        }
    }

    @ViewBuilder private func content(_ field: FfiField, index: Int) -> some View {
        let label = Self.label(field, item: item)
        if editor.draft.isFreeSection(sectionID) {
            VStack(alignment: .leading, spacing: Theme.Space.xs) {
                TextField("item.label", text: labelBinding, prompt: Text(ItemDraft.defaultLabel(field.kind)))
                    .font(.callout)
                    .foregroundStyle(Theme.accent)
                    .accessibilityIdentifier("editor.label.\(field.id)")
                FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding)
                if let message = editor.message(sectionID: sectionID, fieldIndex: index) {
                    EditorErrorLabel(message: message)
                }
            }
        } else if item.itemType == .login, field.id == "username", sectionID == item.sections.first?.id {
            LoginUsernameRow(
                item: $editor.draft.item, label: label, message: editor.message(sectionID: sectionID, fieldIndex: index)
            ) {
                FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding)
            }
        } else if field.kind == .otp {
            OtpRow(field: field, label: label, message: editor.message(sectionID: sectionID, fieldIndex: index),
                value: valueBinding)
        } else {
            EditorRow(label: label, message: editor.message(sectionID: sectionID, fieldIndex: index)) {
                FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding)
            }
        }
    }

    @ViewBuilder private func removeButton(_ field: FfiField, index: Int) -> some View {
        let name = field.displayLabel(itemType: item.itemType)
        if field.kind == .passkey, field.value != .empty {
            // Spec 6: a passkey is removed here, after a confirmation, whatever its position.
            RemoveRowButton { onRemovePasskey(key) }
                .accessibilityLabel(Text("item.deletePasskey"))
                .accessibilityIdentifier("editor.remove.\(field.id)")
        } else if editor.draft.isRemovable(sectionID: sectionID, fieldIndex: index) {
            RemoveRowButton { removeField() }
            .accessibilityLabel(Text("Retirer \(name)"))
            .accessibilityIdentifier("editor.remove.\(field.id)")
        } else if !field.required, !Self.alwaysShown(field, item: item, sectionID: sectionID) {
            // A template row folds back: emptied and hidden until "ajouter plus" brings it again.
            RemoveRowButton { hideField(field) }
                .accessibilityLabel(Text("Retirer \(name)"))
                .accessibilityIdentifier("editor.remove.\(field.id)")
        }
    }

    // MARK: - Remove with Undo

    /// A template row folds back; Undo puts its value back and shows it again.
    private func hideField(_ field: FfiField) {
        let editor = editor, sectionID = sectionID, key = key
        let old = field.value
        editor.hideField(sectionID: sectionID, key: key)
        guard !old.isBlank else { return }
        model.showToast(String(localized: "editor.fieldRemoved"), action: .undo(owner: editor) {
            guard let i = editor.index(of: key, sectionID: sectionID) else { return }
            editor.draft.setValue(old, sectionID: sectionID, fieldIndex: i)
            editor.pin(key)
        })
    }

    /// An added row (free field, repeat) goes; Undo inserts it again at its place.
    private func removeField() {
        let editor = editor, sectionID = sectionID
        guard let i = editor.index(of: key, sectionID: sectionID),
            let removed = editor.draft.item.sections.first(where: { $0.id == sectionID })?.fields[safe: i]
        else { return }
        editor.removeField(sectionID: sectionID, fieldIndex: i)
        model.showToast(String(localized: "editor.fieldRemoved"), action: .undo(owner: editor) {
            Self.restore(removed, at: i, sectionID: sectionID, in: editor)
        })
    }

    /// Puts a removed field back through the editor's own add methods (they keep the row keys in
    /// step), then gives it its id, label and value again.
    private static func restore(_ field: FfiField, at index: Int, sectionID: String, in editor: ItemEditorModel) {
        guard let s = editor.draft.item.sections.firstIndex(where: { $0.id == sectionID }) else { return }
        if editor.draft.isFreeSection(sectionID) {
            editor.addCustomField(kind: field.kind, sectionID: sectionID)
            let last = editor.draft.item.sections[s].fields.count - 1
            guard last >= 0, editor.draft.item.sections[s].fields[last].kind == field.kind else { return }
            editor.draft.item.sections[s].fields[last] = field
            editor.moveField(sectionID: sectionID, from: last, to: index)
        } else {
            // A repeat of a template field: one more occurrence, then the values shift so the
            // restored one sits at its old rank.
            let before = editor.draft.item.sections[s].fields.count
            editor.addRepeat(of: field.id, in: sectionID)
            let fields = editor.draft.item.sections[s].fields
            guard fields.count == before + 1 else { return }
            let positions = fields.indices.filter { fields[$0].id == field.id }
            let rank = positions.firstIndex { $0 >= index } ?? positions.count - 1
            var values = positions.dropLast().map { fields[$0].value }
            values.insert(field.value, at: min(rank, values.count))
            for (position, value) in zip(positions, values) {
                editor.draft.setValue(value, sectionID: sectionID, fieldIndex: position)
            }
        }
    }

    /// The row's id in the editor's keyboard chain.
    static func focusID(sectionID: String, key: UUID) -> String { "\(sectionID)#\(key.uuidString)" }

    /// Field kinds typed with the keyboard: the ones the chain stops at.
    static func isTyped(_ kind: FfiFieldType) -> Bool {
        switch kind {
        case .text, .email, .phone, .url, .concealed, .password, .otp, .mnemonic, .number, .money: true
        default: false
        }
    }

    /// A login's username and password always show: no (−) on them.
    private static func alwaysShown(_ field: FfiField, item: FfiItem, sectionID: String) -> Bool {
        item.itemType == .login && sectionID == item.sections.first?.id && (field.id == "username" || field.id == "password")
    }

    /// The row's label, lowercased first, with "*" when required (a provider waives the username).
    static func label(_ field: FfiField, item: FfiItem) -> String {
        let text = field.displayLabel(itemType: item.itemType).lowercasedFirst
        let waived = item.itemType == .login && field.id == "username" && item.signInProvider != nil
        return field.required && !waived ? "\(text) *" : text
    }

    private var valueBinding: Binding<FfiFieldValue> {
        Binding(
            get: { field?.value ?? .empty },
            set: { value in
                guard let i = index, let id = field?.id else { return }
                editor.draft.setValue(value, sectionID: sectionID, fieldIndex: i)
                editor.pin(key)
                editor.clearError(for: id)
            })
    }

    /// Free field label; a blank one gets its default back at save (`ItemDraft.preparedForSave`).
    private var labelBinding: Binding<String> {
        Binding(
            get: { field?.label ?? "" },
            set: { label in
                guard let i = index, let s = editor.draft.item.sections.firstIndex(where: { $0.id == sectionID }),
                    editor.draft.item.sections[s].fields.indices.contains(i)
                else { return }
                editor.draft.item.sections[s].fields[i].label = label
            })
    }
}

extension String {
    /// "Codes de secours 2FA" → "codes de secours 2FA", for "Ajouter codes de secours 2FA". An
    /// acronym first ("PIN", "URL") stays as is.
    var lowercasedFirst: String {
        guard let first, first.isUppercase else { return self }
        let second = dropFirst().first
        if let second, second.isUppercase { return self }
        return first.lowercased() + dropFirst()
    }
}
