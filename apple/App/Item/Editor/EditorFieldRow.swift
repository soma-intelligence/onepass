import DesignKit
import SwiftUI
import VaultKit

/// One field row of the editor, in any card: the label (editable for a free field), the value's
/// control, its error, and the (−) that fits the row. Looks its field up by its stable key on every
/// access, so a row that went away reads `.empty` and writes nothing.
struct EditorFieldRow: View {
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
                    Label(message, systemImage: "exclamationmark.circle.fill").font(.footnote).foregroundStyle(.red)
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
            RemoveRowButton {
                if let i = editor.index(of: key, sectionID: sectionID) { editor.removeField(sectionID: sectionID, fieldIndex: i) }
            }
            .accessibilityLabel(Text("Retirer \(name)"))
            .accessibilityIdentifier("editor.remove.\(field.id)")
        } else if !field.required, !Self.alwaysShown(field, item: item, sectionID: sectionID) {
            // A template row folds back: emptied and hidden until "ajouter plus" brings it again.
            RemoveRowButton { editor.hideField(sectionID: sectionID, key: key) }
                .accessibilityLabel(Text("Retirer \(name)"))
                .accessibilityIdentifier("editor.remove.\(field.id)")
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
