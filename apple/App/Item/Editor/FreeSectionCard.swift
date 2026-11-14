import DesignKit
import SwiftUI
import VaultKit

/// A free section as its own card: its name as an editable card title and a (−) for the whole
/// section, its fields (☰ handles from two fields on), then "+ ajouter un champ". The card moves
/// with `handle`. Removing a section with a filled field asks first.
struct FreeSectionCard: View {
    @Bindable var editor: ItemEditorModel
    let sectionID: String
    let handle: ReorderHandle
    @State private var confirmRemoval = false
    @State private var addingField = false

    private var section: FfiSection? { editor.draft.item.sections.first { $0.id == sectionID } }

    var body: some View {
        if let section {
            HStack(alignment: .top, spacing: Theme.Space.xs) {
                handle.padding(.top, Theme.Space.xs)
                VStack(alignment: .leading, spacing: Theme.Space.s) {
                    header(section)
                    EditorCard {
                        let rows = editor.keys(sectionID: sectionID).map(FieldRowID.init)
                        ReorderableStack(
                            items: rows,
                            accessibilityName: { row in Text(verbatim: label(of: row.key)) },
                            onMove: { editor.moveField(sectionID: sectionID, from: $0, to: $1) }
                        ) { row, rowHandle in
                            VStack(spacing: 0) {
                                if row.key != rows.first?.key { CardDivider() }
                                EditorFieldRow(
                                    editor: editor, sectionID: sectionID, key: row.key,
                                    handle: rows.count > 1 ? rowHandle : nil)
                            }
                        }
                        if !rows.isEmpty { CardDivider() }
                        AddRowButton(title: String(localized: "editor.section.addField")) { addingField = true }
                            .accessibilityIdentifier("editor.section.\(sectionID).addField")
                            .popover(isPresented: $addingField, arrowEdge: .bottom) {
                                CustomKindGrid { kind in
                                    addingField = false
                                    editor.addCustomField(kind: kind, sectionID: sectionID)
                                }
                                .padding(Theme.Space.m)
                                .frame(width: 340)
                                .presentationCompactAdaptation(.popover)
                            }
                    }
                }
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("editor.section.\(sectionID)")
            .confirmationDialog("editor.section.removeTitle", isPresented: $confirmRemoval, titleVisibility: .visible) {
                Button("editor.section.remove", role: .destructive) { editor.removeSection(id: sectionID) }
                Button("Annuler", role: .cancel) {}
            }
        }
    }

    private func header(_ section: FfiSection) -> some View {
        HStack(spacing: Theme.Space.m) {
            TextField(
                "editor.section.name", text: Binding(get: { section.label }, set: { editor.renameSection(id: sectionID, label: $0) }),
                prompt: Text(ItemDraft.defaultSectionLabel())
            )
            .textFieldStyle(.plain)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Theme.readableAccent)
            .accessibilityIdentifier("editor.section.\(sectionID).name")
            RemoveRowButton {
                if section.fields.contains(where: { !$0.value.isBlank }) {
                    confirmRemoval = true
                } else {
                    editor.removeSection(id: sectionID)
                }
            }
            .accessibilityLabel(Text("editor.section.remove"))
            .accessibilityIdentifier("editor.section.\(sectionID).remove")
        }
        .padding(.horizontal, Theme.Space.l)
    }

    private func label(of key: UUID) -> String {
        guard let i = editor.index(of: key, sectionID: sectionID), let field = section?.fields[safe: i] else { return "" }
        return field.label
    }
}

private struct FieldRowID: Identifiable {
    let key: UUID
    var id: UUID { key }
}
