import DesignKit
import SwiftUI
import VaultKit

/// A card of a template section. The main card (the item's first section) has no label; for a
/// login it reads username, password, one-time password, "se connecter avec", the passkeys, then
/// "+ ajouter une passkey". Other template sections keep their label. Nothing here moves.
struct TemplateSectionCard: View {
    @Bindable var editor: ItemEditorModel
    let section: FfiSection
    var onRemovePasskey: (String, UUID) -> Void

    private var item: FfiItem { editor.draft.item }
    private var isMain: Bool { section.id == item.sections.first?.id }
    private var isLoginMain: Bool { isMain && item.itemType == .login }

    var body: some View {
        let rows = editor.shownRows(section)
        if !rows.isEmpty || isLoginMain {
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                if !isMain {
                    EditorLabel(section.displayLabel(itemType: item.itemType)).padding(.leading, Theme.Space.l)
                }
                EditorCard {
                    ForEach(Array(rows.enumerated()), id: \.element.key) { order, row in
                        if order > 0 { CardDivider() }
                        EditorFieldRow(editor: editor, sectionID: section.id, key: row.key) { key in
                            onRemovePasskey(section.id, key)
                        }
                        if isLoginMain, item.signInProvider != nil, isLastBeforeSignIn(row.position, rows: rows) {
                            CardDivider()
                            SignInRow(editor: editor)
                        }
                        repeatButton(position: row.position)
                    }
                    if isLoginMain {
                        if !rows.isEmpty { CardDivider() }
                        AddPasskeyRow(item: item, editing: true) { editor.addURL() }
                    }
                }
            }
        }
    }

    /// "se connecter avec" sits after the last of username, password and one-time password rows.
    private func isLastBeforeSignIn(_ position: Int, rows: [(position: Int, key: UUID)]) -> Bool {
        let leading = rows.filter { row in
            let field = section.fields[row.position]
            return field.id == "username" || field.id == "password" || field.kind == .otp
        }
        return leading.last?.position == position
    }

    /// "+ ajouter …" under the last copy of a repeatable field. Passkeys and files are read only.
    @ViewBuilder private func repeatButton(position: Int) -> some View {
        if let field = section.fields[safe: position],
            editor.draft.canRepeat(sectionID: section.id, fieldIndex: position),
            field.kind != .passkey, field.kind != .file
        {
            CardDivider()
            AddRowButton(title: String(localized: "item.add2 \(field.displayLabel(itemType: item.itemType).lowercasedFirst)")) {
                editor.addRepeat(of: field.id, in: section.id)
            }
            .accessibilityLabel(Text("item.add \(field.displayLabel(itemType: item.itemType))"))
            .accessibilityIdentifier("editor.repeat.\(field.id)")
        }
    }
}
