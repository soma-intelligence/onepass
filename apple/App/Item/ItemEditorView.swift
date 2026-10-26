import DesignKit
import SwiftUI
import VaultKit

/// The one editor of the 26 types (spec 6.4), driven by the item's template sections and the core's
/// menu options: title first (focused at creation), vault, favorite, websites, template fields with
/// "+ ajouter" for repeatable ones, "+ ajouter un champ", notes, tags. A validation error shows under
/// its field and the form scrolls to it. "Annuler" asks before dropping changes.
struct ItemEditorView: View {
    @Environment(AppModel.self) private var model
    @State private var editor: ItemEditorModel
    @State private var confirmDiscard = false
    @FocusState private var titleFocused: Bool
    private let onDone: (FfiItem?) -> Void

    init(draft: ItemDraft, isNew: Bool, onDone: @escaping (FfiItem?) -> Void) {
        _editor = State(initialValue: ItemEditorModel(draft: draft, isNew: isNew))
        self.onDone = onDone
    }

    private var item: FfiItem { editor.draft.item }

    var body: some View {
        ScrollViewReader { proxy in
            Form {
                if let error = editor.generalError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
                titleSection
                Section {
                    VaultPicker(vaultID: $editor.targetVaultID)
                    Toggle("Favori", isOn: $editor.draft.item.favorite)
                        .accessibilityIdentifier("editor.favorite")
                }
                Section("Sites web") {
                    UrlListEditor(editor: editor)
                }
                ForEach(Array(item.sections.enumerated()), id: \.element.id) { _, section in
                    fieldSection(section)
                }
                Section {
                    addFieldMenu
                }
                Section("Notes") {
                    TextEditor(text: $editor.draft.item.notes)
                        .frame(minHeight: 110)
                        .accessibilityIdentifier("editor.notes")
                }
                Section("Tags") {
                    TagEditor(draft: $editor.draft)
                }
                Section {
                    Toggle("Confirmer avant d'afficher", isOn: $editor.draft.item.reprompt)
                        .accessibilityIdentifier("editor.reprompt")
                } footer: {
                    Text("Face ID, Touch ID ou le mot de passe maître sera demandé avant d'afficher cet élément.")
                }
            }
            .formStyle(.grouped)
            .onChange(of: editor.scrollRequest) {
                guard let anchor = editor.errorAnchor else { return }
                withAnimation { proxy.scrollTo(anchor, anchor: .center) }
                if anchor == ItemEditorModel.titleAnchor { titleFocused = true }
            }
        }
        .navigationTitle(editor.isNew ? Text("Nouvel élément") : Text("Modification"))
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        #endif
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Annuler", action: cancel)
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("editor.cancel")
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Enregistrer", action: save)
                    .keyboardShortcut("s", modifiers: .command)
                    .disabled(editor.saving)
                    .accessibilityIdentifier("editor.save")
            }
        }
        .confirmationDialog("Abandonner les modifications ?", isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Abandonner", role: .destructive) { onDone(nil) }
            Button("Continuer la modification", role: .cancel) {}
        }
        .interactiveDismissDisabled(editor.isDirty)
        .task {
            #if DEBUG
            if UserDefaults.standard.bool(forKey: "OnePassDebugAutoSave") {
                try? await Task.sleep(for: .milliseconds(600))
                save()
                return
            }
            #endif
            guard editor.isNew else { return }
            try? await Task.sleep(for: .milliseconds(350))
            titleFocused = true
        }
    }

    // MARK: - Sections

    private var titleSection: some View {
        Section {
            HStack(spacing: 12) {
                ItemIcon(type: item.itemType, title: item.title, siteIcon: nil, size: 44)
                VStack(alignment: .leading, spacing: 4) {
                    TextField("Titre", text: $editor.draft.item.title, prompt: Text("Titre"))
                        .font(.title3.weight(.semibold))
                        .focused($titleFocused)
                        .onChange(of: item.title) { editor.clearError(for: "title") }
                        .accessibilityIdentifier("editor.title")
                    Text(ItemCategory.of(item.itemType).singular).font(.footnote).foregroundStyle(.secondary)
                }
            }
            if let message = editor.titleMessage {
                Label(message, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("editor.error")
            }
        }
        .id(ItemEditorModel.titleAnchor)
    }

    @ViewBuilder private func fieldSection(_ section: FfiSection) -> some View {
        let isCustom = section.id == ItemDraft.customSectionID
        Section {
            ForEach(Array(editor.keys(sectionID: section.id).enumerated()), id: \.element) { position, key in
                if let field = section.fields[safe: position] {
                    fieldRow(sectionID: section.id, key: key, field: field, isCustom: isCustom)
                        .id(ItemEditorModel.anchor(sectionID: section.id, fieldIndex: position))
                    // Passkeys and files are read only here: nothing to add by hand.
                    if editor.draft.canRepeat(sectionID: section.id, fieldIndex: position),
                        field.kind != .passkey, field.kind != .file
                    {
                        Button {
                            editor.addRepeat(of: field.id, in: section.id)
                        } label: {
                            HStack(spacing: 6) {
                                Text("+ ajouter")
                                Text(field.label).foregroundStyle(.secondary)
                            }
                        }
                        .accessibilityLabel(Text("Ajouter \(field.label)"))
                        .accessibilityIdentifier("editor.repeat.\(field.id)")
                    }
                }
            }
        } header: {
            if item.sections.count > 1 || isCustom { Text(section.label) }
        }
    }

    @ViewBuilder private func fieldRow(sectionID: String, key: UUID, field: FfiField, isCustom: Bool) -> some View {
        let index = editor.index(of: key, sectionID: sectionID) ?? 0
        let removable = editor.draft.isRemovable(sectionID: sectionID, fieldIndex: index)
        HStack(alignment: .top, spacing: 10) {
            if removable {
                Button {
                    if let i = editor.index(of: key, sectionID: sectionID) {
                        editor.removeField(sectionID: sectionID, fieldIndex: i)
                    }
                } label: {
                    Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                }
                .buttonStyle(.borderless)
                .padding(.top, 2)
                .accessibilityLabel(Text("Retirer \(field.label)"))
                .accessibilityIdentifier("editor.remove.\(field.id)")
            }
            if isCustom {
                VStack(alignment: .leading, spacing: 4) {
                    TextField("Libellé", text: labelBinding(sectionID, key), prompt: Text(ItemDraft.defaultLabel(field.kind)))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("editor.label.\(field.id)")
                    FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding(sectionID, key))
                    errorText(sectionID, index)
                }
            } else {
                EditorRow(
                    label: field.required ? "\(field.label) *" : field.label,
                    message: editor.message(sectionID: sectionID, fieldIndex: index)
                ) {
                    FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding(sectionID, key))
                }
            }
        }
    }

    @ViewBuilder private func errorText(_ sectionID: String, _ index: Int) -> some View {
        if let message = editor.message(sectionID: sectionID, fieldIndex: index) {
            Label(message, systemImage: "exclamationmark.circle.fill").font(.footnote).foregroundStyle(.red)
        }
    }

    private var addFieldMenu: some View {
        Menu {
            ForEach(Self.customKinds, id: \.1) { kind, label in
                Button(label) { editor.addCustomField(kind: kind) }
            }
        } label: {
            Text("+ ajouter un champ")
        }
        .accessibilityIdentifier("editor.addField")
    }

    static let customKinds: [(FfiFieldType, String)] = [
        (.text, String(localized: "Texte")), (.concealed, String(localized: "Masqué")),
        (.password, String(localized: "Mot de passe")), (.date, String(localized: "Date")),
        (.url, String(localized: "URL")), (.email, String(localized: "Email")),
        (.phone, String(localized: "Téléphone")),
    ]

    // MARK: - Bindings and actions

    /// Looks the row up by its stable key on every access: after a removal the binding of a row
    /// that went away reads `.empty` and writes nothing.
    private func valueBinding(_ sectionID: String, _ key: UUID) -> Binding<FfiFieldValue> {
        Binding(
            get: {
                guard let i = editor.index(of: key, sectionID: sectionID),
                    let field = editor.draft.item.sections.first(where: { $0.id == sectionID })?.fields[safe: i]
                else { return .empty }
                return field.value
            },
            set: { value in
                guard let i = editor.index(of: key, sectionID: sectionID),
                    let id = editor.draft.item.sections.first(where: { $0.id == sectionID })?.fields[safe: i]?.id
                else { return }
                editor.draft.setValue(value, sectionID: sectionID, fieldIndex: i)
                editor.clearError(for: id)
            })
    }

    /// Custom field label; a blank one gets its default back at save (`ItemDraft.preparedForSave`).
    private func labelBinding(_ sectionID: String, _ key: UUID) -> Binding<String> {
        Binding(
            get: {
                guard let i = editor.index(of: key, sectionID: sectionID) else { return "" }
                return editor.draft.item.sections.first { $0.id == sectionID }?.fields[safe: i]?.label ?? ""
            },
            set: { label in
                guard let i = editor.index(of: key, sectionID: sectionID),
                    let s = editor.draft.item.sections.firstIndex(where: { $0.id == sectionID }),
                    editor.draft.item.sections[s].fields.indices.contains(i)
                else { return }
                editor.draft.item.sections[s].fields[i].label = label
            })
    }

    private func cancel() {
        if editor.isDirty {
            confirmDiscard = true
        } else {
            onDone(nil)
        }
    }

    private func save() {
        Task {
            if let saved = await editor.save(with: model.session) { onDone(saved) }
        }
    }
}

/// Picks the control for a field kind (table of spec 6.4).
struct FieldEditor: View {
    let field: FfiField
    let itemType: FfiItemType
    let ownID: String
    @Binding var value: FfiFieldValue

    var body: some View {
        switch field.kind {
        case .text, .email, .phone, .url:
            TextFieldEditor(field: field, value: $value)
        case .concealed, .password, .otp, .mnemonic:
            SecretFieldEditor(field: field, value: $value)
        case .sshKey:
            SshKeyEditor(field: field, value: $value)
        case .date:
            DateFieldEditor(field: field, value: $value)
        case .monthYear:
            MonthYearEditor(field: field, value: $value)
        case .number:
            NumberEditor(field: field, value: $value)
        case .money:
            MoneyEditor(field: field, value: $value)
        case .address:
            AddressEditor(field: field, value: $value)
        case .menu:
            MenuFieldEditor(field: field, itemType: itemType, value: $value)
        case .itemLink:
            ItemLinkPicker(field: field, ownID: ownID, value: $value)
        case .barcode:
            BarcodeEditor(field: field, value: $value)
        case .location:
            LocationEditor(field: field, value: $value)
        case .passkey, .file:
            ReadOnlyFieldView(field: field)
        }
    }
}
