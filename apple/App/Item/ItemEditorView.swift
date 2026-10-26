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
                    UrlListEditor(draft: $editor.draft)
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
            ForEach(section.fields.indices, id: \.self) { index in
                fieldRow(section: section, index: index, isCustom: isCustom)
                    .id(ItemEditorModel.anchor(sectionID: section.id, fieldIndex: index))
                let field = section.fields[index]
                // Passkeys and files are read only here: nothing to add by hand.
                if editor.draft.canRepeat(sectionID: section.id, fieldIndex: index),
                    field.kind != .passkey, field.kind != .file
                {
                    Button {
                        editor.draft.addRepeat(of: field.id, in: section.id)
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
        } header: {
            if item.sections.count > 1 || isCustom { Text(section.label) }
        }
    }

    @ViewBuilder private func fieldRow(section: FfiSection, index: Int, isCustom: Bool) -> some View {
        let field = section.fields[index]
        let removable = editor.draft.isRemovable(sectionID: section.id, fieldIndex: index)
        HStack(alignment: .top, spacing: 10) {
            if removable {
                Button {
                    editor.draft.removeField(sectionID: section.id, fieldIndex: index)
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
                    TextField("Libellé", text: labelBinding(section.id, index))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding(section.id, index))
                    errorText(section.id, index)
                }
            } else {
                EditorRow(
                    label: field.required ? "\(field.label) *" : field.label,
                    message: editor.message(sectionID: section.id, fieldIndex: index)
                ) {
                    FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding(section.id, index))
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
                Button(label) { editor.draft.addCustomField(kind: kind, label: ItemDraft.defaultLabel(kind)) }
            }
        } label: {
            Label("+ ajouter un champ", systemImage: "plus")
                .labelStyle(.titleOnly)
        }
        .accessibilityIdentifier("editor.addField")
    }

    static let customKinds: [(FfiFieldType, String)] = [
        (.text, "Texte"), (.concealed, "Masqué"), (.password, "Mot de passe"), (.date, "Date"),
        (.url, "URL"), (.email, "Email"), (.phone, "Téléphone"),
    ]

    // MARK: - Bindings and actions

    /// Indices can go stale for one render after a removal: out of range reads give `.empty`.
    private func valueBinding(_ sectionID: String, _ index: Int) -> Binding<FfiFieldValue> {
        Binding(
            get: {
                guard let section = editor.draft.item.sections.first(where: { $0.id == sectionID }),
                    section.fields.indices.contains(index)
                else { return .empty }
                return section.fields[index].value
            },
            set: { value in
                let id = editor.draft.item.sections.first { $0.id == sectionID }?.fields[safe: index]?.id
                editor.draft.setValue(value, sectionID: sectionID, fieldIndex: index)
                if let id { editor.clearError(for: id) }
            })
    }

    private func labelBinding(_ sectionID: String, _ index: Int) -> Binding<String> {
        Binding(
            get: {
                editor.draft.item.sections.first { $0.id == sectionID }?.fields[safe: index]?.label ?? ""
            },
            set: { label in
                guard let s = editor.draft.item.sections.firstIndex(where: { $0.id == sectionID }),
                    editor.draft.item.sections[s].fields.indices.contains(index)
                else { return }
                editor.draft.item.sections[s].fields[index].label = label
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
