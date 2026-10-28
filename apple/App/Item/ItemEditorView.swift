import DesignKit
import SwiftUI
import VaultKit

/// The one editor of the 26 types (spec 6.4), driven by the item's template sections and the core's
/// menu options: title first (focused at creation), vault, favorite, websites, template fields with
/// "+ ajouter" for repeatable ones, "+ ajouter un champ", notes, tags. A validation error shows under
/// its field and the form scrolls to it. "Annuler" asks before dropping changes.
struct ItemEditorView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var editor: ItemEditorModel
    @State private var confirmDiscard = false
    /// The generator asked by a password field (presented here, not from the field's row).
    @State private var generatorRequest: GeneratorRequest?
    /// A passkey whose removal waits for "Supprimer la passkey ?" (section id, row key).
    @State private var passkeyRemoval: PasskeyRemoval?
    @FocusState private var titleFocused: Bool
    /// "Tout afficher": shows every template field left empty.
    @State private var showAllFields = false
    /// "+ ajouter un lieu": the place search sheet.
    @State private var searchingPlace = false
    /// "ajouter plus": its popover is open.
    @State private var addingField = false
    /// Rows shown while folded: required, autofill or filled at opening, and rows added since. A row
    /// emptied while editing stays put.
    @State private var pinnedKeys: Set<UUID>
    private let onDone: (FfiItem?) -> Void

    init(draft: ItemDraft, isNew: Bool, onDone: @escaping (FfiItem?) -> Void) {
        let editor = ItemEditorModel(draft: draft, isNew: isNew)
        _editor = State(initialValue: editor)
        var pinned = Set<UUID>()
        for (sectionIndex, section) in draft.item.sections.enumerated() {
            for (position, (key, field)) in zip(editor.keys(sectionID: section.id), section.fields).enumerated()
            where Self.isEssential(field, sectionID: section.id, leading: sectionIndex == 0 && position < 3) {
                pinned.insert(key)
            }
        }
        _pinnedKeys = State(initialValue: pinned)
        self.onDone = onDone
    }

    private var item: FfiItem { editor.draft.item }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    titleHeader
                    if let error = editor.generalError {
                        EditorCard {
                            Label(error, systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.red)
                                .editorRowPadding()
                        }
                    }
                    ForEach(Array(item.sections.enumerated()), id: \.element.id) { _, section in
                        if !visibleRows(section).isEmpty { fieldSection(section) }
                    }
                    if item.itemType == .login {
                        LoginMethodCard(item: $editor.draft.item)
                    }
                    // Websites and the folded fields share one block: two lone "+" rows read as clutter.
                    EditorCard {
                        UrlListEditor(editor: editor)
                        CardDivider()
                        addMoreMenu
                    }
                    notesCard
                    locationsCard
                    VStack(alignment: .leading, spacing: 8) {
                        EditorLabel("tags").padding(.leading, 16)
                        TagEditor(draft: $editor.draft).padding(.horizontal, 16)
                    }
                    optionsCard
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 20)
                .frame(maxWidth: 760)
                .frame(maxWidth: .infinity)
                #if os(macOS)
                .textFieldStyle(.plain)
                #endif
            }
            .scrollDismissesKeyboard(.interactively)
            .defaultScrollAnchor(.top)
            .groupedScreen()
            .environment(\.requestGenerator) { request in generatorRequest = request }
            .sheet(item: $generatorRequest) { request in
                GeneratorSheet(onUse: { _ in }, onUseWithBits: { text, bits in request.apply(text, bits) })
            }
            .task {
                // On the Mac the notes' text view takes the first responder when the editor
                // appears and scrolls the form down to it: start from the title instead.
                try? await Task.sleep(for: .milliseconds(120))
                proxy.scrollTo(ItemEditorModel.titleAnchor, anchor: .top)
                if editor.isNew { titleFocused = true }
            }
            .onChange(of: editor.scrollRequest) {
                guard let anchor = editor.errorAnchor else { return }
                withAnimation { proxy.scrollTo(anchor, anchor: .center) }
                if anchor == ItemEditorModel.titleAnchor { titleFocused = true }
            }
        }
        .navigationTitle(editor.isNew ? Text("Nouvel élément") : Text("Modification"))
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        #endif
        .toolbar {
            #if os(macOS)
            // Glass buttons on the right of the detail column, Enregistrer as the prominent one.
            ToolbarSpacer(.flexible)
            ToolbarItemGroup(placement: .primaryAction) {
                cancelButton
                saveButton.buttonStyle(.glassProminent)
            }
            #else
            ToolbarItem(placement: .cancellationAction) { cancelButton }
            ToolbarItem(placement: .confirmationAction) { saveButton }
            #endif
        }
        .confirmationDialog("Abandonner les modifications ?", isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Abandonner", role: .destructive) { onDone(nil) }
            Button("Continuer la modification", role: .cancel) {}
        }
        .confirmationDialog(
            "Supprimer la passkey ?",
            isPresented: Binding(get: { passkeyRemoval != nil }, set: { if !$0 { passkeyRemoval = nil } }),
            titleVisibility: .visible, presenting: passkeyRemoval
        ) { removal in
            Button("Supprimer la passkey", role: .destructive) {
                if let i = editor.index(of: removal.key, sectionID: removal.sectionID) {
                    editor.removePasskey(sectionID: removal.sectionID, fieldIndex: i)
                }
                passkeyRemoval = nil
            }
            .accessibilityIdentifier("editor.passkey.confirmRemove")
            Button("Annuler", role: .cancel) { passkeyRemoval = nil }
        } message: { _ in
            Text("Après l'enregistrement, tu ne pourras plus te connecter à ce site avec cette passkey. Le site la garde dans ton compte : supprime-la aussi dans ses réglages.")
        }
        .interactiveDismissDisabled(editor.isDirty)
        // A lock or a navigation asks first while the draft has unsaved changes (`AppModel.perform`).
        .onChange(of: editor.isDirty, initial: true) { _, dirty in model.editorDirty = dirty }
        .onDisappear { model.editorDirty = false }
        .onChange(of: model.saveRequest) { save() }
        // Typing counts as activity: a long edit does not auto-lock under the user's fingers.
        .onChange(of: editor.draft) { model.session.noteActivity() }
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

    private var cancelButton: some View {
        Button("Annuler", action: cancel)
            .keyboardShortcut(.cancelAction)
            .accessibilityIdentifier("editor.cancel")
    }

    /// ⌘S is the "Enregistrer" menu command (`BrowseCommands`).
    private var saveButton: some View {
        Button("Enregistrer", action: save)
            .disabled(editor.saving)
            .accessibilityIdentifier("editor.save")
    }

    // MARK: - Sections

    #if os(iOS)
    private static let titleHairline = Color.primary.opacity(0.06)
    #else
    private static let titleHairline = Color.white.opacity(0.08)
    #endif

    private var titleHeader: some View {
        VStack(alignment: .leading, spacing: 10) {
            #if !os(iOS)
            // iPhone: the navigation bar already says it.
            Text(editor.isNew ? "Nouvel élément" : "Modification")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(Theme.accent.mix(with: .white, by: 0.3))
                .textCase(.uppercase)
                .tracking(0.6)
            #endif
            HStack(alignment: .center, spacing: 16) {
                ItemIcon(type: item.itemType, title: item.title, siteIcon: nil, size: 64)
                TextField("Titre", text: $editor.draft.item.title, prompt: Text(ItemCategory.of(item.itemType).singular))
                    .textFieldStyle(.plain)
                    .font(.system(size: 26, weight: .bold))
                    .focused($titleFocused)
                    .onChange(of: item.title) { editor.clearError(for: "title") }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    #if os(iOS)
                    .background(Color(uiColor: .secondarySystemGroupedBackground), in: .rect(cornerRadius: 12))
                    #else
                    .background(.fill.quaternary, in: .rect(cornerRadius: 12))
                    #endif
                    .overlay {
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(titleFocused ? AnyShapeStyle(Theme.accent.opacity(0.9)) : AnyShapeStyle(Self.titleHairline),
                                lineWidth: titleFocused ? 1.5 : 1)
                    }
                    .animation(.easeOut(duration: 0.15), value: titleFocused)
                    .accessibilityIdentifier("editor.title")
            }
            if let message = editor.titleMessage {
                Label(message, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.leading, 80)
                    .accessibilityIdentifier("editor.error")
            }
        }
        .padding(.bottom, 8)
        .id(ItemEditorModel.titleAnchor)
    }

    @ViewBuilder private func fieldSection(_ section: FfiSection) -> some View {
        let isCustom = section.id == ItemDraft.customSectionID
        let rows = visibleRows(section)
        VStack(alignment: .leading, spacing: 8) {
            if item.sections.count > 1 || isCustom {
                EditorLabel(section.displayLabel(itemType: item.itemType)).padding(.leading, 16)
            }
            EditorCard {
                ForEach(Array(rows.enumerated()), id: \.element.key) { order, row in
                    if let field = section.fields[safe: row.position] {
                        if order > 0 { CardDivider() }
                        fieldRow(sectionID: section.id, key: row.key, field: field, isCustom: isCustom)
                            .id(ItemEditorModel.anchor(sectionID: section.id, fieldIndex: row.position))
                        // Passkeys and files are read only here: nothing to add by hand.
                        if editor.draft.canRepeat(sectionID: section.id, fieldIndex: row.position),
                            field.kind != .passkey, field.kind != .file
                        {
                            CardDivider()
                            AddRowButton(title: "ajouter \(field.displayLabel(itemType: item.itemType).lowercasedFirst)") {
                                editor.addRepeat(of: field.id, in: section.id)
                                pinLastRow(of: field.id, in: section.id)
                            }
                            .accessibilityLabel(Text("Ajouter \(field.displayLabel(itemType: item.itemType))"))
                            .accessibilityIdentifier("editor.repeat.\(field.id)")
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder private func fieldRow(sectionID: String, key: UUID, field: FfiField, isCustom: Bool) -> some View {
        let index = editor.index(of: key, sectionID: sectionID) ?? 0
        let removable = editor.draft.isRemovable(sectionID: sectionID, fieldIndex: index)
        HStack(alignment: .center, spacing: 12) {
            if isCustom {
                VStack(alignment: .leading, spacing: 4) {
                    TextField("Libellé", text: labelBinding(sectionID, key), prompt: Text(ItemDraft.defaultLabel(field.kind)))
                        .font(.callout)
                        .foregroundStyle(Theme.accent)
                        .accessibilityIdentifier("editor.label.\(field.id)")
                    FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding(sectionID, key))
                    errorText(sectionID, index)
                }
            } else {
                EditorRow(
                    label: isRequired(field) ? "\(field.displayLabel(itemType: item.itemType).lowercasedFirst) *" : field.displayLabel(itemType: item.itemType).lowercasedFirst,
                    message: editor.message(sectionID: sectionID, fieldIndex: index)
                ) {
                    FieldEditor(field: field, itemType: item.itemType, ownID: item.id, value: valueBinding(sectionID, key))
                }
            }
            if field.kind == .passkey, field.value != .empty {
                // Spec 6: a passkey is removed here, after a confirmation, whatever its position.
                RemoveRowButton {
                    passkeyRemoval = PasskeyRemoval(sectionID: sectionID, key: key)
                }
                .accessibilityLabel(Text("Supprimer la passkey"))
                .accessibilityIdentifier("editor.remove.\(field.id)")
            } else if removable {
                RemoveRowButton {
                    if let i = editor.index(of: key, sectionID: sectionID) {
                        editor.removeField(sectionID: sectionID, fieldIndex: i)
                    }
                }
                .accessibilityLabel(Text("Retirer \(field.displayLabel(itemType: item.itemType))"))
                .accessibilityIdentifier("editor.remove.\(field.id)")
            }
        }
        .editorRowPadding()
    }

    @ViewBuilder private func errorText(_ sectionID: String, _ index: Int) -> some View {
        if let message = editor.message(sectionID: sectionID, fieldIndex: index) {
            Label(message, systemImage: "exclamationmark.circle.fill").font(.footnote).foregroundStyle(.red)
        }
    }

    /// "ajouter plus": a popover with a search, the template fields folded away (one at a time, or
    /// all), then a grid of custom field kinds.
    private var addMoreMenu: some View {
        Button {
            addingField.toggle()
        } label: {
            HStack {
                Label("ajouter plus", systemImage: "plus")
                    .foregroundStyle(Theme.accent)
                Spacer()
                Image(systemName: "chevron.down").foregroundStyle(.secondary)
            }
            .font(.body.weight(.medium))
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .editorRowPadding()
        .accessibilityIdentifier("editor.addField")
        .popover(isPresented: $addingField, arrowEdge: .bottom) {
            AddFieldPopover(
                hidden: hiddenRows.map { AddFieldPopover.Hidden(key: $0.key, label: $0.label, symbol: Self.symbol(for: $0.field)) },
                customKinds: Self.customKinds.map { kind, label in
                    AddFieldPopover.Kind(kind: kind, label: label, symbol: Self.symbol(for: kind))
                },
                showAll: {
                    addingField = false
                    withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { showAllFields = true }
                },
                reveal: { key in
                    addingField = false
                    withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { _ = pinnedKeys.insert(key) }
                },
                addCustom: { kind in
                    addingField = false
                    withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { editor.addCustomField(kind: kind) }
                })
            .presentationCompactAdaptation(.popover)
        }
    }

    /// Symbol of a template field in the "ajouter plus" popover: by its id where the kind says too
    /// little (PIN, codes de secours, question), else by its kind.
    static func symbol(for field: FfiField) -> String {
        switch field.id {
        case "totp": return "timer"
        case "pin": return "number"
        case "backup_codes": return "list.number"
        case "security_question": return "questionmark.bubble"
        case "security_answer": return "key"
        case "recovery_phone": return "phone"
        default: return symbol(for: field.kind)
        }
    }

    static func symbol(for kind: FfiFieldType) -> String {
        switch kind {
        case .text: "textformat"
        case .concealed: "eye.slash"
        case .password: "key"
        case .url: "link"
        case .email: "envelope"
        case .phone: "phone"
        case .date: "calendar"
        case .monthYear: "calendar.badge.clock"
        case .number: "number"
        case .money: "eurosign"
        case .address: "house"
        case .menu: "list.bullet"
        case .otp: "timer"
        case .passkey: "person.badge.key"
        case .sshKey: "terminal"
        case .file: "paperclip"
        case .location: "mappin.and.ellipse"
        case .mnemonic: "text.word.spacing"
        case .barcode: "barcode"
        case .itemLink: "link.badge.plus"
        }
    }

    /// The item's places (`FfiItem.locations`, read by "À proximité"): a map card per place with a
    /// remove button, then "+ ajouter un lieu" which opens the place search.
    private var locationsCard: some View {
        EditorCard {
            ForEach(Array(item.locations.enumerated()), id: \.offset) { index, location in
                PlaceBlock(location: location) {
                    RemoveRowButton {
                        withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) {
                            guard editor.draft.item.locations.indices.contains(index) else { return }
                            editor.draft.item.locations.remove(at: index)
                        }
                    }
                    .accessibilityLabel(Text("Retirer \(location.label)"))
                    .accessibilityIdentifier("editor.location.remove.\(index)")
                }
                .accessibilityIdentifier("editor.location.\(index)")
                CardDivider()
            }
            AddRowButton(title: item.locations.isEmpty ? "ajouter un lieu" : "ajouter un autre lieu") {
                searchingPlace = true
            }
            .accessibilityIdentifier("editor.location")
        }
        .sheet(isPresented: $searchingPlace) {
            LocationSearchSheet { place in
                withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { editor.draft.item.locations.append(place) }
            }
        }
    }

    private var notesCard: some View {
        EditorCard {
            VStack(alignment: .leading, spacing: 4) {
                EditorLabel("notes")
                // No inner box: the note reads as part of its card.
                TextEditor(text: $editor.draft.item.notes)
                    .scrollContentBackground(.hidden)
                    .scrollIndicators(.never)
                    .font(.body)
                    .frame(minHeight: 48)
                    .overlay(alignment: .topLeading) {
                        if item.notes.isEmpty {
                            Text("Ajoute des notes sur cet élément.")
                                .foregroundStyle(.tertiary)
                                .padding(.leading, 5)
                                .allowsHitTesting(false)
                        }
                    }
                    .accessibilityIdentifier("editor.notes")
            }
            .editorRowPadding()
        }
    }

    /// Where the item lives and how it behaves: vault, favorite, Watch, confirmation.
    private var optionsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            EditorCard {
                HStack {
                    Text("Coffre")
                    Spacer()
                    VaultPicker(vaultID: $editor.targetVaultID).labelsHidden().fixedSize()
                }
                .editorRowPadding()
                CardDivider()
                OptionToggle(title: "Favori", isOn: $editor.draft.item.favorite)
                    .accessibilityIdentifier("editor.favorite")
                CardDivider()
                OptionToggle(title: "Sur l'Apple Watch", isOn: $editor.draft.item.onWatch)
                    .accessibilityIdentifier("editor.onWatch")
                CardDivider()
                OptionToggle(title: "Confirmer avant d'afficher", isOn: $editor.draft.item.reprompt)
                    .help("Face ID, Touch ID ou le mot de passe maître sera demandé avant d'afficher cet élément.")
                    .accessibilityIdentifier("editor.reprompt")
            }

        }
    }

    static let customKinds: [(FfiFieldType, String)] = [
        (.text, String(localized: "Texte")), (.concealed, String(localized: "Masqué")),
        (.password, String(localized: "Mot de passe")), (.date, String(localized: "Date")),
        (.url, String(localized: "URL")), (.email, String(localized: "Email")),
        (.phone, String(localized: "Téléphone")), (.location, String(localized: "Lieu")),
    ]

    /// A login that signs in through a provider needs no username (core validation).
    private func isRequired(_ field: FfiField) -> Bool {
        guard field.required else { return false }
        if item.itemType == .login, field.id == "username",
            item.loginMethods.contains(where: { if case .provider = $0 { true } else { false } })
        {
            return false
        }
        return true
    }

    // MARK: - Folding

    /// Required and filled fields, plus the first three of the item's first section (the template
    /// puts the main ones there: identifiant, mot de passe, email; immatriculation, marque,
    /// modèle). Custom fields always show; an empty passkey row says nothing until a site creates one.
    private static func isEssential(_ field: FfiField, sectionID: String, leading: Bool) -> Bool {
        if sectionID == ItemDraft.customSectionID { return true }
        if field.kind == .passkey { return field.value != .empty }
        return field.required || field.value != .empty || leading
    }

    /// The rows of a section shown now, as (index in the section, stable key). A row with a
    /// validation error always shows.
    private func visibleRows(_ section: FfiSection) -> [(position: Int, key: UUID)] {
        editor.keys(sectionID: section.id).enumerated().compactMap { position, key in
            let shown = showAllFields || section.id == ItemDraft.customSectionID || pinnedKeys.contains(key)
                || editor.message(sectionID: section.id, fieldIndex: position) != nil
            return shown ? (position, key) : nil
        }
    }

    /// The folded template fields, in template order, for the "ajouter plus" popover.
    private var hiddenRows: [(key: UUID, label: String, field: FfiField)] {
        item.sections.flatMap { section in
            let shown = Set(visibleRows(section).map(\.key))
            return zip(editor.keys(sectionID: section.id), section.fields).compactMap { key, field in
                shown.contains(key) || field.kind == .passkey || field.kind == .file ? nil : (key, field.displayLabel(itemType: item.itemType), field)
            }
        }
    }

    /// A repeat just added stays visible: the last row carrying the field's id.
    private func pinLastRow(of fieldID: String, in sectionID: String) {
        guard let fields = item.sections.first(where: { $0.id == sectionID })?.fields,
            let index = fields.lastIndex(where: { $0.id == fieldID }),
            let key = editor.keys(sectionID: sectionID)[safe: index]
        else { return }
        pinnedKeys.insert(key)
    }

    // MARK: - Bindings and actions

    /// A passkey row waiting for the removal confirmation.
    private struct PasskeyRemoval: Equatable {
        var sectionID: String
        var key: UUID
    }

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

private extension String {
    /// "Codes de secours 2FA" → "codes de secours 2FA", for "Ajouter codes de secours 2FA". An
    /// acronym first ("PIN", "URL") stays as is.
    var lowercasedFirst: String {
        guard let first, first.isUppercase else { return self }
        let second = dropFirst().first
        if let second, second.isUppercase { return self }
        return first.lowercased() + dropFirst()
    }
}

/// A switch row of the options card: the title on the left, the switch on the right.
private struct OptionToggle: View {
    let title: LocalizedStringKey
    @Binding var isOn: Bool

    var body: some View {
        Toggle(isOn: $isOn) {
            Text(title).frame(maxWidth: .infinity, alignment: .leading)
        }
        .toggleStyle(.switch)
        .editorRowPadding()
    }
}

/// The "ajouter plus" popover: a search over everything it offers, the folded template fields as
/// icon rows (with "Tout afficher"), then the custom field kinds as a grid of small tiles.
private struct AddFieldPopover: View {
    struct Hidden: Identifiable {
        let key: UUID
        let label: String
        let symbol: String
        var id: UUID { key }
    }

    struct Kind: Identifiable {
        let kind: FfiFieldType
        let label: String
        let symbol: String
        var id: String { label }
    }

    let hidden: [Hidden]
    let customKinds: [Kind]
    let showAll: () -> Void
    let reveal: (UUID) -> Void
    let addCustom: (FfiFieldType) -> Void
    @State private var query = ""
    @FocusState private var searchFocused: Bool

    private var trimmed: String { query.trimmingCharacters(in: .whitespaces) }

    private var shownHidden: [Hidden] {
        trimmed.isEmpty ? hidden : hidden.filter { $0.label.localizedStandardContains(trimmed) }
    }

    private var shownKinds: [Kind] {
        trimmed.isEmpty ? customKinds : customKinds.filter { $0.label.localizedStandardContains(trimmed) }
    }

    private static let columns = Array(repeating: GridItem(.flexible(), spacing: 6), count: 4)

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Rechercher un champ", text: $query)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    .accessibilityIdentifier("editor.addField.search")
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(.fill.quaternary, in: .rect(cornerRadius: 8))
            .overlay { RoundedRectangle(cornerRadius: 8).strokeBorder(.white.opacity(0.07)) }

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if !shownHidden.isEmpty {
                        HStack {
                            heading("Champs du modèle")
                            Spacer()
                            if hidden.count > 1, trimmed.isEmpty {
                                Button("Tout afficher", action: showAll)
                                    .buttonStyle(.plain)
                                    .font(.subheadline.weight(.medium))
                                    .foregroundStyle(Theme.accent)
                                    .accessibilityIdentifier("editor.moreFields")
                            }
                        }
                        VStack(spacing: 1) {
                            ForEach(shownHidden) { row in
                                AddFieldRow(label: row.label, symbol: row.symbol) { reveal(row.key) }
                            }
                        }
                    }
                    if !shownKinds.isEmpty {
                        if !shownHidden.isEmpty { Divider() }
                        heading("Champ personnalisé")
                        LazyVGrid(columns: Self.columns, spacing: 6) {
                            ForEach(shownKinds) { kind in
                                AddFieldTile(label: kind.label, symbol: kind.symbol) { addCustom(kind.kind) }
                                    .accessibilityIdentifier("editor.addField.custom.\(String(describing: kind.kind))")
                            }
                        }
                    }
                    if shownHidden.isEmpty, shownKinds.isEmpty {
                        Text("Aucun champ ne correspond.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                    }
                }
            }
            .frame(maxHeight: 420)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(width: 340)
        .onAppear { searchFocused = true }
    }

    private func heading(_ text: LocalizedStringKey) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .textCase(.uppercase)
    }
}

private struct AddFieldRow: View {
    let label: String
    let symbol: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(Theme.accent))
                    .frame(width: 24, height: 24)
                    .background(hovering ? AnyShapeStyle(.white.opacity(0.15)) : AnyShapeStyle(Theme.accent.opacity(0.14)),
                        in: .rect(cornerRadius: 6))
                Text(label).foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
                Spacer(minLength: 0)
                Image(systemName: "plus")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.white)
                    .opacity(hovering ? 1 : 0)
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.85)) : AnyShapeStyle(.clear), in: .rect(cornerRadius: 7))
            .contentShape(.rect(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

private struct AddFieldTile: View {
    let label: String
    let symbol: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 5) {
                Image(systemName: symbol)
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(Theme.accent))
                    .frame(height: 20)
                Text(label)
                    .font(.caption)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 9)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.85)) : AnyShapeStyle(.fill.quaternary),
                in: .rect(cornerRadius: 9))
            .overlay { RoundedRectangle(cornerRadius: 9).strokeBorder(.white.opacity(0.07)) }
            .contentShape(.rect(cornerRadius: 9))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
