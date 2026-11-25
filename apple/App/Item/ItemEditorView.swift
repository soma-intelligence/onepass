import DesignKit
import SwiftUI
import VaultKit

/// The one editor of the 26 types (spec 6.4), in cards (spec 2026-11-13): the header (icon menu,
/// title), the main card, the other template sections, then the movable cards (websites and free
/// sections, ☰ handles), "+ ajouter plus", notes, places, tags and options. A validation error shows
/// under its field and the form scrolls to it. "Annuler" asks before dropping changes.
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
    /// The keyboard chain (iOS): the field that has the keyboard, the field asked to take it, and
    /// where to scroll for it.
    @State private var chainFocus: String?
    @State private var focusRequest: EditorFocusRequest?
    @State private var chainScroll: String?
    @Environment(\.rxCards) private var rxCards
    /// "+ ajouter un lieu": the place search sheet.
    @State private var searchingPlace = false
    private let onDone: (FfiItem?) -> Void

    init(draft: ItemDraft, isNew: Bool, onDone: @escaping (FfiItem?) -> Void) {
        _editor = State(initialValue: ItemEditorModel(draft: draft, isNew: isNew))
        self.onDone = onDone
    }

    private var item: FfiItem { editor.draft.item }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: rxCards ? Theme.RX.Space.l : Theme.Space.l) {
                    EditorHeader(editor: editor, titleFocused: $titleFocused)
                    if let error = editor.generalError {
                        EditorCard {
                            Label(error, systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(rxCards ? Theme.RX.Palette.negative.color : Color.red)
                                .editorRowPadding()
                        }
                    }
                    ForEach(item.sections.filter { !editor.draft.isFreeSection($0.id) }, id: \.id) { section in
                        TemplateSectionCard(editor: editor, section: section) { sectionID, key in
                            passkeyRemoval = PasskeyRemoval(sectionID: sectionID, key: key)
                        }
                    }
                    movableCards
                    AddMoreCard(editor: editor)
                    notesCard
                    locationsCard
                    VStack(alignment: .leading, spacing: Theme.Space.s) {
                        EditorLabel(String(localized: "item.tags")).padding(.leading, Theme.Space.l)
                        TagEditor(draft: $editor.draft).padding(.horizontal, Theme.Space.l)
                    }
                    optionsCard
                }
                #if os(macOS)
                // The detail's readable column, so editing keeps every card in place.
                .frame(maxWidth: ItemDetailView.macReadableWidth)
                .padding(.horizontal, Theme.Space.xl)
                #else
                .padding(.horizontal, Theme.Space.xl)
                .frame(maxWidth: 760)
                #endif
                .padding(.vertical, Theme.Space.xl)
                .frame(maxWidth: .infinity)
                #if os(macOS)
                .textFieldStyle(.plain)
                #endif
            }
            #if !os(visionOS)
            .scrollDismissesKeyboard(.interactively)
            #endif
            #if os(macOS)
            // Fields scrolling up fade out under the toolbar instead of running behind Annuler and
            // Enregistrer (they float without glass of their own). RX: a soft fade, so the
            // title bar stays see-through with no band behind it.
            .scrollEdgeEffectStyle(rxCards ? .soft : .hard, for: .top)
            .scrollIndicators(.never)
            #endif
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
            .onChange(of: chainScroll) { _, anchor in
                guard let anchor else { return }
                withAnimation { proxy.scrollTo(anchor, anchor: .center) }
                chainScroll = nil
            }
            .onChange(of: editor.scrollRequest) {
                guard let anchor = editor.errorAnchor else { return }
                withAnimation { proxy.scrollTo(anchor, anchor: .center) }
                if anchor == ItemEditorModel.titleAnchor { titleFocused = true }
            }
        }
        #if os(iOS)
        .environment(\.editorFocusRequest, focusRequest)
        .environment(\.editorAdvance) { id in advance(from: id) }
        .environment(\.editorFieldFocused) { id in chainFocus = id }
        .onChange(of: titleFocused) { _, now in if now { chainFocus = EditorKeyboardChain.titleID } }
        #endif
        .navigationTitle(editor.isNew ? Text("Nouvel élément") : Text("Modification"))
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        #endif
        .toolbar {
            #if os(macOS)
            // Right of the detail column: Annuler as quiet text, Enregistrer as one accent capsule. Each
            // item keeps out of the toolbar's shared glass, which fused them into one heavy pill.
            ToolbarSpacer(.flexible)
            ToolbarItem(placement: .primaryAction) {
                cancelButton.buttonStyle(QuietToolbarButtonStyle())
            }
            .sharedBackgroundVisibility(.hidden)
            ToolbarItem(placement: .primaryAction) {
                saveButton.buttonStyle(AccentCapsuleButtonStyle())
            }
            .sharedBackgroundVisibility(.hidden)
            #else
            ToolbarItem(placement: .cancellationAction) { cancelButton }
            ToolbarItem(placement: .confirmationAction) { saveButton }
            #endif
            #if os(iOS)
            // Number and phone pads have no Return: the bar above the keyboard moves on or closes it.
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button("editor.keyboard.next") { advance(from: chainFocus ?? EditorKeyboardChain.titleID) }
                    .disabled(nextFocus(after: chainFocus ?? EditorKeyboardChain.titleID) == nil)
                    .accessibilityIdentifier("editor.keyboard.next")
                Button("common.ok") { dismissKeyboard() }
                    .fontWeight(.semibold)
                    .accessibilityIdentifier("editor.keyboard.done")
            }
            #endif
        }
        .confirmationDialog("Abandonner les modifications ?", isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Abandonner", role: .destructive) { onDone(nil) }
            Button("app.keepEditing", role: .cancel) {}
        }
        .confirmationDialog(
            "Supprimer la passkey ?",
            isPresented: Binding(get: { passkeyRemoval != nil }, set: { if !$0 { passkeyRemoval = nil } }),
            titleVisibility: .visible, presenting: passkeyRemoval
        ) { removal in
            Button("item.deletePasskey", role: .destructive) {
                if let i = editor.index(of: removal.key, sectionID: removal.sectionID) {
                    editor.removePasskey(sectionID: removal.sectionID, fieldIndex: i)
                }
                passkeyRemoval = nil
            }
            .accessibilityIdentifier("editor.passkey.confirmRemove")
            Button("Annuler", role: .cancel) { passkeyRemoval = nil }
        } message: { _ in
            Text("item.onceSaveWontAble")
        }
        .interactiveDismissDisabled(editor.isDirty)
        // A lock or a navigation asks first while the draft has unsaved changes (`AppModel.perform`).
        .onChange(of: editor.isDirty, initial: true) { _, dirty in model.editorDirty = dirty }
        .onDisappear {
            model.editorDirty = false
            // A removed field's Undo holds its value (a password, a seed): it goes with the editor.
            model.dropToastActions(owner: editor)
        }
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

    /// ⌘S is the "Enregistrer" menu command (`BrowseCommands`). While saving, a small spinner
    /// takes the label's place at the same width.
    private var saveButton: some View {
        Button(action: save) {
            ZStack {
                Text("Enregistrer").opacity(editor.saving ? 0 : 1)
                if editor.saving {
                    ProgressView().controlSize(.small)
                }
            }
        }
        .disabled(editor.saving)
        .accessibilityLabel(Text("Enregistrer"))
        .accessibilityIdentifier("editor.save")
    }

    // MARK: - Keyboard chain (iOS)

    /// The typed rows in screen order, after the title: the template cards, then the free sections
    /// in their order. Each with its scroll anchor.
    private var focusOrder: [(id: String, anchor: String)] {
        var order: [(id: String, anchor: String)] = [(EditorKeyboardChain.titleID, ItemEditorModel.titleAnchor)]
        func add(_ section: FfiSection, rows: [(position: Int, key: UUID)]) {
            for row in rows where section.fields.indices.contains(row.position) {
                guard EditorFieldRow.isTyped(section.fields[row.position].kind) else { continue }
                order.append((EditorFieldRow.focusID(sectionID: section.id, key: row.key),
                              ItemEditorModel.anchor(sectionID: section.id, fieldIndex: row.position)))
            }
        }
        for section in item.sections where !editor.draft.isFreeSection(section.id) {
            add(section, rows: editor.shownRows(section))
        }
        for slot in editor.slots {
            guard case .section(let id) = slot, let section = item.sections.first(where: { $0.id == id }) else { continue }
            add(section, rows: editor.shownRows(section))
        }
        return order
    }

    private func nextFocus(after id: String) -> (id: String, anchor: String)? {
        let order = focusOrder
        guard let index = order.firstIndex(where: { $0.id == id }), order.indices.contains(index + 1) else { return nil }
        return order[index + 1]
    }

    /// Return or "Suivant": the next typed row takes the keyboard; after the last one it closes.
    private func advance(from id: String) {
        guard let next = nextFocus(after: id) else {
            dismissKeyboard()
            return
        }
        chainScroll = next.anchor
        if next.id == EditorKeyboardChain.titleID {
            titleFocused = true
        } else {
            titleFocused = false
            focusRequest = EditorFocusRequest(target: next.id, serial: (focusRequest?.serial ?? 0) + 1)
        }
    }

    private func dismissKeyboard() {
        titleFocused = false
        #if os(iOS)
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
        #endif
        chainFocus = nil
    }

    // MARK: - Cards

    /// The websites card and the free sections, in their order, each with its ☰ handle.
    private var movableCards: some View {
        ReorderableStack(
            items: editor.slots.map(SlotID.init), spacing: Theme.Space.l,
            accessibilityName: { slot in Text(verbatim: name(of: slot.slot)) },
            handleIdentifier: { slot in
                switch slot.slot {
                case .websites: "editor.reorder.websites"
                case .section(let id): "editor.reorder.\(id)"
                }
            },
            onMove: { from, to in editor.moveSlot(from: from, to: to) }
        ) { slot, handle in
            switch slot.slot {
            case .websites: WebsitesCard(editor: editor, handle: handle)
            case .section(let id): FreeSectionCard(editor: editor, sectionID: id, handle: handle)
            }
        }
    }

    private func name(of slot: EditorSlot) -> String {
        switch slot {
        case .websites: String(localized: "app.website")
        case .section(let id): item.sections.first { $0.id == id }?.label ?? ""
        }
    }

    private struct SlotID: Identifiable {
        let slot: EditorSlot
        var id: EditorSlot { slot }
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
            AddRowButton(title: item.locations.isEmpty ? String(localized: "item.addPlace2") : String(localized: "item.addAnotherPlace")) {
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
            VStack(alignment: .leading, spacing: Theme.Space.xs) {
                EditorLabel(String(localized: "item.notes"))
                // No inner box: the note reads as part of its card.
                TextEditor(text: $editor.draft.item.notes)
                    .scrollContentBackground(.hidden)
                    .scrollIndicators(.never)
                    .font(.body)
                    .frame(minHeight: 48)
                    .overlay(alignment: .topLeading) {
                        if item.notes.isEmpty {
                            Text("item.addNotesAboutItem")
                                .foregroundStyle(.tertiary)
                                .padding(.leading, Theme.Space.xs)
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
        VStack(alignment: .leading, spacing: Theme.Space.s) {
            EditorCard {
                HStack {
                    Text("term.vault")
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
                    .help("item.faceIdTouchId")
                    .accessibilityIdentifier("editor.reprompt")
            }
            // Travel Mode per item (spec 2026-11-02): hidden leaves the device, extra protection asks
            // for the password and biometrics while travelling.
            EditorCard {
                OptionToggle(title: "item.travel.hidden", isOn: $editor.draft.item.travelHidden)
                    .help("item.travel.hidden.help")
                    .accessibilityIdentifier("editor.travelHidden")
                CardDivider()
                OptionToggle(title: "item.travel.guard", isOn: $editor.draft.item.travelGuard)
                    .help("item.travel.guard.help")
                    .disabled(editor.draft.item.travelHidden)
                    .accessibilityIdentifier("editor.travelGuard")
            }
            Text(editor.draft.item.travelHidden
                ? "item.travel.footer.hidden"
                : "item.travel.footer")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding(.horizontal, Theme.Space.l)

        }
    }

    // MARK: - Bindings and actions

    /// A passkey row waiting for the removal confirmation.
    private struct PasskeyRemoval: Equatable {
        var sectionID: String
        var key: UUID
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

/// Ids of the editor's keyboard chain that are not field rows.
enum EditorKeyboardChain {
    static let titleID = "title"
}
