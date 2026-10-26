import DesignKit
import SwiftUI
import VaultKit

/// Detail of one item, shared by iPhone, iPad and Mac (mockups `PhoneItem` and `Main`): header,
/// non-empty fields by section, websites, tags, Markdown notes, dates, link to previous passwords,
/// and the item menu. Edition replaces the detail in place (`AppModel.editing`). The full item lives
/// in this view's state only (dropped with the view, and the whole tree goes away on lock).
/// A `reprompt` item asks for biometrics or the master password before showing anything.
struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    private let ref: ItemRef

    @State private var item: FfiItem?
    @State private var loadError: String?
    @State private var actionError: String?
    @State private var toast: String?
    @State private var confirmDelete = false
    // Reprompt.
    @State private var confirmed = false
    @State private var askPassword = false
    @State private var password = ""
    @State private var repromptError: String?
    @State private var checking = false
    /// "Modifier" was pressed on a reprompt item: edit once confirmed.
    @State private var editAfterConfirm = false
    /// While editing, a remote change replaced the stored item the editor started from.
    @State private var remoteVersion: FfiItem?

    init(ref: ItemRef) { self.ref = ref }

    private var session: VaultSession { model.session }

    var body: some View {
        Group {
            if let item {
                if model.editing, !locked(item) {
                    ItemEditorView(draft: ItemDraft(item: item), isNew: false) { saved in
                        finishEditing(saved)
                    }
                } else {
                    detail(item)
                }
            } else if let loadError {
                EmptyState(title: String(localized: "Élément indisponible"), systemImage: "exclamationmark.triangle",
                           message: loadError)
            } else {
                ProgressView()
            }
        }
        .task(id: ref) { await load() }
        .onChange(of: model.editRequest) {
            if let item, model.selectedItem == ref { startEditing(item) }
        }
        .onDisappear { model.editing = false }
        // A remote change set was applied: show the stored item, or warn the editor (spec 8).
        .onChange(of: model.remoteRevision) {
            Task { await remoteChanged() }
        }
        .alert(
            "Élément modifié sur un autre appareil",
            isPresented: Binding(get: { remoteVersion != nil }, set: { if !$0 { remoteVersion = nil } })
        ) {
            Button("Recharger", role: .destructive) {
                if let remoteVersion { item = remoteVersion }
                remoteVersion = nil
                model.editing = false
            }
            Button("Continuer la modification", role: .cancel) { remoteVersion = nil }
        } message: {
            Text("Si tu enregistres, tes modifications remplaceront cette nouvelle version. Recharger abandonne tes modifications.")
        }
    }

    /// Not editing: the detail shows what the store now holds (or "introuvable"). Editing: the draft
    /// is kept, and the user chooses between reloading and overwriting.
    private func remoteChanged() async {
        guard let current = item, session.state == .unlocked else { return }
        let target = ItemRef(vaultID: current.vaultId, itemID: current.id)
        guard model.editing else {
            await reload(target)
            return
        }
        guard let stored = try? await session.loadItem(vaultID: target.vaultID, itemID: target.itemID),
            stored != current
        else { return }
        if model.editing { remoteVersion = stored } else { item = stored }
    }

    private func locked(_ item: FfiItem) -> Bool { item.reprompt && !confirmed }

    // MARK: - Detail

    private func detail(_ item: FfiItem) -> some View {
        Form {
            Section {
                ItemHeader(item: item)
            }
            if let actionError {
                Section {
                    Label(actionError, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
            }
            if item.trashedAt != nil {
                Section {
                    Label("Dans Supprimés récemment : effacé définitivement après 30 jours.", systemImage: "trash")
                        .foregroundStyle(.secondary)
                }
            } else if item.archived {
                Section {
                    Label("Archivé : n'apparaît plus dans les listes ni dans les suggestions.", systemImage: "archivebox")
                        .foregroundStyle(.secondary)
                }
            }
            if locked(item) {
                repromptSection(item)
            } else {
                content(item)
            }
            datesSection(item)
        }
        .formStyle(.grouped)
        .environment(\.openURL, OpenURLAction { url in
            // Links in notes and fields open only on a tap, and only web or mail links.
            ["http", "https", "mailto"].contains(url.scheme?.lowercased() ?? "") ? .systemAction : .discarded
        })
        .navigationTitle(item.title)
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar { toolbar(item) }
        .confirmationDialog(
            "Supprimer définitivement « \(item.title) » ?", isPresented: $confirmDelete, titleVisibility: .visible
        ) {
            Button("Supprimer définitivement", role: .destructive) {
                run(clearsSelection: true) {
                    try await session.deletePermanently(itemID: item.id, vaultID: item.vaultId)
                }
            }
            .accessibilityIdentifier("item.delete.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Cette action est irréversible.")
        }
        .overlay(alignment: .bottom) { toastView }
        .simultaneousGesture(TapGesture().onEnded { session.noteActivity() })
    }

    @ViewBuilder private func content(_ item: FfiItem) -> some View {
        let sections = item.sections.filter { $0.fields.contains { !$0.value.isBlank } }
        ForEach(sections, id: \.id) { section in
            Section {
                ForEach(Array(section.fields.enumerated()), id: \.offset) { _, field in
                    if !field.value.isBlank {
                        FieldValueView(field: field) { showToast($0) }
                    }
                }
            } header: {
                if sections.count > 1 || section.id == ItemDraft.customSectionID { Text(section.label) }
            }
        }
        if !item.urls.isEmpty {
            Section {
                ForEach(Array(item.urls.enumerated()), id: \.offset) { index, url in
                    WebsiteRow(url: url, index: index) { showToast($0) }
                }
            }
        }
        if !item.tags.isEmpty {
            Section("tags") {
                FlowLayout(spacing: 6) {
                    ForEach(item.tags, id: \.self) { tag in
                        Text(tag)
                            .font(.footnote)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(.tint.opacity(0.14), in: Capsule())
                    }
                }
                .accessibilityElement(children: .combine)
            }
        }
        if !item.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            Section("notes") {
                Text(Self.markdown(item.notes))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("item.notes")
            }
        }
    }

    private func datesSection(_ item: FfiItem) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 4) {
                Text("Modifié le \(FieldDates.timestamp(item.updatedAt))")
                Text("Créé le \(FieldDates.day(item.createdAt))")
            }
            .font(.footnote)
            .foregroundStyle(.secondary)
            if item.passwordHistoryCount > 0, !locked(item) {
                NavigationLink {
                    PasswordHistoryView(ref: ItemRef(vaultID: item.vaultId, itemID: item.id))
                } label: {
                    Text(Self.historyLabel(item.passwordHistoryCount))
                }
                .accessibilityIdentifier("item.history")
            }
        }
    }

    static func historyLabel(_ count: UInt32) -> String {
        count == 1
            ? String(localized: "1 version précédente")
            : String(localized: "\(count) versions précédentes")
    }

    /// Inline Markdown only (bold, italic, code, links); line breaks kept. Never opens anything itself.
    static func markdown(_ text: String) -> AttributedString {
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: text, options: options)) ?? AttributedString(text)
    }

    // MARK: - Reprompt

    private func repromptSection(_ item: FfiItem) -> some View {
        Section {
            VStack(spacing: 14) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 36))
                    .foregroundStyle(.tint)
                Text("Cet élément demande une confirmation avant d'afficher son contenu.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                if askPassword {
                    SecureField("Mot de passe maître", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .privacySensitive()
                        // No `.password` content type: iOS must never offer to save the master password.
                        .onSubmit { verifyPassword() }
                        .accessibilityIdentifier("item.reprompt.password")
                    Button("Confirmer") { verifyPassword() }
                        .buttonStyle(.borderedProminent)
                        .disabled(password.isEmpty || checking)
                        .accessibilityIdentifier("item.reprompt.confirm")
                } else {
                    Button("Afficher") { Task { await confirmPresence() } }
                        .buttonStyle(.borderedProminent)
                        .accessibilityIdentifier("item.reprompt.show")
                }
                if let repromptError {
                    Text(repromptError).font(.footnote).foregroundStyle(.red)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
    }

    private func confirmPresence() async {
        guard let item else { return }
        repromptError = nil
        if await session.confirmUserPresence(prompt: String(localized: "Afficher « \(item.title) »")) {
            unlockReprompt()
        } else {
            askPassword = true
        }
    }

    private func verifyPassword() {
        guard !password.isEmpty, !checking else { return }
        checking = true
        let typed = password
        Task {
            defer { checking = false }
            do {
                try await session.verifyMasterPassword(typed)
                unlockReprompt()
            } catch {
                repromptError = VaultError(error).localizedMessage
            }
            password = ""
        }
    }

    private func unlockReprompt() {
        confirmed = true
        askPassword = false
        password = ""
        if editAfterConfirm {
            editAfterConfirm = false
            model.editing = true
        }
    }

    // MARK: - Toolbar and actions

    @ToolbarContentBuilder private func toolbar(_ item: FfiItem) -> some ToolbarContent {
        if item.trashedAt == nil {
            ToolbarItem(placement: .primaryAction) {
                // ⌘E is the "Modifier" menu command (`BrowseCommands`).
                Button("Modifier") { startEditing(item) }
                    .accessibilityIdentifier("item.edit")
            }
        }
        ToolbarItem(placement: .primaryAction) {
            Menu {
                menuContent(item)
            } label: {
                Label("Actions", systemImage: "ellipsis.circle")
            }
            .accessibilityIdentifier("item.menu")
        }
    }

    @ViewBuilder private func menuContent(_ item: FfiItem) -> some View {
        if item.trashedAt != nil {
            Button("Restaurer", systemImage: "arrow.uturn.backward") {
                run { try await session.restoreItem(itemID: item.id, vaultID: item.vaultId) }
            }
            .accessibilityIdentifier("item.restore")
            Button("Supprimer définitivement", systemImage: "trash.slash", role: .destructive) {
                confirmDelete = true
            }
            .accessibilityIdentifier("item.delete")
        } else {
            Button(
                item.favorite ? "Retirer des favoris" : "Ajouter aux favoris",
                systemImage: item.favorite ? "star.slash" : "star"
            ) {
                run { try await session.setFavorite(!item.favorite, itemID: item.id, vaultID: item.vaultId) }
            }
            .accessibilityIdentifier("item.favorite")
            MoveToVaultMenu(currentVaultID: item.vaultId) { vault in
                run(movedTo: vault.id, success: String(localized: "Déplacé vers \(vault.meta.name)")) {
                    try await session.move(itemID: item.id, from: item.vaultId, to: vault.id)
                }
            }
            if item.archived {
                Button("Désarchiver", systemImage: "archivebox") {
                    run { try await session.unarchive(itemID: item.id, vaultID: item.vaultId) }
                }
                .accessibilityIdentifier("item.unarchive")
            } else {
                Button("Archiver", systemImage: "archivebox") {
                    run { try await session.archive(itemID: item.id, vaultID: item.vaultId) }
                }
                .accessibilityIdentifier("item.archive")
            }
            Divider()
            Button("Mettre à la corbeille", systemImage: "trash", role: .destructive) {
                run(clearsSelection: true) { try await session.trash(itemID: item.id, vaultID: item.vaultId) }
            }
            .accessibilityIdentifier("item.trash")
        }
    }

    private func startEditing(_ item: FfiItem) {
        guard item.trashedAt == nil, !model.editing else { return }
        if locked(item) {
            editAfterConfirm = true
            Task { await confirmPresence() }
        } else {
            model.editing = true
        }
    }

    /// Runs an item operation, then reloads the item (or leaves the detail, or follows a move).
    private func run(
        clearsSelection: Bool = false, movedTo vaultID: String? = nil, success: String? = nil,
        _ op: @escaping () async throws -> Void
    ) {
        Task {
            do {
                try await op()
                actionError = nil
                if let success { showToast(success) }
                if clearsSelection {
                    // Leaves the detail; if it stays on screen it shows the new state (or "introuvable").
                    if model.selectedItem == ref { model.selectedItem = nil }
                    await reload(ref)
                } else if let vaultID {
                    let moved = ItemRef(vaultID: vaultID, itemID: ref.itemID)
                    if model.selectedItem == ref { model.selectedItem = moved }
                    await reload(moved)
                } else {
                    await reload(ref)
                }
            } catch {
                actionError = VaultError(error).localizedMessage
            }
        }
    }

    private func finishEditing(_ saved: FfiItem?) {
        model.editing = false
        guard let saved else { return }
        item = saved
        let savedRef = ItemRef(vaultID: saved.vaultId, itemID: saved.id)
        if savedRef != ref, model.selectedItem == ref { model.selectedItem = savedRef }
        showToast(String(localized: "Enregistré"))
    }

    private func load() async {
        await reload(ref)
        if let item, item.reprompt, !confirmed { await confirmPresence() }
    }

    private func reload(_ target: ItemRef) async {
        do {
            item = try await session.loadItem(vaultID: target.vaultID, itemID: target.itemID)
            loadError = nil
        } catch {
            item = nil
            loadError = VaultError(error).localizedMessage
        }
    }

    // MARK: - Toast

    private func showToast(_ text: String) {
        withAnimation(.snappy) { toast = text }
        Task {
            try? await Task.sleep(for: .seconds(1.6))
            if toast == text { withAnimation(.snappy) { toast = nil } }
        }
    }

    @ViewBuilder private var toastView: some View {
        if let toast {
            Text(toast)
                .font(.footnote.weight(.medium))
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                #if os(visionOS)
                .glassBackgroundEffect(in: Capsule())
                #else
                .glassEffect(.regular, in: Capsule())
                #endif
                .padding(.bottom, 18)
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .accessibilityAddTraits(.isStaticText)
        }
    }
}
