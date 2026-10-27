import CoreImage
import CoreImage.CIFilterBuiltins
import DesignKit
import GlanceKit
import SwiftUI
import VaultKit
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Detail of one item, shared by iPhone, iPad and Mac (mockups `PhoneItem` and `Main`): header,
/// non-empty fields by section, websites, tags, Markdown notes, dates, link to previous passwords,
/// and the item menu. Edition replaces the detail in place (`AppModel.editing`). The full item lives
/// in this view's state only (dropped with the view, and the whole tree goes away on lock).
/// A `reprompt` item asks for biometrics or the master password before showing anything.
struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    private let ref: ItemRef
    /// Shown in its own window ("Ouvrir dans une nouvelle fenêtre"): read only, "Modifier" goes back
    /// to the main window, whose editing state is global.
    private let standalone: Bool

    @State private var item: FfiItem?
    @State private var loadError: String?
    @State private var actionError: String?
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
    /// The footer's timeline is shown.
    @State private var showDates = false
    /// Timeline of the footer, loaded with the item (labels and dates only, never a value).
    @State private var timeline: [FfiTimelineEvent] = []
    /// "Copier en JSON" asks first: the JSON holds every secret of the item.
    @State private var confirmCopyJSON = false

    init(ref: ItemRef, standalone: Bool = false) {
        self.ref = ref
        self.standalone = standalone
    }

    private var editingHere: Bool { !standalone && model.editing }

    private var session: VaultSession { model.session }

    var body: some View {
        Group {
            if let item {
                if editingHere, !locked(item) {
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
            if !standalone, let item, model.selectedItem == ref { startEditing(item) }
        }
        .onDisappear { if !standalone { model.editing = false } }
        // A remote change set was applied: show the stored item, or warn the editor (spec 8).
        .onChange(of: model.remoteRevision) {
            Task { await remoteChanged() }
        }
        // Same for a write of the AutoFill extension (a passkey added to this Login, for instance).
        .onChange(of: session.externalChangeRevision) {
            Task { await remoteChanged() }
        }
        .alert(
            "Élément modifié entre-temps",
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
        guard editingHere else {
            await reload(target)
            return
        }
        guard let stored = try? await session.loadItem(vaultID: target.vaultID, itemID: target.itemID),
            stored != current
        else { return }
        if editingHere { remoteVersion = stored } else { item = stored }
    }

    private func locked(_ item: FfiItem) -> Bool { item.reprompt && !confirmed }

    // MARK: - Detail

    private func detail(_ item: FfiItem) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                ItemHeader(item: item)
                    .padding(.horizontal, 4)
                    .padding(.bottom, 4)
                if let actionError {
                    EditorCard {
                        Label(actionError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .editorRowPadding()
                    }
                }
                if item.trashedAt != nil {
                    banner("Dans Supprimés récemment : effacé définitivement après 30 jours.", systemImage: "trash")
                } else if item.archived {
                    banner("Archivé : n'apparaît plus dans les listes ni dans les suggestions.", systemImage: "archivebox")
                }
                if locked(item) {
                    repromptSection(item)
                } else {
                    if item.trashedAt == nil, !item.archived, let offer = PasskeyOffer.offer(for: item) {
                        PasskeyOfferBanner(offer: offer) { dismissPasskeyOffer(item) }
                    }
                    if item.itemType == .document {
                        ForEach(DocumentCard.attachments(of: item), id: \.id) { attachment in
                            DocumentCard(attachment: attachment)
                        }
                    }
                    content(item)
                }
                footer(item)
            }
            #if os(macOS)
            .padding(.horizontal, 28)
            #else
            .padding(.horizontal, 16)
            #endif
            .padding(.vertical, 22)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .defaultScrollAnchor(.top)
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
            "Copier « \(item.title) » en JSON ?", isPresented: $confirmCopyJSON, titleVisibility: .visible
        ) {
            Button("Copier en JSON") { copyJSON(item) }
                .accessibilityIdentifier("item.copyJSON.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Le JSON contient tous les secrets de l'élément, mots de passe compris. Le presse-papiers est effacé après 90 s.")
        }
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
        .simultaneousGesture(TapGesture().onEnded { session.noteActivity() })
    }

    private func banner(_ text: LocalizedStringKey, systemImage: String) -> some View {
        Label(text, systemImage: systemImage)
            .font(.callout)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 16)
    }

    @ViewBuilder private func content(_ item: FfiItem) -> some View {
        let sections = item.sections.filter {
            $0.fields.contains { !$0.value.isBlank && !(item.itemType == .document && $0.kind == .file) }
        }
        ForEach(sections, id: \.id) { section in
            VStack(alignment: .leading, spacing: 6) {
                if !section.label.isEmpty {
                    // Small bold capitals above each card ("IDENTIFICATION", "ADRESSE").
                    Text(section.displayLabel(itemType: item.itemType).uppercased())
                        .font(.caption.weight(.bold))
                        .tracking(0.6)
                        .foregroundStyle(.secondary)
                        .padding(.leading, 16)
                        .accessibilityAddTraits(.isHeader)
                }
                EditorCard {
                    // A Document's files have their own preview card at the top.
                    let fields = section.fields.filter {
                        !$0.value.isBlank && !(item.itemType == .document && $0.kind == .file)
                    }
                    ForEach(Array(fields.enumerated()), id: \.offset) { index, field in
                        if index > 0 { CardDivider() }
                        FieldValueView(field: field, itemType: item.itemType) { showToast($0) }
                    }
                }
            }
        }
        // The join code sits right under the network's fields, before websites, notes and tags.
        if item.itemType == .router, let payload = WifiQR.payload(for: item) {
            WifiQRCard(item: item, ssid: WifiQR.ssid(of: item), payload: payload)
                .frame(maxWidth: .infinity)
        }
        if !item.urls.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(item.urls.enumerated()), id: \.offset) { index, url in
                    WebsiteRow(url: url, index: index) { showToast($0) }
                }
            }
        }
        if !item.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            EditorCard {
                VStack(alignment: .leading, spacing: 3) {
                    EditorLabel("notes")
                    Text(Self.markdown(item.notes))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("item.notes")
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
        }
        // A place already shown by a location field of the item is not drawn a second time.
        let fieldPlaces = item.sections.flatMap(\.fields).compactMap { field -> FfiLocation? in
            if case .location(let place) = field.value { place } else { nil }
        }
        let places = item.locations.filter { place in
            !fieldPlaces.contains { abs($0.lat - place.lat) < 1e-6 && abs($0.lon - place.lon) < 1e-6 }
        }
        if !places.isEmpty {
            ItemPlacesCard(locations: places)
        }
        if !item.tags.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                EditorLabel("tags")
                FlowLayout(spacing: 6) {
                    ForEach(item.tags, id: \.self) { tag in
                        Text(tag)
                            .font(.footnote.weight(.medium))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(Theme.accent.opacity(0.18), in: Capsule())
                    }
                }
                .accessibilityElement(children: .combine)
            }
            .padding(.horizontal, 16)
        }
    }

    /// "Modifié le ..." with a chevron; open, the item's timeline (newest first, on a vertical line
    /// with dots) and the link to the previous passwords.
    private func footer(_ item: FfiItem) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.snappy) { showDates.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Text("Modifié le \(FieldDates.timestamp(item.updatedAt))")
                    Image(systemName: "chevron.right")
                        .font(.caption2.weight(.bold))
                        .rotationEffect(.degrees(showDates ? 90 : 0))
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("item.dates")
            .accessibilityValue(showDates ? Text("développé") : Text("réduit"))
            if showDates {
                ItemTimelineView(events: timeline.isEmpty ? ItemTimelineView.fallback(item) : timeline)
                if item.passwordHistoryCount > 0, !locked(item) {
                    NavigationLink {
                        PasswordHistoryView(ref: ItemRef(vaultID: item.vaultId, itemID: item.id))
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "clock.arrow.circlepath")
                            Text("Voir les versions précédentes")
                            Text(verbatim: "(\(item.passwordHistoryCount))")
                            Image(systemName: "chevron.right").font(.caption2.weight(.bold))
                        }
                        .foregroundStyle(Theme.readableAccent)
                        .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .padding(.leading, 22)
                    .accessibilityIdentifier("item.history")
                }
            }
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 16)
        .padding(.top, 4)
        .task(id: TimelineKey(item: item, open: showDates)) {
            guard showDates, !locked(item) else { return }
            timeline = (try? await session.itemTimeline(vaultID: item.vaultId, itemID: item.id)) ?? []
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
        EditorCard {
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
            .padding(20)
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
        // Emptied on submission (success or not): the password lives on in a wiped buffer only (R5).
        let typed = SecretBytes(utf8: password)
        password = ""
        Task {
            defer {
                typed.wipe()
                checking = false
            }
            do {
                try await session.verifyMasterPassword(typed)
                unlockReprompt()
            } catch {
                repromptError = VaultError(error).localizedMessage
            }
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
        #if os(macOS)
        // Actions on the right of the detail column (the search lives at the top of the list).
        ToolbarSpacer(.flexible)
        #endif
        if item.trashedAt == nil {
            ToolbarItem(placement: .primaryAction) {
                VaultToolbarMenu(currentVaultID: item.vaultId) { vault in move(item, to: vault) }
            }
            ToolbarItem(placement: .primaryAction) {
                ShareLink(item: ItemShare.text(item), subject: Text(item.title)) {
                    Label("Partager", systemImage: "square.and.arrow.up")
                }
                .accessibilityIdentifier("item.share")
            }
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
                Label("Actions", systemImage: "ellipsis")
            }
            .menuIndicator(.hidden)
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
            #if os(macOS)
            if !standalone {
                Button("Ouvrir dans une nouvelle fenêtre", systemImage: "macwindow.on.rectangle") {
                    openWindow(id: ItemWindow.id, value: ItemWindow.key(item))
                }
                .accessibilityIdentifier("item.openWindow")
                Divider()
            }
            #endif
            Button(
                item.favorite ? "Retirer des favoris" : "Ajouter aux favoris",
                systemImage: item.favorite ? "star.slash" : "star"
            ) {
                run { try await session.setFavorite(!item.favorite, itemID: item.id, vaultID: item.vaultId) }
            }
            .accessibilityIdentifier("item.favorite")
            MoveToVaultMenu(currentVaultID: item.vaultId, title: "Déplacer…") { vault in move(item, to: vault) }
            Button("Dupliquer…", systemImage: "plus.square.on.square") { duplicate(item) }
                .accessibilityIdentifier("item.duplicate")
            Divider()
            Button("Copier le lien privé", systemImage: "link") {
                copyPlain(OnePassLink.item(vaultID: item.vaultId, itemID: item.id).url.absoluteString,
                          toast: String(localized: "Lien privé copié"))
            }
            .accessibilityIdentifier("item.copyLink")
            Button("Copier l'identifiant de l'élément", systemImage: "number") {
                copyPlain(item.id, toast: String(localized: "Identifiant copié"))
            }
            .accessibilityIdentifier("item.copyID")
            Button("Copier en JSON", systemImage: "curlybraces") { confirmCopyJSON = true }
                .disabled(locked(item))
                .accessibilityIdentifier("item.copyJSON")
            Divider()
            ShareLink(item: ItemShare.text(item), subject: Text(item.title)) {
                Label("Partager…", systemImage: "square.and.arrow.up")
            }
            .accessibilityIdentifier("item.shareMenu")
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
            Button("Supprimer", systemImage: "trash", role: .destructive) {
                run(clearsSelection: true, success: String(localized: "Déplacé vers Supprimés récemment")) {
                    try await session.trash(itemID: item.id, vaultID: item.vaultId)
                }
            }
            .accessibilityIdentifier("item.trash")
        }
    }

    private func move(_ item: FfiItem, to vault: FfiVault) {
        run(movedTo: vault.id, success: String(localized: "Déplacé vers \(vault.meta.name)")) {
            try await session.move(itemID: item.id, from: item.vaultId, to: vault.id)
        }
    }

    private func copyPlain(_ text: String, toast: String) {
        session.copy(text, concealed: false)
        model.showToast(toast, kind: .info)
    }

    /// Every field, secrets included, through the concealed clipboard (local only, cleared after 90 s).
    private func copyJSON(_ item: FfiItem) {
        guard !locked(item), let json = ItemJSON.string(item) else { return }
        session.copy(json, concealed: true)
        model.showToast(String(localized: "JSON copié · effacé dans 90 s"))
    }

    /// A new item (new id from the new-item path) with the fields copied and " (copie)" after the
    /// title, saved, then shown. Passkeys and files are not copied: a passkey belongs to one item.
    private func duplicate(_ item: FfiItem) {
        Task {
            do {
                let fresh = try session.newItem(type: item.itemType, vaultID: item.vaultId)
                var copy = item
                copy.id = fresh.id
                copy.title = String(localized: "\(item.title) (copie)")
                copy.createdAt = fresh.createdAt
                copy.updatedAt = fresh.updatedAt
                copy.trashedAt = nil
                copy.archived = false
                copy.passwordHistoryCount = 0
                for s in copy.sections.indices {
                    for f in copy.sections[s].fields.indices {
                        switch copy.sections[s].fields[f].value {
                        case .passkey, .file: copy.sections[s].fields[f].value = .empty
                        default: break
                        }
                    }
                }
                copy.loginMethods.removeAll { $0 == .passkey }
                let saved = try await session.save(copy)
                model.selectedItem = ItemRef(vaultID: saved.vaultId, itemID: saved.id)
                model.showToast(String(localized: "« \(saved.title) » créé"))
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    /// "Ignorer" on the passkey banner: the check is excluded for this item, saved like an edit.
    private func dismissPasskeyOffer(_ item: FfiItem) {
        var changed = item
        guard !changed.watchtowerExclusions.contains(PasskeyOffer.checkID) else { return }
        changed.watchtowerExclusions.append(PasskeyOffer.checkID)
        Task {
            do {
                self.item = try await session.save(changed)
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    private func startEditing(_ item: FfiItem) {
        if standalone {
            // The editor lives in the main window (one editing state for the app).
            model.selectedItem = ref
            openWindow(id: "main")
            Task {
                try? await Task.sleep(for: .milliseconds(300))
                model.editRequest += 1
            }
            return
        }
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
                    if !standalone, model.selectedItem == ref { model.selectedItem = nil }
                    await reload(ref)
                } else if let vaultID {
                    let moved = ItemRef(vaultID: vaultID, itemID: ref.itemID)
                    if !standalone, model.selectedItem == ref { model.selectedItem = moved }
                    await reload(moved)
                } else {
                    await reload(ref)
                }
            } catch {
                actionError = VaultError(error).localizedMessage
                model.showToast(VaultError(error).localizedMessage, kind: .error)
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
        model.showToast(text)
    }
}

// MARK: - Wi-Fi QR code

/// The standard `WIFI:` join string of a router item (what a phone camera reads to join the
/// network), built from its SSID, password, security and hidden flag. Nil without an SSID.
enum WifiQR {
    static func ssid(of item: FfiItem) -> String { value("ssid", in: item) }

    static func payload(for item: FfiItem) -> String? {
        let ssid = value("ssid", in: item)
        guard !ssid.isEmpty else { return nil }
        let password = value("wifi_password", in: item)
        let security = value("security", in: item).uppercased()
        let type: String =
            if password.isEmpty || security == "OUVERT" { "nopass" }
            else if security == "WEP" { "WEP" }
            else { "WPA" }
        // "Réseau masqué" is a yes/no menu.
        let hidden = ["oui", "yes", "true"].contains(value("hidden", in: item).lowercased())
        var parts = "WIFI:T:\(type);S:\(escape(ssid));"
        if type != "nopass" { parts += "P:\(escape(password));" }
        if hidden { parts += "H:true;" }
        return parts + ";"
    }

    private static func value(_ id: String, in item: FfiItem) -> String {
        item.sections.flatMap(\.fields).first { $0.id == id }?.value.text ?? ""
    }

    /// Backslash before the characters the format reserves.
    private static func escape(_ s: String) -> String {
        var out = ""
        for c in s {
            if "\\;,:\"".contains(c) { out.append("\\") }
            out.append(c)
        }
        return out
    }

    /// Dark navy of the QR modules, on white.
    static var ink: CIColor { CIColor(red: 0.07, green: 0.12, blue: 0.27) }

    /// The QR code as a crisp image, navy on white, high error correction ("H") so the item icon
    /// laid over its center still scans. No smoothing when scaled.
    static func image(for payload: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "H"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 12, y: 12)) else {
            return nil
        }
        let colors = CIFilter.falseColor()
        colors.inputImage = output
        colors.color0 = ink
        colors.color1 = CIColor(red: 1, green: 1, blue: 1)
        guard let tinted = colors.outputImage else { return nil }
        return CIContext().createCGImage(tinted, from: output.extent)
    }
}

/// "Rejoindre le réseau", like the reference: a white rounded square centered under the fields,
/// navy QR with the item icon in its middle, and a menu on its right (Copier l'image, Afficher en
/// grand, Imprimer). Hidden behind a tap and masked again after 30 s, on lock and when the scene
/// leaves the foreground, and kept masked while the screen is captured: it carries the password.
private struct WifiQRCard: View {
    @Environment(AppModel.self) private var model
    #if os(iOS) || os(visionOS)
    @Environment(\.isSceneCaptured) private var captured
    #else
    private let captured = false
    #endif
    let item: FfiItem
    let ssid: String
    let payload: String
    @State private var shown = false
    @State private var large = false

    var body: some View {
        VStack(spacing: 10) {
            HStack(alignment: .top, spacing: 8) {
                // Same width on the left as the menu, so the square stays centered.
                Color.clear.frame(width: 28, height: 28)
                qrSquare
                Menu {
                    Button("Copier l'image", systemImage: "doc.on.doc") { copyImage() }
                        .accessibilityIdentifier("item.wifiQR.copy")
                    Button("Afficher en grand", systemImage: "arrow.up.left.and.arrow.down.right") {
                        shown = true
                        large = true
                    }
                    .accessibilityIdentifier("item.wifiQR.large")
                    Button("Imprimer", systemImage: "printer") { printImage() }
                        .accessibilityIdentifier("item.wifiQR.print")
                } label: {
                    Image(systemName: "ellipsis")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .frame(width: 28, height: 28)
                        .contentShape(.rect)
                }
                .menuStyle(.button)
                .buttonStyle(.borderless)
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel(Text("Actions du code QR"))
                .accessibilityIdentifier("item.wifiQR.menu")
            }
            Text(shown ? "Scanne ce code pour rejoindre « \(ssid) »." : "Touche le code pour l'afficher.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .task(id: shown) {
            // Same rule as a revealed password: masked again after 30 s.
            guard shown else { return }
            try? await Task.sleep(for: .seconds(30))
            if !Task.isCancelled { shown = false }
        }
        .onDisappear { conceal() }
        // Lock, or the scene left the foreground (`VaultSession.concealGeneration`).
        .onChange(of: model.session.concealGeneration) { conceal() }
        // Screen captured (iOS, visionOS): masked now, and still masked once the capture ends.
        .onChange(of: captured) { _, now in if now { conceal() } }
        .sheet(isPresented: Binding(get: { large && visible }, set: { large = $0 })) {
            VStack(spacing: 18) {
                Text(ssid).font(.title2.weight(.semibold))
                QRSquare(item: item, payload: payload, side: 420)
                Button("Fermer") { large = false }.keyboardShortcut(.cancelAction)
            }
            .padding(28)
        }
    }

    /// Shown and not captured.
    private var visible: Bool { shown && !captured }

    private func conceal() {
        shown = false
        large = false
    }

    private var qrSquare: some View {
        ZStack {
            QRSquare(item: item, payload: payload, side: 260)
                .blur(radius: visible ? 0 : 16)
                .privacySensitive()
            if !visible {
                Image(systemName: "eye.slash").font(.title).foregroundStyle(Color(red: 0.07, green: 0.12, blue: 0.27))
            }
        }
        .clipShape(.rect(cornerRadius: 22))
        .contentShape(.rect)
        .onTapGesture { withAnimation(.easeOut(duration: 0.2)) { shown.toggle() } }
        .accessibilityAddTraits(.isButton)
        .accessibilityLabel(Text("Code QR du réseau \(ssid)"))
        .accessibilityValue(visible ? Text("affiché") : Text("masqué"))
        .accessibilityIdentifier("item.wifiQR")
    }

    /// Rendered with the icon, for the clipboard and the printer.
    @MainActor private func rendered() -> CGImage? {
        let renderer = ImageRenderer(content: QRSquare(item: item, payload: payload, side: 520))
        renderer.scale = 2
        return renderer.cgImage
    }

    /// The image holds the password: marked concealed and cleared after 90 s, like a copied secret.
    @MainActor private func copyImage() {
        guard let image = rendered() else { return }
        #if os(macOS)
        let board = NSPasteboard.general
        board.clearContents()
        board.writeObjects([NSImage(cgImage: image, size: NSSize(width: 260, height: 260))])
        board.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        board.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
        let count = board.changeCount
        Task {
            try? await Task.sleep(for: .seconds(90))
            if board.changeCount == count { board.clearContents() }
        }
        #else
        UIPasteboard.general.setItems(
            [["public.png": UIImage(cgImage: image).pngData() ?? Data()]],
            options: [.localOnly: true, .expirationDate: Date.now.addingTimeInterval(90)])
        #endif
    }

    @MainActor private func printImage() {
        guard let image = rendered() else { return }
        #if os(macOS)
        let view = NSImageView(image: NSImage(cgImage: image, size: NSSize(width: 360, height: 360)))
        view.frame = NSRect(x: 0, y: 0, width: 360, height: 360)
        NSPrintOperation(view: view).run()
        #elseif os(iOS)
        let controller = UIPrintInteractionController.shared
        controller.printingItem = UIImage(cgImage: image)
        controller.present(animated: true)
        #endif
    }
}

/// White rounded square with the navy QR and the item icon over its center.
private struct QRSquare: View {
    let item: FfiItem
    let payload: String
    let side: CGFloat

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: side * 0.085, style: .continuous).fill(.white)
            if let image = WifiQR.image(for: payload) {
                Image(decorative: image, scale: 1)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .padding(side * 0.07)
            }
            ItemIcon(type: item.itemType, title: item.title, siteIcon: nil, size: side * 0.18)
                .padding(side * 0.02)
                .background(.white, in: .rect(cornerRadius: side * 0.05, style: .continuous))
                .accessibilityHidden(true)
        }
        .frame(width: side, height: side)
        .environment(\.colorScheme, .light)
    }
}

/// The item's places in the detail: map card, label and address, the distance when the position
/// is already known (never asked from here), and "Ouvrir dans Plans".
private struct ItemPlacesCard: View {
    let locations: [FfiLocation]

    var body: some View {
        let here = LocationAccess.shared.knownLocation
        EditorCard {
            ForEach(Array(locations.enumerated()), id: \.offset) { index, location in
                if index > 0 { CardDivider() }
                PlaceBlock(location: location) {
                    if let here {
                        let point = GeoPoint(latitude: location.lat, longitude: location.lon)
                        let origin = GeoPoint(latitude: here.coordinate.latitude, longitude: here.coordinate.longitude)
                        if point.isPlaced {
                            Text(LocationIndex.distanceLabel(LocationIndex.distance(origin, point)))
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .accessibilityIdentifier("item.location.distance.\(index)")
                        }
                    }
                }
                Button {
                    location.openInMaps()
                } label: {
                    Label("Ouvrir dans Plans", systemImage: "map")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(Theme.readableAccent)
                }
                .buttonStyle(.borderless)
                .padding(.horizontal, 16)
                .padding(.bottom, 12)
                .accessibilityIdentifier("item.location.open.\(index)")
            }
        }
        .accessibilityIdentifier("item.locations")
    }
}

// MARK: - Timeline

/// Reloads the timeline when the item changes or the footer opens.
private struct TimelineKey: Equatable {
    let id: String
    let vaultID: String
    let updatedAt: Int64
    let open: Bool

    init(item: FfiItem, open: Bool) {
        id = item.id
        vaultID = item.vaultId
        updatedAt = item.updatedAt
        self.open = open
    }
}

/// The item's history like 1Password's footer: a vertical line with a dot per event, newest first,
/// an icon and a sentence, the relative date (full date as tooltip). Labels only, never a value.
struct ItemTimelineView: View {
    let events: [FfiTimelineEvent]

    /// Before the core answers (or if it fails): creation and last change from the item itself.
    static func fallback(_ item: FfiItem) -> [FfiTimelineEvent] {
        var out = [FfiTimelineEvent(kind: "created", at: item.createdAt, detail: "")]
        if item.updatedAt > item.createdAt + 1 {
            out.insert(FfiTimelineEvent(kind: "modified", at: item.updatedAt, detail: ""), at: 0)
        }
        return out
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(events.enumerated()), id: \.offset) { index, event in
                row(event, first: index == 0, last: index == events.count - 1)
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("item.timeline")
    }

    private func row(_ event: FfiTimelineEvent, first: Bool, last: Bool) -> some View {
        let date = Date(timeIntervalSince1970: TimeInterval(event.at))
        return HStack(alignment: .top, spacing: 10) {
            VStack(spacing: 0) {
                Rectangle().fill(first ? .clear : Color.secondary.opacity(0.35)).frame(width: 1, height: 7)
                Circle()
                    .fill(first ? Theme.readableAccent : Color.secondary.opacity(0.7))
                    .frame(width: 7, height: 7)
                Rectangle().fill(last ? .clear : Color.secondary.opacity(0.35)).frame(width: 1)
                    .frame(maxHeight: .infinity)
            }
            .frame(width: 12)
            Image(systemName: Self.icon(event.kind))
                .frame(width: 16)
                .padding(.top, 3)
                .accessibilityHidden(true)
            Text(Self.sentence(event))
                .foregroundStyle(.primary.opacity(0.85))
                .padding(.top, 3)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Text(date, format: .relative(presentation: .named))
                .padding(.top, 3)
                .help(FieldDates.timestamp(event.at))
        }
        .padding(.bottom, last ? 0 : 6)
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .combine)
    }

    static func icon(_ kind: String) -> String {
        switch kind {
        case "created": "plus.circle"
        case "imported": "square.and.arrow.down"
        case "field_added": "plus.square"
        case "field_removed": "minus.square"
        case "password_changed": "key"
        case "title_changed": "textformat"
        case "website_added", "website_removed": "globe"
        case "moved": "folder"
        case "favorited": "star"
        case "unfavorited": "star.slash"
        case "archived", "unarchived": "archivebox"
        case "trashed": "trash"
        case "restored": "arrow.uturn.backward"
        case "passkey_added", "passkey_removed": "person.badge.key"
        case "attachment_added": "paperclip"
        default: "pencil"
        }
    }

    static func sentence(_ e: FfiTimelineEvent) -> String {
        let d = e.detail
        switch e.kind {
        case "created": return String(localized: "Élément créé")
        case "imported":
            return d.isEmpty ? String(localized: "Importé") : String(localized: "Importé depuis \(d)")
        case "field_added": return String(localized: "Champ « \(d) » ajouté")
        case "field_removed": return String(localized: "Champ « \(d) » supprimé")
        case "field_changed":
            switch d {
            case "notes": return String(localized: "Notes modifiées")
            case "tags": return String(localized: "Tags modifiés")
            default: return String(localized: "« \(d) » modifié")
            }
        case "password_changed": return String(localized: "Mot de passe modifié")
        case "title_changed": return String(localized: "Titre modifié")
        case "website_added": return String(localized: "Site web ajouté : \(d)")
        case "website_removed": return String(localized: "Site web retiré : \(d)")
        case "moved": return String(localized: "Déplacé vers \(d)")
        case "favorited": return String(localized: "Ajouté aux favoris")
        case "unfavorited": return String(localized: "Retiré des favoris")
        case "archived": return String(localized: "Archivé")
        case "unarchived": return String(localized: "Désarchivé")
        case "trashed": return String(localized: "Mis dans Supprimés récemment")
        case "restored": return String(localized: "Restauré")
        case "passkey_added": return String(localized: "Passkey ajoutée pour \(d)")
        case "passkey_removed": return String(localized: "Passkey supprimée pour \(d)")
        case "attachment_added": return String(localized: "Pièce jointe ajoutée : \(d)")
        default: return String(localized: "Modifié")
        }
    }
}

// MARK: - Share, link, JSON

/// What "Partager" hands to the share sheet: the title and the website, never a secret.
enum ItemShare {
    static func text(_ item: FfiItem) -> String {
        let url = (item.urls.first(where: \.primary) ?? item.urls.first)?.url ?? ""
        return url.isEmpty ? item.title : "\(item.title)\n\(url)"
    }
}

/// "Copier en JSON": the whole item, secrets included (the caller asks first and copies concealed).
/// Passkey private keys never reach the app, so they cannot appear here.
enum ItemJSON {
    static func string(_ item: FfiItem) -> String? {
        let object: [String: Any] = [
            "id": item.id,
            "vault_id": item.vaultId,
            "type": String(describing: item.itemType),
            "title": item.title,
            "favorite": item.favorite,
            "tags": item.tags,
            "notes": item.notes,
            "urls": item.urls.map { ["label": $0.label, "url": $0.url, "primary": $0.primary] },
            "sections": item.sections.map { section in
                [
                    "id": section.id,
                    "label": section.label,
                    "fields": section.fields.filter { !$0.value.isBlank }.map { field in
                        [
                            "id": field.id,
                            "label": field.label,
                            "type": String(describing: field.kind),
                            "value": value(field.value),
                        ] as [String: Any]
                    },
                ] as [String: Any]
            },
            "created_at": iso(item.createdAt),
            "updated_at": iso(item.updatedAt),
        ]
        guard let data = try? JSONSerialization.data(
            withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func iso(_ seconds: Int64) -> String {
        Date(timeIntervalSince1970: TimeInterval(seconds)).ISO8601Format()
    }

    private static func value(_ v: FfiFieldValue) -> Any {
        switch v {
        case .text(let s), .concealed(let s), .password(let s), .url(let s), .email(let s), .phone(let s),
            .menu(let s), .otp(let s), .mnemonic(let s):
            return s
        case .date(let d): return String(format: "%04d-%02d-%02d", d.year, d.month, d.day)
        case .monthYear(let year, let month): return String(format: "%04d-%02d", year, month)
        case .number(let n): return n
        case .money(let minor, let currency): return ["minor_units": minor, "currency": currency]
        case .address(let a):
            return ["line1": a.line1, "line2": a.line2, "city": a.city, "postal_code": a.postalCode,
                    "region": a.region, "country": a.country]
        case .passkey(let p): return ["rp_id": p.rpId, "user_name": p.userName]
        case .sshKey(let k):
            return ["private_key": k.privatePem, "public_key": k.publicOpenssh,
                    "fingerprint": k.fingerprintSha256]
        case .file(let a): return ["name": a.name, "size": a.size, "mime": a.mime]
        case .location(let l):
            return ["label": l.label, "address": l.address ?? "", "lat": l.lat, "lon": l.lon]
        case .barcode(let value, let format): return ["value": value, "format": String(describing: format)]
        case .itemLink(let id): return id
        case .empty: return NSNull()
        }
    }
}

// MARK: - Passkey banner

/// A login whose site accepts passkeys and that has none. The core's passkey directory check
/// (`passkey_available`) loads its catalog from bytes the caller supplies, and the app bundles no
/// catalog yet: `offer(for:)` returns nil until it does, so the banner stays hidden (never faked).
struct PasskeyOffer: Equatable {
    static let checkID = "passkey_available"
    let host: String
    /// The site's account settings page from the directory, else the site.
    let url: URL

    static func offer(for item: FfiItem) -> PasskeyOffer? {
        guard item.itemType == .login, !item.watchtowerExclusions.contains(checkID),
            !item.loginMethods.contains(.passkey)
        else { return nil }
        // No directory in the app: nothing to look the host up in.
        return nil
    }
}

/// Purple card at the top of a login: "Passkey disponible", collapsible, with "Utiliser une
/// passkey" (opens the site's settings) and "Ignorer" (excluded for this item, saved).
struct PasskeyOfferBanner: View {
    @Environment(\.openURL) private var openURL
    let offer: PasskeyOffer
    let onIgnore: () -> Void
    @State private var expanded = true

    private let purple = Color(red: 0.55, green: 0.36, blue: 0.96)

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.snappy) { expanded.toggle() }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "person.badge.key.fill")
                    Text("Passkey disponible").font(.headline)
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.caption.weight(.bold))
                        .rotationEffect(.degrees(expanded ? 0 : -90))
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("item.passkeyOffer.toggle")
            if expanded {
                Text("\(offer.host) accepte les passkeys. Une passkey remplace ton mot de passe : plus rapide, et impossible à hameçonner.")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Button("Utiliser une passkey") { openURL(offer.url) }
                        .buttonStyle(.borderedProminent)
                        .tint(purple)
                        .accessibilityIdentifier("item.passkeyOffer.use")
                    Button("Ignorer", action: onIgnore)
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("item.passkeyOffer.ignore")
                }
            }
        }
        .padding(16)
        .background(purple.opacity(0.16), in: .rect(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(purple.opacity(0.35)))
        .accessibilityIdentifier("item.passkeyOffer")
    }
}

// MARK: - Document preview

/// Top of a Document: file icon and name centered, a collapsible "Aperçu" row, then the size.
/// Attachment contents are not stored in the vault yet (milestone 5), so the preview says so
/// instead of showing anything.
struct DocumentCard: View {
    let attachment: FfiAttachment
    @State private var preview = false

    static func attachments(of item: FfiItem) -> [FfiAttachment] {
        item.sections.flatMap(\.fields).compactMap {
            if case .file(let a) = $0.value { a } else { nil }
        }
    }

    var body: some View {
        EditorCard {
            VStack(spacing: 8) {
                Image(systemName: "doc.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(Theme.readableAccent)
                Text(attachment.name).font(.headline).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 20)
            CardDivider()
            Button {
                withAnimation(.snappy) { preview.toggle() }
            } label: {
                HStack {
                    Text("Aperçu")
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.bold))
                        .rotationEffect(.degrees(preview ? 90 : 0))
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .editorRowPadding()
            .accessibilityIdentifier("item.document.preview")
            if preview {
                Text("Aperçu indisponible : le contenu des pièces jointes n'est pas encore enregistré dans le coffre.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .editorRowPadding()
            }
            CardDivider()
            VStack(alignment: .leading, spacing: 3) {
                EditorLabel("taille du fichier")
                Text(ByteCountFormatter.string(fromByteCount: Int64(clamping: attachment.size), countStyle: .file))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .editorRowPadding()
        }
        .accessibilityIdentifier("item.document")
    }
}

// MARK: - Item window

/// "Ouvrir dans une nouvelle fenêtre" (Mac): one window per item, keyed by "vault/item".
enum ItemWindow {
    static let id = "item"

    static func key(_ item: FfiItem) -> String { "\(item.vaultId)/\(item.id)" }

    static func ref(_ key: String?) -> ItemRef? {
        guard let parts = key?.split(separator: "/"), parts.count == 2 else { return nil }
        return ItemRef(vaultID: String(parts[0]), itemID: String(parts[1]))
    }
}

/// Root of an item window: the detail while unlocked, nothing of the item once locked.
struct ItemWindowRoot: View {
    @Environment(AppModel.self) private var model
    let key: String?

    var body: some View {
        Group {
            if model.session.state == .unlocked, let ref = ItemWindow.ref(key) {
                NavigationStack { ItemDetailView(ref: ref, standalone: true) }
            } else {
                EmptyState(title: String(localized: "OnePass est verrouillé"), systemImage: "lock",
                           message: String(localized: "Déverrouille OnePass dans la fenêtre principale."))
            }
        }
        .frame(minWidth: 480, minHeight: 520)
    }
}
