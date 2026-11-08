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
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
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
    /// Travel Mode extra protection (spec 2026-11-02): each of the two checks passed.
    @State private var presencePassed = false
    @State private var passwordPassed = false
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
    /// The identity color of the item shown (iPhone and iPad), computed once when the header
    /// reports its icon and keyed to the item so a switch never shows the previous tint.
    @State private var identity: (id: String, color: Color)?
    @Environment(\.colorScheme) private var colorScheme
    #if os(iOS) || os(visionOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    #endif

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
                EmptyState(title: String(localized: "item.itemUnavailable"), systemImage: "exclamationmark.triangle",
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
            Button("item.reload", role: .destructive) {
                if let remoteVersion { item = remoteVersion }
                remoteVersion = nil
                model.editing = false
            }
            Button("app.keepEditing", role: .cancel) { remoteVersion = nil }
        } message: {
            Text("item.ifSaveChangesWill")
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

    private func locked(_ item: FfiItem) -> Bool { (item.reprompt || travelGuarded(item)) && !confirmed }

    /// Behind extra protection while travelling: the master password and, when the device has
    /// them, Face ID or Touch ID, both, every time the detail opens.
    private func travelGuarded(_ item: FfiItem) -> Bool { item.travelGuard && session.isTravelling }

    // MARK: - Detail

    #if os(iOS) || os(macOS)
    /// The brand color of a card network, else the icon's average, else the category color.
    private func identityColor(_ item: FfiItem, icon: Data?) -> Color {
        IdentityTint.color(
            brand: item.itemType == .creditCard ? item.cardBrandName : nil,
            siteIcon: icon.flatMap(ItemIcon.filled),
            category: ItemCategory.of(item.itemType).color)
    }

    /// A 30% tall wash from the top edge (status bar included). Flat fallback is no wash at all.
    private func identityWash(_ item: FfiItem) -> some View {
        let color = identity.flatMap { $0.id == item.id ? $0.color : nil } ?? identityColor(item, icon: nil)
        return Color.clear
            .containerRelativeFrame(.vertical) { height, _ in height * 0.30 }
            .washBackground(
                Theme.Wash.identity(color, dark: colorScheme == .dark), flat: .clear, in: Rectangle()
            )
            .ignoresSafeArea(edges: .top)
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
    #endif

    /// Gap between the header, the cards and the footer: the scale's section gap everywhere.
    private static let sectionSpacing: CGFloat = Theme.Space.betweenSections

    private func detail(_ item: FfiItem) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Self.sectionSpacing) {
                #if os(iOS) || os(macOS)
                ItemHeader(item: item) { identity = (item.id, identityColor(item, icon: $0)) }
                    .id(item.id)
                    .padding(.horizontal, Theme.Space.xs)
                    .padding(.bottom, Theme.Space.xs)
                #else
                ItemHeader(item: item)
                    .padding(.horizontal, Theme.Space.xs)
                    .padding(.bottom, Theme.Space.xs)
                #endif
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
                    if item.trashedAt == nil, !item.archived,
                        let offer = PasskeyOffer.offer(for: item, report: model.watchtower.report) {
                        PasskeyOfferBanner(offer: offer) { setWatchtowerExclusion(PasskeyOffer.checkID, excluded: true, item) }
                    }
                    if item.itemType == .document {
                        ForEach(DocumentCard.attachments(of: item), id: \.id) { attachment in
                            DocumentCard(attachment: attachment)
                        }
                    }
                    content(item)
                    ItemAttachmentsSection(item: item, editable: item.trashedAt == nil && !standalone) {
                        self.item = $0
                    }
                    if item.trashedAt == nil, !item.archived {
                        ItemWatchtowerSection(item: item, report: model.watchtower.report) { check, excluded in
                            setWatchtowerExclusion(check, excluded: excluded, item)
                        }
                    }
                }
                footer(item)
            }
            #if os(macOS)
            .padding(.horizontal, 28)
            #else
            .padding(.horizontal, Theme.Space.gutter(regularWidth: sizeClass == .regular))
            #endif
            .padding(.vertical, Theme.Space.xl)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .defaultScrollAnchor(.top)
        #if os(macOS)
        .scrollIndicators(.never)
        #endif
        #if os(iOS) || os(macOS)
        // A soft wash in the item's identity color, fixed at the top like the page's tint. It sits
        // under the content and the navigation bar, and never takes a touch.
        .background(alignment: .top) { identityWash(item) }
        #endif
        .groupedScreen()
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
            Button("item.copyAsJson") { copyJSON(item) }
                .accessibilityIdentifier("item.copyJSON.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("item.jsonContainsAllOf")
        }
        .confirmationDialog(
            "Supprimer définitivement « \(item.title) » ?", isPresented: $confirmDelete, titleVisibility: .visible
        ) {
            Button("item.deletePermanently", role: .destructive) {
                run(clearsSelection: true) {
                    try await session.deletePermanently(itemID: item.id, vaultID: item.vaultId)
                }
            }
            .accessibilityIdentifier("item.delete.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("item.cantUndone")
        }
        .simultaneousGesture(TapGesture().onEnded { session.noteActivity() })
    }

    private func banner(_ text: LocalizedStringKey, systemImage: String) -> some View {
        Label(text, systemImage: systemImage)
            .font(.callout)
            .foregroundStyle(.secondary)
            .padding(.horizontal, Theme.Space.l)
    }

    @ViewBuilder private func content(_ item: FfiItem) -> some View {
        // A login's first card always shows: its sign-in account and "Ajouter une passkey" live there.
        let loginCardID = item.itemType == .login ? item.sections.first?.id : nil
        let signIn = item.signInProvider
        let sections = item.sections.filter {
            $0.id == loginCardID
                || $0.fields.contains { !$0.value.isBlank && !(item.itemType == .document && $0.kind == .file) }
        }
        ForEach(sections, id: \.id) { section in
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                if !section.label.isEmpty {
                    // Small bold capitals above each card ("IDENTIFICATION", "ADRESSE").
                    Text(section.displayLabel(itemType: item.itemType).uppercased())
                        .font(.caption.weight(.bold))
                        .tracking(0.6)
                        .foregroundStyle(.secondary)
                        .padding(.leading, Theme.Space.l)
                        .accessibilityAddTraits(.isHeader)
                }
                EditorCard {
                    // A Document's files have their own preview card at the top.
                    let isLoginCard = section.id == loginCardID
                    // A login that signs in through a provider shows that account in place of its username.
                    let fields = section.fields.filter {
                        !$0.value.isBlank && !(item.itemType == .document && $0.kind == .file)
                            && !(isLoginCard && signIn != nil && $0.id == "username")
                    }
                    if isLoginCard, let signIn {
                        SignInWithRow(provider: signIn.provider, accountItemID: signIn.accountItemID)
                    }
                    ForEach(Array(fields.enumerated()), id: \.offset) { index, field in
                        if index > 0 || (isLoginCard && signIn != nil) { CardDivider() }
                        FieldValueView(field: field, itemType: item.itemType) { showToast($0) }
                    }
                    if isLoginCard, item.trashedAt == nil, !item.archived {
                        if signIn != nil || !fields.isEmpty { CardDivider() }
                        AddPasskeyRow(item: item) { showToast(String(localized: "item.addWebsiteFirst")) }
                    }
                }
            }
        }
        // The join code sits right under the network's fields, before websites, notes and tags.
        if item.itemType == .router, let payload = WifiQR.payload(for: item) {
            WifiQRCard(item: item, ssid: WifiQR.ssid(of: item), payload: payload)
                .frame(maxWidth: .infinity)
            if WifiAutoController.canJoinByHand, !standalone {
                WifiJoinButton(itemID: item.id).frame(maxWidth: .infinity)
            }
        }
        // Watch-only balances: what the Crypto screen watches of this wallet, and the derivation.
        if item.itemType == .cryptoWallet, !standalone {
            CryptoWalletWatchCard(item: item) { self.item = $0 }
        }
        if !item.urls.isEmpty {
            // A card like the fields and the notes around it, rows split by hairlines.
            EditorCard {
                ForEach(Array(item.urls.enumerated()), id: \.offset) { index, url in
                    if index > 0 { CardDivider() }
                    WebsiteRow(url: url, index: index) { showToast($0) }
                        .padding(.vertical, Theme.Space.s)
                }
            }
        }
        if !item.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            EditorCard {
                VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                    EditorLabel(String(localized: "item.notes"))
                    Text(Self.markdown(item.notes))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("item.notes")
                }
                .padding(.horizontal, Theme.Space.l)
                .padding(.vertical, Theme.Space.m)
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
            EditorCard {
                VStack(alignment: .leading, spacing: Theme.Space.s) {
                    EditorLabel(String(localized: "item.tags"))
                    FlowLayout(spacing: Theme.Space.s) {
                        ForEach(item.tags, id: \.self) { tag in
                            Text(tag)
                                .font(.footnote.weight(.medium))
                                .padding(.horizontal, Theme.Space.m)
                                .padding(.vertical, Theme.Space.xs)
                                .background(Theme.accent.opacity(0.18), in: Capsule())
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, Theme.Space.l)
                .padding(.vertical, Theme.Space.m)
            }
        }
    }

    /// "Modifié le ..." with a chevron; open, the item's timeline (newest first, on a vertical line
    /// with dots) and the link to the previous passwords.
    private func footer(_ item: FfiItem) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            Button {
                withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { showDates.toggle() }
            } label: {
                HStack(spacing: Theme.Space.s) {
                    Text("item.modified \(FieldDates.timestamp(item.updatedAt))")
                    Image(systemName: "chevron.right")
                        .font(.caption2.weight(.bold))
                        .rotationEffect(.degrees(showDates ? 90 : 0))
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("item.dates")
            .accessibilityValue(showDates ? Text("item.expanded") : Text("item.collapsed"))
            if showDates {
                ItemTimelineView(events: timeline.isEmpty ? ItemTimelineView.fallback(item) : timeline)
                    .transition(FoldMotion.transition(reduceMotion: reduceMotion))
                if item.passwordHistoryCount > 0, !locked(item) {
                    NavigationLink {
                        PasswordHistoryView(ref: ItemRef(vaultID: item.vaultId, itemID: item.id))
                    } label: {
                        HStack(spacing: Theme.Space.xs) {
                            Image(systemName: "clock.arrow.circlepath").symbolRenderingMode(.hierarchical)
                            Text("item.viewPreviousVersions")
                            Text(verbatim: "(\(item.passwordHistoryCount))")
                            Image(systemName: "chevron.right").font(.caption2.weight(.bold))
                        }
                        .foregroundStyle(Theme.readableAccent)
                        .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .padding(.leading, Theme.Space.xl)
                    .accessibilityIdentifier("item.history")
                }
            }
        }
        .font(.footnote)
        // Secondary, not tertiary: the "Modifié le" line is a button.
        .foregroundStyle(.secondary)
        .padding(.horizontal, Theme.Space.l)
        .padding(.top, Theme.Space.xs)
        .task(id: TimelineKey(item: item, open: showDates)) {
            guard showDates, !locked(item) else { return }
            timeline = (try? await session.itemTimeline(vaultID: item.vaultId, itemID: item.id)) ?? []
        }
    }

    static func historyLabel(_ count: UInt32) -> String {
        count == 1
            ? String(localized: "item.n1PreviousVersion")
            : String(localized: "item.previousVersions \(count)")
    }

    /// Inline Markdown only (bold, italic, code, links); line breaks kept. Never opens anything itself.
    static func markdown(_ text: String) -> AttributedString {
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        return (try? AttributedString(markdown: text, options: options)) ?? AttributedString(text)
    }

    // MARK: - Reprompt

    private func repromptSection(_ item: FfiItem) -> some View {
        EditorCard {
            VStack(spacing: Theme.Space.l) {
                Image(systemName: "lock.shield")
                    .symbolRenderingMode(.hierarchical)
                    .font(.system(size: 36))
                    .foregroundStyle(.tint)
                Text(travelGuarded(item)
                    ? "item.travel.guard.locked"
                    : "Cet élément demande une confirmation avant d'afficher son contenu.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier(travelGuarded(item) ? "item.travelGuard.locked" : "item.reprompt.locked")
                if askPassword {
                    // No `.password` content type, emptied as it leaves the screen: iOS must never
                    // offer to save the master password.
                    SecretInputField(
                        title: String(localized: "Mot de passe maître"), text: $password,
                        onSubmit: { verifyPassword() }, bordered: true, identifier: "item.reprompt.password")
                        .privacySensitive()
                    Button("app.confirm") { verifyPassword() }
                        .buttonStyle(.borderedProminent)
                        .disabled(password.isEmpty || checking)
                        .accessibilityIdentifier("item.reprompt.confirm")
                } else {
                    Button("common.show") { Task { await confirmPresence() } }
                        .buttonStyle(.borderedProminent)
                        .accessibilityIdentifier("item.reprompt.show")
                }
                if let repromptError {
                    Text(repromptError).font(.footnote).foregroundStyle(.red)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(Theme.Space.xl)
        }
    }

    private func confirmPresence() async {
        guard let item else { return }
        repromptError = nil
        if await session.confirmUserPresence(prompt: String(localized: "item.show \(item.title)")) {
            presencePassed = true
            if travelGuarded(item), !passwordPassed {
                askPassword = true
            } else {
                unlockReprompt()
            }
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
                passwordPassed = true
                if let item, travelGuarded(item), session.canUseBiometrics, !presencePassed {
                    // Extra protection: Face ID too, when the device has it.
                    askPassword = false
                    await confirmPresence()
                    if !presencePassed {
                        repromptError = String(localized: "item.travel.guard.needBiometrics")
                    }
                } else {
                    unlockReprompt()
                }
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
        #if os(macOS)
        // The vault as quiet text, then one glass group of same-size icons: Partager, Modifier,
        // Actions (separate glass pills of mixed sizes looked heavy and uneven).
        if item.trashedAt == nil {
            ToolbarItem(placement: .primaryAction) {
                VaultToolbarMenu(currentVaultID: item.vaultId) { vault in move(item, to: vault) }
            }
            .sharedBackgroundVisibility(.hidden)
        }
        // No glass pill: three quiet round icon buttons, the same weight as the vault label, each
        // with a soft circle under the pointer.
        if item.trashedAt == nil {
            ToolbarItem(placement: .primaryAction) {
                ShareLink(item: ItemShare.text(item), subject: Text(item.title)) {
                    Image(systemName: "square.and.arrow.up")
                }
                .buttonStyle(QuietIconButtonStyle())
                .help("common.share")
                .accessibilityLabel(Text("common.share"))
                .accessibilityIdentifier("item.share")
            }
            .sharedBackgroundVisibility(.hidden)
        }
        // A vault shared with this account in Read: nothing to edit (sharing spec 10.2).
        if item.trashedAt == nil, !isReadOnly(item) {
            ToolbarItem(placement: .primaryAction) {
                // ⌘E is the "Modifier" menu command (`BrowseCommands`).
                Button { startEditing(item) } label: { Image(systemName: "pencil") }
                    .buttonStyle(QuietIconButtonStyle())
                    .help("item.editE")
                    .accessibilityLabel(Text("common.edit"))
                    .accessibilityIdentifier("item.edit")
            }
            .sharedBackgroundVisibility(.hidden)
        }
        ToolbarItem(placement: .primaryAction) {
            Menu {
                menuContent(item)
            } label: {
                Image(systemName: "ellipsis")
            }
            .menuStyle(.button)
            .buttonStyle(QuietIconButtonStyle())
            .menuIndicator(.hidden)
            .help("app.actions")
            .accessibilityLabel(Text("app.actions"))
            .accessibilityIdentifier("item.menu")
        }
        .sharedBackgroundVisibility(.hidden)
        #else
        // The big header already names the item: no second title in the bar.
        ToolbarItem(placement: .principal) { Color.clear.frame(width: 1, height: 1) }
        // iPhone and iPad: three icons in one group. The vault is already under the title (its
        // badge), and "Déplacer…" sits in the actions menu.
        if item.trashedAt == nil {
            ToolbarItem(placement: .primaryAction) {
                ShareLink(item: ItemShare.text(item), subject: Text(item.title)) {
                    Label("common.share", systemImage: "square.and.arrow.up")
                }
                .accessibilityIdentifier("item.share")
            }
            if !isReadOnly(item) {
                ToolbarItem(placement: .primaryAction) {
                    Button("common.edit", systemImage: "pencil") { startEditing(item) }
                        .accessibilityIdentifier("item.edit")
                }
            }
        }
        ToolbarItem(placement: .primaryAction) {
            Menu {
                menuContent(item)
            } label: {
                Label("app.actions", systemImage: "ellipsis")
            }
            .menuIndicator(.hidden)
            .accessibilityIdentifier("item.menu")
        }
        #endif
    }

    @ViewBuilder private func menuContent(_ item: FfiItem) -> some View {
        if item.trashedAt != nil {
            Button("app.restore", systemImage: "arrow.uturn.backward") {
                run { try await session.restoreItem(itemID: item.id, vaultID: item.vaultId) }
            }
            .accessibilityIdentifier("item.restore")
            Button("item.deletePermanently", systemImage: "trash.slash", role: .destructive) {
                confirmDelete = true
            }
            .accessibilityIdentifier("item.delete")
        } else {
            #if os(macOS)
            if !standalone {
                Button("item.openInNewWindow", systemImage: "macwindow.on.rectangle") {
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
            Button("item.duplicate", systemImage: "plus.square.on.square") { duplicate(item) }
                .accessibilityIdentifier("item.duplicate")
            Divider()
            Button("item.copyPrivateLink", systemImage: "link") {
                copyPlain(OnePassLink.item(vaultID: item.vaultId, itemID: item.id).url.absoluteString,
                          toast: String(localized: "item.privateLinkCopied"))
            }
            .accessibilityIdentifier("item.copyLink")
            Button("item.copyItemId", systemImage: "number") {
                copyPlain(item.id, toast: String(localized: "item.idCopied"))
            }
            .accessibilityIdentifier("item.copyID")
            Button("item.copyAsJson", systemImage: "curlybraces") { confirmCopyJSON = true }
                .disabled(locked(item))
                .accessibilityIdentifier("item.copyJSON")
            Divider()
            ShareLink(item: ItemShare.text(item), subject: Text(item.title)) {
                Label("item.share", systemImage: "square.and.arrow.up")
            }
            .accessibilityIdentifier("item.shareMenu")
            if item.archived {
                Button("app.unarchive", systemImage: "archivebox") {
                    run { try await session.unarchive(itemID: item.id, vaultID: item.vaultId) }
                }
                .accessibilityIdentifier("item.unarchive")
            } else {
                Button("common.archive", systemImage: "archivebox") {
                    run { try await session.archive(itemID: item.id, vaultID: item.vaultId) }
                }
                .accessibilityIdentifier("item.archive")
            }
            Button("common.delete", systemImage: "trash", role: .destructive) {
                run(clearsSelection: true, success: String(localized: "item.movedToRecentlyDeleted")) {
                    try await session.trash(itemID: item.id, vaultID: item.vaultId)
                }
            }
            .accessibilityIdentifier("item.trash")
        }
    }

    private func move(_ item: FfiItem, to vault: FfiVault) {
        run(movedTo: vault.id, success: String(localized: "app.movedTo \(vault.meta.name)")) {
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
        model.showToast(String(localized: "item.jsonCopiedClearedIn"))
    }

    /// A new item (new id from the new-item path) with the fields copied and " (copie)" after the
    /// title, saved, then shown. Passkeys and files are not copied: a passkey belongs to one item.
    private func duplicate(_ item: FfiItem) {
        Task {
            do {
                let fresh = try session.newItem(type: item.itemType, vaultID: item.vaultId)
                var copy = item
                copy.id = fresh.id
                copy.title = String(localized: "item.copy \(item.title)")
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
                model.showToast(String(localized: "item.created2 \(saved.title)"))
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    /// "Ignorer" (passkey banner, Watchtower section) or "Rétablir": the check is excluded for this
    /// item, or no longer, saved like an edit. The next report follows.
    private func setWatchtowerExclusion(_ check: String, excluded: Bool, _ item: FfiItem) {
        var changed = item
        WatchtowerExclusions.set(check, excluded: excluded, in: &changed.watchtowerExclusions)
        guard changed.watchtowerExclusions != item.watchtowerExclusions else { return }
        Task {
            do {
                self.item = try await session.save(changed)
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    /// The item sits in a vault shared with this account in Read (sharing spec 10.2).
    private func isReadOnly(_ item: FfiItem) -> Bool {
        model.session.sharedRole(of: item.vaultId) == .read
    }

    private func startEditing(_ item: FfiItem) {
        guard !isReadOnly(item) else { return }
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
        showToast(String(localized: "item.saved"))
    }

    private func load() async {
        await reload(ref)
        if let item, item.reprompt || travelGuarded(item), !confirmed { await confirmPresence() }
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

/// "Rejoindre ce réseau" (iPhone, iPad): installs this one network in iOS now, switch or not,
/// near or not (the user asked), and says what iOS answered. Never a loop: one tap, one try.
private struct WifiJoinButton: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    @State private var working = false
    @State private var outcome: WifiInstallOutcome?

    var body: some View {
        VStack(spacing: Theme.Space.s) {
            Button {
                Task { await join() }
            } label: {
                Label("item.wifi.join", systemImage: "wifi")
            }
            .buttonStyle(.bordered)
            .disabled(working)
            .accessibilityIdentifier("item.wifi.join")
            if let message {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("item.wifi.joinResult")
            }
        }
        .onChange(of: itemID) { outcome = nil }
    }

    private var message: LocalizedStringKey? {
        switch outcome {
        case .installed: "item.wifi.joined"
        case .declined: "item.wifi.declined"
        case .rejected: "item.wifi.rejected"
        case .failed: "item.wifi.failed"
        case nil: nil
        }
    }

    private func join() async {
        working = true
        defer { working = false }
        outcome = await model.wifi.join(itemID: itemID, session: model.session) ?? .rejected
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
        VStack(spacing: Theme.Space.m) {
            HStack(alignment: .top, spacing: Theme.Space.s) {
                // Same width on the left as the menu, so the square stays centered.
                Color.clear.frame(width: 28, height: 28)
                qrSquare
                Menu {
                    Button("item.copyImage", systemImage: "doc.on.doc") { copyImage() }
                        .accessibilityIdentifier("item.wifiQR.copy")
                    Button("item.showLarge", systemImage: "arrow.up.left.and.arrow.down.right") {
                        shown = true
                        large = true
                    }
                    .accessibilityIdentifier("item.wifiQR.large")
                    Button("item.print", systemImage: "printer") { printImage() }
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
                .accessibilityLabel(Text("item.qrCodeActions"))
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
            VStack(spacing: Theme.Space.l) {
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
        // QRSquare's plate radius (side * 0.085 at 260 pt): geometry, not the radius scale.
        .clipShape(.rect(cornerRadius: 22))
        .contentShape(.rect)
        .onTapGesture { withAnimation(.easeOut(duration: 0.2)) { shown.toggle() } }
        .accessibilityAddTraits(.isButton)
        .accessibilityLabel(Text("item.qrCodeForNetwork \(ssid)"))
        .accessibilityValue(visible ? Text("item.shown") : Text("item.hidden2"))
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
                    Label("item.openInMaps", systemImage: "map")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(Theme.readableAccent)
                }
                .buttonStyle(.borderless)
                .padding(.horizontal, Theme.Space.l)
                .padding(.bottom, Theme.Space.m)
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
        return HStack(alignment: .top, spacing: Theme.Space.m) {
            VStack(spacing: 0) {
                Rectangle().fill(first ? .clear : Color.secondary.opacity(0.35)).frame(width: 1, height: 7)
                Circle()
                    .fill(first ? Theme.readableAccent : Color.secondary.opacity(0.7))
                    .frame(width: 7, height: 7)
                Rectangle().fill(last ? .clear : Color.secondary.opacity(0.35)).frame(width: 1)
                    .frame(maxHeight: .infinity)
            }
            .frame(width: 12)
            // The 3 pt top offsets set the first line level with the dot (7 pt line, 7 pt dot).
            Image(systemName: Self.icon(event.kind))
                .symbolRenderingMode(.hierarchical)
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
        .padding(.bottom, last ? 0 : Theme.Space.s)
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
        case "created": return String(localized: "item.itemCreated")
        case "imported":
            return d.isEmpty ? String(localized: "item.imported") : String(localized: "item.importedFrom \(d)")
        case "field_added": return String(localized: "item.fieldAdded \(d)")
        case "field_removed": return String(localized: "item.fieldRemoved \(d)")
        case "field_changed":
            switch d {
            case "notes": return String(localized: "item.notesChanged")
            case "tags": return String(localized: "item.tagsChanged")
            default: return String(localized: "item.changed \(d)")
            }
        case "password_changed": return String(localized: "item.passwordChanged")
        case "title_changed": return String(localized: "item.titleChanged")
        case "website_added": return String(localized: "item.websiteAdded \(d)")
        case "website_removed": return String(localized: "item.websiteRemoved \(d)")
        case "moved": return String(localized: "app.movedTo \(d)")
        case "favorited": return String(localized: "app.addedToFavorites")
        case "unfavorited": return String(localized: "item.removedFromFavorites")
        case "archived": return String(localized: "item.archived")
        case "unarchived": return String(localized: "item.unarchived")
        case "trashed": return String(localized: "item.movedToRecentlyDeleted2")
        case "restored": return String(localized: "item.restored")
        case "passkey_added": return String(localized: "item.passkeyAddedFor \(d)")
        case "passkey_removed": return String(localized: "item.passkeyRemovedFor \(d)")
        case "attachment_added": return String(localized: "item.attachmentAdded \(d)")
        default: return String(localized: "item.modified")
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

/// A login whose site accepts passkeys and that has none: the last Watchtower report flagged it
/// (`passkey_available`, from the passkeys directory Watchtower downloads). Without a report, or
/// when the check did not run, there is no banner (never faked).
struct PasskeyOffer: Equatable {
    static let checkID = "passkey_available"
    let host: String
    /// The site of the item's main address, where its passkey settings live.
    let url: URL

    static func offer(for item: FfiItem, report: FfiWatchtowerReport?) -> PasskeyOffer? {
        guard item.itemType == .login, !item.watchtowerExclusions.contains(checkID),
            !item.loginMethods.contains(.passkey),
            let report, WatchtowerExclusions.checks(of: item.id, in: report).contains(checkID)
        else { return nil }
        let main = item.urls.first { $0.primary } ?? item.urls.first
        guard let raw = main?.url, let host = URL(string: raw)?.host() ?? URL(string: "https://" + raw)?.host(),
            let url = URL(string: "https://\(host)")
        else { return nil }
        return PasskeyOffer(host: host, url: url)
    }
}

/// "Watchtower" in an item's detail: what the last report flagged for this item, each with "Ignorer
/// pour cet élément", and the checks ignored for it, each with "Rétablir". Hidden when both are empty.
struct ItemWatchtowerSection: View {
    let item: FfiItem
    let report: FfiWatchtowerReport?
    let onSet: (_ check: String, _ excluded: Bool) -> Void

    private var flagged: [String] {
        guard let report else { return [] }
        // The report may predate an exclusion just saved: an ignored check is listed once, as ignored.
        return WatchtowerExclusions.checks(of: item.id, in: report).filter {
            WatchtowerCard.of(check: $0) != nil && !item.watchtowerExclusions.contains($0)
        }
    }

    var body: some View {
        let ignored = item.watchtowerExclusions.filter { WatchtowerCard.of(check: $0) != nil }
        if !flagged.isEmpty || !ignored.isEmpty {
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                Text("item.watchtower")
                    .font(.caption.weight(.bold))
                    .tracking(0.6)
                    .foregroundStyle(.secondary)
                    .padding(.leading, Theme.Space.l)
                    .accessibilityAddTraits(.isHeader)
                EditorCard {
                    let rows = flagged.map { ($0, false) } + ignored.map { ($0, true) }
                    ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                        if index > 0 { CardDivider() }
                        line(check: row.0, ignored: row.1)
                    }
                }
            }
            .accessibilityIdentifier("item.watchtower")
        }
    }

    @ViewBuilder private func line(check: String, ignored: Bool) -> some View {
        if let card = WatchtowerCard.of(check: check) {
            HStack(spacing: Theme.Space.m) {
                PageTile(symbol: card.symbol, color: ignored ? .gray : card.color, size: 26)
                VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                    Text(card.title).font(.subheadline.weight(.medium))
                    Text(ignored ? String(localized: "item.ignoredForItem") : card.message)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Button(ignored ? LocalizedStringKey("Rétablir") : "Ignorer") { onSet(check, !ignored) }
                    .buttonStyle(.borderless)
                    .accessibilityIdentifier("item.watchtower.\(ignored ? "restore" : "ignore").\(check)")
            }
            .editorRowPadding()
        }
    }
}

/// Purple card at the top of a login: "Passkey disponible", collapsible, with "Utiliser une
/// passkey" (opens the site's settings) and "Ignorer" (excluded for this item, saved).
struct PasskeyOfferBanner: View {
    @Environment(\.openURL) private var openURL
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let offer: PasskeyOffer
    let onIgnore: () -> Void
    @State private var expanded = true

    private let purple = Color(red: 0.55, green: 0.36, blue: 0.96)

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            Button {
                withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { expanded.toggle() }
            } label: {
                HStack(spacing: Theme.Space.s) {
                    Image(systemName: "person.badge.key.fill")
                    Text("item.passkeyAvailable").font(.headline)
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
                Text("item.supportsPasskeysPasskeyReplaces \(offer.host)")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: Theme.Space.m) {
                    Button("item.usePasskey") { openURL(offer.url) }
                        .buttonStyle(.borderedProminent)
                        .tint(purple)
                        .accessibilityIdentifier("item.passkeyOffer.use")
                    Button("Ignorer", action: onIgnore)
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("item.passkeyOffer.ignore")
                }
            }
        }
        .padding(Theme.Space.l)
        .background(purple.opacity(0.16), in: .rect(cornerRadius: Theme.Radius.card, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous).stroke(purple.opacity(0.35)))
        .accessibilityIdentifier("item.passkeyOffer")
    }
}

/// The folds of the detail (dates, passkey offer, document preview). iPhone and iPad take the
/// shared critically damped spring and a fade under Reduce Motion; the Mac keeps its snappy fold.
enum FoldMotion {
    static func animation(reduceMotion: Bool) -> Animation {
        #if os(iOS)
        Motion.fold(reduceMotion: reduceMotion)
        #else
        .snappy
        #endif
    }

    static func transition(reduceMotion: Bool) -> AnyTransition {
        #if os(iOS)
        Motion.reveal(reduceMotion: reduceMotion)
        #else
        .opacity
        #endif
    }
}

// MARK: - Document preview

/// Top of a Document: file icon and name centered, a collapsible "Aperçu" row, then the size.
/// Attachment contents are not stored in the vault yet (milestone 5), so the preview says so
/// instead of showing anything.
struct DocumentCard: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let attachment: FfiAttachment
    @State private var preview = false

    static func attachments(of item: FfiItem) -> [FfiAttachment] {
        item.sections.flatMap(\.fields).compactMap {
            if case .file(let a) = $0.value { a } else { nil }
        }
    }

    var body: some View {
        EditorCard {
            VStack(spacing: Theme.Space.s) {
                Image(systemName: "doc.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(Theme.readableAccent)
                Text(attachment.name).font(.headline).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, Theme.Space.xl)
            CardDivider()
            Button {
                withAnimation(FoldMotion.animation(reduceMotion: reduceMotion)) { preview.toggle() }
            } label: {
                HStack {
                    Text("item.preview")
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
                Text("item.previewUnavailableAttachmentContents")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .editorRowPadding()
            }
            CardDivider()
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                EditorLabel(String(localized: "item.fileSize"))
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
                           message: String(localized: "item.unlockOnepassInMain"))
            }
        }
        .frame(minWidth: 480, minHeight: 520)
    }
}

/// "Se connecter avec": the login signs in through another account (Apple, Google...). The card shows
/// that account as its own row (site icon, favorite star, title, username) and opens it on a click.
/// When the account item is gone, the provider's mark and name stand in.
private struct SignInWithRow: View {
    @Environment(AppModel.self) private var model
    let provider: String
    let accountItemID: String
    @State private var hovering = false

    private var account: FfiItemSummary? {
        model.session.summaries.first { $0.id == accountItemID && $0.trashedAt == nil }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
                EditorLabel(String(localized: "item.signInWith").detailLabelCase)
                if let account {
                    Button {
                        model.selectedItem = ItemRef(vaultID: account.vaultId, itemID: account.id)
                    } label: {
                        HStack(spacing: 0) {
                            ItemListRow(summary: account, vaultName: nil)
                            Image(systemName: "chevron.right")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.tertiary)
                                .opacity(hovering ? 1 : 0)
                        }
                        .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .onHover { hovering = $0 }
                    .help("Ouvrir \(account.title)")
                    .accessibilityIdentifier("item.signInWith.account")
                } else {
                    HStack(spacing: Theme.Space.m) {
                        ProviderMark(provider: LoginProvider(rawValue: provider), size: 34)
                        Text(verbatim: LoginProvider.displayName(provider))
                            .font(.body.weight(.semibold))
                    }
                    .accessibilityIdentifier("item.signInWith.provider")
                }
        }
        .editorRowPadding()
    }
}
