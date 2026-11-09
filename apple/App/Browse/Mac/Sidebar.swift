import DesignKit
import SwiftUI
import VaultKit

/// First column of the Mac and iPad window (spec 6.1, mockup `Main`): account header with its menu,
/// "Tous les éléments", Favoris, Watchtower, Développeur, À proximité, then the folding COFFRES and
/// TAGS sections, then Archive and Supprimés récemment. The item types are a dropdown of the list
/// column ("Toutes les catégories"). Native sidebar list (transparent Liquid Glass background), sync
/// status chip at the bottom when sync is offline, failing or refused data.
struct Sidebar: View {
    @Environment(AppModel.self) private var model
    @State private var creatingVault = false
    /// Not secret: which sections are folded.
    /// The account panel under the account row (Mac).
    @State private var accountMenuOpen = false
    @State private var accountRowBottom: CGFloat = 60
    /// The vault whose sheet is open from its row's context menu.
    @State private var editingVaultID: String?
    /// Doublons possibles (spec 2026-11-03-duplicates): the groups behind the row's count.
    @State private var duplicates = DuplicatesLoader()
    @AppStorage("onepass.sidebar.vaultsExpanded", store: AppModel.browseDefaults) private var vaultsExpanded = true
    @AppStorage("onepass.sidebar.tagsExpanded", store: AppModel.browseDefaults) private var tagsExpanded = true
    #if os(macOS)
    /// Height of the window's title bar and toolbar, which the sidebar column does not report as
    /// a safe area (macOS 26): the account header starts below it.
    @State private var titlebarHeight: CGFloat = 52
    #endif

    private var session: VaultSession { model.session }

    /// A row of the sidebar: an item filter (shown in the list column) or a full page.
    enum Destination: Hashable {
        case filter(ItemFilter)
        case page(BrowsePage)
    }

    /// Choosing a filter goes back to the item list; Watchtower and Développeur open their page.
    private var selection: Binding<Destination?> {
        Binding(
            get: { model.page == .items ? .filter(model.selection) : .page(model.page) },
            set: { destination in
                switch destination {
                case .filter(let filter):
                    // Also clears a Watchtower list shown on the same filter.
                    model.showItems(filter)
                case .page(let page):
                    model.page = page
                case nil:
                    break
                }
            })
    }

    var body: some View {
        #if os(macOS)
        // Mac: the sidebar column reports no top safe area, so a list there starts under the traffic
        // lights. The account row sits above the list, below the title bar (its height read from
        // the window): never under the window buttons, its menu stays clickable.
        VStack(spacing: 0) {
            // The avatar's left edge lines up with the row tiles below.
            AccountHeader(menuOpen: $accountMenuOpen)
                .padding(.horizontal, 15)
                .padding(.bottom, 6)
                // Where the account panel hangs from: right under this row.
                .onGeometryChange(for: CGFloat.self) { $0.frame(in: .named("sidebarColumn")).maxY } action: {
                    accountRowBottom = $0
                }
            // In a VStack the list asks for the height of all its rows as a minimum, which made the
            // split view taller than the window and pushed every column's top out of sight.
            // Rows scrolling up fade out under the account row instead of running behind it.
            // The first row starts below the fade, so at rest its selection is never washed out.
            list
                .contentMargins(.top, 12, for: .scrollContent)
                .frame(minHeight: 0, maxHeight: .infinity)
                .mask {
                    VStack(spacing: 0) {
                        LinearGradient(colors: [.clear, .black], startPoint: .top, endPoint: .bottom).frame(height: 12)
                        Rectangle()
                    }
                }
        }
        .coordinateSpace(.named("sidebarColumn"))
        .background { TitlebarHeightReader(height: $titlebarHeight) }
        // The account menu: our own panel under the account row (the system menu could not take
        // the house style). A click anywhere else or Escape closes it.
        .overlay(alignment: .topLeading) {
            if accountMenuOpen {
                ZStack(alignment: .topLeading) {
                    Color.black.opacity(0.001)
                        .ignoresSafeArea()
                        .onTapGesture { accountMenuOpen = false }
                    AccountMenuPanel(
                        newVault: { accountMenuOpen = false; creatingVault = true },
                        close: { accountMenuOpen = false }
                    )
                    .padding(.top, accountRowBottom - 2)
                    .padding(.horizontal, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .transition(.asymmetric(
                        insertion: .scale(scale: 0.96, anchor: .top).combined(with: .opacity),
                        removal: .opacity))
                }
            }
        }
        .animation(.spring(duration: 0.28, bounce: 0.15), value: accountMenuOpen)
        // The whole column, header included, on the system's translucent sidebar material: the
        // desktop shows through, blurred, behind the account row and the list alike.
        .background { SidebarMaterial().ignoresSafeArea() }
        // Light appearance: a brighter, airier column (a white wash over the blur, the desktop
        // still showing through), so it no longer reads as a gray panel.
        .background { SidebarLightWash().ignoresSafeArea() }
        #else
        list
        #endif
    }

    private var list: some View {
        let counts = session.counts()
        return List(selection: selection) {
            #if !os(macOS)
            Section {
                AccountHeader()
            }
            #endif
            Section {
                row("Tous les éléments", symbol: "square.grid.2x2.fill", color: Theme.accent, count: counts.all,
                    filter: .all, id: "library.all")
                row("Favoris", symbol: "star.fill", color: Self.favoritesColor, count: counts.favorites,
                    filter: .favorites, id: "library.favorites")
                row("Passkeys", symbol: "person.badge.key.fill", color: Self.passkeysColor, count: counts.passkeys,
                    filter: .passkeys, id: "library.passkeys")
                pageRow("Watchtower", symbol: "shield.lefthalf.filled", color: Self.watchtowerColor, page: .watchtower,
                    id: "sidebar.watchtower")
                // Under Watchtower while there is something to review (the open page keeps its row).
                if !duplicates.groups.isEmpty || model.page == .duplicates {
                    pageRow("duplicates.title", symbol: "square.on.square", color: .orange, page: .duplicates,
                        id: "sidebar.duplicates", badge: duplicates.groups.count)
                }
                pageRow("crypto.title", symbol: "bitcoinsign.circle", color: CoinIcon.color("bitcoin"), page: .crypto,
                    id: "sidebar.crypto")
                pageRow("Développeur", symbol: "chevron.left.forwardslash.chevron.right", color: Self.developerColor,
                    page: .developer, id: "sidebar.developer")
                // No count: it depends on where the user is, asked only once the row is opened.
                Label {
                    Text("À proximité")
                } icon: {
                    NearbyTile(size: SymbolTile.sidebarSize)
                }
                .visionHoverEffect()
                .tag(Destination.filter(.nearby))
                .accessibilityIdentifier("sidebar.nearby")
            }
            vaultsSection(counts)
            #if !os(macOS)
            // iPad: no type dropdown in its list column yet, the types stay here.
            categoriesSection(counts)
            #endif
            tagsSection(counts)
            Section {
                row("Archive", symbol: "archivebox.fill", color: Self.binColor, count: counts.archive,
                    filter: .archive, id: "library.archive")
                row("Supprimés récemment", symbol: "trash.fill", color: Self.binColor, count: counts.trash,
                    filter: .trash, id: "library.trash")
            }
        }
        .listStyle(.sidebar)
        .task(id: session.summariesRevision) { await duplicates.load(session) }
        #if os(macOS)
        .scrollIndicators(.never)
        .scrollContentBackground(.hidden)
        #endif
        // The footer sits in the list's bottom safe area (rows end above it when scrolled to the end)
        // on an opaque bar material: rows passing under it never show through "Réglages".
        .sidebarFooter {
            VStack(spacing: 0) {
                #if !os(macOS)
                Divider()
                #endif
                if model.travel.suggestion != .none {
                    TravelSuggestionCard(compact: true)
                        .padding(Theme.Space.m)
                        .background(.thickMaterial, in: RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous)
                                .strokeBorder(Color.primary.opacity(0.08))
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                }
                if model.showsAutoFillTip {
                    #if os(macOS)
                    // A thick material, not clear glass: rows scrolling under the card must not read
                    // through it.
                    AutoFillTipCard(compact: true)
                        .padding(.horizontal, Theme.Space.m)
                        .padding(.vertical, Theme.Space.s)
                        .background(.thickMaterial, in: RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous)
                                .strokeBorder(Color.primary.opacity(0.08))
                        }
                        .shadow(color: .black.opacity(0.18), radius: 8, y: 3)
                        .padding(.horizontal, 10)
                        .padding(.bottom, Theme.Space.xs)
                    #else
                    AutoFillTipCard()
                        .padding(Theme.Space.m)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous))
                        .padding(.horizontal, 10)
                        .padding(.top, 10)
                    #endif
                }
                if model.showsSafariSetupCard {
                    #if os(macOS)
                    SafariSetupCard()
                        .padding(Theme.Space.m)
                        .background(.thickMaterial, in: RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous)
                                .strokeBorder(Color.primary.opacity(0.08))
                        }
                        .shadow(color: .black.opacity(0.18), radius: 8, y: 3)
                        .padding(.horizontal, 10)
                        .padding(.bottom, Theme.Space.xs)
                    #else
                    SafariSetupCard()
                        .padding(Theme.Space.m)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: Theme.Radius.control, style: .continuous))
                        .padding(.horizontal, 10)
                        .padding(.top, 10)
                    #endif
                }
                if case .accountChanged = model.syncStatus {
                    AccountChangedCard(compact: true).padding(10)
                } else {
                    SyncStatusChip(status: model.syncStatus)
                }
                #if os(macOS)
                // Réglages live in the account menu at the top on the Mac.
                Color.clear.frame(height: 6)
                #else
                SettingsRow()
                #endif
            }
            #if !os(macOS)
            .background { SidebarFooterBackground() }
            #endif
        }
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
        }
        .sheet(isPresented: Binding(get: { editingVaultID != nil }, set: { if !$0 { editingVaultID = nil } })) {
            if let vault = session.vaults.first(where: { $0.id == editingVaultID }) {
                VaultEditorView(vault: vault) { editingVaultID = nil }
            }
        }
        #if os(iOS) || os(visionOS)
        .navigationTitle("OnePass")
        #endif
    }

    static let watchtowerColor = Color(red: 0xE1 / 255, green: 0x4D / 255, blue: 0x3C / 255)
    /// Graphite, like Terminal: the accent stays for "Tous les éléments".
    static let developerColor = Color(red: 0x63 / 255, green: 0x63 / 255, blue: 0x66 / 255)
    static let passkeysColor = Color.purple
    static let favoritesColor = Color(red: 0xF5 / 255, green: 0xA6 / 255, blue: 0x23 / 255)
    static let binColor = Color(red: 0x8E / 255, green: 0x8E / 255, blue: 0x93 / 255)

    // MARK: - Sections

    @ViewBuilder private func vaultsSection(_ counts: ItemCounts) -> some View {
        // A plain section with its own header: the system fold chevron sat on the right, on top of
        // the "+" button. Here it leads the title and the "+" keeps the trailing edge alone.
        Section {
            if vaultsExpanded {
                ForEach(session.vaults, id: \.id) { vault in
                    Label {
                        Text(vault.meta.name)
                    } icon: {
                        VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: SymbolTile.sidebarSize)
                    }
                    .badge(counts.byVault[vault.id] ?? 0)
                    .tag(Destination.filter(.vault(vault.id)))
                    // Name, symbol, color and travel safety: the same sheet as "Nouveau coffre".
                    .contextMenu {
                        Button("browse.editVault", systemImage: "paintpalette") { editingVaultID = vault.id }
                            .accessibilityIdentifier("sidebar.vaults.edit.\(vault.id)")
                    }
                    .accessibilityIdentifier("sidebar.vaults.\(vault.id)")
                }
            }
        } header: {
            HStack(spacing: 0) {
                SectionFoldHeader(title: "Coffres", expanded: $vaultsExpanded, id: "sidebar.vaults.fold")
                Spacer(minLength: 8)
                Button {
                    creatingVault = true
                } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 12, weight: .semibold))
                        .frame(width: 22, height: 22)
                        .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .help("Nouveau coffre")
                .accessibilityLabel(Text("Nouveau coffre"))
                .accessibilityIdentifier("sidebar.vaults.new")
            }
        }
    }

    #if !os(macOS)
    @ViewBuilder private func categoriesSection(_ counts: ItemCounts) -> some View {
        let present = ItemCategory.all.filter { (counts.byType[$0.type] ?? 0) > 0 }
        if !present.isEmpty {
            Section {
                ForEach(present) { category in
                    Label {
                        Text(category.plural)
                    } icon: {
                        CategoryTile(category: category)
                    }
                    .visionHoverEffect()
                    .badge(counts.byType[category.type] ?? 0)
                    .tag(Destination.filter(.category(category.type)))
                    .accessibilityIdentifier("sidebar.categories.\(NewItemMenu.key(category.type))")
                }
            } header: {
                Text("Catégories").textCase(.uppercase)
            }
        }
    }
    #endif

    @ViewBuilder private func tagsSection(_ counts: ItemCounts) -> some View {
        let tags = counts.byTag.keys.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        if !tags.isEmpty {
            Section {
                if tagsExpanded {
                ForEach(tags, id: \.self) { tag in
                    Label {
                        Text(tag)
                    } icon: {
                        TagMark(color: TagColor.of(tag))
                            .frame(width: SymbolTile.sidebarSize, height: SymbolTile.sidebarSize)
                    }
                    .badge(counts.byTag[tag] ?? 0)
                    .tag(Destination.filter(.tag(tag)))
                    .accessibilityIdentifier("sidebar.tags.\(tag)")
                }
                }
            } header: {
                SectionFoldHeader(title: "Tags", expanded: $tagsExpanded, id: "sidebar.tags.fold")
            }
        }
    }

    private func row(
        _ title: LocalizedStringKey, symbol: String, color: Color, count: Int, filter: ItemFilter, id: String
    ) -> some View {
        Label {
            Text(title)
        } icon: {
            SymbolTile(symbol: symbol, color: color, size: SymbolTile.sidebarSize)
        }
            .badge(count)
            .tag(Destination.filter(filter))
            .accessibilityIdentifier("sidebar.\(id)")
    }

    private func pageRow(
        _ title: LocalizedStringKey, symbol: String, color: Color, page: BrowsePage, id: String, badge: Int = 0
    ) -> some View {
        Label {
            Text(title)
        } icon: {
            SymbolTile(symbol: symbol, color: color, size: SymbolTile.sidebarSize)
        }
        .visionHoverEffect()
        // The badge goes before the tag, as on the counted rows: put after it, the row lost its
        // selection tag and a click did nothing.
        .badge(badge)
        .tag(Destination.page(page))
        .accessibilityIdentifier(id)
    }
}

/// Account header at the top of the sidebar: initials on an accent square, local name. A click
/// The account button: avatar and name. Its native menu says who is signed in and on which kind of
/// device, then Nouveau coffre, Importer, Réglages, and Verrouiller apart.
struct AccountHeader: View {
    @Environment(AppModel.self) private var model
    #if os(macOS)
    @Environment(\.openSettings) private var openSettings
    #endif
    @State private var creatingVault = false
    @State private var hovering = false
    /// Mac: the row opens the sidebar's own panel instead of the system menu.
    var menuOpen: Binding<Bool>?

    private var name: String {
        model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName
    }

    private var modeLabel: String {
        switch model.settings.deviceMode {
        case .personal: String(localized: "Appareil personnel")
        case .shared: String(localized: "Appareil partagé")
        }
    }

    var body: some View {
        if let menuOpen {
            Button {
                menuOpen.wrappedValue.toggle()
            } label: {
                label(open: menuOpen.wrappedValue)
            }
            .buttonStyle(.plain)
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
            .accessibilityLabel(Text("browse.account \(model.settings.displayName)"))
            .accessibilityIdentifier("account.menu")
        } else {
            systemMenu
        }
    }

    private func label(open: Bool) -> some View {
        HStack(spacing: Theme.Space.m) {
            AccountBadgeAvatar(
                initials: model.initials, photo: model.profileImage, color: model.accountTint,
                badge: model.accountBadge, size: 34)
            Text(name)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.primary)
                .lineLimit(1)
            Spacer(minLength: 8)
            Image(systemName: "chevron.down")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.secondary)
                .rotationEffect(.degrees(open ? 180 : 0))
                .animation(.spring(duration: 0.3, bounce: 0.2), value: open)
        }
        .padding(5)
        .padding(.trailing, 7)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(hovering || open ? AnyShapeStyle(.fill.tertiary) : AnyShapeStyle(.clear),
            in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
        .contentShape(.rect(cornerRadius: Theme.Radius.control, style: .continuous))
    }

    /// iPad and visionOS: the system menu.
    private var systemMenu: some View {
        Menu {
            AccountsMenuItems()
            Section {
                Button("Nouveau coffre…", systemImage: "plus.rectangle.on.rectangle") { creatingVault = true }
                    .accessibilityIdentifier("account.newVault")
                Button("Importer…", systemImage: "square.and.arrow.down") { model.showImport = true }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
                    .accessibilityIdentifier("account.import")
                Button("Réglages…", systemImage: "gearshape") {
                    #if os(macOS)
                    openSettings()
                    #else
                    model.showSettings = true
                    #endif
                }
                .keyboardShortcut(",", modifiers: .command)
                .accessibilityIdentifier("account.settings")
            } header: {
                Text(verbatim: "\(name) · \(modeLabel)")
            }
            Section {
                Button("Verrouiller", systemImage: "lock.fill", role: .destructive) { model.perform(.lock) }
                    .keyboardShortcut("l", modifiers: .command)
                    .accessibilityIdentifier("account.lock")
            }
        } label: {
            // Photo, name, chevron: one full-width row, the photo's corners echoed by the hover.
            HStack(spacing: Theme.Space.m) {
                AccountBadgeAvatar(
                initials: model.initials, photo: model.profileImage, color: model.accountTint,
                badge: model.accountBadge, size: 34)
                Text(name)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer(minLength: 8)
                Image(systemName: "chevron.down")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.secondary)
            }
            .padding(5)
            .padding(.trailing, 7)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(hovering ? AnyShapeStyle(.fill.tertiary) : AnyShapeStyle(.clear),
                in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
            .contentShape(.rect(cornerRadius: Theme.Radius.control, style: .continuous))
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: hovering)
        .visionHoverEffect()
        .accessibilityLabel(Text("browse.account \(model.settings.displayName)"))
        .accessibilityIdentifier("account.menu")
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
        }
    }
}

#if os(macOS)
/// The account panel (Mac): who is signed in and on which device, then Nouveau coffre, Importer,
/// Configurer un appareil, Réglages, and Verrouiller apart in red. Glass card, rows highlighted under the pointer with
/// their shortcut on the right. Escape closes it.
struct AccountMenuPanel: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openSettings) private var openSettings
    let newVault: () -> Void
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // The account row above already shows who: only the kind of device here.
            Text(model.settings.deviceMode == .shared ? "Appareil partagé" : "Appareil personnel")
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 10)
                .padding(.top, 6)
                .padding(.bottom, Theme.Space.xxs)
            divider
            // The accounts of this Mac (multi-account spec 7): switch, add, search all when chosen.
            ForEach(model.accounts.profiles) { profile in
                MacAccountRow(profile: profile) {
                    close()
                    model.runAccountAction(.switchTo(profile.slot))
                }
                .accessibilityIdentifier("accounts.row.\(profile.isPrimary ? "primary" : profile.slot)")
            }
            AccountMenuRow(title: "accounts.add", symbol: "plus", shortcut: nil) {
                close()
                model.runAccountAction(.add)
            }
            .accessibilityIdentifier("accounts.add")
            if model.accounts.unifiedSearch, model.accounts.hasSeveralAccounts {
                AccountMenuRow(title: "accounts.searchAll", symbol: "magnifyingglass", shortcut: nil) {
                    close()
                    model.runAccountAction(.searchAll)
                }
                .accessibilityIdentifier("accounts.searchAll")
            }
            divider
            AccountMenuRow(title: "Nouveau coffre…", symbol: "plus.circle", shortcut: nil, action: newVault)
                .accessibilityIdentifier("account.newVault")
            AccountMenuRow(title: "Importer…", symbol: "square.and.arrow.down", shortcut: "⇧⌘I") {
                close()
                model.showImport = true
            }
            .accessibilityIdentifier("account.import")
            AccountMenuRow(title: "Configurer un appareil…", symbol: "qrcode", shortcut: nil) {
                close()
                model.showDeviceSetup = true
            }
            .accessibilityIdentifier("account.setUpDevice")
            AccountMenuRow(title: "Réglages…", symbol: "gearshape", shortcut: "⌘,") {
                close()
                openSettings()
            }
            .accessibilityIdentifier("account.settings")
            divider
            AccountMenuRow(title: "Verrouiller", symbol: "lock", shortcut: "⌘L", destructive: true) {
                close()
                model.perform(.lock)
            }
            .accessibilityIdentifier("account.lock")
            if model.accounts.unlockedProfiles.count > 1 {
                AccountMenuRow(title: "accounts.lockAll", symbol: "lock.fill", shortcut: nil, destructive: true) {
                    close()
                    model.runAccountAction(.lockAll)
                }
                .accessibilityIdentifier("accounts.lockAll")
            }
        }
        .padding(5)
        // Never wider than the sidebar column (the panel was cut at its edge when it is narrow).
        .frame(maxWidth: 252)
        .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
        .shadow(color: .black.opacity(0.35), radius: 18, y: 10)
        .onExitCommand(perform: close)
    }

    private var divider: some View {
        Rectangle().fill(Color.primary.opacity(0.08)).frame(height: 1).padding(.horizontal, 8).padding(.vertical, 4)
    }
}

/// An account in the account panel: its avatar, name and a check on the account shown.
private struct MacAccountRow: View {
    @Environment(AppModel.self) private var model
    let profile: AccountProfile
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        let active = profile.slot == model.accounts.activeSlot
        Button(action: action) {
            HStack(spacing: 10) {
                AccountBadgeAvatar(
                    initials: model.initials(of: profile), photo: active ? model.profileImage : nil,
                    color: AccountStyle.color(profile.color), badge: AccountStyle.badge(profile), size: 22)
                Text(verbatim: model.displayName(of: profile)).font(.body).lineLimit(1)
                Spacer(minLength: 12)
                if active {
                    Image(systemName: "checkmark").font(.system(size: 12, weight: .semibold))
                } else if model.accounts.madeSession(profile.slot)?.state != .unlocked {
                    Image(systemName: "lock.fill").font(.system(size: 11)).foregroundStyle(.tertiary)
                }
            }
            .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.9)) : AnyShapeStyle(.clear),
                in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
            .contentShape(.rect(cornerRadius: Theme.Radius.control, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityAddTraits(active ? .isSelected : [])
    }
}

/// A row of the account panel.
private struct AccountMenuRow: View {
    let title: LocalizedStringKey
    let symbol: String
    let shortcut: String?
    var destructive = false
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .font(.system(size: 13, weight: .medium))
                    .frame(width: 18)
                Text(title).font(.body)
                Spacer(minLength: 12)
                if let shortcut {
                    Text(verbatim: shortcut)
                        .font(.callout)
                        .foregroundStyle(hovering ? AnyShapeStyle(.white.opacity(0.75)) : AnyShapeStyle(.tertiary))
                }
            }
            .foregroundStyle(hovering ? AnyShapeStyle(.white) : destructive ? AnyShapeStyle(.red) : AnyShapeStyle(.primary))
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(hovering ? AnyShapeStyle((destructive ? Color.red : Theme.accent).opacity(0.9)) : AnyShapeStyle(.clear),
                in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
            .contentShape(.rect(cornerRadius: Theme.Radius.control, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
#endif

/// The account's photo, or its initials on the accent, in a squircle (sidebar, menus, settings).
struct AccountAvatar: View {
    let initials: String
    var photo: Image?
    var size: CGFloat = 28
    /// The account's color (multi-account spec 7), the accent for the primary account.
    var tint: Color = Theme.accent

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
        Group {
            if let photo {
                photo.resizable().scaledToFill()
            } else {
                Text(initials.isEmpty ? "?" : initials)
                    .font(.system(size: size * 0.4, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(tint.gradient)
            }
        }
        .frame(width: size, height: size)
        .clipShape(shape)
        .overlay { shape.strokeBorder(.white.opacity(0.12), lineWidth: 0.5) }
        .accessibilityHidden(true)
    }
}

/// A tag's mark: a soft, rounded label shape (round on three corners, a gentle point at the top
/// left) in the tag's color, with its hole cut through near the point.
struct TagMark: View {
    let color: Color
    var size: CGFloat = 14

    var body: some View {
        UnevenRoundedRectangle(topLeadingRadius: size * 0.18, bottomLeadingRadius: size * 0.5,
                bottomTrailingRadius: size * 0.5, topTrailingRadius: size * 0.5, style: .continuous)
            .fill(color.gradient)
            .frame(width: size, height: size)
            .mask {
                Rectangle()
                    .overlay(alignment: .topLeading) {
                        Circle()
                            .frame(width: size * 0.24, height: size * 0.24)
                            .offset(x: size * 0.24, y: size * 0.24)
                            .blendMode(.destinationOut)
                    }
                    .compositingGroup()
            }
            .accessibilityHidden(true)
    }
}

/// A sidebar section title that folds its section: the chevron leads, turning down when open.
struct SectionFoldHeader: View {
    let title: LocalizedStringKey
    @Binding var expanded: Bool
    let id: String

    var body: some View {
        Button {
            withAnimation(.spring(duration: 0.3, bounce: 0)) { expanded.toggle() }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .bold))
                    .rotationEffect(.degrees(expanded ? 90 : 0))
                    .frame(width: 12)
                Text(title).textCase(.uppercase)
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityValue(Text(expanded ? "Ouvert" : "Fermé"))
        .accessibilityIdentifier(id)
    }
}

/// The house tile, as in System Settings: a squircle in a soft gradient of its color with a white
/// filled symbol and a hairline highlight. Every sidebar row wears one, so the column reads as one set.
struct SymbolTile: View {
    let symbol: String
    let color: Color
    var size: CGFloat = 18

    /// Sidebar rows (Mac and iPad).
    static let sidebarSize: CGFloat = 20

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
        shape
            .fill(color.gradient)
            .overlay { shape.strokeBorder(.white.opacity(0.18), lineWidth: 0.5) }
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: symbol)
                    .font(.system(size: size * 0.52, weight: .semibold))
                    .foregroundStyle(.white)
                    .shadow(color: .black.opacity(0.12), radius: 0.5, y: 0.5)
            }
            .accessibilityHidden(true)
    }
}

/// Small category tile of the sidebar (color of the type, white symbol).
struct CategoryTile: View {
    let category: ItemCategory
    var size: CGFloat = 18

    var body: some View {
        // The illustrated artwork of the type (DesignKit), the same as item icons.
        CategoryArtwork(type: category.type, size: size)
            .accessibilityHidden(true)
    }
}

/// Tag dot color: stable for a given tag name (FNV-1a over its UTF-8 bytes, not `hashValue`).
enum TagColor {
    private static let palette: [Color] = [
        Color(red: 0x25 / 255, green: 0x63 / 255, blue: 0xEB / 255),
        Color(red: 0x16 / 255, green: 0xA3 / 255, blue: 0x4A / 255),
        Color(red: 0xD9 / 255, green: 0x77 / 255, blue: 0x06 / 255),
        Color(red: 0xDB / 255, green: 0x27 / 255, blue: 0x77 / 255),
        Color(red: 0x7C / 255, green: 0x3A / 255, blue: 0xED / 255),
        Color(red: 0x0D / 255, green: 0x94 / 255, blue: 0x88 / 255),
    ]

    static func of(_ tag: String) -> Color {
        var hash: UInt32 = 2_166_136_261
        for byte in tag.utf8 {
            hash ^= UInt32(byte)
            hash = hash &* 16_777_619
        }
        return palette[Int(hash % UInt32(palette.count))]
    }
}

/// Bottom of the sidebar: shown only when sync is offline, failing, refused remote data, or the
/// iCloud account changed.
struct SyncStatusChip: View {
    let status: SyncStatus
    /// A refusal opens its safe exits (spec 3.3).
    @State private var safeExitKind: String?

    private var appearance: (text: String, symbol: String, color: Color)? {
        switch status {
        case .offline: (status.label, "wifi.slash", .orange)
        case .error: (status.label, "exclamationmark.triangle.fill", .red)
        case .refused: (status.label, "xmark.shield.fill", .red)
        case .accountChanged: (status.label, "person.crop.circle.badge.exclamationmark", .orange)
        // Discreet: a sync state, not an error (spec 3.1).
        case .waitingForServer: (status.label, "icloud.and.arrow.up", .secondary)
        case .waitingForMailbox: (status.label, "arrow.up.circle", .secondary)
        case .homeMoved: (status.label, "arrow.triangle.branch", .orange)
        default: nil
        }
    }

    var body: some View {
        if let appearance {
            chip(appearance)
                .contentShape(Capsule())
                .onTapGesture {
                    if case .refused(let kind) = status { safeExitKind = kind }
                }
                .accessibilityAddTraits(isRefusal ? .isButton : [])
                .sheet(item: Binding(get: { safeExitKind.map(RefusedKind.init) }, set: { safeExitKind = $0?.kind })) {
                    SafeExitChooserSheet(kind: $0.kind)
                }
        }
    }

    private var isRefusal: Bool {
        if case .refused = status { true } else { false }
    }

    private func chip(_ appearance: (text: String, symbol: String, color: Color)) -> some View {
        Group {
            Label {
                Text(appearance.text).lineLimit(2)
            } icon: {
                Image(systemName: appearance.symbol).foregroundStyle(appearance.color)
            }
            .font(.footnote)
            .padding(.horizontal, Theme.Space.m)
            .padding(.vertical, 7)
            #if os(visionOS)
            .glassBackgroundEffect(in: Capsule())
            #else
            .glassEffect(.regular, in: Capsule())
            #endif
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("sidebar.sync")
        }
    }
}

/// "Réglages": the Mac `Settings` window, a sheet on iPad.
struct SettingsButton: View {
    @Environment(AppModel.self) private var model
    #if os(macOS)
    @Environment(\.openSettings) private var openSettings
    #endif
    let identifier: String

    var body: some View {
        Button("Réglages", systemImage: "gearshape") {
            #if os(macOS)
            openSettings()
            #else
            model.showSettings = true
            #endif
        }
        .accessibilityIdentifier(identifier)
    }
}

/// Opaque backing of the sidebar footer: the bar material on iPhone and iPad; on Mac, where the
/// bar material stays translucent in a sidebar, the window background color.
private struct SidebarFooterBackground: View {
    var body: some View {
        #if os(macOS)
        Color(nsColor: .windowBackgroundColor)
        #else
        Rectangle().fill(.bar)
        #endif
    }
}

/// Bottom of the sidebar: "Réglages" (spec 6.1).
struct SettingsRow: View {
    var body: some View {
        HStack {
            SettingsButton(identifier: "sidebar.settings")
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .labelStyle(.titleAndIcon)
                .visionHoverEffect()
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Theme.Space.l)
        .padding(.vertical, 10)
    }
}

#if os(macOS)
/// Reads how much of the window the title bar and the toolbar cover (`contentLayoutRect`). Also used
/// by the guest session's sidebar (`PublicSessionView`).
private struct SidebarLightWash: View {
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        if scheme == .light { Color.white.opacity(0.04) } else { Color.clear }
    }
}

/// AppKit's behind-window sidebar vibrancy, for the parts of the column SwiftUI draws itself.
struct SidebarMaterial: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        // Light appearance: the popover's white frosted glass (`.sidebar` and the window
        // materials read gray in light). Dark keeps the sidebar material.
        view.material = .sidebar
        view.blendingMode = .behindWindow
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = context.environment.colorScheme == .light ? .popover : .sidebar
    }
}

struct TitlebarHeightReader: NSViewRepresentable {
    @Binding var height: CGFloat

    func makeNSView(context: Context) -> ReaderView {
        let view = ReaderView()
        view.onChange = { value in if abs(value - height) > 0.5 { height = value } }
        return view
    }

    func updateNSView(_ nsView: ReaderView, context: Context) {}

    final class ReaderView: NSView {
        var onChange: ((CGFloat) -> Void)?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            report()
        }

        override func layout() {
            super.layout()
            report()
        }

        private func report() {
            guard let window, let content = window.contentView else { return }
            // No title bar over the content (full screen without toolbar): no offset.
            let top = max(0, content.bounds.height - window.contentLayoutRect.maxY)
            DispatchQueue.main.async { [onChange] in onChange?(top) }
        }
    }
}
#endif

extension View {
    /// The sidebar's footer. Mac: a bar over the glass sidebar, rows fading under it with the scroll
    /// edge effect, no opaque band. Elsewhere: an inset on its own background.
    @ViewBuilder func sidebarFooter<Footer: View>(@ViewBuilder _ footer: () -> Footer) -> some View {
        #if os(macOS)
        safeAreaBar(edge: .bottom, spacing: 0) { footer() }
        #else
        safeAreaInset(edge: .bottom, spacing: 0) { footer() }
        #endif
    }
}
