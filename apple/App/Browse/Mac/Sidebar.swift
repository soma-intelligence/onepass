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
        // lights. The account header sits above the list, below the title bar (its height read from
        // the window): never under the window buttons, its menu stays clickable.
        VStack(spacing: 0) {
            // The account sits in the title bar row (toolbar item below); the list starts under it.
            Color.clear.frame(height: titlebarHeight)
            // In a VStack the list asks for the height of all its rows as a minimum, which made the
            // split view taller than the window and pushed every column's top out of sight.
            list
                .frame(minHeight: 0, maxHeight: .infinity)
        }
        .background { TitlebarHeightReader(height: $titlebarHeight) }
        // The account pill fills the sidebar's title bar row: the system sidebar button sat across
        // the column edge after it. The sidebar still folds with View > Hide Sidebar (⌃⌘S) or a drag.
        .toolbar(removing: .sidebarToggle)
        .toolbar {
            ToolbarItem(placement: .automatic) {
                AccountHeader(compact: true)
            }
        }
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
                row("Tous les éléments", systemImage: "square.grid.2x2", count: counts.all, filter: .all, id: "library.all")
                row("Favoris", systemImage: "star", count: counts.favorites, filter: .favorites, id: "library.favorites")
                pageRow("Watchtower", symbol: "checkmark.shield.fill", color: Self.watchtowerColor, page: .watchtower,
                    id: "sidebar.watchtower")
                pageRow("Développeur", symbol: "chevron.left.forwardslash.chevron.right", color: Self.developerColor,
                    page: .developer, id: "sidebar.developer")
                // No count: it depends on where the user is, asked only once the row is opened.
                Label {
                    Text("À proximité")
                } icon: {
                    NearbyTile()
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
                row("Archive", systemImage: "archivebox", count: counts.archive, filter: .archive, id: "library.archive")
                row("Supprimés récemment", systemImage: "trash", count: counts.trash, filter: .trash, id: "library.trash")
            }
        }
        .listStyle(.sidebar)
        // The footer sits in the list's bottom safe area (rows end above it when scrolled to the end)
        // on an opaque bar material: rows passing under it never show through "Réglages".
        .sidebarFooter {
            VStack(spacing: 0) {
                #if !os(macOS)
                Divider()
                #endif
                if model.showsAutoFillTip {
                    #if os(macOS)
                    AutoFillTipCard(compact: true)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                        .padding(.horizontal, 10)
                        .padding(.bottom, 4)
                    #else
                    AutoFillTipCard()
                        .padding(12)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
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
        #if os(iOS) || os(visionOS)
        .navigationTitle("OnePass")
        #endif
    }

    static let watchtowerColor = Color(red: 0xE1 / 255, green: 0x4D / 255, blue: 0x3C / 255)
    static let developerColor = Color(red: 0x5E / 255, green: 0x5C / 255, blue: 0xE6 / 255)

    // MARK: - Sections

    @ViewBuilder private func vaultsSection(_ counts: ItemCounts) -> some View {
        Section(isExpanded: $vaultsExpanded) {
            ForEach(session.vaults, id: \.id) { vault in
                Label {
                    Text(vault.meta.name)
                } icon: {
                    VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 18)
                }
                .badge(counts.byVault[vault.id] ?? 0)
                .tag(Destination.filter(.vault(vault.id)))
                .accessibilityIdentifier("sidebar.vaults.\(vault.id)")
            }
        } header: {
            HStack {
                Text("Coffres").textCase(.uppercase)
                Spacer()
                Button {
                    creatingVault = true
                } label: {
                    Label("Nouveau coffre", systemImage: "plus")
                        .labelStyle(.iconOnly)
                }
                .buttonStyle(.borderless)
                .help("Nouveau coffre")
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
            Section(isExpanded: $tagsExpanded) {
                ForEach(tags, id: \.self) { tag in
                    Label {
                        Text(tag)
                    } icon: {
                        Circle()
                            .fill(TagColor.of(tag))
                            .frame(width: 9, height: 9)
                            .frame(width: 18, height: 18)
                    }
                    .badge(counts.byTag[tag] ?? 0)
                    .tag(Destination.filter(.tag(tag)))
                    .accessibilityIdentifier("sidebar.tags.\(tag)")
                }
            } header: {
                Text("Tags").textCase(.uppercase)
            }
        }
    }

    private func row(
        _ title: LocalizedStringKey, systemImage: String, count: Int, filter: ItemFilter, id: String
    ) -> some View {
        Label(title, systemImage: systemImage)
            .badge(count)
            .tag(Destination.filter(filter))
            .accessibilityIdentifier("sidebar.\(id)")
    }

    private func pageRow(
        _ title: LocalizedStringKey, symbol: String, color: Color, page: BrowsePage, id: String
    ) -> some View {
        Label {
            Text(title)
        } icon: {
            SymbolTile(symbol: symbol, color: color)
        }
        .visionHoverEffect()
        .tag(Destination.page(page))
        .accessibilityIdentifier(id)
    }
}

/// Account header at the top of the sidebar: initials on an accent square, local name. A click
/// opens the account popover (who is signed in, Nouveau coffre, Importer, Réglages, Verrouiller).
struct AccountHeader: View {
    @Environment(AppModel.self) private var model
    @State private var creatingVault = false
    @State private var showingMenu = false
    @State private var hovering = false
    /// Mac title bar: a smaller avatar and name, next to the window buttons.
    var compact = false

    private var name: String {
        model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName
    }

    var body: some View {
        Button {
            showingMenu.toggle()
        } label: {
            // No chevron: the whole name is the button, the popover says the rest.
            HStack(spacing: compact ? 7 : 10) {
                AccountAvatar(initials: model.initials, size: compact ? 22 : 28)
                Text(name)
                    .font(compact ? .subheadline.weight(.semibold) : .headline)
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                if !compact { Spacer(minLength: 0) }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(hovering || showingMenu ? AnyShapeStyle(.fill.tertiary) : AnyShapeStyle(.clear),
                in: .rect(cornerRadius: 9))
            .contentShape(.rect(cornerRadius: 9))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: hovering)
        .visionHoverEffect()
        .accessibilityLabel(Text("Compte \(model.settings.displayName)"))
        .accessibilityIdentifier("account.menu")
        .popover(isPresented: $showingMenu, arrowEdge: .bottom) {
            AccountMenuPopover(name: name) { action in
                showingMenu = false
                switch action {
                case .newVault: creatingVault = true
                case .importItems: model.showImport = true
                case .settings: break
                case .lock: model.perform(.lock)
                }
            }
            .presentationCompactAdaptation(.popover)
        }
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
        }
    }
}

/// Initials on the accent square (account header and its popover).
struct AccountAvatar: View {
    let initials: String
    var size: CGFloat = 28

    var body: some View {
        Text(initials.isEmpty ? "?" : initials)
            .font(.system(size: size * 0.43, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(Theme.accent.gradient, in: RoundedRectangle(cornerRadius: size / 4, style: .continuous))
            .accessibilityHidden(true)
    }
}

/// The account popover: who is signed in and on which kind of device, then the account actions with
/// their shortcut, then Verrouiller in red.
private struct AccountMenuPopover: View {
    enum Action { case newVault, importItems, settings, lock }

    @Environment(AppModel.self) private var model
    #if os(macOS)
    @Environment(\.openSettings) private var openSettings
    #endif
    let name: String
    let perform: (Action) -> Void

    private var modeLabel: String {
        switch model.settings.deviceMode {
        case .personal: String(localized: "Appareil personnel")
        case .shared: String(localized: "Appareil partagé")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                AccountAvatar(initials: model.initials, size: 38)
                VStack(alignment: .leading, spacing: 1) {
                    Text(name).font(.headline).lineLimit(1)
                    Text(modeLabel).font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.top, 12)
            .padding(.bottom, 10)
            .accessibilityElement(children: .combine)

            Divider().padding(.horizontal, 8)
            VStack(spacing: 2) {
                PopoverMenuRow(title: "Nouveau coffre…", symbol: "plus.rectangle.on.rectangle", shortcut: nil) {
                    perform(.newVault)
                }
                .accessibilityIdentifier("account.newVault")
                PopoverMenuRow(title: "Importer…", symbol: "square.and.arrow.down", shortcut: "⌘⇧I") {
                    perform(.importItems)
                }
                .accessibilityIdentifier("account.import")
                PopoverMenuRow(title: "Réglages…", symbol: "gearshape", shortcut: "⌘,") {
                    perform(.settings)
                    #if os(macOS)
                    openSettings()
                    #else
                    model.showSettings = true
                    #endif
                }
                .accessibilityIdentifier("account.settings")
                Divider().padding(.horizontal, 6).padding(.vertical, 3)
                PopoverMenuRow(title: "Verrouiller", symbol: "lock", shortcut: "⌘L", tint: .red) {
                    perform(.lock)
                }
                .accessibilityIdentifier("account.lock")
            }
            .padding(6)
        }
        .frame(width: 270)
    }
}
/// A row of a popover menu: icon, title, the shortcut on the right, highlighted under the pointer.
struct PopoverMenuRow: View {
    let title: LocalizedStringKey
    let symbol: String
    var shortcut: String?
    var tint: Color?
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .font(.system(size: 13, weight: .medium))
                    .frame(width: 20)
                    .foregroundStyle(hovering ? AnyShapeStyle(.white) : tint.map(AnyShapeStyle.init) ?? AnyShapeStyle(.secondary))
                Text(title)
                    .foregroundStyle(hovering ? AnyShapeStyle(.white) : tint.map(AnyShapeStyle.init) ?? AnyShapeStyle(.primary))
                Spacer(minLength: 12)
                if let shortcut {
                    Text(shortcut)
                        .font(.callout.monospaced())
                        .foregroundStyle(hovering ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.tertiary))
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(hovering ? AnyShapeStyle((tint ?? Theme.accent).opacity(0.85)) : AnyShapeStyle(.clear),
                in: .rect(cornerRadius: 7))
            .contentShape(.rect(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

/// A colored square with a white SF Symbol, the size of a category tile (Watchtower, Développeur).
struct SymbolTile: View {
    let symbol: String
    let color: Color
    var size: CGFloat = 18

    var body: some View {
        RoundedRectangle(cornerRadius: size * 5 / 18, style: .continuous)
            .fill(color)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: symbol)
                    .font(.system(size: size * 0.5, weight: .semibold))
                    .foregroundStyle(.white)
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
            .padding(.horizontal, 12)
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
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }
}

#if os(macOS)
/// Reads how much of the window the title bar and the toolbar cover (`contentLayoutRect`). Also used
/// by the guest session's sidebar (`PublicSessionView`).
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
