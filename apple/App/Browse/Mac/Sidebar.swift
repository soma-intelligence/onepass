import DesignKit
import SwiftUI
import VaultKit

/// First column of the Mac and iPad window (spec 6.1, mockup `Main`): account header with its menu,
/// "Tous les éléments", Favoris, COFFRES, CATÉGORIES (types present only), TAGS, then Archive and
/// Supprimés récemment. Native sidebar list (transparent Liquid Glass background), sync status chip
/// at the bottom when sync is offline, failing or refused data.
struct Sidebar: View {
    @Environment(AppModel.self) private var model
    @State private var creatingVault = false

    private var session: VaultSession { model.session }

    private var selection: Binding<ItemFilter?> {
        Binding(
            get: { model.selection },
            set: { if let filter = $0 { model.selection = filter } })
    }

    var body: some View {
        let counts = session.counts()
        List(selection: selection) {
            Section {
                AccountHeader()
            }
            Section {
                row("Tous les éléments", systemImage: "square.grid.2x2", count: counts.all, filter: .all, id: "library.all")
                row("Favoris", systemImage: "star", count: counts.favorites, filter: .favorites, id: "library.favorites")
            }
            vaultsSection(counts)
            categoriesSection(counts)
            tagsSection(counts)
            Section {
                row("Archive", systemImage: "archivebox", count: counts.archive, filter: .archive, id: "library.archive")
                row("Supprimés récemment", systemImage: "trash", count: counts.trash, filter: .trash, id: "library.trash")
            }
        }
        .listStyle(.sidebar)
        // The footer sits in the list's bottom safe area (rows end above it when scrolled to the end)
        // on an opaque bar material: rows passing under it never show through "Réglages".
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 0) {
                Divider()
                if case .accountChanged = model.syncStatus {
                    AccountChangedCard(compact: true).padding(10)
                } else {
                    SyncStatusChip(status: model.syncStatus)
                }
                SettingsRow()
            }
            .background { SidebarFooterBackground() }
        }
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
        }
        #if os(iOS) || os(visionOS)
        .navigationTitle("OnePass")
        #endif
    }

    // MARK: - Sections

    @ViewBuilder private func vaultsSection(_ counts: ItemCounts) -> some View {
        Section {
            ForEach(session.vaults, id: \.id) { vault in
                Label {
                    Text(vault.meta.name)
                } icon: {
                    VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 18)
                }
                .badge(counts.byVault[vault.id] ?? 0)
                .tag(ItemFilter.vault(vault.id))
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
                    .tag(ItemFilter.category(category.type))
                    .accessibilityIdentifier("sidebar.categories.\(NewItemMenu.key(category.type))")
                }
            } header: {
                Text("Catégories").textCase(.uppercase)
            }
        }
    }

    @ViewBuilder private func tagsSection(_ counts: ItemCounts) -> some View {
        let tags = counts.byTag.keys.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        if !tags.isEmpty {
            Section {
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
                    .tag(ItemFilter.tag(tag))
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
            .tag(filter)
            .accessibilityIdentifier("sidebar.\(id)")
    }
}

/// Account header at the top of the sidebar: initials on an accent square, local name. Its menu
/// holds Réglages and Verrouiller.
struct AccountHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Menu {
            SettingsButton(identifier: "account.settings")
            Button("Verrouiller", systemImage: "lock") { model.perform(.lock) }
                .accessibilityIdentifier("account.lock")
        } label: {
            HStack(spacing: 10) {
                Text(model.initials.isEmpty ? "?" : model.initials)
                    .font(.system(size: 12, weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(Theme.accent, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                Text(model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName)
                    .font(.headline)
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer(minLength: 0)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .visionHoverEffect()
        .accessibilityLabel(Text("Compte \(model.settings.displayName)"))
        .accessibilityIdentifier("account.menu")
    }
}

/// Small category tile of the sidebar (color of the type, white symbol).
struct CategoryTile: View {
    let category: ItemCategory
    var size: CGFloat = 18

    var body: some View {
        RoundedRectangle(cornerRadius: size * 5 / 18, style: .continuous)
            .fill(category.color)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: category.symbol)
                    .font(.system(size: size * 0.55, weight: .semibold))
                    .foregroundStyle(.white)
            }
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
