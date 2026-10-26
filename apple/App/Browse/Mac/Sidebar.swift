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
        .safeAreaInset(edge: .bottom, spacing: 0) {
            SyncStatusChip(status: model.syncStatus)
        }
        .sheet(isPresented: $creatingVault) {
            NewVaultSheet()
        }
        #if os(iOS)
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
/// holds Verrouiller (Réglages joins it with Task 16).
struct AccountHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Menu {
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

/// Bottom of the sidebar: shown only when sync is offline, failing, or refused remote data.
struct SyncStatusChip: View {
    let status: SyncStatus

    private var appearance: (text: String, symbol: String, color: Color)? {
        switch status {
        case .offline: (status.label, "wifi.slash", .orange)
        case .error: (status.label, "exclamationmark.triangle.fill", .red)
        case .refused: (status.label, "xmark.shield.fill", .red)
        default: nil
        }
    }

    var body: some View {
        if let appearance {
            Label {
                Text(appearance.text).lineLimit(2)
            } icon: {
                Image(systemName: appearance.symbol).foregroundStyle(appearance.color)
            }
            .font(.footnote)
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .glassEffect(.regular, in: Capsule())
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("sidebar.sync")
        }
    }
}

/// "Nouveau coffre": name only, until the vault editor of Task 16 replaces this sheet.
struct NewVaultSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var error: String?
    @State private var saving = false

    private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }

    var body: some View {
        NavigationStack {
            Form {
                TextField("Nom du coffre", text: $name, prompt: Text("Projet Atlas"))
                    .onSubmit(create)
                    .accessibilityIdentifier("vault.name")
                if let error {
                    Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Nouveau coffre")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Créer", action: create)
                        .disabled(trimmed.isEmpty || saving)
                        .accessibilityIdentifier("vault.create")
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 360, minHeight: 180)
        #endif
    }

    private func create() {
        guard !trimmed.isEmpty, !saving else { return }
        saving = true
        let meta = FfiVaultMeta(name: trimmed, icon: "folder", color: "blue", travelSafe: false, mcpAccess: false)
        Task {
            defer { saving = false }
            do {
                try await model.session.createVault(meta)
                dismiss()
            } catch {
                self.error = VaultError(error).localizedMessage
            }
        }
    }
}
