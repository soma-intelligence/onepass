#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Items of one filter of the Éléments tab (vault, category, tag, Archive, Supprimés récemment)
/// sorted by title, or of "À proximité" (closest first, the distance in the subtitle), with a search
/// of its own. A row opens the item's detail. Swiping an active item from the right: Archive first
/// (a full swipe archives), then Mettre à la corbeille (toast, 30 days to restore); an archived
/// item offers Désarchiver.
struct CategoryListView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let filter: ItemFilter
    @State private var query = ""
    /// "À proximité": rows from the position and the session's location index, closest first.
    @State private var nearby = NearbyLoader()

    private var session: VaultSession { model.session }

    var body: some View {
        let items = filter == .nearby
            ? ItemSearch.filter(nearby.summaries, query: query) : session.items(filter: filter, query: query, sort: .title)
        let showVault = showsVaultName
        List {
            // Crypto wallets: the way to the watch-only balances (spec 2026-11-02-crypto-watch).
            if filter == .category(.cryptoWallet), query.isEmpty, !items.isEmpty {
                Section {
                    NavigationLink(value: PhoneRoute.crypto) {
                        Label("crypto.category.link", systemImage: "chart.line.uptrend.xyaxis")
                    }
                    .accessibilityIdentifier("category.crypto.open")
                }
            }
            ForEach(items, id: \.id) { summary in
                let ref = ItemRef(vaultID: summary.vaultId, itemID: summary.id)
                NavigationLink(value: PhoneRoute.item(ref)) {
                    ItemListRow(summary: summary, vaultName: showVault ? vaultName(summary.vaultId) : nil)
                }
                .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                    if summary.trashedAt == nil {
                        // The first button is the one a full swipe runs: Archive, never the trash.
                        if summary.archived {
                            Button("app.unarchive", systemImage: "archivebox") { model.unarchive(ref) }
                                .tint(.indigo)
                                .accessibilityIdentifier("list.swipe.unarchive")
                        } else {
                            Button("common.archive", systemImage: "archivebox") { model.archive(ref) }
                                .tint(.indigo)
                                .accessibilityIdentifier("list.swipe.archive")
                        }
                        Button("term.trash", systemImage: "trash", role: .destructive) {
                            model.trash(ref)
                        }
                        // The list's accent tint would paint it like Archive.
                        .tint(.red)
                        .accessibilityIdentifier("list.swipe.trash")
                    }
                }
                .swipeActions(edge: .leading) {
                    if summary.trashedAt == nil {
                        Button(
                            summary.favorite ? "Retirer des favoris" : "Ajouter aux favoris",
                            systemImage: summary.favorite ? "star.slash" : "star.fill"
                        ) {
                            Task {
                                try? await session.setFavorite(
                                    !summary.favorite, itemID: summary.id, vaultID: summary.vaultId)
                            }
                        }
                        .tint(.orange)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        // A row trashed, restored or favorited: the list closes or opens the gap. Typing in the
        // search refilters instantly (it happens with every key).
        .animation(Motion.list(reduceMotion: reduceMotion), value: session.summariesRevision)
        .scrollContentBackground(.hidden)
        .background(PhoneBackground())
        .overlay {
            if items.isEmpty { emptyState }
        }
        // The permission prompt comes from here (opening "À proximité"), never at launch.
        .task(id: NearbyRequest(active: filter == .nearby, revision: session.summariesRevision)) {
            guard filter == .nearby else { return }
            await nearby.load(session)
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.large)
        .searchable(text: $query, placement: .navigationBarDrawer, prompt: Text("common.search"))
        .toolbar {
            // No count in the bar: the list is the count. A new item of this list's type (Supprimés récemment and À proximité have none).
            if filter != .trash, filter != .nearby {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Nouvel élément", systemImage: "plus") { addItem() }
                        .accessibilityIdentifier("categoryList.new")
                }
            }
        }
    }

    /// A category list opens the editor of that type at once; the other lists ask for the type.
    private func addItem() {
        if case .category(let type) = filter {
            model.perform(.newItem(type))
        } else {
            model.showNewItemPicker = true
        }
    }

    private var showsVaultName: Bool {
        if case .vault = filter { return false }
        return session.vaults.count > 1
    }

    private func vaultName(_ id: String) -> String? {
        session.allVaults.first { $0.id == id }?.meta.name
    }

    private var title: String {
        switch filter {
        case .all: String(localized: "Tous les éléments")
        case .favorites: String(localized: "Favoris")
        case .passkeys: String(localized: "Passkeys")
        case .nearby: String(localized: "À proximité")
        case .vault(let id): vaultName(id) ?? String(localized: "term.vault")
        case .category(let type): ItemCategory.of(type).plural
        case .tag(let tag): tag
        case .archive: String(localized: "Archive")
        case .trash: String(localized: "Supprimés récemment")
        }
    }

    @ViewBuilder private var emptyState: some View {
        if filter == .nearby, query.isEmpty {
            NearbyStatusView(phase: nearby.phase) { Task { await nearby.load(session) } }
        } else {
            ItemListEmptyState(reason: EmptyListReason(filter: filter, query: query)) {
                model.showNewItemPicker = true
            }
        }
    }
}
#endif
