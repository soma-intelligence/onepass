#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Items of one filter of the Éléments tab (vault, category, tag, Archive, Supprimés récemment),
/// sorted by title, with a search of its own. A row opens the item's detail; swiping an active
/// item moves it to Supprimés récemment (toast, 30 days to restore).
struct CategoryListView: View {
    @Environment(AppModel.self) private var model
    let filter: ItemFilter
    @State private var query = ""

    private var session: VaultSession { model.session }

    var body: some View {
        let items = session.items(filter: filter, query: query, sort: .title)
        let showVault = showsVaultName
        List {
            ForEach(items, id: \.id) { summary in
                let ref = ItemRef(vaultID: summary.vaultId, itemID: summary.id)
                NavigationLink(value: PhoneRoute.item(ref)) {
                    ItemListRow(summary: summary, vaultName: showVault ? vaultName(summary.vaultId) : nil)
                }
                .swipeActions(edge: .trailing) {
                    if summary.trashedAt == nil {
                        Button("Mettre à la corbeille", systemImage: "trash", role: .destructive) {
                            model.trash(ref)
                        }
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
        .overlay {
            if items.isEmpty { emptyState }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.large)
        .searchable(text: $query, placement: .navigationBarDrawer, prompt: Text("Rechercher"))
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Text(ItemListColumn.countLabel(items.count))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize()
            }
            .sharedBackgroundVisibility(.hidden)
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
        case .vault(let id): vaultName(id) ?? String(localized: "Coffre")
        case .category(let type): ItemCategory.of(type).plural
        case .tag(let tag): tag
        case .archive: String(localized: "Archive")
        case .trash: String(localized: "Supprimés récemment")
        }
    }

    private var emptyState: some View {
        ItemListEmptyState(reason: EmptyListReason(filter: filter, query: query)) {
            model.showNewItemPicker = true
        }
    }
}
#endif
