import DesignKit
import SwiftUI
import VaultKit
#if os(macOS)
import AppKit

/// ⌘F on Mac: puts the keyboard focus in the window's toolbar search field.
@MainActor
enum SearchFieldFocus {
    static func focus() {
        guard let window = NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.windows.first(where: \.isVisible),
            let frame = window.contentView?.superview,
            let field = find(in: frame)
        else { return }
        window.makeFirstResponder(field)
    }

    private static func find(in view: NSView) -> NSSearchField? {
        if let field = view as? NSSearchField { return field }
        for sub in view.subviews { if let field = find(in: sub) { return field } }
        return nil
    }
}
#endif

/// Middle column (spec 6.1): items of the sidebar filter, search (⌘F), sort by title or by
/// modification date (then grouped by month, "OCTOBRE 2026"), "Nouvel élément" (⌘N).
struct ItemListColumn: View {
    @Environment(AppModel.self) private var model
    @State private var query = ""
    @FocusState private var searchFocused: Bool
    /// Not secret: the list order only.
    @AppStorage("onepass.browse.sortByDate", store: AppModel.browseDefaults) private var sortByDate = false

    private var session: VaultSession { model.session }
    private var sort: ItemSort { sortByDate ? .updated : .title }

    private var rowSelection: Binding<ItemRef?> {
        Binding(
            get: { model.selectedItem },
            set: { model.perform(.select($0)) })
    }

    var body: some View {
        let items = session.items(filter: model.selection, query: query, sort: sort)
        List(selection: rowSelection) {
            if sortByDate {
                ForEach(Self.months(items)) { month in
                    Section {
                        rows(month.items)
                    } header: {
                        Text(month.title)
                    }
                }
            } else {
                rows(items)
            }
        }
        .focusedValue(\.itemListFocused, true)
        #if os(macOS)
        // Delete key on the focused list (Edit > Supprimer): same as ⌘⌫, never from a text field.
        .onDeleteCommand { model.trashSelection() }
        #endif
        .overlay {
            if items.isEmpty { emptyState }
        }
        // Filter, search or remote reload: a selection no longer listed goes away (M2, M3).
        .onChange(of: items.map(\.id), initial: true) { _, ids in
            model.keepSelection(in: Set(ids))
        }
        .navigationTitle(title)
        #if os(macOS)
        // Mockup `Main`: the list names its filter above the rows; the toolbar keeps search and actions.
        .toolbar(removing: .title)
        .safeAreaInset(edge: .top, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(title).font(.headline).lineLimit(1)
                Text(Self.countLabel(items.count)).font(.subheadline).foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("list.title")
        }
        #else
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .searchable(text: $query, prompt: Text("Rechercher"))
        .searchFocused($searchFocused)
        .onChange(of: model.searchFocusRequest) {
            searchFocused = true
            #if os(macOS)
            // `searchFocused` only works the first time once the focus left the field (macOS 26):
            // the toolbar search field is focused directly.
            SearchFieldFocus.focus()
            #endif
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    NewItemMenu { model.perform(.newItem($0)) }
                } label: {
                    Label("Nouvel élément", systemImage: "plus")
                }
                .help("Nouvel élément (⌘N)")
                .accessibilityIdentifier("items.new")
            }
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Picker("Trier par", selection: $sortByDate) {
                        Text("Titre").tag(false)
                        Text("Date de modification").tag(true)
                    }
                    .pickerStyle(.inline)
                } label: {
                    Label("Trier", systemImage: "arrow.up.arrow.down")
                }
                .accessibilityIdentifier("items.sort")
            }
        }
    }

    @ViewBuilder private func rows(_ items: [FfiItemSummary]) -> some View {
        let showVault = showsVaultName
        ForEach(items, id: \.id) { summary in
            ItemListRow(summary: summary, vaultName: showVault ? vaultName(summary.vaultId) : nil)
                .tag(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
                .contextMenu { contextMenu(summary) }
        }
    }

    @ViewBuilder private func contextMenu(_ summary: FfiItemSummary) -> some View {
        if summary.trashedAt == nil {
            Button(
                summary.favorite ? "Retirer des favoris" : "Ajouter aux favoris",
                systemImage: summary.favorite ? "star.slash" : "star"
            ) {
                Task {
                    try? await session.setFavorite(!summary.favorite, itemID: summary.id, vaultID: summary.vaultId)
                }
            }
            Divider()
            Button("Mettre à la corbeille", systemImage: "trash", role: .destructive) {
                model.trash(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
            }
            .disabled(model.isEditing && model.selectedItem == ItemRef(vaultID: summary.vaultId, itemID: summary.id))
        }
    }

    // MARK: - Labels

    /// The vault name is shown when the list mixes vaults and there is more than one vault.
    private var showsVaultName: Bool {
        if case .vault = model.selection { return false }
        return session.vaults.count > 1
    }

    private func vaultName(_ id: String) -> String? {
        session.allVaults.first { $0.id == id }?.meta.name
    }

    private var title: String {
        switch model.selection {
        case .all: String(localized: "Tous les éléments")
        case .favorites: String(localized: "Favoris")
        case .vault(let id): vaultName(id) ?? String(localized: "Coffre")
        case .category(let type): ItemCategory.of(type).plural
        case .tag(let tag): String(localized: "Tag : \(tag)")
        case .archive: String(localized: "Archive")
        case .trash: String(localized: "Supprimés récemment")
        }
    }

    static func countLabel(_ count: Int) -> String {
        count == 1 ? String(localized: "1 élément") : String(localized: "\(count) éléments")
    }

    @ViewBuilder private var emptyState: some View {
        let message: String =
            if !query.trimmingCharacters(in: .whitespaces).isEmpty {
                String(localized: "Essaie avec d'autres mots.")
            } else if model.selection == .trash {
                String(localized: "Les éléments mis à la corbeille restent ici 30 jours.")
            } else if model.selection == .archive {
                String(localized: "Les éléments archivés apparaîtront ici.")
            } else {
                String(localized: "Crée un élément avec « Nouvel élément ».")
            }
        EmptyState(title: String(localized: "Aucun élément ne correspond."), systemImage: "magnifyingglass", message: message)
    }

    // MARK: - Months

    struct Month: Identifiable {
        let id: String
        let title: String
        var items: [FfiItemSummary]
    }

    /// Consecutive months of a list sorted by date, newest first: "OCTOBRE 2026".
    static func months(_ items: [FfiItemSummary], calendar: Calendar = .current) -> [Month] {
        var result: [Month] = []
        for item in items {
            let date = Date(timeIntervalSince1970: TimeInterval(item.updatedAt))
            let parts = calendar.dateComponents([.year, .month], from: date)
            let id = "\(parts.year ?? 0)-\(parts.month ?? 0)"
            if result.last?.id == id {
                result[result.count - 1].items.append(item)
            } else {
                let title = date.formatted(.dateTime.month(.wide).year().locale(Locale(identifier: "fr_FR")))
                result.append(Month(id: id, title: title.uppercased(with: Locale(identifier: "fr_FR")), items: [item]))
            }
        }
        return result
    }
}
