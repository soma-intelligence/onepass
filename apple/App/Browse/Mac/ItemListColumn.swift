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
    /// "À proximité": rows come from the position and the session's location index.
    @State private var nearby = NearbyLoader()
    /// "Toutes les catégories" dropdown: one item type within the sidebar filter (nil: every type).
    @State private var categoryFilter: FfiItemType?
    @State private var choosingCategory = false
    /// Mac: the search field under the header, shown or hidden by its icon (⌘F always shows it).
    @AppStorage("onepass.browse.searchShown", store: AppModel.browseDefaults) private var searchShown = true

    private var session: VaultSession { model.session }
    private var sort: ItemSort { sortByDate ? .updated : .title }

    private var rowSelection: Binding<ItemRef?> {
        Binding(
            get: { model.selectedItem },
            set: { model.perform(.select($0)) })
    }

    private var isNearby: Bool { model.selection == .nearby }

    /// The rows: the filter's items, or "À proximité" closest first (searchable, never by month),
    /// then the type chosen in the dropdown.
    private var listedItems: [FfiItemSummary] {
        // A Watchtower card ("Voir les éléments") narrows the list to its flagged items.
        let items = model.applyWatchtowerFilter(
            isNearby ? ItemSearch.filter(nearby.summaries, query: query)
                : session.items(filter: model.selection, query: query, sort: sort))
        guard let type = categoryFilter, !isCategorySelection else { return items }
        return items.filter { $0.itemType == type }
    }

    /// The sidebar (or a command) chose a type itself: the dropdown shows it.
    private var isCategorySelection: Bool {
        if case .category = model.selection { return true }
        return false
    }

    /// The type the dropdown shows: the sidebar's own type filter, else the dropdown's choice.
    private var shownCategory: FfiItemType? {
        if case .category(let type) = model.selection { return type }
        return categoryFilter
    }

    /// Types present in the sidebar filter, with their counts (search ignored), for the dropdown.
    private var presentTypes: [(type: FfiItemType, count: Int)] {
        let filter: ItemFilter = isCategorySelection ? .all : model.selection
        let base = isNearby ? nearby.summaries : session.items(filter: filter, query: "", sort: .title)
        var counts: [FfiItemType: Int] = [:]
        for item in base { counts[item.itemType, default: 0] += 1 }
        return ItemCategory.all.compactMap { category in
            counts[category.type].map { (category.type, $0) }
        }
    }

    var body: some View {
        let items = listedItems
        List(selection: rowSelection) {
            if sortByDate, !isNearby {
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
            if !items.isEmpty {
                // The count at the end of the list, centered (not a selectable row).
                Text(Self.countLabel(items.count))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 10)
                    .selectionDisabled()
                    .listRowSeparator(.hidden)
                    .accessibilityIdentifier("list.count")
            }
        }
        // A new sidebar filter starts on every type again.
        .onChange(of: model.selection) { categoryFilter = nil }
        .focusedValue(\.itemListFocused, true)
        #if os(macOS)
        // Delete key on the focused list (Edit > Supprimer): same as ⌘⌫, never from a text field.
        .onDeleteCommand { model.trashSelection() }
        #endif
        .overlay {
            if items.isEmpty { emptyState }
        }
        // Asked when "À proximité" opens (the permission prompt comes from here, never at launch),
        // then again whenever the items change.
        .task(id: NearbyRequest(active: isNearby, revision: session.summariesRevision)) {
            guard isNearby else { return }
            await nearby.load(session)
        }
        // Filter, search or remote reload: a selection no longer listed goes away (M2, M3).
        .onChange(of: items.map(\.id), initial: true) { _, ids in
            model.keepSelection(in: Set(ids))
        }
        .navigationTitle(model.watchtowerFilter?.title ?? title)
        #if os(macOS)
        // Mockup `Main`: the list names its filter above the rows; the toolbar keeps search and actions.
        .toolbar(removing: .title)
        // Search on top of its list (the detail column keeps its own actions on the right), then
        // the filter's name. On a bar material: rows scrolling up pass under it, never through it
        // (the list has no background of its own any more).
        .safeAreaInset(edge: .top, spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    categoryPill
                    Spacer(minLength: 4)
                    Button {
                        withAnimation(.snappy) { searchShown.toggle() }
                        if searchShown { searchFocused = true } else { query = "" }
                    } label: {
                        Image(systemName: "magnifyingglass")
                            .frame(width: 26, height: 26)
                            .contentShape(.rect)
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(searchShown ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.secondary))
                    .help("Rechercher (⌘F)")
                    .accessibilityIdentifier("items.searchToggle")
                    sortMenu
                }
                if searchShown { searchField }
            }
            .padding(.horizontal, 14)
            .padding(.top, 6)
            .padding(.bottom, 8)
            .background(.bar)
            .overlay(alignment: .bottom) { Divider().opacity(0.5) }
        }
        #else
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .scrollContentBackground(.hidden)
        // Rows inserted after the first layout (sync, seeding) kept the table's short default
        // height and came out clipped: every row is two lines, so the table gets that height.
        .environment(\.defaultMinListRowHeight, 52)
        #if os(macOS)
        .onChange(of: model.searchFocusRequest) {
            searchShown = true
            searchFocused = true
        }
        #else
        .searchable(text: $query, prompt: Text("Rechercher"))
        .searchFocused($searchFocused)
        .onChange(of: model.searchFocusRequest) { searchFocused = true }
        #endif
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                // The add sheet (common types first, search, every category, import), like ⌘N.
                Button {
                    model.showNewItemPicker = true
                } label: {
                    Label("Nouvel élément", systemImage: "plus")
                }
                .help("Nouvel élément (⌘N)")
                .accessibilityIdentifier("items.new")
            }
            #if !os(macOS)
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
            #endif
        }
    }

    #if os(macOS)
    /// "Toutes les catégories ⌄": a pill with the current type's tile, filled with the accent once a
    /// type is chosen. Opens the types present in the filter, common ones first.
    private var categoryPill: some View {
        let current = shownCategory.map(ItemCategory.of)
        return Button {
            choosingCategory.toggle()
        } label: {
            HStack(spacing: 7) {
                if let current {
                    CategoryTile(category: current, size: 18)
                } else {
                    Image(systemName: "square.grid.2x2").font(.system(size: 12, weight: .semibold))
                }
                Text(current?.plural ?? String(localized: "Toutes les catégories"))
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                Image(systemName: "chevron.down").font(.system(size: 9, weight: .bold))
            }
            .foregroundStyle(current == nil ? AnyShapeStyle(.primary) : AnyShapeStyle(.white))
            .padding(.leading, current == nil ? 10 : 5)
            .padding(.trailing, 10)
            .padding(.vertical, 5)
            .background(current == nil ? AnyShapeStyle(.fill.tertiary) : AnyShapeStyle(Theme.accent.opacity(0.9)),
                in: Capsule())
            .overlay { Capsule().strokeBorder(.white.opacity(0.08)) }
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text(current?.plural ?? String(localized: "Toutes les catégories")))
        .accessibilityIdentifier("list.title")
        .popover(isPresented: $choosingCategory, arrowEdge: .bottom) {
            CategoryFilterPopover(types: presentTypes, current: shownCategory) { type in
                choosingCategory = false
                if isCategorySelection {
                    model.selection = .all
                    model.page = .items
                }
                // After the selection change resets it.
                DispatchQueue.main.async { categoryFilter = type }
            }
        }
    }

    private var sortMenu: some View {
        Menu {
            Picker("Trier par", selection: $sortByDate) {
                Text("Titre").tag(false)
                Text("Date de modification").tag(true)
            }
            .pickerStyle(.inline)
        } label: {
            Image(systemName: "arrow.up.arrow.down")
        }
        .menuStyle(.button)
        .buttonStyle(.borderless)
        .menuIndicator(.hidden)
        .fixedSize()
        .foregroundStyle(.secondary)
        .help("Trier")
        .accessibilityIdentifier("items.sort")
    }

    /// The list's own search field (⌘F), above the rows. Escape clears it.
    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Rechercher", text: $query, prompt: Text("Rechercher"))
                .textFieldStyle(.plain)
                .focused($searchFocused)
                .onExitCommand { query = ""; searchFocused = false }
                .accessibilityIdentifier("items.search")
            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text("Effacer la recherche"))
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(.fill.quaternary, in: .rect(cornerRadius: 9))
        .overlay {
            RoundedRectangle(cornerRadius: 9)
                .strokeBorder(searchFocused ? AnyShapeStyle(Theme.accent.opacity(0.8)) : AnyShapeStyle(.white.opacity(0.06)))
        }
    }
    #endif

    @ViewBuilder private func rows(_ items: [FfiItemSummary]) -> some View {
        let showVault = showsVaultName
        ForEach(items, id: \.id) { summary in
            ItemListRow(summary: summary, vaultName: showVault ? vaultName(summary.vaultId) : nil)
                .tag(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
                .contextMenu { contextMenu(summary) }
                .visionHoverEffect()
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
        case .nearby: String(localized: "À proximité")
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
        if isNearby, query.isEmpty {
            NearbyStatusView(phase: nearby.phase) { Task { await nearby.load(session) } }
        } else {
            ItemListEmptyState(reason: EmptyListReason(filter: model.selection, query: query)) {
                model.showNewItemPicker = true
            }
        }
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

/// Empty item list: "Aucun élément ne correspond." only for a search; an empty scope says so and,
/// where items can be created, offers "Nouvel élément" (Mac, iPad and iPhone lists).
struct ItemListEmptyState: View {
    let reason: EmptyListReason
    let newItem: () -> Void

    var body: some View {
        switch reason {
        case .noMatch:
            EmptyState(
                title: String(localized: "Aucun élément ne correspond."), systemImage: "magnifyingglass",
                message: String(localized: "Essaie avec d'autres mots."))
            .accessibilityIdentifier("list.empty.search")
        case .emptyLibrary:
            EmptyState(
                title: String(localized: "Ce coffre est vide"), systemImage: "tray",
                message: String(localized: "Crée ton premier élément : un identifiant, une carte, une note..."),
                actionTitle: String(localized: "Nouvel élément"), actionIdentifier: "list.empty.newItem",
                action: newItem)
            .accessibilityIdentifier("list.empty.library")
        case .emptyCategory:
            EmptyState(
                title: String(localized: "Aucun élément dans cette catégorie"), systemImage: "square.grid.2x2",
                message: String(localized: "Les éléments de ce type apparaîtront ici."),
                actionTitle: String(localized: "Nouvel élément"), actionIdentifier: "list.empty.newItem",
                action: newItem)
        case .emptyTag:
            EmptyState(
                title: String(localized: "Aucun élément avec ce tag"), systemImage: "tag",
                message: String(localized: "Ajoute ce tag à un élément pour le retrouver ici."))
        case .noNearby:
            EmptyState(
                title: String(localized: "Rien à proximité"), systemImage: "mappin.slash",
                message: String(localized: "Ajoute un lieu à un élément pour le retrouver ici quand tu es à moins de 2 km."))
        case .noFavorites:
            EmptyState(
                title: String(localized: "Aucun favori"), systemImage: "star",
                message: String(localized: "Marque un élément comme favori pour le retrouver ici."))
        case .emptyArchive:
            EmptyState(
                title: String(localized: "Archive vide"), systemImage: "archivebox",
                message: String(localized: "Les éléments archivés apparaîtront ici."))
        case .emptyTrash:
            EmptyState(
                title: String(localized: "Corbeille vide"), systemImage: "trash",
                message: String(localized: "Les éléments mis à la corbeille restent ici 30 jours."))
        }
    }
}

/// Identity of the "À proximité" request: reloads when the filter opens and when the items change.
struct NearbyRequest: Equatable {
    var active: Bool
    var revision: Int
}

#if os(macOS)
/// The dropdown of "Toutes les catégories": every type, then the common types present, a divider,
/// the other types present. A check marks the current one.
private struct CategoryFilterPopover: View {
    let types: [(type: FfiItemType, count: Int)]
    let current: FfiItemType?
    let pick: (FfiItemType?) -> Void

    var body: some View {
        let common = types.filter { NewItemSheet.featured.contains($0.type) }
        let others = types.filter { !NewItemSheet.featured.contains($0.type) }
        ScrollView {
            VStack(alignment: .leading, spacing: 1) {
                CategoryFilterRow(category: nil, count: types.reduce(0) { $0 + $1.count }, checked: current == nil) {
                    pick(nil)
                }
                .accessibilityIdentifier("list.category.all")
                if !common.isEmpty {
                    Divider().padding(.vertical, 4).padding(.horizontal, 6)
                    ForEach(common, id: \.type) { entry in row(entry) }
                }
                if !others.isEmpty {
                    Divider().padding(.vertical, 4).padding(.horizontal, 6)
                    ForEach(others, id: \.type) { entry in row(entry) }
                }
            }
            .padding(6)
        }
        .frame(width: 260)
        .frame(maxHeight: 460)
        .fixedSize(horizontal: false, vertical: true)
    }

    private func row(_ entry: (type: FfiItemType, count: Int)) -> some View {
        CategoryFilterRow(category: ItemCategory.of(entry.type), count: entry.count, checked: current == entry.type) {
            pick(entry.type)
        }
        .accessibilityIdentifier("list.category.\(NewItemMenu.key(entry.type))")
    }
}

private struct CategoryFilterRow: View {
    let category: ItemCategory?
    let count: Int
    let checked: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: "checkmark")
                    .font(.system(size: 11, weight: .bold))
                    .frame(width: 12)
                    .opacity(checked ? 1 : 0)
                if let category {
                    CategoryTile(category: category, size: 20)
                } else {
                    Image(systemName: "square.grid.2x2")
                        .font(.system(size: 12, weight: .semibold))
                        .frame(width: 20, height: 20)
                }
                Text(category?.plural ?? String(localized: "Toutes les catégories")).lineLimit(1)
                Spacer(minLength: 8)
                Text("\(count)")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(hovering ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.tertiary))
            }
            .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .padding(.horizontal, 6)
            .padding(.vertical, 5)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.85)) : AnyShapeStyle(.clear), in: .rect(cornerRadius: 7))
            .contentShape(.rect(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
#endif
