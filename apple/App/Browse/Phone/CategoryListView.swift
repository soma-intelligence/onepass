#if os(iOS)
import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// Items of one filter of the Éléments tab (vault, category, tag, Archive, Supprimés récemment)
/// sorted by title, or of "À proximité" (closest first, the distance in the subtitle), with a search
/// of its own. A row opens the item's detail. Swiping an active item from the right: Archive first
/// (a full swipe archives), then Supprimer (to Supprimés récemment, toast with Undo, 30 days to restore); an archived
/// item offers Désarchiver.
///
/// RX look (Penpot "RX · All Items v2"): a header with the rolling count, the composition strip
/// (one segment per type) and the quick chips (sort, Favoris, one vault, one type), then sections by
/// letter (sorted by title, with the native section index) or by month (sorted by modification), each
/// in an RX card with the Home row. Swipes, context menu, search and "Nouvel élément" are the same.
struct CategoryListView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let filter: ItemFilter
    @State private var query = ""
    /// "À proximité": rows from the position and the session's location index, closest first.
    @State private var nearby = NearbyLoader()
    /// The RX look (Réglages > Général > Nouveau design).
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    /// RX: the list order, shared with the Mac and iPad list (not secret).
    @AppStorage("onepass.browse.sortByDate", store: AppModel.browseDefaults) private var sortByDate = false
    /// RX: the quick chips of this list (reset when the list closes).
    @State private var chips = RXListChips()

    private var session: VaultSession { model.session }

    var body: some View {
        if rxDesign {
            rxBody
        } else {
            classicBody
        }
    }

    private var classicBody: some View {
        let items = filter == .nearby
            ? ItemSearch.filter(nearby.summaries, query: query) : session.items(filter: filter, query: query, sort: .title)
        let showVault = showsVaultName
        return List {
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
                PhoneItemLink(ref: ref) {
                    ItemListRow(summary: summary, vaultName: showVault ? vaultName(summary.vaultId) : nil)
                }
                .itemZoomSource(ref)
                .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                    if summary.trashedAt == nil {
                        // The first button is the one a full swipe runs: Archive, never the trash.
                        archiveButton(summary, ref: ref)
                            .tint(.indigo)
                        trashButton(ref)
                            // The list's accent tint would paint it like Archive.
                            .tint(.red)
                    }
                }
                .swipeActions(edge: .leading) {
                    if summary.trashedAt == nil {
                        favoriteButton(summary)
                            .tint(.orange)
                    }
                }
                // The same actions without a swipe (long press, pointer, VoiceOver actions).
                .contextMenu {
                    if summary.trashedAt == nil {
                        favoriteButton(summary)
                        archiveButton(summary, ref: ref)
                        Divider()
                        trashButton(ref)
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

    // MARK: - RX look

    private typealias RX = Theme.RX

    /// The list before the chips: the filter (or "À proximité"), the search and the order.
    private var baseItems: [FfiItemSummary] {
        filter == .nearby
            ? ItemSearch.filter(nearby.summaries, query: query)
            : session.items(filter: filter, query: query, sort: sortByDate ? .updated : .title)
    }

    private var rxBody: some View {
        let base = baseItems
        let items = chips.apply(base)
        let byDate = sortByDate && filter != .nearby
        let sections = RXListSection.make(items, byDate: byDate, nearby: filter == .nearby)
        let showVault = showsVaultName
        return List {
            Section {
                rxHeader(base: base, shown: items.count)
                    .listRowInsets(EdgeInsets(top: 0, leading: RX.Space.gutter, bottom: RX.Space.s, trailing: 0))
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
            .listSectionSeparator(.hidden)
            if filter == .category(.cryptoWallet), query.isEmpty, !items.isEmpty {
                Section {
                    NavigationLink(value: PhoneRoute.crypto) {
                        RXMenuRow(Text("crypto.category.link"), systemImage: "chart.line.uptrend.xyaxis", chevron: false)
                    }
                    .routeZoomSource(.crypto)
                    .accessibilityIdentifier("category.crypto.open")
                    .rxCardRow(first: true, last: true)
                }
                .listSectionSeparator(.hidden)
            }
            if items.isEmpty {
                rxEmptyState(base: base)
                    .frame(maxWidth: .infinity, minHeight: 360)
                    .listRowBackground(Color.clear)
                    .listRowSeparator(.hidden)
            }
            ForEach(sections) { section in
                Section {
                    ForEach(Array(section.items.enumerated()), id: \.element.id) { index, summary in
                        rxRow(summary, showVault: showVault, byDate: byDate)
                            .rxCardRow(first: index == 0, last: index == section.items.count - 1)
                    }
                } header: {
                    if let title = section.title {
                        RXSectionTitle(Text(verbatim: title))
                            .padding(.leading, RX.Space.gutter - RX.Space.xs)
                            .accessibilityIdentifier("rx.list.section.\(section.id)")
                    }
                }
                .sectionIndexLabel(byDate || section.title == nil ? nil : Text(verbatim: section.id))
                .listSectionSeparator(.hidden)
            }
        }
        .listStyle(.plain)
        .listSectionIndexVisibility(byDate || filter == .nearby ? .hidden : .visible)
        .environment(\.defaultMinListRowHeight, 0)
        // A row trashed, restored or favorited, a chip or the order changed: the list closes or
        // opens the gap.
        .animation(Motion.list(reduceMotion: reduceMotion), value: session.summariesRevision)
        .animation(Motion.list(reduceMotion: reduceMotion), value: chips)
        .animation(Motion.list(reduceMotion: reduceMotion), value: sortByDate)
        .scrollContentBackground(.hidden)
        .background(RX.Palette.pageBackground.color.ignoresSafeArea())
        .task(id: NearbyRequest(active: filter == .nearby, revision: session.summariesRevision)) {
            guard filter == .nearby else { return }
            await nearby.load(session)
        }
        // A chip whose vault or type left the list (moved, trashed) clears itself.
        .onChange(of: session.summariesRevision) { chips = chips.kept(in: base) }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.large)
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always), prompt: Text("common.search"))
        .toolbar {
            if filter != .trash, filter != .nearby {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Nouvel élément", systemImage: "plus") { addItem() }
                        .accessibilityIdentifier("categoryList.new")
                }
            }
        }
        .accessibilityIdentifier("rx.list")
    }

    /// The count (rolling digits), the composition strip (signature) and the chips.
    private func rxHeader(base: [FfiItemSummary], shown: Int) -> some View {
        let strip = chips.composition(base)
        return VStack(alignment: .leading, spacing: RX.Space.m) {
            Text(ItemListColumn.countLabel(shown))
                .rxFont(.title)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .dbRollingNumber(value: Double(shown))
                .dbText(maxLines: 2)
                .padding(.trailing, RX.Space.gutter)
                .accessibilityIdentifier("rx.list.count")
            if strip.count > 1 {
                RXCompositionStrip(strip, focus: chips.type.map(NewItemMenu.key))
                    .padding(.trailing, RX.Space.gutter)
            }
            rxChips(base: base)
        }
        .padding(.top, RX.Space.xs)
    }

    /// One row of quiet controls, scrolled sideways: the order first, then the filters. No menu:
    /// each chip is one tap, a second tap clears it.
    private func rxChips(base: [FfiItemSummary]) -> some View {
        let types = chips.types(base)
        let vaults = showsVaultName ? session.vaults.filter { vault in base.contains { $0.vaultId == vault.id } } : []
        let favorites = filter != .favorites && (chips.favorites || base.contains(where: \.favorite))
        return ScrollView(.horizontal) {
            HStack(spacing: RX.Space.s) {
                if filter != .nearby {
                    Button { sortByDate.toggle() } label: {
                        RXChip(sortByDate ? Text("item.modified") : Text("app.title"), selected: false) {
                            Image(systemName: "arrow.up.arrow.down")
                                .font(RX.Glyph.font(RX.Glyph.chevron, weight: .bold))
                                .accessibilityHidden(true)
                        }
                    }
                    .rxPress(haptic: .selection)
                    .accessibilityLabel(Text("browse.sort"))
                    .accessibilityValue(sortByDate ? Text("item.modified") : Text("app.title"))
                    .accessibilityIdentifier("rx.list.sort")
                }
                if favorites {
                    Button { chips.favorites.toggle() } label: {
                        RXChip(Text("Favoris"), selected: chips.favorites) {
                            Image(systemName: "star.fill")
                                .font(RX.Glyph.font(RX.Glyph.chevron))
                                .foregroundStyle(chips.favorites ? RX.Palette.onAccent.color : RXListChips.amber)
                                .accessibilityHidden(true)
                        }
                    }
                    .rxPress(haptic: .selection)
                    .accessibilityIdentifier("rx.list.chip.favorites")
                }
                if vaults.count > 1 {
                    ForEach(vaults, id: \.id) { vault in
                        Button { chips.vaultID = chips.vaultID == vault.id ? nil : vault.id } label: {
                            RXChip(Text(vault.meta.name), selected: chips.vaultID == vault.id) {
                                VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 20)
                                    .accessibilityHidden(true)
                            }
                        }
                        .rxPress(haptic: .selection)
                        .accessibilityIdentifier("rx.list.chip.vault.\(vault.id)")
                    }
                }
                if types.count > 1 {
                    ForEach(types, id: \.self) { type in
                        let category = ItemCategory.of(type)
                        Button { chips.type = chips.type == type ? nil : type } label: {
                            RXChip(Text(category.plural), selected: chips.type == type) {
                                CategoryTile(category: category, size: 20)
                            }
                        }
                        .rxPress(haptic: .selection)
                        .accessibilityIdentifier("rx.list.chip.type.\(NewItemMenu.key(type))")
                    }
                }
            }
            .padding(.trailing, RX.Space.gutter)
            .padding(.vertical, RX.Space.xxs)
        }
        .scrollIndicators(.hidden)
        .scrollClipDisabled()
    }

    /// An item row in the RX look, with the classic actions.
    private func rxRow(_ summary: FfiItemSummary, showVault: Bool, byDate: Bool) -> some View {
        let ref = ItemRef(vaultID: summary.vaultId, itemID: summary.id)
        // By date: when it changed. By title the row stays clean (the vault chips sort by vault);
        // VoiceOver still hears the vault when the list mixes them.
        let value: Text? = byDate
            ? Text(Date(timeIntervalSince1970: TimeInterval(summary.updatedAt)), format: .relative(presentation: .numeric, unitsStyle: .abbreviated))
            : nil
        let vault = showVault ? vaultName(summary.vaultId) : nil
        return PhoneItemLink(ref: ref) {
            RXListRow(summary: summary, value: value, vaultName: vault)
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
            if summary.trashedAt == nil {
                archiveButton(summary, ref: ref)
                    .tint(.indigo)
                trashButton(ref)
                    .tint(.red)
            }
        }
        .swipeActions(edge: .leading) {
            if summary.trashedAt == nil {
                favoriteButton(summary)
                    .tint(.orange)
            }
        }
        .contextMenu {
            if summary.trashedAt == nil {
                favoriteButton(summary)
                archiveButton(summary, ref: ref)
                Divider()
                trashButton(ref)
            }
        }
    }

    /// Why the RX list is empty, with the one action that fills it again (UX-STATE-04): the chips
    /// hide everything (clear them), a search finds nothing (clear it), an empty scope (new item).
    /// Scopes nothing can be created in keep their words without an action.
    @ViewBuilder private func rxEmptyState(base: [FfiItemSummary]) -> some View {
        let reason = EmptyListReason(filter: filter, query: query)
        if !base.isEmpty, chips.isActive {
            let clear = $chips
            DBEmptyView(DBEmptyState(
                String(localized: "rx.list.filtered.empty"), systemImage: "line.3.horizontal.decrease.circle",
                message: String(localized: "rx.list.filtered.empty.message"),
                actionTitle: String(localized: "rx.list.filters.clear")) { clear.wrappedValue = RXListChips() })
            .accessibilityIdentifier("rx.list.empty.filtered")
        } else if filter == .nearby, query.isEmpty {
            NearbyStatusView(phase: nearby.phase) { Task { await nearby.load(session) } }
        } else if reason == .noMatch {
            let search = $query
            DBEmptyView(DBEmptyState(
                String(localized: "browse.noMatchingItems"), systemImage: "magnifyingglass",
                message: String(localized: "browse.tryOtherWords"),
                actionTitle: String(localized: "browse.clearSearch")) { search.wrappedValue = "" })
            .accessibilityIdentifier("list.empty.search")
        } else if reason.offersNewItem {
            let model = model
            DBEmptyView(DBEmptyState(
                reason == .emptyLibrary ? String(localized: "browse.vaultEmpty") : String(localized: "browse.noItemsInCategory"),
                systemImage: reason == .emptyLibrary ? "tray" : "square.grid.2x2",
                message: reason == .emptyLibrary ? String(localized: "browse.createFirstItemLogin") : String(localized: "browse.itemsOfTypeWill"),
                actionTitle: String(localized: "Nouvel élément")) { model.showNewItemPicker = true })
            .accessibilityIdentifier(reason == .emptyLibrary ? "list.empty.library" : "list.empty.category")
        } else {
            ItemListEmptyState(reason: reason) { model.showNewItemPicker = true }
        }
    }

    // MARK: - Row actions (swipe and context menu)

    @ViewBuilder private func archiveButton(_ summary: FfiItemSummary, ref: ItemRef) -> some View {
        if summary.archived {
            Button("app.unarchive", systemImage: "archivebox") { model.unarchive(ref) }
                .accessibilityIdentifier("list.swipe.unarchive")
        } else {
            Button("common.archive", systemImage: "archivebox") { model.archive(ref) }
                .accessibilityIdentifier("list.swipe.archive")
        }
    }

    /// Goes to Supprimés récemment (toast with Undo): named "Supprimer" as in the item menu.
    private func trashButton(_ ref: ItemRef) -> some View {
        Button("common.delete", systemImage: "trash", role: .destructive) { model.trash(ref) }
            .accessibilityIdentifier("list.swipe.trash")
    }

    private func favoriteButton(_ summary: FfiItemSummary) -> some View {
        Button(
            summary.favorite ? "Retirer des favoris" : "Ajouter aux favoris",
            systemImage: summary.favorite ? "star.slash" : "star.fill"
        ) {
            toggleFavorite(summary)
        }
        .accessibilityIdentifier("list.swipe.favorite")
    }

    /// A failure says so in a toast (never silent).
    private func toggleFavorite(_ summary: FfiItemSummary) {
        let favorite = !summary.favorite
        Task {
            do {
                try await session.setFavorite(favorite, itemID: summary.id, vaultID: summary.vaultId)
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
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
// MARK: - RX pieces

/// The quick chips of the RX list: favourites only, one vault, one type. Each narrows the list;
/// none is a menu.
struct RXListChips: Equatable {
    var favorites = false
    var vaultID: String?
    var type: FfiItemType?

    static let amber = Color(red: 0xF5 / 255, green: 0xA6 / 255, blue: 0x23 / 255)

    var isActive: Bool { favorites || vaultID != nil || type != nil }

    /// Everything but the type: the strip and the type chips count from here.
    private func applyingScope(_ items: [FfiItemSummary]) -> [FfiItemSummary] {
        items.filter { item in
            (!favorites || item.favorite) && (vaultID == nil || item.vaultId == vaultID)
        }
    }

    func apply(_ items: [FfiItemSummary]) -> [FfiItemSummary] {
        let scoped = applyingScope(items)
        guard let type else { return scoped }
        return scoped.filter { $0.itemType == type }
    }

    /// The types of the list, most items first (then the catalogue order).
    func types(_ items: [FfiItemSummary]) -> [FfiItemType] {
        let counts = Dictionary(grouping: applyingScope(items), by: \.itemType).mapValues(\.count)
        let order = ItemCategory.all.map(\.type)
        return counts.keys.sorted { a, b in
            let (ca, cb) = (counts[a] ?? 0, counts[b] ?? 0)
            if ca != cb { return ca > cb }
            return (order.firstIndex(of: a) ?? 0) < (order.firstIndex(of: b) ?? 0)
        }
    }

    /// One segment per type, in its tile colour, in the chips' order.
    func composition(_ items: [FfiItemSummary]) -> [RXCompositionStrip.Segment] {
        let counts = Dictionary(grouping: applyingScope(items), by: \.itemType).mapValues(\.count)
        return types(items).map { type in
            RXCompositionStrip.Segment(id: NewItemMenu.key(type), count: counts[type] ?? 0, color: ItemCategory.of(type).color)
        }
    }

    /// A chip whose vault or type is no longer in the list lets go.
    func kept(in items: [FfiItemSummary]) -> RXListChips {
        var chips = self
        if let vaultID, !items.contains(where: { $0.vaultId == vaultID }) { chips.vaultID = nil }
        if let type, !items.contains(where: { $0.itemType == type }) { chips.type = nil }
        return chips
    }
}

/// A section of the RX list: a letter (sorted by title), a month (sorted by modification), or
/// one untitled section ("À proximité", closest first).
struct RXListSection: Identifiable {
    let id: String
    let title: String?
    var items: [FfiItemSummary]

    static func make(_ items: [FfiItemSummary], byDate: Bool, nearby: Bool, calendar: Calendar = .current) -> [RXListSection] {
        guard !items.isEmpty else { return [] }
        if nearby { return [RXListSection(id: "nearby", title: nil, items: items)] }
        var result: [RXListSection] = []
        var index: [String: Int] = [:]
        for item in items {
            let key: String
            let title: String
            if byDate {
                let date = Date(timeIntervalSince1970: TimeInterval(item.updatedAt))
                let parts = calendar.dateComponents([.year, .month], from: date)
                key = "\(parts.year ?? 0)-\(parts.month ?? 0)"
                let month = date.formatted(.dateTime.month(.wide).year())
                title = month.prefix(1).uppercased() + month.dropFirst()
            } else {
                key = letter(of: item.title)
                title = key
            }
            if let at = index[key] {
                result[at].items.append(item)
            } else {
                index[key] = result.count
                result.append(RXListSection(id: key, title: title, items: [item]))
            }
        }
        return result
    }

    /// The first letter of a title without its accent ("É" files under "E"); "#" for the rest.
    static func letter(of title: String) -> String {
        guard let first = title.trimmingCharacters(in: .whitespacesAndNewlines).first else { return "#" }
        let folded = String(first).folding(options: [.diacriticInsensitive, .caseInsensitive], locale: .current).uppercased()
        guard let scalar = folded.unicodeScalars.first, CharacterSet.letters.contains(scalar) else { return "#" }
        return folded
    }
}

/// An item row of the RX list: the Home row (`RXItemRow`) with the list row's icon, star, second
/// line and identifiers (`list.row.<title>`, `list.row.icon.custom`), so tests and VoiceOver read
/// it the same in both looks.
struct RXListRow: View {
    @Environment(AppModel.self) private var model
    let summary: FfiItemSummary
    let value: Text?
    /// Read by VoiceOver when the list mixes vaults (the row itself stays clean).
    var vaultName: String?
    @State private var resolved: ResolvedIcon?

    private static let iconSize: CGFloat = 40

    private var taskID: ItemIconTaskID { ItemIconTaskID(summary, epoch: model.iconEpoch) }
    private var showsCustomIcon: Bool { model.iconLoader.chosenIcon(CustomIconKey(summary)) != nil }

    /// A login with no username that signs in with a provider: "Se connecte avec GitHub".
    private var secondLine: String {
        if summary.subtitle.isEmpty, let provider = summary.signInProvider {
            return String(localized: "browse.signsInWith \(LoginProvider.displayName(provider))")
        }
        return summary.listSubtitle.isEmpty ? ItemCategory.of(summary.itemType).singular : summary.listSubtitle
    }

    /// Travel Mode per item, before the value: what leaves or locks harder while travelling.
    private var trailing: Text? {
        guard summary.travelHidden || summary.travelGuard else { return value }
        let mark = Text(Image(systemName: summary.travelHidden ? "airplane" : "lock.shield"))
        return value.map { mark + Text(verbatim: " ") + $0 } ?? mark
    }

    var body: some View {
        RXItemRow(title: Text(summary.title), subtitle: Text(secondLine), value: trailing,
                  valueColor: Theme.RX.Palette.textSecondary.color) {
            ItemIcon(
                type: summary.itemType, title: summary.title, siteIcon: model.iconLoader.shownIcon(taskID, resolved: resolved),
                size: Self.iconSize, brand: summary.cardBrand, useCategory: summary.usesCategoryIcon,
                tint: ItemTint.color(named: summary.color), domain: ItemIconResolver.registrableDomain(summary.primaryUrl))
                .accessibilityIdentifier(showsCustomIcon ? "list.row.icon.custom" : "")
                .favoriteBadge(summary.favorite, iconSize: Self.iconSize)
        }
        .accessibilityValue(accessibilityValue)
        .accessibilityIdentifier("list.row.\(summary.title)")
        .task(id: taskID) {
            let id = taskID
            resolved = ResolvedIcon(id: id, data: await model.iconLoader.icon(for: id.url, title: id.title, custom: id.custom))
        }
    }

    private var accessibilityValue: Text {
        let vault = Text(verbatim: vaultName ?? "")
        guard showsCustomIcon else { return vault }
        return vaultName == nil ? Text("list.row.customIcon") : vault + Text(verbatim: ", ") + Text("list.row.customIcon")
    }
}

extension View {
    /// A row of an RX card inside a plain list: the card colour behind it, the card's corners on
    /// the first and last rows, the page gutter on both sides, no rule between rows.
    func rxCardRow(first: Bool, last: Bool) -> some View {
        let radius = Theme.RX.Radius.card
        return listRowInsets(EdgeInsets(
            top: first ? Theme.RX.Space.s : 0, leading: Theme.RX.Space.gutter,
            bottom: last ? Theme.RX.Space.s : 0, trailing: Theme.RX.Space.gutter + Theme.RX.Space.s))
            .listRowSeparator(.hidden)
            .listRowBackground(
                UnevenRoundedRectangle(
                    topLeadingRadius: first ? radius : 0, bottomLeadingRadius: last ? radius : 0,
                    bottomTrailingRadius: last ? radius : 0, topTrailingRadius: first ? radius : 0, style: .continuous)
                    .fill(Theme.RX.Palette.cardBackground.color)
                    .padding(.horizontal, Theme.RX.Space.gutter))
    }
}
#endif
