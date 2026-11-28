import DesignBridgeKit
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

#if os(macOS)
extension EnvironmentValues {
    /// Mac: the width of the title bar's row above the list and the detail (nil: the window's).
    @Entry var titleBarRoom: CGFloat?
}

/// Mac: measures the title bar's row around one toolbar item (the view it sits behind): the other
/// items after it at their natural widths, the gaps and the margins. SwiftUI gives a toolbar item
/// the width it asks for and never stretches it, so the item asks for the row's width less this.
/// Only the other items are measured here: the row's width comes from the layout (`titleBarRoom`),
/// so a resize narrows the item in the same pass, before the bar could push items into its menu.
struct ToolbarRowProbe: NSViewRepresentable {
    @Binding var reserved: CGFloat
    /// The row's width (`titleBarRoom`): where the pane starts, for what sits left of the item.
    let room: CGFloat?
    /// Changes when the bar's other items may change (selection, editing): measured again.
    let trigger: [String]

    func makeNSView(context: Context) -> ProbeView { ProbeView() }

    func updateNSView(_ view: ProbeView, context: Context) {
        view.room = room
        view.onMeasure = { measured in
            let target = measured.rounded(.up)
            if abs(target - reserved) >= 1 { reserved = target }
        }
        view.scheduleMeasure()
    }

    final class ProbeView: NSView {
        var onMeasure: ((CGFloat) -> Void)?
        var room: CGFloat?
        /// The window the row belongs to, kept while the item sits in the overflow menu (out of
        /// the window) so the row can still be measured.
        private weak var hostWindow: NSWindow?

        /// The title bar's room around items, as measured on macOS 26: the row starts 4 pt into
        /// its pane, items sit 0 to 6 pt apart, a closed flexible space keeps 8.5 pt and the last
        /// item ends 7 pt from the window's edge. Rounded up: a point to spare keeps the last item
        /// out of the overflow menu.
        private let gap: CGFloat = 4
        private let flexibleSpaceMinimum: CGFloat = 9
        private let leadingInset: CGFloat = 6
        private let trailingMargin: CGFloat = 8

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window, window.toolbar != nil { hostWindow = window }
            scheduleMeasure()
        }

        /// Toolbar items change on the next pass: measured then, and once more when they settle.
        func scheduleMeasure() {
            DispatchQueue.main.async { [weak self] in self?.measure() }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in self?.measure() }
        }

        private func measure() {
            guard let window = window ?? hostWindow, let items = window.toolbar?.items,
                let index = items.firstIndex(where: { item in item.view.map { isDescendant(of: $0) } ?? false })
            else { return }
            // With the sidebar hidden, its toggle (and the window's buttons) share the row: the
            // item starts after the last of them.
            var leading = leadingInset
            if let room {
                let paneLeft = window.frame.width - room
                for item in items[..<index] {
                    guard let view = item.view, view.window != nil else { continue }
                    let frame = view.convert(view.bounds, to: nil)
                    if frame.minX >= paneLeft - 1 { leading = max(leading, frame.maxX - paneLeft + gap) }
                }
            }
            var reserved = leading + trailingMargin + gap
            for item in items[(index + 1)...] {
                if item.itemIdentifier == .flexibleSpace {
                    reserved += flexibleSpaceMinimum
                    continue
                }
                guard let view = item.view, !(item is NSTrackingSeparatorToolbarItem) else { continue }
                // An item in the overflow menu can report a smaller fitting size than its frame.
                let natural = max(view.fittingSize.width, view.frame.width)
                guard natural > 1 else { continue }
                reserved += natural + gap
            }
            onMeasure?(reserved)
        }
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
    /// The RX look (Réglages > Général > Nouveau design): the count and the composition strip head the list.
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    #if os(macOS)
    /// Mac: two or more rows picked at once (⌘ or ⇧ click, ⌘A). Empty while one item is shown in
    /// the detail column: that one lives in `model.selectedItem`.
    @State private var multiSelection: Set<ItemRef> = []
    @State private var selectAllMonitor: Any?
    /// "Fusionner…" on two picked rows: the merge sheet's pair.
    @State private var mergePick: MergePickRequest?
    /// The title bar's row above the list and the detail, and what its items other than the search
    /// field take (`ToolbarRowProbe`): the search field gets the rest.
    @Environment(\.titleBarRoom) private var titleBarRoom
    @State private var rowReserved: CGFloat = 400
    #endif

    private var session: VaultSession { model.session }
    private var sort: ItemSort { sortByDate ? .updated : .title }

    #if os(macOS)
    /// Mac: one row shows its item in the detail column; several rows form a batch (moved or
    /// trashed together from the bar under the list). No batch while an editor is open.
    private var rowSelection: Binding<Set<ItemRef>> {
        Binding(
            get: {
                if multiSelection.count > 1 { return multiSelection }
                return model.selectedItem.map { [$0] } ?? []
            },
            set: { refs in
                if refs.count > 1 {
                    guard !model.isEditing else { return }
                    multiSelection = refs
                    if model.selectedItem != nil { model.perform(.select(nil)) }
                } else {
                    multiSelection = []
                    model.perform(.select(refs.first))
                }
            })
    }

    /// ⌘A picks every listed row (from the search field once a search is typed, or from the list).
    private func selectAllListed() {
        guard !model.isEditing else { return }
        let refs = Set(listedItems.map { ItemRef(vaultID: $0.vaultId, itemID: $0.id) })
        rowSelection.wrappedValue = refs
    }

    /// The batch, in list order.
    private var batch: [ItemRef] {
        listedItems.map { ItemRef(vaultID: $0.vaultId, itemID: $0.id) }.filter { multiSelection.contains($0) }
    }
    #else
    private var rowSelection: Binding<ItemRef?> {
        Binding(
            get: { model.selectedItem },
            set: { model.perform(.select($0)) })
    }
    #endif

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
        #if os(macOS)
        // No scroll bar parked on the column's edge: the trackpad or wheel still scrolls.
        .scrollIndicators(.never)
        #endif
        // RX: the count in rolling digits over the composition strip (All Items v2 signature);
        // the chosen type stays lit. Above the rows, never over them.
        .safeAreaInset(edge: .top, spacing: 0) {
            if rxDesign, !items.isEmpty { rxHeader(count: items.count) }
        }
        // A new sidebar filter starts on every type again.
        .onChange(of: model.selection) { categoryFilter = nil }
        .focusedValue(\.itemListFocused, true)
        #if os(macOS)
        // Delete key on the focused list (Edit > Supprimer): same as ⌘⌫, never from a text field.
        .onDeleteCommand {
            if multiSelection.count > 1 { trashBatch() } else { model.trashSelection() }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if multiSelection.count > 1 { batchBar }
        }
        .onAppear { installSelectAllMonitor() }
        .onDisappear { removeSelectAllMonitor() }
        .sheet(item: $mergePick) { pick in
            MergePickSheet(refs: pick.refs) { multiSelection = [] }
        }
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
            #if os(macOS)
            let listed = Set(ids)
            multiSelection = multiSelection.filter { listed.contains($0.itemID) }
            if multiSelection.count == 1 {
                let only = multiSelection.first
                multiSelection = []
                model.perform(.select(only))
            }
            #endif
        }
        .navigationTitle(model.watchtowerFilter?.title ?? title)
        #if os(macOS)
        // Mockup `Main`: the list names its filter above the rows; the toolbar keeps search and actions.
        .toolbar(removing: .title)
        // One row in the title bar across the list and the detail: the search field (it names the
        // category it searches) grows to fill it, then the category filter, the sort order and
        // "Nouvel élément" as quiet round icons at the right edge. No glass behind it, no second
        // row under the title bar.
        .toolbar {
            ToolbarItem(placement: .automatic) {
                // A toolbar item keeps the width it asks for: the search field asks for the row
                // less what the bar's other items take (`ToolbarRowProbe`).
                searchField
                    .frame(width: titleBarRoom.map { max(180, $0 - rowReserved - Self.searchLeadingGap) } ?? 210)
                    // Air between the field and the sidebar button, which sits right against it
                    // once the sidebar is closed.
                    .padding(.leading, Self.searchLeadingGap)
                    // When the bar's other items change (a deleted item has fewer), the field eases
                    // to its new width instead of jumping.
                    .animation(.easeInOut(duration: 0.2), value: rowReserved)
                    .background {
                        ToolbarRowProbe(
                            reserved: $rowReserved, room: titleBarRoom,
                            trigger: [model.selectedItem.map { "\($0)" } ?? "", "\(model.isEditing)", "\(shownCategory.map { "\($0)" } ?? "")", "\(newItemCompact)"])
                    }
            }
            .sharedBackgroundVisibility(.hidden)
            ToolbarItem(placement: .primaryAction) {
                HStack(spacing: 4) {
                    categoryPill
                    sortMenu
                    newItemButton
                        .padding(.leading, Theme.Space.xs)
                }
            }
            .sharedBackgroundVisibility(.hidden)
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
        .searchable(text: $query, prompt: Text("common.search"))
        .searchFocused($searchFocused)
        .onChange(of: model.searchFocusRequest) { searchFocused = true }
        #endif
        .toolbar {
            #if !os(macOS)
            ToolbarItem(placement: .primaryAction) {
                // The add sheet (common types first, search, every category, import), like ⌘N.
                Button {
                    model.showNewItemPicker = true
                } label: {
                    Label("Nouvel élément", systemImage: "plus")
                }
                .help("browse.newItemN")
                .accessibilityIdentifier("items.new")
            }
            #endif
            #if !os(macOS)
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Picker("browse.sortBy", selection: $sortByDate) {
                        Text("app.title").tag(false)
                        Text("browse.dateModified").tag(true)
                    }
                    .pickerStyle(.inline)
                } label: {
                    Label("browse.sort", systemImage: "arrow.up.arrow.down")
                }
                .accessibilityIdentifier("items.sort")
            }
            #endif
        }
    }

    /// RX: the list's count and its composition by type (one segment per type, most items first).
    private func rxHeader(count: Int) -> some View {
        let segments = presentTypes
            .sorted { $0.count > $1.count }
            .map { RXCompositionStrip.Segment(id: NewItemMenu.key($0.type), count: $0.count, color: ItemCategory.of($0.type).color) }
        return VStack(alignment: .leading, spacing: Theme.RX.Space.s) {
            Text(Self.countLabel(count))
                .rxFont(.headline)
                .foregroundStyle(Theme.RX.Palette.textPrimary.color)
                .dbRollingNumber(value: Double(count))
                .accessibilityIdentifier("rx.list.count")
            if segments.count > 1 {
                RXCompositionStrip(segments, focus: shownCategory.map(NewItemMenu.key))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, Theme.RX.Space.l)
        .padding(.top, Theme.RX.Space.s)
        .padding(.bottom, Theme.RX.Space.m)
        // Opaque: the rows scroll under the inset and must not show through the count.
        #if os(macOS)
        .background(Color(nsColor: .windowBackgroundColor))
        #else
        .background(.background)
        #endif
    }

    #if os(macOS)
    /// "Toutes les catégories ⌄": a pill with the current type's tile, filled with the accent once a
    /// type is chosen. Opens the types present in the filter, common ones first.
    private var categoryPill: some View {
        let current = shownCategory.map(ItemCategory.of)
        return Button {
            choosingCategory.toggle()
        } label: {
            Group {
                if let current {
                    // A type is chosen: its tile, ringed in the accent.
                    CategoryTile(category: current, size: 18)
                        .padding(3)
                        .overlay { Circle().strokeBorder(Theme.accent, lineWidth: 1.5) }
                } else {
                    Image(systemName: "line.3.horizontal.decrease")
                        .font(.system(size: 13, weight: .medium))
                }
            }
            .frame(width: 28, height: 28)
            .foregroundStyle(.secondary)
            .contentShape(Circle())
        }
        .buttonStyle(QuietIconButtonStyle())
        .help(current?.plural ?? String(localized: "browse.allCategories"))
        .buttonStyle(.plain)
        .accessibilityLabel(Text(current?.plural ?? String(localized: "browse.allCategories")))
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

    /// The add sheet (common types first, search, every category, import), like ⌘N: the last
    /// item of the list's one header row, an accent pill "+ Nouvel élément" that folds to an
    /// accent circle with the bare "+" when the title bar runs short.
    private var newItemButton: some View {
        newItemButton(labelled: !newItemCompact)
    }

    /// Below this row width the pill pushes the bar's last items into its overflow menu:
    /// the label goes and the "+" stays in an accent circle.
    private var newItemCompact: Bool { (titleBarRoom ?? .infinity) < 700 }

    private func newItemButton(labelled: Bool) -> some View {
        Button {
            model.showNewItemPicker = true
        } label: {
            if labelled {
                HStack(spacing: 6) {
                    Image(systemName: "plus").font(.system(size: 13, weight: .bold))
                    Text("Nouvel élément").lineLimit(1)
                }
                .padding(.horizontal, -Theme.Space.xs)
                .frame(height: 18)
            } else {
                Image(systemName: "plus")
                    .font(.system(size: 13, weight: .bold))
                    .frame(width: 18, height: 18)
                    .padding(.horizontal, -10)
            }
        }
        .buttonStyle(AccentCapsuleButtonStyle())
        .fixedSize()
        .help("browse.newItemN")
        .accessibilityLabel(Text("Nouvel élément"))
        .accessibilityIdentifier("items.new")
    }

    private var sortMenu: some View {
        Menu {
            Picker("browse.sortBy", selection: $sortByDate) {
                Text("app.title").tag(false)
                Text("browse.dateModified").tag(true)
            }
            .pickerStyle(.inline)
        } label: {
            Image(systemName: "arrow.up.arrow.down")
        }
        .menuStyle(.button)
        .buttonStyle(QuietIconButtonStyle())
        .menuIndicator(.hidden)
        .fixedSize()
        .help("browse.sort")
        .accessibilityIdentifier("items.sort")
    }

    /// Space before the title bar's search field (the sidebar button or the list's edge).
    private static let searchLeadingGap: CGFloat = 10

    /// "Rechercher", or "Rechercher dans Logins" once a type is chosen.
    private var searchPrompt: String {
        guard let type = shownCategory else { return String(localized: "common.search") }
        return String(localized: "browse.search \(ItemCategory.of(type).plural)")
    }

    /// The list's own search field (⌘F), above the rows. Escape clears it.
    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("common.search", text: $query, prompt: Text(searchPrompt))
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
                .accessibilityLabel(Text("browse.clearSearch"))
            }
        }
        .modifier(SearchFieldChrome(rx: rxDesign, focused: searchFocused, empty: query.isEmpty))
    }

    /// The search field's look. RX: the one search of the window (the sidebar has none), filled
    /// like the RX fields, no hairline, the ⌘F hint while it is empty and idle. Classic: the glass
    /// capsule.
    private struct SearchFieldChrome: ViewModifier {
        let rx: Bool
        let focused: Bool
        let empty: Bool
        private typealias RX = Theme.RX

        func body(content: Content) -> some View {
            if rx {
                let shape = RoundedRectangle(cornerRadius: RX.Radius.macRow, style: .continuous)
                HStack(spacing: RX.Space.s) {
                    content
                    if empty, !focused {
                        Text(verbatim: "⌘F")
                            .rxFont(.footnote)
                            .foregroundStyle(RX.Palette.textTertiary.color)
                    }
                }
                .rxFont(.callout)
                .padding(.horizontal, RX.Space.m)
                .frame(height: 32)
                // The glass fill (system search fill): `field` matches the window in dark and vanishes.
                .background(RX.Palette.glass.color, in: shape)
                .overlay {
                    if focused { shape.strokeBorder(Theme.accent.opacity(0.8), lineWidth: 1.5) }
                }
            } else {
                content
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    // A blur under the fill: the detail's wash, cut at the list's edge, passes
                    // behind the field as a soft glow, not a seam.
                    .background(.fill.quaternary, in: Capsule())
                    .background(.ultraThinMaterial, in: Capsule())
                    .overlay {
                        Capsule()
                            .strokeBorder(focused ? AnyShapeStyle(Theme.accent.opacity(0.8)) : AnyShapeStyle(.white.opacity(0.06)))
                    }
            }
        }
    }
    #endif

    @ViewBuilder private func rows(_ items: [FfiItemSummary]) -> some View {
        let showVault = showsVaultName
        ForEach(items, id: \.id) { summary in
            WatchtowerSetupRow(itemID: summary.id, check: model.watchtowerFilter?.check) {
                ItemListRow(summary: summary, vaultName: showVault ? vaultName(summary.vaultId) : nil)
            }
                .tag(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
                .contextMenu { contextMenu(summary) }
                .visionHoverEffect()
                // Rows breathe on their own: the selection and hover capsules mark them, no rules.
                .listRowSeparator(.hidden)
                #if os(iOS)
                // Unfolded iPhone: drag a row to the vault tray.
                .modifier(ItemRowDrag(ref: ItemRef(vaultID: summary.vaultId, itemID: summary.id)))
                #endif
        }
    }

    @ViewBuilder private func contextMenu(_ summary: FfiItemSummary) -> some View {
        #if os(macOS)
        if multiSelection.count > 1, multiSelection.contains(ItemRef(vaultID: summary.vaultId, itemID: summary.id)) {
            batchActions
        } else {
            singleContextMenu(summary)
        }
        #else
        singleContextMenu(summary)
        #endif
    }

    @ViewBuilder private func singleContextMenu(_ summary: FfiItemSummary) -> some View {
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
            Button("browse.moveToTrash", systemImage: "trash", role: .destructive) {
                model.trash(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
            }
            .disabled(model.isEditing && model.selectedItem == ItemRef(vaultID: summary.vaultId, itemID: summary.id))
        }
    }

    #if os(macOS)
    // MARK: - Batch (Mac)

    /// The batch's vaults: one when every picked item sits in the same vault.
    private var batchVaultID: String {
        let vaults = Set(batch.map(\.vaultID))
        return vaults.count == 1 ? vaults.first ?? "" : ""
    }

    /// The picked rows' summaries, in list order.
    private var batchSummaries: [FfiItemSummary] {
        listedItems.filter { multiSelection.contains(ItemRef(vaultID: $0.vaultId, itemID: $0.id)) }
    }

    @ViewBuilder private var batchActions: some View {
        if !model.isEditing, MergePickRule.offers(batchSummaries) {
            Button("browse.merge", systemImage: "arrow.triangle.merge") {
                mergePick = MergePickRequest(refs: batch)
            }
            .accessibilityIdentifier("list.batch.merge")
            Divider()
        }
        MoveToVaultMenu(currentVaultID: batchVaultID) { moveBatch(to: $0) }
        Divider()
        Button("browse.moveToTrash", systemImage: "trash", role: .destructive) { trashBatch() }
    }

    /// Under the list while several rows are picked: the count, "Déplacer vers", the trash, and
    /// a way out.
    private var batchBar: some View {
        HStack(spacing: Theme.Space.m) {
            Text("browse.selectedCount \(multiSelection.count)")
                .font(.subheadline.weight(.medium))
                .lineLimit(1)
                .accessibilityIdentifier("list.batch.count")
            Spacer(minLength: 4)
            Menu {
                Section("item.moveTo") {
                    ForEach(session.vaults.filter { $0.id != batchVaultID }, id: \.id) { vault in
                        Button(vault.meta.name) { moveBatch(to: vault) }
                            .accessibilityIdentifier("list.batch.move.\(vault.id)")
                    }
                }
            } label: {
                Image(systemName: "folder")
            }
            .menuIndicator(.hidden)
            .fixedSize()
            .help(Text("item.moveTo"))
            .accessibilityLabel(Text("item.moveTo"))
            .accessibilityIdentifier("list.batch.move")
            Button(role: .destructive) {
                trashBatch()
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .help(Text("browse.moveToTrash"))
            .accessibilityLabel(Text("browse.moveToTrash"))
            .accessibilityIdentifier("list.batch.trash")
            Button {
                multiSelection = []
            } label: {
                Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
            }
            .buttonStyle(.plain)
            .help(Text("browse.clearSelection"))
            .accessibilityLabel(Text("browse.clearSelection"))
            .accessibilityIdentifier("list.batch.clear")
        }
        .padding(.horizontal, Theme.Space.l)
        .padding(.vertical, Theme.Space.s)
        .background(.bar)
    }

    /// The two rows the merge sheet works on.
    struct MergePickRequest: Identifiable {
        let refs: [ItemRef]
        var id: [ItemRef] { refs }
    }

    /// Each picked item not already there goes to `vault`, one after the other; a failure stops
    /// the run and says why.
    private func moveBatch(to vault: FfiVault) {
        let refs = batch.filter { $0.vaultID != vault.id }
        guard !refs.isEmpty else { return }
        Task {
            for ref in refs {
                do {
                    try await session.move(itemID: ref.itemID, from: ref.vaultID, to: vault.id)
                } catch {
                    model.showToast(VaultError(error).localizedMessage, kind: .error)
                    return
                }
            }
            multiSelection = []
            model.showToast(String(localized: "app.movedTo \(vault.meta.name)"))
        }
    }

    private func trashBatch() {
        let refs = batch
        guard !refs.isEmpty, !model.isEditing else { return }
        Task {
            for ref in refs {
                do {
                    try await session.trash(itemID: ref.itemID, vaultID: ref.vaultID)
                } catch {
                    model.showToast(VaultError(error).localizedMessage, kind: .error)
                    return
                }
            }
            multiSelection = []
            model.showToast(String(localized: "browse.trashedItems \(refs.count)"))
        }
    }

    /// ⌘A reaches the Edit menu before any view: a local monitor takes it when the search field
    /// holds a search, or when the list itself has the focus. Other fields keep their own ⌘A.
    private func installSelectAllMonitor() {
        guard selectAllMonitor == nil else { return }
        selectAllMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
            guard flags == .command, event.charactersIgnoringModifiers?.lowercased() == "a" else { return event }
            let responder = event.window?.firstResponder
            let inSearch = searchFocused && !query.isEmpty
            let inList = responder is NSTableView
            guard inSearch || inList, !listedItems.isEmpty, !model.isEditing else { return event }
            selectAllListed()
            return nil
        }
    }

    private func removeSelectAllMonitor() {
        if let selectAllMonitor { NSEvent.removeMonitor(selectAllMonitor) }
        selectAllMonitor = nil
    }
    #endif

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
        case .passkeys: String(localized: "Passkeys")
        case .nearby: String(localized: "À proximité")
        case .vault(let id): vaultName(id) ?? String(localized: "term.vault")
        case .category(let type): ItemCategory.of(type).plural
        case .tag(let tag): String(localized: "browse.tag \(tag)")
        case .archive: String(localized: "Archive")
        case .trash: String(localized: "Supprimés récemment")
        }
    }

    static func countLabel(_ count: Int) -> String {
        count == 1 ? String(localized: "browse.n1Item") : String(localized: "browse.items \(count)")
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

    /// Consecutive months of a list sorted by date, newest first: "OCTOBRE 2026", in the app's language.
    static func months(_ items: [FfiItemSummary], calendar: Calendar = .current) -> [Month] {
        var result: [Month] = []
        for item in items {
            let date = Date(timeIntervalSince1970: TimeInterval(item.updatedAt))
            let parts = calendar.dateComponents([.year, .month], from: date)
            let id = "\(parts.year ?? 0)-\(parts.month ?? 0)"
            if result.last?.id == id {
                result[result.count - 1].items.append(item)
            } else {
                let title = date.formatted(.dateTime.month(.wide).year())
                result.append(Month(id: id, title: title.uppercased(with: .current), items: [item]))
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
                title: String(localized: "browse.noMatchingItems"), systemImage: "magnifyingglass",
                message: String(localized: "browse.tryOtherWords"))
            .accessibilityIdentifier("list.empty.search")
        case .emptyLibrary:
            EmptyState(
                title: String(localized: "browse.vaultEmpty"), systemImage: "tray",
                message: String(localized: "browse.createFirstItemLogin"),
                actionTitle: String(localized: "Nouvel élément"), actionIdentifier: "list.empty.newItem",
                action: newItem)
            .accessibilityIdentifier("list.empty.library")
        case .emptyCategory:
            EmptyState(
                title: String(localized: "browse.noItemsInCategory"), systemImage: "square.grid.2x2",
                message: String(localized: "browse.itemsOfTypeWill"),
                actionTitle: String(localized: "Nouvel élément"), actionIdentifier: "list.empty.newItem",
                action: newItem)
        case .emptyTag:
            EmptyState(
                title: String(localized: "browse.noItemsWithTag"), systemImage: "tag",
                message: String(localized: "browse.addTagToItem"))
        case .noNearby:
            EmptyState(
                title: String(localized: "browse.nothingNearby"), systemImage: "mappin.slash",
                message: String(localized: "browse.addPlaceToItem"))
        case .noPasskeys:
            EmptyState(
                title: String(localized: "browse.noPasskeys"), systemImage: "person.badge.key",
                message: String(localized: "browse.pickOnepassWhenSite"))
            .accessibilityIdentifier("list.empty.passkeys")
        case .noFavorites:
            EmptyState(
                title: String(localized: "browse.noFavorites"), systemImage: "star",
                message: String(localized: "browse.markItemAsFavorite"))
        case .emptyArchive:
            EmptyState(
                title: String(localized: "browse.archiveEmpty"), systemImage: "archivebox",
                message: String(localized: "browse.archivedItemsWillAppear"))
        case .emptyTrash:
            EmptyState(
                title: String(localized: "browse.trashEmpty"), systemImage: "trash",
                message: String(localized: "browse.itemsMovedToTrash"))
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
                Text(category?.plural ?? String(localized: "browse.allCategories")).lineLimit(1)
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
