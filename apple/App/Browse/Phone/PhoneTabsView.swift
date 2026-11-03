#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// A screen pushed in one of the iPhone tabs: a filtered list (vault, category, tag, archive,
/// trash) or an item's detail (edition happens in place in the detail).
enum PhoneRoute: Hashable {
    case list(ItemFilter)
    case item(ItemRef)
    /// The items flagged by a Watchtower card.
    case watchtower(title: String, itemIDs: Set<String>)
    /// The Crypto screen (watch-only balances) and one coin of it.
    case crypto
    case cryptoCoin(String)
    /// The review of possible duplicates (spec 2026-11-03-duplicates).
    case duplicates

    var itemRef: ItemRef? {
        if case .item(let ref) = self { return ref }
        return nil
    }
}

enum PhoneTab: String, Hashable {
    case home, items, watchtower, search
}

extension EnvironmentValues {
    /// Switches the iPhone tab bar to a tab.
    @Entry var openPhoneTab: @MainActor (PhoneTab) -> Void = { _ in }
    /// The iPhone search is presented: Accueil keeps its banners for when it is really on screen.
    @Entry var phoneSearchActive = false
}

/// iPhone, and iPad in compact width (spec 6.2, mockups `PhoneHome`, `PhoneItems`, `PhoneSearch`):
/// Liquid Glass tab bar with three tabs, Accueil, Éléments and Watchtower, and the search tab (role
/// `.search`) as the separate button on its right, each tab in its own navigation stack. Réglages
/// opens from the account menu, as a sheet (`BrowseRoot`). The item shown on top of the visible tab's stack is
/// `AppModel.selectedItem`, so the detail's own actions (trash, move, save under a new vault)
/// pop or follow it here. The tab bar hides while an editor is open.
struct PhoneTabsView: View {
    @Environment(AppModel.self) private var model
    @State private var tab: PhoneTab = .home
    @State private var paths: [PhoneTab: [PhoneRoute]] = [:]
    @State private var searchQuery = ""
    @State private var searching = false
    /// Choosing Rechercher opens its field (off for the demo captures of the list).
    @State private var openSearchOnSelect = true

    /// A tab's label: the outline symbol, its filled form when the tab is selected.
    private func tabLabel(_ title: LocalizedStringKey, _ symbol: String, _ value: PhoneTab) -> some View {
        Label(title, systemImage: tab == value ? symbol + ".fill" : symbol)
            .environment(\.symbolVariants, .none)
    }

    var body: some View {
        TabView(selection: $tab) {
            // One family: outline symbols of the same weight, filled only on the selected tab (the
            // bar's own fill variant is turned off so the unselected ones stay light).
            Tab(value: PhoneTab.home) {
                stack(.home) { HomeTab() }
            } label: {
                tabLabel("Accueil", "house", .home)
            }
            .accessibilityIdentifier("tab.home")
            Tab(value: PhoneTab.items) {
                stack(.items) { ItemsTab() }
            } label: {
                tabLabel("Éléments", "rectangle.stack", .items)
            }
            .accessibilityIdentifier("tab.items")
            Tab(value: PhoneTab.watchtower) {
                stack(.watchtower) { WatchtowerTab() }
            } label: {
                tabLabel("Watchtower", "checkmark.shield", .watchtower)
            }
            .accessibilityIdentifier("tab.watchtower")
            Tab("common.search", systemImage: "magnifyingglass", value: PhoneTab.search, role: .search) {
                stack(.search) { SearchTab(query: $searchQuery, isSearching: $searching) }
            }
            .accessibilityIdentifier("tab.search")
        }
        // On the tab view, not in the search tab's stack: the `.search` tab then turns into the
        // search field of the tab bar (a `searchable` inside the tab showed no field at all).
        // Toolbar placement and search tab activation: the search tab is the separate round
        // button on the right of the three tabs, and its field opens at the bottom.
        .searchable(text: $searchQuery, isPresented: $searching, placement: .toolbar, prompt: Text("browse.searchItems"))
        .tabViewSearchActivation(.searchTabSelection)
        .tabBarMinimizeBehavior(.onScrollDown)
        // A search is only ever shown on its own tab, whatever presented it.
        .onChange(of: searching) { _, presented in
            if presented, tab != .search { tab = .search }
        }
        .environment(\.phoneSearchActive, searching)
        .environment(\.openPhoneTab) { tab = $0 }
        .sheet(isPresented: newItemShown) {
            PhoneNewItemSheet()
        }
        // The top of the visible stack is the selection: a tab switch selects that tab's item.
        .onChange(of: tab) { _, newTab in
            // The search field shows only while presented: choosing Rechercher opens it.
            if newTab == .search, openSearchOnSelect, paths[.search]?.isEmpty ?? true { searching = true }
            // Leaving the search tab (the tab button beside the field) does not write
            // `isPresented` back: a search still "presented" here came back later over the other
            // tab (field and keyboard over Accueil, tab bar hidden). It ends with its tab.
            if newTab != .search, searching { searching = false }
            let ref = paths[newTab]?.last?.itemRef
            if model.selectedItem != ref { model.perform(.select(ref)) }
            model.session.noteActivity()
        }
        // Moving in a tab counts as activity (no tap gesture over the tabs, see `BrowseRoot`).
        .onChange(of: paths) { model.session.noteActivity() }
        // The detail cleared or moved the selection (trash, move, new vault on save), or a new
        // item was saved: the visible stack follows.
        .onChange(of: model.selectedItem) { old, new in
            follow(selection: new, previous: old)
        }
        // "Nouvel élément" goes to the vault whose list is open in the visible tab.
        .onChange(of: browsedVault, initial: true) { _, vault in
            model.phoneBrowsedVault = vault
        }
        .onDisappear { model.phoneBrowsedVault = nil }
        // A deep link (widget, Control): the item in Éléments, or the search tab. Also on appear,
        // when the link was waiting for the unlock.
        .onChange(of: model.browseReveal, initial: true) { _, reveal in
            guard let reveal else { return }
            model.browseReveal = nil
            switch reveal {
            case .item(let ref):
                paths[.items] = [.item(ref)]
                tab = .items
            case .search:
                paths[.search] = []
                tab = .search
                searching = true
            }
        }
        #if DEBUG
        .task { applyDemoArguments() }
        #endif
    }

    private func stack<Root: View>(_ which: PhoneTab, @ViewBuilder root: () -> Root) -> some View {
        NavigationStack(path: path(which)) {
            // Every screen of the stack, the root and each one pushed, fades under its header the
            // same way (one shared modifier, never a copy per screen).
            root()
                .headerFade()
                .navigationDestination(for: PhoneRoute.self) { route in
                    Group {
                        switch route {
                        case .list(let filter):
                            CategoryListView(filter: filter)
                        case .watchtower(let title, let itemIDs):
                            WatchtowerItemsList(title: title, itemIDs: itemIDs)
                        case .crypto:
                            CryptoPortfolioView()
                        case .cryptoCoin(let coin):
                            CryptoCoinView(coin: coin)
                        case .duplicates:
                            DuplicatesReviewView()
                        case .item(let ref):
                            ItemDetailView(ref: ref)
                                .id(ref)
                                .toolbar(model.isEditing ? .hidden : .visible, for: .tabBar)
                        }
                    }
                    .headerFade()
                }
        }
    }

    private func path(_ which: PhoneTab) -> Binding<[PhoneRoute]> {
        Binding(
            get: { paths[which] ?? [] },
            set: { newPath in
                paths[which] = newPath
                guard which == tab else { return }
                let ref = newPath.last?.itemRef
                if model.selectedItem != ref { model.perform(.select(ref)) }
            })
    }

    /// The vault of the last vault list in the visible tab's stack (an item opened from it included).
    private var browsedVault: String? {
        for route in (paths[tab] ?? []).reversed() {
            if case .list(let filter) = route {
                if case .vault(let id) = filter { return id }
                return nil
            }
        }
        return nil
    }

    private func follow(selection new: ItemRef?, previous old: ItemRef?) {
        // A revealed item goes to Éléments (handled by the `browseReveal` observer).
        if let new, model.browseReveal == .item(new) { return }
        var current = paths[tab] ?? []
        let top = current.last?.itemRef
        guard top != new else { return }
        if let new {
            if let top, top == old {
                current[current.count - 1] = .item(new)
            } else {
                current.append(.item(new))
            }
        } else if top != nil {
            current.removeLast()
        }
        paths[tab] = current
    }

    /// The type picker then the editor, in one sheet. Also opened by ⌘N with a keyboard.
    private var newItemShown: Binding<Bool> {
        Binding(
            get: { model.showNewItemPicker || model.newItemDraft != nil },
            set: { shown in
                guard !shown else { return }
                model.showNewItemPicker = false
                if model.newItemDraft != nil { model.finishNewItem(nil) }
            })
    }

    #if DEBUG
    /// Captures: `-OnePassDemoTab items|watchtower|search` opens that tab (`settings` opens Réglages),
    /// `-OnePassDemoQuery <text>` fills the search, `-OnePassDemoNewItem YES` opens the add sheet,
    /// `-OnePassDemoList <vault|category|tag|archive|trash>` pushes a list in Éléments, `crypto[:<coin>]` the
    /// Crypto screen. Debug builds only.
    private func applyDemoArguments() {
        let defaults = UserDefaults.standard
        if let name = defaults.string(forKey: "OnePassDemoTab") {
            if let demoTab = PhoneTab(rawValue: name) {
                openSearchOnSelect = false
                tab = demoTab
            } else if name == "settings" {
                model.showSettings = true
            }
        }
        if let query = defaults.string(forKey: "OnePassDemoQuery") {
            searchQuery = query
            searching = true
        }
        if defaults.bool(forKey: "OnePassDemoNewItem") { model.showNewItemPicker = true }
        // `-OnePassDemoList crypto` or `crypto:<coin id>`: the Crypto screen, or a coin's detail.
        if let list = defaults.string(forKey: "OnePassDemoList"), list.hasPrefix("crypto") {
            tab = .home
            let coin = list.split(separator: ":").dropFirst().first.map(String.init)
            paths[.home] = [.crypto] + (coin.map { [PhoneRoute.cryptoCoin($0)] } ?? [])
            return
        }
        // `-OnePassDemoList duplicates` (or `duplicates-merge`, which also opens the first merge).
        if let list = defaults.string(forKey: "OnePassDemoList"), list.hasPrefix("duplicates") {
            tab = .home
            paths[.home] = [.duplicates]
            return
        }
        if let list = defaults.string(forKey: "OnePassDemoList") {
            let filter: ItemFilter? = switch list {
            case "archive": .archive
            case "trash": .trash
            case "favorites": .favorites
            case "passkeys": .passkeys
            case "all": .all
            case "category": model.session.summaries.first.map { .category($0.itemType) }
            case "tag": model.session.counts().byTag.keys.sorted().first.map { .tag($0) }
            default: model.session.vaults.first.map { .vault($0.id) }
            }
            if let filter {
                tab = .items
                paths[.items] = [.list(filter)]
            }
        }
    }
    #endif
}

/// The new item flow on iPhone: "Que veux-tu ajouter ?" (`NewItemSheet`), then the editor in the
/// same sheet. Saving shows the new item in the visible tab; "Annuler" closes the sheet.
struct PhoneNewItemSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        NavigationStack {
            // The editor comes in from the trailing edge as a pushed screen would, the picker leaves
            // to the leading edge: the sheet reads as one step forward.
            ZStack {
                if let draft = model.newItemDraft {
                    ItemEditorView(draft: draft, isNew: true) { saved in
                        model.finishNewItem(saved)
                    }
                    .id(draft.item.id)
                    .headerFade()
                    .transition(stepTransition)
                } else {
                    // "Que veux-tu ajouter ?", as on the Mac: the editor then takes its place here.
                    NewItemSheet(inPhoneSheet: true)
                        .toolbar(.hidden, for: .navigationBar)
                        .transition(stepTransition)
                }
            }
            .animation(Motion.fold(reduceMotion: reduceMotion), value: model.newItemDraft?.item.id)
        }
        // ⌘L with a dirty new item: the confirmation shows over the sheet.
        .discardConfirmation()
    }

    private var stepTransition: AnyTransition {
        reduceMotion ? .opacity : .push(from: .trailing)
    }
}

// MARK: - Unfolded iPhone

extension EnvironmentValues {
    /// Set by the unfolded layout: list rows become draggable and report the drag's start.
    @Entry var itemDragStarted: (@MainActor (ItemRef) -> Void)?
}

/// The unfolded iPhone (spec "iPhone pliable"): the item list and the detail side by side, the
/// fold's seam between them. On unfold the open item slides out from the seam. Dragging a row
/// raises a tray of vaults and a star at the bottom: drop to move or to mark as favorite.
struct FoldSplitView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var appeared = false
    @State private var dragging: ItemRef?
    @State private var dragToken = 0

    var body: some View {
        GeometryReader { proxy in
            let half = proxy.size.width / 2
            // Two plain panes, not a split view: an iPhone-sized split view slides its list over
            // the detail and dims it; here both halves stay put on either side of the fold.
            HStack(spacing: 0) {
                NavigationStack {
                    ItemListColumn()
                        // The account menu (Réglages, Importer, Verrouiller) as on the folded phone.
                        .toolbar {
                            ToolbarItem(placement: .topBarLeading) { AccountMenu() }
                                .sharedBackgroundVisibility(.hidden)
                        }
                }
                .frame(width: half)
                DetailColumn()
                    .frame(width: proxy.size.width - half)
                    // Out from the seam: from the hinge toward the right edge.
                    .offset(x: appeared || reduceMotion ? 0 : -half * 0.4)
                    .opacity(appeared ? 1 : 0)
                    .clipped()
            }
            .overlay(alignment: .topLeading) { hinge.offset(x: half - 4) }
            .overlay(alignment: .bottom) {
                if let dragging {
                    FoldDropTray(ref: dragging) { self.dragging = nil }
                        .padding(.bottom, 24)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.spring(duration: 0.35, bounce: 0.2), value: dragging)
        }
        .environment(\.itemDragStarted) { ref in
            dragging = ref
            dragToken &+= 1
        }
        // A drag dropped outside any target leaves no callback: the tray goes after a while.
        .task(id: dragToken) {
            guard dragging != nil else { return }
            try? await Task.sleep(for: .seconds(8))
            if !Task.isCancelled { dragging = nil }
        }
        .onAppear {
            withAnimation(reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.55, bounce: 0.18).delay(0.05)) {
                appeared = true
            }
        }
    }

    /// The fold: a soft vertical crease, darker in its middle, never taking a touch.
    private var hinge: some View {
        LinearGradient(colors: [.clear, Color.primary.opacity(0.10), .clear], startPoint: .leading, endPoint: .trailing)
            .frame(width: 8)
            .frame(maxHeight: .infinity)
            .overlay {
                LinearGradient(colors: [.clear, Color.primary.opacity(0.18), Color.primary.opacity(0.18), .clear],
                    startPoint: .top, endPoint: .bottom)
                    .frame(width: 1)
            }
            .ignoresSafeArea()
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}

/// While a row is dragged: the vaults as round marks and a star, each one a drop target that
/// grows under the finger.
private struct FoldDropTray: View {
    @Environment(AppModel.self) private var model
    let ref: ItemRef
    let done: () -> Void
    @State private var targeted: String?

    var body: some View {
        HStack(spacing: 14) {
            ForEach(model.session.vaults, id: \.id) { vault in
                target(id: vault.id, label: vault.meta.name, current: vault.id == ref.vaultID) {
                    VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 44)
                } drop: {
                    move(to: vault)
                }
            }
            Rectangle().fill(Color.primary.opacity(0.12)).frame(width: 1, height: 36)
            target(id: "favorite", label: String(localized: "Favori"), current: false) {
                Image(systemName: "star.fill")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 44, height: 44)
                    .background(Color(red: 0xF5 / 255, green: 0xA6 / 255, blue: 0x23 / 255).gradient, in: Circle())
            } drop: {
                favorite()
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 12)
        .glassEffect(.regular, in: Capsule())
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("fold.dropTray")
    }

    private func target(
        id: String, label: String, current: Bool, @ViewBuilder mark: () -> some View, drop: @escaping () -> Void
    ) -> some View {
        VStack(spacing: 5) {
            mark()
                .scaleEffect(targeted == id ? 1.22 : 1)
                .opacity(current ? 0.4 : 1)
            Text(label).font(.caption2.weight(.medium)).lineLimit(1).frame(maxWidth: 70)
        }
        .animation(.spring(duration: 0.25, bounce: 0.4), value: targeted)
        .dropDestination(for: String.self) { items, _ in
            guard !current, items.contains(where: { $0.hasPrefix(FoldDrag.prefix) }) else { return false }
            drop()
            return true
        } isTargeted: { inside in
            if inside { targeted = id } else if targeted == id { targeted = nil }
        }
        .sensoryFeedback(.selection, trigger: targeted)
        .accessibilityIdentifier("fold.drop.\(id)")
    }

    private func move(to vault: FfiVault) {
        let ref = ref
        done()
        Task {
            do {
                try await model.session.move(itemID: ref.itemID, from: ref.vaultID, to: vault.id)
                model.showToast(String(localized: "app.movedTo \(vault.meta.name)"))
            } catch {
                model.showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    private func favorite() {
        let ref = ref
        done()
        Task {
            try? await model.session.setFavorite(true, itemID: ref.itemID, vaultID: ref.vaultID)
            model.showToast(String(localized: "app.addedToFavorites"))
        }
    }
}

/// The drag payload of a row: an opaque reference, never the item's content.
enum FoldDrag {
    static let prefix = "onepass-item:"

    static func payload(_ ref: ItemRef) -> String { prefix + ref.vaultID + "/" + ref.itemID }
}

/// List rows of the unfolded layout: open on tap, draggable to the tray (elsewhere unchanged).
struct ItemRowDrag: ViewModifier {
    @Environment(AppModel.self) private var model
    @Environment(\.itemDragStarted) private var started
    let ref: ItemRef

    func body(content: Content) -> some View {
        if let started {
            // Outside a split view a list does not select on tap: the row opens its item itself.
            content
                .contentShape(.rect)
                .onTapGesture { model.selectedItem = ref }
                .onDrag {
                started(ref)
                return NSItemProvider(object: FoldDrag.payload(ref) as NSString)
            }
        } else {
            content
        }
    }
}
#endif
