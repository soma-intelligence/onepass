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

    var body: some View {
        TabView(selection: $tab) {
            Tab("Accueil", systemImage: "house.fill", value: PhoneTab.home) {
                stack(.home) { HomeTab() }
            }
            .accessibilityIdentifier("tab.home")
            Tab("Éléments", systemImage: "list.bullet.rectangle.fill", value: PhoneTab.items) {
                stack(.items) { ItemsTab() }
            }
            .accessibilityIdentifier("tab.items")
            Tab("Watchtower", systemImage: "checkmark.shield.fill", value: PhoneTab.watchtower) {
                stack(.watchtower) { WatchtowerTab() }
            }
            .accessibilityIdentifier("tab.watchtower")
            Tab("Rechercher", systemImage: "magnifyingglass", value: PhoneTab.search, role: .search) {
                stack(.search) { SearchTab(query: $searchQuery, isSearching: $searching) }
            }
            .accessibilityIdentifier("tab.search")
        }
        // On the tab view, not in the search tab's stack: the `.search` tab then turns into the
        // search field of the tab bar (a `searchable` inside the tab showed no field at all).
        // Toolbar placement and search tab activation: the search tab is the separate round
        // button on the right of the three tabs, and its field opens at the bottom.
        .searchable(text: $searchQuery, isPresented: $searching, placement: .toolbar, prompt: Text("Titre, site, identifiant, tag"))
        .tabViewSearchActivation(.searchTabSelection)
        .tabBarMinimizeBehavior(.onScrollDown)
        .environment(\.openPhoneTab) { tab = $0 }
        .sheet(isPresented: newItemShown) {
            PhoneNewItemSheet()
        }
        // The top of the visible stack is the selection: a tab switch selects that tab's item.
        .onChange(of: tab) { _, newTab in
            // The search field shows only while presented: choosing Rechercher opens it.
            if newTab == .search, openSearchOnSelect, paths[.search]?.isEmpty ?? true { searching = true }
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
            root()
                .navigationDestination(for: PhoneRoute.self) { route in
                    switch route {
                    case .list(let filter):
                        CategoryListView(filter: filter)
                    case .watchtower(let title, let itemIDs):
                        WatchtowerItemsList(title: title, itemIDs: itemIDs)
                    case .item(let ref):
                        ItemDetailView(ref: ref)
                            .id(ref)
                            .toolbar(model.isEditing ? .hidden : .visible, for: .tabBar)
                    }
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
    /// `-OnePassDemoList <vault|category|tag|archive|trash>` pushes a list in Éléments. Debug builds only.
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
        if let list = defaults.string(forKey: "OnePassDemoList") {
            let filter: ItemFilter? = switch list {
            case "archive": .archive
            case "trash": .trash
            case "favorites": .favorites
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
#endif
