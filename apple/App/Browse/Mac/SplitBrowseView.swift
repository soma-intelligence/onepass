import DesignKit
import SwiftUI
import VaultKit

/// Mac window and iPad in regular width (spec 6.1, 6.3, mockup `Main`): sidebar, item list, detail.
/// Edition happens in place in the detail column. A full page (Watchtower, Développeur) takes the
/// whole width right of the sidebar: two columns instead of three.
struct SplitBrowseView: View {
    @Environment(AppModel.self) private var model
    @State private var visibility: NavigationSplitViewVisibility = .all

    var body: some View {
        Group {
            #if os(macOS)
            // Mac: two columns, the item list and the detail side by side in the second one, so the
            // title bar above them is one section: the search field runs across both, its actions
            // at the right edge (a third split column would cut the bar at the list's edge).
            NavigationSplitView(columnVisibility: $visibility) {
                sidebar
            } detail: {
                if model.page == .items {
                    ItemsPane()
                } else {
                    PageColumn(page: model.page)
                }
            }
            // RX: Réglages, a popup over the whole window (sidebar included).
            .modifier(RXMacSettingsPopupHost())
            #else
            if model.page == .items {
                NavigationSplitView(columnVisibility: $visibility) {
                    sidebar
                } content: {
                    ItemListColumn()
                        #if os(iOS)
                        // iPad: the list column fades under its bar like every iPhone screen.
                        .headerFade(color: Color(uiColor: .systemBackground))
                        #endif
                        .navigationSplitViewColumnWidth(min: 320, ideal: 340, max: 440)
                } detail: {
                    DetailColumn()
                }
            } else {
                NavigationSplitView(columnVisibility: $visibility) {
                    sidebar
                } detail: {
                    PageColumn(page: model.page)
                }
            }
            #endif
        }
        #if DEBUG && os(iOS)
        .task {
            // Captures (`-OnePassDemoSidebar YES`): iPad portrait shows the sidebar over the list.
            guard UserDefaults.standard.bool(forKey: "OnePassDemoSidebar") else { return }
            try? await Task.sleep(for: .seconds(1))
            visibility = .doubleColumn
            try? await Task.sleep(for: .milliseconds(300))
            visibility = .all
        }
        #endif
    }

    private var sidebar: some View {
        Sidebar()
            #if os(macOS)
            .navigationSplitViewColumnWidth(min: 210, ideal: 240, max: 320)
            #else
            .navigationSplitViewColumnWidth(min: 290, ideal: 300, max: 360)
            #endif
    }
}

#if os(macOS)
/// Mac, right of the sidebar on the item list: the list, a divider dragged to resize it, then the
/// detail. One SwiftUI tree (not `HSplitView`, whose AppKit panes drop their toolbar items), so the
/// list's search and the detail's actions share the title bar above both.
private struct ItemsPane: View {
    /// Not secret: the list column's width.
    @AppStorage("onepass.browse.listWidth", store: AppModel.browseDefaults) private var listWidth = 330.0
    @State private var dragStart: Double?
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    /// The window's title bar (toolbar included), measured from the window.
    @State private var barHeight: CGFloat = 52

    private static let listRange = 280.0...440.0

    var body: some View {
        // The column's root stack: the title bar takes its items from here.
        NavigationStack {
            GeometryReader { proxy in
                // The chosen width, narrowed when the window is tight so the detail keeps its floor.
                let room = Double(proxy.size.width) - 1 - Self.detailMinimum
                let list = min(listWidth.clamped(to: Self.listRange), max(Self.listRange.lowerBound, room))
                HStack(spacing: 0) {
                    ItemListColumn()
                        .frame(width: list)
                        // Rows scrolling up fade out under the bar, as in the sidebar (the table
                        // gets no system edge effect).
                        .mask {
                            VStack(spacing: 0) {
                                Color.clear.frame(height: barHeight)
                                LinearGradient(colors: [.clear, .black], startPoint: .top, endPoint: .bottom)
                                    .frame(height: 12)
                                Rectangle()
                            }
                            .ignoresSafeArea()
                        }
                    divider
                    DetailColumn()
                        .frame(minWidth: Self.detailMinimum, maxWidth: .infinity)
                        .mask { barEdgeFade.ignoresSafeArea() }
                }
                // The title bar's row above: the list's search field fills what its items leave.
                .environment(\.titleBarRoom, proxy.size.width)
                // The pane runs under the title bar (so the detail's wash shows through it). An
                // empty bar of the title bar's height gives the room back: rows and cards start
                // below it, and the detail's scroll view gets the system's soft edge under it.
                .safeAreaBar(edge: .top, spacing: 0) { Color.clear.frame(height: barHeight) }
                // RX: the title bar is see-through; rows and cards only fade softly under it.
                .scrollEdgeEffectStyle(rxDesign ? .soft : .automatic, for: .top)
            }
            .ignoresSafeArea(.container, edges: .top)
            .background { TitlebarHeightReader(height: $barHeight) }
        }
        // No bar background of its own: the title bar shows the detail's wash through, as it did
        // over the detail column alone.
        .toolbarBackgroundVisibility(.hidden, for: .windowToolbar)
        // The split view only knows its columns: this floor keeps the window from shrinking under
        // the narrowest list and detail (and the title bar's row from spilling into its menu).
        .navigationSplitViewColumnWidth(
            min: Self.listRange.lowerBound + 1 + Self.detailMinimum, ideal: 330 + 1 + 520)
    }

    private static let detailMinimum = 320.0

    /// The detail's glow fades in from the list's side across the title bar, so the bar has no
    /// hard edge where the list ends; just below the bar the detail is whole again. Two layers
    /// (their alphas add up): a fade from the left edge, and a band that is opaque below the bar.
    private var barEdgeFade: some View {
        ZStack {
            HStack(spacing: 0) {
                LinearGradient(colors: [.clear, .black], startPoint: .leading, endPoint: .trailing)
                    .frame(width: 110)
                Color.black
            }
            VStack(spacing: 0) {
                Color.clear.frame(height: barHeight)
                LinearGradient(colors: [.clear, .black], startPoint: .top, endPoint: .bottom)
                    .frame(height: 30)
                Rectangle()
            }
        }
    }

    /// The system's thin separator line, with a wider invisible grip and the resize cursor. It stops
    /// under the title bar, so the search field runs across unbroken.
    private var divider: some View {
        Divider()
            .overlay {
                Color.clear
                    .frame(width: 8)
                    .contentShape(Rectangle())
                    .onHover { inside in
                        if inside { NSCursor.columnResize.push() } else { NSCursor.pop() }
                    }
                    .gesture(
                        DragGesture(minimumDistance: 1, coordinateSpace: .global)
                            .onChanged { drag in
                                let start = dragStart ?? listWidth
                                dragStart = start
                                listWidth = (start + drag.translation.width).clamped(to: Self.listRange)
                            }
                            .onEnded { _ in dragStart = nil })
            }
    }
}

private extension Double {
    func clamped(to range: ClosedRange<Double>) -> Double { Swift.min(Swift.max(self, range.lowerBound), range.upperBound) }
}
#endif

/// Right of the sidebar when a full page is chosen. On the Mac the page names itself in its own
/// heading, so the title bar shows no title (the account stays where it is on the item list), and
/// "+" stays where the item list has it.
struct PageColumn: View {
    @Environment(AppModel.self) private var model
    let page: BrowsePage

    var body: some View {
        NavigationStack {
            Group {
                switch page {
                case .watchtower: WatchtowerPage()
                case .crypto: CryptoSplitPage()
                case .developer: DeveloperPage()
                case .duplicates: DuplicatesReviewView(layout: .page)
                case .profile: ProfileView()
                #if os(macOS)
                case .home: RXMacHome()
                #else
                case .home: EmptyView()
                #endif
                case .items: EmptyView()
                }
            }
            #if os(iOS)
            .headerFade(color: Color(uiColor: .systemBackground))
            #endif
            #if os(macOS)
            .toolbar(removing: .title)
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        model.showNewItemPicker = true
                    } label: {
                        Label("Nouvel élément", systemImage: "plus")
                    }
                    .help("browse.newItemN")
                    .accessibilityIdentifier("items.new")
                }
            }
            #endif
        }
    }
}

/// Third column: the new item's editor, the selected item, or an empty state.
struct DetailColumn: View {
    @Environment(AppModel.self) private var model
    #if os(macOS)
    /// The item on screen and its preloaded contents. A click loads the next item first and swaps
    /// only then, crossfading: never an empty frame with a spinner, no wash and no bar items (the
    /// title bar's row would shrink and grow back).
    @State private var shownRef: ItemRef?
    @State private var preloaded: FfiItem?
    #endif

    var body: some View {
        #if os(macOS)
        // Mac: inside the items pane's own stack (a second stack here took the title bar's items).
        content
        #else
        NavigationStack { content }
        #endif
    }

    @ViewBuilder private var content: some View {
        if let draft = model.newItemDraft {
            ItemEditorView(draft: draft, isNew: true) { saved in
                model.finishNewItem(saved)
            }
            .id(draft.item.id)
            #if os(iOS)
            .headerFade()
            #endif
        } else if let ref = model.selectedItem {
            #if os(macOS)
            ZStack {
                if let shownRef {
                    ItemDetailView(ref: shownRef, preloaded: preloaded)
                        .id(shownRef)
                        .transition(.opacity)
                }
            }
            .animation(.easeInOut(duration: 0.18), value: shownRef)
            .task(id: ref) { await show(ref) }
            #else
            ItemDetailView(ref: ref).id(ref)
                #if os(iOS)
                .headerFade()
                #endif
            #endif
        } else {
            // The vault picture alone carries the empty state; the words stay for VoiceOver.
            VaultIllustration(size: 340, tint: Theme.accent)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .accessibilityElement()
                .accessibilityLabel(Text("browse.noItemSelectedChoose"))
        }
    }

    #if os(macOS)
    /// Reads the item, then puts it on screen. A failed read still swaps: the detail shows its error.
    private func show(_ ref: ItemRef) async {
        guard ref != shownRef else { return }
        let item = try? await model.session.loadItem(vaultID: ref.vaultID, itemID: ref.itemID)
        guard !Task.isCancelled, model.selectedItem == ref else { return }
        preloaded = item
        shownRef = ref
    }
    #endif
}
