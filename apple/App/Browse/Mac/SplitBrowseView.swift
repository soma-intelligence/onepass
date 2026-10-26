import DesignKit
import SwiftUI
import VaultKit

/// Mac window and iPad in regular width (spec 6.1, 6.3, mockup `Main`): sidebar, item list, detail.
/// Edition happens in place in the detail column.
struct SplitBrowseView: View {
    @State private var visibility: NavigationSplitViewVisibility = .all

    var body: some View {
        NavigationSplitView(columnVisibility: $visibility) {
            Sidebar()
                #if os(macOS)
                .navigationSplitViewColumnWidth(min: 210, ideal: 240, max: 320)
                #else
                .navigationSplitViewColumnWidth(min: 260, ideal: 300, max: 360)
                #endif
        } content: {
            ItemListColumn()
                .navigationSplitViewColumnWidth(min: 280, ideal: 330, max: 440)
        } detail: {
            DetailColumn()
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
}

/// Third column: the new item's editor, the selected item, or an empty state.
struct DetailColumn: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        NavigationStack {
            if let draft = model.newItemDraft {
                ItemEditorView(draft: draft, isNew: true) { saved in
                    model.finishNewItem(saved)
                }
                .id(draft.item.id)
            } else if let ref = model.selectedItem {
                ItemDetailView(ref: ref).id(ref)
            } else {
                EmptyState(
                    title: String(localized: "Aucun élément sélectionné"), systemImage: "rectangle.portrait.on.rectangle.portrait",
                    message: String(localized: "Choisis un élément dans la liste."))
            }
        }
    }
}
