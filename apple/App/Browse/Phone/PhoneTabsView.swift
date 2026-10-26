import DesignKit
import SwiftUI
import VaultKit

/// Placeholder for iPhone and iPad in compact width until the iPhone tabs land (Task 15 replaces
/// this file): every active item, its detail and editor in a navigation stack, lock and new item.
struct PhoneTabsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let items = model.session.items(filter: .all, query: "", sort: .title)
        NavigationStack {
            List(items, id: \.id) { summary in
                NavigationLink(value: ItemRef(vaultID: summary.vaultId, itemID: summary.id)) {
                    ItemListRow(summary: summary, vaultName: nil)
                }
            }
            .overlay {
                if items.isEmpty {
                    EmptyState(
                        title: String(localized: "Aucun élément ne correspond."), systemImage: "tray",
                        message: String(localized: "Crée un élément avec « Nouvel élément »."))
                }
            }
            .navigationTitle("Éléments")
            .navigationDestination(for: ItemRef.self) { ref in
                ItemDetailView(ref: ref).id(ref)
            }
            .toolbar {
                if !model.isEditing {
                    ToolbarItem(placement: .navigation) {
                        Button("Verrouiller", systemImage: "lock") { model.perform(.lock) }
                            .accessibilityIdentifier("account.lock")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        NewItemMenu { model.perform(.newItem($0)) }
                    } label: {
                        Label("Nouvel élément", systemImage: "plus")
                    }
                    .accessibilityIdentifier("items.new")
                }
            }
        }
        .sheet(isPresented: newItemShown) {
            if let draft = model.newItemDraft {
                NavigationStack {
                    ItemEditorView(draft: draft, isNew: true) { saved in model.finishNewItem(saved) }
                }
            }
        }
    }

    private var newItemShown: Binding<Bool> {
        Binding(
            get: { model.newItemDraft != nil },
            set: { if !$0 { model.finishNewItem(nil) } })
    }
}
