import DesignKit
import SwiftUI
import VaultKit

/// Link to another item: shows the linked title, opens a searchable list of items to pick one.
struct ItemLinkPicker: View {
    @Environment(AppModel.self) private var model
    let field: FfiField
    /// The item being edited, left out of the list.
    let ownID: String
    @Binding var value: FfiFieldValue
    @State private var picking = false

    private var linkedID: String? {
        if case .itemLink(let id) = value, !id.isEmpty { id } else { nil }
    }

    var body: some View {
        HStack {
            Button {
                picking = true
            } label: {
                if let id = linkedID {
                    Label(Self.title(of: id, in: model.session), systemImage: "link")
                } else {
                    Text("Choisir un élément")
                }
            }
            .accessibilityIdentifier("editor.field.\(field.id)")
            Spacer()
            if linkedID != nil {
                Button("Retirer", systemImage: "xmark.circle.fill") { value = .empty }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
            }
        }
        .sheet(isPresented: $picking) {
            ItemPickerList(excluding: ownID) { picked in
                value = .itemLink(itemId: picked.id)
                picking = false
            }
        }
    }

    static func title(of id: String, in session: VaultSession) -> String {
        session.summaries.first { $0.id == id }?.title ?? String(localized: "Élément introuvable")
    }
}

/// Searchable list of live items (no archive, no trash, no hidden vault).
private struct ItemPickerList: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let excluding: String
    let onPick: (FfiItemSummary) -> Void
    @State private var query = ""

    var body: some View {
        NavigationStack {
            List(model.session.items(filter: .all, query: query, sort: .title).filter { $0.id != excluding }, id: \.id) {
                summary in
                Button {
                    onPick(summary)
                } label: {
                    HStack(spacing: 12) {
                        ItemIcon(type: summary.itemType, title: summary.title, siteIcon: nil, size: 30)
                        VStack(alignment: .leading) {
                            Text(summary.title).foregroundStyle(.primary)
                            if !summary.subtitle.isEmpty {
                                Text(summary.subtitle).font(.footnote).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .searchable(text: $query, prompt: Text("Rechercher"))
            .navigationTitle("Lier un élément")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 380, minHeight: 420)
        #endif
    }
}
