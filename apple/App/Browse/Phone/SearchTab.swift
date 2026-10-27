#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Rechercher (spec 6.2, mockup `PhoneSearch`): the search tab (role `.search`) searches every
/// active item. The search field belongs to the tab view (`PhoneTabsView`): iOS 26 shows it in
/// the tab bar only when `searchable` is applied there.
/// Category chips (types present only) narrow the results; with an empty search they are the
/// suggestions and the list shows every item of the chosen category.
struct SearchTab: View {
    @Environment(AppModel.self) private var model
    @Binding var query: String
    @Binding var isSearching: Bool
    @State private var category: FfiItemType?

    private var session: VaultSession { model.session }

    var body: some View {
        let counts = session.counts()
        let categories = ItemCategory.all.filter { (counts.byType[$0.type] ?? 0) > 0 }
        let filter: ItemFilter = category.map { .category($0) } ?? .all
        let results = session.items(filter: filter, query: query, sort: .title)
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        let showVault = session.vaults.count > 1
        List {
            if !categories.isEmpty {
                Section {
                    chips(categories)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }
            }
            Section {
                ForEach(results, id: \.id) { summary in
                    NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: summary.vaultId, itemID: summary.id))) {
                        ItemListRow(summary: summary, vaultName: showVault ? vaultName(summary.vaultId) : nil)
                    }
                }
                if results.isEmpty {
                    Text(trimmed.isEmpty ? String(localized: "Ce coffre est vide")
                        : String(localized: "Aucun résultat pour « \(trimmed) »"))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 18)
                        .accessibilityIdentifier("search.empty")
                }
            } header: {
                HStack(alignment: .firstTextBaseline) {
                    Text(resultsTitle(searching: !trimmed.isEmpty))
                        .font(.title3.weight(.bold))
                        .foregroundStyle(.primary)
                    Spacer()
                    Text(ItemListColumn.countLabel(results.count))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .textCase(nil)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Rechercher")
    }

    private func chips(_ categories: [ItemCategory]) -> some View {
        ScrollView(.horizontal) {
            HStack(spacing: 8) {
                chip(String(localized: "Tout"), selected: category == nil, id: "search.category.all") {
                    category = nil
                }
                ForEach(categories) { item in
                    chip(item.plural, selected: category == item.type, id: "search.category.\(NewItemMenu.key(item.type))") {
                        category = category == item.type ? nil : item.type
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 2)
        }
        .scrollIndicators(.hidden)
    }

    private func chip(_ label: String, selected: Bool, id: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(label)
                .font(.subheadline.weight(.semibold))
                .padding(.horizontal, 14)
                .frame(height: 34)
                .foregroundStyle(selected ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
                .background(selected ? AnyShapeStyle(Theme.accent) : AnyShapeStyle(.fill.tertiary), in: Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier(id)
    }

    private func resultsTitle(searching: Bool) -> String {
        if let category { return ItemCategory.of(category).plural }
        return searching ? String(localized: "Résultats") : String(localized: "Tous les éléments")
    }

    private func vaultName(_ id: String) -> String? {
        session.allVaults.first { $0.id == id }?.meta.name
    }
}
#endif
