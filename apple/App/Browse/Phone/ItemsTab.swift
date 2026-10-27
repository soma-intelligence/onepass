#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Éléments (spec 6.2, mockup `PhoneItems`): foldable blocks Coffres (letter disc and count,
/// "Nouveau coffre"), Catégories (types present only, color tiles) and Tags (colored tags), then
/// Archive and Supprimés récemment ("N · 30 jours"). Each row opens its filtered list.
struct ItemsTab: View {
    @Environment(AppModel.self) private var model
    @State private var creatingVault = false
    @AppStorage("onepass.items.vaultsOpen", store: AppModel.browseDefaults) private var vaultsOpen = true
    @AppStorage("onepass.items.categoriesOpen", store: AppModel.browseDefaults) private var categoriesOpen = true
    @AppStorage("onepass.items.tagsOpen", store: AppModel.browseDefaults) private var tagsOpen = true

    private var session: VaultSession { model.session }

    var body: some View {
        let counts = session.counts()
        let categories = ItemCategory.all.filter { (counts.byType[$0.type] ?? 0) > 0 }
        let tags = counts.byTag.keys.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        List {
            SyncRefusalSection()
            AccountChangedSection()
            Section {
                if vaultsOpen {
                    ForEach(session.vaults, id: \.id) { vault in
                        row(.vault(vault.id), id: "items.vaults.\(vault.id)") {
                            VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 32)
                        } label: {
                            Text(vault.meta.name)
                        } count: {
                            Text(counts.byVault[vault.id] ?? 0, format: .number)
                        }
                    }
                    Button {
                        creatingVault = true
                    } label: {
                        Label {
                            Text("Nouveau coffre")
                        } icon: {
                            Image(systemName: "plus").frame(width: 32)
                        }
                    }
                    .accessibilityIdentifier("items.vaults.new")
                }
            } header: {
                FoldHeader(title: "Coffres", isOpen: $vaultsOpen, id: "items.vaults")
            }
            if !categories.isEmpty {
                Section {
                    if categoriesOpen {
                        ForEach(categories) { category in
                            row(.category(category.type), id: "items.categories.\(NewItemMenu.key(category.type))") {
                                CategoryTile(category: category, size: 32)
                            } label: {
                                Text(category.plural)
                            } count: {
                                Text(counts.byType[category.type] ?? 0, format: .number)
                            }
                        }
                    }
                } header: {
                    FoldHeader(title: "Catégories", isOpen: $categoriesOpen, id: "items.categories")
                }
            }
            if !tags.isEmpty {
                Section {
                    if tagsOpen {
                        ForEach(tags, id: \.self) { tag in
                            row(.tag(tag), id: "items.tags.\(tag)") {
                                Image(systemName: "tag.fill")
                                    .font(.system(size: 18))
                                    .foregroundStyle(TagColor.of(tag))
                                    .frame(width: 32, height: 32)
                                    .accessibilityHidden(true)
                            } label: {
                                Text(tag)
                            } count: {
                                Text(counts.byTag[tag] ?? 0, format: .number)
                            }
                        }
                    }
                } header: {
                    FoldHeader(title: "Tags", isOpen: $tagsOpen, id: "items.tags")
                }
            }
            Section {
                row(.nearby, id: "items.nearby") {
                    NearbyTile(size: 32)
                } label: {
                    Text("À proximité")
                } count: {
                    Text("2 km")
                }
            }
            Section {
                row(.archive, id: "items.archive") {
                    Image(systemName: "archivebox")
                        .font(.system(size: 19))
                        .foregroundStyle(.secondary)
                        .frame(width: 32, height: 32)
                        .accessibilityHidden(true)
                } label: {
                    Text("Archive")
                } count: {
                    Text(counts.archive, format: .number)
                }
            }
            Section {
                row(.trash, id: "items.trash") {
                    Image(systemName: "trash")
                        .font(.system(size: 19))
                        .foregroundStyle(.red)
                        .frame(width: 32, height: 32)
                        .accessibilityHidden(true)
                } label: {
                    Text("Supprimés récemment")
                } count: {
                    Text("\(counts.trash) · 30 jours")
                }
            }
        }
        .listStyle(.insetGrouped)
        .listSectionSpacing(14)
        .navigationTitle("Éléments")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar { PhoneRootToolbar() }
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
        }
    }

    private func row(
        _ filter: ItemFilter, id: String, @ViewBuilder icon: () -> some View, @ViewBuilder label: () -> Text,
        @ViewBuilder count: () -> Text
    ) -> some View {
        NavigationLink(value: PhoneRoute.list(filter)) {
            HStack(spacing: 12) {
                icon()
                label()
                    .lineLimit(1)
                Spacer(minLength: 8)
                count()
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(id)
    }
}

/// Section title of the Éléments tab (mockup: large title and a chevron that folds the block).
struct FoldHeader: View {
    let title: LocalizedStringKey
    @Binding var isOpen: Bool
    let id: String

    var body: some View {
        Button {
            withAnimation(.snappy) { isOpen.toggle() }
        } label: {
            HStack {
                Text(title)
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.primary)
                Spacer()
                Image(systemName: "chevron.down")
                    .font(.footnote.weight(.bold))
                    .foregroundStyle(.tint)
                    .rotationEffect(.degrees(isOpen ? 0 : -90))
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .textCase(nil)
        .accessibilityAddTraits(.isHeader)
        .accessibilityValue(isOpen ? Text("Déplié") : Text("Replié"))
        .accessibilityIdentifier(id)
    }
}
#endif
