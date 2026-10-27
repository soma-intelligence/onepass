#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Éléments (spec 6.2, mockup `PhoneItems`), the Mac sidebar as cards: foldable blocks Coffres
/// (letter disc and count, "Nouveau coffre"), Catégories (types present only, illustrated
/// artwork) and Tags (colored dots), then Archive and Supprimés récemment ("N · 30 jours"). Each row
/// opens its filtered list.
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
                            VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 30)
                        } label: {
                            Text(vault.meta.name)
                        } count: {
                            Text(counts.byVault[vault.id] ?? 0, format: .number)
                        }
                    }
                    Button {
                        creatingVault = true
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "plus")
                                .font(.system(size: 15, weight: .semibold))
                                .frame(width: 30, height: 30)
                                .background(Theme.accent.opacity(0.12), in: Circle())
                            Text("Nouveau coffre")
                        }
                        .foregroundStyle(Theme.accent)
                    }
                    .accessibilityIdentifier("items.vaults.new")
                }
            } header: {
                FoldHeader(title: "coffres", isOpen: $vaultsOpen, id: "items.vaults")
            }
            if !categories.isEmpty {
                Section {
                    if categoriesOpen {
                        ForEach(categories) { category in
                            row(.category(category.type), id: "items.categories.\(NewItemMenu.key(category.type))") {
                                CategoryTile(category: category, size: 30)
                            } label: {
                                Text(category.plural)
                            } count: {
                                Text(counts.byType[category.type] ?? 0, format: .number)
                            }
                        }
                    }
                } header: {
                    FoldHeader(title: "catégories", isOpen: $categoriesOpen, id: "items.categories")
                }
            }
            if !tags.isEmpty {
                Section {
                    if tagsOpen {
                        ForEach(tags, id: \.self) { tag in
                            row(.tag(tag), id: "items.tags.\(tag)") {
                                Circle()
                                    .fill(TagColor.of(tag).gradient)
                                    .frame(width: 12, height: 12)
                                    .frame(width: 30, height: 30)
                                    .accessibilityHidden(true)
                            } label: {
                                Text(tag)
                            } count: {
                                Text(counts.byTag[tag] ?? 0, format: .number)
                            }
                        }
                    }
                } header: {
                    FoldHeader(title: "tags", isOpen: $tagsOpen, id: "items.tags")
                }
            }
            Section {
                row(.nearby, id: "items.nearby") {
                    NearbyTile(size: 30)
                } label: {
                    Text("À proximité")
                } count: {
                    Text("2 km")
                }
            }
            Section {
                row(.archive, id: "items.archive") {
                    SymbolTile(symbol: "archivebox.fill", color: Color(white: 0.55), size: 30)
                        .accessibilityHidden(true)
                } label: {
                    Text("Archive")
                } count: {
                    Text(counts.archive, format: .number)
                }
            }
            Section {
                row(.trash, id: "items.trash") {
                    SymbolTile(symbol: "trash.fill", color: .red, size: 30)
                        .accessibilityHidden(true)
                } label: {
                    Text("Supprimés récemment")
                } count: {
                    Text("\(counts.trash) · 30 jours")
                }
            }
        }
        .listStyle(.insetGrouped)
        .listSectionSpacing(18)
        .scrollContentBackground(.hidden)
        .background(PhoneBackground())
        .navigationTitle("Éléments")
        .navigationBarTitleDisplayMode(.large)
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

/// Section title of the Éléments tab: the small accent label of the Mac cards and a chevron that
/// folds the block.
struct FoldHeader: View {
    let title: LocalizedStringKey
    @Binding var isOpen: Bool
    let id: String

    var body: some View {
        Button {
            withAnimation(.snappy) { isOpen.toggle() }
        } label: {
            HStack {
                PhoneSectionLabel(title)
                Spacer()
                Image(systemName: "chevron.down")
                    .font(.footnote.weight(.bold))
                    .foregroundStyle(.secondary)
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
