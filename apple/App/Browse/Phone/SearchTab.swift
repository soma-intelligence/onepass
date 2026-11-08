#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Rechercher (spec 6.2, mockup `PhoneSearch`): the search tab (role `.search`) searches every
/// active item. The search field belongs to the tab view (`PhoneTabsView`): iOS 26 shows it in
/// the tab bar only when `searchable` is applied there.
///
/// Before anything is typed the screen helps start: the recent searches of this session (memory
/// only, gone on lock), the items opened lately, and the categories to browse. Once a word is typed
/// the results come at every key, best answers first (`ItemSearch.ranked`), with scope chips (the
/// categories among the results, and their counts) to narrow them. Nothing found says what to try.
struct SearchTab: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Binding var query: String
    @Binding var isSearching: Bool
    @State private var category: FfiItemType?

    private var session: VaultSession { model.session }
    private var trimmed: String { query.trimmingCharacters(in: .whitespaces) }

    var body: some View {
        let all = session.items(filter: .all, query: "", sort: .title)
        let matches = ItemSearch.ranked(all, query: trimmed)
        let results = category.map { type in matches.filter { $0.itemType == type } } ?? matches
        let showVault = session.vaults.count > 1
        List {
            if all.isEmpty {
                emptyVault
            } else if trimmed.isEmpty, category == nil {
                start(all: all)
            } else {
                let present = scopes(in: trimmed.isEmpty ? all : matches)
                if present.count > 1 || category != nil {
                    Section {
                        chips(present, total: trimmed.isEmpty ? all.count : matches.count)
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(Color.clear)
                    }
                    .listSectionSpacing(8)
                }
                if results.isEmpty {
                    noResults
                } else {
                    Section {
                        ForEach(results, id: \.id) { summary in
                            resultRow(summary, vaultName: showVault ? vaultName(summary.vaultId) : nil)
                        }
                    } header: {
                        PhoneSectionLabel(verbatim: resultsTitle(count: results.count))
                            .textCase(nil)
                            .contentTransition(.numericText())
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .scrollDismissesKeyboard(.immediately)
        .background(PhoneBackground())
        .animation(Motion.list(reduceMotion: reduceMotion), value: results.map(\.id))
        .animation(Motion.fold(reduceMotion: reduceMotion), value: trimmed.isEmpty)
        .navigationTitle("common.search")
        // A category chosen for another search would hide what the next one finds.
        .onChange(of: trimmed.isEmpty) { _, empty in if empty { category = nil } }
        // Opening a result keeps the search that found it for next time.
        .onChange(of: model.selectedItem) { _, opened in
            if opened != nil, isSearching, !trimmed.isEmpty { session.noteSearch(trimmed) }
        }
    }

    // MARK: Before typing

    @ViewBuilder private func start(all: [FfiItemSummary]) -> some View {
        let searches = session.recentSearches
        if !searches.isEmpty {
            Section {
                ForEach(searches, id: \.self) { text in
                    Button {
                        query = text
                        isSearching = true
                    } label: {
                        HStack(spacing: Theme.Space.m) {
                            Image(systemName: "clock.arrow.circlepath")
                                .font(.body)
                                .foregroundStyle(.secondary)
                                .frame(width: 30)
                            Text(verbatim: text)
                                .foregroundStyle(.primary)
                                .lineLimit(1)
                            Spacer(minLength: 4)
                            Image(systemName: "arrow.up.left")
                                .font(.footnote.weight(.semibold))
                                .foregroundStyle(.tertiary)
                        }
                        .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text("browse.searchFor \(text)"))
                }
            } header: {
                HStack(alignment: .firstTextBaseline) {
                    PhoneSectionLabel("Recherches récentes")
                    Spacer()
                    Button("browse.clear") {
                        withAnimation(Motion.list(reduceMotion: reduceMotion)) { session.clearRecentSearches() }
                    }
                    .font(.subheadline)
                    .accessibilityIdentifier("search.recent.clear")
                }
                .textCase(nil)
            }
            .accessibilityIdentifier("search.recent")
        }
        let opened = recentlyOpened(all)
        if !opened.isEmpty {
            Section {
                ForEach(opened, id: \.id) { summary in
                    resultRow(summary, vaultName: nil)
                }
            } header: {
                PhoneSectionLabel("Ouverts récemment").textCase(nil)
            }
        }
        Section {
            browseGrid(all)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
        } header: {
            PhoneSectionLabel("Parcourir").textCase(nil)
        }
    }

    /// Items opened during the session, newest first (at most five).
    private func recentlyOpened(_ all: [FfiItemSummary]) -> [FfiItemSummary] {
        let byID = Dictionary(all.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return Array(session.recents.compactMap { byID[$0] }.prefix(5))
    }

    /// The categories present, two to a row: the type's artwork, its name and its count. A tile
    /// shows that category; typing then searches inside it.
    private func browseGrid(_ all: [FfiItemSummary]) -> some View {
        let present = scopes(in: all)
        return LazyVGrid(columns: [GridItem(.flexible(), spacing: Theme.Space.m), GridItem(.flexible(), spacing: Theme.Space.m)], spacing: Theme.Space.m) {
            ForEach(present, id: \.type) { scope in
                Button {
                    withAnimation(Motion.fold(reduceMotion: reduceMotion)) { category = scope.type }
                } label: {
                    HStack(spacing: Theme.Space.m) {
                        CategoryArtwork(type: scope.type, size: 30)
                        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                            Text(ItemCategory.of(scope.type).plural)
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.primary)
                                .lineLimit(1)
                                .minimumScaleFactor(0.85)
                            Text(scope.count, format: .number)
                                .font(.caption)
                                .monospacedDigit()
                                .foregroundStyle(.tertiary)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, Theme.Space.m)
                    .frame(maxWidth: .infinity, minHeight: 56, alignment: .leading)
                    .phoneCard()
                    .contentShape(.rect(cornerRadius: PhoneCard.radius))
                }
                .buttonStyle(PressableButtonStyle())
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("search.browse.\(NewItemMenu.key(scope.type))")
            }
        }
    }

    // MARK: Results

    private func resultRow(_ summary: FfiItemSummary, vaultName: String?) -> some View {
        // No gesture on the link: a simultaneous tap gesture on a NavigationLink in a List swallowed
        // the tap on iOS 27 and the result never opened. The search is noted when the selection
        // moves to the opened result (`onChange(of: model.selectedItem)` above).
        NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: summary.vaultId, itemID: summary.id))) {
            ItemListRow(summary: summary, vaultName: vaultName)
        }
        .itemZoomSource(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
    }

    private struct Scope: Equatable {
        let type: FfiItemType
        let count: Int
    }

    /// The categories among `items`, in the house order, with their counts.
    private func scopes(in items: [FfiItemSummary]) -> [Scope] {
        var counts: [FfiItemType: Int] = [:]
        for item in items { counts[item.itemType, default: 0] += 1 }
        return ItemCategory.all.compactMap { category in
            counts[category.type].map { Scope(type: category.type, count: $0) }
        }
    }

    private func chips(_ scopes: [Scope], total: Int) -> some View {
        ScrollView(.horizontal) {
            HStack(spacing: Theme.Space.s) {
                chip(String(localized: "browse.all"), type: nil, count: total, selected: category == nil, id: "search.category.all") {
                    category = nil
                }
                // A category chosen keeps its chip even when the search no longer finds it.
                let shown = category.flatMap { chosen in scopes.contains { $0.type == chosen } ? nil : Scope(type: chosen, count: 0) }
                ForEach(scopes + (shown.map { [$0] } ?? []), id: \.type) { scope in
                    chip(ItemCategory.of(scope.type).plural, type: scope.type, count: scope.count,
                        selected: category == scope.type, id: "search.category.\(NewItemMenu.key(scope.type))") {
                        category = category == scope.type ? nil : scope.type
                    }
                }
            }
            // The inset grouped list's row inset: the chips line up with the rows below.
            .padding(.horizontal, 20)
            .padding(.vertical, Theme.Space.xxs)
        }
        .scrollIndicators(.hidden)
        .sensoryFeedback(.selection, trigger: category)
    }

    /// A scope chip: the type's artwork, its name and its count; the chosen one in the accent.
    private func chip(
        _ label: String, type: FfiItemType?, count: Int, selected: Bool, id: String, action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: Theme.Space.s) {
                if let type { CategoryArtwork(type: type, size: 20) }
                Text(label).font(.subheadline.weight(.semibold))
                Text(count, format: .number)
                    .font(.subheadline)
                    .monospacedDigit()
                    .foregroundStyle(selected ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.tertiary))
                    .contentTransition(.numericText())
            }
            .padding(.leading, type == nil ? Theme.Space.l : Theme.Space.s)
            .padding(.trailing, Theme.Space.l)
            .frame(height: 34)
            .foregroundStyle(selected ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .background(selected ? Theme.accent : Color(uiColor: .secondarySystemGroupedBackground), in: Capsule())
            .overlay { Capsule().strokeBorder(Color.primary.opacity(selected ? 0 : 0.06)) }
            .animation(.easeOut(duration: 0.15), value: selected)
            // 34 pt chip, 44 pt target.
            .contentShape(Rectangle().inset(by: -5))
        }
        .buttonStyle(PressableButtonStyle())
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier(id)
    }

    private func resultsTitle(count: Int) -> String {
        if trimmed.isEmpty, let category { return ItemCategory.of(category).plural }
        return count == 1 ? String(localized: "browse.n1Result") : String(localized: "browse.results \(count)")
    }

    // MARK: Empty states

    /// Nothing found: what was searched, what to try, and the way out of a category.
    private var noResults: some View {
        Section {
            VStack(spacing: Theme.Space.m) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 34, weight: .regular))
                    .foregroundStyle(.tertiary)
                    .padding(.bottom, Theme.Space.xxs)
                Text(trimmed.isEmpty ? String(localized: "browse.nothingInCategory")
                    : String(localized: "browse.noResultsFor \(trimmed)"))
                    .font(.headline)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("search.empty")
                Text(category == nil
                    ? String(localized: "browse.searchForTitleWebsite")
                    : String(localized: "browse.searchLooksInOne"))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                if category != nil {
                    Button("browse.searchEverywhere") {
                        withAnimation(Motion.fold(reduceMotion: reduceMotion)) { category = nil }
                    }
                    .buttonStyle(.glass)
                    .padding(.top, Theme.Space.xs)
                    .accessibilityIdentifier("search.everywhere")
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 28)
            .listRowBackground(Color.clear)
        }
    }

    private var emptyVault: some View {
        Section {
            ItemListEmptyState(reason: .emptyLibrary) { model.showNewItemPicker = true }
                .padding(.vertical, 40)
                .listRowBackground(Color.clear)
                .accessibilityIdentifier("search.empty")
        }
    }

    private func vaultName(_ id: String) -> String? {
        session.allVaults.first { $0.id == id }?.meta.name
    }
}
#endif
