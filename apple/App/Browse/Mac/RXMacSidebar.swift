#if os(macOS)
import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// The Mac sidebar in the RX look (Penpot "Mac · *"), while the switch is on: flat, on the RX
/// sidebar colour. The OnePass mark and a search field on top, plain rows with small counts and the
/// selected one on a soft accent pill, the vaults with their coloured initials, the tags, Archive
/// and Supprimés récemment, then the account row at the bottom, which opens the account panel.
/// Every row leads where the native sidebar's row leads.
struct RXMacSidebar: View {
    @Environment(AppModel.self) private var model
    @Binding var creatingVault: Bool
    @Binding var editingVaultID: String?
    let duplicateGroups: Int
    @State private var accountMenuOpen = false
    @State private var titlebarHeight: CGFloat = 52

    private typealias RX = Theme.RX
    private var session: VaultSession { model.session }

    var body: some View {
        let counts = session.counts()
        VStack(spacing: 0) {
            // The brand and the search field stay put at the top; only the rows below them scroll.
            // Just under the title bar (traffic lights), on the rows' left edge: the mark, the
            // search field's glass and the row glyphs line up; 12 pt brand to search, 12 pt
            // search to the first row.
            VStack(alignment: .leading, spacing: RX.Space.m) {
                brand
                searchField
            }
            .padding(.horizontal, RX.Space.l)
            .padding(.top, titlebarHeight + RX.Space.xs)
            // A plain list rather than a ScrollView: one row holding the whole column (the window
            // snapshots of the Debug screenshot mode draw a list, not a scroll view, in a sidebar).
            List {
                VStack(alignment: .leading, spacing: RX.Space.xxs) {
                    pageRow("rx.mac.home", symbol: "house.fill", page: .home, id: "sidebar.home")
                    filterRow("Tous les éléments", symbol: "list.bullet.rectangle.fill", count: counts.all,
                              filter: .all, id: "library.all")
                    filterRow("Favoris", symbol: "star.fill", count: counts.favorites, filter: .favorites,
                              id: "library.favorites")
                    filterRow("Passkeys", symbol: "person.badge.key.fill", count: counts.passkeys, filter: .passkeys,
                              id: "library.passkeys")
                    pageRow("Watchtower", symbol: "checkmark.shield.fill", page: .watchtower, id: "sidebar.watchtower")
                    if duplicateGroups > 0 || model.page == .duplicates {
                        pageRow("duplicates.title", symbol: "square.on.square", page: .duplicates,
                                id: "sidebar.duplicates", count: duplicateGroups)
                    }
                    pageRow("crypto.title", symbol: "bitcoinsign.circle.fill", page: .crypto, id: "sidebar.crypto")
                    pageRow("Développeur", symbol: "chevron.left.forwardslash.chevron.right", page: .developer,
                            id: "sidebar.developer")
                    filterRow("À proximité", symbol: "location.fill", count: nil, filter: .nearby, id: "nearby")
                    pageRow("Réglages", symbol: "gearshape.fill", page: .settings, id: "sidebar.settings")
                    vaults(counts)
                    tags(counts)
                    header(Text("rx.mac.more"))
                    filterRow("Archive", symbol: "archivebox.fill", count: counts.archive, filter: .archive,
                              id: "library.archive")
                    filterRow("Supprimés récemment", symbol: "trash.fill", count: counts.trash, filter: .trash,
                              id: "library.trash")
                }
                .padding(.horizontal, RX.Space.l)
                .padding(.top, RX.Space.m)
                .padding(.bottom, RX.Space.l)
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .scrollIndicators(.never)
            .frame(minHeight: 0, maxHeight: .infinity)
            // Rows scrolling up fade out under the search field instead of being cut sharp.
            .mask {
                VStack(spacing: 0) {
                    LinearGradient(colors: [.clear, .black], startPoint: .top, endPoint: .bottom)
                        .frame(height: RX.Space.m)
                    Rectangle()
                }
            }
            footerCards
            accountRow
        }
        .frame(maxHeight: .infinity)
        .ignoresSafeArea(.container, edges: .top)
        .background(RX.Palette.cardBackground.color.ignoresSafeArea())
        .background { TitlebarHeightReader(height: $titlebarHeight) }
        .overlay(alignment: .bottomLeading) {
            if accountMenuOpen {
                ZStack(alignment: .bottomLeading) {
                    Color.black.opacity(0.001)
                        .ignoresSafeArea()
                        // swiftlint:disable:next db_on_tap_gesture - the dismiss scrim of the menu, not an action
                        .onTapGesture { accountMenuOpen = false }
                    AccountMenuPanel(
                        newVault: { accountMenuOpen = false; creatingVault = true },
                        close: { accountMenuOpen = false })
                        .padding(.bottom, RX.Space.xxl * 2)
                        .padding(.horizontal, RX.Space.s)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .transition(.opacity)
                }
            }
        }
        .dbAnimation(.snappy, value: accountMenuOpen)
        .accessibilityIdentifier("rx.mac.sidebar")
    }

    // MARK: - Parts

    private var brand: some View {
        HStack(spacing: RX.Space.m) {
            Image(systemName: "circle.grid.3x3.fill")
                .font(RX.Glyph.font(RX.Glyph.macBrand, weight: .bold))
                .foregroundStyle(RX.Palette.accent.color)
                .frame(width: RX.Metrics.macRowGlyph)
            // swiftlint:disable:next db_unlocalized_string - app name, the same in every language
            Text(verbatim: "OnePass")
                .rxFont(.headline)
                .foregroundStyle(RX.Palette.textPrimary.color)
        }
        .padding(.horizontal, RX.Space.s)
        .frame(height: RX.Metrics.macRowHeight)
        .accessibilityElement(children: .combine)
    }

    /// Not a field: it opens all items with the list's search field focused (⌘F does the same).
    private var searchField: some View {
        Button {
            model.showItems(.all)
            model.searchFocusRequest &+= 1
        } label: {
            HStack(spacing: RX.Space.m) {
                Image(systemName: "magnifyingglass")
                    .frame(width: RX.Metrics.macRowGlyph)
                Text("common.search")
                Spacer(minLength: 0)
                Text(verbatim: "⌘F").rxFont(.footnote)
            }
            .rxFont(.callout)
            .foregroundStyle(RX.Palette.textSecondary.color)
            .padding(.horizontal, RX.Space.s)
            .frame(height: RX.Metrics.macRowHeight)
            .background(RX.Palette.field.color, in: RoundedRectangle(cornerRadius: RX.Radius.macRow, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("rx.mac.search")
    }

    @ViewBuilder private func vaults(_ counts: ItemCounts) -> some View {
        HStack {
            header(Text("Coffres"))
            Spacer()
            Button { creatingVault = true } label: {
                Image(systemName: "plus")
                    .font(RX.Glyph.font(RX.Glyph.macSmall, weight: .semibold))
                    .frame(width: RX.Metrics.macAddButton, height: RX.Metrics.macAddButton)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(RX.Palette.textTertiary.color)
            .help("Nouveau coffre")
            .accessibilityLabel(Text("Nouveau coffre"))
            .accessibilityIdentifier("sidebar.vaults.new")
            .padding(.top, RX.Space.l)
        }
        ForEach(session.vaults, id: \.id) { vault in
            let filter = ItemFilter.vault(vault.id)
            rowButton(selected: isSelected(filter), id: "sidebar.vaults.\(vault.id)", action: { model.showItems(filter) }) {
                Text(String(vault.meta.name.prefix(1)).uppercased())
                    .font(RX.Glyph.font(RX.Glyph.macInitial, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(width: RX.Metrics.macRowGlyph, height: RX.Metrics.macRowGlyph)
                    .background(VaultBadge.color(named: vault.meta.color), in: Circle())
                    .accessibilityHidden(true)
                Text(vault.meta.name)
                count(counts.byVault[vault.id])
            }
            .contextMenu {
                Button("browse.editVault", systemImage: "paintpalette") { editingVaultID = vault.id }
            }
        }
    }

    @ViewBuilder private func tags(_ counts: ItemCounts) -> some View {
        let tags = counts.byTag.keys.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        if !tags.isEmpty {
            header(Text("Tags"))
            ForEach(tags, id: \.self) { tag in
                let filter = ItemFilter.tag(tag)
                rowButton(selected: isSelected(filter), id: "sidebar.tags.\(tag)", action: { model.showItems(filter) }) {
                    Circle()
                        .fill(TagColor.of(tag))
                        .frame(width: RX.Metrics.macTagDot, height: RX.Metrics.macTagDot)
                        .frame(width: RX.Metrics.macRowGlyph, height: RX.Metrics.macRowGlyph)
                        .accessibilityHidden(true)
                    Text(tag)
                    count(counts.byTag[tag])
                }
            }
        }
    }

    /// The cards the native sidebar shows over its footer (travel, AutoFill, Safari, sync).
    private var footerCards: some View {
        VStack(spacing: RX.Space.s) {
            if model.travel.showsCard {
                TravelSuggestionCard(compact: true)
                    .padding(RX.Space.m)
                    .background(RX.Palette.pageBackground.color, in: RoundedRectangle(cornerRadius: RX.Radius.tile, style: .continuous))
            }
            if model.showsAutoFillTip {
                AutoFillTipCard(compact: true)
                    .padding(.horizontal, RX.Space.m)
                    .padding(.vertical, RX.Space.s)
                    .background(RX.Palette.pageBackground.color, in: RoundedRectangle(cornerRadius: RX.Radius.tile, style: .continuous))
            }
            if model.showsSafariSetupCard {
                SafariSetupCard()
                    .padding(RX.Space.m)
                    .background(RX.Palette.pageBackground.color, in: RoundedRectangle(cornerRadius: RX.Radius.tile, style: .continuous))
            }
            if case .accountChanged = model.syncStatus {
                AccountChangedCard(compact: true)
            } else {
                SyncStatusChip(status: model.syncStatus)
            }
        }
        .padding(.horizontal, RX.Space.m)
    }

    /// The account at the bottom: avatar, name, the kind of device; it opens the account panel.
    private var accountRow: some View {
        let _ = model.settingsRevision
        let name = model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName
        return Button { accountMenuOpen.toggle() } label: {
            HStack(spacing: RX.Space.m) {
                RXAvatar(initials: model.initials, photo: model.profileImage, size: RX.Metrics.avatarSmall, ring: false)
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: name)
                        .rxFont(.calloutMedium)
                        .foregroundStyle(RX.Palette.textPrimary.color)
                        .dbText(maxLines: 2)
                    Text(model.settings.deviceMode == .shared
                         ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                        .rxFont(.footnote)
                        .foregroundStyle(RX.Palette.textSecondary.color)
                        .dbText(maxLines: 2)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.up.chevron.down")
                    .font(RX.Glyph.font(RX.Glyph.macSmall, weight: .semibold))
                    .foregroundStyle(RX.Palette.textTertiary.color)
            }
            .padding(.horizontal, RX.Space.l)
            .frame(minHeight: RX.Metrics.macAccountRowHeight)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("sidebar.account")
    }

    // MARK: - Rows

    private func header(_ title: Text) -> some View {
        title
            .rxFont(.caption)
            .textCase(.uppercase)
            .foregroundStyle(RX.Palette.textTertiary.color)
            .padding(.horizontal, RX.Space.s)
            .padding(.top, RX.Space.l)
            .padding(.bottom, RX.Space.xs)
            .accessibilityAddTraits(.isHeader)
    }

    private func isSelected(_ filter: ItemFilter) -> Bool {
        model.page == .items && model.selection == filter
    }

    private func filterRow(
        _ title: LocalizedStringKey, symbol: String, count value: Int?, filter: ItemFilter, id: String
    ) -> some View {
        rowButton(selected: isSelected(filter), id: "sidebar.\(id)", action: { model.showItems(filter) }) {
            glyph(symbol)
            Text(title)
            count(value)
        }
    }

    private func pageRow(
        _ title: LocalizedStringKey, symbol: String, page: BrowsePage, id: String, count value: Int? = nil
    ) -> some View {
        rowButton(selected: model.page == page, id: id, action: { model.page = page }) {
            glyph(symbol)
            Text(title)
            count(value)
        }
    }

    private func glyph(_ symbol: String) -> some View {
        Image(systemName: symbol)
            .font(RX.Glyph.font(RX.Glyph.macRow, weight: .semibold))
            .frame(width: RX.Metrics.macRowGlyph, height: RX.Metrics.macRowGlyph)
            .accessibilityHidden(true)
    }

    @ViewBuilder private func count(_ value: Int?) -> some View {
        Spacer(minLength: RX.Space.s)
        if let value, value > 0 {
            Text(value, format: .number)
                .rxFont(.footnote)
                .monospacedDigit()
                .foregroundStyle(RX.Palette.textTertiary.color)
        }
    }

    /// A plain row; the selected one on a soft accent pill, in the accent.
    private func rowButton<Content: View>(
        selected: Bool, id: String, action: @escaping () -> Void, @ViewBuilder content: () -> Content
    ) -> some View {
        Button(action: action) {
            HStack(spacing: RX.Space.m) { content() }
                .rxFont(selected ? .calloutMedium : .callout)
                .foregroundStyle(selected ? RX.Palette.accentText.color : RX.Palette.textPrimary.color)
                .padding(.horizontal, RX.Space.s)
                .frame(minHeight: RX.Metrics.macRowHeight)
                .background {
                    if selected {
                        RoundedRectangle(cornerRadius: RX.Radius.macRow, style: .continuous)
                            .fill(RX.Palette.accentSoft.color)
                    }
                }
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier(id)
    }
}
#endif
