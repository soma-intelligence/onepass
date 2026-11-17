import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

#if os(iOS)

/// Accueil in the RX look (Penpot "iPhone · Home"): a fixed photo hero under the status bar
/// (account menu, the security score, four quick actions) that fades as the page sheet scrolls
/// over it. The sheet holds the mock's cards in its order (Récents, Favoris,
/// Coffres) followed by the classic cards (`extras`). The navigation bar is hidden.
struct RXHomePage<Extras: View>: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openPhoneTab) private var openTab
    let itemCount: Int
    let recents: [FfiItemSummary]
    let favorites: [FfiItemSummary]
    let extras: Extras

    private typealias RX = Theme.RX

    init(itemCount: Int, recents: [FfiItemSummary], favorites: [FfiItemSummary], @ViewBuilder extras: () -> Extras) {
        self.itemCount = itemCount
        self.recents = recents
        self.favorites = favorites
        self.extras = extras()
    }

    var body: some View {
        RXHeroPage(photo: Image(lightHero ? RXHero.item : RXHero.home), lightPhoto: lightHero, initialOffset: Self.demoScroll) {
            VStack(spacing: RX.Space.xl) {
                topBar
                RXHomeScore(itemCount: itemCount)
                    .padding(.top, RX.Space.xxl)
                quickActions
                    .padding(.top, RX.Space.xl)
            }
            .environment(\.colorScheme, lightHero ? .light : .dark)
        } sheet: {
            VStack(spacing: RX.Space.l) {
                recentCard
                favoritesCard
                vaultsCard
                extras
            }
        }
        .toolbar(.hidden, for: .navigationBar)
    }

    @Environment(\.colorScheme) private var colorScheme
    /// Light appearance: the airy art (Clarity) with dark words and white disc actions; dark
    /// appearance: the indigo art with white words and glass actions.
    private var lightHero: Bool { colorScheme == .light }

    /// Captures: `-OnePassDemoScroll <points>` starts Accueil scrolled. Debug builds only.
    private static var demoScroll: CGFloat? {
        #if DEBUG
        let value = UserDefaults.standard.double(forKey: "OnePassDemoScroll")
        return value > 0 ? CGFloat(value) : nil
        #else
        return nil
        #endif
    }

    /// The account menu alone: search is the tab bar's search tab, a new item is the first quick
    /// action (one entry point each, D-HOME-ACTIONS).
    private var topBar: some View {
        HStack {
            AccountMenu()
            Spacer(minLength: 0)
        }
    }

    /// New item, Generate, Share (the security score). No "More" menu: everything it held is a
    /// direct row of the account menu (Réglages, Importer, Scanner un code, Configurer un appareil,
    /// Verrouiller), and the duplicates have their own banner on the sheet.
    private var quickActions: some View {
        let score = model.watchtower.report.map { Int($0.score) }
        return QuickActionRow {
            Button { model.showNewItemPicker = true } label: {
                QuickActionLabel(Text("Nouvel élément"), systemImage: "plus", onPhoto: !lightHero)
            }
            .accessibilityIdentifier("rx.home.newItem")
            Button { model.showGenerator = true } label: {
                QuickActionLabel(Text("Générer"), systemImage: "character.cursor.ibeam", onPhoto: !lightHero)
            }
            .accessibilityIdentifier("rx.home.generate")
            ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score ?? 0)")) {
                QuickActionLabel(Text("common.share"), systemImage: "square.and.arrow.up", onPhoto: !lightHero)
            }
            .disabled(score == nil)
            .accessibilityIdentifier("rx.home.share")
        }
        .rxPress()
    }

    /// Récents: the last items used, or how the card fills (classic parity: the same words).
    private var recentCard: some View {
        RXCard {
            HStack(alignment: .firstTextBaseline) {
                RXCardHeader(Text("Récents"))
                if !recents.isEmpty {
                    NavigationLink(value: PhoneRoute.list(.all)) {
                        Text("rx.home.seeAll")
                            .rxFont(.calloutMedium)
                            .foregroundStyle(RX.Palette.accentText.color)
                            .dbText(maxLines: 1)
                    }
                    .rxPress()
                    .routeZoomSource(.list(.all))
                    .padding(.trailing, RX.Space.l)
                    .accessibilityIdentifier("rx.home.seeAll")
                }
            }
            if recents.isEmpty {
                RXCardMessage(Text("browse.itemsUsedAppearHere"))
            } else {
                ForEach(recents.prefix(3), id: \.id) { summary in
                    PhoneItemLink(ref: ItemRef(vaultID: summary.vaultId, itemID: summary.id)) {
                        RXSummaryRow(summary: summary)
                    }
                    .rxPress()
                }
            }
        }
        .accessibilityIdentifier("home.recents")
    }

    /// Favoris as a carousel (D-CAROUSELS): tiles snap one by one, the next one peeks.
    private var favoritesCard: some View {
        RXCard {
            RXCardHeader(Text("Favoris"))
            if favorites.isEmpty {
                RXCardMessage(Text("browse.tapItemsStarTo"))
            } else {
                RXCarousel(nil, items: favorites.map(RXFavorite.init), spacing: RX.Space.s, inset: RX.Space.l) { favorite in
                    PhoneItemLink(ref: favorite.ref) {
                        RXFavoriteTile(title: Text(favorite.summary.title)) {
                            RXSummaryIcon(summary: favorite.summary, size: RX.Metrics.favoriteLogo)
                        }
                    }
                    .rxPress()
                    .accessibilityIdentifier("rx.home.favorite.\(favorite.summary.title)")
                }
                .padding(.top, RX.Space.s)
                .padding(.bottom, RX.Space.m)
            }
        }
        .accessibilityIdentifier("home.favorites")
    }

    private var vaultsCard: some View {
        let summaries = model.session.summaries
        return RXCard {
            RXCardHeader(Text("Coffres"))
            ForEach(model.session.vaults, id: \.id) { vault in
                let count = summaries.filter { ItemFilter.vault(vault.id).matches($0) }.count
                NavigationLink(value: PhoneRoute.list(.vault(vault.id))) {
                    RXItemRow(
                        title: Text(vault.meta.name), subtitle: Text("browse.items \(count)"), chevron: true
                    ) {
                        VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: RX.Metrics.itemLead)
                    }
                }
                .rxPress()
                .routeZoomSource(.list(.vault(vault.id)))
            }
        }
        .accessibilityIdentifier("rx.home.vaults")
    }
}

/// A favourite as a carousel element.
private struct RXFavorite: Identifiable {
    let summary: FfiItemSummary
    var id: String { summary.id }
    var ref: ItemRef { ItemRef(vaultID: summary.vaultId, itemID: summary.id) }
}

#endif

/// An item of the RX Home (iPhone and Mac): its icon (loaded like the list rows), the title, the
/// subtitle, and when it was last used.
struct RXSummaryRow: View {
    let summary: FfiItemSummary

    var body: some View {
        RXItemRow(
            title: Text(summary.title),
            subtitle: Text(summary.listSubtitle.isEmpty ? ItemCategory.of(summary.itemType).singular : summary.listSubtitle),
            value: summary.lastUsedAt.map { Text($0, format: .relative(presentation: .numeric, unitsStyle: .abbreviated)) },
            valueColor: Theme.RX.Palette.textSecondary.color
        ) {
            RXSummaryIcon(summary: summary, size: 40)
        }
    }
}

/// The icon of an item summary, as the list rows load it.
struct RXSummaryIcon: View {
    @Environment(AppModel.self) private var model
    let summary: FfiItemSummary
    let size: CGFloat
    @State private var resolved: ResolvedIcon?

    private var taskID: ItemIconTaskID { ItemIconTaskID(summary, epoch: model.iconEpoch) }

    var body: some View {
        ItemIcon(
            type: summary.itemType, title: summary.title, siteIcon: model.iconLoader.shownIcon(taskID, resolved: resolved),
            size: size, brand: summary.cardBrand, useCategory: summary.usesCategoryIcon,
            tint: ItemTint.color(named: summary.color), domain: ItemIconResolver.registrableDomain(summary.primaryUrl))
            .task(id: taskID) {
                let id = taskID
                resolved = ResolvedIcon(id: id, data: await model.iconLoader.icon(for: id.url, title: id.title, custom: id.custom))
            }
    }
}

#if os(iOS)
/// The security score over the photo: the label with the item count, the figure over 100, the
/// status pill. Tapping it opens Watchtower.
struct RXHomeScore: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openPhoneTab) private var openTab
    @Environment(\.colorScheme) private var colorScheme
    let itemCount: Int

    private typealias RX = Theme.RX

    /// "Bonjour Camille" (the first word of the display name), or "Bonjour" without one.
    private var greeting: Text {
        let first = model.settings.displayName.split(separator: " ").first.map(String.init) ?? ""
        return first.isEmpty ? Text("rx.home.hello") : Text("rx.home.hi \(first)")
    }

    /// The headline in words (Clarity): the score itself is the small chip under it.
    static func status(_ score: Int?) -> LocalizedStringKey {
        guard let score else { return "rx.home.status.checking" }
        switch score {
        case 80...: return "rx.home.status.good"
        case 60..<80: return "rx.home.status.almost"
        default: return "rx.home.status.attention"
        }
    }

    /// The words-first headline (Clarity), 44 pt bold, scaled with Dynamic Type.
    @ScaledMetric(relativeTo: .largeTitle) private var headlineSize: CGFloat = 44

    var body: some View {
        let score = model.watchtower.report.map { Int($0.score) }
        // One button: the whole score block opens Watchtower (no tap gesture, UX-PRESS-02).
        Button { openTab(.watchtower) } label: {
            VStack(spacing: RX.Space.s) {
                greeting
                    .rxFont(.calloutMedium)
                    .foregroundStyle(.secondary)
                    .dbText(maxLines: 2)
                Text(Self.status(score))
                    .font(RX.Typography.display.font(size: headlineSize))
                    .tracking(-1.5)
                    .foregroundStyle(.primary)
                    .multilineTextAlignment(.center)
                    .dbText(maxLines: 2, minimumScale: 0.7)
                if let score {
                    scoreChip(score)
                        .padding(.top, RX.Space.xs)
                }
            }
            .frame(maxWidth: .infinity)
            .contentShape(Rectangle())
        }
        .rxPress()
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("rx.home.score")
        // The score comes from the Watchtower report: computed here too when the tab was not opened.
        .task(id: model.session.summariesRevision) { model.watchtower.refreshIfNeeded(model.session) }
    }

    /// The score as a glass chip: the shield, then the figure in rolling digits.
    private func scoreChip(_ score: Int) -> some View {
        HStack(spacing: RX.Space.s) {
            Image(systemName: "checkmark.shield.fill")
                .foregroundStyle(ScoreGauge.color(score))
                .accessibilityHidden(true)
            Text("rx.home.score")
                .rxFont(.footnoteBold)
            RXNumber(score, typography: .footnoteBold)
        }
        .foregroundStyle(.primary)
        .padding(.horizontal, RX.Space.m)
        .frame(minHeight: 32)
        .rxGlass(in: Capsule(), onPhoto: colorScheme == .dark, interactive: false)
    }
}
#endif
