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
    /// A tap on the selected Accueil tab at its root scrolls the page back to its top.
    @Environment(\.phoneTabScrollToTop) private var scrollToTop
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
        RXHeroPage(photo: wallpaper.image, lightPhoto: lightHero, livePhoto: liveWallpaper,
            initialOffset: Self.demoScroll, scrollToTop: scrollToTop) {
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
    private var lightHero: Bool { wallpaper.isLight }
    /// The art behind the hero: the default (light or dark with the appearance), a theme of
    /// Réglages > Général > Fond d'écran, or an imported photo.
    @AppStorage(RXWallpaper.storageKey, store: AppModel.browseDefaults) private var wallpaperID = RXWallpaper.automatic
    private var wallpaper: RXWallpaper.Resolved { RXWallpaper.resolve(wallpaperID, colorScheme: colorScheme) }
    @AppStorage(RXWallpaper.liveKey, store: AppModel.browseDefaults) private var liveWallpaper = true

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
        .rxPress(haptic: .selection)
        .background { if lightHero { lightActionsVeil } }
    }

    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    /// Light appearance: the dark labels sit low on the light art, where the sphere's purple
    /// reflection runs darkest (under Générer above all) and the page veil is at its thinnest. A
    /// soft white pool under the row, light pooling under the white discs, lifts that band so the
    /// labels keep their contrast; stronger under Reduce Transparency or Increase Contrast.
    private var lightActionsVeil: some View {
        let flat = Theme.Wash.isFlat(increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)
        let white = Color.white.opacity(flat ? RX.Veil.lightHero(flat: true)[2] : Self.actionsVeil)
        // A gradient, not a blurred shape: a blur (or `accessibilityHidden` on it) leaves an empty
        // element in the accessibility tree, which the audit reports as one with no description.
        return EllipticalGradient(
            stops: [
                .init(color: white, location: 0),
                .init(color: white, location: 0.55),
                .init(color: .white.opacity(0), location: 1),
            ])
            .padding(.horizontal, -RX.Space.l)
            .padding(.vertical, -RX.Space.l)
            .allowsHitTesting(false)
    }

    /// The white pool under the light quick actions (between the hero veil's middle and bottom).
    private static var actionsVeil: Double { 0.55 }

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
                            .frame(minHeight: RX.Metrics.minTapTarget)
                            .contentShape(Rectangle())
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
        // The card keeps its identifier without lending it to the buttons inside.
        .accessibilityElement(children: .contain)
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
                    .rxPress(haptic: .selection)
                    .accessibilityIdentifier("rx.home.favorite.\(favorite.summary.title)")
                }
                .padding(.top, RX.Space.s)
                .padding(.bottom, RX.Space.m)
            }
        }
        // The card keeps its identifier without lending it to the buttons inside.
        .accessibilityElement(children: .contain)
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
        // The card keeps its identifier without lending it to the buttons inside.
        .accessibilityElement(children: .contain)
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
            value: summary.lastUsedAt.map(Self.usedLabel),
            valueColor: Theme.RX.Palette.textSecondary.color
        ) {
            RXSummaryIcon(summary: summary, size: 40)
        }
    }

    /// "maintenant" for the last minute, then minutes, hours, "hier": the seconds counted up on
    /// every render ("il y a 6 s") and the row's width moved with them (jank audit J17).
    private static func usedLabel(_ date: Date) -> Text {
        let now = Date()
        let shown = now.timeIntervalSince(date) < 60 ? now : date
        return Text(shown, format: .relative(presentation: .named, unitsStyle: .abbreviated))
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

/// What the Home score shows (iPhone and Mac), from the Watchtower model: the score of the last
/// report, a failed first run (with a retry), or a run on its way.
enum RXScoreStatus: Equatable {
    case checking
    case failed
    case score(Int)

    @MainActor static func of(_ watchtower: WatchtowerModel) -> RXScoreStatus {
        if let report = watchtower.report { return .score(Int(report.score)) }
        if case .failed = watchtower.phase { return .failed }
        return .checking
    }

    var score: Int? {
        if case .score(let score) = self { return score }
        return nil
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
    static func status(_ status: RXScoreStatus) -> LocalizedStringKey {
        switch status {
        case .checking: "rx.home.status.checking"
        case .failed: "rx.home.status.failed"
        case .score(80...): "rx.home.status.good"
        case .score(60..<80): "rx.home.status.almost"
        case .score: "rx.home.status.attention"
        }
    }

    /// The words-first headline (Clarity): the Display small typography (Penpot), so two words fit
    /// a line. It scales with Large Title under Dynamic Type; the tracking keeps the token's ratio.
    private static let headlineBase: CGFloat = Theme.RX.Typography.displaySmall.spec.size
    @ScaledMetric(relativeTo: .largeTitle) private var headlineSize: CGFloat = RXHomeScore.headlineBase

    private var headlineTracking: CGFloat {
        let token = RX.Typography.displaySmall.spec
        return token.tracking * headlineSize / token.size
    }

    var body: some View {
        let status = RXScoreStatus.of(model.watchtower)
        VStack(spacing: RX.Space.m) {
            // One button: the whole score block opens Watchtower (no tap gesture, UX-PRESS-02).
            Button { openTab(.watchtower) } label: {
                VStack(spacing: RX.Space.s) {
                    greeting
                        .rxFont(.calloutMedium)
                        .foregroundStyle(.primary)
                        .dbText(maxLines: 2)
                    Text(Self.status(status))
                        .font(RX.Typography.displaySmall.font(size: headlineSize))
                        .tracking(headlineTracking)
                        .foregroundStyle(.primary)
                        .multilineTextAlignment(.center)
                        .dbText(maxLines: 2, minimumScale: 0.7)
                        .contentTransition(.opacity)
                    // The chip keeps its place while the score is computed (a hidden chip of
                    // the same size): the hero does not jump when the report lands at launch.
                    scoreChip(status.score ?? 100)
                        .opacity(status.score == nil ? 0 : 1)
                        .accessibilityHidden(status.score == nil)
                        .padding(.top, RX.Space.xs)
                }
                .frame(maxWidth: .infinity)
                .contentShape(Rectangle())
            }
            .rxPress(haptic: .selection)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("rx.home.score")
            // The first run failed: the headline says so, and this runs it again.
            if status == .failed {
                Button {
                    model.watchtower.refresh(model.session)
                } label: {
                    Label(DBStrings.tryAgain, systemImage: "arrow.clockwise")
                        .rxFont(.footnoteBold)
                        .foregroundStyle(.primary)
                        .padding(.horizontal, RX.Space.l)
                        .frame(minHeight: RX.Metrics.minTapTarget)
                        .rxGlass(in: Capsule(), onPhoto: colorScheme == .dark, interactive: true)
                }
                .rxPress(haptic: .selection)
                .accessibilityIdentifier("rx.home.score.retry")
            }
        }
        .animation(.smooth(duration: 0.35), value: status)
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
        .padding(.vertical, RX.Space.s)
        .rxGlass(in: Capsule(), onPhoto: colorScheme == .dark, interactive: false)
    }
}
#endif
