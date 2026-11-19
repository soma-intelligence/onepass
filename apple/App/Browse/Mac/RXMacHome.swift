#if os(macOS)
import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// Accueil on the Mac in the RX look (Penpot "Mac · Home"), the first sidebar row while the switch
/// is on: the photo card with the security score and three actions, Récents and Coffres side by
/// side, then Favoris as a row of icons. Every row opens what the sidebar would: the item in the
/// list, the vault's items, the full list.
struct RXMacHome: View {
    @Environment(AppModel.self) private var model
    @ScaledMetric(relativeTo: .largeTitle) private var headlineSize: CGFloat = Theme.RX.Typography.displaySmall.spec.size
    /// The hero's picture, picked in Réglages > Général (Lava 3 when nothing is stored).
    @AppStorage(RXWallpaper.storageKey, store: AppModel.browseDefaults) private var wallpaperID = RXWallpaper.platformDefault
    @Environment(\.colorScheme) private var colorScheme

    private typealias RX = Theme.RX

    var body: some View {
        let session = model.session
        let counts = session.counts()
        // As many recents as vaults (3 to 6), so the two cards side by side end together.
        let recents = session.recentlyUsed(limit: min(max(session.vaults.count, 3), 6)).filter { $0.trashedAt == nil }
        let favorites = session.items(filter: .favorites, query: "", sort: .title)
        ScrollView {
            VStack(alignment: .leading, spacing: RX.Space.l) {
                Text("rx.mac.home")
                    .rxFont(.title)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                hero(itemCount: counts.all)
                // Equal heights: each card fills the row's height (the taller card's), its rows
                // from the top.
                HStack(alignment: .top, spacing: RX.Space.l) {
                    recentCard(recents)
                        .frame(maxHeight: .infinity, alignment: .top)
                    vaultsCard
                        .frame(maxHeight: .infinity, alignment: .top)
                }
                .fixedSize(horizontal: false, vertical: true)
                if !favorites.isEmpty {
                    favoritesCard(favorites)
                }
            }
            .frame(maxWidth: 832)
            .padding(.horizontal, RX.Space.xl)
            .padding(.vertical, RX.Space.l)
            .frame(maxWidth: .infinity)
        }
        .background(RX.Palette.pageBackground.color)
        .environment(\.rxCards, true)
        .task(id: session.summariesRevision) { model.watchtower.refreshIfNeeded(session) }
        .accessibilityIdentifier("rx.mac.home")
    }

    /// The photo card, words first as on the iPhone: the greeting, the state in words, the score as
    /// a glass chip with the item count, then the actions in Liquid Glass along the bottom.
    private func hero(itemCount: Int) -> some View {
        let wallpaper = RXWallpaper.resolve(wallpaperID, colorScheme: colorScheme)
        // A light picture keeps dark words, over a white veil (as the iPhone hero does).
        let light = wallpaper.isLight
        let status = RXScoreStatus.of(model.watchtower)
        let score = status.score
        let shape = RoundedRectangle(cornerRadius: 28, style: .continuous)
        return VStack(alignment: .leading, spacing: 0) {
            // The words open Watchtower: one button, no tap gesture on the card (UX-PRESS-02).
            Button { model.page = .watchtower } label: {
                VStack(alignment: .leading, spacing: RX.Space.s) {
                    greeting
                        .rxFont(.calloutMedium)
                        .foregroundStyle(Self.ink(light).opacity(0.8))
                    Text(Self.headline(status))
                        .font(RX.Typography.displaySmall.font(size: headlineSize))
                        .tracking(RX.Typography.displaySmall.spec.tracking * headlineSize / RX.Typography.displaySmall.spec.size)
                        .foregroundStyle(Self.ink(light))
                        .lineLimit(2)
                        .contentTransition(.opacity)
                    HStack(spacing: RX.Space.s) {
                        scoreChip(score, light: light)
                        Text("browse.items \(itemCount)")
                            .rxFont(.footnoteBold)
                            .foregroundStyle(Self.ink(light).opacity(0.75))
                    }
                    .padding(.top, RX.Space.xs)
                }
                .contentShape(Rectangle())
            }
            .rxPress()
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("rx.mac.score")
            Spacer(minLength: RX.Space.xl)
            HStack(spacing: RX.Space.s) {
                if status.canRetry {
                    capsule(Text(DBStrings.tryAgain), systemImage: "arrow.clockwise", light: light) {
                        model.watchtower.refresh(model.session)
                    }
                    .accessibilityIdentifier("rx.mac.score.retry")
                }
                // The main action stands out: solid, the others are glass.
                Button { model.showNewItemPicker = true } label: {
                    Label { Text("Nouvel élément") } icon: { Image(systemName: "plus") }
                        .rxFont(.calloutMedium)
                        .foregroundStyle(light ? Color.white : Color(white: 0.08))
                        .padding(.horizontal, RX.Space.l)
                        .frame(height: 40)
                        .background(light ? Color(white: 0.08) : Color.white, in: Capsule())
                }
                .rxPress()
                .accessibilityIdentifier("rx.mac.newItem")
                capsule(Text("Générer"), systemImage: "character.cursor.ibeam", light: light) { model.showGenerator = true }
                    .accessibilityIdentifier("rx.mac.generate")
                ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score ?? 0)")) {
                    capsuleLabel(Text("common.share"), systemImage: "square.and.arrow.up", light: light)
                }
                .rxPress()
                .disabled(score == nil)
                .accessibilityIdentifier("rx.mac.share")
            }
        }
        .padding(RX.Space.xxl)
        .frame(maxWidth: .infinity, minHeight: 300, alignment: .leading)
        .background {
            wallpaper.image
                .resizable()
                .scaledToFill()
                // Words top left, buttons bottom left: the veil darkens (or lightens) that side
                // and fades out to the right, so the picture keeps its colours there.
                .overlay(LinearGradient(colors: light ? [.white.opacity(0.6), .white.opacity(0.15), .clear]
                                                      : [.black.opacity(0.55), .black.opacity(0.2), .clear],
                                        startPoint: .leading, endPoint: .trailing))
                .overlay(LinearGradient(colors: [.clear, (light ? Color.white : Color.black).opacity(0.25)],
                                        startPoint: .center, endPoint: .bottom))
                .accessibilityHidden(true)
        }
        .clipShape(shape)
        .contentShape(shape)
        .animation(.smooth(duration: 0.35), value: status)
    }

    /// "Bonjour Quentin" (first word of the display name), or "Bonjour" without one.
    private var greeting: Text {
        let first = model.settings.displayName.split(separator: " ").first.map(String.init) ?? ""
        return first.isEmpty ? Text("rx.home.hello") : Text("rx.home.hi \(first)")
    }

    /// The state in words (same keys as the iPhone hero).
    private static func headline(_ status: RXScoreStatus) -> LocalizedStringKey {
        switch status {
        case .checking: "rx.home.status.checking"
        case .failed: "rx.home.status.failed"
        case .stale: "rx.home.status.stale"
        case .score(80...): "rx.home.status.good"
        case .score(60..<80): "rx.home.status.almost"
        case .score: "rx.home.status.attention"
        }
    }

    /// The score as a glass chip: the shield in the score's colour, then the figure over 100. It
    /// keeps its place (hidden) while the score is computed, so the hero does not jump.
    private func scoreChip(_ score: Int?, light: Bool) -> some View {
        HStack(spacing: RX.Space.s) {
            Image(systemName: "checkmark.shield.fill")
                .foregroundStyle(ScoreGauge.color(score ?? 100))
                .accessibilityHidden(true)
            Text("rx.home.score")
                .rxFont(.footnoteBold)
            HStack(spacing: 0) {
                RXNumber(score ?? 100, typography: .footnoteBold)
                Text(verbatim: "/100").rxFont(.footnoteBold).opacity(0.6)
            }
        }
        .foregroundStyle(Self.ink(light))
        .padding(.horizontal, RX.Space.m)
        .padding(.vertical, RX.Space.s)
        .rxGlass(in: Capsule(), onPhoto: !light, interactive: false)
        .environment(\.colorScheme, light ? .light : .dark)
        .opacity(score == nil ? 0 : 1)
    }

    /// The words over the hero: white over a dark picture, near black over a light one.
    private static func ink(_ light: Bool) -> Color {
        light ? Color(white: 0.08) : .white
    }

    private func capsule(_ title: Text, systemImage: String, light: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) { capsuleLabel(title, systemImage: systemImage, light: light) }
            .rxPress()
    }

    private func capsuleLabel(_ title: Text, systemImage: String, light: Bool) -> some View {
        Label { title } icon: { Image(systemName: systemImage) }
            .rxFont(.calloutMedium)
            .foregroundStyle(Self.ink(light))
            .padding(.horizontal, RX.Space.l)
            .frame(height: 40)
            .rxGlass(in: Capsule(), onPhoto: !light, interactive: true)
            .environment(\.colorScheme, light ? .light : .dark)
    }

    private func recentCard(_ recents: [FfiItemSummary]) -> some View {
        homeCard {
            cardHeader(Text("Récents")) {
                // Nothing to see in full while the card is empty.
                if !recents.isEmpty {
                    Button { model.showItems(.all) } label: {
                        Text("rx.home.seeAll")
                            .rxFont(.footnoteBold)
                            .foregroundStyle(RX.Palette.accentText.color)
                            .contentShape(Rectangle())
                    }
                    .rxPress()
                    .accessibilityIdentifier("rx.mac.seeAll")
                }
            }
            if recents.isEmpty {
                RXCardMessage(Text("browse.itemsUsedAppearHere"))
            } else {
                ForEach(recents, id: \.id) { summary in
                    Button { open(summary) } label: {
                        MacHomeRow(
                            title: Text(summary.title),
                            subtitle: Text(summary.listSubtitle.isEmpty
                                           ? ItemCategory.of(summary.itemType).singular : summary.listSubtitle),
                            trailing: summary.lastUsedAt.map(RXSummaryRow.usedLabel)
                        ) {
                            RXSummaryIcon(summary: summary, size: macHomeLead)
                        }
                    }
                    .rxPress()
                }
            }
        }
        .accessibilityIdentifier("rx.mac.recents")
    }

    private var vaultsCard: some View {
        let summaries = model.session.summaries
        return homeCard {
            cardHeader(Text("Coffres")) { EmptyView() }
            ForEach(model.session.vaults, id: \.id) { vault in
                let count = summaries.filter { ItemFilter.vault(vault.id).matches($0) }.count
                Button { model.showItems(.vault(vault.id)) } label: {
                    MacHomeRow(title: Text(vault.meta.name), subtitle: Text("browse.items \(count)"), chevron: true) {
                        VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: macHomeLead)
                    }
                }
                .rxPress()
            }
        }
        .accessibilityIdentifier("rx.mac.vaults")
    }

    /// A card of the Home row: the card token and radius, its rows from the top.
    private func homeCard<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            content()
            Spacer(minLength: 0)
        }
        .padding(.bottom, RX.Space.s)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(RX.Palette.cardBackground.color, in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
    }

    /// The same header in both cards: the title (Callout semibold) and an action on its baseline.
    private func cardHeader<Action: View>(_ title: Text, @ViewBuilder action: () -> Action) -> some View {
        HStack(alignment: .firstTextBaseline) {
            title
                .rxFont(.calloutMedium)
                .fontWeight(.semibold)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .accessibilityAddTraits(.isHeader)
            Spacer(minLength: RX.Space.s)
            action()
        }
        .padding(.horizontal, RX.Space.l)
        .padding(.top, RX.Space.l)
        .padding(.bottom, RX.Space.s)
    }

    private func favoritesCard(_ favorites: [FfiItemSummary]) -> some View {
        MacFavoritesCard(favorites: favorites, open: open)
    }

    /// The item in the list of all items, as a click in the sidebar search would show it.
    private func open(_ summary: FfiItemSummary) {
        model.showItems(.all)
        model.selectedItem = ItemRef(vaultID: summary.vaultId, itemID: summary.id)
    }
}

/// Favoris on the Mac Home: one row of fixed-width tiles (52 pt icon, the name under it, 104 pt
/// per tile), left-aligned, scrolled sideways with the trackpad or Shift and the wheel. No scroll
/// bar; the edge where more tiles wait fades out, and two small chevrons at the header's right
/// page left and right (for a mouse without sideways scroll), shown only when the row overflows.
private struct MacFavoritesCard: View {
    let favorites: [FfiItemSummary]
    let open: (FfiItemSummary) -> Void
    @State private var position = ScrollPosition(idType: String.self)
    @State private var geometry = RowGeometry()
    @State private var hovered: String?

    private typealias RX = Theme.RX
    private static let tileWidth: CGFloat = 104
    private static let fade: CGFloat = 40

    struct RowGeometry: Equatable {
        var offset: CGFloat = 0
        var content: CGFloat = 0
        var container: CGFloat = 0
        var overflows: Bool { content > container + 1 }
        var atStart: Bool { offset <= 1 }
        var atEnd: Bool { offset + container >= content - 1 }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text("Favoris")
                    .rxFont(.calloutMedium)
                    .fontWeight(.semibold)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: RX.Space.s)
                if geometry.overflows {
                    HStack(spacing: RX.Space.xs) {
                        pager("chevron.left", label: Text("rx.mac.favorites.previous"), disabled: geometry.atStart) { page(-1) }
                        pager("chevron.right", label: Text("rx.mac.favorites.next"), disabled: geometry.atEnd) { page(1) }
                    }
                }
            }
            .padding(.horizontal, RX.Space.l)
            .padding(.top, RX.Space.l)
            .padding(.bottom, RX.Space.s)
            ScrollView(.horizontal) {
                LazyHStack(alignment: .top, spacing: 0) {
                    ForEach(favorites, id: \.id) { summary in
                        Button { open(summary) } label: { tile(summary) }
                            .rxPress()
                            .id(summary.id)
                    }
                }
                .padding(.horizontal, RX.Space.s)
                .scrollTargetLayout()
            }
            .scrollIndicators(.never)
            .scrollPosition($position)
            .onScrollGeometryChange(for: RowGeometry.self) { scroll in
                RowGeometry(offset: scroll.contentOffset.x, content: scroll.contentSize.width,
                            container: scroll.containerSize.width)
            } action: { _, new in
                geometry = new
            }
            .mask { edgeFade }
            .padding(.bottom, 14)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RX.Palette.cardBackground.color, in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
        .accessibilityIdentifier("rx.mac.favorites")
    }

    private func tile(_ summary: FfiItemSummary) -> some View {
        VStack(spacing: RX.Space.s) {
            // Every logo on the same squircle, so bare marks (Apple, GitHub) and tiled ones
            // (Amazon) read as one grid.
            RXSummaryIcon(summary: summary, size: 40)
                .frame(width: 64, height: 64)
                .background(RX.Palette.field.color, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .scaleEffect(hovered == summary.id ? 1.06 : 1)
                .animation(.snappy(duration: 0.18), value: hovered)
            // Two lines, centred, so a long title wraps instead of being cut.
            Text(summary.title)
                .rxFont(.footnote)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .multilineTextAlignment(.center)
                .lineLimit(2, reservesSpace: true)
                .padding(.horizontal, RX.Space.xxs)
        }
        .frame(width: Self.tileWidth)
        .padding(.top, RX.Space.xs)
        .contentShape(Rectangle())
        .onHover { inside in
            if inside { hovered = summary.id } else if hovered == summary.id { hovered = nil }
        }
    }

    /// Opaque in the middle; a fade on each side where more tiles wait.
    private var edgeFade: some View {
        HStack(spacing: 0) {
            LinearGradient(colors: [geometry.atStart ? .black : .clear, .black], startPoint: .leading, endPoint: .trailing)
                .frame(width: Self.fade)
            Rectangle()
            LinearGradient(colors: [.black, geometry.atEnd ? .black : .clear], startPoint: .leading, endPoint: .trailing)
                .frame(width: Self.fade)
        }
    }

    private func pager(_ symbol: String, label: Text, disabled: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(RX.Glyph.font(RX.Glyph.macSmall, weight: .bold))
                .foregroundStyle(RX.Palette.textSecondary.color)
                .frame(width: 24, height: 24)
                .background(RX.Palette.field.color, in: Circle())
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .opacity(disabled ? 0.4 : 1)
        .accessibilityLabel(label)
    }

    /// One page: the row's width less one tile, so a tile of the last page stays in view.
    private func page(_ direction: CGFloat) {
        let step = max(geometry.container - Self.tileWidth, Self.tileWidth)
        let target = min(max(geometry.offset + direction * step, 0), max(geometry.content - geometry.container, 0))
        withAnimation(.snappy) { position.scrollTo(x: target) }
    }
}

/// The lead (icon, vault tile) of a Home card row on the Mac.
private let macHomeLead: CGFloat = 32

/// A row of the Home cards on the Mac: a 28 pt lead, the title (Callout medium) over its subtitle
/// (Footnote, secondary), then a trailing column of fixed width (the time, or nothing) and an
/// optional chevron, 48 pt high; so rows with and without a time line up.
private struct MacHomeRow<Lead: View>: View {
    let title: Text
    let subtitle: Text
    var trailing: Text?
    var chevron = false
    @ViewBuilder var leadView: Lead
    @State private var hovering = false

    init(title: Text, subtitle: Text, trailing: Text? = nil, chevron: Bool = false, @ViewBuilder lead: () -> Lead) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing
        self.chevron = chevron
        self.leadView = lead()
    }

    private typealias RX = Theme.RX

    var body: some View {
        HStack(spacing: RX.Space.m) {
            leadView
                .frame(width: macHomeLead, height: macHomeLead)
            VStack(alignment: .leading, spacing: 1) {
                title
                    .rxFont(.calloutMedium)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .lineLimit(1)
                subtitle
                    .rxFont(.footnote)
                    .foregroundStyle(RX.Palette.textSecondary.color)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: RX.Space.s)
            if chevron {
                RXChevron()
            } else {
                // The time column keeps its width with or without a time.
                (trailing ?? Text(verbatim: ""))
                    .rxFont(.footnote)
                    .monospacedDigit()
                    .foregroundStyle(RX.Palette.textTertiary.color)
                    .lineLimit(1)
                    .frame(width: 84, alignment: .trailing)
            }
        }
        .padding(.horizontal, RX.Space.l - RX.Space.s)
        .frame(minHeight: 52)
        // Hover: a soft rounded highlight, inset from the card's edge, as in a Mac source list.
        .background(RX.Palette.field.color.opacity(hovering ? 1 : 0),
                    in: RoundedRectangle(cornerRadius: RX.Radius.macRow, style: .continuous))
        .padding(.horizontal, RX.Space.s)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: hovering)
        .accessibilityElement(children: .combine)
    }
}
#endif
