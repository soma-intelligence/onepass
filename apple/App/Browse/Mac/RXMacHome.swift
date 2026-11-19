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
    @ScaledMetric(relativeTo: .largeTitle) private var scoreSize: CGFloat = 64

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

    /// The photo card: the score on the left, the actions under it.
    private func hero(itemCount: Int) -> some View {
        let status = RXScoreStatus.of(model.watchtower)
        let score = status.score
        let shape = RoundedRectangle(cornerRadius: 28, style: .continuous)
        return VStack(alignment: .leading, spacing: RX.Space.xs) {
            // The score opens Watchtower: one button, no tap gesture on the card (UX-PRESS-02).
            Button { model.page = .watchtower } label: {
                scoreLabel(itemCount: itemCount, score: score)
            }
            .rxPress()
            .accessibilityIdentifier("rx.mac.score")
            // The last run failed: say so (no figure, or an old one), and offer to run it again.
            if status.canRetry {
                Text(status == .failed ? "rx.home.status.failed" : "rx.home.status.stale")
                    .rxFont(.calloutMedium)
                    .foregroundStyle(.white.opacity(0.85))
            }
            Spacer(minLength: RX.Space.l)
            HStack(spacing: RX.Space.s) {
                if status.canRetry {
                    capsule(Text(DBStrings.tryAgain), systemImage: "arrow.clockwise") {
                        model.watchtower.refresh(model.session)
                    }
                    .accessibilityIdentifier("rx.mac.score.retry")
                }
                capsule(Text("Nouvel élément"), systemImage: "plus") { model.showNewItemPicker = true }
                    .accessibilityIdentifier("rx.mac.newItem")
                capsule(Text("Générer"), systemImage: "character.cursor.ibeam") { model.showGenerator = true }
                    .accessibilityIdentifier("rx.mac.generate")
                ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score ?? 0)")) {
                    capsuleLabel(Text("common.share"), systemImage: "square.and.arrow.up")
                }
                .rxPress()
                .disabled(score == nil)
                .accessibilityIdentifier("rx.mac.share")
            }
        }
        .padding(.vertical, RX.Space.xl)
        .padding(.horizontal, RX.Space.xxl)
        .frame(maxWidth: .infinity, minHeight: 260, alignment: .leading)
        .background {
            Image(RXHero.home)
                .resizable()
                .scaledToFill()
                .overlay(LinearGradient(colors: [.black.opacity(0.45), .black.opacity(0.1)],
                                        startPoint: .leading, endPoint: .trailing))
                .accessibilityHidden(true)
        }
        .clipShape(shape)
        .contentShape(shape)
    }

    /// The label with the item count, then the score over 100 in rolling digits.
    private func scoreLabel(itemCount: Int, score: Int?) -> some View {
        VStack(alignment: .leading, spacing: RX.Space.xs) {
            Text("rx.home.scoreLabel \(itemCount)")
                .rxFont(.calloutMedium)
                .foregroundStyle(.white.opacity(0.85))
            HStack(alignment: .lastTextBaseline, spacing: RX.Space.xs) {
                Group {
                    if let score { DBNumber(score) } else { Text(verbatim: "–") }
                }
                .font(RX.Typography.display.font(size: scoreSize))
                .tracking(-2.5)
                .monospacedDigit()
                Text(verbatim: "/100")
                    .rxFont(.title)
                    .opacity(0.7)
            }
            .foregroundStyle(.white)
            .accessibilityElement(children: .combine)
        }
        .contentShape(Rectangle())
    }

    private func capsule(_ title: Text, systemImage: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { capsuleLabel(title, systemImage: systemImage) }
            .rxPress()
    }

    private func capsuleLabel(_ title: Text, systemImage: String) -> some View {
        Label { title } icon: { Image(systemName: systemImage) }
            .rxFont(.calloutMedium)
            .foregroundStyle(.white)
            .padding(.horizontal, RX.Space.l)
            .frame(height: 40)
            .background(.white.opacity(0.18), in: Capsule())
            .background(.ultraThinMaterial.opacity(0.6), in: Capsule())
            .environment(\.colorScheme, .dark)
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
        RXCard {
            cardHeader(Text("Favoris")) { EmptyView() }
            HStack(alignment: .top, spacing: 0) {
                ForEach(favorites.prefix(6), id: \.id) { summary in
                    Button { open(summary) } label: {
                        VStack(spacing: RX.Space.s) {
                            RXSummaryIcon(summary: summary, size: 52)
                            // Two lines, centred, so a long title wraps instead of being cut.
                            Text(summary.title)
                                .rxFont(.footnote)
                                .foregroundStyle(RX.Palette.textPrimary.color)
                                .multilineTextAlignment(.center)
                                .lineLimit(2, reservesSpace: true)
                                .minimumScaleFactor(0.85)
                                .padding(.horizontal, RX.Space.xxs)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .rxPress()
                }
                ForEach(0..<max(0, 6 - min(favorites.count, 6)), id: \.self) { _ in
                    Color.clear.frame(maxWidth: .infinity, maxHeight: 1)
                }
            }
            .padding(EdgeInsets(top: RX.Space.s, leading: RX.Space.s, bottom: 14, trailing: RX.Space.s))
        }
        .accessibilityIdentifier("rx.mac.favorites")
    }

    /// The item in the list of all items, as a click in the sidebar search would show it.
    private func open(_ summary: FfiItemSummary) {
        model.showItems(.all)
        model.selectedItem = ItemRef(vaultID: summary.vaultId, itemID: summary.id)
    }
}

/// The lead (icon, vault tile) of a Home card row on the Mac.
private let macHomeLead: CGFloat = 28

/// A row of the Home cards on the Mac: a 28 pt lead, the title (Callout medium) over its subtitle
/// (Footnote, secondary), then a trailing column of fixed width (the time, or nothing) and an
/// optional chevron, 48 pt high; so rows with and without a time line up.
private struct MacHomeRow<Lead: View>: View {
    let title: Text
    let subtitle: Text
    var trailing: Text?
    var chevron = false
    @ViewBuilder var leadView: Lead

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
        .padding(.horizontal, RX.Space.l)
        .frame(minHeight: 48)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}
#endif
