#if os(macOS)
import DesignKit
import SwiftUI
import VaultKit

/// Accueil on the Mac in the RX look (Penpot "Mac · Home"), the first sidebar row while the switch
/// is on: the photo card with the security score and three actions, Récents and Coffres side by
/// side, then Favoris as a row of icons. Every row opens what the sidebar would: the item in the
/// list, the vault's items, the full list.
struct RXMacHome: View {
    @Environment(AppModel.self) private var model

    private typealias RX = Theme.RX

    var body: some View {
        let session = model.session
        let counts = session.counts()
        let recents = session.recentlyUsed(limit: 3).filter { $0.trashedAt == nil }
        let favorites = session.items(filter: .favorites, query: "", sort: .title)
        ScrollView {
            VStack(alignment: .leading, spacing: RX.Space.l) {
                Text("rx.mac.home")
                    .rxFont(.title)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                hero(itemCount: counts.all)
                HStack(alignment: .top, spacing: RX.Space.l) {
                    recentCard(recents)
                    vaultsCard
                }
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
        let score = model.watchtower.report.map { Int($0.score) }
        let shape = RoundedRectangle(cornerRadius: 28, style: .continuous)
        return VStack(alignment: .leading, spacing: RX.Space.xs) {
            Text("rx.home.scoreLabel \(itemCount)")
                .rxFont(.calloutMedium)
                .foregroundStyle(.white.opacity(0.85))
            HStack(alignment: .lastTextBaseline, spacing: RX.Space.xs) {
                Text(score.map(String.init) ?? "–")
                    .font(.system(size: 64, weight: .bold))
                    .tracking(-2.5)
                    .monospacedDigit()
                Text(verbatim: "/100")
                    .rxFont(.title)
                    .opacity(0.7)
            }
            .foregroundStyle(.white)
            .accessibilityElement(children: .combine)
            Spacer(minLength: RX.Space.l)
            HStack(spacing: RX.Space.s) {
                capsule(Text("Nouvel élément"), systemImage: "plus") { model.showNewItemPicker = true }
                    .accessibilityIdentifier("rx.mac.newItem")
                capsule(Text("Générer"), systemImage: "character.cursor.ibeam") { model.showGenerator = true }
                    .accessibilityIdentifier("rx.mac.generate")
                ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score ?? 0)")) {
                    capsuleLabel(Text("common.share"), systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.plain)
                .disabled(score == nil)
                .accessibilityIdentifier("rx.mac.share")
            }
        }
        .padding(EdgeInsets(top: 28, leading: 32, bottom: 28, trailing: 32))
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
        .onTapGesture { model.page = .watchtower }
    }

    private func capsule(_ title: Text, systemImage: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { capsuleLabel(title, systemImage: systemImage) }
            .buttonStyle(.plain)
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
        RXCard {
            HStack {
                RXCardHeader(Text("Récents"))
                Button { model.showItems(.all) } label: {
                    Text("rx.home.seeAll")
                        .rxFont(.calloutMedium)
                        .foregroundStyle(RX.Palette.accentText.color)
                }
                .buttonStyle(.plain)
                .padding(.trailing, RX.Space.l)
                .padding(.top, 10)
            }
            ForEach(recents, id: \.id) { summary in
                Button { open(summary) } label: { RXSummaryRow(summary: summary) }
                    .buttonStyle(.plain)
            }
        }
        .frame(maxWidth: .infinity)
        .accessibilityIdentifier("rx.mac.recents")
    }

    private var vaultsCard: some View {
        let summaries = model.session.summaries
        return RXCard {
            RXCardHeader(Text("Coffres"))
            ForEach(model.session.vaults, id: \.id) { vault in
                let count = summaries.filter { ItemFilter.vault(vault.id).matches($0) }.count
                Button { model.showItems(.vault(vault.id)) } label: {
                    RXItemRow(title: Text(vault.meta.name), subtitle: Text("browse.items \(count)"), chevron: true) {
                        VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 40)
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .frame(maxWidth: .infinity)
        .accessibilityIdentifier("rx.mac.vaults")
    }

    private func favoritesCard(_ favorites: [FfiItemSummary]) -> some View {
        RXCard {
            RXCardHeader(Text("Favoris"))
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
                                .padding(.horizontal, 2)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.plain)
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
#endif
