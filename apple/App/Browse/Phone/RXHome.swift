#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Accueil in the RX look (Penpot "iPhone · Home"): a full-bleed photo hero under the status bar
/// (account menu, search pill, Watchtower and new item glass buttons, the security score, four
/// quick actions), then the page sheet with the mock's cards in its order (Récents, Favoris,
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
        RXHeroPage(photo: Image("rx-hero")) {
            VStack(spacing: RX.Space.xl) {
                topBar
                RXHomeScore(itemCount: itemCount)
                    .padding(.top, RX.Space.xxl)
                quickActions
                    .padding(.top, RX.Space.xl)
            }
            .environment(\.colorScheme, .dark)
        } sheet: {
            VStack(spacing: RX.Space.l) {
                if !recents.isEmpty { recentCard }
                if !favorites.isEmpty { favoritesCard }
                vaultsCard
                extras
            }
        }
        .toolbar(.hidden, for: .navigationBar)
    }

    private var topBar: some View {
        HStack(spacing: 10) {
            AccountMenu()
            Button { openTab(.search) } label: {
                HStack(spacing: RX.Space.s) {
                    Image(systemName: "magnifyingglass").font(.system(size: 17, weight: .semibold))
                    Text("common.search").rxFont(.body).opacity(0.85)
                    Spacer(minLength: 0)
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 14)
                .frame(height: 40)
                .background(.white.opacity(0.18), in: Capsule())
                .background(.ultraThinMaterial.opacity(0.6), in: Capsule())
                .contentShape(Capsule())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("rx.home.search")
            GlassButton(Text(verbatim: "Watchtower"), systemImage: "checkmark.shield.fill", diameter: 40, onPhoto: true) {
                openTab(.watchtower)
            }
            GlassButton(Text("Nouvel élément"), systemImage: "plus", diameter: 40, onPhoto: true) {
                model.showNewItemPicker = true
            }
            .accessibilityIdentifier("items.new")
        }
    }

    /// New item, Generate, Share (the security score), More (the account panel's actions).
    private var quickActions: some View {
        let score = model.watchtower.report.map { Int($0.score) }
        return QuickActionRow {
            Button { model.showNewItemPicker = true } label: {
                QuickActionLabel(Text("Nouvel élément"), systemImage: "plus", onPhoto: true)
            }
            .accessibilityIdentifier("rx.home.newItem")
            Button { model.showGenerator = true } label: {
                QuickActionLabel(Text("Générer"), systemImage: "character.cursor.ibeam", onPhoto: true)
            }
            .accessibilityIdentifier("rx.home.generate")
            ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score ?? 0)")) {
                QuickActionLabel(Text("common.share"), systemImage: "square.and.arrow.up", onPhoto: true)
            }
            .disabled(score == nil)
            .accessibilityIdentifier("rx.home.share")
            Menu {
                Button("Réglages", systemImage: "gearshape") {
                    SettingsTiming.requested("home more")
                    model.showSettings = true
                }
                Button("Importer", systemImage: "square.and.arrow.down") { model.showImport = true }
                Button("account.panel.scanCode", systemImage: "qrcode.viewfinder") { model.showOtpScanner = true }
                Button("Configurer un appareil", systemImage: "qrcode") { model.showDeviceSetup = true }
                NavigationLink(value: PhoneRoute.duplicates) {
                    Label("rx.home.duplicates", systemImage: "square.on.square")
                }
                Divider()
                Button("Verrouiller", systemImage: "lock", role: .destructive) { model.perform(.lock) }
            } label: {
                QuickActionLabel(Text("rx.home.more"), systemImage: "ellipsis", onPhoto: true)
            }
            .accessibilityIdentifier("rx.home.more")
        }
        .buttonStyle(PressableButtonStyle())
    }

    private var recentCard: some View {
        RXCard {
            HStack {
                RXCardHeader(Text("Récents"))
                NavigationLink(value: PhoneRoute.list(.all)) {
                    Text("rx.home.seeAll")
                        .rxFont(.calloutMedium)
                        .foregroundStyle(RX.Palette.accentText.color)
                }
                .padding(.trailing, RX.Space.l)
                .padding(.top, 10)
            }
            ForEach(recents.prefix(3), id: \.id) { summary in
                PhoneItemLink(ref: ItemRef(vaultID: summary.vaultId, itemID: summary.id)) {
                    RXSummaryRow(summary: summary)
                }
                .buttonStyle(.plain)
            }
        }
        .accessibilityIdentifier("home.recents")
    }

    private var favoritesCard: some View {
        RXCard {
            RXCardHeader(Text("Favoris"))
            HStack(alignment: .top, spacing: 0) {
                ForEach(favorites.prefix(4), id: \.id) { summary in
                    PhoneItemLink(ref: ItemRef(vaultID: summary.vaultId, itemID: summary.id)) {
                        VStack(spacing: RX.Space.s) {
                            RXSummaryIcon(summary: summary, size: 56)
                            Text(summary.title)
                                .rxFont(.footnote)
                                .foregroundStyle(RX.Palette.textPrimary.color)
                                .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.plain)
                }
                ForEach(0..<max(0, 4 - min(favorites.count, 4)), id: \.self) { _ in
                    Color.clear.frame(maxWidth: .infinity, maxHeight: 1)
                }
            }
            .padding(EdgeInsets(top: RX.Space.s, leading: RX.Space.s, bottom: 14, trailing: RX.Space.s))
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
                        VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 40)
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .accessibilityIdentifier("rx.home.vaults")
    }
}

/// An item of the RX Home: its icon (loaded like the list rows), the title, the subtitle, and when
/// it was last used.
private struct RXSummaryRow: View {
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
private struct RXSummaryIcon: View {
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

/// The security score over the photo: the label with the item count, the figure over 100, the
/// status pill. Tapping it opens Watchtower.
struct RXHomeScore: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openPhoneTab) private var openTab
    let itemCount: Int

    private typealias RX = Theme.RX

    var body: some View {
        let score = model.watchtower.report.map { Int($0.score) }
        VStack(spacing: 6) {
            Text("rx.home.scoreLabel \(itemCount)")
                .rxFont(.calloutMedium)
                .foregroundStyle(.white.opacity(0.8))
            HStack(alignment: .lastTextBaseline, spacing: RX.Space.xs) {
                Text(score.map(String.init) ?? "–")
                    .font(.system(size: 64, weight: .bold))
                    .tracking(-2.5)
                    .monospacedDigit()
                    .contentTransition(.numericText())
                Text(verbatim: "/100")
                    .rxFont(.title)
                    .opacity(0.7)
            }
            .foregroundStyle(.white)
            if let score {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(ScoreGauge.color(score))
                    Text(ScoreGauge.label(score))
                        .rxFont(.footnoteBold)
                        .foregroundStyle(.white)
                }
                .padding(.horizontal, RX.Space.m)
                .frame(height: 30)
                .background(.white.opacity(0.18), in: Capsule())
                .background(.ultraThinMaterial.opacity(0.6), in: Capsule())
            }
        }
        .frame(maxWidth: .infinity)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .onTapGesture { openTab(.watchtower) }
        // The score comes from the Watchtower report: computed here too when the tab was not opened.
        .task(id: model.session.summariesRevision) { model.watchtower.refreshIfNeeded(model.session) }
    }
}
#endif
