import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

#if os(iOS)

/// Watchtower in the RX look (Penpot "iPhone · Watchtower"), with the score gauge kept in place of
/// the mock's line chart (owner decision): the title and share button, the gauge, one alert card per
/// red issue (or a green all-clear card), three stat tiles (weak, reused, 2FA), the Improve card with
/// the other flagged checks, then the classic strength, clear checks and breach setting cards.
/// Every tile and row pushes the same flagged items list as the classic tab.
struct RXWatchtowerContent<Scan: View, Status: View>: View {
    @Environment(AppModel.self) private var model
    let score: Int?
    let scanCard: Scan
    let statusLine: Status

    private typealias RX = Theme.RX
    private var watchtower: WatchtowerModel { model.watchtower }

    var body: some View {
        VStack(alignment: .leading, spacing: RX.Space.l) {
            HStack {
                AccountMenu()
                Spacer(minLength: 0)
            }
            header
            PhoneScoreGauge(score: score)
                .frame(maxWidth: .infinity)
            statusLine
                .frame(maxWidth: .infinity)
            scanCard
            // The report is the data of this page: loading (skeleton), empty vault, failure
            // (retry; over an older report, an error toast with Retry) and content (UX-STATE-01).
            DBLoadableView(Self.state(report: watchtower.report, phase: watchtower.phase, items: model.session.summaries.count),
                           empty: emptyState, retry: retry) { report in
                VStack(alignment: .leading, spacing: RX.Space.l) {
                    alerts(report)
                    statTiles(report)
                    improve(report)
                    CryptoPhraseAlertCard()
                    StrengthCard(levels: report.strength.map(Int.init))
                    let clear = WatchtowerCard.all.filter { !WatchtowerTab.isFlagged($0, in: report) }
                    if !clear.isEmpty {
                        ClearChecksCard(
                            cards: clear, report: report, checkBreaches: watchtower.checkBreaches,
                            breachCatalog: watchtower.breachCatalogUsed)
                    }
                }
            } placeholder: {
                placeholder
            }
            BreachSettingCard()
        }
        .environment(\.rxCards, true)
    }

    /// The data state of the page, from the model: no item is an empty vault, a failed run keeps
    /// the last report under the error, no report yet is loading.
    static func state(report: FfiWatchtowerReport?, phase: WatchtowerModel.Phase, items: Int)
        -> DBLoadable<FfiWatchtowerReport>
    {
        if items == 0 { return .empty }
        if case .failed(let message) = phase {
            return .failed(DBLoadError(title: String(localized: "rx.watchtower.failed"), message: message), previous: report)
        }
        if let report { return .content(report) }
        return .loading(previous: nil)
    }

    private var retry: @MainActor @Sendable () -> Void {
        let model = model
        return { model.watchtower.refresh(model.session) }
    }

    private var emptyState: DBEmptyState {
        let model = model
        return DBEmptyState(
            String(localized: "rx.watchtower.empty"), systemImage: "checkmark.shield",
            message: String(localized: "rx.watchtower.empty.message"),
            actionTitle: String(localized: "Nouvel élément")) { model.showNewItemPicker = true }
    }

    /// While the first report runs: the stat tiles at zero, redacted with the shimmer.
    private var placeholder: some View {
        HStack(alignment: .top, spacing: RX.Space.m) {
            ForEach(RXWatchtowerStat.all, id: \.id) { stat in
                RXStatTile(value: 0, label: Text(stat.label), systemImage: stat.symbol, color: stat.color)
            }
        }
    }

    /// "Watchtower" (Large title) over "Security score", the share button on the right.
    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: RX.Space.xs) {
                // swiftlint:disable:next db_unlocalized_string - product name, the same in every language
                Text(verbatim: "Watchtower")
                    .rxFont(.largeTitle)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                Text("browse.securityScore")
                    .rxFont(.calloutMedium)
                    .foregroundStyle(RX.Palette.textSecondary.color)
            }
            Spacer(minLength: RX.Space.s)
            // The shield art of the mock, top right, with the share button on its corner.
            ZStack(alignment: .topTrailing) {
                Image("rx-watch-shield")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 120, height: 120)
                    .padding(.top, RX.Space.s)
                    .padding(.trailing, RX.Space.l)
                    .accessibilityHidden(true)
                if let score {
                    ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score)")) {
                        RXGlassGlyph(systemImage: "square.and.arrow.up")
                    }
                    .rxPress()
                    .accessibilityLabel(Text("browse.shareMyScore"))
                    .accessibilityIdentifier("watchtower.share")
                }
            }
        }
        .padding(.top, RX.Space.s)
        .padding(.horizontal, RX.Space.xs)
    }

    /// One red card per alert check that flagged items, or a green card when none did.
    @ViewBuilder private func alerts(_ report: FfiWatchtowerReport) -> some View {
        let flagged = WatchtowerCard.all.filter { $0.isAlert && WatchtowerTab.isFlagged($0, in: report) }
        if flagged.isEmpty {
            RXAlertCard(
                title: Text("rx.watchtower.allClear"), message: Text("rx.watchtower.allClear.message"),
                systemImage: "checkmark.seal.fill", positive: true, chevron: false)
                .accessibilityIdentifier("rx.watchtower.allClear")
        } else {
            ForEach(flagged) { card in
                let ids = card.itemIDs(in: report)
                NavigationLink(value: PhoneRoute.watchtower(title: card.title, itemIDs: ids, check: card.siteCheck)) {
                    RXAlertCard(
                        title: RXWatchtowerText.alertTitle(card, count: ids.count), message: Text(card.message),
                        systemImage: "exclamationmark", positive: false, chevron: true)
                }
                .rxPress()
                .routeZoomSource(.watchtower(title: card.title, itemIDs: ids, check: card.siteCheck))
                .accessibilityIdentifier("watchtower.show.\(card.id)")
            }
        }
    }

    private func statTiles(_ report: FfiWatchtowerReport) -> some View {
        HStack(alignment: .top, spacing: RX.Space.m) {
            ForEach(RXWatchtowerStat.all, id: \.id) { stat in
                if let card = WatchtowerCard.all.first(where: { $0.id == stat.id }) {
                    let ids = card.itemIDs(in: report)
                    NavigationLink(value: PhoneRoute.watchtower(title: card.title, itemIDs: ids, check: card.siteCheck)) {
                        RXStatTile(
                            value: ids.count, label: Text(stat.label), systemImage: stat.symbol, color: stat.color)
                    }
                    .rxPress()
                    .routeZoomSource(.watchtower(title: card.title, itemIDs: ids, check: card.siteCheck))
                    .disabled(ids.isEmpty)
                    .accessibilityIdentifier("rx.watchtower.stat.\(stat.id)")
                }
            }
        }
    }

    /// The other flagged checks (not an alert, not a stat tile), and the items a former member saw.
    @ViewBuilder private func improve(_ report: FfiWatchtowerReport) -> some View {
        let statIDs = Set(RXWatchtowerStat.all.map(\.id))
        let cards = WatchtowerCard.all.filter {
            !$0.isAlert && !statIDs.contains($0.id) && WatchtowerTab.isFlagged($0, in: report)
        }
        let seen = model.seenByFormerMemberIDs
        if !cards.isEmpty || !seen.isEmpty {
            RXCard {
                RXCardHeader(Text("rx.watchtower.improve"))
                ForEach(cards) { card in
                    row(card, ids: card.itemIDs(in: report))
                }
                if !seen.isEmpty {
                    row(.seenByFormerMember, ids: seen)
                }
            }
        }
    }

    private func row(_ card: WatchtowerCard, ids: Set<String>) -> some View {
        NavigationLink(value: PhoneRoute.watchtower(title: card.title, itemIDs: ids, check: card.siteCheck)) {
            RXItemRow(title: Text(card.title), subtitle: Text(card.message), count: ids.count, chevron: true) {
                ColorDisc(systemImage: card.symbol, color: card.color)
            }
        }
        .rxPress()
        .routeZoomSource(.watchtower(title: card.title, itemIDs: ids, check: card.siteCheck))
        .accessibilityIdentifier("watchtower.show.\(card.id)")
    }
}

#endif

/// The RX Watchtower texts shared by the iPhone tab and the Mac page.
enum RXWatchtowerText {
    /// "1 exposed account": a plural entry per red check (never a figure glued to a title).
    static func alertTitle(_ card: WatchtowerCard, count: Int) -> Text {
        switch card.id {
        case "compromised": Text("rx.watchtower.alert.compromised \(count)")
        case "breached_site": Text("rx.watchtower.alert.breachedSite \(count)")
        case "provider_exposed": Text("rx.watchtower.alert.providerExposed \(count)")
        case "expiring": Text("rx.watchtower.alert.expiring \(count)")
        default: Text(card.title)
        }
    }

}

/// The checks the stat tiles show, with the disc of the mock.
struct RXWatchtowerStat {
    let id: String
    let label: LocalizedStringKey
    let symbol: String
    let color: Color

    @MainActor static let all: [RXWatchtowerStat] = [
        .init(id: "weak", label: "rx.watchtower.stat.weak", symbol: "lock.fill", color: Theme.RX.Hue.orange),
        .init(id: "reused", label: "rx.watchtower.stat.reused", symbol: "square.on.square.fill", color: Theme.RX.Hue.violet),
        .init(id: "2fa", label: "rx.watchtower.stat.twoFactor", symbol: "checkmark.shield.fill", color: Theme.RX.Hue.teal),
    ]
}

/// The alert card of the mock: a red (or green) wash, a white disc with the glyph, the title
/// (Headline) and one line (Footnote), all white.
struct RXAlertCard: View {
    let title: Text
    let message: Text
    let systemImage: String
    let positive: Bool
    let chevron: Bool

    var body: some View {
        let colors = positive ? Theme.RX.Wash.positive : Theme.RX.Wash.alert
        HStack(spacing: Theme.RX.Space.m) {
            Image(systemName: systemImage)
                .font(Theme.RX.Glyph.font(Theme.RX.Glyph.action, weight: .bold))
                .foregroundStyle(colors[1])
                .frame(width: 44, height: 44)
                .background(.white, in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.RX.Space.xxs) {
                title
                    .rxFont(.headline)
                    .dbText()
                message
                    .rxFont(.footnote)
                    .opacity(0.85)
                    .dbText()
            }
            .multilineTextAlignment(.leading)
            Spacer(minLength: 4)
            if chevron {
                Image(systemName: "chevron.right")
                    .font(Theme.RX.Glyph.font(Theme.RX.Glyph.chevron, weight: .bold))
                    .accessibilityHidden(true)
            }
        }
        .foregroundStyle(.white)
        .padding(Theme.RX.Space.l)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            LinearGradient(colors: colors, startPoint: .top, endPoint: .bottom),
            in: RoundedRectangle(cornerRadius: Theme.RX.Radius.card, style: .continuous))
        .shadow(color: colors[0].opacity(0.25), radius: 10, y: 8)
        .accessibilityElement(children: .combine)
    }
}
