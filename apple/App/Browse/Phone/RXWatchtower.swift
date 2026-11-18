import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

#if os(iOS)

/// Watchtower in the RX look (Penpot "iPhone · Watchtower"), with the score gauge kept in place of
/// the mock's line chart (owner decision): the header row (account menu, title, share button), the gauge, one alert card per
/// red issue (or a green all-clear card), three stat tiles (weak, reused, 2FA), the Improve card with
/// the other flagged checks, then the classic strength, clear checks and breach setting cards.
/// Every tile and row pushes the same flagged items list as the classic tab.
/// The centre line of the Watchtower title: the avatar and the share button sit on it, not on the
/// centre of the title and subtitle block.
private extension VerticalAlignment {
    enum RXTitleCentre: AlignmentID {
        static func defaultValue(in context: ViewDimensions) -> CGFloat { context[VerticalAlignment.center] }
    }
    static let rxTitleCentre = VerticalAlignment(RXTitleCentre.self)
}

struct RXWatchtowerContent<Scan: View, Status: View>: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    let score: Int?
    let scanCard: Scan
    let statusLine: Status

    private typealias RX = Theme.RX
    private var watchtower: WatchtowerModel { model.watchtower }

    var body: some View {
        VStack(alignment: .leading, spacing: RX.Space.l) {
            header
            // The gauge, the status and the scan card: the only part that animates with the run.
            VStack(spacing: RX.Space.l) {
                PhoneScoreGauge(
                    score: score, phase: watchtower.phase, isEmptyVault: model.session.summaries.isEmpty, rx: true)
                    .frame(maxWidth: .infinity)
                statusLine
                    .frame(maxWidth: .infinity)
                scanCard
            }
            .dbAnimation(value: watchtower.isRunning)
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
                    let clear = WatchtowerCard.all.filter { !$0.isFlagged(in: report) }
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

    /// The data state of the page (`WatchtowerModel.loadable`, shared with the Mac page).
    static func state(report: FfiWatchtowerReport?, phase: WatchtowerModel.Phase, items: Int)
        -> DBLoadable<FfiWatchtowerReport>
    {
        WatchtowerModel.loadable(report: report, phase: phase, items: items)
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
        RXWatchtowerStat.layout(dynamicTypeSize).callAsFunction {
            ForEach(RXWatchtowerStat.all, id: \.id) { stat in
                RXStatTile(value: 0, label: Text(stat.label), systemImage: stat.symbol, color: stat.color)
            }
        }
    }

    /// One header row: the account menu, "Watchtower" (Large title) over "Security score", and the
    /// share button, all on the avatar's centre line (owner feedback 2026-11-16: the title sits
    /// beside the avatar, the share button lives in the header). At accessibility text sizes the
    /// title moves under the avatar row so it keeps its full width.
    @ViewBuilder private var header: some View {
        if dynamicTypeSize.isAccessibilitySize {
            VStack(alignment: .leading, spacing: RX.Space.s) {
                HStack {
                    AccountMenu()
                    Spacer(minLength: RX.Space.s)
                    shareButton
                }
                titleBlock
            }
        } else {
            HStack(alignment: .rxTitleCentre, spacing: RX.Space.m) {
                AccountMenu()
                    .alignmentGuide(.rxTitleCentre) { $0[VerticalAlignment.center] }
                titleBlock
                Spacer(minLength: RX.Space.s)
                shareButton
                    .alignmentGuide(.rxTitleCentre) { $0[VerticalAlignment.center] }
            }
        }
    }

    private var titleBlock: some View {
        VStack(alignment: .leading, spacing: 0) {
            // swiftlint:disable:next db_unlocalized_string - product name, the same in every language
            Text(verbatim: "Watchtower")
                .rxFont(.largeTitle)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .dbText(maxLines: 1, minimumScale: 0.7)
                .accessibilityAddTraits(.isHeader)
                .alignmentGuide(.rxTitleCentre) { $0[VerticalAlignment.center] }
            Text("browse.securityScore")
                .rxFont(.calloutMedium)
                .foregroundStyle(RX.Palette.textSecondary.color)
        }
    }

    /// Share the score, once there is one (same glass glyph as the other header controls).
    @ViewBuilder private var shareButton: some View {
        if let score {
            ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score)")) {
                RXGlassGlyph(systemImage: "square.and.arrow.up")
            }
            .rxPress()
            .accessibilityLabel(Text("browse.shareMyScore"))
            .accessibilityIdentifier("watchtower.share")
        }
    }

    /// One red card per alert check that flagged items. With none: a green card only when every
    /// red check really ran, else a neutral card that says what was not checked.
    @ViewBuilder private func alerts(_ report: FfiWatchtowerReport) -> some View {
        let flagged = WatchtowerCard.all.filter { $0.isAlert && $0.isFlagged(in: report) }
        let gap = WatchtowerCard.alertGap(
            report: report, checkBreaches: watchtower.checkBreaches, breachCatalog: watchtower.breachCatalogUsed,
            isRunning: watchtower.isRunning)
        if flagged.isEmpty, let gap {
            RXAlertCard(
                title: Text("rx.watchtower.notChecked"), message: Text(gap),
                systemImage: "shield.slash", tone: .neutral, chevron: false)
                .accessibilityIdentifier("rx.watchtower.notChecked")
        } else if flagged.isEmpty {
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
        RXWatchtowerStat.layout(dynamicTypeSize).callAsFunction {
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
            !$0.isAlert && !statIDs.contains($0.id) && $0.isFlagged(in: report)
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

    /// The three tiles side by side, stacked at accessibility text sizes so they never truncate.
    static func layout(_ size: DynamicTypeSize) -> AnyLayout {
        size.isAccessibilitySize
            ? AnyLayout(VStackLayout(spacing: Theme.RX.Space.m))
            : AnyLayout(HStackLayout(alignment: .top, spacing: Theme.RX.Space.m))
    }

    @MainActor static let all: [RXWatchtowerStat] = [
        .init(id: "weak", label: "rx.watchtower.stat.weak", symbol: "lock.fill", color: Theme.RX.Hue.orange),
        .init(id: "reused", label: "rx.watchtower.stat.reused", symbol: "square.on.square.fill", color: Theme.RX.Hue.violet),
        .init(id: "2fa", label: "rx.watchtower.stat.twoFactor", symbol: "checkmark.shield.fill", color: Theme.RX.Hue.teal),
    ]
}

/// The alert card of the mock: a red (or green) wash, a white disc with the glyph, the title
/// (Headline) and one line (Footnote), all white.
struct RXAlertCard: View {
    /// Red issue, green all-clear, or neutral (a check that did not run: no verdict either way).
    enum Tone { case alert, positive, neutral }

    let title: Text
    let message: Text
    let systemImage: String
    let tone: Tone
    let chevron: Bool

    init(title: Text, message: Text, systemImage: String, tone: Tone, chevron: Bool) {
        self.title = title
        self.message = message
        self.systemImage = systemImage
        self.tone = tone
        self.chevron = chevron
    }

    init(title: Text, message: Text, systemImage: String, positive: Bool, chevron: Bool) {
        self.init(title: title, message: message, systemImage: systemImage, tone: positive ? .positive : .alert, chevron: chevron)
    }

    var body: some View {
        if tone == .neutral {
            neutral
        } else {
            washed(tone == .positive ? Theme.RX.Wash.positive : Theme.RX.Wash.alert)
        }
    }

    /// The card surface with primary words and a secondary glyph.
    private var neutral: some View {
        content(foreground: Theme.RX.Palette.textPrimary.color, glyph: Theme.RX.Palette.textSecondary.color,
                disc: Theme.RX.Palette.raisedBackground.color)
            .background(
                Theme.RX.Palette.cardBackground.color,
                in: RoundedRectangle(cornerRadius: Theme.RX.Radius.card, style: .continuous))
            .accessibilityElement(children: .combine)
    }

    private func washed(_ colors: [Color]) -> some View {
        content(foreground: .white, glyph: colors[1], disc: .white)
            .background(
                LinearGradient(colors: colors, startPoint: .top, endPoint: .bottom),
                in: RoundedRectangle(cornerRadius: Theme.RX.Radius.card, style: .continuous))
            .rxRaisedShadow()
            .accessibilityElement(children: .combine)
    }

    private func content(foreground: Color, glyph: Color, disc: Color) -> some View {
        HStack(spacing: Theme.RX.Space.m) {
            Image(systemName: systemImage)
                .font(Theme.RX.Glyph.font(Theme.RX.Glyph.action, weight: .bold))
                .foregroundStyle(glyph)
                .frame(width: Theme.RX.Metrics.glassButton, height: Theme.RX.Metrics.glassButton)
                .background(disc, in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.RX.Space.xxs) {
                title
                    .rxFont(.headline)
                    .dbText()
                message
                    .rxFont(.footnote)
                    .dbText()
            }
            .multilineTextAlignment(.leading)
            Spacer(minLength: Theme.RX.Space.xs)
            if chevron {
                Image(systemName: "chevron.right")
                    .font(Theme.RX.Glyph.font(Theme.RX.Glyph.chevron, weight: .bold))
                    .accessibilityHidden(true)
            }
        }
        .foregroundStyle(foreground)
        .padding(Theme.RX.Space.l)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
