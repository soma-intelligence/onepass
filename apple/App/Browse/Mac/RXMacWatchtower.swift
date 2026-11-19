#if os(macOS)
import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// Watchtower on the Mac in the RX look (Penpot "Mac · Watchtower"), same data as the iPhone tab:
/// the title and status line, the gauge card on the left (as tall as its neighbour) with the alert
/// cards and the three stat tiles beside it, the Improve list underneath, then the strength, clear checks and breach
/// setting cards. Every card opens the flagged items in the list, as the classic page does.
struct RXMacWatchtowerContent<Status: View>: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    let statusLine: Status

    private typealias RX = Theme.RX
    private var watchtower: WatchtowerModel { model.watchtower }

    var body: some View {
        VStack(alignment: .leading, spacing: RX.Space.l) {
            VStack(alignment: .leading, spacing: RX.Space.xs) {
                // swiftlint:disable:next db_unlocalized_string - product name, the same in every language
                Text(verbatim: "Watchtower")
                    .rxFont(.largeTitle)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                statusLine
            }
            // The report is the data of this page, as on iPhone: loading (gauge and tiles redacted),
            // empty vault, failure (retry; over an older report, an error toast with Retry), content.
            DBLoadableView(
                WatchtowerModel.loadable(
                    report: watchtower.report, phase: watchtower.phase, items: model.session.summaries.count),
                empty: emptyState, retry: retry
            ) { report in
                VStack(alignment: .leading, spacing: RX.Space.l) {
                    // Gauge on the left, alerts over the stat tiles on the right. The gauge card
                    // stretches to the height of the right column (gauge centred), so both columns
                    // end on the same line however many alerts there are.
                    HStack(alignment: .top, spacing: RX.Space.l) {
                        gauge(Int(report.score))
                        VStack(spacing: RX.Space.m) {
                            alerts(report)
                            statTiles(report)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                    improve(report)
                    StrengthCard(levels: report.strength.map(Int.init))
                    clearChecks(report)
                }
            } placeholder: {
                HStack(alignment: .top, spacing: RX.Space.l) {
                    gauge(nil)
                    tiles { stat in
                        RXStatTile(value: 0, label: Text(stat.label), systemImage: stat.symbol, color: stat.color)
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            BreachSettingCard()
        }
        .environment(\.rxCards, true)
        .accessibilityIdentifier("rx.mac.watchtower")
    }

    private func gauge(_ score: Int?) -> some View {
        RXCard {
            ScoreGauge(score: score)
                .padding(RX.Space.xl)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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

    /// The checks with nothing flagged: a green disc only when the check ran; one whose source
    /// did not run says why, in grey.
    @ViewBuilder private func clearChecks(_ report: FfiWatchtowerReport) -> some View {
        let clear = WatchtowerCard.all.filter { !$0.isFlagged(in: report) }
        if !clear.isEmpty {
            RXCard {
                RXCardHeader(Text("browse.nothingToReport"))
                ForEach(clear) { card in
                    let note = card.unavailableNote(
                        report: report, checkBreaches: watchtower.checkBreaches,
                        breachCatalog: watchtower.breachCatalogUsed)
                    RXItemRow(title: Text(card.title), subtitle: Text(note ?? card.message)) {
                        ColorDisc(
                            systemImage: card.symbol,
                            color: note == nil ? RX.Palette.positive.color : RX.Palette.textTertiary.color)
                    }
                    .accessibilityIdentifier("watchtower.card.\(card.id)")
                }
            }
        }
    }

    /// One red card per alert check that flagged items; with none, green only when every red
    /// check really ran, else a neutral card that says what was not checked (as on iPhone).
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
                Button { show(card, ids) } label: {
                    RXAlertCard(
                        title: RXWatchtowerText.alertTitle(card, count: ids.count), message: Text(card.message),
                        systemImage: "exclamationmark", positive: false, chevron: true)
                }
                .rxPress()
                .accessibilityIdentifier("watchtower.show.\(card.id)")
            }
        }
    }

    /// The three stat tiles in a row (a column at accessibility text sizes).
    private func tiles<Tile: View>(@ViewBuilder _ tile: @escaping (RXWatchtowerStat) -> Tile) -> some View {
        RXWatchtowerStat.layout(dynamicTypeSize).callAsFunction {
            ForEach(RXWatchtowerStat.all, id: \.id) { stat in
                tile(stat)
            }
        }
    }

    private func statTiles(_ report: FfiWatchtowerReport) -> some View {
        tiles { stat in
            if let card = WatchtowerCard.all.first(where: { $0.id == stat.id }) {
                let ids = card.itemIDs(in: report)
                Button { show(card, ids) } label: {
                    RXStatTile(
                        value: ids.count, label: Text(stat.label),
                        systemImage: stat.symbol, color: stat.color)
                }
                // Dims at zero (disabled), scales under the click otherwise.
                .rxPress()
                .disabled(ids.isEmpty)
                .accessibilityIdentifier("rx.watchtower.stat.\(stat.id)")
            }
        }
    }

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
        Button { show(card, ids) } label: {
            RXItemRow(
                title: Text(card.title), subtitle: Text(card.message), count: ids.count,
                chevron: true
            ) {
                ColorDisc(systemImage: card.symbol, color: card.color)
            }
        }
        .rxPress()
        .accessibilityIdentifier("watchtower.show.\(card.id)")
    }

    private func show(_ card: WatchtowerCard, _ ids: Set<String>) {
        model.showWatchtowerItems(title: card.title, itemIDs: ids, check: card.siteCheck)
    }
}
#endif
