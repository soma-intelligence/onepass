#if os(macOS)
import DesignKit
import SwiftUI
import VaultKit

/// Watchtower on the Mac in the RX look (Penpot "Mac · Watchtower"), same data as the iPhone tab:
/// the title and status line, the gauge card on the left with the alert cards and the three stat
/// tiles beside it, the Improve list underneath, then the strength, clear checks and breach
/// setting cards. Every card opens the flagged items in the list, as the classic page does.
struct RXMacWatchtowerContent<Status: View>: View {
    @Environment(AppModel.self) private var model
    let statusLine: Status

    private typealias RX = Theme.RX
    private var watchtower: WatchtowerModel { model.watchtower }

    var body: some View {
        let report = watchtower.report
        VStack(alignment: .leading, spacing: RX.Space.l) {
            VStack(alignment: .leading, spacing: RX.Space.xs) {
                Text(verbatim: "Watchtower")
                    .rxFont(.largeTitle)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                statusLine
            }
            HStack(alignment: .top, spacing: RX.Space.l) {
                RXCard {
                    ScoreGauge(score: report.map { Int($0.score) })
                        .frame(maxWidth: .infinity)
                        .padding(RX.Space.xl)
                }
                .frame(maxWidth: .infinity)
                VStack(spacing: RX.Space.m) {
                    if let report {
                        alerts(report)
                        statTiles(report)
                    }
                }
                .frame(maxWidth: .infinity)
            }
            if let report {
                improve(report)
                StrengthCard(levels: report.strength.map(Int.init))
                let clear = WatchtowerCard.all.filter { $0.itemIDs(in: report).isEmpty }
                if !clear.isEmpty {
                    RXCard {
                        RXCardHeader(Text("rx.watchtower.allClear"))
                        ForEach(clear) { card in
                            RXItemRow(title: Text(card.title), subtitle: Text(card.message)) {
                                ColorDisc(systemImage: card.symbol, color: RX.Palette.positive.color)
                            }
                        }
                    }
                }
            }
            BreachSettingCard()
        }
        .environment(\.rxCards, true)
        .accessibilityIdentifier("rx.mac.watchtower")
    }

    @ViewBuilder private func alerts(_ report: FfiWatchtowerReport) -> some View {
        let flagged = WatchtowerCard.all.filter { $0.isAlert && !$0.itemIDs(in: report).isEmpty }
        if flagged.isEmpty {
            RXAlertCard(
                title: Text("rx.watchtower.allClear"), message: Text("rx.watchtower.allClear.message"),
                systemImage: "checkmark.seal.fill", positive: true, chevron: false)
        } else {
            ForEach(flagged) { card in
                let ids = card.itemIDs(in: report)
                Button { show(card, ids) } label: {
                    RXAlertCard(
                        title: RXWatchtowerText.alertTitle(card, count: ids.count), message: Text(card.message),
                        systemImage: "exclamationmark", positive: false, chevron: true)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("watchtower.show.\(card.id)")
            }
        }
    }

    private func statTiles(_ report: FfiWatchtowerReport) -> some View {
        HStack(alignment: .top, spacing: RX.Space.m) {
            ForEach(RXWatchtowerStat.all, id: \.id) { stat in
                if let card = WatchtowerCard.all.first(where: { $0.id == stat.id }) {
                    let ids = card.itemIDs(in: report)
                    Button { show(card, ids) } label: {
                        RXStatTile(
                            value: Text(ids.count, format: .number), label: Text(stat.label),
                            systemImage: stat.symbol, color: stat.color)
                    }
                    .buttonStyle(.plain)
                    .disabled(ids.isEmpty)
                    .accessibilityIdentifier("rx.watchtower.stat.\(stat.id)")
                }
            }
        }
    }

    @ViewBuilder private func improve(_ report: FfiWatchtowerReport) -> some View {
        let statIDs = Set(RXWatchtowerStat.all.map(\.id))
        let cards = WatchtowerCard.all.filter {
            !$0.isAlert && !statIDs.contains($0.id) && !$0.itemIDs(in: report).isEmpty
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
                title: Text(card.title), subtitle: Text(card.message), value: Text(ids.count, format: .number),
                chevron: true
            ) {
                ColorDisc(systemImage: card.symbol, color: card.color)
            }
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("watchtower.show.\(card.id)")
    }

    private func show(_ card: WatchtowerCard, _ ids: Set<String>) {
        model.showWatchtowerItems(title: card.title, itemIDs: ids, check: card.siteCheck)
    }
}
#endif
