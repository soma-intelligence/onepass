#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

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
            header
            PhoneScoreGauge(score: score)
                .frame(maxWidth: .infinity)
            statusLine
                .frame(maxWidth: .infinity)
            scanCard
            if let report = watchtower.report {
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
            BreachSettingCard()
        }
        .environment(\.rxCards, true)
    }

    /// "Watchtower" (Large title) over "Security score", the share button on the right.
    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: RX.Space.xs) {
                Text(verbatim: "Watchtower")
                    .rxFont(.largeTitle)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .accessibilityAddTraits(.isHeader)
                Text("browse.securityScore")
                    .rxFont(.calloutMedium)
                    .foregroundStyle(RX.Palette.textSecondary.color)
            }
            Spacer()
            if let score {
                ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score)")) {
                    RXGlassGlyph(systemImage: "square.and.arrow.up")
                }
                .buttonStyle(PressableButtonStyle())
                .accessibilityLabel(Text("browse.shareMyScore"))
                .accessibilityIdentifier("watchtower.share")
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
                        title: Text(card.title), message: Text(card.message),
                        systemImage: "exclamationmark", count: ids.count, positive: false, chevron: true)
                }
                .buttonStyle(PressableButtonStyle())
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
                            value: Text(ids.count, format: .number), label: Text(stat.label),
                            systemImage: stat.symbol, color: stat.color)
                    }
                    .buttonStyle(PressableButtonStyle())
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
}

/// The checks the stat tiles show, with the disc of the mock.
private struct RXWatchtowerStat {
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
private struct RXAlertCard: View {
    let title: Text
    let message: Text
    let systemImage: String
    /// Shown in the white disc in place of the glyph.
    var count: Int? = nil
    let positive: Bool
    let chevron: Bool

    var body: some View {
        let colors: [Color] = positive
            ? [Color(red: 0x2B / 255, green: 0xB6 / 255, blue: 0x73 / 255), Color(red: 0x11 / 255, green: 0x93 / 255, blue: 0x58 / 255)]
            : [Color(red: 0xF0 / 255, green: 0x62 / 255, blue: 0x5F / 255), Color(red: 0xD9 / 255, green: 0x3C / 255, blue: 0x3F / 255)]
        HStack(spacing: 14) {
            Group {
                if let count {
                    Text(count, format: .number).font(.system(size: 18, weight: .bold)).monospacedDigit()
                } else {
                    Image(systemName: systemImage).font(.system(size: 20, weight: .bold))
                }
            }
                .foregroundStyle(colors[1])
                .frame(width: 44, height: 44)
                .background(.white, in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                title.rxFont(.headline)
                message
                    .rxFont(.footnote)
                    .opacity(0.85)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .multilineTextAlignment(.leading)
            Spacer(minLength: 4)
            if chevron {
                Image(systemName: "chevron.right")
                    .font(.system(size: 14, weight: .bold))
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
#endif
