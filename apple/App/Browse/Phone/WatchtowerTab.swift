#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Watchtower on iPhone: the score gauge on top with "Partager mon score", one paragraph, the
/// password strength, then one full-colour card per check that flagged something ("Voir les
/// éléments" pushes the flagged items), the checks with nothing to report in one card, and the
/// breach setting. Everything comes from the core's report (`WatchtowerModel`); nothing is shown
/// before it.
struct WatchtowerTab: View {
    @Environment(AppModel.self) private var model

    private var watchtower: WatchtowerModel { model.watchtower }

    var body: some View {
        let score = watchtower.report.map { Int($0.score) }
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(spacing: 14) {
                    PhoneScoreGauge(score: score)
                        .padding(.top, 4)
                    if let score {
                        ShareLink(item: String(localized: "Mon score de sécurité OnePass : \(score) sur 100.")) {
                            Label("Partager mon score", systemImage: "square.and.arrow.up")
                                .font(.subheadline.weight(.semibold))
                                .padding(.horizontal, 4)
                                .frame(minHeight: 30)
                        }
                        .buttonStyle(.glass)
                        .accessibilityIdentifier("watchtower.share")
                    }
                }
                .frame(maxWidth: .infinity)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Watchtower repère les mots de passe à changer et les sites où tu peux renforcer la sécurité de tes comptes.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    statusLine
                }
                .padding(.horizontal, 4)
                if let report = watchtower.report {
                    StrengthCard(levels: report.strength.map(Int.init))
                    let flagged = WatchtowerCard.all.filter { Self.isFlagged($0, in: report) }
                    ForEach(flagged) { card in
                        PhoneWatchtowerCard(card: card, count: card.itemIDs(in: report).count, ids: card.itemIDs(in: report))
                    }
                    let clear = WatchtowerCard.all.filter { !Self.isFlagged($0, in: report) }
                    if !clear.isEmpty {
                        ClearChecksCard(
                            cards: clear, report: report, checkBreaches: watchtower.checkBreaches,
                            breachCatalog: watchtower.breachCatalogUsed)
                    }
                }
                BreachSettingCard()
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 24)
        }
        .background(PhoneBackground())
        .navigationTitle("Watchtower")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            PhoneRootToolbar()
        }
        .refreshable { watchtower.refresh(model.session) }
        .task(id: model.session.summariesRevision) { watchtower.refreshIfNeeded(model.session) }
        .onChange(of: watchtower.checkBreaches) { watchtower.refreshIfNeeded(model.session) }
        .onChange(of: model.session.hiddenVaultIDs) { watchtower.refreshIfNeeded(model.session) }
        .accessibilityIdentifier("page.watchtower")
    }

    /// A check with items to look at (a check whose source did not run counts as clear here; the
    /// clear card says why it has no figure).
    static func isFlagged(_ card: WatchtowerCard, in report: FfiWatchtowerReport) -> Bool {
        !card.itemIDs(in: report).isEmpty
    }

    @ViewBuilder private var statusLine: some View {
        switch watchtower.phase {
        case .idle, .ready:
            if let report = watchtower.report {
                Text(report.itemsAnalyzed == 1
                     ? String(localized: "1 élément analysé") : String(localized: "\(report.itemsAnalyzed) éléments analysés"))
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
            }
        case .analyzing:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Analyse des éléments…").font(.footnote).foregroundStyle(.secondary)
            }
        case .checkingBreaches(let done, let total):
            HStack(spacing: 8) {
                ProgressView(value: Double(done), total: Double(max(total, 1))).frame(width: 120)
                Text("Vérification des fuites : \(done) sur \(total)").font(.footnote).foregroundStyle(.secondary)
            }
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .font(.footnote)
                .foregroundStyle(.orange)
        }
    }
}

/// The score as a three-quarter dial: a track, the filled arc in the score's color, tick marks
/// that light up to the score, the figure and its word in the middle. Flat colors, no glow.
struct PhoneScoreGauge: View {
    let score: Int?
    private static let ticks = 40
    private static let sweep = 270.0

    var body: some View {
        let fraction = Double(score ?? 0) / 100
        let color = score.map(ScoreGauge.color) ?? .secondary
        ZStack {
            Dial(fraction: 1)
                .stroke(Color.primary.opacity(0.10), style: StrokeStyle(lineWidth: 14, lineCap: .round))
            Dial(fraction: fraction)
                .stroke(color, style: StrokeStyle(lineWidth: 14, lineCap: .round))
                .animation(.smooth, value: fraction)
            // Ticks 0 through `lit` take the score's color, the rest stay faint.
            let lit = score == nil ? -1 : Int((fraction * Double(Self.ticks)).rounded())
            Ticks(count: Self.ticks, sweep: Self.sweep, indices: 0..<(lit + 1))
                .stroke(color.opacity(0.6), style: StrokeStyle(lineWidth: 2, lineCap: .round))
            Ticks(count: Self.ticks, sweep: Self.sweep, indices: (lit + 1)..<(Self.ticks + 1))
                .stroke(Color.primary.opacity(0.12), style: StrokeStyle(lineWidth: 2, lineCap: .round))
            VStack(spacing: 2) {
                Text(score.map(String.init) ?? "–")
                    .font(.system(size: 58, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                Text(score.map(ScoreGauge.label) ?? String(localized: "Analyse…"))
                    .font(.subheadline.weight(.semibold))
                    .textCase(.uppercase)
                    .foregroundStyle(score == nil ? AnyShapeStyle(.secondary) : AnyShapeStyle(color))
            }
            .offset(y: 4)
        }
        .frame(width: 210, height: 210)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Score de sécurité"))
        .accessibilityValue(Text(score.map { "\($0) sur 100, \(ScoreGauge.label($0))" } ?? ""))
    }

    /// The arc, opening at the bottom, filled clockwise from the lower left by `fraction`.
    private struct Dial: Shape {
        var fraction: Double
        var animatableData: Double {
            get { fraction }
            set { fraction = newValue }
        }

        func path(in rect: CGRect) -> Path {
            let radius = min(rect.width, rect.height) / 2 - 7
            var path = Path()
            path.addArc(
                center: CGPoint(x: rect.midX, y: rect.midY), radius: radius, startAngle: .degrees(135),
                endAngle: .degrees(135 + PhoneScoreGauge.sweep * min(max(fraction, 0), 1)), clockwise: false)
            return path
        }
    }

    /// Short marks inside the arc: `count + 1` positions from end to end, those in `indices` drawn.
    private struct Ticks: Shape {
        let count: Int
        let sweep: Double
        let indices: Range<Int>

        func path(in rect: CGRect) -> Path {
            let outer = min(rect.width, rect.height) / 2 - 22
            let inner = outer - 7
            let center = CGPoint(x: rect.midX, y: rect.midY)
            var path = Path()
            for i in indices.clamped(to: 0..<(count + 1)) {
                let angle = Angle.degrees(135 + sweep * Double(i) / Double(count)).radians
                path.move(to: CGPoint(x: center.x + inner * cos(angle), y: center.y + inner * sin(angle)))
                path.addLine(to: CGPoint(x: center.x + outer * cos(angle), y: center.y + outer * sin(angle)))
            }
            return path
        }
    }
}

/// One check that flagged items, as a full-colour card: the figure, the title, one sentence, then
/// "Voir les éléments", which pushes the flagged items. The whole card is the link and shrinks as
/// one piece under the finger.
private struct PhoneWatchtowerCard: View {
    let card: WatchtowerCard
    let count: Int
    let ids: Set<String>

    var body: some View {
        NavigationLink(value: PhoneRoute.watchtower(title: card.title, itemIDs: ids)) {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .top) {
                        Text(count, format: .number)
                            .font(.system(size: 44, weight: .bold, design: .rounded))
                            .monospacedDigit()
                        Spacer()
                        Image(systemName: card.symbol)
                            .font(.system(size: 30, weight: .semibold))
                            .opacity(0.35)
                            .accessibilityHidden(true)
                    }
                    Text(card.title).font(.headline)
                    Text(card.message)
                        .font(.subheadline)
                        .opacity(0.9)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(16)
                Rectangle().fill(.white.opacity(0.25)).frame(height: 0.5)
                HStack {
                    Text("Voir les éléments").font(.body.weight(.medium))
                    Spacer()
                    Image(systemName: "chevron.forward").font(.footnote.weight(.bold))
                }
                .padding(.horizontal, 16)
                .frame(minHeight: 48)
            }
            .foregroundStyle(.white)
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Self.fill(card), in: .rect(cornerRadius: PhoneCard.radius, style: .continuous))
            .contentShape(.rect(cornerRadius: PhoneCard.radius))
        }
        .buttonStyle(PressableButtonStyle())
        .accessibilityElement(children: .combine)
        .accessibilityHint(Text("Voir les éléments"))
        .accessibilityIdentifier("watchtower.show.\(card.id)")
    }

    /// Issues in red or orange, chances to do better (passkeys, codes) in the accent or blue, each a
    /// shade deep enough for white text (4.5:1).
    static func fill(_ card: WatchtowerCard) -> Color {
        switch card.id {
        case "compromised", "expiring", "breached_site", "provider_exposed": Color(red: 0.78, green: 0.16, blue: 0.16)
        case "duplicate": Color(red: 0.38, green: 0.38, blue: 0.42)
        case "passkey": Theme.accent
        case "2fa": Color(red: 0.04, green: 0.39, blue: 0.78)
        default: Color(red: 0.70, green: 0.30, blue: 0.0)
        }
    }
}

/// The checks with nothing to report: one row each, a green check, or why there is no figure.
private struct ClearChecksCard: View {
    let cards: [WatchtowerCard]
    let report: FfiWatchtowerReport
    let checkBreaches: Bool
    let breachCatalog: Bool

    var body: some View {
        EditorCard {
            VStack(alignment: .leading, spacing: 0) {
                Text("Rien à signaler")
                    .font(.headline)
                    .padding(.horizontal, 16)
                    .padding(.top, 14)
                    .padding(.bottom, 6)
                ForEach(Array(cards.enumerated()), id: \.element.id) { index, card in
                    if index > 0 { Divider().padding(.leading, 52) }
                    HStack(spacing: 12) {
                        PageTile(symbol: card.symbol, color: card.color, size: 26)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(card.title).font(.subheadline.weight(.medium))
                            if let note = note(card) {
                                Text(note).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer(minLength: 4)
                        if note(card) == nil {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                                .accessibilityLabel(Text("Rien à signaler"))
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 9)
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("watchtower.card.\(card.id)")
                }
            }
            .padding(.bottom, 6)
        }
    }

    /// Why a check has no figure: its data source did not run (same words as the Mac cards).
    private func note(_ card: WatchtowerCard) -> String? {
        card.unavailableNote(report: report, checkBreaches: checkBreaches, breachCatalog: breachCatalog)
    }
}

/// The items a Watchtower card flagged, pushed from the Watchtower tab.
struct WatchtowerItemsList: View {
    @Environment(AppModel.self) private var model
    let title: String
    let itemIDs: Set<String>

    var body: some View {
        let items = model.session.items(filter: .all, query: "", sort: .title).filter { itemIDs.contains($0.id) }
        let showVault = model.session.vaults.count > 1
        List {
            ForEach(items, id: \.id) { summary in
                NavigationLink(value: PhoneRoute.item(ItemRef(vaultID: summary.vaultId, itemID: summary.id))) {
                    ItemListRow(
                        summary: summary,
                        vaultName: showVault ? model.session.allVaults.first { $0.id == summary.vaultId }?.meta.name : nil)
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(PhoneBackground())
        .overlay {
            if items.isEmpty {
                EmptyState(title: String(localized: "Rien à signaler"), systemImage: "checkmark.shield",
                    message: String(localized: "Aucun élément concerné pour l'instant."))
            }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.large)
    }
}
#endif
