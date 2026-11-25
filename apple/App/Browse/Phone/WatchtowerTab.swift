#if os(iOS)
import DesignBridgeKit
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
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// A tap on the selected Watchtower tab at its root scrolls the page back to its top.
    @Environment(\.phoneTabScrollToTop) private var scrollToTop
    /// Pushed from Accueil (zoom out of the score): a back button in place of the root's bar items.
    @Environment(\.watchtowerPushed) private var pushed
    @State private var position = ScrollPosition(edge: .top)

    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault

    private var watchtower: WatchtowerModel { model.watchtower }

    /// Captures: `-OnePassDemoScroll bottom` starts Watchtower at its end. Debug builds only.
    private static var demoBottom: Bool {
        #if DEBUG
        UserDefaults.standard.string(forKey: "OnePassDemoScroll") == "bottom"
        #else
        false
        #endif
    }

    var body: some View {
        let score = watchtower.report.map { Int($0.score) }
        ScrollView {
            if rxDesign {
                // The run animates inside (gauge, status, scan card), not the whole page. On a
                // regular width (iPad, unfolded) the column keeps a readable measure.
                RXWatchtowerContent(score: score, scanCard: scanCard, statusLine: statusLine(showsFailure: false))
                    .frame(maxWidth: Self.readableWidth)
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, Theme.Space.gutter(regularWidth: sizeClass == .regular))
                    .padding(.bottom, Theme.Space.xl)
            } else {
                classicContent(score: score)
            }
        }
        .defaultScrollAnchor(Self.demoBottom ? .bottom : .top)
        .scrollPosition($position)
        .onChange(of: scrollToTop) {
            withDBAnimation(.smooth, reduceMotion: reduceMotion) { position.scrollTo(edge: .top) }
        }
        .background {
            if !rxDesign { PhoneBackground() }
        }
        .modifier(RXScrollingBackdrop(name: RXHero.watchtower, active: rxDesign))
        // RX: the page draws its own large title.
        .navigationTitle(rxDesign ? "" : "Watchtower")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !pushed { PhoneRootToolbar() }
        }
        // RX at the tab's root: no navigation bar. A new item is Accueil's quick action and the
        // account menu sits in the page header. Pushed from Accueil the bar shows, empty but for
        // the back button over the art, so the zoomed page has a way back besides the swipe.
        .toolbar(rxDesign && !pushed ? .hidden : .automatic, for: .navigationBar)
        .vaultRefresh { await watchtower.refreshAndWait(model.session) }
        .task(id: model.session.summariesRevision) {
            watchtower.refreshIfNeeded(model.session)
            _ = try? await model.session.seenByFormerMemberItems()
        }
        .onChange(of: watchtower.checkBreaches) { watchtower.refreshIfNeeded(model.session) }
        .onChange(of: model.session.hiddenVaultIDs) { watchtower.refreshIfNeeded(model.session) }
        .accessibilityIdentifier("page.watchtower")
    }

    /// The classic layout (the RX look off).
    private func classicContent(score: Int?) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.l) {
            VStack(spacing: Theme.Space.l) {
                PhoneScoreGauge(score: score)
                    .padding(.top, Theme.Space.xs)
                if let score {
                    ShareLink(item: String(localized: "browse.myOnepassSecurityScore \(score)")) {
                        Label("browse.shareMyScore", systemImage: "square.and.arrow.up")
                            .font(.subheadline.weight(.semibold))
                            .padding(.horizontal, Theme.Space.xs)
                            .frame(minHeight: 30)
                    }
                    .buttonStyle(.glass)
                    .accessibilityIdentifier("watchtower.share")
                }
            }
            .frame(maxWidth: .infinity)
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                Text("browse.watchtowerFindsPasswordsTo")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                statusLine(showsFailure: true)
            }
            .padding(.horizontal, Theme.Space.xs)
            scanCard
            if let report = watchtower.report {
                StrengthCard(levels: report.strength.map(Int.init))
                let flagged = WatchtowerCard.all.filter { Self.isFlagged($0, in: report) }
                ForEach(flagged) { card in
                    PhoneWatchtowerCard(card: card, count: card.itemIDs(in: report).count, ids: card.itemIDs(in: report))
                }
                let seen = model.seenByFormerMemberIDs
                if !seen.isEmpty {
                    PhoneWatchtowerCard(card: .seenByFormerMember, count: seen.count, ids: seen)
                }
                // Passkeys a 1PUX import left behind, until each one is recreated (hidden at zero).
                PasskeyMigrationEntry(boxed: true)
                CryptoPhraseAlertCard()
                let clear = WatchtowerCard.all.filter { !Self.isFlagged($0, in: report) }
                if !clear.isEmpty {
                    ClearChecksCard(
                        cards: clear, report: report, checkBreaches: watchtower.checkBreaches,
                        breachCatalog: watchtower.breachCatalogUsed)
                }
            }
            BreachSettingCard()
        }
        .padding(.horizontal, Theme.Space.gutter(regularWidth: sizeClass == .regular))
        .padding(.bottom, Theme.Space.xl)
        .animation(.smooth(duration: 0.3), value: watchtower.isRunning)
    }

    /// The widest the RX column grows on a regular width (iPad, unfolded): a readable measure.
    /// No RX token holds it yet.
    private static let readableWidth: CGFloat = 640

    /// A check with items to look at (`WatchtowerCard.isFlagged`, the rule the Mac page shares).
    static func isFlagged(_ card: WatchtowerCard, in report: FfiWatchtowerReport) -> Bool {
        card.isFlagged(in: report)
    }

    /// While a scan runs: a card with its step and a slim bar (the analysis, then the breach check
    /// with its figures).
    @ViewBuilder private var scanCard: some View {
        if watchtower.isRunning {
            Group {
                switch watchtower.phase {
                case .checkingBreaches(let done, let total):
                    ScanProgressBar(
                        title: Text("browse.checkingForBreaches"), detail: Text("app.of \(done) \(total)"), done: done,
                        total: total)
                default:
                    ScanProgressBar(title: Text("browse.analyzingItems"))
                }
            }
            .padding(.horizontal, Theme.Space.l)
            .padding(.vertical, Theme.Space.l)
            .phoneCard()
            .transition(.opacity)
            .accessibilityIdentifier("watchtower.scan")
        }
    }

    /// The count and how far the breach check went (the Mac page's words). The RX page leaves
    /// a failure to its error state (`DBLoadableView`), so it is not said twice.
    @ViewBuilder private func statusLine(showsFailure: Bool) -> some View {
        switch watchtower.phase {
        case .idle, .ready:
            if let report = watchtower.report {
                Text(WatchtowerModel.summary(report))
                    .font(.footnote)
                    // Secondary, not tertiary: tertiary read at about 2:1 on the light page.
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        case .analyzing, .checkingBreaches:
            // The scan's own card says it (`scanCard`).
            EmptyView()
        case .failed:
            if showsFailure {
                Label(WatchtowerModel.failureMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.orange)
            }
        }
    }
}

/// The score as a three-quarter dial: a track, the filled arc in the score's color, tick marks
/// that light up to the score, the figure and its word in the middle. Flat colors, no glow.
struct PhoneScoreGauge: View {
    let score: Int?
    /// The run's phase: without a score, the caption says "Analyse…" only while one is coming.
    var phase: WatchtowerModel.Phase? = nil
    /// No item to score: no caption at all.
    var isEmptyVault = false
    /// RX: the Display typography, scaled with Dynamic Type, and a dial sized from it.
    var rx = false
    private static let ticks = 40
    nonisolated private static let sweep = 270.0
    /// The classic dial: 210 pt around a 58 pt figure.
    private static let side: CGFloat = 210
    private static let classicDigits: CGFloat = 58
    /// The RX dial grows with the figure up to this side, then the figure shrinks to fit.
    private static let maxSide: CGFloat = 320

    @ScaledMetric(relativeTo: .largeTitle) private var rxDigits = Theme.RX.Typography.display.spec.size

    /// The dial's side: fixed in the classic look, from the scaled figure in RX.
    private var dialSide: CGFloat {
        guard rx else { return Self.side }
        return min(Self.side * rxDigits / Theme.RX.Typography.display.spec.size, Self.maxSide)
    }

    /// The word under the figure: the score's word, "Analyse…" while a run is on its way, else
    /// nothing (an empty vault, or a failure the page shows once in its error state).
    private var caption: String? {
        if let score { return ScoreGauge.label(score) }
        if isEmptyVault { return nil }
        if case .failed = phase { return nil }
        return String(localized: "browse.analyzing")
    }

    var body: some View {
        let fraction = Double(score ?? 0) / 100
        let color = score.map(ScoreGauge.color) ?? .secondary
        ZStack {
            Dial(fraction: 1)
                .stroke(Color.primary.opacity(0.10), style: StrokeStyle(lineWidth: 14, lineCap: .round))
            Dial(fraction: fraction)
                .stroke(color, style: StrokeStyle(lineWidth: 14, lineCap: .round))
                .dbAnimation(value: fraction)
            // Ticks 0 through `lit` take the score's color, the rest stay faint.
            let lit = score == nil ? -1 : Int((fraction * Double(Self.ticks)).rounded())
            Ticks(count: Self.ticks, sweep: Self.sweep, indices: 0..<(lit + 1))
                .stroke(color.opacity(0.6), style: StrokeStyle(lineWidth: 2, lineCap: .round))
            Ticks(count: Self.ticks, sweep: Self.sweep, indices: (lit + 1)..<(Self.ticks + 1))
                .stroke(Color.primary.opacity(0.12), style: StrokeStyle(lineWidth: 2, lineCap: .round))
            VStack(spacing: Theme.Space.xxs) {
                // Rolling digits (DesignBridgeKit) as the score arrives and changes.
                Group {
                    if let score { DBNumber(score) } else { Text(verbatim: "–") }
                }
                .font(rx ? Theme.RX.Typography.display.font(size: rxDigits)
                    : .system(size: Self.classicDigits, weight: .bold, design: .rounded))
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.5)
                if let caption {
                    Text(caption)
                        .font(.subheadline.weight(.semibold))
                        .textCase(.uppercase)
                        .foregroundStyle(score == nil ? AnyShapeStyle(.secondary) : AnyShapeStyle(color))
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                }
            }
            // Inside the ticks, so the figure and its word never touch the ring.
            .frame(maxWidth: dialSide * 0.6)
            .offset(y: 4)
        }
        // A square no wider than the screen allows.
        .aspectRatio(1, contentMode: .fit)
        .frame(maxWidth: dialSide, maxHeight: dialSide)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("browse.securityScore"))
        .accessibilityValue(score.map { ScoreGauge.accessibilityValue($0) } ?? Text(verbatim: ""))
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
        NavigationLink(value: PhoneRoute.watchtower(title: card.title, itemIDs: ids, check: card.siteCheck)) {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: Theme.Space.s) {
                    HStack(alignment: .top) {
                        Text(count, format: .number)
                            .font(.system(size: 44, weight: .bold, design: .rounded))
                            .monospacedDigit()
                        Spacer()
                        WatchtowerArtwork(card: card, size: 34, onWash: true)
                    }
                    Text(card.title).font(.headline)
                    Text(card.message)
                        .font(.subheadline)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(Theme.Space.l)
                Rectangle().fill(.white.opacity(0.25)).frame(height: 0.5)
                HStack {
                    Text("browse.showItems").font(.body.weight(.medium))
                    Spacer()
                    Image(systemName: "chevron.forward").font(.footnote.weight(.bold))
                }
                .padding(.horizontal, Theme.Space.l)
                .frame(minHeight: 48)
            }
            .foregroundStyle(.white)
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            .modifier(CardFill(card: card))
            .contentShape(.rect(cornerRadius: PhoneCard.radius))
        }
        .buttonStyle(PressableButtonStyle())
        .accessibilityElement(children: .combine)
        .accessibilityHint(Text("browse.showItems"))
        .accessibilityIdentifier("watchtower.show.\(card.id)")
    }

    /// Red issue cards get the alert wash; the others keep their flat fill.
    private struct CardFill: ViewModifier {
        let card: WatchtowerCard

        func body(content: Content) -> some View {
            let fill = PhoneWatchtowerCard.fill(card)
            let shape = RoundedRectangle(cornerRadius: PhoneCard.radius, style: .continuous)
            if card.isAlert {
                content.washBackground(Theme.Wash.alert(fill), flat: fill, in: shape)
            } else {
                content.background(fill, in: shape)
            }
        }
    }

    /// Issues in red or orange, chances to do better (passkeys, codes) in the accent or blue, each a
    /// shade deep enough for white text (4.5:1).
    static func fill(_ card: WatchtowerCard) -> Color {
        if card.isAlert { return WatchtowerCard.alertFill }
        return switch card.id {
        case "duplicate": Color(red: 0.38, green: 0.38, blue: 0.42)
        case "passkey": Theme.accent
        case "2fa": Color(red: 0.04, green: 0.39, blue: 0.78)
        default: Color(red: 0.70, green: 0.30, blue: 0.0)
        }
    }
}

/// The checks with nothing to report: one row each, a green check, or why there is no figure.
struct ClearChecksCard: View {
    let cards: [WatchtowerCard]
    let report: FfiWatchtowerReport
    let checkBreaches: Bool
    let breachCatalog: Bool

    var body: some View {
        EditorCard {
            VStack(alignment: .leading, spacing: 0) {
                Text("browse.nothingToReport")
                    .font(.headline)
                    .padding(.horizontal, Theme.Space.l)
                    .padding(.top, Theme.Space.l)
                    .padding(.bottom, Theme.Space.s)
                ForEach(Array(cards.enumerated()), id: \.element.id) { index, card in
                    // Starts at the row title: padding, the 26 pt tile, spacing.
                    if index > 0 { Divider().padding(.leading, Theme.Space.l + 26 + Theme.Space.m) }
                    HStack(spacing: Theme.Space.m) {
                        WatchtowerArtwork(card: card, size: 26)
                        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                            Text(card.title).font(.subheadline.weight(.medium))
                            if let note = note(card) {
                                Text(note).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer(minLength: 4)
                        if note(card) == nil {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                                .accessibilityLabel(Text("browse.nothingToReport"))
                        }
                    }
                    .padding(.horizontal, Theme.Space.l)
                    .padding(.vertical, Theme.Space.s)
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("watchtower.card.\(card.id)")
                }
            }
            .padding(.bottom, Theme.Space.s)
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
    /// The card's site check: its rows carry the setup button (`WatchtowerSetupRow`).
    let check: String?

    var body: some View {
        let items = model.session.items(filter: .all, query: "", sort: .title).filter { itemIDs.contains($0.id) }
        let showVault = model.session.vaults.count > 1
        List {
            ForEach(items, id: \.id) { summary in
                WatchtowerSetupRow(itemID: summary.id, check: check) {
                    PhoneItemLink(ref: ItemRef(vaultID: summary.vaultId, itemID: summary.id)) {
                        ItemListRow(
                            summary: summary,
                            vaultName: showVault ? model.session.allVaults.first { $0.id == summary.vaultId }?.meta.name : nil)
                    }
                }
                .itemZoomSource(ItemRef(vaultID: summary.vaultId, itemID: summary.id))
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(PhoneBackground())
        .overlay {
            if items.isEmpty {
                EmptyState(title: String(localized: "browse.nothingToReport"), systemImage: "checkmark.shield",
                    message: String(localized: "browse.noItemAffectedFor"))
            }
        }
        .navigationTitle(title)
        // Inline: the finding titles are long, a large title cut them ("Comptes de connexio...",
        // jank audit J15).
        .navigationBarTitleDisplayMode(.inline)
    }
}
#endif
