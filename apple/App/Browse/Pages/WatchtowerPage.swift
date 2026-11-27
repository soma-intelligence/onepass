import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// Watchtower page of the main window: score gauge, password strength, one card per check.
/// Everything comes from the core's report (`WatchtowerModel`); nothing is shown before it.
struct WatchtowerPage: View {
    @Environment(AppModel.self) private var model
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault

    private var watchtower: WatchtowerModel { model.watchtower }

    var body: some View {
        ScrollView {
            #if os(macOS)
            if rxDesign {
                // RX: the failure belongs to the page's error state, not to the status line.
                RXMacWatchtowerContent(statusLine: statusLine(showsFailure: false))
                    .padding(.horizontal, Theme.RX.Space.xl)
                    .padding(.vertical, Theme.RX.Space.l)
                    .frame(maxWidth: 864, alignment: .leading)
                    .frame(maxWidth: .infinity)
            } else {
                classic
            }
            #else
            classic
            #endif
        }
        #if os(macOS)
        .background {
            if rxDesign { Theme.RX.Palette.pageBackground.color.ignoresSafeArea() }
        }
        #endif
        .navigationTitle("Watchtower")
        .toolbar {
            ToolbarItem {
                Button {
                    watchtower.refresh(model.session)
                } label: {
                    Label("browse.analyzeAgain", systemImage: "arrow.clockwise")
                }
                .disabled(watchtower.isRunning)
                .help(Text("browse.analyzeAgain"))
            }
        }
        .task(id: model.session.summariesRevision) {
            watchtower.refreshIfNeeded(model.session)
            _ = try? await model.session.seenByFormerMemberItems()
        }
        .onChange(of: watchtower.checkBreaches) { watchtower.refreshIfNeeded(model.session) }
        .onChange(of: model.session.hiddenVaultIDs) { watchtower.refreshIfNeeded(model.session) }
        .accessibilityIdentifier("page.watchtower")
    }

    /// The classic page (the RX look off): header with the gauge, strength, the cards grid.
    private var classic: some View {
        VStack(alignment: .leading, spacing: 22) {
            PageHeader(
                title: "Watchtower", symbol: "shield.lefthalf.filled", color: Theme.accent,
                message: String(localized: "browse.watchtowerFindsPasswordsTo")
            ) {
                ScoreGauge(score: watchtower.report.map { Int($0.score) })
            }
            statusLine(showsFailure: true)
            if let report = watchtower.report {
                StrengthCard(levels: report.strength.map(Int.init))
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 250), spacing: 14)], spacing: 14) {
                    ForEach(WatchtowerCard.all) { card in
                        WatchtowerCardView(
                            card: card, report: report, checkBreaches: watchtower.checkBreaches,
                            breachCatalog: watchtower.breachCatalogUsed
                        ) {
                            model.showWatchtowerItems(title: card.title, itemIDs: card.itemIDs(in: report), check: card.siteCheck)
                        }
                    }
                    let seen = model.seenByFormerMemberIDs
                    if !seen.isEmpty {
                        WatchtowerCardView(
                            card: .seenByFormerMember, report: report, checkBreaches: watchtower.checkBreaches,
                            breachCatalog: watchtower.breachCatalogUsed, itemIDs: seen
                        ) {
                            model.showWatchtowerItems(title: WatchtowerCard.seenByFormerMember.title, itemIDs: seen)
                        }
                    }
                }
            }
            BreachSettingCard()
        }
        .padding(28)
        .frame(maxWidth: 1100, alignment: .leading)
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder private func statusLine(showsFailure: Bool) -> some View {
        switch watchtower.phase {
        case .idle, .ready:
            if let report = watchtower.report {
                Text(WatchtowerModel.summary(report)).font(.callout).foregroundStyle(.secondary)
            }
        case .analyzing:
            ScanProgressBar(title: Text("browse.analyzingItems"))
                .frame(maxWidth: 420)
        case .checkingBreaches(let done, let total):
            ScanProgressBar(
                title: Text("browse.checkingForBreaches"), detail: Text("app.of \(done) \(total)"), done: done, total: total)
                .frame(maxWidth: 420)
        case .failed:
            if showsFailure {
                Label(WatchtowerModel.failureMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
        }
    }
}

extension WatchtowerModel {
    /// The data state of the RX pages (iPhone and Mac): no item is an empty vault, a failed run
    /// keeps the last report under the error, no report yet is loading. The error has fixed
    /// words; the raw error is in the log, never on screen.
    static func loadable(report: FfiWatchtowerReport?, phase: Phase, items: Int) -> DBLoadable<FfiWatchtowerReport> {
        if items == 0 { return .empty }
        if case .failed = phase {
            return .failed(
                DBLoadError(title: String(localized: "rx.watchtower.failed"), message: failureMessage),
                previous: report)
        }
        if let report { return .content(report) }
        return .loading(previous: nil)
    }
}

// MARK: - Score

/// Semicircle gauge of the core's score (0 to 100) with its label.
struct ScoreGauge: View {
    let score: Int?
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    static func label(_ score: Int) -> String {
        switch score {
        case ..<40: String(localized: "browse.weak")
        case ..<60: String(localized: "browse.fair")
        case ..<80: String(localized: "browse.good")
        case ..<95: String(localized: "app.excellent")
        default: String(localized: "browse.fantastic")
        }
    }

    /// "72 out of 100, Good" for VoiceOver, in the app's language.
    static func accessibilityValue(_ score: Int) -> Text {
        Text("rx.watchtower.scoreValue \(score) \(label(score))")
    }

    static func color(_ score: Int) -> Color {
        switch score {
        case ..<40: .red
        case ..<60: .orange
        case ..<80: .yellow
        default: .green
        }
    }

    private let arcStyle = StrokeStyle(lineWidth: 16, lineCap: .round)

    var body: some View {
        let fraction = Double(score ?? 0) / 100
        let isFlat = Theme.Wash.isFlat(
            increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency)
        ZStack(alignment: .bottom) {
            Arc(fraction: 1)
                .stroke(.secondary.opacity(0.2), style: arcStyle)
            // The full scale gradient, masked to the filled part so a low score shows only red. It
            // is always drawn and only faded, so the first score grows the arc instead of popping
            // it in. Under Increase Contrast or Reduce Transparency it is one flat score color.
            Arc(fraction: 1)
                .stroke(
                    isFlat ? AnyShapeStyle(Self.color(score ?? 0)) : Theme.Wash.scale(fraction: fraction),
                    style: arcStyle
                )
                .mask(Arc(fraction: fraction).stroke(style: arcStyle))
                .opacity(Theme.Wash.scaleShowsFill(score: score) ? 1 : 0)
                .animation(.smooth, value: fraction)
            VStack(spacing: 0) {
                Text(score.map(String.init) ?? "–")
                    .font(.system(size: 46, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                Text(score.map(Self.label) ?? String(localized: "browse.analyzing"))
                    .font(.headline)
                    .foregroundStyle(score.map(Self.color) ?? .secondary)
            }
            .padding(.bottom, 2)
        }
        .frame(width: 230, height: 125)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("browse.securityScore"))
        .accessibilityValue(score.map { Self.accessibilityValue($0) } ?? Text(verbatim: ""))
    }

    /// Upper half circle, filled from the left by `fraction`.
    private struct Arc: Shape {
        var fraction: Double
        var animatableData: Double {
            get { fraction }
            set { fraction = newValue }
        }

        func path(in rect: CGRect) -> Path {
            let lineInset: CGFloat = 8
            let radius = min(rect.width / 2, rect.height) - lineInset
            let center = CGPoint(x: rect.midX, y: rect.maxY - lineInset)
            var path = Path()
            path.addArc(
                center: center, radius: radius, startAngle: .degrees(180),
                endAngle: .degrees(180 + 180 * min(max(fraction, 0), 1)), clockwise: false)
            return path
        }
    }
}

// MARK: - Strength

/// "Force globale des mots de passe": the password fields by strength level, red to green.
struct StrengthCard: View {
    /// Counts by level, 0 (trop court) to 4 (excellent).
    let levels: [Int]

    private static let names = [
        String(localized: "browse.tooShort"), String(localized: "browse.weak2"), String(localized: "browse.fair2"),
        String(localized: "browse.good2"), String(localized: "browse.excellent"),
    ]
    private static let colors: [Color] = [.red, .orange, .yellow, .mint, .green]

    var body: some View {
        let total = levels.reduce(0, +)
        EditorCard {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    Text("browse.overallPasswordStrength").font(.headline)
                    Spacer()
                    Text(total == 1 ? String(localized: "browse.n1Password") : String(localized: "browse.passwords \(total)"))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                if total == 0 {
                    Text("browse.noPasswordsToAnalyze")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    bar(total: total)
                    legend
                }
            }
            .padding(16)
        }
    }

    private func bar(total: Int) -> some View {
        GeometryReader { geo in
            let spacing: CGFloat = 3
            let shown = levels.indices.filter { levels[$0] > 0 }
            let width = geo.size.width - spacing * CGFloat(max(shown.count - 1, 0))
            HStack(spacing: spacing) {
                ForEach(shown, id: \.self) { i in
                    Self.colors[i]
                        .frame(width: max(6, width * CGFloat(levels[i]) / CGFloat(total)))
                }
            }
            .clipShape(.rect(cornerRadius: 6))
        }
        .frame(height: 14)
        .accessibilityHidden(true)
    }

    private var legend: some View {
        #if os(iOS)
        // iPhone: the five levels wrap instead of squeezing into one row.
        ChipFlow(spacing: 14) { legendEntries }
        #else
        HStack(spacing: 18) { legendEntries }
        #endif
    }

    @ViewBuilder private var legendEntries: some View {
            ForEach(levels.indices, id: \.self) { i in
                HStack(spacing: 6) {
                    Circle().fill(Self.colors[i]).frame(width: 8, height: 8)
                    Text("\(Self.names[i]) \(levels[i])")
                        .font(.callout)
                        .monospacedDigit()
                        .foregroundStyle(levels[i] == 0 ? .tertiary : .secondary)
                }
                .accessibilityElement(children: .combine)
            }
    }
}

// MARK: - Cards

/// One card of the grid: the checks it counts and its copy.
struct WatchtowerCard: Identifiable {
    enum Source {
        case local
        /// Needs the breach ranges.
        case breaches
        /// Needs the 2FA and passkey catalogs.
        case sites
        /// Needs the HIBP breach catalog.
        case breachCatalog
    }

    /// The four red issue cards, on the Mac page and the iPhone tab alike.
    static let alertIDs: Set<String> = ["compromised", "expiring", "breached_site", "provider_exposed"]
    /// The red of those cards, deep enough for white text (4.5:1).
    static let alertFill = Color(red: 0.78, green: 0.16, blue: 0.16)

    var isAlert: Bool { Self.alertIDs.contains(id) }

    let id: String
    let checks: [String]
    let title: String
    let message: String
    let symbol: String
    let color: Color
    let source: Source

    /// The card's drawn icon in Assets (Watchtower/watchtower-<id>), in the settings icons' style.
    var artwork: String { "watchtower-\(id)" }

    /// The site check of a card made of `missing_2fa` or `passkey_available` alone: its list rows
    /// carry the setup button. Nil for every other card.
    var siteCheck: String? {
        guard checks.count == 1, let check = checks.first,
            SiteSetupOffer.Kind(rawValue: check) != nil
        else { return nil }
        return check
    }

    func itemIDs(in report: FfiWatchtowerReport) -> Set<String> {
        Set(report.checks.filter { checks.contains($0.check) }.flatMap(\.itemIds))
    }

    /// A check with items to look at, on the iPhone tab and the Mac page alike. A check whose
    /// source did not run is not flagged; the clear list says why it has no figure.
    func isFlagged(in report: FfiWatchtowerReport) -> Bool {
        !itemIDs(in: report).isEmpty
    }

    /// Why the red checks cannot be called clear, or nil when every one of them really ran: the
    /// breach ranges were all checked and each alert source was available. While a scan runs,
    /// the step it is on.
    static func alertGap(
        report: FfiWatchtowerReport, checkBreaches: Bool, breachCatalog: Bool, isRunning: Bool
    ) -> String? {
        let notes = all.filter(\.isAlert).compactMap {
            $0.unavailableNote(report: report, checkBreaches: checkBreaches, breachCatalog: breachCatalog)
        }
        let gap: String? = switch report.pwned {
        case .checked: notes.first
        case .partial: String(localized: "rx.watchtower.notChecked.partial")
        case .unavailable, .disabled: notes.first ?? String(localized: "browse.breachCheckTurnedOff2")
        }
        guard let gap else { return nil }
        return isRunning ? String(localized: "browse.checkingForBreaches") : gap
    }

    /// Why the card has no figure: its data source did not run. Nil when it did.
    func unavailableNote(report: FfiWatchtowerReport, checkBreaches: Bool, breachCatalog: Bool) -> String? {
        switch source {
        case .local:
            return nil
        case .breaches:
            switch report.pwned {
            case .disabled: return String(localized: "browse.breachCheckTurnedOff2")
            // Not run: with the setting off, the card says so instead of showing a clean result.
            case .unavailable:
                return checkBreaches ? String(localized: "browse.waitingForNetwork")
                    : String(localized: "browse.breachCheckTurnedOff2")
            case .checked, .partial: return nil
            }
        case .sites:
            // The site pack ships in the app: these checks never wait for "Vérifier les fuites".
            return report.sitesChecked ? nil : String(localized: "browse.siteCatalogNotDownloaded")
        case .breachCatalog:
            return breachCatalog ? nil
                : checkBreaches ? String(localized: "browse.breachListNotDownloaded")
                : String(localized: "browse.turnOnCheckFor")
        }
    }

    /// The card holding `check`, for the item detail.
    static func of(check: String) -> WatchtowerCard? {
        all.first { $0.checks.contains(check) }
    }

    /// Items a removed member of a shared vault could read (sharing spec 10.4): not a report
    /// check, the ids come from the sharing state.
    static let seenByFormerMember = WatchtowerCard(
        id: "seen_by_former_member", checks: [],
        title: VaultSession.seenByFormerMemberTitle,
        message: String(localized: "watchtower.seenByFormerMember.message"),
        symbol: "person.crop.circle.badge.xmark", color: .orange, source: .local)

    static let all: [WatchtowerCard] = [
        WatchtowerCard(
            id: "compromised", checks: ["compromised"],
            title: String(localized: "browse.compromisedPasswords"),
            message: String(localized: "browse.theyAppearInKnown"),
            symbol: "exclamationmark.octagon.fill", color: .red, source: .breaches),
        WatchtowerCard(
            id: "breached_site", checks: ["breached_site"],
            title: String(localized: "browse.breachedSites"),
            message: String(localized: "browse.theseSitesHadBreach"),
            symbol: "exclamationmark.shield.fill", color: .red, source: .breachCatalog),
        WatchtowerCard(
            id: "provider_exposed", checks: ["provider_exposed"],
            title: String(localized: "browse.exposedSignInAccounts"),
            message: String(localized: "browse.accountUseToSign"),
            symbol: "person.crop.circle.badge.exclamationmark", color: .red, source: .local),
        WatchtowerCard(
            id: "reused", checks: ["reused"],
            title: String(localized: "browse.reusedPasswords"),
            message: String(localized: "browse.onePasswordOnSeveral"),
            symbol: "arrow.triangle.2.circlepath", color: .orange, source: .local),
        WatchtowerCard(
            id: "weak", checks: ["weak"],
            title: String(localized: "browse.weakPasswords"),
            message: String(localized: "browse.easyToGuessReplace"),
            symbol: "lock.open.fill", color: .orange, source: .local),
        WatchtowerCard(
            id: "passkey", checks: ["passkey_available"],
            title: String(localized: "browse.passkeysAvailable"),
            message: String(localized: "browse.theseSitesSupportPasskeys"),
            symbol: "person.badge.key.fill", color: Theme.accent, source: .sites),
        WatchtowerCard(
            id: "2fa", checks: ["missing_2fa"],
            title: String(localized: "browse.twoFactorAuthenticationAvailable"),
            message: String(localized: "browse.theseSitesOfferOne"),
            symbol: "lock.shield.fill", color: .blue, source: .sites),
        WatchtowerCard(
            id: "http", checks: ["insecure_url"],
            title: String(localized: "browse.httpSites"),
            message: String(localized: "browse.theseAddressesArentEncrypted"),
            symbol: "globe.badge.chevron.backward", color: .yellow, source: .local),
        WatchtowerCard(
            id: "expiring", checks: ["expired", "expiring"],
            title: String(localized: "browse.expiringItems"),
            message: String(localized: "browse.cardsDocumentsAndLicenses"),
            symbol: "calendar.badge.exclamationmark", color: .pink, source: .local),
        WatchtowerCard(
            id: "wifi", checks: ["wifi_insecure"],
            title: String(localized: "browse.poorlyProtectedWiFi"),
            message: String(localized: "browse.theseNetworksUseWep"),
            symbol: "wifi.exclamationmark", color: .orange, source: .local),
        WatchtowerCard(
            id: "ssh", checks: ["ssh_weak"],
            title: String(localized: "browse.weakSshKeys"),
            message: String(localized: "browse.rsaKeysUnder3"),
            symbol: "terminal.fill", color: .orange, source: .local),
        WatchtowerCard(
            id: "wallet", checks: ["wallet_no_backup"],
            title: String(localized: "browse.walletsWithoutBackup"),
            message: String(localized: "browse.noteWherePhysicalCopy"),
            symbol: "archivebox.fill", color: .yellow, source: .local),
        WatchtowerCard(
            id: "duplicate", checks: ["duplicate"],
            title: String(localized: "browse.duplicates"),
            message: String(localized: "browse.sameSiteAndSame"),
            symbol: "square.on.square", color: .gray, source: .local),
        WatchtowerCard(
            id: "old", checks: ["old_password"],
            title: String(localized: "browse.oldPasswords"),
            message: String(localized: "browse.unchangedForOverYear"),
            symbol: "clock.arrow.circlepath", color: .gray, source: .local),
        WatchtowerCard(
            id: "pending", checks: ["pending_unused"],
            title: String(localized: "browse.pendingPassword"),
            message: String(localized: "browse.generatedPasswordNeverConfirmed"),
            symbol: "hourglass", color: .gray, source: .local),
        WatchtowerCard(
            id: "dormant", checks: ["dormant"],
            title: String(localized: "browse.dormantKeys"),
            message: String(localized: "browse.keysUnusedOver90"),
            symbol: "key.fill", color: .gray, source: .local),
    ]
}

struct WatchtowerCardView: View {
    /// Mac: the grid's cards line up; iPhone: one column, each card as tall as its text.
    #if os(iOS)
    private static let minHeight: CGFloat = 0
    #else
    private static let minHeight: CGFloat = 210
    #endif

    let card: WatchtowerCard
    let report: FfiWatchtowerReport
    let checkBreaches: Bool
    let breachCatalog: Bool
    /// The items when they do not come from the report ("Vus par un ancien membre").
    var itemIDs: Set<String>? = nil
    let onShow: () -> Void

    private var unavailable: String? {
        card.unavailableNote(report: report, checkBreaches: checkBreaches, breachCatalog: breachCatalog)
    }

    var body: some View {
        let ids = itemIDs ?? card.itemIDs(in: report)
        // A red issue card that flagged something is the alert wash with white text, like on
        // iPhone; with nothing to report it stays a plain card.
        let alert = card.isAlert && unavailable == nil && !ids.isEmpty
        Group {
            if alert {
                cardBody(ids: ids, alert: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .washBackground(
                        Theme.Wash.alert(WatchtowerCard.alertFill), flat: WatchtowerCard.alertFill,
                        in: RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
            } else {
                EditorCard { cardBody(ids: ids, alert: false) }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("watchtower.card.\(card.id)")
    }

    private func cardBody(ids: Set<String>, alert: Bool) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            HStack(alignment: .firstTextBaseline) {
                Text(unavailable == nil ? "\(ids.count)" : "–")
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .foregroundStyle(
                        alert ? AnyShapeStyle(.white)
                            : unavailable == nil && !ids.isEmpty ? AnyShapeStyle(card.color) : AnyShapeStyle(.secondary))
                Spacer()
                WatchtowerArtwork(card: card, size: 40, onWash: alert)
            }
            Text(card.title).font(.headline).foregroundStyle(alert ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            Text(unavailable ?? card.message)
                .font(.callout)
                .foregroundStyle(alert ? AnyShapeStyle(.white) : AnyShapeStyle(.secondary))
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            PageLinkButton(title: String(localized: "browse.showItems"), action: onShow, onWash: alert)
                .disabled(ids.isEmpty)
                .opacity(ids.isEmpty ? 0.45 : 1)
        }
        .padding(Theme.Space.l)
        .frame(maxWidth: .infinity, minHeight: Self.minHeight, alignment: .topLeading)
    }
}

// MARK: - Setting

/// "Vérifier les fuites" and "Me prévenir": two quiet rows, a short line under each, the switch on
/// the right. What the check sends is one click away (the info button), not a paragraph.
struct BreachSettingCard: View {
    @Environment(AppModel.self) private var model
    @Environment(\.toast) private var toast
    @Environment(\.openURL) private var openURL
    @State private var showingDetails = false

    var body: some View {
        @Bindable var watchtower = model.watchtower
        EditorCard {
            VStack(spacing: 0) {
                row(title: "Vérifier les fuites", detail: "Tes mots de passe ne quittent jamais l'appareil.",
                    isOn: $watchtower.checkBreaches, id: "watchtower.checkBreaches") {
                    Button {
                        showingDetails = true
                    } label: {
                        Image(systemName: "info.circle").foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("browse.whatSent")
                    .popover(isPresented: $showingDetails, arrowEdge: .bottom) {
                        Text("""
                            Pour chaque mot de passe, Cleon envoie à Have I Been Pwned les 5 premiers \
                            caractères de son empreinte SHA-1, partagés avec des centaines d'autres, et \
                            compare le reste ici. La liste des sites piratés est téléchargée en entier \
                            et gardée une semaine. Désactivé, aucune requête réseau.
                            """)
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(width: 320)
                            .padding(14)
                    }
                    .accessibilityLabel(Text("browse.whatSent"))
                    .accessibilityIdentifier("watchtower.checkBreaches.info")
                }
                Rectangle().fill(Color.primary.opacity(0.06)).frame(height: 1).padding(.leading, 16)
                row(title: "Me prévenir", detail: "Le nombre seulement, jamais le nom d'un élément.",
                    isOn: $watchtower.notify, id: "watchtower.notify") { EmptyView() }
            }
        }
        // The system said no: the switch went back off, and this says why with a way out.
        .onChange(of: watchtower.notifyDenials) { _, _ in
            let openURL = openURL
            toast(.info(
                String(localized: "rx.watchtower.notify.denied"), systemImage: "bell.slash",
                action: DBToastButton(String(localized: "app.openSettings")) {
                    if let url = Self.notificationSettingsURL { openURL(url) }
                }))
        }
    }

    /// The app's page in Settings (iOS), or the Notifications pane (macOS).
    private static var notificationSettingsURL: URL? {
        #if canImport(UIKit)
        URL(string: UIApplication.openSettingsURLString)
        #else
        URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension")
        #endif
    }

    private func row<Accessory: View>(
        title: LocalizedStringKey, detail: LocalizedStringKey, isOn: Binding<Bool>, id: String,
        @ViewBuilder accessory: () -> Accessory
    ) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(title).font(.body.weight(.medium))
                    accessory()
                }
                Text(detail).font(.footnote).foregroundStyle(.secondary)
            }
            Spacer(minLength: 12)
            Toggle(title, isOn: isOn)
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
                .accessibilityIdentifier(id)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 11)
    }
}

/// A Watchtower card's drawn icon, like the settings pages' icons. On the red alert wash it sits
/// on a pale disc so the red artwork keeps its edge.
struct WatchtowerArtwork: View {
    let card: WatchtowerCard
    var size: CGFloat = 28
    var onWash = false

    var body: some View {
        Image(card.artwork)
            .resizable()
            .interpolation(.high)
            .frame(width: size, height: size)
            .padding(onWash ? size * 0.14 : 0)
            .background { if onWash { Circle().fill(.white.opacity(0.92)) } }
            .accessibilityHidden(true)
    }
}
