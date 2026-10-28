import DesignKit
import SwiftUI
import VaultKit

/// Watchtower page of the main window: score gauge, password strength, one card per check.
/// Everything comes from the core's report (`WatchtowerModel`); nothing is shown before it.
struct WatchtowerPage: View {
    @Environment(AppModel.self) private var model

    private var watchtower: WatchtowerModel { model.watchtower }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                PageHeader(
                    title: "Watchtower", symbol: "checkmark.shield.fill", color: Theme.accent,
                    message: String(localized: "Watchtower repère les mots de passe à changer et les sites où tu peux renforcer la sécurité de tes comptes.")
                ) {
                    ScoreGauge(score: watchtower.report.map { Int($0.score) })
                }
                statusLine
                if let report = watchtower.report {
                    StrengthCard(levels: report.strength.map(Int.init))
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 250), spacing: 14)], spacing: 14) {
                        ForEach(WatchtowerCard.all) { card in
                            WatchtowerCardView(
                                card: card, report: report, checkBreaches: watchtower.checkBreaches,
                                breachCatalog: watchtower.breachCatalogUsed
                            ) {
                                model.showWatchtowerItems(title: card.title, itemIDs: card.itemIDs(in: report))
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
        .navigationTitle("Watchtower")
        .toolbar {
            ToolbarItem {
                Button {
                    watchtower.refresh(model.session)
                } label: {
                    Label("Analyser à nouveau", systemImage: "arrow.clockwise")
                }
                .disabled(watchtower.isRunning)
                .help(Text("Analyser à nouveau"))
            }
        }
        .task(id: model.session.summariesRevision) { watchtower.refreshIfNeeded(model.session) }
        .onChange(of: watchtower.checkBreaches) { watchtower.refreshIfNeeded(model.session) }
        .onChange(of: model.session.hiddenVaultIDs) { watchtower.refreshIfNeeded(model.session) }
        .accessibilityIdentifier("page.watchtower")
    }

    @ViewBuilder private var statusLine: some View {
        switch watchtower.phase {
        case .idle, .ready:
            if let report = watchtower.report {
                Text(summary(report)).font(.callout).foregroundStyle(.secondary)
            }
        case .analyzing:
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Analyse des éléments…").font(.callout).foregroundStyle(.secondary)
            }
        case .checkingBreaches(let done, let total):
            HStack(spacing: 8) {
                ProgressView(value: Double(done), total: Double(max(total, 1)))
                    .frame(width: 140)
                Text("Vérification des fuites : \(done) sur \(total)").font(.callout).foregroundStyle(.secondary)
            }
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(.orange)
        }
    }

    private func summary(_ report: FfiWatchtowerReport) -> String {
        let items = report.itemsAnalyzed == 1
            ? String(localized: "1 élément analysé") : String(localized: "\(report.itemsAnalyzed) éléments analysés")
        switch report.pwned {
        case .checked:
            return items + String(localized: " · fuites vérifiées")
        case .partial(let failed):
            return items + String(localized: " · fuites vérifiées en partie (\(failed) requêtes en échec)")
        case .unavailable:
            return items + String(localized: " · fuites non vérifiées (pas de réseau)")
        case .disabled:
            return items + String(localized: " · vérification des fuites désactivée")
        }
    }
}

// MARK: - Score

/// Semicircle gauge of the core's score (0 to 100) with its label.
struct ScoreGauge: View {
    let score: Int?

    static func label(_ score: Int) -> String {
        switch score {
        case ..<40: String(localized: "Faible")
        case ..<60: String(localized: "Moyen")
        case ..<80: String(localized: "Bon")
        case ..<95: String(localized: "Excellent")
        default: String(localized: "Fantastique")
        }
    }

    static func color(_ score: Int) -> Color {
        switch score {
        case ..<40: .red
        case ..<60: .orange
        case ..<80: .yellow
        default: .green
        }
    }

    var body: some View {
        let fraction = Double(score ?? 0) / 100
        ZStack(alignment: .bottom) {
            Arc(fraction: 1)
                .stroke(.secondary.opacity(0.2), style: StrokeStyle(lineWidth: 16, lineCap: .round))
            Arc(fraction: fraction)
                .stroke(
                    AngularGradient(
                        colors: [.red, .orange, .yellow, .green], center: .bottom,
                        startAngle: .degrees(180), endAngle: .degrees(360)),
                    style: StrokeStyle(lineWidth: 16, lineCap: .round))
                .animation(.smooth, value: fraction)
            VStack(spacing: 0) {
                Text(score.map(String.init) ?? "–")
                    .font(.system(size: 46, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                Text(score.map(Self.label) ?? String(localized: "Analyse…"))
                    .font(.headline)
                    .foregroundStyle(score.map(Self.color) ?? .secondary)
            }
            .padding(.bottom, 2)
        }
        .frame(width: 230, height: 125)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Score de sécurité"))
        .accessibilityValue(Text(score.map { "\($0) sur 100, \(Self.label($0))" } ?? ""))
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
        String(localized: "Trop courts"), String(localized: "Faibles"), String(localized: "Moyens"),
        String(localized: "Bons"), String(localized: "Excellents"),
    ]
    private static let colors: [Color] = [.red, .orange, .yellow, .mint, .green]

    var body: some View {
        let total = levels.reduce(0, +)
        EditorCard {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Force globale des mots de passe").font(.headline)
                    Spacer()
                    Text(total == 1 ? String(localized: "1 mot de passe") : String(localized: "\(total) mots de passe"))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                if total == 0 {
                    Text("Aucun mot de passe à analyser pour l'instant.")
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

    let id: String
    let checks: [String]
    let title: String
    let message: String
    let symbol: String
    let color: Color
    let source: Source

    func itemIDs(in report: FfiWatchtowerReport) -> Set<String> {
        Set(report.checks.filter { checks.contains($0.check) }.flatMap(\.itemIds))
    }

    /// Why the card has no figure: its data source did not run. Nil when it did.
    func unavailableNote(report: FfiWatchtowerReport, checkBreaches: Bool, breachCatalog: Bool) -> String? {
        switch source {
        case .local:
            return nil
        case .breaches:
            switch report.pwned {
            case .disabled: return String(localized: "Vérification des fuites désactivée.")
            case .unavailable: return checkBreaches ? String(localized: "En attente du réseau.") : nil
            case .checked, .partial: return nil
            }
        case .sites:
            return report.sitesChecked ? nil
                : checkBreaches ? String(localized: "Catalogue des sites pas encore téléchargé.")
                : String(localized: "Active « Vérifier les fuites » pour télécharger le catalogue des sites.")
        case .breachCatalog:
            return breachCatalog ? nil
                : checkBreaches ? String(localized: "Catalogue des fuites pas encore téléchargé.")
                : String(localized: "Active « Vérifier les fuites » pour télécharger le catalogue des sites piratés.")
        }
    }

    /// The card holding `check`, for the item detail.
    static func of(check: String) -> WatchtowerCard? {
        all.first { $0.checks.contains(check) }
    }

    static let all: [WatchtowerCard] = [
        WatchtowerCard(
            id: "compromised", checks: ["compromised"],
            title: String(localized: "Mots de passe compromis"),
            message: String(localized: "Ils apparaissent dans des fuites de données connues. Change-les en priorité."),
            symbol: "exclamationmark.octagon.fill", color: .red, source: .breaches),
        WatchtowerCard(
            id: "breached_site", checks: ["breached_site"],
            title: String(localized: "Sites piratés"),
            message: String(localized: "Ces sites ont subi une fuite depuis ton dernier changement de mot de passe. Change-le sur chacun."),
            symbol: "exclamationmark.shield.fill", color: .red, source: .breachCatalog),
        WatchtowerCard(
            id: "provider_exposed", checks: ["provider_exposed"],
            title: String(localized: "Comptes de connexion exposés"),
            message: String(localized: "Un compte qui te sert à te connecter ailleurs est compromis, faible, réutilisé ou sans double authentification : tous les sites qui en dépendent sont exposés."),
            symbol: "person.crop.circle.badge.exclamationmark", color: .red, source: .local),
        WatchtowerCard(
            id: "reused", checks: ["reused"],
            title: String(localized: "Mots de passe réutilisés"),
            message: String(localized: "Un même mot de passe sur plusieurs comptes : une seule fuite suffit à tous les ouvrir."),
            symbol: "arrow.triangle.2.circlepath", color: .orange, source: .local),
        WatchtowerCard(
            id: "weak", checks: ["weak"],
            title: String(localized: "Mots de passe faibles"),
            message: String(localized: "Faciles à deviner. Remplace-les par des mots de passe générés."),
            symbol: "lock.open.fill", color: .orange, source: .local),
        WatchtowerCard(
            id: "passkey", checks: ["passkey_available"],
            title: String(localized: "Passkeys disponibles"),
            message: String(localized: "Ces sites acceptent les passkeys, plus sûres et plus simples qu'un mot de passe."),
            symbol: "person.badge.key.fill", color: Theme.accent, source: .sites),
        WatchtowerCard(
            id: "2fa", checks: ["missing_2fa"],
            title: String(localized: "Double authentification disponible"),
            message: String(localized: "Ces sites proposent des codes à usage unique que tu n'as pas encore ajoutés."),
            symbol: "lock.shield.fill", color: .blue, source: .sites),
        WatchtowerCard(
            id: "http", checks: ["insecure_url"],
            title: String(localized: "Sites en HTTP"),
            message: String(localized: "Ces adresses ne sont pas chiffrées. Passe-les en HTTPS si le site le permet."),
            symbol: "globe.badge.chevron.backward", color: .yellow, source: .local),
        WatchtowerCard(
            id: "expiring", checks: ["expired", "expiring"],
            title: String(localized: "Éléments qui expirent"),
            message: String(localized: "Cartes, documents et licences expirés ou qui expirent dans les 30 jours."),
            symbol: "calendar.badge.exclamationmark", color: .pink, source: .local),
        WatchtowerCard(
            id: "wifi", checks: ["wifi_insecure"],
            title: String(localized: "Wi-Fi peu protégés"),
            message: String(localized: "Ces réseaux utilisent WEP ou aucun chiffrement. Passe-les en WPA2 ou WPA3 sur le routeur."),
            symbol: "wifi.exclamationmark", color: .orange, source: .local),
        WatchtowerCard(
            id: "ssh", checks: ["ssh_weak"],
            title: String(localized: "Clés SSH faibles"),
            message: String(localized: "Clés RSA de moins de 3 072 bits ou DSA. Remplace-les par une clé Ed25519."),
            symbol: "terminal.fill", color: .orange, source: .local),
        WatchtowerCard(
            id: "wallet", checks: ["wallet_no_backup"],
            title: String(localized: "Portefeuilles sans sauvegarde"),
            message: String(localized: "Indique où est rangée la copie physique de la phrase de récupération de ces portefeuilles."),
            symbol: "archivebox.fill", color: .yellow, source: .local),
        WatchtowerCard(
            id: "duplicate", checks: ["duplicate"],
            title: String(localized: "Doublons"),
            message: String(localized: "Même site et même identifiant dans plusieurs éléments. Garde-en un seul."),
            symbol: "square.on.square", color: .gray, source: .local),
        WatchtowerCard(
            id: "old", checks: ["old_password"],
            title: String(localized: "Vieux mots de passe"),
            message: String(localized: "Inchangés depuis plus d'un an. Pense à les renouveler."),
            symbol: "clock.arrow.circlepath", color: .gray, source: .local),
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
    let onShow: () -> Void

    private var unavailable: String? {
        card.unavailableNote(report: report, checkBreaches: checkBreaches, breachCatalog: breachCatalog)
    }

    var body: some View {
        let ids = card.itemIDs(in: report)
        EditorCard {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Text(unavailable == nil ? "\(ids.count)" : "–")
                        .font(.system(size: 40, weight: .bold, design: .rounded))
                        .monospacedDigit()
                        .foregroundStyle(unavailable == nil && !ids.isEmpty ? card.color : .secondary)
                    Spacer()
                    PageTile(symbol: card.symbol, color: card.color, size: 28)
                }
                Text(card.title).font(.headline)
                Text(unavailable ?? card.message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                PageLinkButton(title: String(localized: "Voir les éléments"), action: onShow)
                    .disabled(ids.isEmpty)
                    .opacity(ids.isEmpty ? 0.45 : 1)
            }
            .padding(16)
            .frame(maxWidth: .infinity, minHeight: Self.minHeight, alignment: .topLeading)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("watchtower.card.\(card.id)")
    }
}

// MARK: - Setting

/// "Vérifier les fuites" and what it sends, then "Me prévenir" (local notifications).
struct BreachSettingCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var watchtower = model.watchtower
        EditorCard {
            VStack(alignment: .leading, spacing: 8) {
                Toggle(isOn: $watchtower.checkBreaches) {
                    Text("Vérifier les fuites").font(.headline)
                }
                .toggleStyle(.switch)
                .accessibilityIdentifier("watchtower.checkBreaches")
                Text("""
                    Tes mots de passe ne quittent jamais l'appareil. Pour chacun, OnePass envoie à \
                    Have I Been Pwned les 5 premiers caractères de son empreinte SHA-1, partagés avec des \
                    centaines d'autres mots de passe, et compare le reste ici. Les catalogues publics de \
                    2fa.directory (double authentification et passkeys) et la liste des sites piratés de \
                    Have I Been Pwned sont téléchargés en entier et gardés une semaine. Désactivé, \
                    Watchtower ne fait aucune requête réseau.
                    """)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Divider().padding(.vertical, 4)
                Toggle(isOn: $watchtower.notify) {
                    Text("Me prévenir").font(.headline)
                }
                .toggleStyle(.switch)
                .accessibilityIdentifier("watchtower.notify")
                Text("Une notification quand Watchtower trouve un nouveau mot de passe compromis, un site piraté, un compte de connexion exposé ou un élément qui expire. Elle donne seulement le nombre, jamais le nom d'un élément.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(16)
        }
    }
}
