import DesignKit
import SwiftUI

// MARK: - The tour pages

/// One page of the feature tour. The same pages serve the first launch intro and the "Quoi de neuf"
/// sheet, so a feature is described once and both stay in step.
struct FeatureTourPage: Identifiable {
    /// A small feature in the grid page: a glyph and two short lines.
    struct Tile: Identifiable {
        let id: String
        let symbol: String
        let hue: Color
        let title: LocalizedStringResource
        let detail: LocalizedStringResource
    }

    let id: String
    let symbol: String
    let hue: Color
    let title: LocalizedStringResource
    let body: LocalizedStringResource
    /// Two small discs floating around the main art. They move a little faster than it while the
    /// page slides, which gives the depth without any extra art.
    var satellites: [String] = []
    /// The grid page lists several features at once instead of one art.
    var tiles: [Tile] = []
}

extension FeatureTourPage {
    private typealias Hue = Theme.RX.Hue

    /// A new key with its French text as the fallback: the page reads right before the key reaches
    /// the string catalog (keys handed over in strings-H.json).
    private static func text(_ key: StaticString, _ french: String.LocalizationValue) -> LocalizedStringResource {
        LocalizedStringResource(key, defaultValue: french)
    }

    static let onePlace = FeatureTourPage(
        id: "oneplace", symbol: "key.horizontal.fill", hue: Hue.indigo,
        title: "onboarding.intro.oneplace.title", body: "onboarding.intro.oneplace.body",
        satellites: ["person.crop.circle.fill", "globe"])

    /// Passkeys are stored and filled by the AutoFill extension; Credential Exchange
    /// (`CredentialExchangeImport`) brings everything from Apple Passwords or another manager.
    static let passkeys = FeatureTourPage(
        id: "passkeys", symbol: "person.badge.key.fill", hue: Hue.violet,
        title: text("onboarding.intro.passkeys.title", "Tes passkeys, ici aussi"),
        body: text(
            "onboarding.intro.passkeys.body",
            "Connecte-toi avec Face ID ou Touch ID, sans mot de passe à retenir. Tu viens d'une autre app, Mots de passe d'Apple compris ? Tout arrive en un seul geste."),
        satellites: ["faceid", "square.and.arrow.down.fill"])

    /// Weak, reused and breached passwords (`WatchtowerModel`).
    static let watchtower = FeatureTourPage(
        id: "watchtower", symbol: "shield.lefthalf.filled", hue: Hue.green,
        title: text("onboarding.intro.watchtower.title", "Watchtower veille sur toi"),
        body: text(
            "onboarding.intro.watchtower.body",
            "Un mot de passe faible, réutilisé ou trouvé dans une fuite ? Tu le sais tout de suite, et tu sais quoi changer."),
        satellites: ["exclamationmark.triangle.fill", "checkmark.circle.fill"])

    /// Only what ships: Nearby (`Browse/Nearby.swift`), Travel Mode (`TravelSettings`), Family
    /// (`FamilyView`, recovery included), Wi-Fi automatique (`WifiAutoController`), the Watch app
    /// (codes) and the developer pages (SSH agent and MCP approvals).
    static let extras = FeatureTourPage(
        id: "extras", symbol: "sparkles", hue: Hue.orange,
        title: text("onboarding.intro.extras.title", "Et plein de petites attentions"),
        body: text("onboarding.intro.extras.body", "Ce qu'on a ajouté ces derniers temps. À découvrir quand tu veux."),
        tiles: [
            Tile(id: "nearby", symbol: "location.fill", hue: Hue.blue,
                 title: text("onboarding.intro.tile.nearby.title", "À proximité"),
                 detail: text("onboarding.intro.tile.nearby.detail", "Les codes de l'endroit où tu es")),
            Tile(id: "travel", symbol: "airplane", hue: Hue.teal,
                 title: text("onboarding.intro.tile.travel.title", "Mode Voyage"),
                 detail: text("onboarding.intro.tile.travel.detail", "Des coffres qui restent à la maison")),
            Tile(id: "family", symbol: "person.2.fill", hue: Hue.pink,
                 title: text("onboarding.intro.tile.family.title", "Famille"),
                 detail: text("onboarding.intro.tile.family.detail", "Partage et récupération entre proches")),
            Tile(id: "wifi", symbol: "wifi", hue: Hue.indigo,
                 title: text("onboarding.intro.tile.wifi.title", "Wi-Fi"),
                 detail: text("onboarding.intro.tile.wifi.detail", "Tes réseaux rejoints tout seuls")),
            Tile(id: "watch", symbol: "applewatch", hue: Hue.red,
                 title: text("onboarding.intro.tile.watch.title", "Apple Watch"),
                 detail: text("onboarding.intro.tile.watch.detail", "Tes codes au poignet")),
            Tile(id: "developer", symbol: "terminal.fill", hue: Hue.slate,
                 title: text("onboarding.intro.tile.developer.title", "Développeurs"),
                 detail: text("onboarding.intro.tile.developer.detail", "Agent SSH et MCP, avec ton accord")),
        ])

    /// The promise that closes the intro. The iCloud sentence only where the build syncs through
    /// iCloud: a mailbox build would be told something false.
    static func yourKey(iCloud: Bool) -> FeatureTourPage {
        FeatureTourPage(
            id: "yourkey", symbol: "lock.fill", hue: Hue.indigo,
            title: "onboarding.intro.yourkey.title",
            body: iCloud
                ? text(
                    "onboarding.intro.yourkey.icloud.body",
                    "Ton coffre est chiffré sur ton appareil et voyage par ton iCloud. Même nous ne pouvons pas l'ouvrir. Sur ton prochain appareil, ton mot de passe maître suffit.")
                : "onboarding.intro.yourkey.body",
            satellites: ["icloud.fill", "macbook.and.iphone"])
    }

    /// First launch: what Cleon is, what it does now, and who holds the key. Five pages, the
    /// three in the middle being the ones "Quoi de neuf" shows too.
    static func intro(iCloud: Bool) -> [FeatureTourPage] {
        [onePlace, passkeys, watchtower, extras, yourKey(iCloud: iCloud)]
    }

    /// "Quoi de neuf": the features only, the promise is known already.
    static let whatsNew: [FeatureTourPage] = [passkeys, watchtower, extras]
}

// MARK: - The pager

/// A paged tour: one page per screen, swiped or advanced by the button, a skip at the top right and
/// a page indicator above the button. Shared by the intro and the "Quoi de neuf" sheet.
struct FeatureTour: View {
    let pages: [FeatureTourPage]
    /// A small line above the pages ("Quoi de neuf"); nil in the intro.
    var eyebrow: LocalizedStringResource?
    /// The last page's button.
    var finishTitle: LocalizedStringResource
    /// Prefix of the accessibility identifiers, so UI tests tell the intro from the sheet.
    var identifier: String
    let finish: () -> Void

    @State private var page: Int? = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var current: Int { page ?? 0 }
    private var isLast: Bool { current == pages.count - 1 }

    var body: some View {
        VStack(spacing: 0) {
            topBar
            pager
            footer
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        #if os(iOS)
        .sensoryFeedback(.selection, trigger: page)
        #endif
        #if DEBUG
        .onAppear {
            // Captures: `-OnePassIntroPage 3` opens the tour on that page.
            let start = UserDefaults.standard.integer(forKey: "OnePassIntroPage")
            if pages.indices.contains(start) { page = start }
        }
        #endif
    }

    private var topBar: some View {
        HStack {
            if let eyebrow {
                Text(eyebrow)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(Theme.accent)
                    .textCase(.uppercase)
                    .accessibilityAddTraits(.isHeader)
            }
            Spacer()
            if !isLast {
                Button("onboarding.intro.skip") { finish() }
                    .buttonStyle(.plain)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, Theme.Space.s)
                    .frame(minHeight: Theme.RX.Metrics.minTapTarget)
                    .contentShape(.rect)
                    .accessibilityIdentifier("\(identifier).skip")
                    .transition(.opacity)
            }
        }
        .frame(height: 52)
        .padding(.horizontal, Platform.isMac ? Theme.Space.xl : Theme.Space.l)
        .animation(.easeOut(duration: 0.2), value: isLast)
    }

    /// A paging scroll view rather than a swipe gesture: the page follows the finger, can be
    /// thrown back, and gives `scrollTransition` the progress the parallax reads.
    private var pager: some View {
        GeometryReader { proxy in
            ScrollView(.horizontal) {
                LazyHStack(spacing: 0) {
                    ForEach(Array(pages.enumerated()), id: \.offset) { index, item in
                        FeatureTourPageView(page: item, isActive: index == current)
                            .frame(width: proxy.size.width, height: proxy.size.height)
                            .id(index)
                    }
                }
                .scrollTargetLayout()
            }
            .scrollTargetBehavior(.paging)
            .scrollPosition(id: $page)
            .scrollIndicators(.hidden)
        }
    }

    private var footer: some View {
        VStack(spacing: Theme.Space.xl) {
            FeatureTourDots(count: pages.count, current: current)
            Button {
                advance()
            } label: {
                Text(isLast ? finishTitle : "common.continue")
                    .font(.headline)
                    .frame(maxWidth: Platform.isMac ? 240 : .infinity)
                    .frame(height: Platform.isMac ? 36 : 52)
                    // The label swaps without sliding (the width stays, only the words change).
                    .transaction { $0.animation = nil }
            }
            .buttonStyle(.glassProminent)
            .buttonBorderShape(.capsule)
            #if os(macOS)
            .keyboardShortcut(.defaultAction)
            #endif
            .accessibilityIdentifier("\(identifier).next")
        }
        .frame(maxWidth: 520)
        .padding(.horizontal, Theme.Space.xl)
        .padding(.top, Theme.Space.m)
        .padding(.bottom, Platform.isMac ? 40 : Theme.Space.m)
    }

    private func advance() {
        guard !isLast else { return finish() }
        withAnimation(reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.45, bounce: 0)) {
            page = current + 1
        }
    }
}

/// The page indicator: the current page a wider accent capsule, the others small dots. Read by
/// VoiceOver as one "Étape 2 sur 5" value.
private struct FeatureTourDots: View {
    let count: Int
    let current: Int
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Theme.Space.s) {
            ForEach(0..<count, id: \.self) { index in
                Capsule()
                    .fill(index == current ? Theme.accent : Color.primary.opacity(0.15))
                    .frame(width: index == current ? 20 : 8, height: 8)
            }
        }
        .animation(reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.35, bounce: 0), value: current)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("onboarding.progress"))
        .accessibilityValue(Text("onboarding.stepOf \(current + 1) \(count)"))
    }
}

/// One page: the art (or the grid of tiles), a large title and a short body, coming in one after
/// the other the first time the page shows. With Reduce Motion they fade in together, the art
/// stays still and the symbols do not bounce.
private struct FeatureTourPageView: View {
    let page: FeatureTourPage
    let isActive: Bool

    /// Latched on the first show: swiping back to a page never blanks it again.
    @State private var shown = false
    @State private var bounce = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        // Vertical scrolling only when the text is too tall (large Dynamic Type, small iPhone).
        ScrollView(.vertical) {
            VStack(spacing: Theme.Space.l) {
                if page.tiles.isEmpty {
                    art
                        .padding(.bottom, Theme.Space.s)
                        .entrance(shown, step: 0, reduceMotion: reduceMotion)
                }
                Text(page.title)
                    .font(.system(.largeTitle, weight: .bold))
                    .accessibilityAddTraits(.isHeader)
                    .entrance(shown, step: 1, reduceMotion: reduceMotion)
                Text(page.body)
                    .font(Platform.isMac ? .title3 : .body)
                    .foregroundStyle(.secondary)
                    .lineSpacing(2)
                    .entrance(shown, step: 2, reduceMotion: reduceMotion)
                if !page.tiles.isEmpty {
                    tileGrid.padding(.top, Theme.Space.s)
                }
            }
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: 460)
            .padding(.horizontal, Theme.Space.xl)
            .padding(.top, page.tiles.isEmpty ? (Platform.isMac ? 96 : 72) : Theme.Space.xl)
            .padding(.bottom, Theme.Space.l)
            .frame(maxWidth: .infinity)
        }
        .scrollBounceBehavior(.basedOnSize)
        .scrollIndicators(.hidden)
        .accessibilityIdentifier("onboarding.intro.page.\(page.id)")
        .onChange(of: isActive, initial: true) { _, active in
            guard active, !shown else { return }
            shown = true
            if !reduceMotion { bounce += 1 }
        }
    }

    // MARK: Art

    /// A tile of the page's hue with its white glyph, two small discs around it. The tile and the
    /// discs slide at different rates while the page moves: a light parallax, none with Reduce
    /// Motion.
    private var art: some View {
        let tile: CGFloat = 112
        let radius: CGFloat = Theme.RX.Radius.sheet
        return ZStack {
            RoundedRectangle(cornerRadius: radius, style: .continuous)
                .fill(Color.clear)
                .frame(width: tile, height: tile)
                .washBackground(hueWash(page.hue), flat: page.hue,
                                in: RoundedRectangle(cornerRadius: radius, style: .continuous))
                .overlay {
                    Image(systemName: page.symbol)
                        .font(.system(size: 48, weight: .semibold))
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(.white)
                        .symbolEffect(.bounce.up.byLayer, options: .nonRepeating, value: bounce)
                }
                .shadow(color: page.hue.opacity(0.25), radius: 16, y: 8)
                .parallax(rate: 50, enabled: !reduceMotion)

            ForEach(Array(page.satellites.prefix(2).enumerated()), id: \.offset) { index, symbol in
                satellite(symbol)
                    .offset(x: index == 0 ? 70 : -72, y: index == 0 ? -44 : 46)
                    .parallax(rate: index == 0 ? 110 : 90, enabled: !reduceMotion)
                    .entrance(shown, step: 3 + index, reduceMotion: reduceMotion)
            }
        }
        .frame(width: 240, height: 150)
        .accessibilityHidden(true)
    }

    /// A small round chip on the page background: the hue glyph, hierarchical, on a soft disc.
    private func satellite(_ symbol: String) -> some View {
        let size: CGFloat = 44
        return Circle()
            .fill(.background)
            .frame(width: size, height: size)
            .overlay {
                Circle().fill(page.hue.opacity(0.14))
            }
            .overlay {
                Image(systemName: symbol)
                    .font(Theme.RX.Glyph.font(Theme.RX.Metrics.discGlyph(diameter: size)))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(page.hue)
                    .symbolEffect(.bounce, options: .nonRepeating, value: bounce)
            }
            .shadow(color: .black.opacity(Theme.RX.Shadow.raisedOpacity),
                    radius: Theme.RX.Shadow.raisedRadius, y: Theme.RX.Shadow.raisedY)
    }

    // MARK: Tiles

    private var tileGrid: some View {
        LazyVGrid(
            columns: [GridItem(.flexible(), spacing: Theme.Space.m), GridItem(.flexible(), spacing: Theme.Space.m)],
            spacing: Theme.Space.m
        ) {
            ForEach(Array(page.tiles.enumerated()), id: \.element.id) { index, tile in
                tileView(tile)
                    .entrance(shown, step: 3 + index, reduceMotion: reduceMotion)
            }
        }
    }

    /// A card of the RX look: the glyph on a soft disc of its hue, the name, one line under it.
    /// The disc sits `Space.m` inside the card, so its corner follows the card's (concentric).
    private func tileView(_ tile: FeatureTourPage.Tile) -> some View {
        let padding = Theme.Space.m
        let outer = Theme.RX.Radius.card
        let disc: CGFloat = 36
        return VStack(alignment: .leading, spacing: Theme.Space.s) {
            RoundedRectangle(cornerRadius: Theme.Radius.nested(outer: outer, padding: padding), style: .continuous)
                .fill(tile.hue.opacity(0.14))
                .frame(width: disc, height: disc)
                .overlay {
                    Image(systemName: tile.symbol)
                        .font(Theme.RX.Glyph.font(Theme.RX.Metrics.discGlyph(diameter: disc)))
                        .symbolRenderingMode(.hierarchical)
                        .foregroundStyle(tile.hue)
                        .symbolEffect(.bounce, options: .nonRepeating, value: bounce)
                }
                .accessibilityHidden(true)
            Text(tile.title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.primary)
            Text(tile.detail)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .multilineTextAlignment(.leading)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(padding)
        // The field grey rather than the card white: the onboarding page is white in light mode.
        .background(
            Theme.RX.Palette.field.color,
            in: RoundedRectangle(cornerRadius: outer, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    /// The page's hue lightened on top, as the accent wash.
    private func hueWash(_ hue: Color) -> LinearGradient {
        LinearGradient(colors: [hue.mix(with: .white, by: 0.12), hue], startPoint: .top, endPoint: .bottom)
    }
}

private extension View {
    /// Comes in after `step` short beats: up a few points and in from transparent. One beat is
    /// 70 ms, short enough that the whole page settles in about half a second.
    func entrance(_ shown: Bool, step: Int, reduceMotion: Bool) -> some View {
        opacity(shown ? 1 : 0)
            .offset(y: shown || reduceMotion ? 0 : 14)
            .animation(
                reduceMotion
                    ? .easeOut(duration: 0.25)
                    : .spring(duration: 0.5, bounce: 0).delay(Double(step) * 0.07),
                value: shown)
    }

    /// Slides `rate` points against the page while it moves, so the art lags behind the text.
    func parallax(rate: CGFloat, enabled: Bool) -> some View {
        scrollTransition(.interactive, axis: .horizontal) { content, phase in
            content.offset(x: enabled ? phase.value * rate : 0)
        }
    }
}

// MARK: - First launch intro

/// The tour before the welcome screen, shown once on a first launch: what Cleon is, what it does
/// now (passkeys, Watchtower, the smaller features) and who holds the key. Plain words only; the
/// cryptography stays in Settings. A vault found in iCloud closes it at once (`OnboardingFlow`).
struct OnboardingIntro: View {
    /// Called on "Passer" and on the last page's button.
    let finish: () -> Void

    @Environment(AppModel.self) private var app

    var body: some View {
        #if DEBUG
        // Captures: `-OnePassShowIntro YES -OnePassWhatsNewPreview YES` shows the "Quoi de neuf"
        // pages in place of the intro, so they can be shot before the root presents the sheet.
        if UserDefaults.standard.bool(forKey: "OnePassWhatsNewPreview") {
            WhatsNewSheet()
        } else {
            intro
        }
        #else
        intro
        #endif
    }

    private var intro: some View {
        FeatureTour(
            pages: FeatureTourPage.intro(iCloud: app.cloudKitEnabled),
            finishTitle: "onboarding.intro.start",
            identifier: "onboarding.intro",
            finish: finish)
    }
}

extension OnboardingIntro {
    private static let seenKey = "OnePassOnboardingIntroSeen"

    /// First launch only. Never under UI tests or the screenshot launch arguments, which drive
    /// the welcome screen directly.
    @MainActor static func shouldShow(for app: AppModel, restoreOnly: Bool) -> Bool {
        let defaults = UserDefaults.standard
        if restoreOnly || app.addingAccount != nil || app.onboardingStart != nil { return false }
        if defaults.bool(forKey: "OnePassTestIsolation") { return false }
        if defaults.string(forKey: "OnePassOnboardingStep") != nil { return false }
        if defaults.bool(forKey: "OnePassSkipIntro") { return false }
        if defaults.bool(forKey: "OnePassShowIntro") { return true }
        return !defaults.bool(forKey: seenKey)
    }

    /// `toured`: the pages were on screen (read or skipped), so this version's "Quoi de neuf"
    /// would only repeat them. False when a vault found in iCloud closed the intro before anyone
    /// saw it: that returning user gets "Quoi de neuf" after the unlock instead.
    static func markSeen(toured: Bool = true) {
        UserDefaults.standard.set(true, forKey: seenKey)
        if toured { WhatsNew.markSeen() }
    }
}

// MARK: - Quoi de neuf

/// "Quoi de neuf" after an update: the feature pages of the intro in a sheet, once per app version
/// (`CFBundleShortVersionString`), only once the vault is unlocked and no onboarding is running.
enum WhatsNew {
    private static let lastSeenKey = "OnePassWhatsNewLastSeenVersion"

    static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
    }

    @MainActor static func shouldShow(for app: AppModel) -> Bool {
        let defaults = UserDefaults.standard
        guard app.session.state == .unlocked, !app.onboardingInProgress else { return false }
        // UI tests and the capture runs drive their own screens: a sheet would cover them.
        if defaults.bool(forKey: "OnePassTestIsolation") || defaults.bool(forKey: "OnePassSkipWhatsNew") {
            return false
        }
        #if DEBUG
        if defaults.bool(forKey: "OnePassShowWhatsNew") { return true }
        #endif
        return defaults.string(forKey: lastSeenKey) != currentVersion
    }

    static func markSeen() {
        UserDefaults.standard.set(currentVersion, forKey: lastSeenKey)
    }
}

/// The sheet itself: the same pager as the intro, with a "Quoi de neuf" line on top.
struct WhatsNewSheet: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        FeatureTour(
            pages: FeatureTourPage.whatsNew,
            eyebrow: LocalizedStringResource("whatsNew.eyebrow", defaultValue: "Quoi de neuf"),
            finishTitle: LocalizedStringResource("whatsNew.done", defaultValue: "C'est parti"),
            identifier: "whatsNew",
            finish: { dismiss() })
        #if os(macOS)
        .frame(width: 560, height: 680)
        #endif
        .presentationDetents([.large])
        .presentationCornerRadius(Theme.RX.Radius.sheet)
    }
}

/// Attach once at the root (inside the `AppModel` environment): presents "Quoi de neuf" after the
/// first unlock of a new version. Marked seen when it opens, so a crash or a swipe down never
/// brings it back for the same version.
private struct WhatsNewPresenter: ViewModifier {
    @Environment(AppModel.self) private var app
    @State private var presented = false

    func body(content: Content) -> some View {
        content
            .task(id: trigger) {
                guard trigger else { return }
                // Let the vault door open and the first screen settle before a sheet slides up.
                try? await Task.sleep(for: .milliseconds(900))
                guard !Task.isCancelled, WhatsNew.shouldShow(for: app) else { return }
                WhatsNew.markSeen()
                presented = true
            }
            .sheet(isPresented: $presented) {
                WhatsNewSheet()
            }
    }

    /// Unlocked with no onboarding on screen: the only moment the sheet may come up.
    private var trigger: Bool {
        app.session.state == .unlocked && !app.onboardingInProgress
    }
}

extension View {
    /// "Quoi de neuf" once per app version, after the unlock. See `WhatsNewPresenter`.
    func whatsNewAfterUpdate() -> some View {
        modifier(WhatsNewPresenter())
    }
}
