import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

#if os(iOS)

/// Réglages in the RX look (Penpot "iPhone · Settings"): the photo hero with the round close and
/// profile buttons, the account in the middle, the Plus plan card over the photo; then, on the page
/// sheet, "Get more from Plus" as a paging carousel of perks, and every page of Réglages in menu cards. Each
/// row pushes the same page as the classic list (`SettingsPage`), so nothing is lost.
struct RXSettingsHome: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var showProfileQR = Self.demoOpens("profileQR")
    @State private var showPlan = Self.demoOpens("plan")

    /// Screenshots (Debug): `-OnePassDemoRXSettings plan|profileQR` opens the plan page or the
    /// profile QR code.
    private static func demoOpens(_ name: String) -> Bool {
        #if DEBUG
        UserDefaults.standard.string(forKey: "OnePassDemoRXSettings") == name
        #else
        false
        #endif
    }

    private typealias RX = Theme.RX

    var body: some View {
        let _ = model.settingsRevision
        RXHeroPage(photo: Image(RXHero.settings)) {
            hero
        } sheet: {
            VStack(spacing: RX.Space.l) {
                RXSectionTitle(Text("rx.perks.title"))
                RXPerkCarousel(bleed: RX.Space.gutter)
                RXCard {
                    menu(.general)
                    menu(.security)
                    menu(.autofill)
                    menu(.sync)
                }
                RXCard {
                    menu(.accounts)
                    menu(.vaults, value: model.session.vaults.count)
                    menu(.contacts)
                    menu(.family)
                    menu(.organisation)
                    menu(.devices, value: model.session.devices.isEmpty ? nil : model.session.devices.count)
                    menu(.travel)
                    menu(.crypto)
                    NavigationLink {
                        WatchSettings()
                    } label: {
                        // swiftlint:disable:next db_unlocalized_string - product name, the same in every language
                        RXMenuRow(Text(verbatim: "Apple Watch"), systemImage: "applewatch")
                    }
                    .accessibilityIdentifier("settings.watch")
                    NavigationLink {
                        AgentsSettings()
                    } label: {
                        // swiftlint:disable:next db_unlocalized_string - feature name, the same in every language
                        RXMenuRow(Text(verbatim: "Agents"), systemImage: "point.3.connected.trianglepath.dotted")
                    }
                    .accessibilityIdentifier("settings.agents")
                }
                RXCard {
                    menu(.about)
                    #if DEBUG
                    menu(.iconCheck)
                    #endif
                }
                RXCard {
                    Button {
                        dismiss()
                        model.lock()
                    } label: {
                        RXMenuRow(
                            Text("Verrouiller OnePass"), systemImage: "lock.fill",
                            tint: RX.Palette.negative.color, chevron: false)
                    }
                    .accessibilityIdentifier("rx.settings.lock")
                }
                VStack(spacing: RX.Space.xs) {
                    // swiftlint:disable:next db_unlocalized_string - product name and version number
                    Text(verbatim: "OnePass \(Self.version)")
                    Text("settings.onepassOpenSourceAgpl")
                }
                .rxFont(.footnote)
                .foregroundStyle(RX.Palette.textTertiary.color)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
            }
            .rxPress(haptic: .selection)
        }
        .toolbar(.hidden, for: .navigationBar)
        .navigationDestination(isPresented: $showPlan) { RXPlanPage().zoomDestination(Self.planZoomID) }
        .sheet(isPresented: $showProfileQR) { RXProfileQRSheet() }
        .accessibilityIdentifier("rx.settings")
    }

    private static let planZoomID = "rx.plan"

    /// The top of the photo: close and profile buttons, the account, the plan card.
    private var hero: some View {
        VStack(spacing: RX.Space.xl) {
            HStack {
                GlassButton(Text("rx.settings.close"), systemImage: "xmark", onPhoto: true) { dismiss() }
                    .accessibilityIdentifier("settings.done")
                Spacer()
                GlassButton(Text("rx.profileQR.open"), systemImage: "qrcode", onPhoto: true) { showProfileQR = true }
                    .accessibilityIdentifier("rx.settings.profileQR")
            }
            NavigationLink {
                ProfileSettings()
            } label: {
                VStack(spacing: RX.Space.s) {
                    RXAvatar(initials: model.initials, photo: model.profileImage, size: 72)
                        .padding(.bottom, RX.Space.xs)
                    Text(model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName)
                        .rxFont(.title)
                        .foregroundStyle(.white)
                        .multilineTextAlignment(.center)
                        .dbText(maxLines: 2)
                    Text(model.settings.deviceMode == .shared
                         ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                        .rxFont(.callout)
                        .foregroundStyle(.white.opacity(0.72))
                }
                .frame(maxWidth: .infinity)
                .padding(.top, RX.Space.xl)
                .contentShape(Rectangle())
            }
            .rxPress(haptic: .selection)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("settings.account")
            Button {
                showPlan = true
            } label: {
                PlanCard(
                    // swiftlint:disable:next db_unlocalized_string - plan name, the same in every language
                    title: Text(verbatim: "Plus"), subtitle: Text("rx.plan.benefits"), art: Image("rx-plan-lux"),
                    perks: ["key.fill", "person.3.fill", "airplane", "chevron.right"])
            }
            .rxPress(haptic: .selection)
            .zoomSource(Self.planZoomID)
            .accessibilityIdentifier("rx.settings.plan")
            .padding(.top, RX.Space.l)
        }
    }

    private func menu(_ page: SettingsPage, value: Int? = nil) -> some View {
        NavigationLink(value: page) {
            RXMenuRow(Text(page.title), systemImage: page.symbol, value: value.map { Text($0, format: .number) })
        }
        .zoomSource(page)
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }

    private static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }
}

#endif

/// "Get more from Plus" (D-CAROUSELS): perk tiles on `RXCarousel`, each opening the page of
/// Réglages that holds the feature (nothing here is a feature this build lacks), one tile per
/// page. The tiles snap one by one and the next one peeks at the trailing edge. `bleed` is the
/// page gutter the row runs under, so it scrolls edge to edge while its first tile lines up with
/// the cards.
struct RXPerkCarousel: View {
    var bleed: CGFloat = 0
    var idPrefix = "rx.settings.perk"
    @State private var position = ScrollPosition(idType: String.self)

    private typealias RX = Theme.RX

    /// Captures: `-OnePassDemoPerk <id>` starts the carousel on that tile. Debug builds only.
    private static var demoPerk: String? {
        #if DEBUG
        UserDefaults.standard.string(forKey: "OnePassDemoPerk")
        #else
        nil
        #endif
    }

    struct Perk: Identifiable {
        let id: String
        let page: SettingsPage
        let title: LocalizedStringKey
        let subtitle: LocalizedStringKey
        let symbol: String
        let art: String
    }

    /// One tile per page: emergency access lives on the Famille page, which the family tile opens.
    static let perks: [Perk] = [
        Perk(id: "family", page: .family, title: "rx.perks.family.title", subtitle: "rx.perks.family.subtitle",
             symbol: "person.3.fill", art: "rx-perk-lux-family"),
        Perk(id: "keys", page: .security, title: "rx.perks.keys.title", subtitle: "rx.perks.keys.subtitle",
             symbol: "key.fill", art: "rx-perk-lux-hardware"),
        Perk(id: "passkeys", page: .autofill, title: "Passkeys", subtitle: "rx.perks.passkeys.subtitle",
             symbol: "person.badge.key.fill", art: "rx-perk-lux-passkey"),
        Perk(id: "travel", page: .travel, title: "Travel Mode", subtitle: "rx.perks.travel.subtitle",
             symbol: "airplane", art: "rx-perk-lux-travel"),
    ]

    var body: some View {
        RXCarousel(nil, items: Self.perks, bleed: bleed, position: $position) { perk in
            link(perk)
                .frame(width: RX.Metrics.perkCarouselTileWidth)
                .accessibilityIdentifier("\(idPrefix).\(perk.id)")
        }
        .task {
            guard let id = Self.demoPerk else { return }
            try? await Task.sleep(for: .milliseconds(500))
            position.scrollTo(id: id, anchor: .leading)
        }
        .rxPress(haptic: .selection)
    }

    private func tile(_ perk: Perk) -> some View {
        PerkTile(title: Text(perk.title), subtitle: Text(perk.subtitle), systemImage: perk.symbol, art: Image(perk.art))
    }

    /// iPhone: the page zooms out of its tile. The Mac pushes the page by value, as its rows do.
    @ViewBuilder private func link(_ perk: Perk) -> some View {
        #if os(iOS)
        NavigationLink {
            perk.page.content
                .zoomDestination("perk.\(perk.id)")
        } label: {
            tile(perk)
        }
        .zoomSource("perk.\(perk.id)")
        #else
        NavigationLink(value: perk.page) {
            tile(perk)
        }
        #endif
    }
}

/// The account in the RX look: a round photo, or the initials on the indigo gradient of the mock,
/// with a soft white ring.
struct RXAvatar: View {
    let initials: String
    var photo: Image?
    var size: CGFloat = 40
    var ring = true

    var body: some View {
        Group {
            if let photo {
                photo.resizable().scaledToFill()
            } else {
                Text(verbatim: initials.isEmpty ? "?" : initials)
                    .font(Theme.RX.Glyph.font(size * 0.38, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(
                        LinearGradient(
                            colors: Theme.RX.Wash.avatar,
                            startPoint: UnitPoint(x: 0.2, y: 0), endPoint: UnitPoint(x: 0.8, y: 1)))
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
        .overlay {
            if ring { Circle().strokeBorder(.white.opacity(0.6), lineWidth: 2) }
        }
        .accessibilityHidden(true)
    }
}
/// The Plus card's page (Penpot "Plan benefits", laid out as a plan page: the name big over the
/// photo with four quick actions, the perk carousel, then grouped lists). Each line opens the page
/// of Réglages that already holds it. OnePass has no plan or subscription data: every benefit
/// listed is a feature of this build, so nothing here is invented.
struct RXPlanPage: View {
    @Environment(\.dismiss) private var dismiss
    @ScaledMetric(relativeTo: .largeTitle) private var planNameSize: CGFloat = 52

    private typealias RX = Theme.RX

    var body: some View {
        RXHeroPage(photo: Image(RXHero.settings)) {
            VStack(alignment: .leading, spacing: RX.Space.xl) {
                #if os(iOS)
                // The Mac keeps the window toolbar's back button.
                GlassButton(Text("rx.plan.back"), systemImage: "chevron.left", onPhoto: true) { dismiss() }
                    .accessibilityIdentifier("rx.plan.back")
                #endif
                // The plan name big and centred, a line under it.
                VStack(spacing: RX.Space.s) {
                    // swiftlint:disable:next db_unlocalized_string - plan name, the same in every language
                    Text(verbatim: "Plus")
                        .font(RX.Typography.display.font(size: planNameSize))
                        .tracking(-1.5)
                        .dbText(maxLines: 1, minimumScale: 0.7)
                    Text("rx.plan.tagline")
                        .rxFont(.callout)
                        .opacity(0.75)
                        .multilineTextAlignment(.center)
                }
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.top, RX.Space.xl)
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(.isHeader)
            }
            .padding(.bottom, RX.Space.l)
        } sheet: {
            VStack(spacing: RX.Space.l) {
                RXSectionTitle(Text("rx.perks.title"))
                RXPerkCarousel(bleed: RX.Space.gutter, idPrefix: "rx.plan.perk")
                RXSectionTitle(Text("rx.plan.included"))
                // The carousel opens Famille, Sécurité, Remplissage and Voyage: the list holds the
                // rest, so no page has two entries on this screen.
                RXCard {
                    benefit(.vaults, Text("rx.plan.vaults"))
                    benefit(.contacts, Text("rx.plan.sharing"))
                    benefit(.organisation, Text("rx.plan.organisation"))
                    benefit(.devices, Text("rx.plan.devices"))
                    benefit(.crypto, Text("rx.plan.crypto"))
                }
                .rxPress(haptic: .selection)
                Text("rx.plan.footnote")
                    .rxFont(.footnote)
                    .foregroundStyle(RX.Palette.textTertiary.color)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
            }
        }
        #if os(iOS)
        .toolbar(.hidden, for: .navigationBar)
        #endif
        .accessibilityIdentifier("rx.plan")
    }

    private func benefit(_ page: SettingsPage, _ title: Text) -> some View {
        NavigationLink(value: page) {
            RXMenuRow(title, systemImage: page.symbol)
        }
        .accessibilityIdentifier("rx.plan.\(page.rawValue)")
    }
}

/// The right glass button of Réglages: the account as a contact card (vCard 3.0 with the display
/// name only), drawn as a QR code on the device with CoreImage. Nothing leaves the device until the
/// person shares the card; no server is involved.
struct RXProfileQRSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// Taps on Partager, for its haptic.
    @State private var shares = 0

    private typealias RX = Theme.RX

    private var name: String {
        let trimmed = model.settings.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? String(localized: "app.myAccount") : trimmed
    }

    /// The vCard text: FN is the whole name, N splits the last word off as the family name. The
    /// characters vCard escapes (RFC 6350 3.4) are escaped.
    var card: String {
        let words = name.split(separator: " ").map(String.init)
        let family = words.count > 1 ? words[words.count - 1] : ""
        let given = words.count > 1 ? words.dropLast().joined(separator: " ") : name
        return "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:\(Self.escape(name))\r\n"
            + "N:\(Self.escape(family));\(Self.escape(given));;;\r\nEND:VCARD\r\n"
    }

    private static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: ",", with: "\\,")
            .replacingOccurrences(of: ";", with: "\\;")
            .replacingOccurrences(of: "\n", with: " ")
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: RX.Space.l) {
                RXAvatar(initials: model.initials, photo: model.profileImage, size: 72, ring: false)
                Text(verbatim: name)
                    .rxFont(.title)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .multilineTextAlignment(.center)
                    .dbText(maxLines: 2)
                if let image = PairingQRView.image(card, side: 720) {
                    Image(decorative: image, scale: 3)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 240)
                        .padding(RX.Space.l)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
                        .padding(.vertical, RX.Space.s)
                        .accessibilityLabel(Text("rx.profileQR.code"))
                        .accessibilityIdentifier("rx.profileQR.code")
                }
                Text("rx.profileQR.hint")
                    .rxFont(.callout)
                    .foregroundStyle(RX.Palette.textSecondary.color)
                    .multilineTextAlignment(.center)
                ShareLink(item: card, preview: SharePreview(Text(verbatim: name))) {
                    Label("rx.profileQR.share", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.borderedProminent)
                // ShareLink has no action to observe: count the taps for the haptic.
                .simultaneousGesture(TapGesture().onEnded { shares += 1 })
                .dbHaptic(.selection, trigger: shares)
                .accessibilityIdentifier("rx.profileQR.share")
                Spacer(minLength: 0)
            }
            .padding(.horizontal, RX.Space.xl)
            .padding(.vertical, RX.Space.xl)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .background(RX.Palette.pageBackground.color)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(role: .close) { dismiss() }
                        .accessibilityIdentifier("rx.profileQR.done")
                }
            }
        }
        #if os(iOS)
        .presentationDetents([.large])
        #else
        .frame(minWidth: 380, minHeight: 520)
        #endif
    }
}

extension View {
    /// The pressed look of RX cards and tiles: DesignBridge's 0.97 press on every platform.
    func rxPressable() -> some View {
        rxPress()
    }
}
