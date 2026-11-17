import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

#if os(iOS)

/// Réglages in the RX look, frosted (spec 2026-11-17-settings-frosted-design): the wallpaper blurred
/// behind the page, the account big in the middle (the line under it opens the profile QR), the
/// Plus plan card, then every page of Réglages in frosted cards. Each row pushes the same page as
/// the classic list (`SettingsPage`), so nothing is lost. Every pushed page zooms out of its row.
///
/// Every row and card pushes by value (`SettingsRoute`) through the path of the stack in
/// `SettingsView`, which draws them with its one `navigationDestination(for:)`: the back button's
/// menu and the demo launch arguments see every page.
struct RXSettingsHome: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme

    private typealias RX = Theme.RX

    var body: some View {
        let _ = model.settingsRevision
        RXFrostedPage {
            RXAvatar(initials: model.initials, photo: model.profileImage, size: RXFrost.compactAvatar, ring: false)
        } header: {
            header
        } content: {
            // The plan card opens its page and scrolls with the rest.
            NavigationLink(value: SettingsRoute.plan) {
                PlanCard(
                    // swiftlint:disable:next db_unlocalized_string - plan name, the same in every language
                    title: Text(verbatim: "Plus"), subtitle: Text("rx.plan.cardSubtitle"), art: Image("rx-plan-lux"),
                    perks: ["key.fill", "person.3.fill", "airplane", "chevron.right"],
                    frosted: true)
            }
            .rxPress(haptic: .selection)
            .zoomSource(Self.planZoomID)
            .accessibilityIdentifier("rx.settings.plan")
            RXFrostedCard {
                menu(.general)
                pushRow(Text("rx.settings.homeCards"), systemImage: "house.fill", id: "rx.settings.homeCards",
                        route: .homeCards)
                menu(.security)
                menu(.autofill)
                menu(.sync)
            }
            RXFrostedCard {
                menu(.accounts)
                menu(.vaults, value: model.session.vaults.count)
                menu(.contacts)
                menu(.family)
                menu(.organisation)
                menu(.devices, value: model.session.devices.isEmpty ? nil : model.session.devices.count)
                menu(.travel)
                menu(.crypto)
                // swiftlint:disable:next db_unlocalized_string - product name, the same in every language
                pushRow(Text(verbatim: "Apple Watch"), systemImage: "applewatch", id: "settings.watch", route: .watch)
                // swiftlint:disable:next db_unlocalized_string - feature name, the same in every language
                pushRow(Text(verbatim: "Agents"), systemImage: "point.3.connected.trianglepath.dotted",
                        id: "settings.agents", route: .agents)
            }
            RXFrostedCard {
                menu(.about)
                #if DEBUG
                menu(.iconCheck)
                #endif
            }
            RXFrostedCard {
                // The same words as the account menu; not destructive (nothing is lost), and
                // through `perform`, which asks first when an edit is not saved.
                Button {
                    dismiss()
                    model.perform(.lock)
                } label: {
                    RXFrostedRow(Text("Verrouiller"), systemImage: "lock.fill")
                }
                .accessibilityIdentifier("rx.settings.lock")
            }
            RXFrostedFooter([
                // swiftlint:disable:next db_unlocalized_string - product name and version number
                Text(verbatim: "OnePass \(Self.version)"),
                Text("settings.onepassOpenSourceAgpl"),
            ])
        }
        .rxPress(haptic: .selection)
        .toolbarColorScheme(colorScheme, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button(role: .close) { dismiss() }
                    .tint(RX.Palette.textPrimary.color)
                    .accessibilityIdentifier("settings.done")
            }
        }
        .accessibilityIdentifier("rx.settings")
    }

    static let planZoomID = "rx.plan"
    static let profileQRZoomID = "rx.profileQR"

    /// The account: the avatar and the name open the profile, the line under them opens the
    /// profile QR (the device mode, with a small QR glyph).
    private var header: some View {
        VStack(spacing: 0) {
            NavigationLink(value: SettingsRoute.profile) {
                RXFrostedProfileName(Text(verbatim: model.settings.displayName.isEmpty
                                          ? String(localized: "app.myAccount") : model.settings.displayName)) {
                    RXAvatar(initials: model.initials, photo: model.profileImage, size: RXFrost.avatar)
                }
            }
            .rxPress(haptic: .selection)
            .zoomSource("settings.account")
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("settings.account")
            NavigationLink(value: SettingsRoute.profileQR) {
                RXFrostedProfileDetail(
                    Text(model.settings.deviceMode == .shared ? "Appareil partagé" : "Appareil personnel"),
                    systemImage: "qrcode")
            }
            .buttonStyle(.plain)
            .zoomSource(Self.profileQRZoomID)
            .accessibilityLabel(Text("rx.profileQR.open"))
            .accessibilityIdentifier("rx.settings.profileQR")
        }
    }

    private func menu(_ page: SettingsPage, value: Int? = nil) -> some View {
        NavigationLink(value: SettingsRoute.page(page)) {
            RXFrostedRow(Text(page.title), systemImage: page.symbol, value: value.map { Text($0, format: .number) })
        }
        .zoomSource(page)
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }

    /// A row that pushes a page outside `SettingsPage`, zooming out of the row like the others (the
    /// destination zooms from `id`).
    private func pushRow(_ title: Text, systemImage: String, id: String, route: SettingsRoute) -> some View {
        NavigationLink(value: route) {
            RXFrostedRow(title, systemImage: systemImage)
        }
        .zoomSource(id)
        .accessibilityIdentifier(id)
    }

    private static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }
}

/// The background of a pushed page of the frosted Réglages: the screen under the sheet, blurred.
struct RXSettingsBackdrop: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(RXFrostedBackdrop().ignoresSafeArea())
            .containerBackground(Color.clear, for: .navigation)
    }
}

/// The keys of the Home cards picked in Réglages > Personnaliser l'accueil, in the browse defaults
/// (the same keys and defaults as `HomeTab`, which reads them).
enum HomeCardKeys {
    static let nearby = "onepass.home.showsNearbyCard"
    static let profile = "onepass.home.showsProfile"
    static let frequent = "onepass.home.showsFrequent"
    static let crypto = "onepass.home.showsCrypto"
}

/// Réglages > Personnaliser l'accueil (RX): the cards the RX Home shows under its own sections. The
/// RX Home has no navigation bar, so the options menu of the classic Home is here. Favoris and
/// Récemment utilisés are part of the RX Home itself, so they are not listed.
struct RXHomeCardsSettings: View {
    @AppStorage(HomeCardKeys.nearby, store: AppModel.browseDefaults) private var showsNearby = false
    @AppStorage(HomeCardKeys.profile, store: AppModel.browseDefaults) private var showsProfile = true
    @AppStorage(HomeCardKeys.frequent, store: AppModel.browseDefaults) private var showsFrequent = true
    @AppStorage(HomeCardKeys.crypto, store: AppModel.browseDefaults) private var showsCrypto = true

    private typealias RX = Theme.RX

    var body: some View {
        ScrollView {
            RXFrostedCard {
                RXCardHeader(Text("browse.showOnHome"))
                toggle("À proximité", systemImage: "location.fill", isOn: $showsNearby, id: "nearby")
                toggle("Profil", systemImage: "person.crop.circle.fill", isOn: $showsProfile, id: "profile")
                toggle("home.frequentlyUsed", systemImage: "chart.bar.fill", isOn: $showsFrequent, id: "frequent")
                toggle("crypto.title", systemImage: "bitcoinsign.circle.fill", isOn: $showsCrypto, id: "crypto")
            }
            .padding(RX.Space.gutter)
        }
        .modifier(RXSettingsBackdrop())
        .navigationTitle(Text("rx.settings.homeCards"))
        .navigationBarTitleDisplayMode(.inline)
        .accessibilityIdentifier("rx.homeCards")
    }

    private func toggle(_ title: LocalizedStringKey, systemImage: String, isOn: Binding<Bool>, id: String) -> some View {
        Toggle(isOn: isOn) {
            HStack(spacing: RX.Space.l) {
                Image(systemName: systemImage)
                    .font(RX.Glyph.font(RX.Glyph.menu, weight: .medium))
                    .frame(width: RX.Metrics.menuGlyph, height: RX.Metrics.menuGlyph)
                    .accessibilityHidden(true)
                Text(title)
                    .rxFont(.bodyMedium)
                    .dbText(maxLines: 2)
            }
            .foregroundStyle(RX.Palette.textPrimary.color)
        }
        .tint(RX.Palette.accent.color)
        .padding(.horizontal, RX.Space.l)
        .padding(.vertical, RX.Space.m)
        .frame(minHeight: RX.Metrics.menuPitch)
        .accessibilityIdentifier("rx.homeCards.\(id)")
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
    /// The tile widens with the text size (up to a maximum), so its glyph and title are never cut.
    @ScaledMetric(relativeTo: .headline) private var tileWidth = Theme.RX.Metrics.perkCarouselTileWidth

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
                .frame(width: min(tileWidth, RX.Metrics.perkCarouselTileMaxWidth))
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

    /// iPhone: the page zooms out of its tile (its own route). The Mac pushes the page itself, as
    /// its rows do.
    @ViewBuilder private func link(_ perk: Perk) -> some View {
        #if os(iOS)
        NavigationLink(value: SettingsRoute.perk(perk.id)) {
            tile(perk)
        }
        .zoomSource("perk.\(perk.id)")
        #else
        NavigationLink(value: SettingsRoute.page(perk.page)) {
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
/// photo, the perk carousel, then grouped lists). Each line opens the page of Réglages that
/// already holds it. OnePass has no plan or subscription data: every benefit listed is a feature
/// of this build, so nothing here is invented. The system back button stays (long press menu,
/// swipe back) on a clear bar over the photo.
struct RXPlanPage: View {
    @ScaledMetric(relativeTo: .largeTitle) private var planNameSize: CGFloat = 52

    private typealias RX = Theme.RX

    var body: some View {
        RXHeroPage(photo: Image(RXHero.settings)) {
            VStack(alignment: .leading, spacing: RX.Space.xl) {
                // The plan name big and centred, a line under it.
                VStack(spacing: RX.Space.s) {
                    // swiftlint:disable:next db_unlocalized_string - plan name, the same in every language
                    Text(verbatim: "Plus")
                        .font(RX.Typography.display.font(size: planNameSize))
                        .tracking(-1.5)
                        .dbText(maxLines: 1, minimumScale: 0.7)
                    Text("rx.plan.tagline")
                        .rxFont(.callout)
                        .rxOnPhotoSecondary()
                        .multilineTextAlignment(.center)
                }
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.top, RX.Space.s)
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
        .toolbarBackground(.hidden, for: .navigationBar)
        .toolbarColorScheme(.dark, for: .navigationBar)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .accessibilityIdentifier("rx.plan")
    }

    private func benefit(_ page: SettingsPage, _ title: Text) -> some View {
        NavigationLink(value: SettingsRoute.page(page)) {
            RXMenuRow(title, systemImage: page.symbol)
        }
        .accessibilityIdentifier("rx.plan.\(page.rawValue)")
    }
}

/// The QR button of Réglages: the account as a contact card (vCard 3.0 with the display name
/// only), drawn as a QR code on the device with CoreImage. Nothing leaves the device until the
/// person shares the card; no server is involved. A page that scrolls, so Partager stays reachable
/// at every text size. The iPhone pushes it inside Réglages; the Mac shows it in a sheet. When the
/// code cannot be drawn, the page says so in its place, offers Réessayer, and Partager still sends
/// the card.
struct RXProfileQRPage: View {
    @Environment(AppModel.self) private var model
    /// Taps on Partager, for its haptic.
    @State private var shares = 0
    /// Taps on Réessayer: each one draws the code again (and plays its haptic).
    @State private var attempts = 0

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

    /// The code of the card, or nil when CoreImage cannot draw it. Debug builds:
    /// `-OnePassDemoQRFail YES` fails the first try, so the fallback and Réessayer can be seen.
    private func code(attempt: Int) -> CGImage? {
        #if DEBUG
        if attempt == 0, UserDefaults.standard.bool(forKey: "OnePassDemoQRFail") { return nil }
        #endif
        return PairingQRView.image(card, side: 720)
    }

    private static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: ",", with: "\\,")
            .replacingOccurrences(of: ";", with: "\\;")
            .replacingOccurrences(of: "\n", with: " ")
    }

    var body: some View {
        ScrollView {
            VStack(spacing: RX.Space.l) {
                RXAvatar(initials: model.initials, photo: model.profileImage, size: RX.Metrics.avatarLarge, ring: false)
                Text(verbatim: name)
                    .rxFont(.title)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .multilineTextAlignment(.center)
                    .dbText(maxLines: 2)
                let image = code(attempt: attempts)
                Group {
                    if let image {
                        // A labelled image, not `Image(decorative:)`: a decorative image is hidden
                        // from accessibility, and a label added afterwards does not bring it back,
                        // so VoiceOver (and the UI tests) never found the drawn code.
                        Image(image, scale: 3, label: Text("rx.profileQR.code"))
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(maxWidth: RX.Metrics.profileQR)
                            .padding(RX.Space.l)
                            .background(Color.white, in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
                            .padding(.vertical, RX.Space.s)
                            .accessibilityElement(children: .ignore)
                            .accessibilityLabel(Text("rx.profileQR.code"))
                            .accessibilityAddTraits(.isImage)
                            .accessibilityIdentifier("rx.profileQR.code")
                        Text("rx.profileQR.hint")
                            .rxFont(.callout)
                            .foregroundStyle(RX.Palette.textSecondary.color)
                            .multilineTextAlignment(.center)
                            .dbText()
                    } else {
                        fallback
                    }
                }
                .dbAnimation(value: image == nil)
                ShareLink(item: card, preview: SharePreview(Text(verbatim: name))) {
                    Label("rx.profileQR.share", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.borderedProminent)
                // ShareLink has no action to observe: count the taps for the haptic.
                .simultaneousGesture(TapGesture().onEnded { shares += 1 })
                .dbHaptic(.selection, trigger: shares)
                .accessibilityIdentifier("rx.profileQR.share")
            }
            .padding(.horizontal, RX.Space.xl)
            .padding(.vertical, RX.Space.xl)
            .frame(maxWidth: .infinity)
        }
        #if os(iOS)
        .modifier(RXSettingsBackdrop())
        #else
        .background(RX.Palette.pageBackground.color.ignoresSafeArea())
        #endif
        .navigationTitle(Text("rx.profileQR.open"))
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .accessibilityIdentifier("rx.profileQR")
    }

    /// In place of the code when it cannot be drawn: what happened, that Partager still works, and
    /// Réessayer. The same square as the code, so Partager does not jump when the code comes back.
    private var fallback: some View {
        VStack(spacing: RX.Space.m) {
            Image(systemName: "qrcode")
                .rxFont(.title)
                .foregroundStyle(RX.Palette.textTertiary.color)
                .accessibilityHidden(true)
            Text("rx.profileQR.failed.title")
                .rxFont(.bodyMedium)
                .foregroundStyle(RX.Palette.textPrimary.color)
                .multilineTextAlignment(.center)
                .dbText()
            Text("rx.profileQR.failed.message")
                .rxFont(.callout)
                .foregroundStyle(RX.Palette.textSecondary.color)
                .multilineTextAlignment(.center)
                .dbText()
            Button {
                attempts += 1
            } label: {
                Label("Réessayer", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.bordered)
            .dbHaptic(.selection, trigger: attempts)
            .accessibilityIdentifier("rx.profileQR.retry")
        }
        .padding(RX.Space.l)
        .frame(maxWidth: RX.Metrics.profileQR + 2 * RX.Space.l, minHeight: RX.Metrics.profileQR + 2 * RX.Space.l)
        .background(RX.Palette.cardBackground.color, in: RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
        .padding(.vertical, RX.Space.s)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("rx.profileQR.fallback")
    }
}

#if os(macOS)
/// The Mac Settings window: the profile QR page in a sheet, with the system close button.
struct RXProfileQRSheet: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            RXProfileQRPage()
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(role: .close) { dismiss() }
                            .accessibilityIdentifier("rx.profileQR.done")
                    }
                }
        }
        .frame(minWidth: 380, minHeight: 520)
    }
}
#endif

extension View {
    /// The pressed look of RX cards and tiles: DesignBridge's 0.97 press on every platform.
    func rxPressable() -> some View {
        rxPress()
    }
}
