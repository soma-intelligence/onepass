import DesignKit
import SwiftUI
import VaultKit

#if os(iOS)

/// Réglages in the RX look (Penpot "iPhone · Settings"): the photo hero with the round close and
/// profile buttons, the account in the middle, the Plus plan card over the photo; then, on the page
/// sheet, "Get more from Plus" with two perk tiles, and every page of Réglages in menu cards. Each
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
        RXHeroPage(photo: Image("rx-hero")) {
            hero
        } sheet: {
            VStack(spacing: RX.Space.l) {
                RXSectionTitle(Text("rx.perks.title"))
                HStack(spacing: RX.Space.m) {
                    NavigationLink(value: SettingsPage.family) {
                        PerkTile(
                            title: Text("rx.perks.family.title"), subtitle: Text("rx.perks.family.subtitle"),
                            systemImage: "person.3.fill", art: Image("rx-perk-family"))
                    }
                    .accessibilityIdentifier("rx.settings.perk.family")
                    NavigationLink(value: SettingsPage.travel) {
                        PerkTile(
                            title: Text(SettingsPage.travel.title), subtitle: Text("rx.perks.travel.subtitle"),
                            systemImage: "airplane", art: Image("rx-perk-travel"))
                    }
                    .accessibilityIdentifier("rx.settings.perk.travel")
                }
                .buttonStyle(PressableButtonStyle())
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
                        RXMenuRow(Text(verbatim: "Apple Watch"), systemImage: "applewatch")
                    }
                    .accessibilityIdentifier("settings.watch")
                    NavigationLink {
                        AgentsSettings()
                    } label: {
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
                    Text(verbatim: "OnePass \(Self.version)")
                    Text("settings.onepassOpenSourceAgpl")
                }
                .rxFont(.footnote)
                .foregroundStyle(RX.Palette.textTertiary.color)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.plain)
        }
        .toolbar(.hidden, for: .navigationBar)
        .navigationDestination(isPresented: $showPlan) { RXPlanPage() }
        .sheet(isPresented: $showProfileQR) { RXProfileQRSheet() }
        .accessibilityIdentifier("rx.settings")
    }

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
                VStack(spacing: 6) {
                    RXAvatar(initials: model.initials, photo: model.profileImage, size: 72)
                        .padding(.bottom, RX.Space.xs)
                    Text(model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName)
                        .rxFont(.title)
                        .foregroundStyle(.white)
                        .lineLimit(1)
                    Text(model.settings.deviceMode == .shared
                         ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                        .rxFont(.callout)
                        .foregroundStyle(.white.opacity(0.72))
                }
                .frame(maxWidth: .infinity)
                .padding(.top, RX.Space.xl)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("settings.account")
            Button {
                showPlan = true
            } label: {
                PlanCard(
                    title: Text(verbatim: "Plus"), subtitle: Text("rx.plan.benefits"), art: Image("rx-plan-keys"),
                    perks: ["key.fill", "person.3.fill", "airplane", "chevron.right"])
            }
            .buttonStyle(PressableButtonStyle())
            .accessibilityIdentifier("rx.settings.plan")
            .padding(.top, RX.Space.l)
        }
    }

    private func menu(_ page: SettingsPage, value: Int? = nil) -> some View {
        NavigationLink(value: page) {
            RXMenuRow(Text(page.title), systemImage: page.symbol, value: value.map { Text($0, format: .number) })
        }
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
                Text(initials.isEmpty ? "?" : initials)
                    .font(.system(size: size * 0.38, weight: .bold))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(
                        LinearGradient(
                            colors: [Color(red: 0x8B / 255, green: 0x89 / 255, blue: 0xF0 / 255),
                                     Color(red: 0x4B / 255, green: 0x48 / 255, blue: 0xC9 / 255)],
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
/// The Plus card's page (Penpot "Plan benefits"): the plan card again over the photo, then what it
/// brings, each line opening the page of Réglages that already holds it. OnePass has no plan or
/// subscription data: every benefit listed is a feature of this build, so nothing here is invented.
struct RXPlanPage: View {
    @Environment(\.dismiss) private var dismiss

    private typealias RX = Theme.RX

    var body: some View {
        RXHeroPage(photo: Image("rx-hero")) {
            VStack(alignment: .leading, spacing: RX.Space.xl) {
                GlassButton(Text("rx.plan.back"), systemImage: "chevron.left", onPhoto: true) { dismiss() }
                    .accessibilityIdentifier("rx.plan.back")
                PlanCard(
                    title: Text(verbatim: "Plus"), subtitle: Text("rx.plan.benefits"), art: Image("rx-plan-keys"),
                    perks: ["key.fill", "person.3.fill", "airplane", "shield.lefthalf.filled"])
            }
        } sheet: {
            VStack(spacing: RX.Space.l) {
                RXSectionTitle(Text("rx.perks.title"))
                HStack(spacing: RX.Space.m) {
                    NavigationLink(value: SettingsPage.family) {
                        PerkTile(
                            title: Text("rx.perks.family.title"), subtitle: Text("rx.perks.family.subtitle"),
                            systemImage: "person.3.fill", art: Image("rx-perk-family"))
                    }
                    NavigationLink(value: SettingsPage.travel) {
                        PerkTile(
                            title: Text(SettingsPage.travel.title), subtitle: Text("rx.perks.travel.subtitle"),
                            systemImage: "airplane", art: Image("rx-perk-travel"))
                    }
                }
                .rxPressable()
                RXSectionTitle(Text("rx.plan.included"))
                RXCard {
                    benefit(.vaults, Text("rx.plan.vaults"))
                    benefit(.contacts, Text("rx.plan.sharing"))
                    benefit(.family, Text("rx.plan.family"))
                    benefit(.organisation, Text("rx.plan.organisation"))
                    benefit(.devices, Text("rx.plan.devices"))
                    benefit(.travel, Text("rx.plan.travel"))
                    benefit(.crypto, Text("rx.plan.crypto"))
                }
                .buttonStyle(.plain)
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
            VStack(spacing: RX.Space.xl) {
                RXAvatar(initials: model.initials, photo: model.profileImage, size: 72, ring: false)
                Text(verbatim: name)
                    .rxFont(.title)
                    .foregroundStyle(RX.Palette.textPrimary.color)
                    .lineLimit(1)
                if let image = PairingQRView.image(card, side: 720) {
                    Image(decorative: image, scale: 3)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 240)
                        .clipShape(RoundedRectangle(cornerRadius: RX.Radius.card, style: .continuous))
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
                .accessibilityIdentifier("rx.profileQR.share")
                Spacer(minLength: 0)
            }
            .padding(RX.Space.xl)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(RX.Palette.pageBackground.color)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("OK") { dismiss() }
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
    /// The pressed look of RX cards and tiles: `PressableButtonStyle` on iOS, a plain button on the
    /// Mac (where the style is not built).
    @ViewBuilder func rxPressable() -> some View {
        #if os(iOS)
        buttonStyle(PressableButtonStyle())
        #else
        buttonStyle(.plain)
        #endif
    }
}
