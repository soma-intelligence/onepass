#if os(iOS)
import DesignKit
import SwiftUI
import VaultKit

/// Réglages in the RX look (Penpot "iPhone · Settings"): the photo hero with the round close and
/// profile buttons, the account in the middle, the Plus plan card over the photo; then, on the page
/// sheet, "Get more from Plus" with two perk tiles, and every page of Réglages in menu cards. Each
/// row pushes the same page as the classic list (`SettingsPage`), so nothing is lost.
struct RXSettingsHome: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

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
        .accessibilityIdentifier("rx.settings")
    }

    /// The top of the photo: close and profile buttons, the account, the plan card.
    private var hero: some View {
        VStack(spacing: RX.Space.xl) {
            HStack {
                GlassButton(Text("rx.settings.close"), systemImage: "xmark", onPhoto: true) { dismiss() }
                    .accessibilityIdentifier("settings.done")
                Spacer()
                NavigationLink {
                    ProfileSettings()
                } label: {
                    RXGlassGlyph(systemImage: "person.crop.circle", onPhoto: true)
                }
                .buttonStyle(PressableButtonStyle())
                .accessibilityLabel(Text("Profil"))
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
            PlanCard(
                title: Text(verbatim: "Plus"), subtitle: Text("rx.plan.benefits"), art: Image("rx-plan-keys"),
                perks: ["key.fill", "person.3.fill", "airplane", "chevron.right"])
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
#endif
