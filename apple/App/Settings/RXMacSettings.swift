#if os(macOS)
import DesignBridgeKit
import DesignKit
import SwiftUI
import VaultKit

/// The Mac Settings window in the RX look (Penpot "Mac · Settings"), while the switch is on: on the
/// left, the photo banner with the account, its QR button and the Plus card, then "Get more from
/// Plus" with the perk tiles; on the right, every page of Réglages in menu cards and the lock
/// row. Rows push the same pages as the classic window; the Plus card pushes the plan page. Every
/// push is by value (`SettingsRoute`) through `path`, drawn by the stack's one
/// `navigationDestination(for:)`; the profile QR code is a sheet.
struct RXMacSettingsHome: View {
    @Environment(AppModel.self) private var model
    @Binding var path: [SettingsRoute]
    @State private var showProfileQR = RXMacSettingsHome.demoOpens("profileQR")
    @Environment(\.colorSchemeContrast) private var contrast
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private typealias RX = Theme.RX

    /// Screenshots (Debug): `-OnePassDemoRXSettings plan|profileQR`, as on the iPhone.
    private static func demoOpens(_ name: String) -> Bool {
        #if DEBUG
        UserDefaults.standard.string(forKey: "OnePassDemoRXSettings") == name
        #else
        false
        #endif
    }

    /// The pushed pages the window opens on: the plan page for `-OnePassDemoRXSettings plan`.
    static var initialPath: [SettingsRoute] {
        demoOpens("plan") ? [.plan] : []
    }

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                HStack(alignment: .top, spacing: RX.Space.l) {
                    VStack(alignment: .leading, spacing: RX.Space.l) {
                        banner
                        RXSectionTitle(Text("rx.perks.title"))
                        RXPerkCarousel()
                    }
                    .frame(maxWidth: .infinity)
                    VStack(spacing: RX.Space.l) {
                        RXCard {
                            menu(.general)
                            menu(.security)
                            menu(.autofill)
                            menu(.sync)
                            menu(.devices, value: model.session.devices.isEmpty ? nil : model.session.devices.count)
                        }
                        RXCard {
                            menu(.accounts)
                            menu(.vaults, value: model.session.vaults.count)
                            menu(.contacts)
                            menu(.family)
                            menu(.organisation)
                            menu(.travel)
                            menu(.crypto)
                            menu(.developer)
                        }
                        RXCard {
                            menu(.about)
                            #if DEBUG
                            menu(.iconCheck)
                            #endif
                        }
                        RXCard {
                            // The account menu's words; through `perform`, which asks first when
                            // an edit is not saved.
                            Button {
                                model.perform(.lock)
                            } label: {
                                RXMenuRow(Text("Verrouiller"), systemImage: "lock.fill", chevron: false)
                            }
                            .accessibilityIdentifier("rx.settings.lock")
                        }
                    }
                    .buttonStyle(.plain)
                    .frame(maxWidth: .infinity)
                }
                .padding(RX.Space.xl)
                .frame(maxWidth: 900)
                .frame(maxWidth: .infinity)
            }
            .background(RX.Palette.pageBackground.color)
            .environment(\.rxCards, true)
            .navigationTitle(Text("Réglages"))
            .navigationDestination(for: SettingsRoute.self) { route in
                switch route {
                case .page(let page):
                    page.content
                        .scrollContentBackground(.hidden)
                        .navigationTitle(Text(page.title))
                case .plan:
                    RXPlanPage()
                }
            }
        }
        .sheet(isPresented: $showProfileQR) { RXProfileQRSheet() }
        .accessibilityIdentifier("rx.settings")
    }

    /// The photo banner: the account with its QR button, then the Plus card.
    private var banner: some View {
        let _ = model.settingsRevision
        let name = model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName
        return VStack(alignment: .leading, spacing: RX.Space.l) {
            HStack(spacing: RX.Space.m) {
                RXAvatar(initials: model.initials, photo: model.profileImage, size: RX.Metrics.avatarMedium)
                VStack(alignment: .leading, spacing: RX.Space.xxs) {
                    Text(verbatim: name)
                        .rxFont(.title)
                        .foregroundStyle(.white)
                        .dbText(maxLines: 2)
                    Text(model.settings.deviceMode == .shared
                         ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                        .rxFont(.callout)
                        .foregroundStyle(.white)
                        .rxOnPhotoSecondary()
                }
                Spacer(minLength: RX.Space.s)
                GlassButton(Text("rx.profileQR.open"), systemImage: "qrcode", onPhoto: true) { showProfileQR = true }
                    .accessibilityIdentifier("rx.settings.profileQR")
            }
            NavigationLink(value: SettingsRoute.plan) {
                PlanCard(
                    // swiftlint:disable:next db_unlocalized_string - plan name, the same in every language
                    title: Text(verbatim: "Plus"), subtitle: Text("rx.plan.cardSubtitle"), art: Image("rx-plan-lux"),
                    perks: ["key.fill", "person.3.fill", "airplane", "chevron.right"])
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("rx.settings.plan")
        }
        .padding(RX.Space.l)
        .background {
            Image(RXHero.settings)
                .resizable()
                .scaledToFill()
                .overlay(Color.black.opacity(RX.Veil.banner(flat: Theme.Wash.isFlat(
                    increaseContrast: contrast == .increased, reduceTransparency: reduceTransparency))))
                .accessibilityHidden(true)
        }
        .clipShape(RoundedRectangle(cornerRadius: RX.Radius.pageSheet, style: .continuous))
    }

    private func menu(_ page: SettingsPage, value: Int? = nil) -> some View {
        NavigationLink(value: SettingsRoute.page(page)) {
            RXMenuRow(Text(page.title), systemImage: page.symbol, value: value.map { Text($0, format: .number) })
        }
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }
}
#endif
