#if os(macOS)
import DesignKit
import SwiftUI
import VaultKit

/// The Mac Settings window in the RX look (Penpot "Mac · Settings"), while the switch is on: on the
/// left, the photo banner with the account, its QR button and the Plus card, then "Get more from
/// Plus" with the two perk tiles; on the right, every page of Réglages in menu cards and the red
/// lock row. Rows push the same pages as the classic window; the Plus card pushes the plan page.
struct RXMacSettingsHome: View {
    @Environment(AppModel.self) private var model
    @Binding var path: [SettingsPage]
    @State private var showPlan = RXMacSettingsHome.demoOpens("plan")
    @State private var showProfileQR = RXMacSettingsHome.demoOpens("profileQR")

    private typealias RX = Theme.RX

    /// Screenshots (Debug): `-OnePassDemoRXSettings plan|profileQR`, as on the iPhone.
    private static func demoOpens(_ name: String) -> Bool {
        #if DEBUG
        UserDefaults.standard.string(forKey: "OnePassDemoRXSettings") == name
        #else
        false
        #endif
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
                            Button {
                                model.lock()
                            } label: {
                                RXMenuRow(
                                    Text("Verrouiller OnePass"), systemImage: "lock.fill",
                                    tint: RX.Palette.negative.color, chevron: false)
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
            .navigationDestination(for: SettingsPage.self) { page in
                page.content
                    .scrollContentBackground(.hidden)
                    .navigationTitle(Text(page.title))
            }
            .navigationDestination(isPresented: $showPlan) { RXPlanPage() }
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
                RXAvatar(initials: model.initials, photo: model.profileImage, size: 52)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: name)
                        .rxFont(.title)
                        .foregroundStyle(.white)
                        .lineLimit(1)
                    Text(model.settings.deviceMode == .shared
                         ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                        .rxFont(.callout)
                        .foregroundStyle(.white.opacity(0.72))
                }
                Spacer(minLength: RX.Space.s)
                GlassButton(Text("rx.profileQR.open"), systemImage: "qrcode", onPhoto: true) { showProfileQR = true }
                    .accessibilityIdentifier("rx.settings.profileQR")
            }
            Button {
                showPlan = true
            } label: {
                PlanCard(
                    // swiftlint:disable:next db_unlocalized_string - plan name, the same in every language
                    title: Text(verbatim: "Plus"), subtitle: Text("rx.plan.benefits"), art: Image("rx-plan-lux"),
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
                .overlay(Color.black.opacity(0.2))
                .accessibilityHidden(true)
        }
        .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
    }

    private func menu(_ page: SettingsPage, value: Int? = nil) -> some View {
        NavigationLink(value: page) {
            RXMenuRow(Text(page.title), systemImage: page.symbol, value: value.map { Text($0, format: .number) })
        }
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }
}
#endif
