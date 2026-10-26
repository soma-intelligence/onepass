import DesignKit
import SwiftUI
import VaultKit

/// The five pages of the settings (spec 6.1): a grouped list on iPhone and iPad, tabs in the Mac
/// `Settings` window.
enum SettingsPage: String, CaseIterable, Identifiable {
    case general, security, sync, vaults, about

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .general: "Général"
        case .security: "Sécurité"
        case .sync: "Sync"
        case .vaults: "Coffres"
        case .about: "À propos"
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape"
        case .security: "lock.shield"
        case .sync: "arrow.triangle.2.circlepath.icloud"
        case .vaults: "square.stack.3d.up"
        case .about: "info.circle"
        }
    }

    var tint: Color {
        switch self {
        case .general: Color(red: 0.36, green: 0.62, blue: 0.86)
        case .security: Color(red: 0.88, green: 0.58, blue: 0.0)
        case .sync: Color(red: 0.13, green: 0.63, blue: 0.42)
        case .vaults: Color(red: 0.49, green: 0.23, blue: 0.93)
        case .about: Color(red: 0.36, green: 0.40, blue: 0.45)
        }
    }

    /// The page's content, without its own navigation container.
    @ViewBuilder var content: some View {
        switch self {
        case .general: GeneralSettings()
        case .security: SecuritySettings()
        case .sync: SyncSettings()
        case .vaults: VaultsSettings()
        case .about: AboutSettings()
        }
    }
}

#if os(iOS)
/// iPhone and iPad (mockup `PhoneSettings`): grouped list of pages, "OK" closes. Later milestones
/// add their pages (Extension Safari, Remplissage auto, Appareils) to this list.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var path: [SettingsPage] = SettingsView.initialPath

    /// Screenshots (Debug): `-OnePassDemoSettingsPage <page>` opens that page.
    private static var initialPath: [SettingsPage] {
        #if DEBUG
        if let name = UserDefaults.standard.string(forKey: "OnePassDemoSettingsPage"),
            let page = SettingsPage(rawValue: name)
        {
            return [page]
        }
        #endif
        return []
    }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                Section {
                    row(.general)
                    row(.security)
                    row(.sync)
                }
                Section {
                    row(.vaults)
                }
                Section {
                    row(.about)
                } footer: {
                    Text("OnePass est open source (GPL-3.0)")
                }
            }
            .navigationTitle("Réglages")
            .navigationBarTitleDisplayMode(.inline)
            .navigationDestination(for: SettingsPage.self) { page in
                page.content
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("OK") { dismiss() }
                        .accessibilityIdentifier("settings.done")
                }
            }
        }
        .simultaneousGesture(TapGesture().onEnded { model.session.noteActivity() })
    }

    private func row(_ page: SettingsPage) -> some View {
        NavigationLink(value: page) {
            Label {
                Text(page.title)
            } icon: {
                Image(systemName: page.symbol)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(page.tint, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            }
        }
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }
}
#endif

#if os(macOS)
/// The Mac `Settings` window (⌘,): one tab per page. Nothing is shown while the vault is locked.
struct MacSettingsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            if model.session.state == .unlocked {
                TabView {
                    ForEach(SettingsPage.allCases) { page in
                        Tab {
                            // A stack per tab, so pushed pages ("Coffres visibles") work.
                            NavigationStack { page.content }
                        } label: {
                            Label {
                                Text(page.title)
                            } icon: {
                                Image(systemName: page.symbol)
                            }
                        }
                        .accessibilityIdentifier("settings.\(page.rawValue)")
                    }
                }
            } else {
                ContentUnavailableView(
                    "Réglages verrouillés", systemImage: "lock",
                    description: Text("Déverrouille OnePass pour ouvrir les réglages."))
            }
        }
        .frame(width: 560, height: 520)
        .simultaneousGesture(TapGesture().onEnded { model.session.noteActivity() })
    }
}
#endif
