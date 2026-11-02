import DesignKit
import SwiftUI
import VaultKit

/// The pages of the settings (spec 6.1, plus Remplissage automatique from milestone 3, Appareils
/// from milestone 2b, Travel Mode and, on the Mac, Développeur from milestone 7): a grouped list on
/// iPhone and iPad, tabs in the Mac `Settings` window.
enum SettingsPage: String, CaseIterable, Identifiable {
    case general, security, autofill, sync, accounts, vaults, devices, travel, developer, about

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .general: "Général"
        case .security: "Sécurité"
        case .autofill: "Remplissage automatique"
        case .sync: "Sync"
        case .accounts: "accounts.title"
        case .vaults: "Coffres"
        case .devices: "Appareils"
        case .travel: "Travel Mode"
        case .developer: "Développeur"
        case .about: "À propos"
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape.fill"
        case .security: "lock.shield.fill"
        case .autofill: "key.viewfinder"
        case .sync: "arrow.triangle.2.circlepath.icloud"
        case .accounts: "person.2.fill"
        case .vaults: "square.stack.3d.up.fill"
        case .devices: "laptopcomputer.and.iphone"
        case .travel: "airplane"
        case .developer: "chevron.left.forwardslash.chevron.right"
        case .about: "info.circle"
        }
    }

    var tint: Color {
        switch self {
        case .general: Color(red: 0.54, green: 0.55, blue: 0.58)
        case .security: Color(red: 0.88, green: 0.58, blue: 0.0)
        case .autofill: Color(red: 0.20, green: 0.47, blue: 0.96)
        case .sync: Color(red: 0.13, green: 0.63, blue: 0.42)
        case .accounts: Color(red: 0.35, green: 0.34, blue: 0.84)
        case .vaults: Color(red: 0.49, green: 0.23, blue: 0.93)
        case .devices: Color(red: 0.0, green: 0.55, blue: 0.70)
        case .travel: Color(red: 0.0, green: 0.55, blue: 0.75)
        case .developer: Color(red: 0x47 / 255, green: 0x55 / 255, blue: 0x69 / 255)
        case .about: Theme.accent
        }
    }

    /// The page's content, without its own navigation container.
    @MainActor @ViewBuilder var content: some View {
        switch self {
        case .general: GeneralSettings()
        case .security: SecuritySettings()
        case .autofill: AutoFillSettings()
        case .sync: SyncSettings()
        case .accounts: AccountsSettings()
        case .vaults: VaultsSettings()
        case .devices: DevicesSettings()
        case .travel: TravelSettings()
        case .developer:
            #if os(macOS)
            DeveloperSettingsPage()
            #else
            EmptyView()
            #endif
        case .about: AboutSettings()
        }
    }
}

#if os(iOS) || os(visionOS)
/// iPhone, iPad and Vision Pro: Réglages, a sheet opened from the account panel. The account on
/// top (it opens Profil), then the pages in grouped cards, each with its colored tile as in the
/// Mac sidebar, on the app's page color. Labels stay short; a footer only where a choice needs one.
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
                    NavigationLink {
                        ProfileSettings()
                    } label: {
                        SettingsAccountHeader()
                    }
                    .accessibilityIdentifier("settings.account")
                }
                Section {
                    row(.general)
                    row(.security)
                    row(.autofill)
                    row(.sync)
                }
                Section {
                    row(.accounts)
                    row(.vaults)
                    row(.devices)
                    row(.travel)
                    #if os(iOS)
                    watchRow
                    agentsRow
                    #endif
                }
                Section {
                    row(.about)
                } footer: {
                    Text("OnePass est open source (AGPL-3.0)")
                        .frame(maxWidth: .infinity)
                        .padding(.top, 8)
                }
            }
            .settingsPage("Réglages")
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
        // Not a tap gesture on the stack or the pages: on iOS 27 it swallows the taps of the
        // navigation rows and pickers below it. Opening or leaving a page counts as activity.
        .onChange(of: path) { model.session.noteActivity() }
    }

    #if os(iOS)
    /// "Apple Watch": iOS only, so not a `SettingsPage` (the Mac window iterates over those).
    /// An iPad has no pairing and the page says so.
    private var watchRow: some View {
        NavigationLink {
            WatchSettings()
        } label: {
            SettingsRowLabel(title: "Apple Watch", symbol: "applewatch", color: SettingsTint.watch)
        }
        .accessibilityIdentifier("settings.watch")
    }

    /// "Agents": the requests of the Mac's agents answered on this iPhone (agent-ready spec 7).
    /// iOS only, like the watch.
    private var agentsRow: some View {
        NavigationLink {
            AgentsSettings()
        } label: {
            SettingsRowLabel(title: "Agents", symbol: "point.3.connected.trianglepath.dotted", color: SettingsTint.agents)
        }
        .accessibilityIdentifier("settings.agents")
    }
    #endif

    private func row(_ page: SettingsPage) -> some View {
        NavigationLink(value: page) {
            SettingsRowLabel(title: page.title, symbol: page.symbol, color: page.tint)
        }
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }
}

/// The account at the top of Réglages: the photo or initials, the name, the kind of device.
private struct SettingsAccountHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let _ = model.settingsRevision
        HStack(spacing: 14) {
            AccountAvatar(initials: model.initials, photo: model.profileImage, size: 56)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Text(model.settings.deviceMode == .shared
                     ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
    }
}

/// A settings row: the colored tile of the Mac sidebar and the page's name.
struct SettingsRowLabel: View {
    let title: LocalizedStringKey
    let symbol: String
    let color: Color

    var body: some View {
        Label {
            Text(title)
        } icon: {
            SymbolTile(symbol: symbol, color: color, size: 29)
        }
    }
}

/// Tiles of the iOS-only rows (the pages' own tints live on `SettingsPage`).
enum SettingsTint {
    static let watch = Color(red: 0.20, green: 0.52, blue: 0.80)
    static let agents = Color(red: 0.55, green: 0.30, blue: 0.85)
}
#endif

extension View {
    /// Every settings page, iPhone, iPad and Mac: grouped cards and the page's title. iPhone and
    /// iPad: an inline title over the app's page color, content fading under the bar with the
    /// shared header fade.
    func settingsPage(_ title: LocalizedStringKey) -> some View {
        formStyle(.grouped)
            .navigationTitle(title)
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            #if os(iOS)
            .scrollContentBackground(.hidden)
            .background(Theme.page.ignoresSafeArea())
            // Buttons and values in the accent keep 4.5:1 on the dark cards too.
            .tint(Theme.readableAccent)
            .headerFade()
            #endif
    }
}

#if os(macOS)
/// The Mac `Settings` window (⌘,): pages in a sidebar of colored tiles, the page on the right.
/// Nothing is shown while the vault is locked.
struct MacSettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var page: SettingsPage? = .general

    var body: some View {
        Group {
            if model.session.state == .unlocked {
                NavigationSplitView {
                    List(selection: $page) {
                        Section {
                            ForEach([SettingsPage.general, .security, .autofill, .sync], id: \.self) { row($0) }
                        }
                        Section {
                            row(.accounts)
                            row(.vaults)
                            row(.devices)
                            row(.travel)
                            row(.developer)
                        }
                        Section {
                            row(.about)
                        }
                    }
                    .listStyle(.sidebar)
                    .navigationSplitViewColumnWidth(min: 250, ideal: 260, max: 300)
                    .toolbar(removing: .sidebarToggle)
                } detail: {
                    // A stack per page, so pushed pages ("Coffres visibles") work.
                    NavigationStack {
                        (page ?? .general).content
                            .scrollContentBackground(.hidden)
                    }
                    .id(page)
                }
                .navigationTitle(page.map { Text($0.title) } ?? Text("Réglages"))
            } else {
                ContentUnavailableView(
                    "Réglages verrouillés", systemImage: "lock",
                    description: Text("Déverrouille OnePass pour ouvrir les réglages."))
            }
        }
        .frame(minWidth: 760, idealWidth: 820, minHeight: 540, idealHeight: 600)
        .containerBackground(.thinMaterial, for: .window)
        .onAppear(perform: takeRequest)
        .onChange(of: model.settingsPageRequest) { takeRequest() }
        .simultaneousGesture(TapGesture().onEnded { model.session.noteActivity() })
    }

    /// A page asked by another screen (Développeur page cards).
    private func takeRequest() {
        guard let request = model.settingsPageRequest else { return }
        page = request
        model.settingsPageRequest = nil
    }

    /// A sidebar row: the page's colored tile and its name.
    private func row(_ page: SettingsPage) -> some View {
        Label {
            Text(page.title)
        } icon: {
            Image(systemName: page.symbol)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 26, height: 26)
                .background(page.tint.gradient, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        }
        .padding(.vertical, 3)
        .tag(page)
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }
}
#endif
