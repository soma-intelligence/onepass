import DesignKit
import SwiftUI
import VaultKit

/// The pages of the settings (spec 6.1, plus Remplissage automatique from milestone 3, Appareils
/// from milestone 2b, Travel Mode and, on the Mac, Développeur from milestone 7): a grouped list on
/// iPhone and iPad, tabs in the Mac `Settings` window.
enum SettingsPage: String, CaseIterable, Identifiable {
    case general, security, autofill, sync, vaults, devices, travel, developer, about

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .general: "Général"
        case .security: "Sécurité"
        case .autofill: "Remplissage automatique"
        case .sync: "Sync"
        case .vaults: "Coffres"
        case .devices: "Appareils"
        case .travel: "Travel Mode"
        case .developer: "Développeur"
        case .about: "À propos"
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape"
        case .security: "lock.shield"
        case .autofill: "key.viewfinder"
        case .sync: "arrow.triangle.2.circlepath.icloud"
        case .vaults: "square.stack.3d.up"
        case .devices: "laptopcomputer.and.iphone"
        case .travel: "airplane"
        case .developer: "chevron.left.forwardslash.chevron.right"
        case .about: "info.circle"
        }
    }

    var tint: Color {
        switch self {
        case .general: Color(red: 0.36, green: 0.62, blue: 0.86)
        case .security: Color(red: 0.88, green: 0.58, blue: 0.0)
        case .autofill: Color(red: 0.20, green: 0.47, blue: 0.96)
        case .sync: Color(red: 0.13, green: 0.63, blue: 0.42)
        case .vaults: Color(red: 0.49, green: 0.23, blue: 0.93)
        case .devices: Color(red: 0.0, green: 0.55, blue: 0.70)
        case .travel: Color(red: 0.0, green: 0.55, blue: 0.75)
        case .developer: Color(red: 0x47 / 255, green: 0x55 / 255, blue: 0x69 / 255)
        case .about: Color(red: 0.36, green: 0.40, blue: 0.45)
        }
    }

    /// The page's content, without its own navigation container.
    @MainActor @ViewBuilder var content: some View {
        switch self {
        case .general: GeneralSettings()
        case .security: SecuritySettings()
        case .autofill: AutoFillSettings()
        case .sync: SyncSettings()
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
/// iPhone, iPad and Vision Pro (mockup `PhoneSettings`): grouped list of pages, "OK" closes. Later milestones
/// add their pages (Extension Safari, Remplissage auto, Appareils) to this list. On iPhone it is the
/// Réglages tab (`inTab`): the account on top, as in the Mac account popover, "Verrouiller" at the
/// bottom, no "OK".
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var path: [SettingsPage] = SettingsView.initialPath
    @State private var creatingVault = false
    var inTab = false

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
                if inTab {
                    accountSection
                }
                Section {
                    row(.general)
                    row(.security)
                    row(.autofill)
                    row(.sync)
                }
                Section {
                    row(.vaults)
                    row(.devices)
                    row(.travel)
                    #if os(iOS)
                    watchRow
                    #endif
                }
                Section {
                    row(.about)
                } footer: {
                    if !inTab { Text("OnePass est open source (AGPL-3.0)") }
                }
                if inTab {
                    Section {
                        Button(role: .destructive) {
                            model.perform(.lock)
                        } label: {
                            Label {
                                Text("Verrouiller").foregroundStyle(.red)
                            } icon: {
                                tile("lock.fill", .red)
                            }
                        }
                        .accessibilityIdentifier("settings.lock")
                    } footer: {
                        Text("OnePass est open source (AGPL-3.0)")
                    }
                }
            }
            .navigationTitle("Réglages")
            .navigationBarTitleDisplayMode(inTab ? .large : .inline)
            .navigationDestination(for: SettingsPage.self) { page in
                page.content
            }
            .toolbar {
                if !inTab {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("OK") { dismiss() }
                            .accessibilityIdentifier("settings.done")
                    }
                }
            }
            .sheet(isPresented: $creatingVault) {
                VaultEditorView(vault: nil) { creatingVault = false }
            }
        }
        // Not a tap gesture on the stack or the pages: on iOS 27 it swallows the taps of the
        // navigation rows and pickers below it. Opening or leaving a page counts as activity.
        .onChange(of: path) { model.session.noteActivity() }
    }

    /// The Réglages tab: who is signed in and on which kind of device, then the account actions.
    @ViewBuilder private var accountSection: some View {
        let name = model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName
        Section {
            HStack(spacing: 14) {
                AccountAvatar(initials: model.initials, size: 52)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).font(.title3.weight(.semibold)).lineLimit(1)
                    Text(model.settings.deviceMode == .shared
                         ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 4)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("settings.account")
            Button {
                creatingVault = true
            } label: {
                Label { Text("Nouveau coffre…").foregroundStyle(.primary) } icon: {
                    tile("plus.rectangle.on.rectangle", Theme.accent)
                }
            }
            .accessibilityIdentifier("settings.newVault")
            Button {
                model.showImport = true
            } label: {
                Label { Text("Importer…").foregroundStyle(.primary) } icon: {
                    tile("square.and.arrow.down", Color(red: 0.13, green: 0.63, blue: 0.42))
                }
            }
            .accessibilityIdentifier("settings.import")
        }
    }

    /// The colored tile of a row, as in the Mac settings sidebar.
    private func tile(_ symbol: String, _ color: Color) -> some View {
        Image(systemName: symbol)
            .font(.system(size: 14, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 28, height: 28)
            .background(color.gradient, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
    }

    #if os(iOS)
    /// "Apple Watch": iOS only, so not a `SettingsPage` (the Mac window iterates over those).
    /// An iPad has no pairing and the page says so.
    private var watchRow: some View {
        NavigationLink {
            WatchSettings()
        } label: {
            Label {
                Text("Apple Watch")
            } icon: {
                Image(systemName: "applewatch")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(
                        Color(red: 0.20, green: 0.52, blue: 0.80).gradient,
                        in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            }
        }
        .accessibilityIdentifier("settings.watch")
    }
    #endif

    private func row(_ page: SettingsPage) -> some View {
        NavigationLink(value: page) {
            Label {
                Text(page.title)
            } icon: {
                Image(systemName: page.symbol)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 28, height: 28)
                    .background(page.tint.gradient, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            }
        }
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }
}
#endif

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
