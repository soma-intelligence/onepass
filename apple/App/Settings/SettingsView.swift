import DesignKit
import SwiftUI
import VaultKit
import os

/// How long Réglages takes to show after the tap that asks for it (Debug builds log it under the
/// `settings` category, so a slow opening can be measured on a large vault).
@MainActor
enum SettingsTiming {
    static let log = Logger(subsystem: "me.somalabs.onepass", category: "settings")
    private static var requestedAt: ContinuousClock.Instant?

    /// The tap on "Réglages".
    static func requested(_ step: String) {
        #if DEBUG
        requestedAt = .now
        log.notice("settings: requested (\(step, privacy: .public))")
        #endif
    }

    /// A step after the tap: logs the time since it.
    static func mark(_ step: String) {
        #if DEBUG
        guard let requestedAt else { return }
        let ms = Int((ContinuousClock.now - requestedAt) / .milliseconds(1))
        log.notice("settings: \(step, privacy: .public) after \(ms, privacy: .public) ms")
        #endif
    }
}

/// The pages of the settings (spec 6.1, plus Remplissage automatique from milestone 3, Appareils
/// from milestone 2b, Travel Mode and, on the Mac, Développeur from milestone 7): a grouped list on
/// iPhone and iPad, tabs in the Mac `Settings` window.
enum SettingsPage: String, CaseIterable, Identifiable {
    case general, security, autofill, sync, accounts, vaults, contacts, family, organisation, devices, travel, crypto,
        developer, about
    #if DEBUG
    case iconCheck
    #endif

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .general: "Général"
        case .security: "Sécurité"
        case .autofill: "Remplissage automatique"
        case .sync: "Sync"
        case .accounts: "accounts.title"
        case .vaults: "Coffres"
        case .contacts: "settings.contacts.title"
        case .family: "settings.family.title"
        case .organisation: "org.title"
        case .devices: "Appareils"
        case .travel: "Travel Mode"
        case .crypto: "crypto.title"
        case .developer: "Développeur"
        case .about: "À propos"
        #if DEBUG
        case .iconCheck: "Icônes à vérifier"
        #endif
        }
    }

    var symbol: String {
        switch self {
        case .general: "gearshape.fill"
        case .security: "lock.shield.fill"
        case .autofill: "key.viewfinder"
        case .sync: "arrow.triangle.2.circlepath.icloud"
        case .accounts: "person.2.fill"
        case .vaults: "lock.rectangle.stack.fill"
        case .contacts: "person.crop.circle.badge.checkmark"
        case .family: "figure.2.and.child.holdinghands"
        case .organisation: "building.2.fill"
        case .devices: "laptopcomputer.and.iphone"
        case .travel: "airplane"
        case .crypto: "bitcoinsign.circle"
        case .developer: "chevron.left.forwardslash.chevron.right"
        case .about: "info.circle"
        #if DEBUG
        case .iconCheck: "photo.badge.checkmark"
        #endif
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
        case .contacts: Color(red: 0.16, green: 0.60, blue: 0.86)
        case .family: Color(red: 0.93, green: 0.36, blue: 0.45)
        case .organisation: Color(red: 0.35, green: 0.34, blue: 0.84)
        case .devices: Color(red: 0.0, green: 0.55, blue: 0.70)
        case .travel: Color(red: 0.0, green: 0.55, blue: 0.75)
        case .crypto: Color(red: 0.95, green: 0.58, blue: 0.10)
        case .developer: Color(red: 0x47 / 255, green: 0x55 / 255, blue: 0x69 / 255)
        case .about: Theme.accent
        #if DEBUG
        case .iconCheck: Color(red: 0x47 / 255, green: 0x55 / 255, blue: 0x69 / 255)
        #endif
        }
    }

    /// The page's drawn tile in Assets (Settings/settings-<page>), chosen in the icon lab. Organisation
    /// has none yet: its symbol on its tint.
    var artwork: String? {
        if self == .organisation { return nil }
        #if DEBUG
        if self == .iconCheck { return nil }
        #endif
        return "settings-\(rawValue)"
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
        case .contacts: ContactsView()
        case .family: FamilyView()
        case .organisation: OrganisationSettings()
        case .devices: DevicesSettings()
        case .travel: TravelSettings()
        case .crypto: CryptoSettingsView()
        case .developer:
            #if os(macOS)
            DeveloperSettingsPage()
            #else
            EmptyView()
            #endif
        case .about: AboutSettings()
        #if DEBUG
        case .iconCheck: IconCheckSettings()
        #endif
        }
    }
}

/// Where Réglages pushes, by value, through the stack's path: a page of `SettingsPage`, or a page
/// outside that list (the plan page; on iPhone Profil, Apple Watch, Agents, Personnaliser
/// l'accueil, the profile QR code and the perk tiles). Each stack draws them with one
/// `navigationDestination(for:)`, so the path holds every pushed page and the demo launch
/// arguments open a page by setting the path.
enum SettingsRoute: Hashable {
    case page(SettingsPage)
    /// RX: the page of the Plus card.
    case plan
    #if os(iOS)
    case profile, homeCards, watch, agents
    /// RX: the profile QR code, pushed in Réglages (the Mac shows it in a sheet).
    case profileQR
    /// RX: the page of a perk tile (`RXPerkCarousel.Perk.id`), zooming out of the tile rather than
    /// out of the row of the same page.
    case perk(String)
    #endif
}

#if os(iOS) || os(visionOS)
/// iPhone, iPad and Vision Pro: Réglages, a sheet opened from the account panel. The account on
/// top (it opens Profil), then the pages in grouped cards, each with its colored tile as in the
/// Mac sidebar, on the app's page color. Labels stay short; a footer only where a choice needs one.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var path: [SettingsRoute] = SettingsView.initialPath
    /// RX (iPhone): the zoom from a row or tile of Réglages into its page.
    @Namespace private var settingsZoom
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    @State private var showsFeatureRequest = false

    /// Screenshots (Debug): `-OnePassDemoSettingsPage <page>` opens that page; in the RX look,
    /// `-OnePassDemoRXSettings plan|profileQR` opens the plan page or the profile QR code.
    private static var initialPath: [SettingsRoute] {
        var path: [SettingsRoute] = []
        #if DEBUG
        let defaults = UserDefaults.standard
        if let name = defaults.string(forKey: "OnePassDemoSettingsPage"), let page = SettingsPage(rawValue: name) {
            path = [.page(page)]
        }
        #if os(iOS)
        let rx = AppModel.browseDefaults.object(forKey: RXDesign.storageKey) as? Bool ?? RXDesign.launchDefault
        switch rx ? defaults.string(forKey: "OnePassDemoRXSettings") : nil {
        case "plan": path.append(.plan)
        case "profileQR": path.append(.profileQR)
        default: break
        }
        #endif
        #endif
        return path
    }

    var body: some View {
        NavigationStack(path: $path) {
            root
                // The one destination of the stack: every row, tile and card pushes by value.
                .navigationDestination(for: SettingsRoute.self) { route in
                    destination(route)
                        #if os(iOS)
                        // The pushed page needs the namespace too, or its zoom has no source.
                        .environment(\.itemZoomNamespace, rxDesign ? settingsZoom : nil)
                        #endif
                }
                #if os(iOS)
                // RX: rows, perk tiles and the plan card zoom into the page they open; the classic
                // list has no namespace, so its pages push as usual.
                .environment(\.itemZoomNamespace, rxDesign ? settingsZoom : nil)
                #endif
        }
        #if os(iOS)
        // RX: Réglages are a full screen cover, which has no drag to dismiss; every frosted page
        // closes them when pulled down past its top (RXPullDownToDismiss).
        .environment(\.rxPullDownDismiss, rxDesign ? { dismiss() } : nil)
        #endif
        // Not a tap gesture on the stack or the pages: on iOS 27 it swallows the taps of the
        // navigation rows and pickers below it. Opening or leaving a page counts as activity.
        .onChange(of: path) { model.session.noteActivity() }
        .onAppear {
            SettingsTiming.mark("shown")
            // A page asked by another screen (Profil > Synchronisation, Sécurité): opened on top.
            if let request = model.settingsPageRequest {
                model.settingsPageRequest = nil
                path = [.page(request)]
            }
        }
    }

    /// The classic grouped list (the RX look off).
    private var classicList: some View {
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
                row(.contacts)
                row(.family)
                row(.organisation)
                row(.devices)
                row(.travel)
                row(.crypto)
                #if os(iOS)
                watchRow
                agentsRow
                #endif
            }
            Section {
                row(.about)
                featureRequestRow
                #if DEBUG
                row(.iconCheck)
                #endif
            } footer: {
                Text("settings.onepassOpenSourceAgpl")
                    .frame(maxWidth: .infinity)
                    .padding(.top, Theme.Space.s)
            }
        }
        .settingsPage("Réglages")
        .toolbar { doneItem }
        .sheet(isPresented: $showsFeatureRequest) { FeatureRequestSheet() }
    }

    /// "Suggérer une fonctionnalité": a sheet over Réglages, the row drawn like the others.
    private var featureRequestRow: some View {
        Button {
            showsFeatureRequest = true
        } label: {
            SettingsRowLabel(title: Text("featureRequest.title", tableName: FeatureRequestSheet.table),
                             symbol: "lightbulb.fill", color: SettingsTint.featureRequest)
                .foregroundStyle(.primary)
        }
        .accessibilityIdentifier("settings.featureRequest")
    }

    /// The root: the RX Réglages while the look is on (iPhone), else the classic list.
    @ViewBuilder private var root: some View {
        #if os(iOS)
        if rxDesign {
            RXSettingsHome()
        } else {
            classicList
        }
        #else
        classicList
        #endif
    }

    /// The page of a route. "OK" on every page of `SettingsPage`: opened straight on one, it still
    /// closes the sheet. In the RX look each page zooms out of the row, tile or card that opened it
    /// (nothing without the namespace, so the classic list pushes as usual).
    @ViewBuilder private func destination(_ route: SettingsRoute) -> some View {
        switch route {
        case .page(let page):
            #if os(iOS)
            page.content
                .toolbar { doneItem }
                .zoomDestination(page)
            #else
            page.content
                .toolbar { doneItem }
            #endif
        case .plan:
            #if os(iOS)
            RXPlanPage().zoomDestination(RXSettingsHome.planZoomID)
            #else
            RXPlanPage()
            #endif
        #if os(iOS)
        case .profile:
            ProfileSettings().zoomDestination("settings.account")
        case .homeCards:
            RXHomeCardsSettings().zoomDestination("rx.settings.homeCards")
        case .watch:
            WatchSettings().zoomDestination("settings.watch")
        case .agents:
            AgentsSettings().zoomDestination("settings.agents")
        case .profileQR:
            RXProfileQRPage().zoomDestination(RXSettingsHome.profileQRZoomID)
        case .perk(let id):
            if let perk = RXPerkCarousel.perks.first(where: { $0.id == id }) {
                perk.page.content
                    .zoomDestination("perk.\(perk.id)")
            }
        #endif
        }
    }

    /// The system close button of the sheet, on the root and on every page (the same role and
    /// identifier as the RX root's).
    private var doneItem: some ToolbarContent {
        ToolbarItem(placement: .topBarTrailing) {
            // Monochrome in the frosted Réglages, as on the root.
            Button(role: .close) { dismiss() }
                .tint(rxDesign ? Theme.RX.Palette.textPrimary.color : nil)
                .accessibilityIdentifier("settings.done")
        }
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
        NavigationLink(value: SettingsRoute.page(page)) {
            SettingsRowLabel(title: page.title, symbol: page.symbol, color: page.tint, artwork: page.artwork)
        }
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }
}

/// The account at the top of Réglages: the photo or initials, the name, the kind of device.
private struct SettingsAccountHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let _ = model.settingsRevision
        HStack(spacing: Theme.Space.l) {
            AccountAvatar(initials: model.initials, photo: model.profileImage, size: 56)
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName)
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Text(model.settings.deviceMode == .shared
                     ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel"))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, Theme.Space.s)
        .accessibilityElement(children: .combine)
    }
}

/// A settings row: the colored tile of the Mac sidebar and the page's name.
struct SettingsRowLabel: View {
    let title: Text
    let symbol: String
    let color: Color
    /// A drawn tile from Assets, in place of the symbol on its tint.
    var artwork: String? = nil

    init(title: LocalizedStringKey, symbol: String, color: Color, artwork: String? = nil) {
        self.init(title: Text(title), symbol: symbol, color: color, artwork: artwork)
    }

    init(title: Text, symbol: String, color: Color, artwork: String? = nil) {
        self.title = title
        self.symbol = symbol
        self.color = color
        self.artwork = artwork
    }

    var body: some View {
        Label {
            title
        } icon: {
            if let artwork {
                Image(artwork)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 29, height: 29)
                    .accessibilityHidden(true)
            } else {
                SymbolTile(symbol: symbol, color: color, size: 29)
            }
        }
    }
}

/// Tiles of the iOS-only rows (the pages' own tints live on `SettingsPage`).
enum SettingsTint {
    static let watch = Color(red: 0.20, green: 0.52, blue: 0.80)
    static let agents = Color(red: 0.55, green: 0.30, blue: 0.85)
    static let featureRequest = Color(red: 0.96, green: 0.65, blue: 0.0)
}
#endif

extension View {
    /// Every settings page, iPhone, iPad and Mac: grouped cards and the page's title. iPhone and
    /// iPad: an inline title over the app's page color, content fading under the bar with the
    /// shared header fade.
    func settingsPage(_ title: LocalizedStringKey) -> some View {
        modifier(SettingsFormStyle())
            .navigationTitle(title)
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            #if os(iOS)
            .scrollContentBackground(.hidden)
            .modifier(ClassicSettingsBackground())
            // Buttons and values in the accent keep 4.5:1 on the dark cards too.
            .tint(Theme.readableAccent)
            .headerFade()
            #endif
    }
}

/// The grouped form everywhere, except inside the Réglages page of the Mac main window (RX look),
/// where the form draws as RX cards (`RXMacFormStyle`).
private struct SettingsFormStyle: ViewModifier {
    #if os(macOS)
    @Environment(\.rxMacSettingsPage) private var inRXPage
    @Environment(\.rxMacSettingsDepth) private var depth
    @Environment(\.dismiss) private var dismiss
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    /// Pushed over another settings form of the popup: a back button above the cards.
    @State private var pushed = false
    #endif

    func body(content: Content) -> some View {
        #if os(macOS)
        if inRXPage, rxDesign {
            content
                .formStyle(RXMacFormStyle())
                .environment(\.rxSettings, true)
                .safeAreaInset(edge: .top, spacing: 0) {
                    if pushed { RXMacSettingsBackBar { dismiss() } }
                }
                .onAppear {
                    guard let depth else { return }
                    pushed = depth.current > 0
                    depth.appeared()
                }
                .onDisappear { depth?.disappeared() }
        } else {
            content.formStyle(.grouped)
        }
        #else
        content.formStyle(.grouped)
        #endif
    }
}

#if os(iOS)
/// The background of a settings page: the page colour, or in the RX look the screen under
/// Réglages blurred (RXFrostedBackdrop), with no colour from the navigation stack.
private struct ClassicSettingsBackground: ViewModifier {
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault

    func body(content: Content) -> some View {
        if rxDesign {
            content
                .modifier(RXPullDownToDismiss())
                .background(RXFrostedBackdrop().ignoresSafeArea())
                .containerBackground(Color.clear, for: .navigation)
        } else {
            content.background(Theme.page.ignoresSafeArea())
        }
    }
}
#endif

#if os(macOS)
/// The Mac `Settings` window (⌘,): pages in a sidebar of colored tiles, the page on the right.
/// Nothing is shown while the vault is locked.
struct MacSettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var page: SettingsPage? = .general
    @AppStorage(RXDesign.storageKey, store: AppModel.browseDefaults) private var rxDesign = RXDesign.launchDefault
    @State private var showsFeatureRequest = false

    var body: some View {
        Group {
            if model.session.state == .unlocked, rxDesign {
                // The RX look opens Réglages in the main window: this window hands over and closes.
                RXSettingsWindowRedirect()
            } else if model.session.state == .unlocked {
                NavigationSplitView {
                    List(selection: $page) {
                        Section {
                            ForEach([SettingsPage.general, .security, .autofill, .sync], id: \.self) { row($0) }
                        }
                        Section {
                            row(.accounts)
                            row(.vaults)
                            row(.contacts)
                            row(.family)
                            row(.organisation)
                            row(.devices)
                            row(.travel)
                            row(.crypto)
                            row(.developer)
                        }
                        Section {
                            row(.about)
                            #if DEBUG
                            row(.iconCheck)
                            #endif
                            featureRequestRow
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
                    description: Text("settings.unlockOnepassToOpen"))
            }
        }
        .frame(minWidth: 760, idealWidth: 820, minHeight: 540, idealHeight: 600)
        .containerBackground(.thinMaterial, for: .window)
        .onAppear(perform: takeRequest)
        .onChange(of: model.settingsPageRequest) { takeRequest() }
        .simultaneousGesture(TapGesture().onEnded { model.session.noteActivity() })
        .sheet(isPresented: $showsFeatureRequest) { FeatureRequestSheet() }
    }

    /// "Suggérer une fonctionnalité": opens its sheet, nothing selected (the sidebar rows' look).
    private var featureRequestRow: some View {
        Button {
            showsFeatureRequest = true
        } label: {
            Label {
                Text("featureRequest.title", tableName: FeatureRequestSheet.table)
            } icon: {
                Image(systemName: "lightbulb.fill")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 26, height: 26)
                    .background(Color(red: 0.96, green: 0.65, blue: 0.0),
                                in: RoundedRectangle(cornerRadius: Theme.Radius.chip, style: .continuous))
                    .accessibilityHidden(true)
            }
            .padding(.vertical, 3)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("settings.featureRequest")
    }

    /// A page asked by another screen (Développeur page cards).
    private func takeRequest() {
        guard let request = model.settingsPageRequest else { return }
        // The RX page takes the request itself.
        guard !rxDesign else { return }
        page = request
        model.settingsPageRequest = nil
    }

    /// A sidebar row: the page's colored tile and its name.
    private func row(_ page: SettingsPage) -> some View {
        Label {
            Text(page.title)
        } icon: {
            if let artwork = page.artwork {
                Image(artwork)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 26, height: 26)
            } else {
                Image(systemName: page.symbol)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 26, height: 26)
                    .background(page.tint, in: RoundedRectangle(cornerRadius: Theme.Radius.chip, style: .continuous))
            }
        }
        .padding(.vertical, 3)
        .tag(page)
        .accessibilityIdentifier("settings.\(page.rawValue)")
    }
}
#endif
