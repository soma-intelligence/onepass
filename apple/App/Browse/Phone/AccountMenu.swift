import DesignKit
import SwiftUI

#if os(iOS)
/// Account button of the iPhone navigation bars: the account's initials on the accent square and a
/// small chevron, as the Mac account header. It opens the account panel.
struct AccountMenu: View {
    @Environment(AppModel.self) private var model
    @Environment(\.pushPhoneRoute) private var push
    @State private var isOpen = false
    /// What the panel asked for: run once the popover is gone, so a sheet never fights it.
    /// "Gone" is the panel's `onDisappear`, at the end of the popover's dismissal: run as soon as
    /// `isOpen` turns false, a sheet of the root (Réglages, Ajouter un compte) was refused by UIKit
    /// ("already presenting" the popover) and only showed up at a later redraw, up to a minute on
    /// device.
    @State private var pending: AccountPanelAction?
    @State private var creatingVault = false

    var body: some View {
        Button {
            isOpen = true
        } label: {
            HStack(spacing: Theme.Space.xs) {
                AccountBadgeAvatar(
                    initials: model.initials, photo: model.profileImage, color: model.accountTint,
                    badge: model.accountBadge, size: 32)
                Image(systemName: "chevron.down")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            .frame(minHeight: 44)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text("browse.accountMenu"))
        .accessibilityIdentifier("account.menu")
        // Anchored at the chevron's end, not the button's middle: the arrow then clears the panel's
        // corner, so the top-left corner keeps the same radius as the other three.
        .popover(isPresented: $isOpen, attachmentAnchor: .point(.trailing), arrowEdge: .top) {
            AccountPanel { action in
                if case .settings = action { SettingsTiming.requested("account panel") }
                pending = action
                // Closed without its fade: the panel's action (a sheet, mostly) follows at once.
                var instant = Transaction()
                instant.disablesAnimations = true
                withTransaction(instant) { isOpen = false }
            }
            .presentationCompactAdaptation(.popover)
            .onDisappear(perform: runPending)
        }
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
        }
        .onChange(of: isOpen) { _, open in
            model.accountPanelsOpen = max(0, model.accountPanelsOpen + (open ? 1 : -1))
        }
        .onDisappear {
            if isOpen { model.accountPanelsOpen = max(0, model.accountPanelsOpen - 1) }
        }
        #if DEBUG
        // Screenshots: `-OnePassDemoAccountPanel YES` opens the panel once the screen is there.
        .task {
            guard UserDefaults.standard.bool(forKey: "OnePassDemoAccountPanel") else { return }
            try? await Task.sleep(for: .milliseconds(600))
            isOpen = true
        }
        #endif
    }

    private func runPending() {
        guard let action = pending else { return }
        pending = nil
        run(action)
    }

    private func run(_ action: AccountPanelAction) {
        switch action {
        case .settings:
            SettingsTiming.mark("popover closed")
            model.showSettings = true
        case .profile: push(.profile)
        case .newVault: creatingVault = true
        case .importItems: model.showImport = true
        case .scanCode: model.showOtpScanner = true
        case .setUpDevice: model.showDeviceSetup = true
        case .lock: model.perform(.lock)
        case .account(let action): model.runAccountAction(action)
        }
    }
}

#endif

/// What a row of the account panel does.
enum AccountPanelAction {
    case settings, newVault, importItems, scanCode, setUpDevice, lock
    /// Profil (spec 2026-11-14-profile-account-security): the account row, or its own row with several
    /// accounts.
    case profile
    /// The accounts section: switch, add, search all, lock all (multi-account spec 7).
    case account(AccountsPanelAction)
}

/// The account panel: a glass popover under the account button (iPhone), the same panel under the
/// sidebar's account row (Mac). The accounts on this device on top (with several, each switches on
/// tap), then the actions, each with its colored tile as in the sidebar, and Verrouiller apart at
/// the bottom. On the Mac each action shows its shortcut, and Configurer un appareil takes the
/// place of Scanner un code (no camera scanner there).
struct AccountPanel: View {
    @Environment(AppModel.self) private var model
    let perform: (AccountPanelAction) -> Void

    #if os(iOS)
    /// iPhone: the cards keep clear of the glass popover's edge, their corners following its curve
    /// (8 pt read as cards pressed against the panel's side).
    static let inset: CGFloat = Theme.Space.m
    static let cardRadius: CGFloat = 24
    #else
    static let inset: CGFloat = Theme.Space.s
    static let cardRadius: CGFloat = Theme.Radius.card
    #endif

    var body: some View {
        let _ = model.settingsRevision
        VStack(alignment: .leading, spacing: 0) {
            accounts
                .padding(.horizontal, Theme.Space.l)
                .padding(.top, Theme.Space.l)
                .padding(.bottom, Theme.Space.m)
            AccountPanelGroup {
                if model.accounts.hasSeveralAccounts {
                    AccountPanelRow(title: "Profil", symbol: "person.crop.circle.fill", color: AccountPanelTint.accounts) {
                        perform(.profile)
                    }
                    .accessibilityIdentifier("account.profile")
                }
                AccountPanelRow(title: "accounts.add", symbol: "person.badge.plus", color: AccountPanelTint.accounts) {
                    perform(.account(.add))
                }
                .accessibilityIdentifier("accounts.add")
                AccountPanelRow(title: "Réglages", symbol: "gearshape.fill", color: AccountPanelTint.settings,
                    shortcut: "⌘,") {
                    perform(.settings)
                }
                .accessibilityIdentifier("account.settings")
                AccountPanelRow(title: "Nouveau coffre", symbol: "square.stack.3d.up.fill", color: Theme.accent) {
                    perform(.newVault)
                }
                .accessibilityIdentifier("account.newVault")
                AccountPanelRow(title: "Importer", symbol: "square.and.arrow.down.fill", color: AccountPanelTint.importItems,
                    shortcut: "⇧⌘I") {
                    perform(.importItems)
                }
                .accessibilityIdentifier("account.import")
                #if os(macOS)
                AccountPanelRow(title: "Configurer un appareil", symbol: "qrcode", color: AccountPanelTint.scan) {
                    perform(.setUpDevice)
                }
                .accessibilityIdentifier("account.setUpDevice")
                #elseif os(iOS)
                // Shown whenever the device can scan: the scanner sheet explains a denied camera.
                if SecretKeyScanner.isDeviceSupported {
                    AccountPanelRow(title: "account.panel.scanCode", symbol: "qrcode.viewfinder", color: AccountPanelTint.scan) {
                        perform(.scanCode)
                    }
                    .accessibilityIdentifier("account.scanOtp")
                }
                #endif
            }
            AccountPanelGroup {
                AccountPanelRow(title: "Verrouiller", symbol: "lock.fill", color: .red, role: .destructive,
                    shortcut: "⌘L") {
                    perform(.lock)
                }
                .accessibilityIdentifier("account.lock")
                if model.accounts.unlockedProfiles.count > 1 {
                    AccountPanelRow(title: "accounts.lockAll", symbol: "lock.fill", color: .red, role: .destructive) {
                        perform(.account(.lockAll))
                    }
                    .accessibilityIdentifier("accounts.lockAll")
                }
            }
            .padding(.top, Theme.Space.s)
        }
        .padding(.horizontal, AccountPanel.inset)
        .padding(.bottom, AccountPanel.inset)
        #if os(macOS)
        // Never wider than the sidebar column (the panel was cut at its edge when it is narrow).
        .frame(maxWidth: 272)
        #else
        .frame(width: 296)
        #endif
    }

    /// The accounts of this device. One: the signed in account, its kind of device. Several: each
    /// with its color and kind, switching on tap, and the search over all of them when chosen.
    @ViewBuilder private var accounts: some View {
        if model.accounts.hasSeveralAccounts {
            AccountsPanelSection(showsAdd: false, showsLockAll: false) { perform(.account($0)) }
                .background(Theme.card.opacity(0.6), in: .rect(cornerRadius: AccountPanel.cardRadius, style: .continuous))
                // Cancels the accounts block's side padding: the card runs to the groups' edges.
                .padding(.horizontal, -Theme.Space.l)
        } else {
            currentAccount
        }
    }

    /// The account and its kind of device: opens the Profil.
    private var currentAccount: some View {
        Button { perform(.profile) } label: {
            currentAccountLabel
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("account.current")
    }

    private var currentAccountLabel: some View {
        HStack(spacing: Theme.Space.m) {
            AccountBadgeAvatar(
                initials: model.initials, photo: model.profileImage, color: model.accountTint,
                badge: model.accountBadge, size: AccountPanelRow.avatarSize)
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(name)
                    .font(.headline)
                    .lineLimit(1)
                Text(device)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            Image(systemName: "chevron.right")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
        }
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
    }

    private var name: String {
        model.settings.displayName.isEmpty ? String(localized: "app.myAccount") : model.settings.displayName
    }

    private var device: String {
        model.settings.deviceMode == .shared
            ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel")
    }
}

/// Tiles of the account panel that are not the accent or red.
enum AccountPanelTint {
    static let settings = Color(red: 0.54, green: 0.55, blue: 0.58)
    static let importItems = Color(red: 0.13, green: 0.63, blue: 0.42)
    static let scan = Color(red: 0.0, green: 0.48, blue: 1.0)
    static let accounts = Color(red: 0.35, green: 0.34, blue: 0.84)
}

/// Rows of the panel on one rounded card, a hairline between them, over the popover's glass.
private struct AccountPanelGroup<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            Group(subviews: content) { rows in
                ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                    if index > 0 {
                        // Starts at the row title: padding, the tile, spacing.
                        Divider().padding(.leading, Theme.Space.m + AccountPanelRow.tileSize + Theme.Space.m)
                    }
                    row
                }
            }
        }
        .background(Theme.card.opacity(0.6), in: .rect(cornerRadius: AccountPanel.cardRadius, style: .continuous))
    }
}

/// One action of the panel: its tile, its short name, and on the Mac its shortcut on the right.
struct AccountPanelRow: View {
    #if os(macOS)
    // Mac rows are a menu's: shorter, smaller tiles, as the sidebar's density.
    static let tileSize: CGFloat = 24
    static let rowHeight: CGFloat = 38
    static let avatarSize: CGFloat = 38
    #else
    static let tileSize: CGFloat = 30
    static let rowHeight: CGFloat = 50
    static let avatarSize: CGFloat = 44
    #endif
    let title: LocalizedStringKey
    let symbol: String
    let color: Color
    var role: ButtonRole?
    /// The menu bar shortcut, shown on the Mac only.
    var shortcut: String?
    let action: () -> Void

    var body: some View {
        Button(role: role, action: action) {
            HStack(spacing: Theme.Space.m) {
                SymbolTile(symbol: symbol, color: color, size: Self.tileSize)
                Text(title)
                    .font(.body)
                    .foregroundStyle(role == .destructive ? Color.red : Color.primary)
                Spacer(minLength: 0)
                #if os(macOS)
                if let shortcut {
                    Text(verbatim: shortcut)
                        .font(.callout)
                        .foregroundStyle(.tertiary)
                }
                #endif
            }
            .padding(.horizontal, Theme.Space.m)
            .frame(minHeight: Self.rowHeight)
            .contentShape(.rect)
        }
        .buttonStyle(AccountPanelRowStyle())
    }
}

/// A soft highlight while pressed, as a menu row; on the Mac also under the pointer.
private struct AccountPanelRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HoverRow(configuration: configuration)
    }

    private struct HoverRow: View {
        let configuration: Configuration
        @State private var hovering = false

        var body: some View {
            configuration.label
                .background(Color.primary.opacity(configuration.isPressed ? 0.12 : hovering ? 0.07 : 0),
                    in: .rect(cornerRadius: Theme.Radius.card, style: .continuous))
                .onHover { hovering = $0 }
        }
    }
}

#if os(iOS)
/// The toolbar of the Accueil, Éléments and Watchtower roots: the account menu on the leading
/// side; on the trailing side, glass circles: the screen's display options when it has some, then
/// "Nouvel élément".
struct PhoneRootToolbar<Options: View>: ToolbarContent {
    @Environment(AppModel.self) private var model
    private let options: Options?

    init(@ViewBuilder options: () -> Options) {
        self.options = options()
    }

    var body: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            AccountMenu()
        }
        .sharedBackgroundVisibility(.hidden)
        if let options {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    options
                } label: {
                    Label("common.show", systemImage: "slider.horizontal.3")
                }
                .accessibilityIdentifier("root.options")
            }
        }
        ToolbarSpacer(.fixed, placement: .topBarTrailing)
        ToolbarItem(placement: .topBarTrailing) {
            Button("Nouvel élément", systemImage: "plus") { model.showNewItemPicker = true }
                .accessibilityIdentifier("items.new")
        }
    }
}

extension PhoneRootToolbar where Options == EmptyView {
    /// Watchtower: no display options, only "Nouvel élément".
    init() {
        options = nil
    }
}
#endif
