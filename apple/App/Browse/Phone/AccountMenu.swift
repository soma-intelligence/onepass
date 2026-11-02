#if os(iOS)
import DesignKit
import SwiftUI

/// Account button of the iPhone navigation bars: the account's initials on the accent square and a
/// small chevron, as the Mac account header. It opens the account panel.
struct AccountMenu: View {
    @Environment(AppModel.self) private var model
    @State private var isOpen = false
    /// What the panel asked for: run once the popover is gone, so a sheet never fights it.
    @State private var pending: AccountPanelAction?
    @State private var creatingVault = false

    var body: some View {
        Button {
            isOpen = true
        } label: {
            HStack(spacing: 4) {
                AccountAvatar(initials: model.initials, photo: model.profileImage, size: 32)
                Image(systemName: "chevron.down")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            .frame(minHeight: 44)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text("Menu du compte"))
        .accessibilityIdentifier("account.menu")
        .popover(isPresented: $isOpen, arrowEdge: .top) {
            AccountPanel { action in
                pending = action
                isOpen = false
            }
            .presentationCompactAdaptation(.popover)
        }
        .onChange(of: isOpen) { _, open in
            guard !open, let action = pending else { return }
            pending = nil
            run(action)
        }
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
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

    private func run(_ action: AccountPanelAction) {
        switch action {
        case .settings: model.showSettings = true
        case .newVault: creatingVault = true
        case .importItems: model.showImport = true
        case .scanCode: model.showOtpScanner = true
        case .lock: model.perform(.lock)
        }
    }
}

/// What a row of the account panel does.
enum AccountPanelAction {
    case settings, newVault, importItems, scanCode, lock
}

/// The account panel: a glass popover under the account button. The accounts on this device on
/// top (one today; profiles add theirs to `accounts`), then the actions, each with its colored
/// tile as in the sidebar, and Verrouiller apart at the bottom.
struct AccountPanel: View {
    @Environment(AppModel.self) private var model
    let perform: (AccountPanelAction) -> Void

    var body: some View {
        let _ = model.settingsRevision
        VStack(alignment: .leading, spacing: 0) {
            accounts
                .padding(.horizontal, 14)
                .padding(.top, 14)
                .padding(.bottom, 10)
            AccountPanelGroup {
                AccountPanelRow(title: "Réglages", symbol: "gearshape.fill", color: AccountPanelTint.settings) {
                    perform(.settings)
                }
                .accessibilityIdentifier("account.settings")
                AccountPanelRow(title: "Nouveau coffre", symbol: "square.stack.3d.up.fill", color: Theme.accent) {
                    perform(.newVault)
                }
                .accessibilityIdentifier("account.newVault")
                AccountPanelRow(title: "Importer", symbol: "square.and.arrow.down.fill", color: AccountPanelTint.importItems) {
                    perform(.importItems)
                }
                .accessibilityIdentifier("account.import")
                if SecretKeyScanner.isSupported {
                    AccountPanelRow(title: "Scanner un code", symbol: "qrcode.viewfinder", color: AccountPanelTint.scan) {
                        perform(.scanCode)
                    }
                    .accessibilityIdentifier("account.scanOtp")
                }
            }
            AccountPanelGroup {
                AccountPanelRow(title: "Verrouiller", symbol: "lock.fill", color: .red, role: .destructive) {
                    perform(.lock)
                }
                .accessibilityIdentifier("account.lock")
            }
            .padding(.top, 8)
        }
        .padding(.horizontal, 8)
        .padding(.bottom, 8)
        .frame(width: 296)
    }

    /// The accounts of this device. One today: the signed in account, its kind of device. The
    /// profiles work adds the others here, each switching on tap.
    @ViewBuilder private var accounts: some View {
        HStack(spacing: 12) {
            AccountAvatar(initials: model.initials, photo: model.profileImage, size: 44)
            VStack(alignment: .leading, spacing: 1) {
                Text(name)
                    .font(.headline)
                    .lineLimit(1)
                Text(device)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("account.current")
    }

    private var name: String {
        model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName
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
}

/// Rows of the panel on one rounded card, a hairline between them, over the popover's glass.
private struct AccountPanelGroup<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            Group(subviews: content) { rows in
                ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                    if index > 0 {
                        Divider().padding(.leading, 54)
                    }
                    row
                }
            }
        }
        .background(Theme.card.opacity(0.6), in: .rect(cornerRadius: 14, style: .continuous))
    }
}

/// One action of the panel: its tile, its short name.
private struct AccountPanelRow: View {
    let title: LocalizedStringKey
    let symbol: String
    let color: Color
    var role: ButtonRole?
    let action: () -> Void

    var body: some View {
        Button(role: role, action: action) {
            HStack(spacing: 12) {
                SymbolTile(symbol: symbol, color: color, size: 30)
                Text(title)
                    .font(.body)
                    .foregroundStyle(role == .destructive ? Color.red : Color.primary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .frame(minHeight: 50)
            .contentShape(.rect)
        }
        .buttonStyle(AccountPanelRowStyle())
    }
}

/// A soft highlight while pressed, as a menu row.
private struct AccountPanelRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .background(Color.primary.opacity(configuration.isPressed ? 0.08 : 0), in: .rect(cornerRadius: 14, style: .continuous))
    }
}

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
                    Label("Afficher", systemImage: "slider.horizontal.3")
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
