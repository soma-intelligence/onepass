#if os(iOS)
import DesignKit
import SwiftUI

/// Account button of the iPhone navigation bars: the account's initials on the accent square and a
/// small chevron, as the Mac account header. Its menu holds the Mac popover's content: who is
/// signed in and on which kind of device, then Réglages (a sheet, it left the tab bar), Nouveau
/// coffre, Importer and Verrouiller.
struct AccountMenu: View {
    @Environment(AppModel.self) private var model
    @State private var creatingVault = false

    var body: some View {
        Menu {
            Section {
                Button("Réglages", systemImage: "gearshape") { model.showSettings = true }
                    .accessibilityIdentifier("account.settings")
                Button("Nouveau coffre…", systemImage: "plus.rectangle.on.rectangle") { creatingVault = true }
                    .accessibilityIdentifier("account.newVault")
                Button("Importer…", systemImage: "square.and.arrow.down") { model.showImport = true }
                    .accessibilityIdentifier("account.import")
            } header: {
                Text(verbatim: "\(name) · \(device)")
            }
            Button("Verrouiller", systemImage: "lock", role: .destructive) { model.perform(.lock) }
                .accessibilityIdentifier("account.lock")
        } label: {
            HStack(spacing: 4) {
                AccountAvatar(initials: model.initials, size: 32)
                Image(systemName: "chevron.down")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            .frame(minHeight: 44)
            .contentShape(.rect)
        }
        .accessibilityLabel(Text("Menu du compte"))
        .accessibilityIdentifier("account.menu")
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
        }
    }

    private var name: String {
        model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName
    }

    private var device: String {
        model.settings.deviceMode == .shared
            ? String(localized: "Appareil partagé") : String(localized: "Appareil personnel")
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
