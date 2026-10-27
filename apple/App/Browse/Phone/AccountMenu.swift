#if os(iOS)
import DesignKit
import SwiftUI

/// Account button of the iPhone navigation bars (mockups `PhoneHome`, `PhoneItems`): the account's
/// initials on the accent square, as in the Mac account header. Its menu holds the account actions
/// of the Mac popover: Nouveau coffre, Importer, Réglages (the tab) and Verrouiller, which asks
/// first when an edited draft would be lost.
struct AccountMenu: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openPhoneTab) private var openTab
    @State private var creatingVault = false

    var body: some View {
        Menu {
            Section(model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName) {
                Button("Nouveau coffre…", systemImage: "plus.rectangle.on.rectangle") { creatingVault = true }
                    .accessibilityIdentifier("account.newVault")
                Button("Importer…", systemImage: "square.and.arrow.down") { model.showImport = true }
                    .accessibilityIdentifier("account.import")
                Button("Réglages", systemImage: "gearshape") { openTab(.settings) }
                    .accessibilityIdentifier("account.settings")
            }
            Button("Verrouiller", systemImage: "lock", role: .destructive) { model.perform(.lock) }
                .accessibilityIdentifier("account.lock")
        } label: {
            AccountAvatar(initials: model.initials, size: 34)
                .contentShape(Rectangle())
        }
        .accessibilityLabel(Text("Menu du compte"))
        .accessibilityIdentifier("account.menu")
        .sheet(isPresented: $creatingVault) {
            VaultEditorView(vault: nil) { creatingVault = false }
        }
    }
}

/// The toolbar shared by the Accueil, Éléments and Watchtower roots: account menu on the leading
/// side, "Nouvel élément" on the trailing side.
struct PhoneRootToolbar: ToolbarContent {
    @Environment(AppModel.self) private var model

    var body: some ToolbarContent {
        ToolbarItem(placement: .topBarLeading) {
            AccountMenu()
        }
        .sharedBackgroundVisibility(.hidden)
        ToolbarItem(placement: .topBarTrailing) {
            Button("Nouvel élément", systemImage: "plus") { model.showNewItemPicker = true }
                .buttonStyle(.glassProminent)
                .accessibilityIdentifier("items.new")
        }
    }
}
#endif
