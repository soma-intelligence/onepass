#if os(iOS)
import DesignKit
import SwiftUI

/// Account button of the iPhone navigation bars (mockups `PhoneHome`, `PhoneItems`): initials on
/// an accent square. Its menu holds Réglages (a sheet) and Verrouiller, which asks first when an
/// edited draft would be lost.
struct AccountMenu: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Menu {
            Section(model.settings.displayName.isEmpty ? String(localized: "Mon compte") : model.settings.displayName) {
                Button("Réglages", systemImage: "gearshape") { model.showSettings = true }
                    .accessibilityIdentifier("account.settings")
                Button("Verrouiller", systemImage: "lock") { model.perform(.lock) }
                    .accessibilityIdentifier("account.lock")
            }
        } label: {
            HStack(spacing: 4) {
                Text(model.initials.isEmpty ? "?" : model.initials)
                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                    .frame(width: 34, height: 34)
                    .background(Theme.accent, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                Image(systemName: "chevron.down")
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .accessibilityLabel(Text("Menu du compte"))
        .accessibilityIdentifier("account.menu")
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
                .accessibilityIdentifier("items.new")
        }
    }
}
#endif
