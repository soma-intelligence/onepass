import DesignKit
import SwiftUI
import VaultKit

/// "Déplacer vers" submenu: every visible vault but the current one. Moving re-wraps the item key
/// for the chosen vault (done by the core).
struct MoveToVaultMenu: View {
    @Environment(AppModel.self) private var model
    let currentVaultID: String
    let onMove: (FfiVault) -> Void

    private var targets: [FfiVault] { model.session.vaults.filter { $0.id != currentVaultID } }

    var body: some View {
        Menu("Déplacer vers", systemImage: "folder") {
            if targets.isEmpty {
                Text("Aucun autre coffre")
            }
            ForEach(targets, id: \.id) { vault in
                Button(vault.meta.name) { onMove(vault) }
                    .accessibilityIdentifier("item.move.\(vault.id)")
            }
        }
        .disabled(targets.isEmpty)
        .accessibilityIdentifier("item.move")
    }
}

/// Vault picker of the editor: badge and name of each visible vault.
struct VaultPicker: View {
    @Environment(AppModel.self) private var model
    @Binding var vaultID: String

    var body: some View {
        Picker("Coffre", selection: $vaultID) {
            ForEach(model.session.vaults, id: \.id) { vault in
                Text(vault.meta.name).tag(vault.id)
            }
            if !model.session.vaults.contains(where: { $0.id == vaultID }),
                let hidden = model.session.allVaults.first(where: { $0.id == vaultID })
            {
                Text(hidden.meta.name).tag(hidden.id)
            }
        }
        .accessibilityIdentifier("editor.vault")
    }
}
