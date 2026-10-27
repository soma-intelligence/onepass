import DesignKit
import SwiftUI
import VaultKit

/// Shared device mode: which vaults this device shows. The others stay encrypted and do not
/// appear. At least one vault stays visible.
struct VisibleVaultsView: View {
    @Environment(AppModel.self) private var model

    private var session: VaultSession { model.session }

    var body: some View {
        let visibleCount = session.allVaults.filter { !session.hiddenVaultIDs.contains($0.id) }.count
        Form {
            Section {
                ForEach(session.allVaults, id: \.id) { vault in
                    let hidden = session.hiddenVaultIDs.contains(vault.id)
                    // The last visible vault cannot be hidden.
                    let isLastVisible = !hidden && visibleCount <= 1
                    Toggle(isOn: Binding(
                        get: { !hidden },
                        set: { setVisible(vault, $0) }
                    )) {
                        HStack(spacing: 12) {
                            VaultBadge(name: vault.meta.name, colorName: vault.meta.color, size: 28)
                            Text(vault.meta.name)
                        }
                    }
                    .disabled(isLastVisible)
                    .accessibilityIdentifier("settings.visibleVaults.\(vault.id)")
                }
            } footer: {
                Text("Les coffres décochés restent chiffrés et n'apparaissent pas sur cet appareil. Au moins un coffre reste visible.")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Coffres visibles")
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }

    private func setVisible(_ vault: FfiVault, _ visible: Bool) {
        let visibleCount = session.allVaults.filter { !session.hiddenVaultIDs.contains($0.id) }.count
        if !visible, visibleCount <= 1 { return }
        session.setVaultHidden(vault.id, hidden: !visible)
        // A list showing a vault that just disappeared would be empty.
        if !visible, case .vault(let shown) = model.selection, shown == vault.id {
            model.selection = .all
            model.perform(.select(nil))
        }
        session.noteActivity()
    }
}
