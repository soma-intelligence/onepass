import DesignKit
import SwiftUI
import VaultKit

/// Coffres: the list, rename, symbol and color of each, new vault. An empty vault that is not the
/// last one is deleted from its editor (R14, milestone 2b).
struct VaultsSettings: View {
    @Environment(AppModel.self) private var model

    /// What the editor sheet works on: a vault, or a new one.
    private enum Editing: Identifiable {
        case new
        case existing(FfiVault)

        var id: String {
            switch self {
            case .new: "new"
            case .existing(let vault): vault.id
            }
        }

        var vault: FfiVault? {
            if case .existing(let vault) = self { vault } else { nil }
        }
    }

    @State private var editing: Editing?

    var body: some View {
        // Read so the page redraws when the device mode changes.
        let _ = model.settingsRevision
        let shared = model.settings.deviceMode == .shared
        Form {
            Section {
                ForEach(model.session.allVaults, id: \.id) { vault in
                    Button {
                        editing = .existing(vault)
                    } label: {
                        HStack(spacing: 12) {
                            VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 30)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(vault.meta.name).foregroundStyle(.primary)
                                if shared, model.session.hiddenVaultIDs.contains(vault.id) {
                                    Text("Masqué sur cet appareil").font(.footnote).foregroundStyle(.secondary)
                                }
                            }
                            Spacer(minLength: 0)
                            Image(systemName: "pencil").foregroundStyle(.secondary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .visionHoverEffect()
                    .accessibilityLabel(Text("Modifier le coffre \(vault.meta.name)"))
                    .accessibilityIdentifier("settings.vaults.\(vault.id)")
                }
                Button {
                    editing = .new
                } label: {
                    Label("Nouveau coffre", systemImage: "plus")
                }
                .accessibilityIdentifier("settings.vaults.new")
            } footer: {
                Text("Un coffre vide peut être supprimé depuis sa fiche, sauf le dernier.")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Coffres")
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        #if DEBUG
        .onAppear {
            // Screenshots: `-OnePassDemoVaultEditor YES` opens the editor of the first vault.
            if UserDefaults.standard.bool(forKey: "OnePassDemoVaultEditor"), editing?.id == nil {
                editing = model.session.allVaults.first.map { .existing($0) }
            }
        }
        #endif
        .sheet(item: $editing) { target in
            VaultEditorView(vault: target.vault) { editing = nil }
        }
    }
}
