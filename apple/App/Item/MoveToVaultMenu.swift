import DesignKit
import SwiftUI
import VaultKit

/// "Déplacer vers" submenu: every visible vault but the current one. Moving re-wraps the item key
/// for the chosen vault (done by the core).
struct MoveToVaultMenu: View {
    @Environment(AppModel.self) private var model
    let currentVaultID: String
    var title: LocalizedStringKey = "item.moveTo"
    let onMove: (FfiVault) -> Void

    private var targets: [FfiVault] { model.session.vaults.filter { $0.id != currentVaultID } }

    var body: some View {
        Menu(title, systemImage: "folder") {
            if targets.isEmpty {
                Text("item.noOtherVaults")
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
        Picker("term.vault", selection: $vaultID) {
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

/// Vault of the item in the detail toolbar ("Projet Atlas ⌄" with its badge): picking another vault
/// moves the item there. The current vault is listed first, checked.
struct VaultToolbarMenu: View {
    @Environment(AppModel.self) private var model
    let currentVaultID: String
    let onMove: (FfiVault) -> Void

    private var current: FfiVault? { model.session.allVaults.first { $0.id == currentVaultID } }
    private var targets: [FfiVault] { model.session.vaults.filter { $0.id != currentVaultID } }

    #if os(macOS)
    @State private var open = false
    @State private var hovering = false

    /// Mac: the vault label opens a small panel in the house style: every vault as a row with its
    /// round mark, the current one checked, a click on another moves the item.
    var body: some View {
        Button {
            open.toggle()
        } label: {
            HStack(spacing: 6) {
                if let current {
                    VaultIconTile(icon: current.meta.icon, colorName: current.meta.color, size: 16)
                    Text(current.meta.name).lineLimit(1)
                }
                if !targets.isEmpty {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.tertiary)
                }
            }
            .font(.body.weight(.medium))
            .foregroundStyle(hovering || open ? .primary : .secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(hovering || open ? AnyShapeStyle(.fill.tertiary) : AnyShapeStyle(.clear), in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .disabled(targets.isEmpty)
        .popover(isPresented: $open, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 2) {
                Text("term.vault")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.top, 4)
                    .padding(.bottom, 2)
                ForEach(model.session.vaults, id: \.id) { vault in
                    VaultPickRow(vault: vault, isCurrent: vault.id == currentVaultID) {
                        open = false
                        if vault.id != currentVaultID { onMove(vault) }
                    }
                    .accessibilityIdentifier("item.vault.move.\(vault.id)")
                }
            }
            .padding(6)
            .frame(width: 220)
        }
        .accessibilityLabel(Text("item.vault \(current?.meta.name ?? "")"))
        .accessibilityIdentifier("item.vault")
    }
    #else
    var body: some View {
        Menu {
            if let current {
                Button {} label: { Label(current.meta.name, systemImage: "checkmark") }
                    .disabled(true)
            }
            if !targets.isEmpty {
                Section("item.moveTo") {
                    ForEach(targets, id: \.id) { vault in
                        Button(vault.meta.name) { onMove(vault) }
                            .accessibilityIdentifier("item.vault.move.\(vault.id)")
                    }
                }
            }
        } label: {
            HStack(spacing: Theme.Space.s) {
                if let current {
                    VaultIconTile(icon: current.meta.icon, colorName: current.meta.color, size: 16)
                    Text(current.meta.name).lineLimit(1)
                }
            }
        }
        .menuIndicator(targets.isEmpty ? .hidden : .visible)
        .accessibilityLabel(Text("item.vault \(current?.meta.name ?? "")"))
        .accessibilityIdentifier("item.vault")
    }
    #endif
}

#if os(macOS)
/// A vault in the move panel: its mark, its name, a check on the current one; accent under the
/// pointer.
private struct VaultPickRow: View {
    let vault: FfiVault
    let isCurrent: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                VaultIconTile(icon: vault.meta.icon, colorName: vault.meta.color, size: 22)
                Text(vault.meta.name).lineLimit(1)
                Spacer(minLength: 8)
                if isCurrent {
                    Image(systemName: "checkmark")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(Theme.accent))
                }
            }
            .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(hovering ? AnyShapeStyle(Theme.accent.opacity(0.9)) : AnyShapeStyle(.clear),
                in: .rect(cornerRadius: 9, style: .continuous))
            .contentShape(.rect(cornerRadius: 9, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityAddTraits(isCurrent ? .isSelected : [])
    }
}
#endif
