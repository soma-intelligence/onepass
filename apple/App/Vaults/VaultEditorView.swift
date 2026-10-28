import DesignKit
import SwiftUI
import VaultKit

/// The twelve symbols a vault can take, and the seven named colors (the vault badge palette).
enum VaultStyle {
    static let icons = [
        "folder", "briefcase", "house", "person", "person.2", "heart",
        "star", "cart", "creditcard", "airplane", "graduationcap", "gamecontroller",
    ]

    static let colors = VaultBadge.colorNames

    static func colorLabel(_ name: String) -> String {
        switch name {
        case "blue": String(localized: "Bleu")
        case "teal": String(localized: "Turquoise")
        case "orange": String(localized: "Orange")
        case "green": String(localized: "Vert")
        case "purple": String(localized: "Violet")
        case "pink": String(localized: "Rose")
        default: String(localized: "Gris")
        }
    }

    static func iconLabel(_ name: String) -> String {
        switch name {
        case "folder": String(localized: "Dossier")
        case "briefcase": String(localized: "Mallette")
        case "house": String(localized: "Maison")
        case "person": String(localized: "Personne")
        case "person.2": String(localized: "Deux personnes")
        case "heart": String(localized: "Cœur")
        case "star": String(localized: "Étoile")
        case "cart": String(localized: "Panier")
        case "creditcard": String(localized: "Carte bancaire")
        case "airplane": String(localized: "Avion")
        case "graduationcap": String(localized: "Études")
        case "gamecontroller": String(localized: "Jeux")
        default: name
        }
    }
}

/// Rounded tile with a vault's symbol on its color (preview of the editor, list of the settings).
struct VaultIconTile: View {
    let icon: String
    let colorName: String
    var size: CGFloat = 30

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
            .fill(VaultBadge.color(named: colorName))
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: VaultStyle.icons.contains(icon) ? icon : "folder")
                    .font(.system(size: size * 0.5, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .accessibilityHidden(true)
    }
}

/// Creates a vault (`vault` nil) or renames and restyles one: name, symbol among twelve, color
/// among seven. An existing vault is deleted here when it is empty and not the last (R14).
struct VaultEditorView: View {
    @Environment(AppModel.self) private var model
    let vault: FfiVault?
    let onDone: () -> Void

    @State private var name: String
    @State private var icon: String
    @State private var color: String
    /// Stays on the device in Travel Mode (synced with the vault).
    @State private var travelSafe: Bool
    @State private var saving = false
    @State private var errorMessage: String?
    @State private var confirmDelete = false
    @FocusState private var nameFocused: Bool

    init(vault: FfiVault?, onDone: @escaping () -> Void) {
        self.vault = vault
        self.onDone = onDone
        _name = State(initialValue: vault?.meta.name ?? "")
        _icon = State(initialValue: vault?.meta.icon ?? "folder")
        _color = State(initialValue: vault?.meta.color ?? "blue")
        _travelSafe = State(initialValue: vault?.meta.travelSafe ?? false)
    }

    private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var canSave: Bool { !trimmed.isEmpty && !saving }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(spacing: 14) {
                        VaultIconTile(icon: icon, colorName: color, size: 44)
                        TextField("Nom du coffre", text: $name, prompt: Text("Projet Atlas"))
                            .focused($nameFocused)
                            .onSubmit(save)
                            .submitLabel(.done)
                            .accessibilityIdentifier("vault.editor.name")
                    }
                }
                Section("Icône") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 44), spacing: 8)], spacing: 8) {
                        ForEach(VaultStyle.icons, id: \.self) { symbol in
                            iconButton(symbol)
                        }
                    }
                    .padding(.vertical, 4)
                }
                Section("Couleur") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 44), spacing: 8)], spacing: 8) {
                        ForEach(VaultStyle.colors, id: \.self) { name in
                            colorButton(name)
                        }
                    }
                    .padding(.vertical, 4)
                }
                Section {
                    Toggle("Sûr en voyage", isOn: $travelSafe)
                        .accessibilityIdentifier("vault.editor.travelSafe")
                } footer: {
                    Text("En Travel Mode, les coffres qui ne sont pas sûrs en voyage quittent tes appareils jusqu'à ton retour.")
                }
                if let vault {
                    deleteSection(vault)
                }
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("vault.editor.error")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(vault == nil ? Text("Nouveau coffre") : Text("Coffre"))
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler", action: onDone)
                        .accessibilityIdentifier("vault.editor.cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(vault == nil ? "Créer" : "Enregistrer", action: save)
                        .disabled(!canSave)
                        .accessibilityIdentifier("vault.editor.save")
                }
            }
            .onAppear { if vault == nil { nameFocused = true } }
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 440)
        #endif
        .interactiveDismissDisabled(saving)
    }

    // MARK: - Suppression

    /// No live or archived item left (trashed ones go with the vault).
    private func isEmpty(_ vault: FfiVault) -> Bool {
        !model.session.summaries.contains { $0.vaultId == vault.id && $0.trashedAt == nil }
    }

    private func deleteSection(_ vault: FfiVault) -> some View {
        let last = model.session.allVaults.count <= 1
        let empty = isEmpty(vault)
        return Section {
            Button("Supprimer le coffre", systemImage: "trash", role: .destructive) { confirmDelete = true }
                .disabled(last || !empty || saving)
                .accessibilityIdentifier("vault.editor.delete")
        } footer: {
            if last {
                Text("Le dernier coffre ne peut pas être supprimé.")
            } else if !empty {
                Text("Vide ce coffre avant de le supprimer. Les éléments à la corbeille partent avec lui.")
            }
        }
        .confirmationDialog(
            Text("Supprimer « \(vault.meta.name) » ?"), isPresented: $confirmDelete, titleVisibility: .visible
        ) {
            Button("Supprimer le coffre", role: .destructive) { delete(vault) }
                .accessibilityIdentifier("vault.editor.delete.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Il disparaît de tous tes appareils, avec les éléments de sa corbeille.")
        }
    }

    private func delete(_ vault: FfiVault) {
        saving = true
        errorMessage = nil
        Task {
            defer { saving = false }
            do {
                try await model.session.deleteVault(vault.id)
                onDone()
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }

    private func iconButton(_ symbol: String) -> some View {
        let selected = icon == symbol
        return Button {
            icon = symbol
        } label: {
            Image(systemName: symbol)
                .font(.system(size: 18, weight: .medium))
                .foregroundStyle(selected ? Color.white : Color.primary)
                .frame(width: 44, height: 44)
                .background(
                    selected ? AnyShapeStyle(VaultBadge.color(named: color)) : AnyShapeStyle(.quaternary),
                    in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        }
        .buttonStyle(.plain)
        .visionHoverEffect()
        .accessibilityLabel(Text(VaultStyle.iconLabel(symbol)))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("vault.editor.icon.\(symbol)")
    }

    private func colorButton(_ colorName: String) -> some View {
        let selected = color == colorName
        return Button {
            color = colorName
        } label: {
            Circle()
                .fill(VaultBadge.color(named: colorName))
                .frame(width: 32, height: 32)
                .overlay {
                    if selected {
                        Image(systemName: "checkmark").font(.system(size: 13, weight: .bold)).foregroundStyle(.white)
                    }
                }
                .frame(width: 44, height: 44)
        }
        .buttonStyle(.plain)
        .visionHoverEffect()
        .accessibilityLabel(Text(VaultStyle.colorLabel(colorName)))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("vault.editor.color.\(colorName)")
    }

    private func save() {
        guard canSave else { return }
        saving = true
        errorMessage = nil
        // The MCP flag is set from Réglages > Développeur, with the signed policy: kept as is here.
        let meta = FfiVaultMeta(
            name: trimmed, icon: icon, color: color,
            travelSafe: travelSafe, mcpAccess: vault?.meta.mcpAccess ?? false)
        Task {
            defer { saving = false }
            do {
                if let vault {
                    try await model.session.updateVault(id: vault.id, meta: meta)
                } else {
                    try await model.session.createVault(meta)
                }
                onDone()
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }
}
