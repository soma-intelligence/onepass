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
/// among seven. A vault cannot be deleted in this version (ruling R14).
struct VaultEditorView: View {
    @Environment(AppModel.self) private var model
    let vault: FfiVault?
    let onDone: () -> Void

    @State private var name: String
    @State private var icon: String
    @State private var color: String
    @State private var saving = false
    @State private var errorMessage: String?
    @FocusState private var nameFocused: Bool

    init(vault: FfiVault?, onDone: @escaping () -> Void) {
        self.vault = vault
        self.onDone = onDone
        _name = State(initialValue: vault?.meta.name ?? "")
        _icon = State(initialValue: vault?.meta.icon ?? "folder")
        _color = State(initialValue: vault?.meta.color ?? "blue")
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
        // A rename keeps the flags this editor does not show.
        let meta = FfiVaultMeta(
            name: trimmed, icon: icon, color: color,
            travelSafe: vault?.meta.travelSafe ?? false, mcpAccess: vault?.meta.mcpAccess ?? false)
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
