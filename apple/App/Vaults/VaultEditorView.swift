import DesignKit
import SwiftUI
import VaultKit

/// The symbols a vault can take (SF Symbols, drawn white on the vault's color) and its named colors
/// (the `VaultBadge` palette). Vaults made before the larger set keep their outline symbols.
enum VaultStyle {
    static let catalog: [(symbol: String, label: String)] = [
        ("folder.fill", String(localized: "Dossier")),
        ("archivebox.fill", String(localized: "Archives")),
        ("house.fill", String(localized: "Maison")),
        ("building.2.fill", String(localized: "Bureau")),
        ("building.columns.fill", String(localized: "Banque")),
        ("briefcase.fill", String(localized: "Travail")),
        ("person.fill", String(localized: "Personne")),
        ("person.2.fill", String(localized: "Duo")),
        ("figure.2.and.child.holdinghands", String(localized: "Famille")),
        ("heart.fill", String(localized: "Cœur")),
        ("star.fill", String(localized: "Étoile")),
        ("crown.fill", String(localized: "Couronne")),
        ("cart.fill", String(localized: "Panier")),
        ("bag.fill", String(localized: "Achats")),
        ("gift.fill", String(localized: "Cadeau")),
        ("creditcard.fill", String(localized: "Carte bancaire")),
        ("banknote.fill", String(localized: "Argent")),
        ("chart.bar.fill", String(localized: "Finances")),
        ("scalemass.fill", String(localized: "Juridique")),
        ("doc.text.fill", String(localized: "Documents")),
        ("envelope.fill", String(localized: "Courrier")),
        ("phone.fill", String(localized: "Téléphone")),
        ("bubble.left.and.bubble.right.fill", String(localized: "Messages")),
        ("globe.americas.fill", String(localized: "Monde")),
        ("airplane", String(localized: "Voyage")),
        ("car.fill", String(localized: "Voiture")),
        ("sailboat.fill", String(localized: "Bateau")),
        ("tram.fill", String(localized: "Transports")),
        ("map.fill", String(localized: "Carte")),
        ("mountain.2.fill", String(localized: "Montagne")),
        ("tent.fill", String(localized: "Camping")),
        ("tree.fill", String(localized: "Nature")),
        ("leaf.fill", String(localized: "Feuille")),
        ("flame.fill", String(localized: "Flamme")),
        ("drop.fill", String(localized: "Goutte")),
        ("bolt.fill", String(localized: "Énergie")),
        ("sun.max.fill", String(localized: "Soleil")),
        ("moon.stars.fill", String(localized: "Nuit")),
        ("cloud.fill", String(localized: "Nuage")),
        ("snowflake", String(localized: "Hiver")),
        ("graduationcap.fill", String(localized: "Études")),
        ("book.fill", String(localized: "Livre")),
        ("pencil.and.outline", String(localized: "Écriture")),
        ("paintbrush.fill", String(localized: "Art")),
        ("music.note", String(localized: "Musique")),
        ("film.fill", String(localized: "Cinéma")),
        ("camera.fill", String(localized: "Photo")),
        ("gamecontroller.fill", String(localized: "Jeux")),
        ("dice.fill", String(localized: "Dés")),
        ("puzzlepiece.fill", String(localized: "Puzzle")),
        ("tennisball.fill", String(localized: "Sport")),
        ("dumbbell.fill", String(localized: "Fitness")),
        ("figure.run", String(localized: "Course")),
        ("cross.case.fill", String(localized: "Santé")),
        ("pills.fill", String(localized: "Médicaments")),
        ("pawprint.fill", String(localized: "Animaux")),
        ("cup.and.saucer.fill", String(localized: "Café")),
        ("fork.knife", String(localized: "Restaurants")),
        ("wrench.and.screwdriver.fill", String(localized: "Outils")),
        ("hammer.fill", String(localized: "Bricolage")),
        ("terminal.fill", String(localized: "Terminal")),
        ("chevron.left.forwardslash.chevron.right", String(localized: "Code")),
        ("server.rack", String(localized: "Serveurs")),
        ("cpu.fill", String(localized: "Matériel")),
        ("wifi", String(localized: "Wi-Fi")),
        ("atom", String(localized: "Science")),
        ("testtube.2", String(localized: "Laboratoire")),
        ("key.fill", String(localized: "Clé")),
        ("lock.fill", String(localized: "Cadenas")),
        ("shield.fill", String(localized: "Bouclier")),
        ("flag.fill", String(localized: "Drapeau")),
        ("sparkles", String(localized: "Étincelles")),
    ]

    static let icons = catalog.map(\.symbol)

    /// The first twelve symbols, outline, from before the larger set.
    static let legacy = [
        "folder", "briefcase", "house", "person", "person.2", "heart",
        "star", "cart", "creditcard", "airplane", "graduationcap", "gamecontroller",
    ]

    /// The symbol to draw: a stored legacy outline name becomes its filled sibling.
    static func symbol(_ icon: String) -> String {
        if icons.contains(icon) { return icon }
        if legacy.contains(icon) { return icons.contains(icon + ".fill") ? icon + ".fill" : icon }
        return "folder.fill"
    }

    static let colors = VaultBadge.colorNames

    static func colorLabel(_ name: String) -> String {
        switch name {
        case "red": String(localized: "Rouge")
        case "orange": String(localized: "Orange")
        case "amber": String(localized: "Ambre")
        case "yellow": String(localized: "Jaune")
        case "lime": String(localized: "Citron vert")
        case "green": String(localized: "Vert")
        case "mint": String(localized: "Menthe")
        case "teal": String(localized: "Turquoise")
        case "cyan": String(localized: "Cyan")
        case "sky": String(localized: "Ciel")
        case "blue": String(localized: "Bleu")
        case "indigo": String(localized: "Indigo")
        case "purple": String(localized: "Violet")
        case "pink": String(localized: "Rose")
        case "rose": String(localized: "Rose poudré")
        case "brown": String(localized: "Brun")
        case "graphite": String(localized: "Graphite")
        case "gray": String(localized: "Gris")
        default: String(localized: "Gris")
        }
    }

    static func iconLabel(_ name: String) -> String {
        catalog.first { $0.symbol == symbol(name) }?.label ?? name
    }
}

/// A vault's symbol on a squircle in a soft gradient of its color, with a hairline highlight: the
/// same family as the sidebar's row tiles.
struct VaultIconTile: View {
    let icon: String
    let colorName: String
    var size: CGFloat = 30

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
        shape
            .fill(VaultBadge.color(named: colorName).gradient)
            .overlay { shape.strokeBorder(.white.opacity(0.18), lineWidth: 0.5) }
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: VaultStyle.symbol(icon))
                    .font(.system(size: size * 0.5, weight: .semibold))
                    .foregroundStyle(.white)
                    .shadow(color: .black.opacity(0.12), radius: 0.5, y: 0.5)
            }
            .accessibilityHidden(true)
    }
}

/// Creates a vault (`vault` nil) or renames and restyles one: a large live preview with the name
/// under it, then the colors, then the symbols, each drawn in the chosen color. An existing vault is deleted here when it is empty and not the last (R14).
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
        _icon = State(initialValue: vault.map { VaultStyle.symbol($0.meta.icon) } ?? "folder.fill")
        _color = State(initialValue: vault?.meta.color ?? "blue")
        _travelSafe = State(initialValue: vault?.meta.travelSafe ?? false)
    }

    private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var canSave: Bool { !trimmed.isEmpty && !saving }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 14) {
                        VaultIconTile(icon: icon, colorName: color, size: 76)
                            .shadow(color: VaultBadge.color(named: color).opacity(0.35), radius: 14, y: 6)
                            .animation(.spring(duration: 0.35, bounce: 0.3), value: color)
                            .animation(.spring(duration: 0.35, bounce: 0.3), value: icon)
                        TextField("Nom du coffre", text: $name, prompt: Text("Projet Atlas"))
                            .labelsHidden()
                            .textFieldStyle(.plain)
                            .multilineTextAlignment(.center)
                            .font(.title2.weight(.semibold))
                            .focused($nameFocused)
                            .onSubmit(save)
                            .submitLabel(.done)
                            .padding(.vertical, 8)
                            .padding(.horizontal, 12)
                            .background(.fill.quaternary, in: .rect(cornerRadius: 10, style: .continuous))
                            .accessibilityIdentifier("vault.editor.name")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                }
                Section("Couleur") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 30, maximum: 34), spacing: 8)], spacing: 10) {
                        ForEach(VaultStyle.colors, id: \.self) { name in
                            colorButton(name)
                        }
                    }
                    .padding(.vertical, 6)
                }
                Section("Icône") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 40, maximum: 46), spacing: 8)], spacing: 8) {
                        ForEach(VaultStyle.icons, id: \.self) { symbol in
                            iconButton(symbol)
                        }
                    }
                    .padding(.vertical, 6)
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
                        #if os(macOS)
                        .buttonStyle(QuietToolbarButtonStyle())
                        #endif
                        .accessibilityIdentifier("vault.editor.cancel")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(vault == nil ? "Créer" : "Enregistrer", action: save)
                        #if os(macOS)
                        .buttonStyle(AccentCapsuleButtonStyle())
                        #endif
                        .disabled(!canSave)
                        .accessibilityIdentifier("vault.editor.save")
                }
            }
            .onAppear { if vault == nil { nameFocused = true } }
        }
        #if os(macOS)
        .frame(width: 480, height: 640)
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

    /// A symbol of the grid, already in the vault's color: tinted when idle, the full tile once
    /// chosen, with a ring.
    private func iconButton(_ symbol: String) -> some View {
        let selected = icon == symbol
        let tint = VaultBadge.color(named: color)
        return Button {
            withAnimation(.spring(duration: 0.3, bounce: 0.3)) { icon = symbol }
        } label: {
            ZStack {
                if selected {
                    VaultIconTile(icon: symbol, colorName: color, size: 40)
                } else {
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .fill(tint.opacity(0.16))
                        .frame(width: 40, height: 40)
                        .overlay {
                            Image(systemName: symbol)
                                .font(.system(size: 17, weight: .semibold))
                                .foregroundStyle(tint.mix(with: .white, by: 0.25))
                        }
                }
            }
            .padding(2)
            .overlay {
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .strokeBorder(selected ? tint : .clear, lineWidth: 2)
            }
            .scaleEffect(selected ? 1.04 : 1)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .help(VaultStyle.iconLabel(symbol))
        .visionHoverEffect()
        .accessibilityLabel(Text(VaultStyle.iconLabel(symbol)))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("vault.editor.icon.\(symbol)")
    }

    /// A color dot; the chosen one gets a ring a little away from it.
    private func colorButton(_ colorName: String) -> some View {
        let selected = color == colorName
        let fill = VaultBadge.color(named: colorName)
        return Button {
            withAnimation(.spring(duration: 0.3, bounce: 0.3)) { color = colorName }
        } label: {
            Circle()
                .fill(fill.gradient)
                .frame(width: 24, height: 24)
                .padding(3)
                .overlay { Circle().strokeBorder(selected ? fill : .clear, lineWidth: 2) }
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .help(VaultStyle.colorLabel(colorName))
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
