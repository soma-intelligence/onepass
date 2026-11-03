import DesignKit
import SwiftUI
import VaultKit

/// The symbols a vault can take (SF Symbols, drawn white on the vault's color) and its named colors
/// (the `VaultBadge` palette). Vaults made before the larger set keep their outline symbols.
enum VaultStyle {
    static let catalog: [(symbol: String, label: String)] = [
        ("folder.fill", String(localized: "app.folder")),
        ("archivebox.fill", String(localized: "vaults.archives")),
        ("house.fill", String(localized: "vaults.house")),
        ("building.2.fill", String(localized: "vaults.office")),
        ("building.columns.fill", String(localized: "Banque")),
        ("briefcase.fill", String(localized: "Travail")),
        ("person.fill", String(localized: "vaults.person")),
        ("person.2.fill", String(localized: "vaults.twoPeople")),
        ("figure.2.and.child.holdinghands", String(localized: "Famille")),
        ("heart.fill", String(localized: "vaults.heart")),
        ("star.fill", String(localized: "vaults.star")),
        ("crown.fill", String(localized: "vaults.crown")),
        ("cart.fill", String(localized: "vaults.cart")),
        ("bag.fill", String(localized: "vaults.shopping")),
        ("gift.fill", String(localized: "vaults.gift")),
        ("creditcard.fill", String(localized: "vaults.creditCard")),
        ("banknote.fill", String(localized: "vaults.money")),
        ("chart.bar.fill", String(localized: "vaults.finances")),
        ("scalemass.fill", String(localized: "vaults.legal")),
        ("doc.text.fill", String(localized: "vaults.documents")),
        ("envelope.fill", String(localized: "vaults.mail")),
        ("phone.fill", String(localized: "app.phone")),
        ("bubble.left.and.bubble.right.fill", String(localized: "vaults.messages")),
        ("globe.americas.fill", String(localized: "vaults.world")),
        ("airplane", String(localized: "Voyage")),
        ("car.fill", String(localized: "vaults.car")),
        ("sailboat.fill", String(localized: "vaults.boat")),
        ("tram.fill", String(localized: "vaults.transit")),
        ("map.fill", String(localized: "vaults.map")),
        ("mountain.2.fill", String(localized: "vaults.mountain")),
        ("tent.fill", String(localized: "vaults.camping")),
        ("tree.fill", String(localized: "vaults.nature")),
        ("leaf.fill", String(localized: "vaults.leaf")),
        ("flame.fill", String(localized: "vaults.flame")),
        ("drop.fill", String(localized: "vaults.drop")),
        ("bolt.fill", String(localized: "vaults.energy")),
        ("sun.max.fill", String(localized: "vaults.sun")),
        ("moon.stars.fill", String(localized: "vaults.night")),
        ("cloud.fill", String(localized: "vaults.cloud")),
        ("snowflake", String(localized: "vaults.winter")),
        ("graduationcap.fill", String(localized: "vaults.school")),
        ("book.fill", String(localized: "vaults.book")),
        ("pencil.and.outline", String(localized: "vaults.writing")),
        ("paintbrush.fill", String(localized: "vaults.art")),
        ("music.note", String(localized: "vaults.music")),
        ("film.fill", String(localized: "vaults.movies")),
        ("camera.fill", String(localized: "vaults.photo")),
        ("gamecontroller.fill", String(localized: "vaults.games")),
        ("dice.fill", String(localized: "vaults.dice")),
        ("puzzlepiece.fill", String(localized: "vaults.puzzle")),
        ("tennisball.fill", String(localized: "vaults.sports")),
        ("dumbbell.fill", String(localized: "vaults.fitness")),
        ("figure.run", String(localized: "vaults.running")),
        ("cross.case.fill", String(localized: "vaults.health")),
        ("pills.fill", String(localized: "vaults.medication")),
        ("pawprint.fill", String(localized: "vaults.pets")),
        ("cup.and.saucer.fill", String(localized: "vaults.coffee")),
        ("fork.knife", String(localized: "vaults.restaurants")),
        ("wrench.and.screwdriver.fill", String(localized: "vaults.tools")),
        ("hammer.fill", String(localized: "vaults.diy")),
        ("terminal.fill", String(localized: "vaults.terminal")),
        ("chevron.left.forwardslash.chevron.right", String(localized: "vaults.code")),
        ("server.rack", String(localized: "vaults.servers")),
        ("cpu.fill", String(localized: "vaults.hardware")),
        ("wifi", String(localized: "vaults.wiFi")),
        ("atom", String(localized: "vaults.science")),
        ("testtube.2", String(localized: "vaults.lab")),
        ("key.fill", String(localized: "app.key")),
        ("lock.fill", String(localized: "vaults.lock")),
        ("shield.fill", String(localized: "vaults.shield")),
        ("flag.fill", String(localized: "vaults.flag")),
        ("sparkles", String(localized: "vaults.sparkles")),
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
        case "red": String(localized: "vaults.red")
        case "orange": String(localized: "vaults.orange")
        case "amber": String(localized: "vaults.amber")
        case "yellow": String(localized: "vaults.yellow")
        case "lime": String(localized: "vaults.lime")
        case "green": String(localized: "vaults.green")
        case "mint": String(localized: "vaults.mint")
        case "teal": String(localized: "vaults.teal")
        case "cyan": String(localized: "vaults.cyan")
        case "sky": String(localized: "vaults.sky")
        case "blue": String(localized: "vaults.blue")
        case "indigo": String(localized: "vaults.indigo")
        case "purple": String(localized: "vaults.purple")
        case "pink": String(localized: "vaults.pink")
        case "rose": String(localized: "vaults.rose")
        case "brown": String(localized: "vaults.brown")
        case "graphite": String(localized: "vaults.graphite")
        case "gray": String(localized: "vaults.gray")
        default: String(localized: "vaults.gray")
        }
    }

    static func iconLabel(_ name: String) -> String {
        catalog.first { $0.symbol == symbol(name) }?.label ?? name
    }
}

/// A vault's mark: a disc in a soft gradient of its color with the symbol in white, a light from
/// the top left and a hairline rim. Round, so a vault never reads as one of the library's square
/// rows (Tous les éléments, Favoris...).
struct VaultIconTile: View {
    let icon: String
    let colorName: String
    var size: CGFloat = 30

    var body: some View {
        let color = VaultBadge.color(named: colorName)
        Circle()
            .fill(LinearGradient(colors: [color.mix(with: .white, by: 0.22), color, color.mix(with: .black, by: 0.18)],
                startPoint: .topLeading, endPoint: .bottomTrailing))
            .overlay {
                // Soft sheen on the upper left.
                Circle()
                    .fill(RadialGradient(colors: [.white.opacity(0.28), .clear],
                        center: UnitPoint(x: 0.3, y: 0.22), startRadius: 0, endRadius: size * 0.55))
            }
            .overlay { Circle().strokeBorder(.white.opacity(0.2), lineWidth: 0.5) }
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: VaultStyle.symbol(icon))
                    .font(.system(size: size * 0.46, weight: .semibold))
                    .foregroundStyle(.white)
                    .shadow(color: .black.opacity(0.18), radius: 0.6, y: 0.6)
            }
            .shadow(color: color.opacity(0.25), radius: size * 0.08, y: size * 0.04)
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
                        TextField("vaults.vaultName", text: $name, prompt: Text("Projet Atlas"))
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
                Section("vaults.color") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 30, maximum: 34), spacing: 8)], spacing: 10) {
                        ForEach(VaultStyle.colors, id: \.self) { name in
                            colorButton(name)
                        }
                    }
                    .padding(.vertical, 6)
                }
                Section("vaults.icon") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 40, maximum: 46), spacing: 8)], spacing: 8) {
                        ForEach(VaultStyle.icons, id: \.self) { symbol in
                            iconButton(symbol)
                        }
                    }
                    .padding(.vertical, 6)
                }
                Section {
                    Toggle("app.safeForTravel", isOn: $travelSafe)
                        .accessibilityIdentifier("vault.editor.travelSafe")
                } footer: {
                    Text("vaults.inTravelModeVaults")
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
            .navigationTitle(vault == nil ? Text("Nouveau coffre") : Text("term.vault"))
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
            Button("vaults.deleteVault", systemImage: "trash", role: .destructive) { confirmDelete = true }
                .disabled(last || !empty || saving)
                .accessibilityIdentifier("vault.editor.delete")
        } footer: {
            if last {
                Text("vaults.lastVaultCantDeleted")
            } else if !empty {
                Text("vaults.emptyVaultBeforeDeleting")
            }
        }
        .confirmationDialog(
            Text("Supprimer « \(vault.meta.name) » ?"), isPresented: $confirmDelete, titleVisibility: .visible
        ) {
            Button("vaults.deleteVault", role: .destructive) { delete(vault) }
                .accessibilityIdentifier("vault.editor.delete.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("vaults.itDisappearsFromAll")
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
                    Circle()
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
                Circle()
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
