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
        ("figure.and.child.holdinghands", String(localized: "Famille")),
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
        ("globe.europe.africa.fill", String(localized: "vaults.world")),
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
        ("note.text", String(localized: "vaults.writing")),
        ("paintpalette.fill", String(localized: "vaults.art")),
        ("music.note", String(localized: "vaults.music")),
        ("film.fill", String(localized: "vaults.movies")),
        ("camera.fill", String(localized: "vaults.photo")),
        ("gamecontroller.fill", String(localized: "vaults.games")),
        ("dice.fill", String(localized: "vaults.dice")),
        ("puzzlepiece.fill", String(localized: "vaults.puzzle")),
        ("tennisball.fill", String(localized: "vaults.sports")),
        ("dumbbell.fill", String(localized: "vaults.fitness")),
        ("shoe.fill", String(localized: "vaults.running")),
        ("cross.case.fill", String(localized: "vaults.health")),
        ("pills.fill", String(localized: "vaults.medication")),
        ("pawprint.fill", String(localized: "vaults.pets")),
        ("cup.and.saucer.fill", String(localized: "vaults.coffee")),
        ("fork.knife", String(localized: "vaults.restaurants")),
        ("wrench.and.screwdriver.fill", String(localized: "vaults.tools")),
        ("hammer.fill", String(localized: "vaults.diy")),
        ("terminal.fill", String(localized: "vaults.terminal")),
        ("curlybraces", String(localized: "vaults.code")),
        ("server.rack", String(localized: "vaults.servers")),
        ("cpu.fill", String(localized: "vaults.hardware")),
        ("wifi", String(localized: "vaults.wiFi")),
        ("atom", String(localized: "vaults.science")),
        ("flask.fill", String(localized: "vaults.lab")),
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

    /// Symbols the 2026-11-25 audit swapped for a stronger sibling: thin or very wide glyphs that
    /// read as a smudge at 16 pt (menus, item header) or as a different weight from their
    /// neighbours. A vault saved with the old name draws the new one, and is stored with it the
    /// next time it is saved; nothing is migrated in the core.
    static let renamed: [String: String] = [
        "figure.2.and.child.holdinghands": "figure.and.child.holdinghands",
        "globe.americas.fill": "globe.europe.africa.fill",
        "pencil.and.outline": "note.text",
        "paintbrush.fill": "paintpalette.fill",
        "figure.run": "shoe.fill",
        "chevron.left.forwardslash.chevron.right": "curlybraces",
        "testtube.2": "flask.fill",
    ]

    /// Optical size of each glyph against a typical one (about 100 x 100 at 100 pt). SF Symbols
    /// share a cap height, not an ink area: a mountain range is twice as wide as a lock, so in the
    /// same disc one shouts and the other whispers. Measured once on the semibold glyphs
    /// (scale = 102 / sqrt(ink width x ink height), kept within 0.8...1.15 and to 138 pt on the
    /// long side), rounded to 0.02; glyphs within 5% of 1 are left out. Diagonal tools (hammer,
    /// wrench) are nudged up by hand: their bounding box overstates their ink.
    static let opticalScale: [String: CGFloat] = [
        "archivebox.fill": 1.06, "house.fill": 0.90, "building.2.fill": 0.92,
        "building.columns.fill": 0.90, "briefcase.fill": 0.94, "person.fill": 1.14,
        "person.2.fill": 0.94, "heart.fill": 1.06, "star.fill": 0.94, "crown.fill": 0.88,
        "bag.fill": 1.06, "chart.bar.fill": 0.92, "doc.text.fill": 1.06, "phone.fill": 1.08,
        "bubble.left.and.bubble.right.fill": 0.80, "sailboat.fill": 0.82, "tram.fill": 0.94,
        "mountain.2.fill": 0.80, "tent.fill": 0.82, "tree.fill": 0.80, "flame.fill": 1.08,
        "drop.fill": 1.14, "bolt.fill": 1.12, "sun.max.fill": 0.92, "snowflake": 1.08,
        "graduationcap.fill": 0.80, "note.text": 1.06, "paintpalette.fill": 0.92,
        "music.note": 1.14, "camera.fill": 0.94, "gamecontroller.fill": 0.88,
        "puzzlepiece.fill": 0.86, "shoe.fill": 0.90, "cross.case.fill": 0.94, "pills.fill": 0.92,
        "cup.and.saucer.fill": 0.90, "fork.knife": 1.12, "wrench.and.screwdriver.fill": 0.94,
        "hammer.fill": 0.94, "wifi": 1.08, "atom": 0.90, "key.fill": 1.12, "lock.fill": 1.14,
        "shield.fill": 1.14, "flag.fill": 1.10,
    ]

    /// Glyph height against its disc, the same for every mark and every size, so a vault looks
    /// the same in the sidebar (24 pt), a menu (16 pt) and the editor's preview (76 pt).
    static let glyphRatio: CGFloat = 0.46

    /// The point size of `symbol` drawn in a disc of `size`.
    static func glyphSize(_ symbol: String, in size: CGFloat) -> CGFloat {
        size * glyphRatio * (opticalScale[symbol] ?? 1)
    }

    /// The one colour rule for a glyph drawn in the vault's colour on a pale disc (the "Teinté"
    /// mark and the editor's idle symbols): deepened a touch on light pages for contrast, lifted
    /// on dark ones so it does not sink into the disc.
    static func glyphColor(_ tint: Color, dark: Bool) -> Color {
        dark ? tint.mix(with: .white, by: 0.25) : tint.mix(with: .black, by: 0.1)
    }

    /// The pale disc behind such a glyph, by the same rule.
    static func paleFill(_ tint: Color, dark: Bool) -> Color {
        tint.opacity(dark ? 0.22 : 0.14)
    }

    /// How a vault's mark is drawn. Stored after the symbol in the vault's icon string
    /// ("person.fill#glass"), so it syncs with the vault without a new field in the core: an older
    /// app reads an unknown symbol and draws a folder, nothing breaks. No suffix is the classic disc.
    enum Mark: String, CaseIterable {
        case classic = ""
        case tinted
        case glass

        var label: String {
            switch self {
            case .classic: String(localized: "vaults.style.classic")
            case .tinted: String(localized: "vaults.style.tinted")
            case .glass: String(localized: "vaults.style.glass")
            }
        }
    }

    static let markSeparator: Character = "#"

    /// The stored icon string split into its symbol (as stored) and its mark. An unknown mark is
    /// drawn classic.
    static func split(_ icon: String) -> (symbol: String, mark: Mark) {
        guard let index = icon.firstIndex(of: markSeparator) else { return (icon, .classic) }
        let suffix = String(icon[icon.index(after: index)...])
        return (String(icon[..<index]), Mark(rawValue: suffix) ?? .classic)
    }

    /// The icon string to store for `symbol` drawn as `mark`.
    static func compose(symbol: String, mark: Mark) -> String {
        mark == .classic ? symbol : symbol + String(markSeparator) + mark.rawValue
    }

    /// The symbol to draw: a stored legacy outline name becomes its filled sibling.
    static func symbol(_ stored: String) -> String {
        let stored = split(stored).symbol
        let icon = renamed[stored] ?? stored
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

/// A vault's mark: a disc in the vault's color with its symbol. Round on purpose, so a vault never
/// reads as one of the library's square rows (Tous les éléments, Favoris...). The three marks share
/// one glyph (same size, weight and optical correction, `VaultGlyph`) and differ only in the disc,
/// so switching the mark never makes the symbol jump.
struct VaultIconTile: View {
    let icon: String
    let colorName: String
    var size: CGFloat = 30
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Group {
            switch VaultStyle.split(icon).mark {
            case .classic: classic
            case .tinted: tinted
            case .glass: glass
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    private var dark: Bool { colorScheme == .dark }
    private var color: Color { VaultBadge.color(named: colorName) }
    private var symbol: String { VaultStyle.symbol(icon) }

    /// Light, rim and shadow are drawn from 24 pt up: under that (menus, the item header's vault
    /// chip) they only blur the edge of a 16 pt disc.
    private var detailed: Bool { size >= 24 }

    /// "Teinté": a pale disc of the color, the symbol in the color.
    private var tinted: some View {
        Circle()
            .fill(VaultStyle.paleFill(color, dark: dark))
            .overlay {
                VaultGlyph(symbol: symbol, size: size)
                    .foregroundStyle(VaultStyle.glyphColor(color, dark: dark))
            }
    }

    /// "Verre": a translucent disc of the color, light on its upper half, a hairline rim brighter at
    /// the top, the symbol in white.
    private var glass: some View {
        Circle()
            .fill(color.opacity(dark ? 0.55 : 0.7))
            .overlay {
                if detailed {
                    Circle()
                        .fill(LinearGradient(colors: [.white.opacity(0.22), .clear], startPoint: .top,
                            endPoint: .center))
                        .padding(size * 0.03)
                    Circle().strokeBorder(
                        LinearGradient(colors: [.white.opacity(0.55), .white.opacity(0.08)], startPoint: .top,
                            endPoint: .bottom),
                        lineWidth: max(0.5, size * 0.025))
                }
            }
            .overlay {
                VaultGlyph(symbol: symbol, size: size).foregroundStyle(.white)
            }
    }

    /// The first mark: a gradient disc with a sheen and the symbol in white.
    private var classic: some View {
        Circle()
            .fill(LinearGradient(colors: [color.mix(with: .white, by: 0.22), color, color.mix(with: .black, by: 0.18)],
                startPoint: .topLeading, endPoint: .bottomTrailing))
            .overlay {
                if detailed {
                    // Soft sheen on the upper left.
                    Circle()
                        .fill(RadialGradient(colors: [.white.opacity(0.28), .clear],
                            center: UnitPoint(x: 0.3, y: 0.22), startRadius: 0, endRadius: size * 0.55))
                    Circle().strokeBorder(.white.opacity(0.2), lineWidth: 0.5)
                }
            }
            .overlay {
                VaultGlyph(symbol: symbol, size: size)
                    .foregroundStyle(.white)
                    .shadow(color: .black.opacity(detailed ? 0.18 : 0), radius: 0.6, y: 0.6)
            }
            .shadow(color: color.opacity(detailed ? 0.25 : 0), radius: size * 0.08, y: size * 0.04)
    }
}

/// A vault symbol at its optical size for a disc of `size`: semibold everywhere, centred in a
/// square box so a tall glyph (key) and a wide one (mountains) share one centre. The editor's grid
/// uses it too, so the idle symbols match the chosen one exactly.
struct VaultGlyph: View {
    let symbol: String
    let size: CGFloat

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: VaultStyle.glyphSize(symbol, in: size), weight: .semibold))
            .symbolRenderingMode(.monochrome)
            .frame(width: size, height: size)
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
    @State private var mark: VaultStyle.Mark
    @State private var color: String
    /// Stays on the device in Travel Mode (synced with the vault).
    @State private var travelSafe: Bool
    @State private var saving = false
    @State private var errorMessage: String?
    @State private var confirmDelete = false
    @FocusState private var nameFocused: Bool

    @State private var sharingVault = false

    init(vault: FfiVault?, onDone: @escaping () -> Void) {
        self.vault = vault
        self.onDone = onDone
        _name = State(initialValue: vault?.meta.name ?? "")
        _icon = State(initialValue: vault.map { VaultStyle.symbol($0.meta.icon) } ?? "folder.fill")
        // A new vault starts tinted; an existing one keeps its mark (classic when it has none).
        _mark = State(initialValue: vault.map { VaultStyle.split($0.meta.icon).mark } ?? .tinted)
        _color = State(initialValue: vault?.meta.color ?? "blue")
        _travelSafe = State(initialValue: vault?.meta.travelSafe ?? false)
    }

    /// The icon string saved with the vault: the symbol and its mark.
    private var stored: String { VaultStyle.compose(symbol: icon, mark: mark) }

    private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }
    private var canSave: Bool { !trimmed.isEmpty && !saving }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: Theme.Space.m) {
                        VaultIconTile(icon: stored, colorName: color, size: 76)
                            .shadow(color: VaultBadge.color(named: color).opacity(0.35), radius: 14, y: 6)
                            .animation(.spring(duration: 0.35, bounce: 0.3), value: color)
                            .animation(.spring(duration: 0.35, bounce: 0.3), value: icon)
                            .animation(.spring(duration: 0.35, bounce: 0.3), value: mark)
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
                            .background(.fill.quaternary, in: .rect(cornerRadius: Theme.Radius.control, style: .continuous))
                            .accessibilityIdentifier("vault.editor.name")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Theme.Space.m)
                }
                Section("vaults.style") {
                    HStack(spacing: Theme.Space.xl) {
                        ForEach(VaultStyle.Mark.allCases, id: \.self) { option in
                            markButton(option)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, Theme.Space.s)
                }
                Section("vaults.color") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 30, maximum: 34), spacing: Theme.Space.s)],
                        spacing: Theme.Space.m) {
                        ForEach(VaultStyle.colors, id: \.self) { name in
                            colorButton(name)
                        }
                    }
                    .padding(.vertical, Theme.Space.s)
                }
                Section("vaults.icon") {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 46, maximum: 52), spacing: Theme.Space.s)],
                        spacing: Theme.Space.s) {
                        ForEach(VaultStyle.icons, id: \.self) { symbol in
                            iconButton(symbol)
                        }
                    }
                    .padding(.vertical, Theme.Space.s)
                }
                Section {
                    Toggle("app.safeForTravel", isOn: $travelSafe)
                        .accessibilityIdentifier("vault.editor.travelSafe")
                } footer: {
                    Text("vaults.inTravelModeVaults")
                }
                if let vault {
                    shareSection(vault)
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

    /// "Partage" (sharing spec 10): the members of a shared vault, or "Partager" on a private one.
    @ViewBuilder private func shareSection(_ vault: FfiVault) -> some View {
        Section("sharing.vault.section") {
            if model.session.sharedRole(of: vault.id) != nil {
                NavigationLink {
                    MembersView(vaultID: vault.id)
                } label: {
                    Label("sharing.vault.members", systemImage: "person.2")
                }
                .accessibilityIdentifier("vault.editor.members")
            } else {
                Button {
                    sharingVault = true
                } label: {
                    Label("sharing.vault.share", systemImage: "person.crop.circle.badge.plus")
                }
                .accessibilityIdentifier("vault.editor.share")
                .sheet(isPresented: $sharingVault) { ShareVaultSheet(vaultID: vault.id) }
            }
        }
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

    /// Every picker cell (mark, colour, symbol) is a disc with the same selection ring: 2 pt,
    /// 3 pt away from the disc, so the ring stays concentric whatever the disc's size.
    private static let ringGap: CGFloat = 3
    private static let ringWidth: CGFloat = 2
    /// The disc of a mark and of a symbol cell: one size, so the chosen symbol in the grid is the
    /// very tile shown in the mark row.
    private static let cellSize: CGFloat = 40

    private func selectionRing<Content: View>(_ selected: Bool, tint: Color, @ViewBuilder _ content: () -> Content)
        -> some View
    {
        content()
            .padding(Self.ringGap)
            .overlay { Circle().strokeBorder(selected ? tint : .clear, lineWidth: Self.ringWidth) }
    }

    /// A symbol of the grid, already in the vault's color: the "Teinté" disc when idle (one colour
    /// rule with the mark, `VaultStyle.glyphColor`), the full tile in the chosen mark once picked.
    private func iconButton(_ symbol: String) -> some View {
        let selected = icon == symbol
        let tint = VaultBadge.color(named: color)
        let shown = VaultStyle.compose(symbol: symbol, mark: selected ? mark : .tinted)
        return Button {
            withAnimation(.spring(duration: 0.3, bounce: 0.3)) { icon = symbol }
        } label: {
            selectionRing(selected, tint: tint) {
                VaultIconTile(icon: shown, colorName: color, size: Self.cellSize)
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .help(VaultStyle.iconLabel(symbol))
        .visionHoverEffect()
        .accessibilityLabel(Text(VaultStyle.iconLabel(symbol)))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("vault.editor.icon.\(symbol)")
    }

    /// A mark to choose, drawn with the vault's symbol and color, its name under it.
    private func markButton(_ option: VaultStyle.Mark) -> some View {
        let selected = mark == option
        let tint = VaultBadge.color(named: color)
        return Button {
            withAnimation(.spring(duration: 0.3, bounce: 0.3)) { mark = option }
        } label: {
            VStack(spacing: Theme.Space.s) {
                selectionRing(selected, tint: tint) {
                    VaultIconTile(icon: VaultStyle.compose(symbol: icon, mark: option), colorName: color,
                        size: Self.cellSize)
                }
                Text(option.label)
                    .font(.caption)
                    .foregroundStyle(selected ? .primary : .secondary)
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .visionHoverEffect()
        .accessibilityLabel(Text(option.label))
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("vault.editor.mark.\(option == .classic ? "classic" : option.rawValue)")
    }

    /// A color dot; the chosen one gets the same ring as the symbols.
    private func colorButton(_ colorName: String) -> some View {
        let selected = color == colorName
        let fill = VaultBadge.color(named: colorName)
        return Button {
            withAnimation(.spring(duration: 0.3, bounce: 0.3)) { color = colorName }
        } label: {
            selectionRing(selected, tint: fill) {
                Circle()
                    .fill(fill.gradient)
                    .frame(width: 24, height: 24)
            }
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
            name: trimmed, icon: stored, color: color,
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
