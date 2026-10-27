import DesignKit
import SwiftUI
import UniformTypeIdentifiers
import VaultKit

/// A password manager or browser an export can come from, with the core formats it writes (the
/// first one is used when the content does not say which) and where its export lives.
struct ImportSource: Identifiable, Hashable {
    let id: String
    let name: String
    let formats: [String]
    let hint: String

    /// "Détecter automatiquement": the format comes from the content alone.
    static let automatic = ImportSource(
        id: "auto", name: String(localized: "Détecter automatiquement"), formats: [],
        hint: String(localized: "OnePass reconnaît le format d'après le contenu du fichier."))

    static let all: [ImportSource] = [
        ImportSource(
            id: "apple", name: String(localized: "Mots de passe d'Apple"), formats: ["safari-csv"],
            hint: String(localized: "App Mots de passe : Fichier > Exporter tous les mots de passe vers un fichier.")),
        ImportSource(
            id: "safari", name: "Safari", formats: ["safari-csv"],
            hint: String(localized: "Fichier > Exporter les données de navigation, avec les mots de passe (.zip ou .csv).")),
        ImportSource(
            id: "1password", name: "1Password", formats: ["1pux", "1password-csv"],
            hint: String(localized: "Fichier > Exporter, puis le format 1PUX (ou CSV).")),
        ImportSource(
            id: "bitwarden", name: "Bitwarden", formats: ["bitwarden-json", "bitwarden-csv"],
            hint: String(localized: "Outils > Exporter le coffre, en .json non chiffré ou en .csv.")),
        ImportSource(
            id: "nordpass", name: "NordPass", formats: ["nordpass-csv"],
            hint: String(localized: "Réglages > Importer et exporter > Exporter les éléments (.csv).")),
        ImportSource(
            id: "dashlane", name: "Dashlane", formats: ["dashlane-zip", "dashlane-csv"],
            hint: String(localized: "Réglages > Exporter les données > CSV (le .zip ou un des fichiers .csv).")),
        ImportSource(
            id: "lastpass", name: "LastPass", formats: ["lastpass-csv"],
            hint: String(localized: "Options avancées > Exporter > fichier CSV LastPass.")),
        ImportSource(
            id: "protonpass", name: "Proton Pass", formats: ["protonpass-csv"],
            hint: String(localized: "Réglages > Exporter, au format CSV.")),
        ImportSource(
            id: "keeper", name: "Keeper", formats: ["keeper-csv"],
            hint: String(localized: "Réglages > Exporter > fichier .csv.")),
        ImportSource(
            id: "enpass", name: "Enpass", formats: ["enpass-json"],
            hint: String(localized: "Fichier > Exporter, au format .json.")),
        ImportSource(
            id: "roboform", name: "RoboForm", formats: ["roboform-csv"],
            hint: String(localized: "Options > Exporter les identifiants et les notes (.csv).")),
        ImportSource(
            id: "keepass", name: "KeePass, KeePassXC", formats: ["keepass-xml"],
            hint: String(localized: "Fichier > Exporter en XML KeePass 2 (le .kdbx ne se lit pas directement).")),
        ImportSource(
            id: "chrome", name: "Google Chrome", formats: ["chrome-csv"],
            hint: String(localized: "Gestionnaire de mots de passe Google > Paramètres > Exporter les mots de passe.")),
        ImportSource(
            id: "edge", name: "Microsoft Edge", formats: ["chrome-csv"],
            hint: String(localized: "Paramètres > Mots de passe > ⋯ > Exporter les mots de passe.")),
        ImportSource(
            id: "brave", name: "Brave", formats: ["chrome-csv"],
            hint: String(localized: "brave://password-manager/settings > Exporter les mots de passe.")),
        ImportSource(
            id: "opera", name: "Opera", formats: ["chrome-csv"],
            hint: String(localized: "Réglages > Mots de passe > ⋯ > Exporter les mots de passe.")),
        ImportSource(
            id: "arc", name: "Arc", formats: ["chrome-csv"],
            hint: String(localized: "arc://password-manager/settings > Exporter les mots de passe.")),
        ImportSource(
            id: "vivaldi", name: "Vivaldi", formats: ["chrome-csv"],
            hint: String(localized: "Réglages > Confidentialité > Mots de passe > Exporter.")),
        ImportSource(
            id: "firefox", name: "Firefox", formats: ["firefox-csv"],
            hint: String(localized: "about:logins > ⋯ > Exporter les identifiants.")),
        ImportSource(
            id: "cxf", name: String(localized: "Autre gestionnaire (Credential Exchange)"), formats: ["cxf"],
            hint: String(localized: "Fichier .json au format d'échange d'identifiants (CXF).")),
        ImportSource(
            id: "otpauth", name: String(localized: "Codes à usage unique"), formats: ["otpauth"],
            hint: String(localized: "Liens otpauth:// (Google Authenticator et autres), un par ligne.")),
        ImportSource(
            id: "wifi", name: String(localized: "Réseaux Wi-Fi (codes QR)"), formats: ["wifi-qr"],
            hint: String(localized: "Texte des codes QR Wi-Fi (WIFI:S:...), un par ligne.")),
        ImportSource(
            id: "onepass", name: String(localized: "OnePass (export CSV)"), formats: ["onepass-csv"],
            hint: String(localized: "Le fichier CSV en clair exporté par OnePass.")),
    ]

    /// Display name of a core format, for the preview.
    static func name(ofFormat format: String) -> String {
        switch format {
        case "safari-csv": String(localized: "Mots de passe d'Apple, Safari (CSV)")
        case "chrome-csv": String(localized: "Chrome et navigateurs Chromium (CSV)")
        default: all.first { $0.formats.contains(format) }?.name ?? format
        }
    }
}

/// Holds the bytes of the chosen export between the preview and the import, and wipes them as soon
/// as they are no longer needed (import done, other file, sheet closed). Never logged.
@MainActor
private final class ImportBuffer {
    private(set) var data = Data()

    func replace(with new: Data) {
        wipe()
        data = new
    }

    func wipe() {
        VaultSession.wipeImportBuffer(&data)
        data = Data()
    }
}

/// "Importer…" (Fichier menu, ⌘⇧I, and Réglages > Général): drop the export or choose its source,
/// check what it holds, choose the vault, import. The file is read on this device only, never kept:
/// its bytes are wiped once the import is done or the sheet closes. Laid out like the ⌘N type
/// picker (`NewItemSheet`): custom header, searchable grid of colored tiles.
struct ImportSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    /// The source the next chosen file is read as (`.automatic` for a dropped file).
    @State private var source: ImportSource?
    /// The tile whose export steps are shown under the grid.
    @State private var selected: ImportSource?
    @State private var query = ""
    @State private var dropTargeted = false
    @State private var picking = false
    @State private var buffer = ImportBuffer()
    @State private var fileName = ""
    @State private var format: String?
    @State private var preview: FfiImportSummary?
    @State private var vaultID = ""
    @State private var busy = false
    @State private var errorMessage: String?

    private static let calloutID = "import.callout"

    var body: some View {
        ZStack {
            if let preview, let format {
                previewStep(preview, format: format)
                    .transition(.move(edge: .trailing).combined(with: .opacity))
            } else {
                sourceStep
                    .transition(.move(edge: .leading).combined(with: .opacity))
            }
        }
        .clipped()
        .disabled(busy)
        .overlay {
            if busy { busyOverlay.transition(.opacity) }
        }
        .animation(.easeInOut(duration: 0.25), value: preview != nil)
        .animation(.easeInOut(duration: 0.2), value: busy)
        .animation(.easeInOut(duration: 0.2), value: errorMessage)
        .fileImporter(isPresented: $picking, allowedContentTypes: [.data]) { result in
            switch result {
            case .success(let url): Task { await load(url) }
            case .failure: break
            }
        }
        .presentationDetents([.large])
        #if os(macOS)
        .frame(width: 620, height: 600)
        #endif
        .onAppear {
            if vaultID.isEmpty { vaultID = defaultVaultID }
        }
        .onDisappear { buffer.wipe() }
    }

    // MARK: - Shared pieces

    private func header(_ subtitle: LocalizedStringKey, showsCancel: Bool) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Importer").font(.title2.weight(.semibold))
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if showsCancel { cancelButton }
        }
        .padding(.horizontal, 20)
        .padding(.top, 18)
        .padding(.bottom, 14)
    }

    private var cancelButton: some View {
        Button("Annuler") { dismiss() }
            .keyboardShortcut(.cancelAction)
            .accessibilityIdentifier("import.cancel")
    }

    private func sectionTitle(_ title: LocalizedStringKey) -> some View {
        Text(title)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.leading, 4)
    }

    /// Red callout: the file could not be read, recognized or imported.
    private func errorCallout(_ message: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Text(message)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(.callout)
        .padding(12)
        .background(Color.red.opacity(0.1), in: .rect(cornerRadius: 12))
        .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(Color.red.opacity(0.35)) }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("import.error")
        .transition(.opacity)
    }

    private var busyOverlay: some View {
        VStack(spacing: 12) {
            ProgressView().controlSize(.large)
            if preview == nil {
                Text("Lecture du fichier…")
            } else {
                Text("Import en cours…")
            }
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 28)
        .padding(.vertical, 22)
        .background(.regularMaterial, in: .rect(cornerRadius: 16))
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.black.opacity(0.08))
    }

    // MARK: - Step 1: source

    private var sourceStep: some View {
        VStack(spacing: 0) {
            header("Depuis un autre gestionnaire ou un navigateur", showsCancel: true)
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        if let errorMessage { errorCallout(errorMessage) }
                        dropZone
                        sourcePicker
                        privacyNote
                    }
                    .padding(20)
                }
                .onChange(of: selected) { _, new in
                    guard new != nil else { return }
                    // Once the callout is laid out: bring it (and its button) into view.
                    Task { @MainActor in
                        try? await Task.sleep(for: .milliseconds(80))
                        withAnimation(.easeInOut(duration: 0.25)) {
                            proxy.scrollTo(Self.calloutID, anchor: .bottom)
                        }
                    }
                }
            }
        }
        // The whole step takes the drop, the zone lights up.
        .dropDestination(for: URL.self) { urls, _ in
            guard !busy, let url = urls.first(where: \.isFileURL) else { return false }
            source = .automatic
            errorMessage = nil
            Task { await load(url) }
            return true
        } isTargeted: { dropTargeted = $0 }
    }

    /// Dashed zone: drop the export, or click to choose it. The format comes from the content.
    private var dropZone: some View {
        Button {
            pickFile(as: .automatic)
        } label: {
            VStack(spacing: 12) {
                Image(systemName: dropTargeted ? "tray.and.arrow.down.fill" : "tray.and.arrow.down")
                    .font(.system(size: 24, weight: .medium))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 54, height: 54)
                    .background(Theme.accent.opacity(dropTargeted ? 0.22 : 0.13), in: .circle)
                VStack(spacing: 3) {
                    Text("Dépose ton export ici")
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Text("ou choisis un fichier")
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(Theme.accent)
                }
                Text(ImportSource.automatic.hint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 26)
            .padding(.horizontal, 20)
            .background(Theme.accent.opacity(dropTargeted ? 0.12 : 0.04), in: .rect(cornerRadius: 16))
            .overlay {
                RoundedRectangle(cornerRadius: 16)
                    .strokeBorder(
                        Theme.accent.opacity(dropTargeted ? 0.9 : 0.45),
                        style: StrokeStyle(lineWidth: 1.5, dash: [6, 5]))
            }
            .contentShape(.rect(cornerRadius: 16))
            .scaleEffect(dropTargeted ? 1.01 : 1)
        }
        .buttonStyle(.plain)
        .animation(.easeInOut(duration: 0.15), value: dropTargeted)
        .accessibilityIdentifier("import.source.auto")
    }

    private var groups: [ImportSourceGroup] {
        let needle = query.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else { return ImportSourceGroup.all }
        return ImportSourceGroup.all.compactMap { group in
            let sources = group.sources.filter { $0.name.localizedStandardContains(needle) }
            return sources.isEmpty ? nil : ImportSourceGroup(id: group.id, title: group.title, sources: sources)
        }
    }

    private var sourcePicker: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Ou choisis la source").font(.headline)
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Rechercher une source", text: $query)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("import.search")
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(.quaternary.opacity(0.6), in: .rect(cornerRadius: 8))

            if groups.isEmpty {
                ContentUnavailableView.search(text: query).padding(.vertical, 12)
            } else {
                VStack(alignment: .leading, spacing: 18) {
                    ForEach(groups) { group in
                        VStack(alignment: .leading, spacing: 8) {
                            sectionTitle(group.title)
                            LazyVGrid(columns: [GridItem(.adaptive(minimum: 168), spacing: 8)], spacing: 8) {
                                ForEach(group.sources) { s in
                                    ImportSourceTile(source: s, isSelected: selected == s) {
                                        selected = selected == s ? nil : s
                                        errorMessage = nil
                                    }
                                }
                            }
                            // The steps open under the group of the chosen tile, not at the bottom.
                            if let selected, group.sources.contains(selected) {
                                exportSteps(selected)
                                    .id(Self.calloutID)
                                    .transition(.opacity.combined(with: .move(edge: .top)))
                            }
                        }
                    }
                }
                .animation(.easeInOut(duration: 0.2), value: selected)
            }
        }
    }

    /// Where the chosen source keeps its export, one step per menu level, then the file picker.
    private func exportSteps(_ s: ImportSource) -> some View {
        let steps = Self.steps(of: s.hint)
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                ImportSourceGlyph(source: s, size: 24)
                Text("Exporte depuis \(s.name)").font(.subheadline.weight(.semibold))
                Spacer(minLength: 0)
            }
            VStack(alignment: .leading, spacing: 8) {
                if steps.count == 1 {
                    Text(steps[0])
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                        HStack(alignment: .top, spacing: 10) {
                            Text(index + 1, format: .number)
                                .font(.caption2.weight(.bold))
                                .monospacedDigit()
                                .foregroundStyle(.white)
                                .frame(width: 18, height: 18)
                                .background(Theme.accent, in: .circle)
                            Text(step)
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(.top, 1)
                        }
                    }
                }
            }
            HStack {
                Spacer()
                Button {
                    pickFile(as: s)
                } label: {
                    Label("Choisir le fichier", systemImage: "doc.badge.plus")
                }
                .buttonStyle(.borderedProminent)
                .tint(Theme.accent)
                .accessibilityIdentifier("import.pick")
            }
        }
        .padding(14)
        .background(Theme.accent.opacity(0.07), in: .rect(cornerRadius: 12))
        .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.accent.opacity(0.25)) }
    }

    private var privacyNote: some View {
        Label {
            Text("Le fichier est lu sur cet appareil, jamais envoyé ni gardé. Supprime l'export une fois l'import fait : il contient tes mots de passe en clair.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "lock.fill")
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 4)
    }

    // MARK: - Step 2: preview

    private func previewStep(_ p: FfiImportSummary, format: String) -> some View {
        VStack(spacing: 0) {
            header("Vérifie ce que contient le fichier avant de l'importer", showsCancel: false)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    fileCard(format: format)
                    contentSection(p)
                    destinationSection
                }
                .padding(20)
            }
            if let errorMessage {
                errorCallout(errorMessage)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 12)
            }
            Divider()
            footerBar(p)
        }
    }

    private func fileCard(format: String) -> some View {
        EditorCard {
            HStack(spacing: 14) {
                Image(systemName: "doc.text.fill")
                    .font(.system(size: 21))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 44, height: 44)
                    .background(Theme.accent.opacity(0.14), in: .rect(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 4) {
                    Text(fileName)
                        .font(.headline)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Label {
                        Text(ImportSource.name(ofFormat: format))
                    } icon: {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                    }
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .padding(14)
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private func contentSection(_ p: FfiImportSummary) -> some View {
        let notes: [(symbol: String, text: String)] =
            p.warnings.map { ("info.circle", Self.warningLine($0)) }
            + (p.skipped > 0 ? [("arrow.uturn.right", Self.skippedLine(p.skipped))] : [])
        VStack(alignment: .leading, spacing: 8) {
            sectionTitle("Contenu")
            if p.items == 0 {
                EditorCard {
                    Label("Aucun élément à importer dans ce fichier.", systemImage: "tray")
                        .foregroundStyle(.secondary)
                        .editorRowPadding()
                }
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 128), spacing: 8)], spacing: 8) {
                    ForEach(p.byType, id: \.itemType) { countTile($0) }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(Self.countsLine(p.byType))
                .accessibilityIdentifier("import.counts")
            }
            if !notes.isEmpty {
                EditorCard {
                    ForEach(Array(notes.enumerated()), id: \.offset) { index, note in
                        if index > 0 { CardDivider() }
                        Label(note.text, systemImage: note.symbol)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .editorRowPadding()
                    }
                }
            }
            Text("Chaque élément est ajouté avec un nouvel identifiant : rien de ce qui est déjà dans OnePass n'est remplacé. Le dossier d'origine devient un tag.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 4)
        }
    }

    /// "3 / identifiants" under the type's colored glyph.
    private func countTile(_ c: FfiImportTypeCount) -> some View {
        let n = Int(c.count)
        return EditorCard {
            VStack(alignment: .leading, spacing: 10) {
                CategoryTile(category: .of(c.itemType), size: 26)
                VStack(alignment: .leading, spacing: 0) {
                    Text(n, format: .number)
                        .font(.system(size: 28, weight: .semibold, design: .rounded))
                        .monospacedDigit()
                    Text(Self.typeLabel(c.itemType, n))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }
            .padding(14)
        }
    }

    private var destinationSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionTitle("Destination")
            EditorCard {
                HStack(spacing: 12) {
                    Image(systemName: "lock.rectangle.stack.fill")
                        .foregroundStyle(Theme.accent)
                    Text("Coffre")
                    Spacer(minLength: 12)
                    Picker("Coffre", selection: $vaultID) {
                        ForEach(model.session.vaults, id: \.id) { vault in
                            Text(vault.meta.name).tag(vault.id)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .fixedSize()
                    .accessibilityIdentifier("import.vault")
                }
                .editorRowPadding()
            }
        }
    }

    private func footerBar(_ p: FfiImportSummary) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                otherFileButton
                Spacer(minLength: 12)
                cancelButton
                importButton(p)
            }
            // Narrow sheets (iPhone): the main pair on top, the way back under it.
            VStack(spacing: 10) {
                HStack(spacing: 10) {
                    cancelButton.frame(maxWidth: .infinity)
                    importButton(p).frame(maxWidth: .infinity)
                }
                otherFileButton
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var otherFileButton: some View {
        Button("Choisir un autre fichier", systemImage: "arrow.uturn.backward") {
            reset()
            picking = true
        }
    }

    private func importButton(_ p: FfiImportSummary) -> some View {
        Button {
            Task { await runImport() }
        } label: {
            Text("Importer").frame(minWidth: 64)
        }
        .buttonStyle(.borderedProminent)
        .tint(Theme.accent)
        .keyboardShortcut(.return, modifiers: .command)
        .disabled(busy || vaultID.isEmpty || p.items == 0)
        .help("Importer (⌘↩)")
        .accessibilityIdentifier("import.confirm")
    }

    private func pickFile(as s: ImportSource) {
        source = s
        errorMessage = nil
        picking = true
    }

    // MARK: - Actions

    private var defaultVaultID: String {
        if case .vault(let id) = model.selection, model.session.vaults.contains(where: { $0.id == id }) {
            return id
        }
        return model.session.vaults.first?.id ?? ""
    }

    private func reset() {
        buffer.wipe()
        preview = nil
        format = nil
        fileName = ""
        errorMessage = nil
    }

    /// Reads the chosen file (security-scoped, size capped) off the main actor, detects or resolves
    /// its format, then previews it. Any failure wipes the bytes.
    private func load(_ url: URL) async {
        reset()
        busy = true
        defer { busy = false }
        let max = VaultSession.importMaxBytes
        let read: Result<Data, ImportReadError> = await Task.detached {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            guard size <= max else { return .failure(.tooLarge) }
            guard let data = try? Data(contentsOf: url, options: [.uncached]) else {
                return .failure(.unreadable)
            }
            guard data.count <= max else {
                var data = data
                VaultSession.wipeImportBuffer(&data)
                return .failure(.tooLarge)
            }
            return .success(data)
        }.value
        let data: Data
        switch read {
        case .success(let d): data = d
        case .failure(let e):
            errorMessage = e.message
            return
        }
        buffer.replace(with: data)
        let name = url.lastPathComponent
        let detected = await VaultSession.detectImportFormat(fileName: name, data: buffer.data)
        if detected == "onepass" {
            errorMessage = VaultError.importMessage("onepass archive")
            buffer.wipe()
            return
        }
        let chosen: String?
        if let source, !source.formats.isEmpty {
            chosen = detected.flatMap { source.formats.contains($0) ? $0 : nil } ?? source.formats.first
        } else {
            chosen = detected
        }
        guard let chosen else {
            errorMessage = String(localized: "Format non reconnu. Choisis la source de l'export dans la liste.")
            buffer.wipe()
            return
        }
        do {
            let summary = try await VaultSession.previewImport(format: chosen, data: buffer.data)
            fileName = name
            format = chosen
            preview = summary
            if vaultID.isEmpty || !model.session.vaults.contains(where: { $0.id == vaultID }) {
                vaultID = defaultVaultID
            }
        } catch {
            errorMessage = VaultError(error).localizedMessage
            buffer.wipe()
        }
    }

    private func runImport() async {
        guard let format, !vaultID.isEmpty else { return }
        busy = true
        defer { busy = false }
        let vaultName = model.session.vaults.first { $0.id == vaultID }?.meta.name ?? ""
        do {
            let done = try await model.session.importItems(format: format, data: buffer.data, vaultID: vaultID)
            buffer.wipe()
            model.showToast(Self.doneLine(done.items, vault: vaultName))
            dismiss()
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }

    // MARK: - Text

    /// "124 identifiants, 8 cartes, 3 notes".
    static func countsLine(_ counts: [FfiImportTypeCount]) -> String {
        counts.map { typeCount($0.itemType, Int($0.count)) }.joined(separator: ", ")
    }

    private static func typeCount(_ type: FfiItemType, _ n: Int) -> String {
        guard let forms = typeForms(type) else {
            return String(localized: "\(CoreLabels.typeName(type)) : \(n)")
        }
        return "\(n) \(n > 1 ? forms.many : forms.one)"
    }

    /// The word under the number of a count tile: "identifiants", "carte".
    private static func typeLabel(_ type: FfiItemType, _ n: Int) -> String {
        if let forms = typeForms(type) { return n > 1 ? forms.many : forms.one }
        return CoreLabels.typeName(type)
    }

    private static func typeForms(_ type: FfiItemType) -> (one: String, many: String)? {
        switch type {
        case .login: (String(localized: "identifiant"), String(localized: "identifiants"))
        case .password: (String(localized: "mot de passe"), String(localized: "mots de passe"))
        case .secureNote: (String(localized: "note"), String(localized: "notes"))
        case .creditCard: (String(localized: "carte"), String(localized: "cartes"))
        case .identity: (String(localized: "identité"), String(localized: "identités"))
        case .bankAccount: (String(localized: "compte bancaire"), String(localized: "comptes bancaires"))
        case .router: (String(localized: "réseau Wi-Fi"), String(localized: "réseaux Wi-Fi"))
        case .sshKey: (String(localized: "clé SSH"), String(localized: "clés SSH"))
        case .passport: (String(localized: "passeport"), String(localized: "passeports"))
        case .idCard: (String(localized: "carte d'identité"), String(localized: "cartes d'identité"))
        case .driverLicense: (String(localized: "permis de conduire"), String(localized: "permis de conduire"))
        default: nil
        }
    }

    /// "Fichier > Exporter, puis le format 1PUX" as numbered steps, one per menu level.
    private static func steps(of hint: String) -> [String] {
        let steps = hint.components(separatedBy: " > ")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        return steps.isEmpty ? [hint] : steps
    }

    private static func warningLine(_ w: FfiImportWarningCount) -> String {
        let n = Int(w.count)
        return switch w.code {
        case "field_moved": String(localized: "\(n) valeur(s) rangée(s) dans la section Importé")
        case "login_to_password":
            String(localized: "\(n) identifiant(s) sans nom d'utilisateur, gardé(s) comme mot de passe")
        case "to_secure_note": String(localized: "\(n) élément(s) gardé(s) comme note sécurisée")
        case "totp_moved": String(localized: "\(n) code(s) à usage unique rangé(s) dans la section Importé")
        case "attachment_skipped": String(localized: "\(n) pièce(s) jointe(s) non importée(s)")
        case "unsupported_entry": String(localized: "\(n) entrée(s) d'un type non pris en charge, ignorée(s)")
        case "bad_date": String(localized: "\(n) date(s) illisible(s), gardée(s) en texte")
        default: "\(w.code) : \(n)"
        }
    }

    private static func skippedLine(_ n: UInt32) -> String {
        String(localized: "\(Int(n)) ligne(s) vide(s), dossier(s) ou élément(s) supprimé(s) ignoré(s)")
    }

    private static func doneLine(_ n: UInt32, vault: String) -> String {
        n == 1
            ? String(localized: "1 élément importé dans « \(vault) »")
            : String(localized: "\(Int(n)) éléments importés dans « \(vault) »")
    }
}

/// Why the chosen file could not be read (before the core sees it).
private enum ImportReadError: Error {
    case tooLarge, unreadable

    var message: String {
        switch self {
        case .tooLarge: VaultError.importMessage("import file too large") ?? ""
        case .unreadable: String(localized: "Impossible de lire ce fichier.")
        }
    }
}

/// A heading of the source grid and its tiles, in the order of `ImportSource.all`.
private struct ImportSourceGroup: Identifiable {
    let id: String
    let title: LocalizedStringKey
    let sources: [ImportSource]

    private static let managers: Set<String> = [
        "apple", "1password", "bitwarden", "nordpass", "dashlane", "lastpass", "protonpass", "keeper", "enpass",
        "roboform", "keepass",
    ]
    private static let browsers: Set<String> = ["safari", "chrome", "edge", "brave", "opera", "arc", "vivaldi", "firefox"]

    /// Anything not listed above (a source added later) lands in "Autres formats".
    static var all: [ImportSourceGroup] { [
        ImportSourceGroup(
            id: "managers", title: "Gestionnaires de mots de passe",
            sources: ImportSource.all.filter { managers.contains($0.id) }),
        ImportSourceGroup(
            id: "browsers", title: "Navigateurs",
            sources: ImportSource.all.filter { browsers.contains($0.id) }),
        ImportSourceGroup(
            id: "other", title: "Autres formats",
            sources: ImportSource.all.filter { !managers.contains($0.id) && !browsers.contains($0.id) }),
    ] }
}

/// The colored square of a source: a neutral symbol or the first letter of its name, never the
/// vendor's logo.
private struct ImportSourceGlyph: View {
    let source: ImportSource
    var size: CGFloat = 28

    private static let palette: [Color] = [.blue, .indigo, .teal, .orange, .pink, .purple, .green, .red, .cyan, .brown, .mint]

    private var symbol: String? {
        switch source.id {
        case "apple": "key.fill"
        case "cxf": "arrow.left.arrow.right"
        case "otpauth": "timer"
        case "wifi": "wifi"
        case "onepass": "lock.fill"
        default: nil
        }
    }

    private var color: Color {
        switch source.id {
        case "apple": .gray
        case "onepass": Theme.accent
        default:
            // Position in the list: neighbors never share a color.
            Self.palette[(ImportSource.all.firstIndex(of: source) ?? 0) % Self.palette.count]
        }
    }

    var body: some View {
        RoundedRectangle(cornerRadius: size / 4, style: .continuous)
            .fill(color.gradient)
            .frame(width: size, height: size)
            .overlay {
                if let symbol {
                    Image(systemName: symbol)
                        .font(.system(size: size / 2, weight: .semibold))
                } else {
                    Text(source.name.prefix(1).uppercased())
                        .font(.system(size: size * 0.55, weight: .bold, design: .rounded))
                }
            }
            .foregroundStyle(.white)
            .accessibilityHidden(true)
    }
}

/// One source in the grid, as the ⌘N tiles: glyph and name, highlighted on hover, tinted when its
/// export steps are shown.
private struct ImportSourceTile: View {
    let source: ImportSource
    let isSelected: Bool
    let action: () -> Void
    @State private var hovering = false

    private var fill: AnyShapeStyle {
        if isSelected { return AnyShapeStyle(Theme.accent.opacity(0.14)) }
        return hovering ? AnyShapeStyle(.quaternary) : AnyShapeStyle(.clear)
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                ImportSourceGlyph(source: source)
                Text(source.name)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                    .foregroundStyle(.primary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 7)
            .contentShape(.rect(cornerRadius: 9))
            .background(fill, in: .rect(cornerRadius: 9))
            .overlay {
                if isSelected { RoundedRectangle(cornerRadius: 9).strokeBorder(Theme.accent.opacity(0.5)) }
            }
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(source.hint)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
        .accessibilityHint(source.hint)
        .accessibilityIdentifier("import.source.\(source.id)")
    }
}
