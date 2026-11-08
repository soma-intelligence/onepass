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
        id: "auto", name: String(localized: "settings.detectAutomatically"), formats: [],
        hint: String(localized: "settings.onepassRecognizesFormatFrom"))

    static let all: [ImportSource] = [
        ImportSource(
            id: "apple", name: String(localized: "settings.applePasswords"), formats: ["safari-csv"],
            hint: String(localized: "settings.passwordsAppFileExport")),
        ImportSource(
            id: "safari", name: "Safari", formats: ["safari-csv"],
            hint: String(localized: "settings.fileExportBrowsingData")),
        ImportSource(
            id: "1password", name: "1Password", formats: ["1pux", "1password-csv"],
            hint: String(localized: "settings.fileExportThen1pux")),
        ImportSource(
            id: "bitwarden", name: "Bitwarden", formats: ["bitwarden-json", "bitwarden-csv"],
            hint: String(localized: "settings.toolsExportVaultAs")),
        ImportSource(
            id: "nordpass", name: "NordPass", formats: ["nordpass-csv"],
            hint: String(localized: "settings.settingsImportAndExport")),
        ImportSource(
            id: "dashlane", name: "Dashlane", formats: ["dashlane-zip", "dashlane-csv"],
            hint: String(localized: "settings.settingsExportDataCsv")),
        ImportSource(
            id: "lastpass", name: "LastPass", formats: ["lastpass-csv"],
            hint: String(localized: "settings.advancedOptionsExportLastpass")),
        ImportSource(
            id: "protonpass", name: "Proton Pass", formats: ["protonpass-csv"],
            hint: String(localized: "settings.settingsExportAsCsv")),
        ImportSource(
            id: "keeper", name: "Keeper", formats: ["keeper-csv"],
            hint: String(localized: "settings.settingsExportCsvFile")),
        ImportSource(
            id: "enpass", name: "Enpass", formats: ["enpass-json"],
            hint: String(localized: "settings.fileExportAsJson")),
        ImportSource(
            id: "roboform", name: "RoboForm", formats: ["roboform-csv"],
            hint: String(localized: "settings.optionsExportLoginsAnd")),
        ImportSource(
            id: "keepass", name: "KeePass, KeePassXC", formats: ["keepass-xml"],
            hint: String(localized: "settings.fileExportAsKeepass")),
        ImportSource(
            id: "chrome", name: "Google Chrome", formats: ["chrome-csv"],
            hint: String(localized: "settings.googlePasswordManagerSettings")),
        ImportSource(
            id: "edge", name: "Microsoft Edge", formats: ["chrome-csv"],
            hint: String(localized: "settings.settingsPasswordsExportPasswords")),
        ImportSource(
            id: "brave", name: "Brave", formats: ["chrome-csv"],
            hint: String(localized: "settings.bravePasswordManagerSettings")),
        ImportSource(
            id: "opera", name: "Opera", formats: ["chrome-csv"],
            hint: String(localized: "settings.settingsPasswordsExportPasswords2")),
        ImportSource(
            id: "arc", name: "Arc", formats: ["chrome-csv"],
            hint: String(localized: "settings.arcPasswordManagerSettings")),
        ImportSource(
            id: "vivaldi", name: "Vivaldi", formats: ["chrome-csv"],
            hint: String(localized: "settings.settingsPrivacyPasswordsExport")),
        ImportSource(
            id: "firefox", name: "Firefox", formats: ["firefox-csv"],
            hint: String(localized: "settings.aboutLoginsExportLogins")),
        ImportSource(
            id: "cxf", name: String(localized: "settings.otherPasswordManagerCredential"), formats: ["cxf"],
            hint: String(localized: "settings.jsonFileInCredential")),
        ImportSource(
            id: "otpauth", name: String(localized: "Codes à usage unique"), formats: ["otpauth"],
            hint: String(localized: "settings.otpauthLinksGoogleAuthenticator")),
        ImportSource(
            id: "wifi", name: String(localized: "settings.wiFiNetworksQr"), formats: ["wifi-qr"],
            hint: String(localized: "settings.wiFiQrCode")),
        ImportSource(
            id: "onepass", name: String(localized: "settings.onepassCsvExport"), formats: ["onepass-csv"],
            hint: String(localized: "settings.plainTextCsvFile")),
        ImportSource(
            id: "pdf", name: String(localized: "settings.credentialsPdf"), formats: ["pdf-text"],
            hint: String(localized: "settings.passwordListPrintedTo")),
    ]

    /// Display name of a core format, for the preview.
    static func name(ofFormat format: String) -> String {
        switch format {
        case "safari-csv": String(localized: "settings.applePasswordsSafariCsv")
        case "chrome-csv": String(localized: "settings.chromeAndChromiumBrowsers")
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
    /// Items of the export already in the chosen vault from an earlier import: updated, not added.
    /// What importing into the chosen vault would do (`previewImportInto`): nil until counted.
    @State private var into: FfiImportSummary?
    /// Merge, skip or import for each item of the export that looks like one already in the chosen
    /// vault (`into.duplicates`), the core's suggestion until the user changes it.
    @State private var duplicateChoices = ImportDuplicateChoices()
    @State private var vaultID = ""
    @State private var busy = false
    @State private var errorMessage: String?
    /// A OnePass archive was chosen: it goes to the restore sheet.
    @State private var restoreRequest: RestoreRequest?
    /// What the import wrote, shown before the sheet closes.
    @State private var done: FfiImportSummary?
    @State private var doneVaultName = ""
    /// Credentials another app handed over through the system's Credential Exchange (Passwords >
    /// Export to OnePass): read with this one-time token when the sheet opens, then previewed and
    /// imported like a CXF file (passkeys included).
    private let credentialExchange: UUID?

    init(credentialExchange: UUID? = nil) {
        self.credentialExchange = credentialExchange
    }

    private static let calloutID = "import.callout"

    var body: some View {
        ZStack {
            if let done {
                doneStep(done)
                    .transition(.move(edge: .trailing).combined(with: .opacity))
            } else if let preview, let format {
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
        .task(id: credentialExchange) {
            guard let token = credentialExchange else { return }
            await receive(token)
        }
        #if DEBUG
        .task {
            // `-OnePassDebugImport <path>` (`DebugItems`): reads that file as if it had been dropped.
            guard let url = model.debugImportURL else { return }
            model.debugImportURL = nil
            source = .automatic
            await load(url)
            if UserDefaults.standard.bool(forKey: "OnePassDebugImportConfirm"), preview != nil {
                await runImport()
            }
        }
        #endif
        .sheet(item: $restoreRequest) { request in
            RestoreSheet(request: request)
        }
        .onDisappear { buffer.wipe() }
    }

    // MARK: - Shared pieces

    private func header(_ subtitle: LocalizedStringKey, showsCancel: Bool) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text("Importer").font(.title2.weight(.semibold))
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if showsCancel { cancelButton }
        }
        .padding(.horizontal, 20)
        .padding(.top, Theme.Space.l)
        .padding(.bottom, Theme.Space.l)
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
            .padding(.leading, Theme.Space.xs)
    }

    /// Red callout: the file could not be read, recognized or imported.
    private func errorCallout(_ message: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Theme.Space.m) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Text(message)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(.callout)
        .padding(Theme.Space.m)
        .background(Color.red.opacity(0.1), in: .rect(cornerRadius: Theme.Radius.control))
        .overlay { RoundedRectangle(cornerRadius: Theme.Radius.control).strokeBorder(Color.red.opacity(0.35)) }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("import.error")
        .transition(.opacity)
    }

    private var busyOverlay: some View {
        VStack(spacing: Theme.Space.m) {
            ProgressView().controlSize(.large)
            if preview == nil {
                Text("settings.readingFile")
            } else {
                Text("settings.importing")
            }
        }
        .font(.callout)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 28)
        .padding(.vertical, Theme.Space.xl)
        .background(.regularMaterial, in: .rect(cornerRadius: Theme.Radius.card))
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
                    VStack(alignment: .leading, spacing: Theme.Space.xl) {
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
            VStack(spacing: Theme.Space.m) {
                Image(systemName: dropTargeted ? "tray.and.arrow.down.fill" : "tray.and.arrow.down")
                    .font(.system(size: 24, weight: .medium))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 54, height: 54)
                    .background(Theme.accent.opacity(dropTargeted ? 0.22 : 0.13), in: .circle)
                VStack(spacing: Theme.Space.xxs) {
                    Text("settings.dropExportHere")
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Text("settings.orChooseFile")
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
            .background(Theme.accent.opacity(dropTargeted ? 0.12 : 0.04), in: .rect(cornerRadius: Theme.Radius.card))
            .overlay {
                RoundedRectangle(cornerRadius: Theme.Radius.card)
                    .strokeBorder(
                        Theme.accent.opacity(dropTargeted ? 0.9 : 0.45),
                        style: StrokeStyle(lineWidth: 1.5, dash: [6, 5]))
            }
            .contentShape(.rect(cornerRadius: Theme.Radius.card))
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
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            Text("settings.orChooseSource").font(.headline)
            HStack(spacing: Theme.Space.s) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("settings.searchSources", text: $query)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("import.search")
            }
            .padding(.horizontal, Theme.Space.m)
            .padding(.vertical, Theme.Space.s)
            .background(.quaternary.opacity(0.6), in: .rect(cornerRadius: Theme.Radius.control))

            if groups.isEmpty {
                ContentUnavailableView.search(text: query).padding(.vertical, Theme.Space.m)
            } else {
                VStack(alignment: .leading, spacing: Theme.Space.l) {
                    ForEach(groups) { group in
                        VStack(alignment: .leading, spacing: Theme.Space.s) {
                            sectionTitle(group.title)
                            LazyVGrid(columns: [GridItem(.adaptive(minimum: 168), spacing: Theme.Space.s)], spacing: Theme.Space.s) {
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
        return VStack(alignment: .leading, spacing: Theme.Space.m) {
            HStack(spacing: Theme.Space.m) {
                ImportSourceGlyph(source: s, size: 24)
                Text("settings.exportFrom \(s.name)").font(.subheadline.weight(.semibold))
                Spacer(minLength: 0)
            }
            VStack(alignment: .leading, spacing: Theme.Space.s) {
                if steps.count == 1 {
                    Text(steps[0])
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                        HStack(alignment: .top, spacing: Theme.Space.m) {
                            Text(index + 1, format: .number)
                                .font(.caption2.weight(.bold))
                                .monospacedDigit()
                                .foregroundStyle(.white)
                                .frame(width: 18, height: 18)
                                .background(Theme.accent, in: .circle)
                            Text(step)
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                                // Centers the first line on the 18 pt step circle.
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
                    Label("settings.chooseFile", systemImage: "doc.badge.plus")
                }
                .buttonStyle(.borderedProminent)
                .tint(Theme.accent)
                .accessibilityIdentifier("import.pick")
            }
        }
        .padding(Theme.Space.l)
        .background(Theme.accent.opacity(0.07), in: .rect(cornerRadius: Theme.Radius.control))
        .overlay { RoundedRectangle(cornerRadius: Theme.Radius.control).strokeBorder(Theme.accent.opacity(0.25)) }
    }

    private var privacyNote: some View {
        Label {
            Text("settings.fileReadOnDevice")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "lock.fill")
        }
        .font(.footnote)
        .foregroundStyle(.secondary)
        .padding(.horizontal, Theme.Space.xs)
    }

    // MARK: - Step 3: result

    /// What was written, by type, with the warnings of the file: the per-item outcome of the import.
    private func doneStep(_ d: FfiImportSummary) -> some View {
        VStack(spacing: 0) {
            header("Import terminé", showsCancel: false)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Space.xl) {
                    EditorCard {
                        Label(Self.doneLine(d.items, vault: doneVaultName), systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.headline)
                            .editorRowPadding()
                    }
                    .accessibilityIdentifier("import.done")
                    if d.updated > 0 || d.archivedDuplicates > 0 {
                        Label(Self.outcomeLine(d), systemImage: "arrow.triangle.2.circlepath")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, Theme.Space.xs)
                            .accessibilityIdentifier("import.outcome")
                    }
                    if d.merged + d.skippedDuplicates + d.separate > 0 {
                        Label(Self.duplicatesDoneLine(d), systemImage: "square.on.square")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, Theme.Space.xs)
                            .accessibilityIdentifier("import.duplicates.done")
                    }
                    contentSection(d, done: true)
                }
                .padding(20)
            }
            Divider()
            HStack {
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Text("common.done").frame(minWidth: 64)
                }
                .buttonStyle(.borderedProminent)
                .tint(Theme.accent)
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("import.finish")
            }
            .padding(.horizontal, 20)
            .padding(.vertical, Theme.Space.l)
        }
    }

    // MARK: - Step 2: preview

    private func previewStep(_ p: FfiImportSummary, format: String) -> some View {
        VStack(spacing: 0) {
            header("Vérifie ce que contient le fichier avant de l'importer", showsCancel: false)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Space.xl) {
                    fileCard(format: format)
                    contentSection(p)
                    destinationSection
                    if let into {
                        Label(Self.outcomeLine(into), systemImage: "arrow.triangle.2.circlepath")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, Theme.Space.xs)
                            .accessibilityIdentifier("import.updates")
                    }
                    if !duplicateChoices.isEmpty {
                        duplicatesSection
                    }
                }
                .padding(20)
            }
            // The destination decides what is an update: counted again for each vault.
            .task(id: vaultID) { await countUpdates() }
            if let errorMessage {
                errorCallout(errorMessage)
                    .padding(.horizontal, 20)
                    .padding(.bottom, Theme.Space.m)
            }
            Divider()
            footerBar(p)
        }
    }

    // MARK: Possible duplicates

    /// "3 doublons possibles": each item of the export that matches one of the chosen vault (same
    /// site and username, same TOTP, same card or document number), with what differs and a
    /// Merge / Skip / Import choice; bulk buttons set every row at once.
    private var duplicatesSection: some View {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
            sectionTitle("duplicates.banner.title \(duplicateChoices.count)")
            Text("import.duplicates.subtitle")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, Theme.Space.xs)
            HStack(spacing: Theme.Space.s) {
                Button("import.duplicates.mergeAll", systemImage: "arrow.triangle.merge") {
                    duplicateChoices.setAll(.merge)
                }
                .disabled(duplicateChoices.all(.merge))
                .accessibilityIdentifier("import.duplicates.mergeAll")
                Button("import.duplicates.skipAll", systemImage: "arrow.uturn.right") {
                    duplicateChoices.setAll(.skip)
                }
                .disabled(duplicateChoices.all(.skip))
                .accessibilityIdentifier("import.duplicates.skipAll")
                Spacer(minLength: 0)
                if !duplicateChoices.decisions.isEmpty {
                    Button("import.duplicates.suggested") { duplicateChoices.resetToSuggested() }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("import.duplicates.suggested")
                }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .font(.subheadline)
            EditorCard {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(duplicateChoices.rows.enumerated()), id: \.element.index) { n, row in
                        if n > 0 { CardDivider() }
                        duplicateRow(row)
                    }
                }
            }
            .accessibilityIdentifier("import.duplicates")
            Text(Self.duplicatesPlanLine(duplicateChoices))
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding(.horizontal, Theme.Space.xs)
                .accessibilityIdentifier("import.duplicates.plan")
        }
    }

    /// The file's item, the vault item it matches, what differs, and the choice.
    private func duplicateRow(_ row: FfiImportDuplicate) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.m) {
            HStack(alignment: .top, spacing: Theme.Space.m) {
                CategoryTile(category: .of(row.incoming.itemType), size: 30)
                VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                    Text(row.incoming.title.isEmpty ? row.existing.title : row.incoming.title)
                        .font(.headline)
                        .lineLimit(1)
                    if !row.incoming.subtitle.isEmpty {
                        Text(row.incoming.subtitle)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Label {
                        Text("import.duplicates.inVault \(Self.vaultLine(row))")
                            .lineLimit(1)
                    } icon: {
                        Image(systemName: "arrow.turn.down.right")
                    }
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            if row.exact {
                Label("import.duplicates.exact", systemImage: "equal.circle.fill")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.green)
            } else if !row.differences.isEmpty {
                Text(Self.differencesLine(row.differences))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Picker("import.duplicates.choice", selection: choiceBinding(row.index)) {
                Text("import.choice.merge").tag(FfiImportChoice.merge)
                Text("import.choice.skip").tag(FfiImportChoice.skip)
                Text("import.choice.import").tag(FfiImportChoice.import)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityIdentifier("import.duplicates.choice.\(row.index)")
        }
        .editorRowPadding()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("import.duplicates.row.\(row.index)")
    }

    private func choiceBinding(_ index: UInt32) -> Binding<FfiImportChoice> {
        Binding(
            get: { duplicateChoices.choice(for: index) },
            set: { duplicateChoices.set($0, for: index) })
    }

    private func fileCard(format: String) -> some View {
        EditorCard {
            HStack(spacing: Theme.Space.l) {
                Image(systemName: "doc.text.fill")
                    .font(.system(size: 21))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 44, height: 44)
                    .background(Theme.accent.opacity(0.14), in: .rect(cornerRadius: Theme.Radius.chip))
                VStack(alignment: .leading, spacing: Theme.Space.xs) {
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
            .padding(Theme.Space.l)
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private func contentSection(_ p: FfiImportSummary, done: Bool = false) -> some View {
        let notes: [(symbol: String, text: String)] =
            p.warnings.map { ("info.circle", Self.warningLine($0)) }
            + (p.skipped > 0 ? [("arrow.uturn.right", Self.skippedLine(p.skipped))] : [])
        VStack(alignment: .leading, spacing: Theme.Space.s) {
            sectionTitle("Contenu")
            if p.byType.isEmpty {
                EditorCard {
                    Label("settings.theresNothingToImport", systemImage: "tray")
                        .foregroundStyle(.secondary)
                        .editorRowPadding()
                }
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 128), spacing: Theme.Space.s)], spacing: Theme.Space.s) {
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
            // With possible duplicates, their section says what happens to the vault items.
            if done || duplicateChoices.isEmpty {
                Text(done
                    ? "Les éléments rangés autrement que dans la source sont dans la section « Importé » de chaque élément."
                    : "Chaque élément est ajouté avec un nouvel identifiant : rien de ce qui est déjà dans OnePass n'est remplacé. Le dossier d'origine devient un tag.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, Theme.Space.xs)
            }
        }
    }

    /// "3 / identifiants" under the type's colored glyph.
    private func countTile(_ c: FfiImportTypeCount) -> some View {
        let n = Int(c.count)
        return EditorCard {
            VStack(alignment: .leading, spacing: Theme.Space.m) {
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
            .padding(Theme.Space.l)
        }
    }

    private var destinationSection: some View {
        VStack(alignment: .leading, spacing: Theme.Space.s) {
            sectionTitle("Destination")
            EditorCard {
                HStack(spacing: Theme.Space.m) {
                    Image(systemName: "lock.rectangle.stack.fill")
                        .foregroundStyle(Theme.accent)
                    Text("term.vault")
                    Spacer(minLength: 12)
                    Picker("term.vault", selection: $vaultID) {
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
            HStack(spacing: Theme.Space.m) {
                otherFileButton
                Spacer(minLength: 12)
                cancelButton
                importButton(p)
            }
            // Narrow sheets (iPhone): the main pair on top, the way back under it.
            VStack(spacing: Theme.Space.m) {
                HStack(spacing: Theme.Space.m) {
                    cancelButton.frame(maxWidth: .infinity)
                    importButton(p).frame(maxWidth: .infinity)
                }
                otherFileButton
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, Theme.Space.l)
    }

    private var otherFileButton: some View {
        Button("settings.chooseAnotherFile", systemImage: "arrow.uturn.backward") {
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
        .help("settings.import")
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
        into = nil
        duplicateChoices = ImportDuplicateChoices()
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
            // An encrypted OnePass backup or export: restored, not imported. The restore sheet owns
            // the bytes from here (and wipes them); the buffer's copy is wiped now.
            restoreRequest = RestoreRequest(data: buffer.data, fileName: name)
            buffer.wipe()
            return
        }
        if detected == "pdf-text" {
            // A PDF: PDFKit reads its text here, and the core parses that text. The PDF bytes are
            // wiped once the text replaces them.
            let pdf = buffer.data
            let text: Result<Data, PDFImportError> = await Task.detached {
                Result { () throws(PDFImportError) -> Data in try VaultSession.pdfImportText(pdf) }
            }.value
            switch text {
            case .success(let t): buffer.replace(with: t)
            case .failure(let e):
                errorMessage = Self.pdfMessage(e)
                buffer.wipe()
                return
            }
        }
        let chosen: String?
        if detected == "pdf-text" {
            chosen = "pdf-text"
        } else if let source, !source.formats.isEmpty {
            chosen = detected.flatMap { source.formats.contains($0) ? $0 : nil } ?? source.formats.first
        } else {
            chosen = detected
        }
        guard let chosen else {
            errorMessage = String(localized: "settings.unrecognizedFormatChooseWhere")
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

    /// Reads the credentials of a Credential Exchange (`CredentialExchangeImport`) and previews them
    /// as CXF. The token works once: a failure leaves the sheet on its sources with the reason.
    private func receive(_ token: UUID) async {
        reset()
        busy = true
        defer { busy = false }
        do {
            buffer.replace(with: try await CredentialExchangeImport.receive(token: token))
            let summary = try await VaultSession.previewImport(format: CredentialExchangeImport.format, data: buffer.data)
            fileName = String(localized: "settings.credentialExchange")
            format = CredentialExchangeImport.format
            preview = summary
            if vaultID.isEmpty || !model.session.vaults.contains(where: { $0.id == vaultID }) {
                vaultID = defaultVaultID
            }
        } catch {
            errorMessage = String(localized: "settings.credentialsSentByOther")
            buffer.wipe()
        }
    }

    /// How many items of the export already sit in the chosen vault from an earlier import.
    private func countUpdates() async {
        guard let format, !vaultID.isEmpty else {
            into = nil
            return
        }
        let summary = try? await model.session.previewImport(format: format, data: buffer.data, vaultID: vaultID)
        into = summary
        duplicateChoices.update(summary?.duplicates ?? [])
    }

    private func runImport() async {
        guard let format, !vaultID.isEmpty else { return }
        busy = true
        defer { busy = false }
        let vaultName = model.session.vaults.first { $0.id == vaultID }?.meta.name ?? ""
        do {
            let written = try await model.session.importItems(
                format: format, data: buffer.data, vaultID: vaultID, decisions: duplicateChoices.decisions)
            buffer.wipe()
            model.showToast(written.updated > 0 || written.archivedDuplicates > 0
                ? Self.outcomeLine(written)
                : Self.doneLine(written.items, vault: vaultName))
            doneVaultName = vaultName
            done = written
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
            return String(localized: "app.text \(CoreLabels.typeName(type)) \(n)")
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
        case .login: (String(localized: "settings.login"), String(localized: "settings.logins"))
        case .password: (String(localized: "settings.password"), String(localized: "settings.passwords"))
        case .secureNote: (String(localized: "note"), String(localized: "notes"))
        case .creditCard: (String(localized: "settings.card"), String(localized: "settings.cards"))
        case .identity: (String(localized: "settings.identity"), String(localized: "settings.identities"))
        case .bankAccount: (String(localized: "settings.bankAccount"), String(localized: "settings.bankAccounts"))
        case .router: (String(localized: "settings.wiFiNetwork"), String(localized: "settings.wiFiNetworks"))
        case .sshKey: (String(localized: "settings.sshKey"), String(localized: "settings.sshKeys"))
        case .passport: (String(localized: "settings.passport"), String(localized: "settings.passports"))
        case .idCard: (String(localized: "settings.idCard"), String(localized: "settings.idCards"))
        case .driverLicense: (String(localized: "settings.driversLicense"), String(localized: "settings.driversLicense"))
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
        case "field_moved": String(localized: "settings.valuesPlacedInImported \(n)")
        case "login_to_password":
            String(localized: "settings.loginsWithoutUsernameKept \(n)")
        case "to_secure_note": String(localized: "settings.itemsKeptAsSecure \(n)")
        case "totp_moved": String(localized: "settings.oneTimeCodesPlaced \(n)")
        case "attachment_skipped": String(localized: "settings.attachmentsNotImported \(n)")
        case "unsupported_entry": String(localized: "settings.entriesOfUnsupportedType \(n)")
        case "bad_date": String(localized: "settings.unreadableDatesKeptAs \(n)")
        case "passkey_needs_cxf": String(localized: "settings.passkeysNeedCredentialExchange \(n)")
        // A warning this version does not know yet: counted, never shown as its raw code.
        default: String(localized: "settings.itemsImportedWithNote \(n)")
        }
    }

    /// "4 mis à jour, 3 créés, 2 convertis depuis une note, 1 doublon archivé, 120 inchangés": the
    /// dry run of an import into the chosen vault, and its result. Items an earlier import of the
    /// same export made are updated in place, never duplicated; nothing is deleted.
    private static func outcomeLine(_ s: FfiImportSummary) -> String {
        String(localized: "settings.importDryRun \(Int(s.fixed)) \(Int(s.added)) \(Int(s.converted)) \(Int(s.archivedDuplicates)) \(Int(s.unchanged))")
    }

    /// "Gmail, alice@example.com": the vault item a file item matches, its subtitle only when it
    /// is not the file item's.
    private static func vaultLine(_ row: FfiImportDuplicate) -> String {
        let s = row.existing
        return s.subtitle.isEmpty || s.subtitle == row.incoming.subtitle ? s.title : "\(s.title), \(s.subtitle)"
    }

    /// "Diffère : mot de passe, sites".
    private static func differencesLine(_ aspects: [FfiDuplicateAspect]) -> String {
        let list = aspects.map(DuplicatesText.aspect).formatted(.list(type: .and, width: .narrow))
        return String(localized: "duplicates.copy.differs \(list)")
    }

    /// "2 à fusionner, 1 à ignorer, 0 gardés à part".
    private static func duplicatesPlanLine(_ c: ImportDuplicateChoices) -> String {
        String(localized: "import.duplicates.plan \(c.count(of: .merge)) \(c.count(of: .skip)) \(c.count(of: .import))")
    }

    private static func duplicatesDoneLine(_ s: FfiImportSummary) -> String {
        String(localized: "import.duplicates.done \(Int(s.merged)) \(Int(s.skippedDuplicates)) \(Int(s.separate))")
    }

    private static func pdfMessage(_ e: PDFImportError) -> String {
        switch e {
        case .unreadable: String(localized: "settings.pdfCantReadOr")
        case .locked: String(localized: "settings.pdfPasswordProtectedOpen")
        case .noText: String(localized: "settings.pdfHasNoReadable")
        }
    }

    private static func skippedLine(_ n: UInt32) -> String {
        String(localized: "settings.emptyRowsFoldersOr \(Int(n))")
    }

    private static func doneLine(_ n: UInt32, vault: String) -> String {
        n == 1
            ? String(localized: "settings.n1ItemImportedInto \(vault)")
            : String(localized: "settings.itemsImportedInto \(Int(n)) \(vault)")
    }
}

/// Why the chosen file could not be read (before the core sees it).
private enum ImportReadError: Error {
    case tooLarge, unreadable

    var message: String {
        switch self {
        case .tooLarge: VaultError.importMessage("import file too large") ?? ""
        case .unreadable: String(localized: "app.cantReadFile")
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
        case "pdf": "doc.richtext"
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
            HStack(spacing: Theme.Space.m) {
                ImportSourceGlyph(source: source)
                Text(source.name)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                    .foregroundStyle(.primary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, Theme.Space.s)
            .padding(.vertical, Theme.Space.s)
            .contentShape(.rect(cornerRadius: Theme.Radius.control))
            .background(fill, in: .rect(cornerRadius: Theme.Radius.control))
            .overlay {
                if isSelected { RoundedRectangle(cornerRadius: Theme.Radius.control).strokeBorder(Theme.accent.opacity(0.5)) }
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
