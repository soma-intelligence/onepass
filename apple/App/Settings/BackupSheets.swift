import DesignKit
import SwiftUI
import UniformTypeIdentifiers
import VaultKit

/// A file handed to `RestoreSheet` by another sheet (an archive dropped into "Importer…").
struct RestoreRequest: Identifiable {
    let id = UUID()
    let data: Data
    let fileName: String
}

/// "Restaurer une sauvegarde…": choose a `.onepass` file, read its header, open it (by this account,
/// whose signature is then verified, or by its passphrase), check what it holds, restore. Nothing in
/// the account is overwritten. The archive bytes and the passphrase are wiped when the sheet closes.
struct RestoreSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var request: RestoreRequest?

    @State private var data: Data?
    @State private var fileName = ""
    @State private var info: FfiArchiveInfo?
    @State private var passphrase = ""
    @State private var preview: FfiRestoreSummary?
    @State private var done: FfiRestoreSummary?
    @State private var picking = false
    @State private var busy = false
    @State private var errorMessage: String?

    private static let archiveType = UTType(filenameExtension: EncryptedBackupFile.fileExtension) ?? .data

    private var needsPassphrase: Bool {
        guard let info else { return false }
        return !info.forThisAccount && preview == nil
    }

    var body: some View {
        NavigationStack {
            Form {
                if let done {
                    doneSection(done)
                } else if data == nil {
                    chooseSection
                } else {
                    if let info { fileSection(info) }
                    if needsPassphrase { passphraseSection }
                    if let preview { previewSection(preview) }
                }
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("restore.error")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Restaurer une sauvegarde")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(done == nil ? LocalizedStringKey("Annuler") : "Fermer") { dismiss() }.disabled(busy)
                }
                if done == nil, let preview {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Restaurer") { Task { await restore() } }
                            .disabled(busy || preview.items == 0)
                            .accessibilityIdentifier("restore.confirm")
                    }
                }
            }
            .overlay {
                if busy { ProgressView().controlSize(.large) }
            }
        }
        #if os(macOS)
        .frame(minWidth: 480, minHeight: 440)
        #endif
        .interactiveDismissDisabled(busy)
        .fileImporter(isPresented: $picking, allowedContentTypes: [Self.archiveType, .data]) { result in
            if case .success(let url) = result { Task { await load(url) } }
        }
        .task {
            if let request, data == nil { await take(request.data, named: request.fileName) }
        }
        .onDisappear(perform: forget)
    }

    // MARK: - Sections

    @ViewBuilder private var chooseSection: some View {
        Section {
            Text("Choisis un fichier .onepass : une sauvegarde chiffrée de ce compte, ou une sauvegarde d'un autre compte avec sa phrase de passe. Rien de ce qui est déjà dans OnePass n'est remplacé.")
                .fixedSize(horizontal: false, vertical: true)
            Button("Choisir une sauvegarde…", systemImage: "doc.badge.arrow.up") { picking = true }
                .accessibilityIdentifier("restore.choose")
        }
    }

    @ViewBuilder private func fileSection(_ info: FfiArchiveInfo) -> some View {
        Section {
            LabeledContent("Fichier") {
                Text(verbatim: fileName).lineLimit(1).truncationMode(.middle)
            }
            LabeledContent("Type", value: info.kind == .backup
                ? String(localized: "Sauvegarde du compte") : String(localized: "Export OnePass"))
            LabeledContent("Créée le") {
                Text(Date(timeIntervalSince1970: TimeInterval(info.createdAt)), format: .dateTime.day().month().year().hour().minute())
            }
            Label(Self.signatureLine(info, verified: preview?.signatureVerified ?? false), systemImage: Self.signatureSymbol(info, verified: preview?.signatureVerified ?? false))
                .foregroundStyle(preview?.signatureVerified == true ? .green : .secondary)
                .accessibilityIdentifier("restore.signature")
        }
    }

    @ViewBuilder private var passphraseSection: some View {
        Section {
            SecureField("Phrase de passe de la sauvegarde", text: $passphrase)
                .privacySensitive()
                .onSubmit { Task { await open() } }
                .accessibilityIdentifier("restore.passphrase")
            Button("Ouvrir") { Task { await open() } }
                .disabled(passphrase.isEmpty || busy)
                .accessibilityIdentifier("restore.open")
        } footer: {
            Text("Cette sauvegarde n'est pas pour ce compte : elle s'ouvre avec la phrase de passe choisie à l'export.")
        }
    }

    @ViewBuilder private func previewSection(_ p: FfiRestoreSummary) -> some View {
        Section {
            if p.items == 0 {
                Label("Tout ce que contient cette sauvegarde est déjà dans OnePass.", systemImage: "checkmark.circle")
            } else {
                Label(ImportSheet.countsLine(p.byType), systemImage: "tray.and.arrow.down")
                    .accessibilityIdentifier("restore.counts")
            }
            if p.vaultsCreated > 0 {
                Label(p.vaultsCreated == 1
                    ? String(localized: "1 coffre sera créé")
                    : String(localized: "\(p.vaultsCreated) coffres seront créés"), systemImage: "lock.rectangle.stack")
            }
            if p.skipped > 0 {
                Label(p.skipped == 1
                    ? String(localized: "1 élément déjà présent, laissé tel quel")
                    : String(localized: "\(p.skipped) éléments déjà présents, laissés tels quels"), systemImage: "arrow.uturn.right")
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Contenu")
        } footer: {
            Text("Les éléments gardent leur identifiant, ceux de la corbeille et les archivés compris. Une restauration signée par ton compte est enregistrée pour tes autres appareils.")
        }
    }

    @ViewBuilder private func doneSection(_ d: FfiRestoreSummary) -> some View {
        Section {
            Label(d.items == 1
                ? String(localized: "1 élément restauré")
                : String(localized: "\(d.items) éléments restaurés"), systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
                .accessibilityIdentifier("restore.done")
            if !d.byType.isEmpty { Text(ImportSheet.countsLine(d.byType)).foregroundStyle(.secondary) }
            if d.skipped > 0 {
                Text(d.skipped == 1
                    ? String(localized: "1 élément était déjà là.")
                    : String(localized: "\(d.skipped) éléments étaient déjà là.")).foregroundStyle(.secondary)
            }
            if d.epoch == nil {
                Label("Les éléments sont restaurés, mais la restauration n'a pas pu être enregistrée pour tes autres appareils. Synchronise, puis restaure à nouveau ce fichier.", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        }
    }

    static func signatureLine(_ info: FfiArchiveInfo, verified: Bool) -> String {
        if verified { return String(localized: "Signature de ton compte vérifiée") }
        if info.forThisAccount { return String(localized: "Signée par ton compte : la signature est vérifiée à l'ouverture") }
        if info.signed { return String(localized: "Signée par un autre compte : seule la phrase de passe protège ce fichier") }
        return String(localized: "Non signée : seule la phrase de passe protège ce fichier")
    }

    static func signatureSymbol(_ info: FfiArchiveInfo, verified: Bool) -> String {
        verified ? "checkmark.seal.fill" : info.forThisAccount ? "seal" : "key"
    }

    // MARK: - Actions

    private func load(_ url: URL) async {
        let max = VaultSession.importMaxBytes
        let read: Data? = await Task.detached {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            guard size <= max, let data = try? Data(contentsOf: url, options: [.uncached]), data.count <= max else {
                return nil
            }
            return data
        }.value
        guard let read else {
            errorMessage = String(localized: "Ce fichier n'a pas pu être lu, ou il est trop gros.")
            return
        }
        await take(read, named: url.lastPathComponent)
    }

    /// Reads the header; an archive for this account opens at once (no passphrase).
    private func take(_ bytes: Data, named name: String) async {
        forget()
        errorMessage = nil
        busy = true
        defer { busy = false }
        do {
            let header = try await model.session.archiveInfo(bytes)
            if header.newerVersion { throw ArchiveError.newerVersion }
            if !header.forThisAccount, !header.hasPassphrase { throw ArchiveError.otherAccount }
            data = bytes
            fileName = name
            info = header
            if header.forThisAccount { preview = try await model.session.previewRestore(bytes, passphrase: nil) }
        } catch {
            errorMessage = ArchiveError(error).message
        }
    }

    private func open() async {
        guard let data, !passphrase.isEmpty, !busy else { return }
        busy = true
        defer { busy = false }
        errorMessage = nil
        let phrase = SecretBytes(utf8: passphrase)
        defer { phrase.wipe() }
        do {
            preview = try await model.session.previewRestore(data, passphrase: phrase)
        } catch {
            errorMessage = error.message
        }
    }

    private func restore() async {
        guard let data, preview != nil else { return }
        busy = true
        defer { busy = false }
        errorMessage = nil
        let phrase = passphrase.isEmpty ? nil : SecretBytes(utf8: passphrase)
        defer { phrase?.wipe() }
        do {
            done = try await model.session.restoreArchive(data, passphrase: phrase)
            passphrase = ""
            wipeData()
        } catch {
            errorMessage = error.message
        }
    }

    private func wipeData() {
        if var bytes = data {
            data = nil
            VaultSession.wipeImportBuffer(&bytes)
        }
    }

    private func forget() {
        passphrase = ""
        info = nil
        preview = nil
        wipeData()
    }
}

/// "Exporter en CSV non chiffré…": the strongest warning of the app, a box to tick, the vaults, the
/// master password, then the file. Mac: a save panel (second warning for a cloud folder), never over
/// an existing file, created readable by this user only. iPhone, iPad, Vision Pro: the share sheet
/// over a temporary copy removed when it closes. The bytes are wiped when the sheet closes.
struct PlaintextExportSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var understood = false
    @State private var excludedVaults: Set<String> = []
    @State private var password = ""
    @State private var busy = false
    @State private var errorMessage: String?
    @State private var csv: Data?
    @State private var saved = false
    #if os(macOS)
    @State private var cloudDestination: URL?
    @State private var cloudWarning = false
    #else
    @State private var sharedFile: SharedPlaintextFile?
    @State private var temporaryFile: URL?
    #endif

    private var fileName: String { PlaintextExportFile.fileName(for: Date()) }
    private var chosenVaults: [String] {
        model.session.vaults.map(\.id).filter { !excludedVaults.contains($0) }
    }
    private var canExport: Bool { understood && !password.isEmpty && !chosenVaults.isEmpty && !busy }

    var body: some View {
        NavigationStack {
            Form {
                warningSection
                if csv == nil {
                    entry
                } else {
                    ready
                }
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Export non chiffré")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(csv == nil ? LocalizedStringKey("Annuler") : "Fermer") { dismiss() }.disabled(busy)
                }
                if csv == nil {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Exporter", action: export)
                            .disabled(!canExport)
                            .accessibilityIdentifier("plaintext.confirm")
                    }
                }
            }
            #if os(macOS)
            .alert("Cet emplacement est synchronisé dans le cloud", isPresented: $cloudWarning) {
                Button("Enregistrer quand même", role: .destructive) {
                    if let url = cloudDestination { write(to: url) }
                    cloudDestination = nil
                }
                Button("Annuler", role: .cancel) { cloudDestination = nil }
            } message: {
                Text("Le fichier, en clair, sera copié sur les serveurs de ce service et sur tes autres appareils.")
            }
            #else
            .sheet(item: $sharedFile, onDismiss: removeSharedFile) { file in
                KitShareController(url: file.url) { sharedFile = nil }
                    .ignoresSafeArea()
            }
            #endif
        }
        #if os(macOS)
        .frame(minWidth: 480, minHeight: 520)
        #endif
        .interactiveDismissDisabled(busy)
        .onDisappear(perform: forget)
    }

    @ViewBuilder private var warningSection: some View {
        Section {
            Label {
                Text("Ce fichier n'est pas chiffré. Toute personne ou app qui y accède lit tous tes mots de passe, codes et notes. Un tableur peut exécuter une cellule qui commence par « = ». Les passkeys et les lieux n'y figurent pas.")
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            }
            Text("Pour une copie de sécurité, préfère la sauvegarde chiffrée. N'utilise ce fichier que pour passer à un autre gestionnaire, puis supprime-le.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder private var entry: some View {
        Section {
            Toggle("Je comprends que ce fichier n'est pas chiffré", isOn: $understood)
                .accessibilityIdentifier("plaintext.understood")
        }
        Section("Coffres") {
            ForEach(model.session.vaults, id: \.id) { vault in
                Toggle(vault.meta.name, isOn: Binding(
                    get: { !excludedVaults.contains(vault.id) },
                    set: { on in
                        if on { excludedVaults.remove(vault.id) } else { excludedVaults.insert(vault.id) }
                    }))
            }
        }
        Section {
            SecureField("Mot de passe maître", text: $password)
                .privacySensitive()
                .onSubmit(export)
                .accessibilityIdentifier("plaintext.password")
        } footer: {
            Text("Les éléments de la corbeille ne sont pas exportés.")
        }
    }

    @ViewBuilder private var ready: some View {
        Section {
            Label(saved ? LocalizedStringKey("Fichier enregistré.") : "Export prêt.", systemImage: "checkmark.circle")
                .foregroundStyle(saved ? .green : .primary)
            Text(verbatim: fileName).font(.footnote.monospaced()).foregroundStyle(.secondary)
            Button("Enregistrer le fichier…", action: saveFile)
                .accessibilityIdentifier("plaintext.save")
        } footer: {
            Text("Supprime le fichier dès que tu n'en as plus besoin, corbeille comprise.")
        }
    }

    private func export() {
        guard canExport else { return }
        busy = true
        errorMessage = nil
        let typed = SecretBytes(utf8: password)
        password = ""
        let vaults = chosenVaults.count == model.session.allVaults.count ? [] : chosenVaults
        Task {
            defer {
                busy = false
                typed.wipe()
            }
            do {
                csv = try await model.session.exportPlaintextCSV(password: typed, vaultIDs: vaults)
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }

    private func saveFile() {
        guard csv != nil else { return }
        #if os(macOS)
        Task {
            guard let url = await KitSavePanel.chooseDestination(
                fileName: fileName, contentType: .commaSeparatedText,
                message: String(localized: "Ce fichier n'est pas chiffré. Choisis un emplacement hors ligne et supprime-le après usage."))
            else { return }
            if KitDestination.isCloudSynced(url) {
                cloudDestination = url
                cloudWarning = true
            } else {
                write(to: url)
            }
        }
        #else
        guard let csv else { return }
        do {
            let url = try PlaintextExportFile.writeTemporary(csv, named: fileName, under: FileManager.default.temporaryDirectory)
            temporaryFile = url
            sharedFile = SharedPlaintextFile(url: url)
        } catch {
            errorMessage = String(localized: "Le fichier n'a pas pu être préparé.")
        }
        #endif
    }

    #if os(macOS)
    private func write(to url: URL) {
        guard let csv else { return }
        do {
            // The save panel already confirmed replacing an existing file: it goes first.
            if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
            try PlaintextExportFile.writeNew(csv, to: url)
            saved = true
        } catch {
            errorMessage = String(localized: "Le fichier n'a pas pu être enregistré.")
        }
    }
    #else
    private func removeSharedFile() {
        if let url = temporaryFile {
            PlaintextExportFile.remove(url, under: FileManager.default.temporaryDirectory)
        }
        temporaryFile = nil
        sharedFile = nil
        saved = true
    }
    #endif

    private func forget() {
        #if os(iOS) || os(visionOS)
        removeSharedFile()
        #endif
        password = ""
        if var bytes = csv {
            csv = nil
            VaultSession.wipeImportBuffer(&bytes)
        }
    }
}

#if os(iOS) || os(visionOS)
private struct SharedPlaintextFile: Identifiable {
    let url: URL
    var id: URL { url }
}
#endif
