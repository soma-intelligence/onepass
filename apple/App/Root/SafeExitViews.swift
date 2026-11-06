import DesignKit
import SwiftUI
import UniformTypeIdentifiers
import VaultKit

/// The safe exits of "Données refusées" (spec 3.3, ruling 6), in order: export first, then keep this
/// device's version or take iCloud's. Each one asks the master password; the last one also asks to
/// confirm that unexported local changes are lost, and offers the export first.
struct SafeExitActions: View {
    @Environment(AppModel.self) private var model
    @State private var sheet: SafeExitSheet?

    enum SafeExitSheet: Identifiable {
        case export, keep, take
        var id: Self { self }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("root.toGetOutOf")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                sheet = .export
            } label: {
                Label("root.exportEncryptedBackup", systemImage: "square.and.arrow.down.on.square")
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
            .accessibilityIdentifier("safeExit.export")
            Button {
                sheet = .keep
            } label: {
                Label("Garder la version de cet appareil", systemImage: "checkmark.shield")
            }
            .buttonStyle(.glass)
            .controlSize(.large)
            .accessibilityIdentifier("safeExit.keep")
            Button(role: .destructive) {
                sheet = .take
            } label: {
                Label("Prendre la version d'iCloud", systemImage: "icloud.and.arrow.down")
            }
            .buttonStyle(.glass)
            .tint(.red)
            .controlSize(.large)
            .accessibilityIdentifier("safeExit.take")
        }
        .sheet(item: $sheet) { kind in
            switch kind {
            case .export: ExportBackupSheet()
            case .keep: SafeExitConfirmSheet(exit: .keepThisDevice) { sheet = .export }
            case .take: SafeExitConfirmSheet(exit: .takeServer) { sheet = .export }
            }
        }
    }
}

/// The safe exits in a sheet, for the places that only show the refusal (sync settings, the iPhone
/// banner, the Mac sidebar chip) while the vault stays readable from this device's copy.
struct SafeExitChooserSheet: View {
    let kind: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    IntegrityBanner(kind: kind)
                    SafeExitActions()
                }
                .padding(24)
            }
            .navigationTitle("Données refusées")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Fermer") { dismiss() }
                }
            }
        }
        #if os(macOS)
        .frame(width: 480, height: 420)
        #endif
    }
}

/// "Garder la version de cet appareil" or "Prendre la version d'iCloud": the master password, and
/// for iCloud's version an explicit confirmation of the loss. Once issued, the sheet says "En
/// attente d'iCloud" until every vault is `Ok` again, and "Réparé" only then.
struct SafeExitConfirmSheet: View {
    let exit: SafeExit
    /// "Exporter d'abord": the caller swaps this sheet for the export.
    let exportFirst: () -> Void

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var lossAccepted = false
    @State private var busy = false
    @State private var issued = false
    @State private var errorMessage: String?
    @FocusState private var focused: Bool

    private var title: LocalizedStringKey {
        exit == .keepThisDevice ? "Garder la version de cet appareil" : "Prendre la version d'iCloud"
    }

    private var confirmTitle: LocalizedStringKey {
        exit == .keepThisDevice ? "Garder cette version" : "Prendre la version d'iCloud"
    }

    private var canConfirm: Bool {
        !password.isEmpty && !busy && (exit == .keepThisDevice || lossAccepted)
    }

    var body: some View {
        NavigationStack {
            Form {
                if issued {
                    progress
                } else {
                    explanation
                    if exit == .takeServer { lossSection }
                    Section {
                        SecureField("Mot de passe maître", text: $password)
                            .focused($focused)
                            .onSubmit(run)
                            // No `.password` content type: iOS must never offer to save the master password.
                            .privacySensitive()
                            .accessibilityIdentifier("safeExit.password")
                    } footer: {
                        Text("root.masterPasswordRequiredTo")
                    }
                    if let errorMessage {
                        Section {
                            Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(title)
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                if issued {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Fermer") { dismiss() }
                    }
                } else {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Annuler") { dismiss() }.disabled(busy)
                    }
                    ToolbarItem(placement: exit == .takeServer ? .destructiveAction : .confirmationAction) {
                        Button(confirmTitle, role: exit == .takeServer ? .destructive : nil, action: run)
                            .disabled(!canConfirm)
                            .accessibilityIdentifier("safeExit.confirm")
                    }
                }
            }
            .onAppear { focused = true }
        }
        #if os(macOS)
        .frame(minWidth: 440, minHeight: 360)
        #endif
        .interactiveDismissDisabled(busy)
        .onDisappear { password = "" }
    }

    @ViewBuilder private var explanation: some View {
        Section {
            if exit == .keepThisDevice {
                Text("root.devicesVerifiedCopyReplaces")
            } else {
                Text("root.deviceTakesWhatIcloud")
            }
        }
    }

    private var lossSection: some View {
        Section {
            Label("root.changesMadeOnDevice", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
            Button("root.exportFirst", action: exportFirst)
                .accessibilityIdentifier("safeExit.exportFirst")
            Toggle("root.iUnderstandChangesNot", isOn: $lossAccepted)
                .accessibilityIdentifier("safeExit.acceptLoss")
        }
    }

    /// Never "Réparé" before the coordinator reports every vault `Ok` (`safeExitSettled`).
    @ViewBuilder private var progress: some View {
        Section {
            if model.safeExitSettled {
                Label("root.fixedIcloudServesSame", systemImage: "checkmark.icloud")
                    .foregroundStyle(.green)
                    .accessibilityIdentifier("safeExit.settled")
            } else {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text("root.waitingForIcloud")
                }
                .accessibilityIdentifier("safeExit.waiting")
                Text("root.syncContinuesInBackground")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func run() {
        guard canConfirm else { return }
        busy = true
        errorMessage = nil
        // Emptied on submission (success or not): the password lives on in a wiped buffer only (R5).
        let typed = SecretBytes(utf8: password)
        password = ""
        Task {
            defer { busy = false }
            do {
                try await model.runSafeExit(exit, password: typed)
                issued = true
            } catch {
                errorMessage = VaultError(error).localizedMessage
                focused = true
            }
        }
    }
}

/// "Exporter une sauvegarde chiffrée": master password, then a passphrase typed twice (its strength
/// is checked by the core). The archive is then saved through the same warning-first flow as the
/// Emergency Kit file: a warning, then the share sheet (iPhone, iPad, Vision Pro) or a save panel
/// with a second warning for a cloud folder (Mac).
struct ExportBackupSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var busy = false
    @State private var errorMessage: String?
    @State private var archive: Data?
    @State private var saveWarning = false
    @State private var saved = false
    #if os(macOS)
    @State private var cloudDestination: URL?
    @State private var cloudWarning = false
    #else
    @State private var sharedFile: SharedBackupFile?
    /// The temporary copy behind the share sheet, removed when the sheet closes.
    @State private var temporaryFile: URL?
    #endif

    private var fileName: String { EncryptedBackupFile.fileName(for: Date()) }

    private var canExport: Bool {
        !password.isEmpty && !passphrase.isEmpty && passphrase == confirmation && !busy
    }

    var body: some View {
        NavigationStack {
            Form {
                if archive == nil {
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
            .navigationTitle("root.encryptedBackup")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(archive == nil ? LocalizedStringKey("Annuler") : "Fermer") { dismiss() }.disabled(busy)
                }
                if archive == nil {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("common.export", action: export)
                            .disabled(!canExport)
                            .accessibilityIdentifier("safeExit.export.confirm")
                    }
                }
            }
            .alert("root.saveBackupToFile", isPresented: $saveWarning) {
                Button("common.continue") { saveFile() }
                Button("Annuler", role: .cancel) {}
            } message: {
                Text("root.fileHoldsWholeVault")
            }
            #if os(macOS)
            .alert("Cet emplacement est synchronisé dans le cloud", isPresented: $cloudWarning) {
                Button("app.saveAnyway", role: .destructive) {
                    if let url = cloudDestination { write(to: url) }
                    cloudDestination = nil
                }
                Button("Annuler", role: .cancel) { cloudDestination = nil }
            } message: {
                Text("root.fileWillCopiedTo")
            }
            #else
            .sheet(item: $sharedFile, onDismiss: removeSharedFile) { file in
                KitShareController(url: file.url) { sharedFile = nil }
                    .ignoresSafeArea()
            }
            #endif
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 420)
        #endif
        .interactiveDismissDisabled(busy)
        .onDisappear(perform: forget)
    }

    @ViewBuilder private var entry: some View {
        Section {
            Text("root.encryptedOnepassArchiveOf")
        }
        Section {
            SecureField("Mot de passe maître", text: $password)
                .privacySensitive()
                .accessibilityIdentifier("safeExit.export.password")
        }
        Section {
            SecureField("app.backupPassphrase", text: $passphrase)
                .privacySensitive()
                .accessibilityIdentifier("safeExit.export.passphrase")
            SecureField("root.confirmPassphrase", text: $confirmation)
                .privacySensitive()
                .onSubmit(export)
                .accessibilityIdentifier("safeExit.export.confirmation")
        } footer: {
            if !confirmation.isEmpty, passphrase != confirmation {
                Text("root.twoPassphrasesDontMatch").foregroundStyle(.red)
            } else {
                Text("root.chooseLongPassphraseDont")
            }
        }
    }

    @ViewBuilder private var ready: some View {
        Section {
            Label(saved ? LocalizedStringKey("root.backupSaved") : "Sauvegarde prête.", systemImage: "checkmark.seal")
                .foregroundStyle(.green)
            Text(verbatim: fileName)
                .font(.footnote.monospaced())
                .foregroundStyle(.secondary)
        }
        Section {
            Button("app.saveFile") { saveWarning = true }
                .accessibilityIdentifier("safeExit.export.save")
        } footer: {
            Text("root.keepPassphraseTooWithout")
        }
    }

    private func export() {
        guard canExport else { return }
        busy = true
        errorMessage = nil
        // Submitted: every field is emptied now (success or not); the secrets live on in wiped
        // buffers only, and cross the FFI as bytes (R5).
        let typed = SecretBytes(utf8: password)
        let phrase = SecretBytes(utf8: passphrase)
        password = ""
        passphrase = ""
        confirmation = ""
        Task {
            defer { busy = false }
            do {
                archive = try await model.exportEncryptedBackup(password: typed, passphrase: phrase)
            } catch {
                errorMessage = VaultError(error).localizedMessage
            }
        }
    }

    private func saveFile() {
        guard archive != nil else { return }
        #if os(macOS)
        Task {
            let type = UTType(filenameExtension: EncryptedBackupFile.fileExtension) ?? .data
            guard let url = await KitSavePanel.chooseDestination(
                fileName: fileName, contentType: type,
                message: String(localized: "root.chooseOfflineLocationSuch"))
            else { return }
            if KitDestination.isCloudSynced(url) {
                cloudDestination = url
                cloudWarning = true
            } else {
                write(to: url)
            }
        }
        #else
        guard let archive else { return }
        do {
            let url = try EncryptedBackupFile.write(archive, named: fileName, under: FileManager.default.temporaryDirectory)
            temporaryFile = url
            sharedFile = SharedBackupFile(url: url)
        } catch {
            errorMessage = ErrorText.appending(error, to: String(localized: "root.backupCouldntPrepared"))
        }
        #endif
    }

    #if os(macOS)
    private func write(to url: URL) {
        guard let archive else { return }
        do {
            try archive.write(to: url, options: .atomic)
            saved = true
        } catch {
            errorMessage = ErrorText.appending(error, to: String(localized: "root.backupCouldntSaved"))
        }
    }
    #else
    /// The share sheet closed: the temporary copy goes away.
    private func removeSharedFile() {
        if let url = temporaryFile {
            EncryptedBackupFile.remove(url, under: FileManager.default.temporaryDirectory)
        }
        temporaryFile = nil
        sharedFile = nil
        saved = true
    }
    #endif

    /// The sheet went away: fields emptied, archive bytes overwritten and dropped.
    private func forget() {
        #if os(iOS) || os(visionOS)
        removeSharedFile()
        #endif
        password = ""
        passphrase = ""
        confirmation = ""
        if var bytes = archive {
            archive = nil
            bytes.resetBytes(in: 0..<bytes.count)
        }
    }
}

#if os(iOS) || os(visionOS)
private struct SharedBackupFile: Identifiable {
    let url: URL
    var id: URL { url }
}
#endif
