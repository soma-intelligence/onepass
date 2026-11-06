import DesignKit
import SwiftUI
import VaultKit

/// "Données refusées" (spec 8): the core refused the stored data. Nothing from the vault is shown
/// while the error lasts and the storage is never repaired automatically. "Réessayer" runs a sync
/// round then reads the store again. Other store failures (unreadable database) use the same screen
/// with their message. For remote data refused (not a missing account), the safe exits of spec 3.3
/// follow "Réessayer": export first, then keep this device's version or take iCloud's.
struct IntegrityFailureView: View {
    let error: VaultError
    /// Retry action; the app passes `AppModel.retryAfterFailure`. Previews pass nil.
    var retry: (() async -> Void)?

    @Environment(AppModel.self) private var model: AppModel?
    @State private var retrying = false
    @State private var showDetails = false
    @State private var confirmKitRestore = false
    @State private var confirmStartOver = false
    @State private var recoveryError: String?

    private var integrityKind: String? {
        if case .integrity(let kind) = error { return kind }
        return nil
    }

    /// "Le compte a disparu du stockage": the screen offers ways out (spec 14, ruling E22).
    private var accountMissing: Bool { integrityKind == VaultSession.accountMissingKind }
    private var cloudKitEnabled: Bool { model?.cloudKitEnabled ?? false }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 52))
                    .foregroundStyle(.red)
                    .accessibilityHidden(true)
                Text("Données refusées")
                    .font(.largeTitle.bold())
                if let integrityKind {
                    IntegrityBanner(kind: integrityKind)
                    Text("root.onepassFoundChangeIn")
                        .foregroundStyle(.secondary)
                } else {
                    Text(error.localizedMessage)
                        .foregroundStyle(.secondary)
                }
                if accountMissing {
                    recoveryActions
                } else {
                    HStack(spacing: 12) {
                        retryButton(title: "Réessayer")
                        Button("root.learnMore") { showDetails = true }
                            .accessibilityIdentifier("integrity.learnMore")
                            .buttonStyle(.glass)
                            .controlSize(.large)
                    }
                    if integrityKind != nil, model?.session.safeExitAvailable == true {
                        Divider()
                        SafeExitActions()
                            .disabled(retrying)
                    }
                }
            }
            .frame(maxWidth: 520, alignment: .leading)
            .padding(32)
            .frame(maxWidth: .infinity)
        }
        .sheet(isPresented: $showDetails) { details }
        .sheet(isPresented: $confirmStartOver) {
            StartOverConfirmation { try await model?.startOver() }
        }
        .confirmationDialog(
            "Restaurer avec ton Emergency Kit ?", isPresented: $confirmKitRestore, titleVisibility: .visible
        ) {
            Button("root.eraseLocalCopyAnd", role: .destructive) {
                Task { await recover { try await model?.recoverWithEmergencyKit() } }
            }
            .accessibilityIdentifier("integrity.kitRestore.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text(kitRestoreMessage)
        }
        .alert(
            "Action impossible", isPresented: Binding(get: { recoveryError != nil }, set: { if !$0 { recoveryError = nil } })
        ) {
            Button("OK") { recoveryError = nil }
        } message: {
            Text(recoveryError ?? "")
        }
    }

    private var kitRestoreMessage: String {
        cloudKitEnabled
            ? String(localized: "root.copyOfVaultOn2")
            : String(localized: "root.copyOfVaultOn")
    }

    private func retryButton(title: LocalizedStringKey) -> some View {
        Button {
            Task { await runRetry() }
        } label: {
            if retrying {
                ProgressView().controlSize(.small)
            } else {
                Text(title)
            }
        }
        .buttonStyle(.glassProminent)
        .controlSize(.large)
        .disabled(retrying)
        .accessibilityIdentifier("integrity.retry")
    }

    /// iCloud first (when there is one), then the Emergency Kit, then starting over (destructive, last).
    private var recoveryActions: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("root.ifVaultStillExists")
                .font(.callout)
                .foregroundStyle(.secondary)
            if cloudKitEnabled {
                retryButton(title: "Récupérer depuis iCloud")
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Button {
                confirmKitRestore = true
            } label: {
                Label("root.restoreWithMyEmergency", systemImage: "doc.text.viewfinder")
            }
            .buttonStyle(.glass)
            .controlSize(.large)
            .disabled(retrying)
            .accessibilityIdentifier("integrity.kitRestore")
            Button(role: .destructive) {
                confirmStartOver = true
            } label: {
                Label("root.startOver", systemImage: "trash")
            }
            .buttonStyle(.glass)
            .tint(.red)
            .controlSize(.large)
            .disabled(retrying)
            .accessibilityIdentifier("integrity.startOver")
            Button("root.learnMore") { showDetails = true }
                .accessibilityIdentifier("integrity.learnMore")
                .buttonStyle(.borderless)
        }
    }

    private func recover(_ action: () async throws -> Void) async {
        retrying = true
        defer { retrying = false }
        do {
            try await action()
        } catch {
            recoveryError = VaultError(error).localizedMessage
        }
    }

    private func runRetry() async {
        retrying = true
        defer { retrying = false }
        if let retry {
            await retry()
        } else {
            await model?.retryAfterFailure()
        }
    }

    private var details: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text("root.eachVaultCarriesSigned")
                    if accountMissing {
                        Text("root.accountDeviceKnewNo")
                        Text("root.recoverFromIcloudRuns")
                    } else {
                        Text("root.tryAgainRunsFull")
                        Text("root.exportingEncryptedBackupKeeps")
                    }
                }
                .padding(24)
            }
            .navigationTitle("Données refusées")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("OK") { showDetails = false }
                }
            }
        }
        #if os(macOS)
        .frame(width: 460, height: 360)
        #endif
    }
}

/// "Repartir de zéro": the user types EFFACER to confirm. The local copy is cleared and the onboarding
/// starts over; nothing in iCloud is deleted.
struct StartOverConfirmation: View {
    let action: () async throws -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var typed = ""
    @State private var working = false
    @State private var errorMessage: String?

    static let word = "EFFACER"
    private var confirmed: Bool { typed.trimmingCharacters(in: .whitespaces) == Self.word }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("root.copyOfVaultOn3")
                    Text("root.nothingErasedInIcloud")
                        .foregroundStyle(.secondary)
                }
                Section {
                    TextField("EFFACER", text: $typed)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.characters)
                        #endif
                        .accessibilityIdentifier("startOver.field")
                } header: {
                    Text("root.typeEraseToConfirm")
                } footer: {
                    if let errorMessage { Text(errorMessage).foregroundStyle(.red) }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("root.startOver")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }.disabled(working)
                }
                ToolbarItem(placement: .destructiveAction) {
                    Button("app.erase", role: .destructive) {
                        Task { await run() }
                    }
                    .disabled(!confirmed || working)
                    .accessibilityIdentifier("startOver.confirm")
                }
            }
        }
        #if os(macOS)
        .frame(width: 440, height: 340)
        #endif
    }

    private func run() async {
        working = true
        defer { working = false }
        do {
            try await action()
            dismiss()
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }
}

#Preview("Données refusées") {
    IntegrityFailureView(error: .integrity(kind: "manifest_rollback"), retry: {})
}

#Preview("Compte disparu") {
    IntegrityFailureView(error: .integrity(kind: "account_missing"), retry: {})
}

#Preview("Stockage illisible") {
    IntegrityFailureView(error: .other("Le stockage local est illisible."), retry: {})
}
