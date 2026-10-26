import DesignKit
import SwiftUI
import VaultKit

/// "Données refusées" (spec 8): the core refused the stored data. Nothing from the vault is shown
/// while the error lasts and the storage is never repaired automatically. "Réessayer" runs a sync
/// round then reads the store again. Other store failures (unreadable database) use the same screen
/// with their message.
struct IntegrityFailureView: View {
    let error: VaultError
    /// Retry action; the app passes `AppModel.retryAfterFailure`. Previews pass nil.
    var retry: (() async -> Void)?

    @Environment(AppModel.self) private var model: AppModel?
    @State private var retrying = false
    @State private var showDetails = false

    private var integrityKind: String? {
        if case .integrity(let kind) = error { return kind }
        return nil
    }

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
                    Text("OnePass a détecté une modification du stockage qu'il n'a pas faite lui-même. Par sécurité, aucune donnée n'est affichée et rien n'est réparé automatiquement.")
                        .foregroundStyle(.secondary)
                } else {
                    Text(error.localizedMessage)
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 12) {
                    Button {
                        Task { await runRetry() }
                    } label: {
                        if retrying {
                            ProgressView().controlSize(.small)
                        } else {
                            Text("Réessayer")
                        }
                    }
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                    .disabled(retrying)
                    .accessibilityIdentifier("integrity.retry")
                    Button("En savoir plus") { showDetails = true }
                        .accessibilityIdentifier("integrity.learnMore")
                        .buttonStyle(.glass)
                        .controlSize(.large)
                }
            }
            .frame(maxWidth: 520, alignment: .leading)
            .padding(32)
            .frame(maxWidth: .infinity)
        }
        .sheet(isPresented: $showDetails) { details }
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
                    Text("Chaque coffre porte une liste signée de ses éléments et un numéro de version. OnePass vérifie ces signatures à chaque lecture : un élément retiré, ajouté, modifié ou une ancienne version rejouée par le stockage ou par iCloud est refusé.")
                    Text("Réessayer relance une synchronisation complète puis relit le stockage. Si le problème persiste, tes données restent chiffrées et intactes sur tes autres appareils : n'efface rien et utilise un autre appareil ou ton Emergency Kit.")
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
        .frame(width: 460, height: 320)
        #endif
    }
}

#Preview("Données refusées") {
    IntegrityFailureView(error: .integrity(kind: "manifest_rollback"), retry: {})
}

#Preview("Stockage illisible") {
    IntegrityFailureView(error: .other("Le stockage local est illisible."), retry: {})
}
