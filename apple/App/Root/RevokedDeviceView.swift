import DesignKit
import SwiftUI
import VaultKit

/// The signed device list marked this device revoked: the session is locked and its OnePass data
/// kept (rule 8.4 of the key rotation v2 spec: a revoked device can sign that list too). "Effacer cet
/// appareil" erases it after a confirmation. When the erase failed (L6), the screen says so and
/// "Réessayer" tries again (also once on appear, after a relaunch).
struct RevokedDeviceView: View {
    @Environment(AppModel.self) private var model
    @State private var confirmErase = false

    private var eraseFailed: Bool { model.session.revokedEraseFailed }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "iphone.slash")
                .font(.system(size: 52, weight: .light))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(VaultError.deviceRevoked.localizedMessage)
                .font(.title2.bold())
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("revoked.message")
            Group {
                if eraseFailed {
                    Text("Ses données OnePass n'ont pas encore pu être effacées. OnePass réessaie à chaque ouverture ; tu peux aussi réessayer maintenant.")
                } else {
                    Text("Ses données OnePass restent chiffrées sur cet appareil tant que tu ne l'effaces pas. Si tu ne l'as pas retiré depuis un autre de tes appareils, un appareil déjà retiré a pu le faire : vérifie tes appareils avant d'effacer.")
                }
            }
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .accessibilityIdentifier("revoked.detail")
            Button {
                if eraseFailed {
                    Task { await model.session.refresh() }
                } else {
                    confirmErase = true
                }
            } label: {
                Text(eraseFailed ? "Réessayer" : "Effacer cet appareil")
                    .font(.headline).frame(minWidth: 160).frame(height: Platform.isMac ? 24 : 40)
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .accessibilityIdentifier("revoked.continue")
        }
        .frame(maxWidth: 440)
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .confirmationDialog(
            "Effacer les données OnePass de cet appareil ?", isPresented: $confirmErase, titleVisibility: .visible
        ) {
            Button("Effacer", role: .destructive) { Task { await model.session.eraseRevokedDevice() } }
                .accessibilityIdentifier("revoked.confirmErase")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Ce qui n'a pas encore été synchronisé sera perdu. Tu pourras l'ajouter de nouveau depuis un autre appareil ou avec ton Emergency Kit.")
        }
        .task {
            // After a relaunch the erase is tried again at once.
            if eraseFailed { await model.session.refresh() }
        }
    }
}
