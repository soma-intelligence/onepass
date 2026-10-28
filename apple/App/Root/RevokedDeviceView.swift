import DesignKit
import SwiftUI
import VaultKit

/// The signed device list marked this device revoked: its OnePass data was erased (ruling A5).
/// "Continuer" goes back to the welcome screen. When the erase failed (L6), the screen says so and
/// "Réessayer" tries again (also once on appear, after a relaunch).
struct RevokedDeviceView: View {
    @Environment(AppModel.self) private var model

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
                    Text("Ses données OnePass ont été effacées. Tu peux l'ajouter de nouveau depuis un autre appareil ou avec ton Emergency Kit.")
                }
            }
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .accessibilityIdentifier("revoked.detail")
            Button {
                Task { await model.session.refresh() }
            } label: {
                Text(eraseFailed ? "Réessayer" : "Continuer")
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
        .task {
            // After a relaunch the erase is tried again at once.
            if eraseFailed { await model.session.refresh() }
        }
    }
}
