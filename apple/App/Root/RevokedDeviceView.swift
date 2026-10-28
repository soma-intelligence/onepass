import DesignKit
import SwiftUI
import VaultKit

/// The signed device list marked this device revoked: its OnePass data was erased (ruling A5).
/// "Continuer" goes back to the welcome screen.
struct RevokedDeviceView: View {
    @Environment(AppModel.self) private var model

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
            Text("Ses données OnePass ont été effacées. Tu peux l'ajouter de nouveau depuis un autre appareil ou avec ton Emergency Kit.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                Task { await model.session.refresh() }
            } label: {
                Text("Continuer").font(.headline).frame(minWidth: 160).frame(height: Platform.isMac ? 24 : 40)
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .accessibilityIdentifier("revoked.continue")
        }
        .frame(maxWidth: 440)
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
