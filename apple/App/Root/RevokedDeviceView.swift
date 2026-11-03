import DesignKit
import SwiftUI
import VaultKit

/// The signed device list marked this device revoked: the session is locked and its OnePass data
/// kept (rule 8.4 of the key rotation v2 spec: a revoked device can sign that list too). "Effacer cet
/// appareil" erases it after a confirmation. When the erase failed (L6), the screen says so and
/// "Réessayer" tries again (also once on appear, after a relaunch). A device the key lineage removed
/// (quarantine, also every old device after a recovery) shows the date it erases itself and the time
/// left (founder decision 2026-11-03).
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
                    Text("root.onepassDataCouldNot")
                } else {
                    Text("root.onepassDataStaysEncrypted")
                }
            }
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .accessibilityIdentifier("revoked.detail")
            if let eraseAt = model.session.quarantineEraseAt, !eraseFailed {
                // Key rotation v2 quarantine: the date the device erases itself and the time left.
                VStack(spacing: 4) {
                    Text("root.quarantineErasesOn \(eraseAt.formatted(date: .long, time: .shortened))")
                    Text("root.quarantineTimeLeft \(Text(eraseAt, style: .relative))")
                        .monospacedDigit()
                }
                .font(.callout.weight(.medium))
                .multilineTextAlignment(.center)
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("revoked.eraseAt")
            }
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
            Button("app.erase", role: .destructive) { Task { await model.session.eraseRevokedDevice() } }
                .accessibilityIdentifier("revoked.confirmErase")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("root.anythingNotSyncedYet")
        }
        .task {
            // After a relaunch the erase is tried again at once.
            if eraseFailed { await model.session.refresh() }
        }
    }
}
