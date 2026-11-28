import DesignKit
import SwiftUI
import VaultKit

/// "Saisir un code": the 8 characters the unlocked device shows (`K7QM-4XPR`). Case, spaces and the
/// hyphen do not matter. Debug builds take `-OnePassJoinCode` instead of a keyboard (ruling A3).
struct TypeCodeStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        StepTitle(
            title: "Saisis le code",
            subtitle: "pairing.type.whereToFindCode")
        OnboardingField(
            label: "Code d'appairage", prompt: "K7QM-4XPR", text: $model.joinCode, monospaced: true,
            secretKey: true, identifier: "pairing.joinCode")
            .onSubmit { Task { await model.primary() } }
        Label(
            "Les deux appareils doivent être proches, sur le même Wi-Fi.",
            systemImage: "wifi")
            .font(.footnote)
            .foregroundStyle(.secondary)
        Color.clear.frame(height: 0)
            .onAppear {
                #if DEBUG
                if let injected = UserDefaults.standard.string(forKey: "OnePassJoinCode"), !injected.isEmpty,
                    model.joinCode.isEmpty
                {
                    // Debug only, never in Release (ruling A3: the Simulator has no camera).
                    model.joinCode = injected
                    model.joinPairing(code: injected)
                }
                #endif
            }
    }
}

#if os(iOS)
/// "Scanner un QR code": Cleon's own scanner, which takes only an `OPPAIR2:` text.
struct ScanCodeStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        StepTitle(
            title: "Scanne le QR code",
            subtitle: "pairing.scan.whereToFindCode")
        Label {
            Text("pairing.neverScanQrCode")
                .font(.subheadline.weight(.semibold))
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
        }
        // Both codes of the unlocked device: the invite of Réglages > Appareils and the code of
        // Fichier > Configurer un appareil… Anything else says so under the camera.
        SecretKeyScanner(
            onKey: { text in model.joinScanned(text) },
            accept: { payload in
                let routed = PairingScanText.route(payload)
                if routed == nil { model.scanRejected = true }
                return routed == nil ? nil : payload
            }
        )
            .frame(maxWidth: .infinity)
            .frame(height: 320)
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .accessibilityIdentifier("pairing.scanner")
        if model.scanRejected {
            Label("pairing.scan.notOnePassCode", systemImage: "exclamationmark.triangle.fill")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("pairing.scan.rejected")
        }
        Button("pairing.typeCodeInstead") { model.pairMethod = .type }
            .buttonStyle(.plain)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Theme.accent)
            .frame(maxWidth: .infinity)
            .accessibilityIdentifier("pairing.scan.typeInstead")
    }
}

#else
/// The Mac and the Vision Pro have no QR scanner: `pairMethod` never selects `.scan` there.
struct ScanCodeStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        TypeCodeStep(model: model)
    }
}
#endif
