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
            subtitle: "Sur ton Mac : Fichier > Configurer un appareil… Le code à 8 caractères s'affiche sous le QR code.")
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
/// "Scanner un QR code": OnePass's own scanner, which takes only an `OPPAIR2:` text.
struct ScanCodeStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        StepTitle(
            title: "Scanne le QR code",
            subtitle: "Sur ton Mac : Fichier > Configurer un appareil… Place le QR code dans le cadre.")
        Label {
            Text("Ne scanne jamais un QR code qu'on t'a envoyé.")
                .font(.subheadline.weight(.semibold))
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
        }
        SecretKeyScanner(onKey: { text in model.joinPairing(code: text) }, accept: RendezvousQR.accept)
            .frame(maxWidth: .infinity)
            .frame(height: 320)
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .accessibilityIdentifier("pairing.scanner")
        Button("Saisir le code à la place") { model.pairMethod = .type }
            .buttonStyle(.plain)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(Theme.accent)
            .frame(maxWidth: .infinity)
            .accessibilityIdentifier("pairing.scan.typeInstead")
    }
}

/// The rendezvous QR text: `OPPAIR2:` and nothing else (no URL, the system camera never opens it).
enum RendezvousQR {
    static let prefix = "OPPAIR2:"

    static func accept(_ payload: String) -> String? {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.hasPrefix(prefix) ? trimmed : nil
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
