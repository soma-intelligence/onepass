import CoreImage
import CoreImage.CIFilterBuiltins
import DesignKit
import SwiftUI
import VaultKit

/// The pairing step of the new device, driven by `PairingNewcomerFlow`: the QR (renewed every 30 s),
/// the code to compare, the wait for the approval, then the master password. Errors show the flow's
/// message and "Recommencer".
struct PairingStep: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        Group {
            if let flow = model.pairing {
                content(flow)
                    .onChange(of: flow.state, initial: true) { _, state in model.pairingStateChanged(state) }
            } else {
                ProgressView().frame(maxWidth: .infinity)
            }
        }
    }

    @ViewBuilder private func content(_ flow: PairingNewcomerFlow) -> some View {
        switch flow.state {
        case .idle, .showingCode:
            StepTitle(
                title: "Scanne ce QR code",
                subtitle: "Sur ton iPhone ou ton iPad : Réglages > Appareils > Ajouter un appareil")
            if case .showingCode(let text, let expiresAt) = flow.state {
                PairingQRView(text: text, expiresAt: expiresAt)
            } else {
                ProgressView().frame(maxWidth: .infinity, minHeight: 220)
            }
            Label(
                "Les deux appareils doivent être proches, sur le même Wi-Fi.",
                systemImage: "wifi")
                .font(.footnote)
                .foregroundStyle(.secondary)
        case .comparing(let sas):
            StepTitle(
                title: "Compare les codes",
                subtitle: "Le même code doit s'afficher sur ton autre appareil. S'il est différent, quelqu'un d'autre essaie de se connecter.")
            PairingCodeView(code: sas)
            VStack(spacing: 10) {
                Button {
                    Task { await flow.confirmCode() }
                } label: {
                    Text("Les codes sont identiques")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .frame(height: Platform.isMac ? 28 : 40)
                }
                .buttonStyle(.glassProminent)
                .controlSize(Platform.isMac ? .large : .regular)
                .accessibilityIdentifier("pairing.codesMatch")
                Button(role: .destructive) {
                    flow.rejectCode()
                } label: {
                    Text("Ils sont différents")
                        .frame(maxWidth: .infinity)
                        .frame(height: Platform.isMac ? 28 : 40)
                }
                .buttonStyle(.glass)
                .controlSize(Platform.isMac ? .large : .regular)
                .accessibilityIdentifier("pairing.codesDiffer")
            }
        case .waitingForApproval:
            StepTitle(
                title: "En attente de ton autre appareil",
                subtitle: "Confirme les codes sur ton autre appareil, puis valide avec Face ID ou ton mot de passe maître.")
            ProgressView().frame(maxWidth: .infinity, minHeight: 80)
        case .receivedFull, .importing:
            PairingPasswordStep(model: model)
        case .done:
            ProgressView().frame(maxWidth: .infinity, minHeight: 80)
        case .receivedPublic:
            StepTitle(title: "Session invitée", subtitle: "Ouverture...")
        case .cancelled:
            StepTitle(title: "Appairage arrêté", subtitle: nil)
        case .failed(let failure):
            StepTitle(title: "L'appairage n'a pas abouti", subtitle: nil)
            Label(failure.message, systemImage: "exclamationmark.triangle.fill")
                .font(.subheadline)
                .foregroundStyle(.red)
                .accessibilityIdentifier("pairing.error")
        }
    }
}

/// The QR code of the pairing (CoreImage, sharp modules on white) and the time it stays valid. The
/// flow replaces it before it expires.
struct PairingQRView: View {
    let text: String
    let expiresAt: Date

    var body: some View {
        VStack(spacing: 12) {
            if let image = Self.image(text, side: 600) {
                Image(decorative: image, scale: 1)
                    .interpolation(.none)
                    .resizable()
                    .aspectRatio(1, contentMode: .fit)
                    .frame(maxWidth: Platform.isMac ? 260 : 280)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .accessibilityLabel(Text("QR code d'appairage"))
                    .accessibilityIdentifier("pairing.qr")
            }
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let left = max(0, Int(expiresAt.timeIntervalSince(context.date).rounded(.up)))
                Text("Un nouveau code s'affiche toutes les 30 s. Celui-ci reste valable \(left) s.")
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity)
        .card()
        #if DEBUG
        // Simulator end to end (ruling A3): the approver takes this text with `-OnePassPairingQRText`.
        .onChange(of: text, initial: true) { _, value in print("OnePassPairingQRText \(value)") }
        #endif
    }

    /// A square QR code (error correction M, 4 module quiet zone, whole-module scaling).
    static func image(_ text: String, side: CGFloat) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let raw = filter.outputImage else { return nil }
        let quiet: CGFloat = 4
        let modules = raw.extent.width
        let scale = max(1, floor(side / (modules + 2 * quiet)))
        let full = (modules + 2 * quiet) * scale
        let code = raw
            .samplingNearest()
            .transformed(by: CGAffineTransform(scaleX: scale, y: scale))
            .transformed(by: CGAffineTransform(translationX: quiet * scale, y: quiet * scale))
        let white = CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: full, height: full))
        let composed = code.composited(over: white).cropped(to: white.extent)
        return CIContext(options: [.useSoftwareRenderer: true]).createCGImage(composed, from: composed.extent)
    }
}
