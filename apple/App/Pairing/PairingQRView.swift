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
    /// iPhone and iPad: the scanner of the code a Mac shows (it never scans, ruling A2).
    @State private var scanningInvite = false

    var body: some View {
        Group {
            if let flow = model.pairing {
                content(flow)
                    .onChange(of: flow.state, initial: true) { _, state in model.pairingStateChanged(state) }
            } else {
                switch model.effectivePairMethod {
                case .scan:
                    ScanCodeStep(model: model)
                case .type:
                    TypeCodeStep(model: model)
                case .showCode:
                    ProgressView().frame(maxWidth: .infinity)
                }
            }
        }
    }

    @ViewBuilder private func content(_ flow: PairingNewcomerFlow) -> some View {
        if let stage = Self.stage(flow.state) {
            // One tile through the QR, the connection and the code to compare: it animates from one
            // to the next (`CipherQRCode`).
            switch flow.state {
            case .joining:
                StepTitle(
                    title: "Connexion à ton autre appareil",
                    subtitle: "Les deux appareils doivent être proches, sur le même Wi-Fi.")
            case .comparing:
                StepTitle(
                    title: "Compare les codes",
                    subtitle: "Le même code doit s'afficher sur ton autre appareil. S'il est différent, quelqu'un d'autre essaie de se connecter.")
            default:
                StepTitle(
                    title: "Scanne ce QR code",
                    subtitle: "Sur ton iPhone ou ton iPad : Réglages > Appareils > Ajouter un appareil")
            }
            PairingStageTile(stage: stage.tile, expiresAt: stage.expiresAt)
            switch flow.state {
            case .comparing:
                compareButtons(flow)
            case .joining:
                EmptyView()
            default:
                codeFootnotes
            }
        } else {
            other(flow)
        }
    }

    /// The tile's moment for the states that share it, with the QR's expiry.
    private static func stage(_ state: PairingNewcomerFlow.State) -> (tile: CipherQRCode.Stage, expiresAt: Date?)? {
        switch state {
        case .showingCode(let text, let expiresAt): (.code(text), expiresAt)
        case .joining: (.connecting, nil)
        case .comparing(let sas): (.verify(sas), nil)
        default: nil
        }
    }

    @ViewBuilder private var codeFootnotes: some View {
        Label(
            "Les deux appareils doivent être proches, sur le même Wi-Fi.",
            systemImage: "wifi")
            .font(.footnote)
            .foregroundStyle(.secondary)
        #if os(iOS)
        Button {
            scanningInvite = true
        } label: {
            Label("pairing.scanMyOtherDevices", systemImage: "qrcode.viewfinder")
                .frame(maxWidth: .infinity)
                .frame(height: 40)
        }
        .buttonStyle(.glass)
        .accessibilityIdentifier("pairing.scanInvite")
        .sheet(isPresented: $scanningInvite) {
            InviteScanSheet { text in
                scanningInvite = false
                model.joinInvite(text)
            }
        }
        Text("pairing.otherDeviceMacOpen")
            .font(.footnote)
            .foregroundStyle(.secondary)
        #endif
    }

    private func compareButtons(_ flow: PairingNewcomerFlow) -> some View {
        VStack(spacing: 10) {
            Button {
                Task { await flow.confirmCode() }
            } label: {
                Text("pairing.codesMatch")
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
                Text("pairing.theyreDifferent")
                    .frame(maxWidth: .infinity)
                    .frame(height: Platform.isMac ? 28 : 40)
            }
            .buttonStyle(.glass)
            .controlSize(Platform.isMac ? .large : .regular)
            .accessibilityIdentifier("pairing.codesDiffer")
        }
    }

    @ViewBuilder private func other(_ flow: PairingNewcomerFlow) -> some View {
        switch flow.state {
        case .idle:
            StepTitle(
                title: "Scanne ce QR code",
                subtitle: "Sur ton iPhone ou ton iPad : Réglages > Appareils > Ajouter un appareil")
            ProgressView().frame(maxWidth: .infinity, minHeight: 220)
        case .showingCode, .joining, .comparing:
            // Drawn by the shared tile above.
            EmptyView()
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

#if os(iOS)
/// The camera on the code another device shows (`OPJOIN1:` only: a pairing QR or anything else is
/// ignored). Debug builds take `-OnePassPairingInviteText` instead (ruling A3: no camera in the
/// Simulator).
private struct InviteScanSheet: View {
    let onInvite: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text("pairing.pointAtCodeMac")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                scanner
                    .frame(maxWidth: .infinity)
                    .frame(height: 360)
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            }
            .padding(20)
            .frame(maxHeight: .infinity, alignment: .top)
            .navigationTitle("pairing.scanCode")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
            }
        }
    }

    @ViewBuilder private var scanner: some View {
        #if DEBUG
        if let injected = UserDefaults.standard.string(forKey: "OnePassPairingInviteText"), !injected.isEmpty {
            Label("pairing.injectedCodeDebug", systemImage: "ladybug")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(.fill.tertiary)
                .task { onInvite(injected) }
        } else {
            camera
        }
        #else
        camera
        #endif
    }

    @ViewBuilder private var camera: some View {
        if SecretKeyScanner.isSupported {
            SecretKeyScanner(onKey: onInvite) { payload in
                let text = payload.trimmingCharacters(in: .whitespacesAndNewlines)
                return pairingCodeKind(text: text) == .invite ? text : nil
            }
        } else {
            ContentUnavailableView(
                "Caméra indisponible", systemImage: "camera",
                description: Text("pairing.deviceCantReadQr"))
                .background(.fill.tertiary)
        }
    }
}
#endif

/// The QR code of the pairing on its tile (`CipherQRCode`) and the time it stays valid. The flow
/// replaces it before it expires.
struct PairingQRView: View {
    /// How the code on screen is replaced: every 30 s (the new device's QR), or shortly before it
    /// expires (the approver's invite).
    enum Renewal { case every30s, beforeExpiry }

    let text: String
    let expiresAt: Date
    var renewal: Renewal = .every30s

    var body: some View {
        VStack(spacing: 12) {
            PairingStageTile(stage: .code(text), expiresAt: expiresAt)
            PairingCountdown(expiresAt: expiresAt, renewal: renewal)
        }
        .frame(maxWidth: .infinity)
        #if DEBUG
        // Simulator end to end (ruling A3): the other device takes this text with
        // `-OnePassPairingQRText` (or `-OnePassPairingInviteText` for an invite). Debug builds only:
        // an invite carries its one-time secret.
        .onChange(of: text, initial: true) { _, value in print("OnePassPairingQRText \(value)") }
        #endif
        #if os(macOS)
        // An invite carries its secret: kept out of screen sharing and recordings.
        .background(WindowSharingGuard(active: renewal == .beforeExpiry))
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

/// The pairing tile (`CipherQRCode`) at the size of the pairing screens, named for assistive
/// technologies after what it shows: the QR code, the connection, or the code to compare.
struct PairingStageTile: View {
    let stage: CipherQRCode.Stage
    var expiresAt: Date?

    private var label: Text {
        switch stage {
        case .code: Text("pairing.pairingQrCode")
        case .connecting: Text("Connexion à ton autre appareil")
        case .verify: Text("Code de vérification")
        }
    }

    private var value: Text {
        if case .verify(let code) = stage { Text(verbatim: code.map(String.init).joined(separator: " ")) } else { Text(verbatim: "") }
    }

    private var identifier: String {
        switch stage {
        case .code: "pairing.qr"
        case .connecting: "pairing.connecting"
        case .verify: "pairing.code"
        }
    }

    var body: some View {
        CipherQRCode(stage: stage, expiresAt: expiresAt)
            .frame(maxWidth: Platform.isMac ? 260 : 280)
            .frame(maxWidth: .infinity)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(label)
            .accessibilityValue(value)
            .accessibilityIdentifier(identifier)
    }
}

/// How long the code on screen stays, in words under the tile (the ring around the tile says the
/// same).
private struct PairingCountdown: View {
    let expiresAt: Date
    let renewal: PairingQRView.Renewal

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let left = max(0, Int(expiresAt.timeIntervalSince(context.date).rounded(.up)))
            Group {
                switch renewal {
                case .every30s: Text("pairing.newCodeShowsEvery \(left)")
                case .beforeExpiry: Text("pairing.codeStaysValidFor \(left)")
                }
            }
            .font(.footnote.monospacedDigit())
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
        }
    }
}

#if os(macOS)
/// Keeps its window out of screen sharing and screen recordings while `active` (the window shows an
/// invite's secret), and gives the window back as it was afterwards.
private struct WindowSharingGuard: NSViewRepresentable {
    let active: Bool

    final class Probe: NSView {
        var active = false { didSet { apply() } }
        private weak var guarded: NSWindow?
        private var previous: NSWindow.SharingType = .readOnly

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            apply()
        }

        func apply() {
            if active, let window, guarded !== window {
                release()
                previous = window.sharingType
                window.sharingType = .none
                guarded = window
            } else if !active || window == nil {
                release()
            }
        }

        func release() {
            guarded?.sharingType = previous
            guarded = nil
        }
    }

    func makeNSView(context: Context) -> Probe {
        let probe = Probe()
        probe.active = active
        return probe
    }

    func updateNSView(_ view: Probe, context: Context) {
        view.active = active
    }

    static func dismantleNSView(_ view: Probe, coordinator: ()) {
        view.release()
    }
}
#endif
