import DesignKit
import SwiftUI
import VaultKit

/// "Ajouter un appareil" (spec 2b 5.1, approver side). On iPhone and iPad: the warning, OnePass's own
/// scanner (only an `OPPAIR1:` QR is accepted). On the Mac, which never scans (ruling A2): the invite
/// code the new device scans, renewed before it expires. Then the new device's kind, name and
/// requested mode, the 6-digit code, "Les codes sont identiques", a fresh presence check (Face ID or
/// Touch ID, else the master password) and the grant. A public request first picks the lent items and
/// the duration, then shows the monitor (iPhone and iPad only).
struct ApproveDeviceSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var flow: PairingApproverFlow?
    /// Public request: the codes matched here, the picker is on screen.
    @State private var picking = false
    @State private var password = ""
    @State private var approving = false

    var body: some View {
        NavigationStack {
            Group {
                if let flow {
                    content(flow)
                } else {
                    ProgressView()
                }
            }
            .navigationTitle(Platform.isMac ? "Configurer un appareil" : "Ajouter un appareil")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    // Not while the grant is sent: it may already be out (M1).
                    Button(finished ? "OK" : "Annuler") { close() }
                        .disabled(granting)
                        .accessibilityIdentifier("approve.close")
                }
            }
        }
        .interactiveDismissDisabled(!finished)
        #if os(macOS)
        .frame(width: 460, height: 620)
        #endif
        .onAppear {
            if flow == nil {
                let flow = PairingApproverFlow(vault: model.session, connector: LocalNetworkPairingConnector())
                self.flow = flow
                #if os(macOS)
                Task { await flow.invite(listener: LocalNetworkPairingListener()) }
                #endif
            }
        }
        .onDisappear {
            flow?.cancel()
            password = ""
        }
    }

    private var granting: Bool {
        if case .granting = flow?.state { true } else { false }
    }

    private var finished: Bool {
        switch flow?.state {
        case .done, .failed: true
        default: false
        }
    }

    private func close() {
        flow?.cancel()
        dismiss()
    }

    @ViewBuilder private func content(_ flow: PairingApproverFlow) -> some View {
        switch flow.state {
        case .idle:
            #if os(iOS)
            ScanStep { text in Task { await flow.begin(qrText: text) } }
            #else
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            #endif
        case .inviting(let text, let expiresAt):
            InviteStep(text: text, expiresAt: expiresAt)
        case .connecting, .hosting:
            // `hosting` is the Mac's way in (the code is shown there); this sheet scans.
            status("Connexion au nouvel appareil...", detail: "Les deux appareils doivent être proches, sur le même Wi-Fi.")
        case .comparing(let sas, let peer, let requestedMode):
            #if os(iOS)
            if requestedMode == .public, picking {
                PublicSessionPicker(flow: flow)
            } else {
                compare(flow, sas: sas, peer: peer, mode: requestedMode)
            }
            #else
            compare(flow, sas: sas, peer: peer, mode: requestedMode)
            #endif
        case .waitingForPeer:
            status("En attente du nouvel appareil...", detail: "Confirme que les codes sont identiques sur le nouvel appareil.")
        case .granting:
            status("Envoi...", detail: nil)
        case .publicRunning:
            #if os(iOS)
            PublicSessionMonitor(flow: flow)
            #else
            EmptyView()
            #endif
        case .done:
            outcome(
                symbol: "checkmark.circle.fill", tint: .green,
                title: picking ? "Session terminée" : "Appareil ajouté",
                message: picking
                    ? String(localized: "Le nouvel appareil n'a plus accès aux éléments prêtés.")
                    : String(localized: "Il te demande maintenant ton mot de passe maître."))
        case .failed(let failure):
            outcome(
                symbol: "exclamationmark.triangle.fill", tint: .red, title: "L'appairage n'a pas abouti",
                message: failure.message)
        }
    }

    // MARK: - Code comparison

    private func compare(_ flow: PairingApproverFlow, sas: String, peer: FfiPeerDevice, mode: FfiDeviceMode) -> some View {
        Form {
            Section {
                HStack(spacing: 14) {
                    Image(systemName: DeviceKindText.symbol(peer.kind))
                        .font(.system(size: 22, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: 48, height: 48)
                        .background(Theme.accent.gradient, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(peer.name).font(.headline)
                        Text("\(DeviceKindText.kind(peer.kind)) · demande un accès \(DeviceKindText.mode(mode))")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("approve.peer")
            } footer: {
                Text(modeFooter(mode))
            }
            Section {
                PairingCodeView(code: sas)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
            } header: {
                Text("Code de vérification")
            } footer: {
                Text("Le même code doit s'afficher sur le nouvel appareil.")
            }
            if flow.approvalError != nil {
                Section {
                    SecureField("Mot de passe maître", text: $password)
                        .privacySensitive()
                        .onSubmit {
                            // Return twice must not start a second approval (L1).
                            guard !approving, !password.isEmpty else { return }
                            Task { await approve(flow, mode: mode) }
                        }
                        .accessibilityIdentifier("approve.password")
                } footer: {
                    if let error = flow.approvalError, error != .passwordRequired {
                        Text(error.localizedMessage).foregroundStyle(.red)
                    } else {
                        Text("Confirme avec ton mot de passe maître.")
                    }
                }
            }
            #if os(macOS)
            if mode == .public {
                Section {
                    Label(
                        "Une session invitée s'approuve depuis ton iPhone ou ton iPad.",
                        systemImage: "iphone")
                        .foregroundStyle(.secondary)
                }
            }
            #endif
            Section {
                Button {
                    Task { await approve(flow, mode: mode) }
                } label: {
                    HStack {
                        Text("Les codes sont identiques").font(.headline)
                        Spacer()
                        if approving { ProgressView() }
                    }
                }
                .disabled(approving || (flow.approvalError != nil && password.isEmpty) || (Platform.isMac && mode == .public))
                .accessibilityIdentifier("approve.codesMatch")
                Button("Ils sont différents", role: .destructive) { flow.cancel() }
                    .disabled(approving)
                    .accessibilityIdentifier("approve.codesDiffer")
            }
        }
        .formStyle(.grouped)
    }

    private func modeFooter(_ mode: FfiDeviceMode) -> LocalizedStringKey {
        switch mode {
        case .personal: "Il recevra tout ton compte et ta Secret Key, puis te demandera ton mot de passe maître."
        case .shared: "Il recevra tout ton compte, sans Face ID, avec les coffres visibles au choix."
        case .public: "Il recevra seulement les éléments que tu choisis, en lecture seule, pour un temps limité."
        }
    }

    /// Personal or shared: presence then grant. Public: the picker comes first, presence follows it.
    private func approve(_ flow: PairingApproverFlow, mode: FfiDeviceMode) async {
        if mode == .public {
            picking = true
            return
        }
        // Set before the first await: a second tap or Return does nothing (L1).
        guard !approving else { return }
        approving = true
        defer { approving = false }
        if flow.approvalError != nil, !password.isEmpty {
            let typed = SecretBytes(utf8: password)
            password = ""
            defer { typed.wipe() }
            await flow.approve(mode: mode, password: typed)
        } else {
            await flow.approve(mode: mode)
        }
    }

    // MARK: - Pieces

    private func status(_ title: LocalizedStringKey, detail: LocalizedStringKey?) -> some View {
        VStack(spacing: 14) {
            ProgressView().controlSize(.large)
            Text(title).font(.headline)
            if let detail {
                Text(detail).font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func outcome(symbol: String, tint: Color, title: LocalizedStringKey, message: String) -> some View {
        VStack(spacing: 14) {
            Image(systemName: symbol).font(.system(size: 52)).foregroundStyle(tint).accessibilityHidden(true)
            Text(title).font(.title2.bold())
            Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .accessibilityIdentifier("approve.outcome")
            Button {
                close()
            } label: {
                Text("OK").font(.headline).frame(minWidth: 140).frame(height: 40)
            }
            .buttonStyle(.glassProminent)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// The invite code on the Mac: the new device scans it from "J'ai déjà OnePass sur un autre
/// appareil". It carries a one-time secret: kept out of screen recordings and the logs.
private struct InviteStep: View {
    let text: String
    let expiresAt: Date

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Scanne ce code avec ton nouvel appareil")
                        .font(.title3.bold())
                    Text("Sur l'iPhone ou l'iPad : « J'ai déjà OnePass sur un autre appareil », puis « Scanner le code de mon autre appareil ».")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                PairingQRView(text: text, expiresAt: expiresAt, renewal: .beforeExpiry)
                    .accessibilityIdentifier("approve.invite")
                Label("Ne montre ce code qu'à ton propre appareil, devant toi.", systemImage: "exclamationmark.shield.fill")
                    .font(.footnote)
                    .foregroundStyle(.orange)
                Label("Les deux appareils doivent être proches, sur le même Wi-Fi.", systemImage: "wifi")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .padding(20)
        }
    }
}

#if os(iOS)
/// The warning, then the camera; only an `OPPAIR1:` text goes through. Debug builds take the text of
/// `-OnePassPairingQRText` instead of the camera (ruling A3: the Simulator has none).
private struct ScanStep: View {
    let onText: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label {
                Text("Ne scanne jamais un QR code qu'on t'a envoyé.")
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
            }
            .accessibilityIdentifier("approve.warning")
            Text("Scanne seulement le QR code affiché par ton nouvel appareil, devant toi : « J'ai déjà OnePass sur un autre appareil ».")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            scanner
                .frame(maxWidth: .infinity)
                .frame(height: 340)
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        }
        .padding(20)
        .frame(maxHeight: .infinity, alignment: .top)
    }

    @ViewBuilder private var scanner: some View {
        #if DEBUG
        if let injected = UserDefaults.standard.string(forKey: "OnePassPairingQRText"), !injected.isEmpty {
            // Debug only, never in Release (ruling A3).
            Label("QR code injecté (Debug)", systemImage: "ladybug")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(.fill.tertiary)
                .task { onText(injected) }
                .accessibilityIdentifier("approve.injected")
        } else {
            camera
        }
        #else
        camera
        #endif
    }

    @ViewBuilder private var camera: some View {
        if SecretKeyScanner.isSupported {
            SecretKeyScanner(onKey: onText, accept: PairingQR.accept)
        } else {
            ContentUnavailableView(
                "Caméra indisponible", systemImage: "camera",
                description: Text("Cet appareil ne peut pas lire de QR code."))
                .background(.fill.tertiary)
        }
    }
}

/// The pairing QR text: `OPPAIR1:` and nothing else (no URL, the system camera never opens it).
enum PairingQR {
    static let prefix = "OPPAIR1:"

    static func accept(_ payload: String) -> String? {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.hasPrefix(prefix) ? trimmed : nil
    }
}
#endif
