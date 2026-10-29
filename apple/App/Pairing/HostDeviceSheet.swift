#if os(macOS)
import DesignKit
import SwiftUI
import VaultKit

/// "Configurer un appareil…" (Mac): this Mac shows the pairing code, the new iPhone or iPad scans it or
/// types it. A big QR code and, under it, the 8-character code, both renewed every 30 s. Then the
/// 6-digit code both screens show, "Les codes sont identiques", Touch ID (else the master password)
/// and the grant. A public request is not served here: lending items starts from an iPhone or iPad.
struct HostDeviceSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var flow: PairingApproverFlow?
    @State private var password = ""
    @State private var approving = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            Group {
                if let flow {
                    content(flow)
                } else {
                    ProgressView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(width: 480, height: 640)
        .onAppear {
            guard flow == nil else { return }
            let created = PairingApproverFlow(vault: model.session, listener: LocalNetworkPairingListener())
            flow = created
            created.startHosting()
        }
        .onDisappear {
            flow?.cancel()
            password = ""
        }
    }

    private var header: some View {
        HStack {
            Text("Configurer un appareil").font(.headline)
            Spacer()
            // Not while the grant is sent: it may already be out.
            Button(finished ? "OK" : "Annuler") { close() }
                .keyboardShortcut(.cancelAction)
                .disabled(granting)
                .accessibilityIdentifier("host.close")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
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
        case .idle, .connecting:
            ProgressView().controlSize(.large)
        case .hosting(let code):
            hosting(code)
        case .comparing(let sas, let peer, let requestedMode):
            if requestedMode == .public {
                outcome(
                    symbol: "iphone", tint: .secondary, title: "Utilise ton iPhone ou ton iPad",
                    message: String(
                        localized: "Une session invitée se prête depuis un iPhone ou un iPad. Ce Mac ne prête pas d'éléments."
                    ), identifier: "host.public")
                .onAppear { flow.cancel() }
            } else {
                compare(flow, sas: sas, peer: peer, mode: requestedMode)
            }
        case .waitingForPeer:
            status("En attente du nouvel appareil...", detail: "Confirme que les codes sont identiques sur le nouvel appareil.")
        case .granting:
            status("Envoi...", detail: nil)
        case .publicRunning:
            // Never reached: a public request is refused above.
            EmptyView()
        case .done:
            outcome(
                symbol: "checkmark.circle.fill", tint: .green, title: "Appareil ajouté",
                message: String(localized: "Il te demande maintenant ton mot de passe maître."), identifier: "host.outcome")
        case .failed(let failure):
            outcome(
                symbol: "exclamationmark.triangle.fill", tint: .red, title: "L'appairage n'a pas abouti",
                message: failure.message, identifier: "host.outcome")
        }
    }

    // MARK: - The code on screen

    private func hosting(_ code: FfiHostCode) -> some View {
        VStack(spacing: 18) {
            VStack(spacing: 6) {
                Text("Sur le nouvel appareil").font(.title3.bold())
                Text("Choisis « J'ai déjà OnePass sur un autre appareil », puis scanne ce QR code avec la caméra de OnePass, ou saisis le code.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            PairingQRView(text: code.qrText, expiresAt: Date(timeIntervalSince1970: TimeInterval(code.expiresAt)))
            VStack(spacing: 6) {
                Text("Ou saisis ce code")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Text(verbatim: code.shortText)
                    .font(.system(size: 38, weight: .semibold, design: .monospaced))
                    .tracking(3)
                    .textSelection(.disabled)
                    .privacySensitive()
                    .accessibilityLabel(Text("Code d'appairage"))
                    .accessibilityValue(Text(verbatim: code.shortText.filter { $0 != "-" }.map(String.init).joined(separator: " ")))
                    .accessibilityIdentifier("host.code")
            }
            Label("Les deux appareils doivent être proches, sur le même Wi-Fi.", systemImage: "wifi")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(24)
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
                .accessibilityIdentifier("host.peer")
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
                Text("Le même code doit s'afficher sur le nouvel appareil. S'il est différent, quelqu'un d'autre essaie de se connecter.")
            }
            if flow.approvalError != nil {
                Section {
                    SecureField("Mot de passe maître", text: $password)
                        .privacySensitive()
                        .onSubmit {
                            guard !approving, !password.isEmpty else { return }
                            Task { await approve(flow, mode: mode) }
                        }
                        .accessibilityIdentifier("host.password")
                } footer: {
                    if let error = flow.approvalError, error != .passwordRequired {
                        Text(error.localizedMessage).foregroundStyle(.red)
                    } else {
                        Text("Confirme avec ton mot de passe maître.")
                    }
                }
            }
            Section {
                Button {
                    Task { await approve(flow, mode: mode) }
                } label: {
                    HStack {
                        Text("Les codes sont identiques").font(.headline)
                        Spacer()
                        if approving { ProgressView().controlSize(.small) }
                    }
                }
                .disabled(approving || (flow.approvalError != nil && password.isEmpty))
                .accessibilityIdentifier("host.codesMatch")
                Button("Ils sont différents", role: .destructive) { flow.cancel() }
                    .disabled(approving)
                    .accessibilityIdentifier("host.codesDiffer")
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

    /// Presence (Touch ID, else the master password) then the grant.
    private func approve(_ flow: PairingApproverFlow, mode: FfiDeviceMode) async {
        // Set before the first await: a second click or Return does nothing.
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
    }

    private func outcome(
        symbol: String, tint: Color, title: LocalizedStringKey, message: String, identifier: String
    ) -> some View {
        VStack(spacing: 14) {
            Image(systemName: symbol).font(.system(size: 52)).foregroundStyle(tint).accessibilityHidden(true)
            Text(title).font(.title2.bold())
            Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center)
                .accessibilityIdentifier(identifier)
            Button {
                close()
            } label: {
                Text("OK").font(.headline).frame(minWidth: 140).frame(height: 28)
            }
            .buttonStyle(.glassProminent)
            .controlSize(.large)
        }
        .padding(32)
    }
}
#endif
