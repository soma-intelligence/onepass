#if os(macOS)
import SwiftUI
import VaultKit

/// A browser extension asks to pair (spec 6.4): the user compares the code with the one the
/// extension shows, then approves with Touch ID. The name and browser are what the extension
/// says about itself.
struct BrowserPairingSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openSettings) private var openSettings
    let bridge: BrowserBridge
    let request: BrowserBridge.Request
    @State private var working = false

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "puzzlepiece.extension")
                .font(.system(size: 34))
                .foregroundStyle(.tint)
            Text("Associer un navigateur")
                .font(.title2.bold())
            Text("« \(request.extensionName) » dans \(request.browser) demande l'accès à ton coffre.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Text(request.code)
                .font(.system(size: 34, weight: .semibold, design: .monospaced))
                .accessibilityLabel(Text("Code \(request.code)"))
                .accessibilityIdentifier("bridge.pairing.code")
            Text("Approuve seulement si l'extension affiche exactement ce code.")
                .font(.callout)
                .multilineTextAlignment(.center)
            HStack {
                Button("Refuser", role: .cancel) { bridge.refuse(request.id) }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("bridge.pairing.refuse")
                Button("Approuver") {
                    working = true
                    Task {
                        await bridge.approve(request.id)
                        working = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(working || !bridge.canApprove)
                .accessibilityIdentifier("bridge.pairing.approve")
            }
            if bridge.canApprove {
                Text("Touch ID est demandé. Sans Touch ID activé dans OnePass, l'association est refusée.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            } else {
                // Said before the tap: approving without Touch ID can only be refused.
                VStack(spacing: 8) {
                    Label("Touch ID n'est pas activé dans OnePass", systemImage: "touchid")
                        .font(.callout.weight(.semibold))
                    Text("Pour approuver un navigateur, OnePass demande Touch ID. Active-le dans Réglages > Sécurité, puis approuve : l'extension attend.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Button("Activer Touch ID…") {
                        model.settingsPageRequest = .security
                        openSettings()
                    }
                    .accessibilityIdentifier("bridge.pairing.enableTouchID")
                }
                .padding(12)
                .frame(maxWidth: .infinity)
                .background(.orange.opacity(0.12), in: .rect(cornerRadius: 10))
                .accessibilityIdentifier("bridge.pairing.touchIDOff")
            }
        }
        .padding(28)
        .frame(width: 380)
        .interactiveDismissDisabled()
    }
}

/// Réglages > Remplissage automatique > Navigateurs: the browsers paired with this Mac, and
/// "Oublier" for each (its next connection must pair again).
struct BrowserBridgeSection: View {
    let bridge: BrowserBridge

    var body: some View {
        Section {
            if !bridge.isRunning {
                Text("Indisponible dans cette version de OnePass.")
                    .foregroundStyle(.secondary)
            } else if bridge.paired.isEmpty {
                Text("Aucun navigateur associé.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(bridge.paired) { p in
                    LabeledContent {
                        Button("Oublier", role: .destructive) { bridge.forget(p.id) }
                            .accessibilityIdentifier("bridge.forget")
                    } label: {
                        Text(p.browser)
                        Text(p.automatic
                            ? "Associé automatiquement, utilisé \(p.lastUsed.formatted(.relative(presentation: .named)))"
                            : "\(p.extensionName), utilisé \(p.lastUsed.formatted(.relative(presentation: .named)))")
                    }
                }
            }
        } header: {
            Text("Navigateurs")
        } footer: {
            Text("Les extensions OnePass de Safari, Chrome, Edge, Brave et Firefox se connectent seules quand le Mac vérifie la signature du navigateur, et remplissent depuis le coffre ouvert dans cette app. Verrouiller OnePass les verrouille aussi.")
        }
    }
}
#endif
