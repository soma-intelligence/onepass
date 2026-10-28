#if os(macOS)
import AppKit
import DesignKit
import SwiftUI
import VaultKit

/// Shows the questions of the SSH agent and the MCP server in a floating panel, one at a time, above
/// every window (the main window may be closed: the agent still asks). The panel says exactly what is
/// asked: the client, the action, the vault, item and field, never a value.
@MainActor
final class ApprovalPanelController {
    private let hosts: DeveloperHosts
    private var panel: NSPanel?
    private var shownID: UUID?

    init(hosts: DeveloperHosts) {
        self.hosts = hosts
        observe()
    }

    private func observe() {
        withObservationTracking {
            _ = hosts.prompts
        } onChange: { [weak self] in
            Task { @MainActor in
                self?.refresh()
                self?.observe()
            }
        }
        refresh()
    }

    private func refresh() {
        guard let prompt = hosts.prompts.first else {
            panel?.orderOut(nil)
            shownID = nil
            return
        }
        guard prompt.id != shownID else { return }
        shownID = prompt.id
        let view = ApprovalView(prompt: prompt) { [weak self] decision in
            self?.hosts.answer(prompt.id, with: decision)
        }
        let panel = self.panel ?? makePanel()
        panel.contentView = NSHostingView(rootView: view)
        panel.setContentSize(panel.contentView?.fittingSize ?? NSSize(width: 460, height: 320))
        panel.center()
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        self.panel = panel
    }

    private func makePanel() -> NSPanel {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 460, height: 320),
            styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.level = .floating
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.isMovableByWindowBackground = true
        return panel
    }
}

/// One question: approve a request, or pair a client.
struct ApprovalView: View {
    let prompt: DeveloperPrompt
    let answer: (FfiDecision) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            switch prompt.kind {
            case .approval(let request): approval(request)
            case .pairing(let client): pairing(client)
            }
        }
        .padding(24)
        .frame(width: 460, alignment: .leading)
        .accessibilityIdentifier("approval.panel")
    }

    @ViewBuilder private func approval(_ r: FfiApprovalRequest) -> some View {
        HStack(spacing: 12) {
            PageTile(
                symbol: r.surface == "ssh" ? "key.fill" : "point.3.connected.trianglepath.dotted",
                color: r.surface == "ssh" ? Color(red: 0x47 / 255, green: 0x55 / 255, blue: 0x69 / 255) : .purple,
                size: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(r.surface == "ssh" ? "Demande de l'agent SSH" : "Demande d'un agent IA").font(.headline)
                HStack(spacing: 4) {
                    Text(r.client).font(.subheadline)
                    Image(systemName: r.clientVerified ? "checkmark.seal.fill" : "questionmark.circle")
                        .foregroundStyle(r.clientVerified ? .green : .orange)
                        .help(Text(r.clientVerified ? "Identité vérifiée par sa signature" : "Identité non vérifiée"))
                }
                .foregroundStyle(.secondary)
            }
        }
        Text(Self.actionTitle(r.action)).font(.title3.weight(.semibold))
        if !r.targets.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(r.targets.enumerated()), id: \.offset) { _, t in
                    Label([t.vault, t.item, t.field].compactMap { $0 }.joined(separator: " › "), systemImage: "key")
                        .font(.callout)
                }
            }
        }
        if !r.details.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(r.details.enumerated()), id: \.offset) { _, d in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(Self.detailLabel(d.label)).font(.caption).foregroundStyle(.secondary)
                        Text(Self.detailValue(d.value)).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                            .lineLimit(4)
                    }
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 8))
        }
        HStack {
            Button("Refuser", role: .cancel) { answer(.deny) }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("approval.deny")
            Spacer()
            if r.rememberAllowed {
                Menu("Autoriser pendant…") {
                    Button("5 minutes") { answer(.allowForMinutes(minutes: 5)) }
                    Button("15 minutes") { answer(.allowForMinutes(minutes: 15)) }
                    Button("1 heure") { answer(.allowForMinutes(minutes: 60)) }
                }
                .fixedSize()
                .accessibilityIdentifier("approval.allowFor")
            }
            Button("Autoriser une fois") { answer(.allowOnce) }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("approval.allowOnce")
        }
    }

    @ViewBuilder private func pairing(_ c: FfiMcpClient) -> some View {
        HStack(spacing: 12) {
            PageTile(symbol: "link", color: .purple, size: 36)
            Text("Appairer un agent IA ?").font(.headline)
        }
        Text("\(c.label) veut utiliser le serveur MCP de OnePass.").font(.title3.weight(.semibold))
        VStack(alignment: .leading, spacing: 4) {
            Text("Identité vérifiée").font(.caption).foregroundStyle(.secondary)
            Text(c.id).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
        }
        Text("Appairé, il verra les coffres exposés (métadonnées) et pourra demander à utiliser leurs secrets, chaque fois avec ton accord. Touch ID confirme l'appairage.")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        HStack {
            Button("Refuser", role: .cancel) { answer(.deny) }
                .keyboardShortcut(.cancelAction)
            Spacer()
            Button("Appairer") { answer(.allowOnce) }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("approval.pair")
        }
    }

    /// French names of the detail lines the servers send (fixed English keys).
    static func detailLabel(_ label: String) -> String {
        switch label {
        case "key": String(localized: "Clé")
        case "fingerprint": String(localized: "Empreinte")
        case "process": String(localized: "Programme")
        case "destination": String(localized: "Destination")
        case "forwarded": String(localized: "Connexion transférée")
        case "namespace": String(localized: "Espace de noms")
        case "warning": String(localized: "Attention")
        case "command": String(localized: "Commande")
        case "cwd": String(localized: "Dossier")
        case "template": String(localized: "Modèle")
        case "output": String(localized: "Fichier écrit")
        case "overwrite": String(localized: "Remplacer")
        case "reference": String(localized: "Secret")
        case "title": String(localized: "Titre")
        case "username": String(localized: "Identifiant")
        case "url": String(localized: "Site")
        default: label
        }
    }

    static func detailValue(_ value: String) -> String {
        switch value {
        case "yes": String(localized: "oui")
        case "no": String(localized: "non")
        default: value
        }
    }

    static func actionTitle(_ action: String) -> String {
        switch action {
        case "ssh_sign": String(localized: "Signer avec une clé SSH")
        case "run_with_secrets": String(localized: "Lancer une commande avec des secrets")
        case "fill_template": String(localized: "Remplir un fichier avec des secrets")
        case "create_login": String(localized: "Créer un identifiant")
        case "totp_code": String(localized: "Lire un code à usage unique")
        case "reveal_secret": String(localized: "Révéler un secret")
        default: action
        }
    }
}
#endif
