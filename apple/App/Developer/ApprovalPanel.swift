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
    /// The outcome line stays this long once the question is settled ("Approuvé sur …").
    private static let outcomeDelay: Duration = .milliseconds(1600)
    private var hiding: Task<Void, Never>?

    init(hosts: DeveloperHosts) {
        self.hosts = hosts
        observe()
    }

    private func observe() {
        withObservationTracking {
            _ = hosts.prompts
            _ = hosts.lastOutcome
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
            // The question on screen was settled: where the answer came from, briefly.
            if let id = shownID, let outcome = hosts.lastOutcome, outcome.promptID == id, let panel {
                shownID = nil
                show(ApprovalOutcomeView(outcome: outcome), in: panel)
                hiding?.cancel()
                hiding = Task { @MainActor [weak self] in
                    try? await Task.sleep(for: Self.outcomeDelay)
                    guard !Task.isCancelled, let self, self.shownID == nil else { return }
                    self.panel?.orderOut(nil)
                    self.hiding = nil
                }
                return
            }
            // An outcome is on screen: it hides by itself.
            guard hiding == nil else { return }
            panel?.orderOut(nil)
            shownID = nil
            return
        }
        guard prompt.id != shownID else { return }
        hiding?.cancel()
        hiding = nil
        shownID = prompt.id
        let id = prompt.id
        let view = ApprovalPanelContent(hosts: hosts, prompt: prompt) { [weak self] decision in
            self?.hosts.answer(id, with: decision)
        }
        let panel = self.panel ?? makePanel()
        show(view, in: panel)
        panel.center()
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        self.panel = panel
    }

    private func show(_ view: some View, in panel: NSPanel) {
        panel.contentView = NSHostingView(rootView: view)
        panel.setContentSize(panel.contentView?.fittingSize ?? NSSize(width: 460, height: 320))
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

/// The question on screen, with the iPhone line kept current (the race moves on while it shows).
private struct ApprovalPanelContent: View {
    let hosts: DeveloperHosts
    let prompt: DeveloperPrompt
    let answer: (FfiDecision) -> Void

    var body: some View {
        ApprovalView(
            prompt: prompt, phoneNotice: hosts.prompts.first { $0.id == prompt.id }?.phoneNotice ?? prompt.phoneNotice,
            answer: answer)
    }
}

/// Where the answer was given, shown a moment after the question closes.
struct ApprovalOutcomeView: View {
    let outcome: ApprovalOutcome

    var body: some View {
        Label {
            Text(outcome.text).font(.headline)
        } icon: {
            Image(systemName: outcome.approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(outcome.approved ? Color.green : Color.orange)
                .font(.title2)
        }
        .padding(24)
        .frame(width: 460, alignment: .leading)
        .accessibilityIdentifier("approval.outcome")
    }
}

/// One question: approve a request, or pair a client.
struct ApprovalView: View {
    let prompt: DeveloperPrompt
    /// "Envoyé à <iPhone>" or "iPhone indisponible : approuve ici", nil when the iPhone is not asked.
    var phoneNotice: String?
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
        // A web fill: the site the values go to, in large type (spec 4).
        let isFill = r.action == "fill_login" || r.action == "fill_card"
        if isFill, let site = r.details.first(where: { $0.label == "site" })?.value {
            Text(site)
                .font(.largeTitle.weight(.bold))
                .lineLimit(1)
                .minimumScaleFactor(0.5)
                .textSelection(.enabled)
                .accessibilityIdentifier("approval.site")
        }
        if !r.targets.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(r.targets.enumerated()), id: \.offset) { _, t in
                    Label([t.vault, t.item, t.field].compactMap { $0 }.joined(separator: " › "), systemImage: "key")
                        .font(.callout)
                }
            }
        }
        let details = isFill ? r.details.filter { $0.label != "site" } : r.details
        if !details.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(details.enumerated()), id: \.offset) { _, d in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(Self.detailLabel(d.label)).font(.caption).foregroundStyle(.secondary)
                        Text(Self.detailValue(d.value, label: d.label)).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                            .lineLimit(4)
                    }
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 8))
        }
        if r.action == "fill_card" {
            Text("developer.cardAskedEveryTime")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        if let phoneNotice {
            Label(phoneNotice, systemImage: "iphone")
                .font(.callout)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("approval.phone")
        }
        HStack {
            Button("app.refuse", role: .cancel) { answer(.deny) }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("approval.deny")
            Spacer()
            if r.rememberAllowed {
                Menu("developer.allowFor") {
                    Button("developer.n5Minutes") { answer(.allowForMinutes(minutes: 5)) }
                    Button("developer.n15Minutes") { answer(.allowForMinutes(minutes: 15)) }
                    Button("developer.n1Hour") { answer(.allowForMinutes(minutes: 60)) }
                }
                .fixedSize()
                .accessibilityIdentifier("approval.allowFor")
            }
            Button("developer.allowOnce") { answer(.allowOnce) }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("approval.allowOnce")
        }
    }

    @ViewBuilder private func pairing(_ c: FfiMcpClient) -> some View {
        HStack(spacing: 12) {
            PageTile(symbol: "link", color: .purple, size: 36)
            Text("developer.pairAiAgent").font(.headline)
        }
        Text("developer.wantsToUseOnepass \(c.label)").font(.title3.weight(.semibold))
        VStack(alignment: .leading, spacing: 4) {
            Text("developer.verifiedIdentity").font(.caption).foregroundStyle(.secondary)
            Text(c.id).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
        }
        Text("developer.oncePairedItSees")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        HStack {
            Button("app.refuse", role: .cancel) { answer(.deny) }
                .keyboardShortcut(.cancelAction)
            Spacer()
            Button("developer.pair") { answer(.allowOnce) }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("approval.pair")
        }
    }

    /// French names of the detail lines the servers send (fixed English keys).
    static func detailLabel(_ label: String) -> String { AgentRequestText.detailLabel(label) }

    static func detailValue(_ value: String, label: String = "") -> String {
        AgentRequestText.detailValue(value, label: label)
    }

    static func actionTitle(_ action: String) -> String { AgentRequestText.actionTitle(action) }
}
#endif
