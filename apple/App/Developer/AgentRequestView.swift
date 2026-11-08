import SwiftUI
import VaultKit

/// French names of what an agent asks (fixed English keys from the servers), shared by the Mac
/// approval panel and the iPhone request screen.
enum AgentRequestText {
    static func detailLabel(_ label: String) -> String {
        switch label {
        case "key": String(localized: "app.key")
        case "fingerprint": String(localized: "app.fingerprint")
        case "process": String(localized: "developer.program")
        case "destination": String(localized: "Destination")
        case "forwarded": String(localized: "developer.forwardedConnection")
        case "namespace": String(localized: "developer.namespace")
        case "warning": String(localized: "developer.warning")
        case "command": String(localized: "developer.command")
        case "cwd": String(localized: "app.folder")
        case "template": String(localized: "developer.template")
        case "output": String(localized: "developer.fileWritten")
        case "overwrite": String(localized: "app.replace")
        case "reference": String(localized: "developer.secret")
        case "title": String(localized: "app.title")
        case "username": String(localized: "developer.username")
        case "url": String(localized: "developer.website")
        case "site": String(localized: "developer.siteLabel")
        case "tab": String(localized: "developer.tabLabel")
        case "card": String(localized: "developer.cardLabel")
        case "browser": String(localized: "developer.browserLabel")
        default: label
        }
    }

    static func detailValue(_ value: String) -> String {
        switch value {
        case "yes": String(localized: "oui")
        case "no": String(localized: "developer.no")
        case "cdp": String(localized: "developer.cdpBrowser")
        default: value
        }
    }

    static func actionTitle(_ action: String) -> String {
        switch action {
        case "ssh_sign": String(localized: "developer.signWithSshKey")
        case "run_with_secrets": String(localized: "developer.runCommandWithSecrets")
        case "fill_template": String(localized: "developer.fillFileWithSecrets")
        case "create_login": String(localized: "developer.createLogin")
        case "totp_code": String(localized: "developer.readOneTimeCode")
        case "reveal_secret": String(localized: "developer.revealSecret")
        case "remote_unlock": String(localized: "developer.unlockForAgents")
        case "remote_unlock_pair": String(localized: "developer.turnOnRemoteUnlock")
        case "fill_login": String(localized: "developer.fillLoginInPage")
        case "fill_card": String(localized: "developer.fillCardInPage")
        default: action
        }
    }
}

#if os(iOS)
/// The requests waiting on this iPhone (opened from the notification or as they arrive). Nothing is
/// answered from the notification itself: every answer is made here, after Face ID.
struct AgentRequestsSheet: View {
    let agents: PhoneAgents
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if agents.clockLooksWrong {
                        Label(RemoteResponderError.clockSkew.message, systemImage: "clock.badge.exclamationmark")
                            .font(.callout)
                            .foregroundStyle(.orange)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .accessibilityIdentifier("agents.clockHint")
                    }
                    if agents.requests.isEmpty {
                        ContentUnavailableView(
                            "Aucune demande en attente", systemImage: "checkmark.circle",
                            description: Text("developer.requestsFromMacsAgents"))
                    }
                    ForEach(agents.requests) { request in
                        AgentRequestView(agents: agents, request: request)
                    }
                }
                .padding()
            }
            .navigationTitle("developer.agentRequests")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("OK") { dismiss() }
                }
            }
        }
        // An expired request leaves the screen on its own.
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                await agents.expireStale()
            }
        }
    }
}

/// One request (agent-ready spec 7): the verified identity of the client, the action, the targets,
/// the confirmation code, then "Refuser", "Autoriser une fois", "Autoriser 5 min" (when allowed).
/// An unlock shows who asks and the agents window instead of items; a pairing shows the two letters
/// the Mac shows.
struct AgentRequestView: View {
    let agents: PhoneAgents
    let request: OpenedRequest
    @State private var busy = false
    @State private var error: String?

    private var body_: FfiRequestBody { request.body }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            if request.isPairing {
                pairing
            } else {
                Text(request.isUnlock
                     ? String(localized: "developer.lockedUnlockItFor \(request.macName)")
                     : AgentRequestText.actionTitle(body_.action))
                    .font(.title3.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                if request.isUnlock, let minutes = body_.windowMinutes {
                    Label("developer.agentsWindow \(Self.duration(minutes))", systemImage: "timer")
                        .font(.callout)
                        .accessibilityIdentifier("agentRequest.window")
                }
                if !request.isUnlock && !body_.targets.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(body_.targets.enumerated()), id: \.offset) { _, target in
                            Label(target, systemImage: "key").font(.callout)
                        }
                    }
                }
                details
                if !body_.confirmCode.isEmpty {
                    code(body_.confirmCode, caption: "developer.codeShownToAgent")
                }
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
            buttons
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: .rect(cornerRadius: 16))
        .disabled(busy)
        .accessibilityIdentifier("agentRequest")
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Group {
                if request.isPairing {
                    Text("developer.requestFrom \(request.macName)")
                } else {
                    Text("developer.requestFromAgentOn \(request.macName)")
                }
            }
            .font(.headline)
            if !request.isPairing {
                HStack(spacing: 4) {
                    Text(body_.client)
                    Image(systemName: body_.clientVerified ? "checkmark.seal.fill" : "questionmark.circle")
                        .foregroundStyle(body_.clientVerified ? .green : .orange)
                        .accessibilityLabel(body_.clientVerified
                            ? Text("Identité vérifiée par sa signature") : Text("Identité non vérifiée"))
                }
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var details: some View {
        if !body_.details.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(body_.details.enumerated()), id: \.offset) { _, d in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(AgentRequestText.detailLabel(d.label)).font(.caption).foregroundStyle(.secondary)
                        Text(AgentRequestText.detailValue(d.value))
                            .font(.system(.callout, design: .monospaced))
                            .lineLimit(4)
                    }
                }
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 8))
        }
    }

    @ViewBuilder private var pairing: some View {
        Text("developer.turnOnRemoteUnlock \(request.macName)")
            .font(.title3.weight(.semibold))
            .fixedSize(horizontal: false, vertical: true)
        Text("developer.iphoneWillKeepKey")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        code(body_.confirmCode, caption: "developer.checkMacShowsSame")
    }

    private func code(_ value: String, caption: LocalizedStringKey) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(caption).font(.caption).foregroundStyle(.secondary)
            Text(value.uppercased())
                .font(.system(size: 34, weight: .bold, design: .monospaced))
                .accessibilityIdentifier("agentRequest.code")
        }
    }

    @ViewBuilder private var buttons: some View {
        if request.isPairing {
            HStack {
                Button("app.refuse", role: .cancel) { Task { await agents.dismiss(request) } }
                    .accessibilityIdentifier("agentRequest.deny")
                Spacer()
                Button("app.turnOn") { run { try await agents.acceptEnrollment(request) } }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("agentRequest.accept")
            }
        } else {
            VStack(spacing: 10) {
                Button {
                    run { try await agents.answer(request, decision: .once) }
                } label: {
                    Text("developer.allowOnce").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("agentRequest.allowOnce")
                if request.mayGrantMinutes {
                    Button {
                        run { try await agents.answer(request, decision: .grant5m) }
                    } label: {
                        Text("developer.allowFor5Min").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("agentRequest.allowFor")
                }
                Button(role: .destructive) {
                    run { try await agents.answer(request, decision: .denied) }
                } label: {
                    Text("app.refuse").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("agentRequest.deny")
            }
            .controlSize(.large)
        }
    }

    private func run(_ work: @escaping @MainActor () async throws -> Void) {
        busy = true
        error = nil
        Task {
            defer { busy = false }
            do {
                try await work()
            } catch let failure as RemoteResponderError {
                error = failure.message
            } catch {
                self.error = RemoteResponderError.unavailable.message
            }
        }
    }

    static func duration(_ minutes: UInt32) -> String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = minutes >= 60 ? [.hour, .minute] : [.minute]
        formatter.unitsStyle = .short
        return formatter.string(from: TimeInterval(minutes) * 60) ?? "\(minutes) min"
    }
}
#endif
