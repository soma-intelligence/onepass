import SwiftUI
import VaultKit

/// French names of what an agent asks (fixed English keys from the servers), shared by the Mac
/// approval panel and the iPhone request screen.
enum AgentRequestText {
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
        case "remote_unlock": String(localized: "Déverrouiller pour les agents")
        case "remote_unlock_pair": String(localized: "Activer le déverrouillage à distance")
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
                            description: Text("Les demandes des agents de ton Mac apparaissent ici pendant une minute."))
                    }
                    ForEach(agents.requests) { request in
                        AgentRequestView(agents: agents, request: request)
                    }
                }
                .padding()
            }
            .navigationTitle("Demandes des agents")
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
                     ? String(localized: "\(request.macName) est verrouillé. Déverrouiller pour les agents et autoriser cette demande ?")
                     : AgentRequestText.actionTitle(body_.action))
                    .font(.title3.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                if request.isUnlock, let minutes = body_.windowMinutes {
                    Label("Fenêtre agents : \(Self.duration(minutes))", systemImage: "timer")
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
                    code(body_.confirmCode, caption: "Code montré à l'agent")
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
                    Text("Demande de \(request.macName)")
                } else {
                    Text("Demande d'un agent sur \(request.macName)")
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
        Text("Activer le déverrouillage à distance de \(request.macName) ?")
            .font(.title3.weight(.semibold))
            .fixedSize(horizontal: false, vertical: true)
        Text("Ton iPhone gardera une clé qui permet à ce Mac de s'ouvrir pour les agents, chaque fois avec ton accord et Face ID.")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        code(body_.confirmCode, caption: "Vérifie que le Mac montre le même code")
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
                Button("Refuser", role: .cancel) { Task { await agents.dismiss(request) } }
                    .accessibilityIdentifier("agentRequest.deny")
                Spacer()
                Button("Activer") { run { try await agents.acceptEnrollment(request) } }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("agentRequest.accept")
            }
        } else {
            VStack(spacing: 10) {
                Button {
                    run { try await agents.answer(request, decision: .once) }
                } label: {
                    Text("Autoriser une fois").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("agentRequest.allowOnce")
                if request.mayGrantMinutes {
                    Button {
                        run { try await agents.answer(request, decision: .grant5m) }
                    } label: {
                        Text("Autoriser 5 min").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("agentRequest.allowFor")
                }
                Button(role: .destructive) {
                    run { try await agents.answer(request, decision: .denied) }
                } label: {
                    Text("Refuser").frame(maxWidth: .infinity)
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
