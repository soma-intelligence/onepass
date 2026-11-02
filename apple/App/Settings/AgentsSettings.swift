#if os(iOS)
import SwiftUI
import UserNotifications
import VaultKit

/// Réglages > Agents (agent-ready spec 7): approve the requests of the Mac's agents on this iPhone,
/// each Mac of the account with its remote unlock, "Verrouiller maintenant", "Oublier le
/// déverrouillage à distance", and the last 20 answers. iOS only.
struct AgentsSettings: View {
    @Environment(AppModel.self) private var model
    @State private var busy = false
    @State private var error: String?
    @State private var forgetting: PhoneAgents.Mac?

    var body: some View {
        Form {
            if let agents = model.phoneAgents, agents.isAvailable {
                content(agents)
            } else {
                Section {
                    Label("Nécessite la version iCloud de OnePass", systemImage: "icloud.slash")
                        .foregroundStyle(.secondary)
                } footer: {
                    Text("Les demandes des agents passent par iCloud, chiffrées de bout en bout entre ton Mac et cet iPhone.")
                }
            }
        }
        .settingsPage("Agents")
        .disabled(busy)
        .task { await model.phoneAgents?.refresh() }
    }

    @ViewBuilder private func content(_ agents: PhoneAgents) -> some View {
        Section {
            if agents.isEnabled {
                Label("Cet iPhone approuve les demandes", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .accessibilityIdentifier("agents.enabled")
                Button("Voir les demandes en attente (\(agents.requests.count))") {
                    agents.showRequests = true
                }
                .accessibilityIdentifier("agents.pending")
            } else {
                Button("Approuver les demandes sur cet iPhone") {
                    run {
                        try await agents.enable()
                        // The alert of a request (time sensitive, no action in it).
                        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
                    }
                }
                .accessibilityIdentifier("agents.enable")
            }
            if agents.faceIDNeedsReset {
                Label("Face ID a changé sur cet iPhone. Réactive-le pour répondre aux demandes.", systemImage: "faceid")
                    .foregroundStyle(.orange)
                Button("Réactiver Face ID") {
                    run { try await agents.reArmFaceID() }
                }
                .accessibilityIdentifier("agents.rearmFaceID")
            }
            if agents.clockLooksWrong {
                Label(RemoteResponderError.clockSkew.message, systemImage: "clock.badge.exclamationmark")
                    .foregroundStyle(.orange)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        } footer: {
            Text("settings.agents.footer")
        }

        ForEach(agents.macs) { mac in
            Section(mac.name) {
                LabeledContent("Déverrouillage à distance") {
                    mac.unlockEnrolled ? Text("Activé") : Text("Désactivé")
                }
                if let end = mac.windowEndsAt {
                    LabeledContent("Fenêtre agents demandée") {
                        Text("jusqu'à \(end.formatted(date: .omitted, time: .shortened))")
                    }
                }
                if mac.unlockEnrolled {
                    Button("Verrouiller maintenant") {
                        run { try await agents.lockNow(mac: mac.id) }
                    }
                    .accessibilityIdentifier("agents.lockNow")
                    Button("Oublier le déverrouillage à distance", role: .destructive) {
                        forgetting = mac
                    }
                    .accessibilityIdentifier("agents.forget")
                }
            }
        }
        .confirmationDialog(
            "Oublier le déverrouillage à distance ?",
            isPresented: Binding(get: { forgetting != nil }, set: { if !$0 { forgetting = nil } }),
            titleVisibility: .visible, presenting: forgetting
        ) { mac in
            Button("Oublier", role: .destructive) {
                run { try await agents.forget(mac: mac.id) }
            }
            Button("Annuler", role: .cancel) {}
        } message: { mac in
            Text("Cet iPhone efface sa clé et \(mac.name) efface la sienne. Pour le réactiver, recommence depuis le Mac.")
        }

        if !agents.log.isEmpty {
            Section("Journal") {
                ForEach(agents.log) { line in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: "\(line.client) · \(AgentRequestText.actionTitle(line.action))")
                            .font(.callout)
                        Text(verbatim: "\(line.decision) · \(line.mac) · \(line.date.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
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
            } catch let failure as VaultError {
                error = failure.localizedMessage
            } catch {
                self.error = RemoteResponderError.unavailable.message
            }
        }
    }
}
#endif
