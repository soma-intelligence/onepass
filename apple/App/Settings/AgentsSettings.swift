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
    /// The pending requests open over Réglages: the root's sheet (`showRequests`) cannot show while
    /// Réglages, itself a sheet, is up.
    @State private var showingRequests = false

    var body: some View {
        Form {
            if let agents = model.phoneAgents, agents.isAvailable {
                content(agents)
            } else {
                Section {
                    Label("settings.requiresIcloudVersionOf", systemImage: "icloud.slash")
                        .foregroundStyle(.secondary)
                } footer: {
                    Text("settings.agentRequestsGoThrough")
                }
            }
        }
        .settingsPage("Agents")
        .disabled(busy)
        .task { await model.phoneAgents?.refresh() }
        .sheet(isPresented: $showingRequests) {
            if let agents = model.phoneAgents {
                AgentRequestsSheet(agents: agents)
            }
        }
    }

    @ViewBuilder private func content(_ agents: PhoneAgents) -> some View {
        Section {
            if agents.isEnabled {
                Label("settings.iphoneApprovesRequests", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .accessibilityIdentifier("agents.enabled")
                Button("settings.seePendingRequests \(agents.requests.count)") {
                    showingRequests = true
                }
                .accessibilityIdentifier("agents.pending")
            } else {
                Button("settings.approveRequestsOnIphone") {
                    run {
                        try await agents.enable()
                        // The alert of a request (time sensitive, no action in it).
                        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
                    }
                }
                .accessibilityIdentifier("agents.enable")
            }
            if agents.faceIDNeedsReset {
                Label("settings.faceIdChangedOn", systemImage: "faceid")
                    .foregroundStyle(.orange)
                Button("settings.turnFaceIdBack") {
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
                LabeledContent("settings.remoteUnlock") {
                    mac.unlockEnrolled ? Text("app.on") : Text("app.off")
                }
                if let end = mac.windowEndsAt {
                    LabeledContent("settings.agentsWindowRequested") {
                        Text("settings.until \(end.formatted(date: .omitted, time: .shortened))")
                    }
                }
                if mac.unlockEnrolled {
                    Button("settings.lockNow") {
                        run { try await agents.lockNow(mac: mac.id) }
                    }
                    .accessibilityIdentifier("agents.lockNow")
                    Button("settings.forgetRemoteUnlock", role: .destructive) {
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
            Button("settings.forget", role: .destructive) {
                run { try await agents.forget(mac: mac.id) }
            }
            Button("Annuler", role: .cancel) {}
        } message: { mac in
            Text("settings.iphoneErasesKeyAnd \(mac.name)")
        }

        if !agents.log.isEmpty {
            Section("app.log") {
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
