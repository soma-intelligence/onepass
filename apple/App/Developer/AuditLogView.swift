#if os(macOS)
import DesignKit
import SwiftUI
import VaultKit

/// The audit log of the SSH agent and the MCP server, newest first, verified before it is shown. A log
/// that no longer verifies shows nothing and offers to archive it and start a new one.
struct AuditLogView: View {
    @Environment(AppModel.self) private var model
    @State private var report: FfiAuditReport?
    @State private var errorMessage: String?

    var body: some View {
        Group {
            if let report, let problem = report.problem {
                ContentUnavailableView {
                    Label("Journal refusé", systemImage: "exclamationmark.shield")
                } description: {
                    Text("Le journal ne se vérifie plus (\(problem)). Archive-le pour en commencer un nouveau : l'ancien reste à côté pour examen.")
                } actions: {
                    Button("Archiver et recommencer") { Task { await rotate() } }
                }
            } else if let report, report.entries.isEmpty {
                ContentUnavailableView(
                    "Journal vide", systemImage: "list.bullet.rectangle",
                    description: Text("Les signatures SSH et les accès MCP apparaîtront ici."))
            } else if let report {
                Table(report.entries) {
                    TableColumn("Date") { e in Text(Self.date(e.time)) }
                        .width(min: 120, ideal: 140)
                    TableColumn("Origine") { e in Text(e.surface.uppercased()) }
                        .width(48)
                    TableColumn("Client", value: \.client)
                    TableColumn("Action", value: \.action)
                    TableColumn("Cible") { e in Text([e.vault, e.item, e.field].compactMap { $0 }.joined(separator: " › ")) }
                    TableColumn("Décision") { e in
                        Text(e.outcome == "ok" ? e.decision : "\(e.decision) · \(e.outcome)")
                            .foregroundStyle(e.decision == "denied" || e.outcome != "ok" ? Color.orange : Color.primary)
                    }
                }
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Journal d'audit")
        .safeAreaInset(edge: .bottom) {
            if let report, report.unsealedTail {
                Label("Les dernières lignes ne sont pas encore scellées (arrêt pendant une écriture).", systemImage: "info.circle")
                    .font(.footnote)
                    .padding(8)
            }
        }
        .task(id: model.developer.revision) { await load() }
    }

    private func load() async {
        do {
            report = try await model.session.auditReport(dataDirectory: model.developer.dataDirectory)
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }

    private func rotate() async {
        try? await model.session.rotateAuditLog(dataDirectory: model.developer.dataDirectory)
        await load()
    }

    private static func date(_ rfc3339: String) -> String {
        guard let date = try? Date(rfc3339, strategy: .iso8601) else { return rfc3339 }
        return date.formatted(date: .abbreviated, time: .standard)
    }
}

extension FfiAuditEntry: @retroactive Identifiable {
    public var id: UInt64 { seq }
}
#endif
