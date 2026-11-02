import SwiftUI
import VaultKit

/// "Passer au serveur OnePass" (cross-platform spec D.5): what happens, then the migration, then
/// where the vault syncs now. Started only on the user's gesture, on an unlocked device.
struct MigrationSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var running = false
    @State private var result: MailboxMigration.Outcome?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("settings.sync.migrate.explain")
                        .fixedSize(horizontal: false, vertical: true)
                }
                if running {
                    Section {
                        HStack {
                            ProgressView().controlSize(.small)
                            Text("settings.sync.migrate.uploading")
                        }
                    }
                }
                if let result {
                    Section { Text(message(result)).accessibilityIdentifier("settings.sync.migrate.result") }
                }
            }
            .navigationTitle("settings.sync.migrate.button")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("common.close") { dismiss() }.disabled(running)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("common.continue") { Task { await migrate() } }
                        .disabled(running || isDone)
                        .accessibilityIdentifier("settings.sync.migrate.continue")
                }
            }
        }
    }

    private var isDone: Bool {
        if case .done = result { true } else { false }
    }

    private func migrate() async {
        running = true
        defer { running = false }
        result = await model.migrateToMailbox(choice: .hosted)
    }

    private func message(_ outcome: MailboxMigration.Outcome) -> String {
        switch outcome {
        case .done: String(localized: "settings.sync.migrate.done \(model.syncBackendName)")
        case .lostRace: String(localized: "settings.sync.migrate.lostRace")
        case .blocked(.locked): String(localized: "settings.sync.migrate.blocked.locked")
        case .blocked(.offline): String(localized: "settings.sync.migrate.blocked.offline")
        case .blocked(.rotating): String(localized: "settings.sync.migrate.blocked.rotating")
        case .blocked(.notSynced), .blocked(.refused): String(localized: "settings.sync.migrate.blocked.notSynced")
        case .failed(let reason): reason
        }
    }
}
