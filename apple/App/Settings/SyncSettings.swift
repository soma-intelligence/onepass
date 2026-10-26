import SwiftUI
import VaultKit

/// Sync: status of the iCloud sync and "Synchroniser maintenant". An unsigned build has no
/// CloudKit (ruling R8) and says so.
struct SyncSettings: View {
    @Environment(AppModel.self) private var model
    @State private var syncing = false

    /// Status line and its symbol; nil last sync means a first round has not finished yet.
    private enum Line {
        case disabled, offline, refused(String), error(String), syncing, idle(Date?)
    }

    private var line: Line {
        guard model.cloudKitEnabled else { return .disabled }
        switch model.syncStatus {
        case .disabled: return .disabled
        case .offline: return .offline
        case .refused(let kind): return .refused(kind)
        case .error(let message): return .error(message)
        case .syncing: return .syncing
        case .idle(let last): return .idle(last)
        }
    }

    private var canSync: Bool {
        if case .disabled = line { return false }
        if case .syncing = line { return false }
        return model.coordinator != nil && !syncing
    }

    var body: some View {
        Form {
            Section {
                statusRow
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("settings.sync.status")
                Button {
                    syncNow()
                } label: {
                    HStack {
                        Text("Synchroniser maintenant")
                        if syncing { Spacer(); ProgressView().controlSize(.small) }
                    }
                }
                .disabled(!canSync)
                .accessibilityIdentifier("settings.syncNow")
            } footer: {
                footer
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Sync")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }

    @ViewBuilder private var statusRow: some View {
        switch line {
        case .disabled:
            Label("Sync désactivée : build local sans iCloud", systemImage: "icloud.slash")
                .foregroundStyle(.secondary)
        case .offline:
            Label("Hors ligne", systemImage: "wifi.slash").foregroundStyle(.orange)
        case .refused(let kind):
            VStack(alignment: .leading, spacing: 4) {
                Label("Données refusées", systemImage: "xmark.shield.fill").foregroundStyle(.red)
                Text(VaultError.integrityLabel(kind)).font(.footnote).foregroundStyle(.secondary)
            }
        case .error(let message):
            Label(message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
        case .syncing:
            Label("Synchronisation en cours", systemImage: "arrow.triangle.2.circlepath")
        case .idle(let last):
            if let last {
                // Re-evaluated every 30 seconds so "il y a 1 minute" moves on.
                TimelineView(.periodic(from: .now, by: 30)) { context in
                    Label(Self.agoText(since: last, now: context.date), systemImage: "checkmark.icloud")
                }
            } else {
                Label("En attente de la première synchronisation", systemImage: "icloud")
            }
        }
    }

    @ViewBuilder private var footer: some View {
        switch line {
        case .disabled:
            Text("Les données restent sur cet appareil. La synchronisation chiffrée par iCloud demande une version signée de OnePass.")
        case .refused:
            Text("Les données reçues d'iCloud ont été refusées par OnePass. Aucune n'a été utilisée.")
        default:
            Text("Tout est chiffré avant de quitter cet appareil. iCloud ne voit que des données illisibles.")
        }
    }

    /// "Synchronisé il y a 3 minutes" (French, whatever the device language).
    static func agoText(since date: Date, now: Date) -> String {
        if now.timeIntervalSince(date) < 45 { return String(localized: "Synchronisé à l'instant") }
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "fr_FR")
        formatter.unitsStyle = .full
        return String(localized: "Synchronisé \(formatter.localizedString(for: date, relativeTo: now))")
    }

    private func syncNow() {
        guard let coordinator = model.coordinator, !syncing else { return }
        syncing = true
        Task {
            await coordinator.syncNow()
            syncing = false
        }
    }
}
