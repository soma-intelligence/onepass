import SwiftUI
import VaultKit

/// Sync: status of the iCloud sync and "Synchroniser maintenant". An unsigned build has no
/// CloudKit (ruling R8) and says so.
struct SyncSettings: View {
    @Environment(AppModel.self) private var model
    @State private var syncing = false

    /// Status line and its symbol; nil last sync means a first round has not finished yet.
    private enum Line {
        case disabled, offline, refused(String), error(String), syncing, idle(Date?), accountChanged, waiting
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
        case .accountChanged: return .accountChanged
        case .waitingForServer: return .waiting
        }
    }

    @State private var safeExitKind: String?

    private var canSync: Bool {
        if case .disabled = line { return false }
        if case .syncing = line { return false }
        if case .accountChanged = line { return false }
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
                if case .accountChanged = line {
                    UseICloudAccountButton()
                }
                if case .refused(let kind) = line {
                    Button("Voir les solutions") { safeExitKind = kind }
                        .accessibilityIdentifier("settings.sync.safeExits")
                }
            } footer: {
                footer
            }
            if model.ignoredDeletionCount > 0 {
                Section {
                    NavigationLink {
                        IgnoredDeletionsView()
                    } label: {
                        Label {
                            if model.ignoredDeletionCount == 1 {
                                Text("1 suppression refusée venant d'iCloud")
                            } else {
                                Text("\(model.ignoredDeletionCount) suppressions refusées venant d'iCloud")
                            }
                        } icon: {
                            Image(systemName: "hand.raised.fill")
                        }
                    }
                    .accessibilityIdentifier("settings.ignoredDeletions")
                } footer: {
                    Text("OnePass a gardé ces éléments sur cet appareil.")
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Sync")
        .sheet(item: Binding(get: { safeExitKind.map(RefusedKind.init) }, set: { safeExitKind = $0?.kind })) {
            SafeExitChooserSheet(kind: $0.kind)
        }
        #if os(iOS) || os(visionOS)
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
        case .accountChanged:
            Label("Le compte iCloud a changé", systemImage: "person.crop.circle.badge.exclamationmark")
                .foregroundStyle(.orange)
        case .syncing:
            Label("Synchronisation en cours", systemImage: "arrow.triangle.2.circlepath")
        case .waiting:
            Label("Synchronisation en attente d'iCloud", systemImage: "icloud.and.arrow.up")
                .foregroundStyle(.secondary)
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
        case .waiting:
            Text("iCloud sert encore une version plus ancienne que celle de cet appareil. OnePass continue avec sa copie vérifiée et la renvoie ; rien n'est à faire.")
        case .accountChanged:
            Text("Cet appareil est maintenant connecté à un autre compte iCloud que celui avec lequel ton coffre se synchronisait. Par sécurité, OnePass ne lit et n'envoie plus rien vers iCloud : ton coffre reste intact sur cet appareil. Reconnecte-toi au compte iCloud d'origine dans Réglages pour reprendre la synchronisation, ou utilise ce compte : OnePass vérifie d'abord qu'il ne contient pas un autre coffre.")
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

/// A refusal kind, as a sheet item.
struct RefusedKind: Identifiable {
    let kind: String
    var id: String { kind }
}
