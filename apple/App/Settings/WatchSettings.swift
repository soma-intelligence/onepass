#if os(iOS)
import CompanionLink
import SwiftUI

/// Apple Watch: what the iPhone sends to the watch and how to take it back. iOS only (the Mac
/// settings window has no such page).
struct WatchSettings: View {
    @Environment(AppModel.self) private var model
    @State private var confirmWipe = false

    var body: some View {
        Form {
            if let phone = model.companion.phone {
                content(phone)
            } else {
                Section {
                    Label("Non disponible sur cet appareil", systemImage: "applewatch.slash")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Apple Watch")
        .navigationBarTitleDisplayMode(.inline)
    }

    @ViewBuilder private func content(_ phone: PhoneCompanion) -> some View {
        @Bindable var phone = phone
        if phone.status == .unsupported {
            Section {
                statusRow(.unsupported)
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("settings.watch.status")
            }
        } else {
            Section {
                Toggle("Envoyer à l'Apple Watch", isOn: $phone.isEnabled)
                    .accessibilityIdentifier("settings.watch.enabled")
                    .onChange(of: phone.isEnabled) { _, enabled in
                        if enabled { Task { await phone.vaultChanged() } }
                    }
                if phone.isEnabled {
                    statusRow(phone.status)
                        .accessibilityElement(children: .combine)
                        .accessibilityIdentifier("settings.watch.status")
                } else {
                    Label("Désactivé", systemImage: "pause.circle").foregroundStyle(.secondary)
                        .accessibilityIdentifier("settings.watch.status")
                }
                if let last = phone.lastSent {
                    LabeledContent("Dernier envoi", value: Self.relative(last))
                        .accessibilityIdentifier("settings.watch.lastSent")
                }
                if let issue = phone.lastError {
                    Label(message(issue), systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .accessibilityIdentifier("settings.watch.error")
                }
            } footer: {
                Text(
                    "Seuls les éléments marqués « Sur l'Apple Watch » sont envoyés. Au-delà de 50 éléments marqués, les derniers par ordre alphabétique ne sont pas copiés."
                )
            }
            Section {
                Text(
                    "La montre reçoit les codes à usage unique, l'identifiant d'un Login, les Wi-Fi avec leur mot de passe, les cartes de membre, la carte bancaire réduite aux 4 derniers chiffres, les codes d'accès et les pièces d'identité. Jamais le mot de passe d'un Login, le CVV, le code PIN, le numéro complet d'une carte ni les notes. Les coffres masqués sont exclus."
                )
                Text(
                    "Sans la détection du poignet, les codes restent visibles tant que la montre est déverrouillée. Verrouille-la pour les protéger."
                )
            }
            .font(.footnote)
            .foregroundStyle(.secondary)
            Section {
                Button("Retirer de l'Apple Watch", role: .destructive) {
                    confirmWipe = true
                }
                .confirmationDialog(
                    "Retirer les données de l'Apple Watch ?", isPresented: $confirmWipe,
                    titleVisibility: .visible
                ) {
                    Button("Retirer de l'Apple Watch", role: .destructive) { phone.wipeWatch() }
                    Button("Annuler", role: .cancel) {}
                } message: {
                    Text("La montre oublie tous les éléments reçus et l'envoi est coupé.")
                }
                .accessibilityIdentifier("settings.watch.wipe")
            } footer: {
                Text("Efface tout ce que la montre a reçu et coupe l'envoi. Réactive « Envoyer à l'Apple Watch » pour envoyer de nouveau.")
            }
        }
    }

    private static func relative(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "fr_FR")
        formatter.unitsStyle = .short
        return formatter.localizedString(for: date, relativeTo: .now)
    }

    @ViewBuilder private func statusRow(_ status: CompanionStatus) -> some View {
        switch status {
        case .ready:
            Label("Prête", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case .notPaired:
            Label("Aucune Apple Watch appairée", systemImage: "applewatch.slash")
                .foregroundStyle(.secondary)
        case .appNotInstalled:
            Label("Installe OnePass sur ton Apple Watch", systemImage: "arrow.down.app")
                .foregroundStyle(.orange)
        case .unsupported:
            Label("Non disponible sur cet appareil", systemImage: "applewatch.slash")
                .foregroundStyle(.secondary)
        }
    }

    private func message(_ issue: CompanionIssue) -> String {
        switch issue {
        case .sendFailed: "Le dernier envoi a échoué. Il sera retenté au prochain changement."
        case .wipeFailed: "L'effacement n'a pas pu être envoyé : la montre garde peut-être ses données."
        }
    }
}
#endif
