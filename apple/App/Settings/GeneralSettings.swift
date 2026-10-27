import SwiftUI
import VaultKit

/// Général: automatic lock delay, site icons, and the import of other password managers' exports.
struct GeneralSettings: View {
    @Environment(AppModel.self) private var model
    @State private var importing = false

    private var settings: VaultSettings { model.settings }
    private var shared: Bool { settings.deviceMode == .shared }

    /// Shared devices lock after 5 minutes at most: longer delays are not offered.
    private var delays: [AutoLockDelay] {
        shared ? [settings.autoLockDelay == .oneMinute ? .oneMinute : .fiveMinutes] : AutoLockDelay.allCases
    }

    var body: some View {
        // Read so the page redraws when a setting changes.
        let _ = model.settingsRevision
        Form {
            Section {
                Picker("Verrouillage automatique", selection: Binding(
                    get: { delays.contains(settings.autoLockDelay) ? settings.autoLockDelay : .fiveMinutes },
                    set: { delay in model.updateSettings { $0.autoLockDelay = delay } }
                )) {
                    ForEach(delays, id: \.self) { delay in
                        Text(delay.label).tag(delay)
                    }
                }
                .disabled(shared)
                .accessibilityIdentifier("settings.autoLock")
            } footer: {
                if shared {
                    Text("Appareil partagé : le délai est imposé (5 minutes au plus). Repasse en mode personnel pour le régler.")
                } else {
                    Text("OnePass se verrouille après ce délai d'inactivité et quand l'app reste en arrière-plan aussi longtemps.")
                }
            }
            Section {
                Toggle("Icônes des sites", isOn: Binding(
                    get: { settings.siteIconsEnabled },
                    set: { value in model.updateSettings { $0.siteIconsEnabled = value } }
                ))
                .accessibilityIdentifier("settings.siteIcons")
            } footer: {
                Text("Récupérées directement sur le site de l'élément, sans cookies et sans service tiers. Désactivées, aucune requête n'est envoyée.")
            }
            Section {
                Button("Importer depuis un autre gestionnaire…", systemImage: "square.and.arrow.down") {
                    importing = true
                }
                .accessibilityIdentifier("settings.import")
            } header: {
                Text("Import")
            } footer: {
                Text("Mots de passe d'Apple, 1Password, Bitwarden, NordPass, Dashlane, LastPass, Proton Pass, Keeper, Enpass, RoboForm, KeePass et les navigateurs.")
            }
        }
        // Over the settings themselves (the Mac `Settings` window has no browse sheet).
        .sheet(isPresented: $importing) {
            ImportSheet()
        }
        .formStyle(.grouped)
        .navigationTitle("Général")
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}
