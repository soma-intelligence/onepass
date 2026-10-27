import SwiftUI
import VaultKit

/// Remplissage automatique (spec 6): provider state, "Activer OnePass" (system prompt, with the system
/// settings as fallback), verification code app, QuickType suggestions, and what the system sees.
/// The state is read again when the page appears, after the prompt, and on every return to the
/// foreground (`AppModel.scenePhaseChanged`).
struct AutoFillSettings: View {
    @Environment(AppModel.self) private var model
    @State private var requesting = false

    private var settings: VaultSettings { model.settings }

    var body: some View {
        // Read so the page redraws when a setting changes.
        let _ = model.settingsRevision
        Form {
            providerSection
            Section {
                Button("Codes de vérification", systemImage: "number.square") {
                    Task { await AutoFillStatus.openVerificationCodeSettings() }
                }
                .accessibilityIdentifier("autofill.codes")
            } footer: {
                Text("Choisis OnePass comme app de codes de vérification : le code du Login du site est proposé dans le champ.")
            }
            Section {
                Toggle("Suggestions au-dessus du clavier", isOn: Binding(
                    get: { settings.quickTypeSuggestions },
                    set: { on in
                        model.session.setQuickTypeSuggestions(on)
                        model.settingsChanged()
                    }
                ))
                .accessibilityIdentifier("autofill.quicktype")
            } header: {
                Text("Ce que voit le système")
            } footer: {
                Text("Pour te suggérer le bon compte, le système reçoit les domaines et les identifiants de tes Logins, jamais tes mots de passe, codes ou clés. Désactivées, plus rien n'est transmis : tu choisis alors le compte avec la touche clé du clavier.")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Remplissage automatique")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .task { await model.refreshAutoFillStatus() }
    }

    @ViewBuilder private var providerSection: some View {
        let enabled = model.autofillEnabled
        Section {
            LabeledContent("OnePass") {
                Group {
                    switch enabled {
                    case true?: Label("Activé", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    case false?: Text("Désactivé")
                    case nil: ProgressView().controlSize(.small)
                    }
                }
            }
            // UI tests read the value: "Activé", "Désactivé", or empty while the state is read.
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("OnePass"))
            .accessibilityValue(statusValue(enabled))
            .accessibilityIdentifier("autofill.status")
            if enabled == false {
                Button {
                    activate()
                } label: {
                    Label("Activer OnePass", systemImage: "key.fill")
                }
                .disabled(requesting)
                .accessibilityIdentifier("autofill.enable")
                Button("Ouvrir les réglages du système", systemImage: "gear") {
                    Task { await AutoFillStatus.openProviderSettings() }
                }
                .accessibilityIdentifier("autofill.systemSettings")
            } else if enabled == true {
                Button("Gérer dans les réglages du système", systemImage: "gear") {
                    Task { await AutoFillStatus.openProviderSettings() }
                }
                .accessibilityIdentifier("autofill.systemSettings")
            }
        } header: {
            Text("OnePass remplit tes identifiants, codes et passkeys dans les apps et Safari.")
                .font(.subheadline)
                .textCase(nil)
        } footer: {
            if enabled == true {
                #if os(macOS)
                Text("Clique dans un champ d'identifiant : OnePass propose tes comptes et se déverrouille par \(OnboardingModel.biometryName) ou ton mot de passe maître avant de remplir.")
                #else
                Text("Touche un champ d'identifiant : OnePass apparaît au-dessus du clavier et se déverrouille par \(OnboardingModel.biometryName) ou ton mot de passe maître avant de remplir.")
                #endif
            } else {
                Text("Si la demande ne s'affiche pas, active OnePass dans les réglages du système, rubrique Remplissage automatique et mots de passe.")
            }
        }
    }

    private func statusValue(_ enabled: Bool?) -> Text {
        switch enabled {
        case true?: Text("Activé")
        case false?: Text("Désactivé")
        case nil: Text(verbatim: "")
        }
    }

    private func activate() {
        guard !requesting else { return }
        requesting = true
        Task {
            await model.requestAutoFillActivation()
            requesting = false
        }
    }
}
