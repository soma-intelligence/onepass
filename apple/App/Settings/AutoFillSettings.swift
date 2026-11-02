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
            #if os(macOS)
            if let bridge = model.browserBridge {
                BrowserBridgeSection(bridge: bridge)
            }
            #endif
            Section {
                Button("Codes de vérification", systemImage: "number.square") {
                    Task { await AutoFillStatus.openVerificationCodeSettings() }
                }
                .accessibilityIdentifier("autofill.codes")
            } footer: {
                Text("Le code du site est proposé dans le champ.")
            }
            Section {
                Toggle("Suggestions du clavier", isOn: Binding(
                    get: { settings.quickTypeSuggestions },
                    set: { on in
                        model.session.setQuickTypeSuggestions(on)
                        model.settingsChanged()
                    }
                ))
                .accessibilityIdentifier("autofill.quicktype")
            } footer: {
                Text("Le système reçoit les sites et identifiants, jamais les mots de passe ni les codes.")
            }
            #if os(iOS)
            // The system asks the extension for a password only on iOS (26.2 and later).
            GeneratorProfileSection()
            #endif
            Section {
                NavigationLink {
                    ForgetSiteChoices()
                } label: {
                    Label("Comptes retenus par site", systemImage: "eraser")
                }
                .accessibilityIdentifier("autofill.forgetSites")
            } footer: {
                Text("Le compte choisi sur un site est proposé en premier.")
            }
        }
        .settingsPage("Remplissage automatique")
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
            Text("Identifiants, codes et passkeys, dans les apps et Safari.")
                .font(.subheadline)
                .textCase(nil)
        } footer: {
            if enabled == true {
                #if os(macOS)
                Text("Clique dans un champ d'identifiant : OnePass propose tes comptes.")
                #else
                Text("Touche un champ d'identifiant : OnePass apparaît au-dessus du clavier.")
                #endif
            } else {
                Text("Sinon : Réglages du système > Remplissage automatique et mots de passe.")
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

/// "Oublier les choix pour un site": the sites the visible vaults remember a choice for, each with a
/// button that forgets it in every item (other devices drop it at the next sync).
struct ForgetSiteChoices: View {
    @Environment(AppModel.self) private var model
    @State private var sites: [String]?
    @State private var forgetting: String?
    @State private var errorMessage: String?

    var body: some View {
        Form {
            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                }
            }
            Section {
                switch sites {
                case nil:
                    ProgressView()
                case let sites? where sites.isEmpty:
                    Text("Aucun site retenu pour l'instant.")
                        .foregroundStyle(.secondary)
                case let sites?:
                    ForEach(sites, id: \.self) { site in
                        LabeledContent(site) {
                            Button("Oublier", role: .destructive) { forgetting = site }
                                .accessibilityIdentifier("autofill.forgetSites.forget")
                        }
                    }
                }
            } footer: {
                Text("Oublier un site efface son choix sur tous tes appareils. Tes Logins ne changent pas.")
            }
        }
        .settingsPage("Comptes retenus")
        .task { await reload() }
        .confirmationDialog(
            "Oublier ce site ?", isPresented: Binding(get: { forgetting != nil }, set: { if !$0 { forgetting = nil } }),
            titleVisibility: .visible, presenting: forgetting
        ) { site in
            Button("Oublier \(site)", role: .destructive) { Task { await forget(site) } }
            Button("Annuler", role: .cancel) {}
        }
    }

    private func reload() async {
        do {
            sites = try await model.session.knownUsageSites()
            errorMessage = nil
        } catch {
            sites = []
            errorMessage = VaultError(error).localizedMessage
        }
    }

    private func forget(_ site: String) async {
        forgetting = nil
        do {
            try await model.session.forgetSiteUsage(site: site)
            await reload()
        } catch {
            // Never shown as done: some vaults may still remember the site.
            let message = VaultError(error).localizedMessage
            await reload()
            errorMessage = message
        }
    }
}
