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
                Button("settings.verificationCodes", systemImage: "number.square") {
                    Task { await AutoFillStatus.openVerificationCodeSettings() }
                }
                .accessibilityIdentifier("autofill.codes")
            } footer: {
                Text("settings.autofill.codes.footer")
            }
            Section {
                Toggle("settings.autofill.quickType", isOn: Binding(
                    get: { settings.quickTypeSuggestions },
                    set: { on in
                        model.session.setQuickTypeSuggestions(on)
                        model.settingsChanged()
                    }
                ))
                .accessibilityIdentifier("autofill.quicktype")
            } footer: {
                Text("settings.autofill.quickType.footer")
            }
            #if os(iOS)
            // The system asks the extension for a password only on iOS (26.2 and later).
            GeneratorProfileSection()
            #endif
            Section {
                NavigationLink {
                    ForgetSiteChoices()
                } label: {
                    Label("settings.autofill.forgetSites", systemImage: "eraser")
                }
                .accessibilityIdentifier("autofill.forgetSites")
            } footer: {
                Text("settings.autofill.forgetSites.footer")
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
                    case true?: Label("app.on", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    case false?: Text("app.off")
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
                    Label("app.turnOnOnepass", systemImage: "key.fill")
                }
                .disabled(requesting)
                .accessibilityIdentifier("autofill.enable")
                Button("settings.openSystemSettings", systemImage: "gear") {
                    Task { await AutoFillStatus.openProviderSettings() }
                }
                .accessibilityIdentifier("autofill.systemSettings")
            } else if enabled == true {
                Button("settings.manageInSystemSettings", systemImage: "gear") {
                    Task { await AutoFillStatus.openProviderSettings() }
                }
                .accessibilityIdentifier("autofill.systemSettings")
            }
        } header: {
            Text("settings.autofill.provider.header")
                .font(.subheadline)
                .textCase(nil)
        } footer: {
            if enabled == true {
                #if os(macOS)
                Text("settings.autofill.enabled.footer.mac")
                #else
                Text("settings.autofill.enabled.footer.ios")
                #endif
            } else {
                Text("settings.autofill.disabled.footer")
            }
        }
    }

    private func statusValue(_ enabled: Bool?) -> Text {
        switch enabled {
        case true?: Text("app.on")
        case false?: Text("app.off")
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
                    Text("settings.noSiteRememberedYet")
                        .foregroundStyle(.secondary)
                case let sites?:
                    ForEach(sites, id: \.self) { site in
                        LabeledContent(site) {
                            Button("settings.forget", role: .destructive) { forgetting = site }
                                .accessibilityIdentifier("autofill.forgetSites.forget")
                        }
                    }
                }
            } footer: {
                Text("settings.autofill.forgetSites.pageFooter")
            }
        }
        .settingsPage("settings.autofill.forgetSites.title")
        .task { await reload() }
        .confirmationDialog(
            "Oublier ce site ?", isPresented: Binding(get: { forgetting != nil }, set: { if !$0 { forgetting = nil } }),
            titleVisibility: .visible, presenting: forgetting
        ) { site in
            Button("settings.forget \(site)", role: .destructive) { Task { await forget(site) } }
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
