import SwiftUI
import VaultKit

/// Sécurité: biometric unlock (asks the master password to turn on), Apple Watch (Mac), the
/// 14 day password reminder, device mode, visible vaults (shared mode), lock now.
struct SecuritySettings: View {
    @Environment(AppModel.self) private var model

    /// The master password prompt serves two changes: turning biometrics on, and turning the
    /// Watch on or off while biometrics are on (the Secure Enclave key is created again).
    private enum Prompt: Identifiable, Equatable {
        case enableBiometrics
        case watch(Bool)

        var id: String {
            switch self {
            case .enableBiometrics: "biometrics"
            case .watch(let on): "watch.\(on)"
            }
        }
    }

    @State private var prompt: Prompt?
    @State private var pendingMode: DeviceMode?
    @State private var errorMessage: String?
    @State private var changingPassword = false

    private var session: VaultSession { model.session }
    private var settings: VaultSettings { model.settings }
    private var biometry: String { OnboardingModel.biometryName }
    private var availability: BiometricAvailability { session.environment.biometrics.availability }
    private var hardwareAvailable: Bool { availability == .available }

    var body: some View {
        // Read so the page redraws when a setting changes.
        let _ = model.settingsRevision
        Form {
            unlockSection
            Section {
                Button("Changer le mot de passe maître", systemImage: "key") { changingPassword = true }
                    .accessibilityIdentifier("settings.changePassword")
            } footer: {
                Text("Ta Secret Key ne change pas : ton Emergency Kit reste valable.")
            }
            deviceModeSection
            Section {
                Button("Verrouiller maintenant", systemImage: "lock") {
                    // The discard confirmation of an edited draft belongs to the main screen.
                    model.showSettings = false
                    model.perform(.lock)
                }
                    .accessibilityIdentifier("settings.lockNow")
            }
            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .accessibilityIdentifier("settings.security.error")
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Sécurité")
        #if os(iOS) || os(visionOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .sheet(isPresented: $changingPassword) { ChangePasswordSheet() }
        .sheet(item: $prompt) { current in
            PasswordPromptSheet(title: promptTitle(current), footer: promptFooter(current)) { password in
                try await confirm(current, password: password)
            }
        }
        .confirmationDialog(
            modeDialogTitle, isPresented: Binding(get: { pendingMode != nil }, set: { if !$0 { pendingMode = nil } }),
            titleVisibility: .visible
        ) {
            Button(pendingMode == .shared ? "Passer en mode partagé" : "Repasser en mode personnel") {
                if let mode = pendingMode { setMode(mode) }
                pendingMode = nil
            }
            .accessibilityIdentifier("settings.deviceMode.confirm")
            Button("Annuler", role: .cancel) { pendingMode = nil }
        } message: {
            Text(modeDialogMessage)
        }
    }

    // MARK: - Déverrouillage

    @ViewBuilder private var unlockSection: some View {
        let personal = settings.deviceMode.biometricsAllowed
        Section {
            if personal {
                // Shown even when it cannot work here: disabled, the footer says why.
                Toggle(isOn: Binding(
                    get: { hardwareAvailable && session.canUseBiometrics },
                    set: { on in
                        errorMessage = nil
                        if on { prompt = .enableBiometrics } else {
                            session.disableBiometrics()
                            model.settingsChanged()
                        }
                    }
                )) {
                    Label("Déverrouiller avec \(biometry)", systemImage: OnboardingModel.biometrySymbol)
                }
                .disabled(!hardwareAvailable)
                .accessibilityIdentifier("settings.biometrics")
            }
            if personal, hardwareAvailable {
                #if os(macOS)
                Toggle("Apple Watch", isOn: Binding(
                    get: { settings.allowWatchUnlock },
                    set: { on in
                        errorMessage = nil
                        if session.canUseBiometrics {
                            prompt = .watch(on)
                        } else {
                            model.updateSettings { $0.allowWatchUnlock = on }
                        }
                    }
                ))
                .accessibilityIdentifier("settings.watch")
                #endif
            }
            LabeledContent("Mot de passe maître") {
                Text("Redemandé tous les 14 jours")
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("settings.passwordReminder")
        } header: {
            Text("Déverrouillage")
        } footer: {
            unlockFooter(personal: personal)
        }
    }

    @ViewBuilder private func unlockFooter(personal: Bool) -> some View {
        if !personal {
            Text("\(biometry) n'est pas proposé sur un appareil partagé : le mot de passe maître est demandé à chaque déverrouillage.")
        } else if availability == .keychainRefused {
            Text("Cet appareil a \(biometry), mais cette version de OnePass n'est pas signée : le trousseau refuse sa clé de la Secure Enclave (erreur -34018). Le mot de passe maître déverrouille OnePass. \(biometry) marche dans un build signé.")
                .accessibilityIdentifier("settings.biometrics.unavailable")
        } else if availability == .noBiometry {
            Text("\(biometry) n'est pas disponible sur cet appareil (pas de Secure Enclave ou biométrie non configurée). Le mot de passe maître déverrouille OnePass.")
                .accessibilityIdentifier("settings.biometrics.unavailable")
        } else {
            Text("Le mot de passe maître est aussi redemandé après un redémarrage et quand les empreintes ou le visage enregistrés changent.")
        }
    }

    private func promptTitle(_ prompt: Prompt) -> LocalizedStringKey {
        switch prompt {
        case .enableBiometrics: "Activer \(biometry)"
        case .watch(let on): on ? "Activer l'Apple Watch" : "Désactiver l'Apple Watch"
        }
    }

    private func promptFooter(_ prompt: Prompt) -> LocalizedStringKey {
        switch prompt {
        case .enableBiometrics: "Saisis ton mot de passe maître, puis confirme avec \(biometry)."
        case .watch: "Le mot de passe maître est demandé pour changer ce réglage."
        }
    }

    private func confirm(_ prompt: Prompt, password: SecretBytes) async throws {
        switch prompt {
        case .enableBiometrics:
            // Master password, then one Touch ID or Face ID check.
            try await model.enableBiometrics(password: password)
        case .watch(let on):
            let previous = settings.allowWatchUnlock
            model.updateSettings { $0.allowWatchUnlock = on }
            do {
                try await session.enrollBiometrics(password: password)
            } catch {
                model.updateSettings { $0.allowWatchUnlock = previous }
                throw error
            }
        }
        model.settingsChanged()
    }

    // MARK: - Mode d'appareil

    private var deviceModeSection: some View {
        Section {
            Picker("Mode de l'appareil", selection: Binding(
                get: { settings.deviceMode },
                set: { mode in
                    if mode != settings.deviceMode { pendingMode = mode }
                }
            )) {
                Text("Personnel").tag(DeviceMode.personal)
                Text("Partagé").tag(DeviceMode.shared)
            }
            .accessibilityIdentifier("settings.deviceMode")
            if settings.deviceMode == .shared {
                NavigationLink {
                    VisibleVaultsView()
                } label: {
                    LabeledContent("Coffres visibles") {
                        Text(visibleSummary)
                    }
                }
                .accessibilityIdentifier("settings.visibleVaults")
            }
        } header: {
            Text("Mode de l'appareil")
        } footer: {
            if settings.deviceMode == .shared {
                Text("Appareil de la famille ou du bureau : pas de \(biometry), verrouillage après 5 minutes, coffres visibles au choix.")
            } else {
                Text("Appareil à toi : déverrouillage par \(biometry), verrouillage automatique réglable.")
            }
        }
    }

    private var visibleSummary: String {
        let all = session.allVaults.count
        let visible = session.allVaults.filter { !session.hiddenVaultIDs.contains($0.id) }.count
        return String(localized: "\(visible) sur \(all)")
    }

    private var modeDialogTitle: LocalizedStringKey {
        pendingMode == .shared ? "Passer en mode partagé ?" : "Repasser en mode personnel ?"
    }

    private var modeDialogMessage: LocalizedStringKey {
        if pendingMode == .shared {
            "\(biometry) est désactivé sur cet appareil, OnePass se verrouille après 5 minutes au plus et le mot de passe maître est demandé à chaque déverrouillage. Tu choisis ensuite les coffres visibles."
        } else {
            "Tous les coffres redeviennent visibles. \(biometry) reste désactivé jusqu'à ce que tu le réactives avec ton mot de passe maître."
        }
    }

    private func setMode(_ mode: DeviceMode) {
        errorMessage = nil
        // Drops the biometric enrollment when the new mode forbids it.
        session.setDeviceMode(mode)
        if mode == .shared {
            // Shared devices lock after 5 minutes at most; a 1 minute delay already fits.
            if settings.autoLockDelay != .oneMinute { model.updateSettings { $0.autoLockDelay = .fiveMinutes } }
            // At least one vault stays visible.
            if session.vaults.isEmpty, let first = session.allVaults.first {
                session.setVaultHidden(first.id, hidden: false)
            }
        } else {
            // Hiding vaults is a shared-mode rule: every vault is back.
            for id in session.hiddenVaultIDs { session.setVaultHidden(id, hidden: false) }
        }
        model.settingsChanged()
    }
}

/// Asks the master password (never trimmed) and runs `submit`; the sheet closes when it succeeds
/// and shows the error otherwise.
struct PasswordPromptSheet: View {
    @Environment(\.dismiss) private var dismiss
    let title: LocalizedStringKey
    let footer: LocalizedStringKey
    /// Gets the typed password in a wipeable buffer, wiped once `submit` returns.
    let submit: (SecretBytes) async throws -> Void

    init(
        title: LocalizedStringKey,
        footer: LocalizedStringKey = "Le mot de passe maître est demandé pour changer ce réglage.",
        submit: @escaping (SecretBytes) async throws -> Void
    ) {
        self.title = title
        self.footer = footer
        self.submit = submit
    }

    @State private var password = ""
    @State private var busy = false
    @State private var errorMessage: String?
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Mot de passe maître", text: $password)
                        .focused($focused)
                        .onSubmit(run)
                        // No `.password` content type: iOS must never offer to save the master password.
                        .privacySensitive()
                        .accessibilityIdentifier("settings.prompt.password")
                } footer: {
                    Text(footer)
                }
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(title)
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Confirmer", action: run)
                        .disabled(password.isEmpty || busy)
                        .accessibilityIdentifier("settings.prompt.confirm")
                }
            }
            .onAppear { focused = true }
        }
        #if os(macOS)
        .frame(minWidth: 380, minHeight: 220)
        #endif
        .interactiveDismissDisabled(busy)
        .onDisappear { password = "" }
    }

    private func run() {
        guard !password.isEmpty, !busy else { return }
        busy = true
        errorMessage = nil
        // Emptied on submission (success or not): the password lives on in a wiped buffer only (R5).
        let value = SecretBytes(utf8: password)
        password = ""
        Task {
            defer {
                value.wipe()
                busy = false
            }
            do {
                try await submit(value)
                dismiss()
            } catch {
                errorMessage = VaultError(error).localizedMessage
                focused = true
            }
        }
    }
}
