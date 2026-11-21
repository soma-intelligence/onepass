import SwiftUI
import VaultKit

/// Sécurité: biometric unlock (asks the master password to turn on), Apple Watch (Mac), the
/// 14 day password reminder, the 90 second AutoFill unlock, the Emergency Kit protection (Guarded
/// Kit), device mode, visible vaults (shared mode), lock now, delete the account (App Review
/// 5.1.1(v): this device and iCloud).
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
    @State private var confirmingDelete = false
    @State private var deletingAccount = false

    private var session: VaultSession { model.session }
    private var settings: VaultSettings { model.settings }
    private var biometry: String { OnboardingModel.biometryName }
    private var availability: BiometricAvailability { session.environment.biometrics.availability }
    private var hardwareAvailable: Bool { availability == .available }

    /// Scroll target of the device mode section (Profil > Mode d'appareil).
    static let deviceModeAnchor = "settings.security.deviceMode"

    var body: some View {
        // Read so the page redraws when a setting changes.
        let _ = model.settingsRevision
        ScrollViewReader { proxy in
            Form {
                Group {
                    unlockSection
                    autofillReuseSection
                    KitProtectionSection()
                    deviceModeSection
                    Section {
                        Button("settings.deleteAccount", systemImage: "trash", role: .destructive) { confirmingDelete = true }
                            .accessibilityIdentifier("settings.deleteAccount")
                    } footer: {
                        SettingsFootnote("settings.deleteAccount.footer")
                    }
                    if let errorMessage {
                        Section {
                            Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.red)
                                .accessibilityIdentifier("settings.security.error")
                        }
                    }
                }
                .rxSettingsRows()
            }
            .rxSettingsSkin()
            .onAppear { focus(proxy) }
            .onChange(of: model.settingsFocusRequest) { focus(proxy) }
        }
        .settingsPage("Sécurité")
        .sheet(isPresented: $changingPassword) { ChangePasswordSheet() }
        .sheet(isPresented: $deletingAccount) {
            PasswordPromptSheet(title: "settings.deleteAccount", footer: "settings.deleteAccount.promptFooter") { password in
                try await model.deleteAccount(password: password)
            }
        }
        .confirmationDialog("settings.deleteAccount.confirmTitle", isPresented: $confirmingDelete, titleVisibility: .visible) {
            Button("settings.deleteAccount.confirmButton", role: .destructive) { deletingAccount = true }
                .accessibilityIdentifier("settings.deleteAccount.confirm")
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("settings.deleteAccount.confirmMessage")
        }
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
                Text("settings.security.passwordReminder")
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("settings.passwordReminder")
            // In the card of the master password; the sheet itself says the Emergency Kit stays valid.
            Button("settings.security.changePassword", systemImage: "key") { changingPassword = true }
                .accessibilityIdentifier("settings.changePassword")
        } header: {
            SettingsHeader("settings.unlock")
        } footer: {
            unlockFooter(personal: personal)
        }
    }

    /// "Remplir 90 secondes sans redemander" (on by default): after Face ID or Touch ID in the
    /// AutoFill provider, the passwords and codes of the same site or app are filled for 90 seconds
    /// without asking again. Personal devices only: a shared device never keeps an unlock.
    @ViewBuilder private var autofillReuseSection: some View {
        if settings.deviceMode.biometricsAllowed, hardwareAvailable {
            Section {
                Toggle("settings.security.autofillReuse", isOn: Binding(
                    get: { settings.autofillUnlockReuse },
                    set: { on in model.updateSettings { $0.autofillUnlockReuse = on } }
                ))
                .accessibilityIdentifier("settings.autofillReuse")
            } header: {
                // The long rule (90 seconds, same site, passkeys excluded) behind the info button.
                SettingsHeader(
                    "Remplissage automatique", info: Text("settings.security.autofillReuse.footer \(biometry)"),
                    id: "settings.autofillReuse.info")
            }
        }
    }

    @ViewBuilder private func unlockFooter(personal: Bool) -> some View {
        if !personal {
            SettingsFootnote(Text("settings.security.unlock.sharedFooter"))
        } else if availability == .keychainRefused {
            SettingsFootnote(Text("settings.security.biometry.unsigned \(biometry)"))
                .accessibilityIdentifier("settings.biometrics.unavailable")
        } else if availability == .noBiometry {
            SettingsFootnote(Text("settings.security.biometry.unavailable \(biometry)"))
                .accessibilityIdentifier("settings.biometrics.unavailable")
        } else {
            SettingsFootnote(Text("settings.security.unlock.footer"))
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

    /// Scrolls to the section another screen asked for (Profil > Mode d'appareil), once.
    private func focus(_ proxy: ScrollViewProxy) {
        guard let target = model.settingsFocusRequest else { return }
        model.settingsFocusRequest = nil
        Task {
            // After the page is laid out: a scroll asked on appear is otherwise lost.
            try? await Task.sleep(for: .milliseconds(350))
            withAnimation { proxy.scrollTo(target, anchor: .center) }
        }
    }

    // MARK: - Mode d'appareil

    private var deviceModeSection: some View {
        Section {
            // The label beside the menu, so the RX cards of the Mac put the menu on the trailing
            // edge (the grouped form draws it the same).
            LabeledContent("settings.device") {
                Picker("settings.device", selection: Binding(
                    get: { settings.deviceMode },
                    set: { mode in
                        if mode != settings.deviceMode { pendingMode = mode }
                    }
                )) {
                    Text("Personnel").tag(DeviceMode.personal)
                    Text("Partagé").tag(DeviceMode.shared)
                }
                .labelsHidden()
                .fixedSize()
                .accessibilityIdentifier("settings.deviceMode")
            }
            .id(Self.deviceModeAnchor)
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
            Button("settings.lockNow", systemImage: "lock") {
                // The discard confirmation of an edited draft belongs to the main screen.
                model.showSettings = false
                model.perform(.lock)
            }
            .accessibilityIdentifier("settings.lockNow")
        } footer: {
            if settings.deviceMode == .shared {
                SettingsFootnote(Text("settings.security.deviceMode.sharedFooter \(biometry)"))
            }
        }
    }

    private var visibleSummary: String {
        let all = session.allVaults.count
        let visible = session.allVaults.filter { !session.hiddenVaultIDs.contains($0.id) }.count
        return String(localized: "app.of \(visible) \(all)")
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
    @State private var focused = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    // No `.password` content type, emptied as it leaves the screen: iOS must never
                    // offer to save the master password.
                    SecretInputField(
                        title: String(localized: "Mot de passe maître"), text: $password, focused: $focused,
                        onSubmit: run, identifier: "settings.prompt.password")
                        .privacySensitive()
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
                    Button("app.confirm", action: run)
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

// MARK: - Protection du kit d'urgence

/// "Protection du kit d'urgence" (Guarded Kit, spec 2026-11-20, section 9). Opt-in: on, a restore
/// from the Emergency Kit also needs two of three realms run by Soma, which allow 15 attempts in
/// all. Hidden behind "Bientôt disponible" while this build pins no realm. Turning it on goes
/// through a confirmation sheet (the loss case of spec 8.4), the master password, then the offer
/// of a new kit; off and renew ask the master password. The Secret Key comes from this device.
struct KitProtectionSection: View {
    @Environment(AppModel.self) private var model

    private enum Sheet: String, Identifiable {
        case enable, disable, renew
        var id: String { rawValue }
    }

    @State private var state: FfiGuardState?
    @State private var health: FfiGuardHealth?
    @State private var sheet: Sheet?

    private var session: VaultSession { model.session }

    private var needsRenewal: Bool {
        guard let state, state.on, state.available else { return false }
        return !state.realmSetCurrent || health?.needsRenewal == true
    }

    var body: some View {
        Section {
            Toggle(isOn: Binding(
                get: { state?.on ?? false },
                set: { on in sheet = on ? .enable : .disable }
            )) {
                Label("settings.guard.title", systemImage: "lock.shield")
            }
            .disabled(state?.available != true)
            .accessibilityIdentifier("settings.guard")
            if needsRenewal {
                Button("settings.guard.renew", systemImage: "arrow.triangle.2.circlepath") { sheet = .renew }
                    .accessibilityIdentifier("settings.guard.renew")
            }
            if let health, !health.failures.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Label("settings.guard.failures", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                    ForEach(Array(VaultSession.guardFailureDates(health).enumerated()), id: \.offset) { _, date in
                        Text(verbatim: date.formatted(date: .long, time: .shortened))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("settings.guard.failures")
            }
        } footer: {
            footer
        }
        .task { await load() }
        .sheet(item: $sheet) { current in
            switch current {
            case .enable:
                GuardEnableSheet { await load() }
            case .disable:
                PasswordPromptSheet(title: "settings.guard.disable", footer: "settings.guard.disable.footer") { password in
                    try await change(.disable, password: password)
                }
            case .renew:
                PasswordPromptSheet(title: "settings.guard.renew", footer: "settings.guard.renew.footer") { password in
                    try await change(.renew, password: password)
                }
            }
        }
    }

    /// Off or renew, after the master password; the sheet shows a refusal.
    private func change(_ kind: Sheet, password: SecretBytes) async throws {
        switch kind {
        case .disable: try await session.disableGuard(password: password)
        case .renew: try await session.renewGuard(password: password)
        case .enable: return
        }
        await load()
        model.settingsChanged()
    }

    @ViewBuilder private var footer: some View {
        if let state, !state.available {
            SettingsFootnote("settings.guard.soon")
                .accessibilityIdentifier("settings.guard.soon")
        } else if needsRenewal {
            SettingsFootnote("settings.guard.renew.due")
        } else if state?.on == true {
            SettingsFootnote("settings.guard.on")
        } else {
            SettingsFootnote("settings.guard.off")
        }
    }

    /// The state from the store, then (guard on) the realms' report of failed restores. A poll
    /// that cannot reach the realms shows nothing more.
    private func load() async {
        guard let current = try? await session.guardState() else { return }
        state = current
        guard current.on, current.available else {
            health = nil
            return
        }
        health = try? await session.guardHealth()
    }
}

/// Turning the Emergency Kit protection on: what it changes and the one case where the account is
/// lost (spec 8.4), then the master password, then the offer to print a new kit (spec 8.1: the old
/// one still works, with the password and the realms).
struct GuardEnableSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// Run once the guard is on.
    let enabled: () async -> Void

    @State private var password = ""
    @State private var focused = false
    @State private var busy = false
    @State private var done = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                if done {
                    Section {
                        Label("settings.guard.enabled", systemImage: "checkmark.shield")
                    } footer: {
                        Text("settings.guard.newKit.footer")
                    }
                    Section {
                        Button("settings.guard.printKit", systemImage: "printer", action: printKit)
                            .accessibilityIdentifier("settings.guard.printKit")
                    }
                } else {
                    Section {
                        Text("settings.guard.explain")
                    }
                    Section {
                        Text("settings.guard.loss")
                    } header: {
                        Text("settings.guard.loss.header")
                    }
                    Section {
                        SecretInputField(
                            title: String(localized: "Mot de passe maître"), text: $password, focused: $focused,
                            onSubmit: run, identifier: "settings.guard.password")
                            .privacySensitive()
                    } footer: {
                        Text("settings.guard.enable.footer")
                    }
                }
                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("settings.guard.error")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("settings.guard.enable")
            #if os(iOS) || os(visionOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                if done {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("settings.guard.done") { dismiss() }
                            .accessibilityIdentifier("settings.guard.done")
                    }
                } else {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Annuler") { dismiss() }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("settings.guard.enable.confirm", action: run)
                            .disabled(password.isEmpty || busy)
                            .accessibilityIdentifier("settings.guard.confirm")
                    }
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 440, minHeight: 420)
        #endif
        .interactiveDismissDisabled(busy)
        .onDisappear { password = "" }
    }

    private func run() {
        guard !password.isEmpty, !busy else { return }
        busy = true
        errorMessage = nil
        // Emptied on submission: the password lives on in a wiped buffer only (R5).
        let value = SecretBytes(utf8: password)
        password = ""
        Task {
            defer {
                value.wipe()
                busy = false
            }
            do {
                try await model.session.enableGuard(password: value)
                done = true
                model.settingsChanged()
                await enabled()
            } catch {
                errorMessage = VaultError(error).localizedMessage
                focused = true
            }
        }
    }

    /// The new kit, built from this device's Secret Key and printed from memory (`KitPrinter`).
    private func printKit() {
        errorMessage = nil
        guard let accountID = model.settings.accountID,
            let secretKey = try? SecretKeyVault(keychain: model.session.environment.keychain).load(accountID: accountID)
        else {
            errorMessage = String(localized: "onboarding.emergencyKitCouldntPrepared")
            return
        }
        do {
            let pdf = try EmergencyKit.pdf(
                secretKey: secretKey, accountID: accountID, displayName: model.settings.displayName,
                createdAt: Date(), server: model.emergencyKitServer(), guarded: true)
            if !KitPrinter.print(pdf) {
                errorMessage = String(localized: "onboarding.noPrinterAvailableOn")
            }
        } catch {
            errorMessage = ErrorText.appending(error, to: String(localized: "onboarding.emergencyKitCouldntPrepared"))
        }
    }
}
