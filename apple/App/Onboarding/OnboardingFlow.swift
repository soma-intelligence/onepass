import DesignKit
import LocalAuthentication
import Observation
import SwiftUI
import VaultKit

enum OnboardingStep: Hashable, Sendable {
    case welcome, device, password, secretKey, biometrics, visibleVaults, restore, done
    /// "J'ai déjà OnePass sur un autre appareil": the mode, then the QR, code and password.
    case pairMode, pairing
}

enum OnboardingPath: Sendable {
    case create, restore, pair
}

/// The onboarding state machine (spec 7): create an account, or restore one with the Emergency Kit.
/// The typed fields are emptied as soon as they are submitted. When the biometric step follows, the
/// master password then stays in a wipeable buffer until the last step, as does the new Secret Key
/// (shown once and put in the Emergency Kit); both are wiped at the end or on lock.
@MainActor
@Observable
final class OnboardingModel {
    private(set) var path: OnboardingPath = .create
    private(set) var step: OnboardingStep
    /// The device lacks the Secret Key of an account already in the store: restore only.
    let restoreOnly: Bool

    var mode: DeviceMode = .personal
    var displayName = ""
    /// Typed fields and the kept secrets (`OnboardingCredentials`: emptied on submit, wiped on
    /// `clear()`).
    private var credentials = OnboardingCredentials()
    var password: String {
        get { credentials.password }
        set { credentials.password = newValue }
    }
    var confirmation: String {
        get { credentials.confirmation }
        set { credentials.confirmation = newValue }
    }
    var kitStoredOffline = false
    var allowWatch = false
    private(set) var biometricsEnabled = false

    var restoreKey: String {
        get { credentials.restoreKey }
        set { credentials.restoreKey = newValue }
    }
    var restorePassword: String {
        get { credentials.restorePassword }
        set { credentials.restorePassword = newValue }
    }

    private(set) var busyMessage: String?
    var errorMessage: String?
    /// The creation was refused because this iCloud already holds an account (R13).
    private(set) var offerRestore = false

    /// The mode asked for on "J'ai déjà OnePass sur un autre appareil" (public included).
    var pairDeviceMode: FfiDeviceMode = .personal
    /// The running pairing (new device side), from the QR step on.
    private(set) var pairing: PairingNewcomerFlow?

    @ObservationIgnored private let model: AppModel

    init(model: AppModel, restoreOnly: Bool) {
        self.model = model
        self.restoreOnly = restoreOnly
        if restoreOnly {
            path = .restore
            step = .restore
            mode = model.settings.deviceMode
        } else {
            step = .welcome
        }
        // "Restaurer avec mon Emergency Kit" from the account-missing screen.
        if !restoreOnly, model.onboardingStart == .restore {
            path = .restore
            step = .restore
        }
        model.onboardingStart = nil
        displayName = model.settings.displayName
        allowWatch = model.settings.allowWatchUnlock
        #if DEBUG
        // Screenshots: `-OnePassOnboardingStep device|password|restore` opens that step directly.
        if !restoreOnly, let start = UserDefaults.standard.string(forKey: "OnePassOnboardingStep") {
            switch start {
            case "device": step = .device
            case "password": step = .password
            case "restore": path = .restore; step = .restore
            default: break
            }
        }
        #endif
    }

    var session: VaultSession { model.session }
    var cloudKitEnabled: Bool { model.cloudKitEnabled }
    var busy: Bool { busyMessage != nil }

    // MARK: - Steps

    /// Secure Enclave present and the device is personal.
    var biometricsOffered: Bool { mode.biometricsAllowed && session.environment.biometrics.isAvailable }

    var steps: [OnboardingStep] {
        if path == .pair {
            var steps: [OnboardingStep] = [.welcome, .pairMode, .pairing]
            // A guest session opens its own screen: nothing follows.
            guard pairDeviceMode != .public else { return steps }
            if biometricsOffered { steps.append(.biometrics) }
            if mode == .shared { steps.append(.visibleVaults) }
            steps.append(.done)
            return steps
        }
        var steps: [OnboardingStep] = restoreOnly ? [] : [.welcome, .device]
        steps.append(contentsOf: path == .create ? [.password, .secretKey] : [.restore])
        if biometricsOffered { steps.append(.biometrics) }
        if mode == .shared { steps.append(.visibleVaults) }
        steps.append(.done)
        return steps
    }

    var stepIndex: Int { steps.firstIndex(of: step) ?? 0 }

    /// Back is possible until the account exists on this device.
    var canGoBack: Bool {
        guard !busy else { return false }
        switch step {
        case .device, .password, .pairMode: return true
        case .restore: return !restoreOnly
        case .pairing:
            // Until the account arrives: going back stops the pairing.
            switch pairing?.state {
            case .comparing, .waitingForApproval, .receivedFull, .importing, .done, .receivedPublic: return false
            default: return true
            }
        default: return false
        }
    }

    func back() {
        errorMessage = nil
        offerRestore = false
        let index = stepIndex
        guard canGoBack, index > 0 else { return }
        if step == .pairing { stopPairing() }
        step = steps[index - 1]
    }

    private func advance() {
        errorMessage = nil
        let all = steps
        if let index = all.firstIndex(of: step), index + 1 < all.count {
            step = all[index + 1]
        }
    }

    func choose(_ path: OnboardingPath) {
        self.path = path
        errorMessage = nil
        offerRestore = false
        step = path == .pair ? .pairMode : .device
    }

    // MARK: - Primary action

    var passwordBits: Double { PasswordStrength.estimatedBits(password) }

    /// The Secret Key in display form, decoded on each read (never stored as a `String`).
    var secretKey: String? { credentials.secretKey?.string() }

    var confirmationMismatch: Bool { !confirmation.isEmpty && confirmation != password }

    /// "Continuer" once the password reaches the master password gate (five random words pass,
    /// `PasswordStrength.masterPasswordMinimumBits`) and both fields match.
    var passwordAccepted: Bool {
        PasswordStrength.acceptsMasterPassword(password) && password == confirmation
    }

    /// Shown under "Générer" so it can be written down, decoded on each read (kept in a wipeable
    /// buffer, never as a stored `String`); cleared with the password.
    var generatedPassword: String? { generated?.string() }
    private var generated: SecretBytes?

    /// "Générer": five French words drawn at random, put in both fields.
    func generateMasterPassword() {
        guard let value = try? generatePassword(recipe: PasswordStrength.masterPasswordRecipe) else {
            return
        }
        password = value
        confirmation = value
        generated?.wipe()
        generated = SecretBytes(utf8: value)
    }

    private func clearGeneratedPassword() {
        generated?.wipe()
        generated = nil
    }

    var primaryLabel: String? {
        switch step {
        case .welcome: nil
        case .pairMode: String(localized: "Afficher le QR code")
        case .pairing:
            switch pairing?.state {
            case .receivedFull, .importing: String(localized: "Déverrouiller")
            case .failed, .cancelled: String(localized: "Recommencer")
            default: nil
            }
        case .biometrics: String(localized: "Activer \(biometryName)")
        case .restore: String(localized: "Déverrouiller")
        case .done: String(localized: "Ouvrir OnePass")
        default: String(localized: "Continuer")
        }
    }

    var primaryEnabled: Bool {
        guard !busy else { return false }
        switch step {
        case .password: return passwordAccepted
        case .secretKey: return kitStoredOffline
        case .restore: return !restoreKey.trimmingCharacters(in: .whitespaces).isEmpty && !restorePassword.isEmpty
        case .pairing:
            if pairing?.state == .receivedFull { return !restorePassword.isEmpty }
            return true
        default: return true
        }
    }

    var canSkip: Bool { step == .biometrics && !busy }

    func primary() async {
        guard primaryEnabled else { return }
        switch step {
        case .welcome: break
        case .device: advance()
        case .password: await createAccount()
        case .secretKey: advance()
        case .biometrics: await enrollBiometrics()
        case .visibleVaults: advance()
        case .restore: await restore()
        case .done: finish()
        case .pairMode:
            startPairing()
            advance()
        case .pairing:
            if pairing?.state == .receivedFull {
                await unlockPaired()
            } else {
                startPairing()
            }
        }
    }

    /// "Plus tard" on the biometric step: the first-unlock offer is not made again either.
    func skip() {
        if step == .biometrics { model.markBiometricOfferAnswered() }
        advance()
    }

    // MARK: - Actions

    private func createAccount() async {
        busyMessage = cloudKitEnabled ? String(localized: "Vérification de ton iCloud...") : String(localized: "Création du coffre...")
        defer { busyMessage = nil }
        errorMessage = nil
        offerRestore = false
        guard await model.iCloudAccountAvailable() else {
            errorMessage = String(localized: "Connecte-toi à iCloud dans Réglages pour créer ton coffre.")
            return
        }
        do {
            if try await model.remoteHasAccount() {
                errorMessage = String(localized: "Un compte OnePass existe déjà dans ton iCloud, utilise ton Emergency Kit.")
                offerRestore = true
                return
            }
        } catch RemoteStoreError.accountUnavailable {
            errorMessage = String(localized: "Connecte-toi à iCloud dans Réglages pour créer ton coffre.")
            return
        } catch {
            errorMessage = String(localized: "Impossible de vérifier ton iCloud. Vérifie ta connexion puis réessaie.")
            return
        }
        busyMessage = String(localized: "Création du coffre...")
        // Submitted: both fields are emptied now, whatever the outcome. The password lives on in a
        // buffer wiped after the call (and copied for the biometric step only); it crosses the FFI
        // as bytes.
        let typed = credentials.submitCreation()
        defer { typed.wipe() }
        clearGeneratedPassword()
        do {
            let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
            let key = try await session.createAccount(password: typed, displayName: name, mode: mode)
            // The password is kept only when the biometric step follows.
            credentials.accountCreated(secretKey: key, password: typed, keepPasswordForBiometrics: biometricsOffered)
            advance()
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }

    private func enrollBiometrics() async {
        busyMessage = String(localized: "Activation de \(biometryName)...")
        defer { busyMessage = nil }
        model.settings.allowWatchUnlock = allowWatch
        guard let typed = credentials.enrollmentPassword else {
            errorMessage = VaultError.passwordRequired.localizedMessage
            return
        }
        do {
            // Master password check, Secure Enclave key, then one Touch ID or Face ID check.
            try await model.enableBiometrics(password: typed)
            model.markBiometricOfferAnswered()
            biometricsEnabled = true
            advance()
        } catch {
            errorMessage = VaultError(error).localizedMessage
        }
    }

    private func restore() async {
        busyMessage = cloudKitEnabled ? String(localized: "Récupération de ton coffre dans iCloud...") : String(localized: "Recherche du compte...")
        defer { busyMessage = nil }
        errorMessage = nil
        guard await model.iCloudAccountAvailable() else {
            errorMessage = String(localized: "Connecte-toi à iCloud dans Réglages pour retrouver ton coffre.")
            return
        }
        do {
            let found: Bool
            if cloudKitEnabled {
                found = try await model.remoteHasAccount()
            } else {
                let path = session.environment.databaseURL.path
                found = try await CoreThread.run { try hasAccount(dbPath: path) }
            }
            guard found else {
                errorMessage = String(localized: "Aucun compte trouvé dans ton iCloud.")
                return
            }
        } catch RemoteStoreError.accountUnavailable {
            errorMessage = String(localized: "Connecte-toi à iCloud dans Réglages pour retrouver ton coffre.")
            return
        } catch {
            errorMessage = String(localized: "Impossible de joindre iCloud. Vérifie ta connexion puis réessaie.")
            return
        }
        busyMessage = String(localized: "Déverrouillage...")
        // The password field is emptied on submission, whatever the outcome. The Secret Key field
        // is kept after a failure (a typo or a wrong password), so the long key need not be typed
        // again, and emptied on success.
        let typedPassword = credentials.submitRestore()
        defer { typedPassword.wipe() }
        do {
            try await session.restore(secretKey: restoreKey, password: typedPassword)
        } catch {
            errorMessage = VaultError(error).restoreMessage
            return
        }
        credentials.restored(password: typedPassword, keepPasswordForBiometrics: biometricsOffered)
        if !restoreOnly { session.setDeviceMode(mode) }
        #if os(macOS)
        let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        if !name.isEmpty { model.settings.displayName = name }
        #endif
        advance()
    }

    // MARK: - Pairing (new device)

    /// Shows a first QR (renewed every 30 s by the flow) and waits for the approver.
    private func startPairing() {
        stopPairing()
        errorMessage = nil
        if pairDeviceMode != .public { mode = pairDeviceMode == .shared ? .shared : .personal }
        let flow = PairingNewcomerFlow(vault: session, mode: pairDeviceMode, listener: LocalNetworkPairingListener())
        pairing = flow
        flow.start()
    }

    private func stopPairing() {
        pairing?.cancel()
        pairing = nil
        restorePassword = ""
    }

    /// iOS: the app went to the background. A received account not unlocked yet is dropped (M3): the
    /// screen shows "Recommencer".
    func sceneWentToBackground() {
        guard pairing?.state == .receivedFull else { return }
        pairing?.cancel()
        restorePassword = ""
    }

    /// The approver granted the account: imports it with the master password. A wrong password keeps
    /// the grant for another try (ruling A9).
    private func unlockPaired() async {
        guard let pairing else { return }
        busyMessage = String(localized: "Déverrouillage...")
        defer { busyMessage = nil }
        errorMessage = nil
        // Emptied on submission, whatever the outcome; crosses the FFI as bytes.
        let typed = credentials.submitRestore()
        defer { typed.wipe() }
        await pairing.importAndUnlock(password: typed)
        guard pairing.state == .done else {
            errorMessage = pairing.importError.map { $0.restoreMessage } ?? VaultError.wrongPassword.localizedMessage
            return
        }
        // The mode comes from the grant.
        mode = model.settings.deviceMode
        credentials.restored(password: typed, keepPasswordForBiometrics: biometricsOffered)
        advance()
    }

    /// A public grant arrived: the guest session takes the whole window (nothing on disk).
    func pairingStateChanged(_ state: PairingNewcomerFlow.State) {
        if case .receivedPublic(let guest) = state {
            pairing = nil
            model.publicSession = guest
        }
    }

    /// "Créer un nouveau coffre" on the Emergency Kit screen of a device without the Secret Key,
    /// confirmed by typing EFFACER: the unreadable local copy is cleared, the onboarding starts over.
    func startOver() async throws {
        try await model.startOver()
    }

    func newVaultOffer() async -> NewVaultOffer { await model.newVaultOffer() }

    func switchToRestore() {
        offerRestore = false
        errorMessage = nil
        path = .restore
        step = .restore
    }

    /// The session locked (auto-lock, background, "Verrouiller") after the account was created or
    /// restored: the Secret Key and the master password leave memory, the Emergency Kit file is
    /// deleted and the lock screen replaces the onboarding. The Secret Key stays in the keychain.
    func sessionLocked() {
        stopPairing()
        deleteKit()
        credentials.clear()
        clearGeneratedPassword()
        errorMessage = nil
        model.onboardingInProgress = false
    }

    private func finish() {
        pairing = nil
        credentials.clear()
        clearGeneratedPassword()
        model.onboardingInProgress = false
    }

    // MARK: - Emergency Kit

    /// The PDF bytes, built when the step appears and printed from memory (spec 4). A file is
    /// written only when the user goes past the save warning: on iOS and visionOS a temporary
    /// copy for the share sheet (`EmergencyKitFile`: excluded from backups, complete protection),
    /// on Mac the destination chosen in the save panel. `deleteKit()` drops both.
    private(set) var kitData: Data?
    private(set) var kitURL: URL?

    func prepareKit() {
        guard kitData == nil, let secretKey, let accountID = model.settings.accountID else { return }
        do {
            kitData = try EmergencyKit.pdf(
                secretKey: secretKey, accountID: accountID,
                displayName: model.settings.displayName, createdAt: Date())
        } catch {
            errorMessage = String(localized: "L'Emergency Kit n'a pas pu être préparé.")
        }
    }

    /// "Imprimer le kit": the system print panel, from memory.
    func printKit() {
        prepareKit()
        guard let kitData else { return }
        if !KitPrinter.print(kitData) {
            errorMessage = String(localized: "Aucune imprimante n'est disponible sur cet appareil.")
        }
    }

    /// The temporary kit file for the share sheet, written on first use.
    func kitFileForSharing() -> URL? {
        if let kitURL { return kitURL }
        prepareKit()
        guard let kitData else { return nil }
        do {
            kitURL = try EmergencyKitFile.write(kitData, under: FileManager.default.temporaryDirectory)
        } catch {
            errorMessage = String(localized: "L'Emergency Kit n'a pas pu être préparé.")
        }
        return kitURL
    }

    /// The share sheet closed: the temporary copy goes away (the PDF stays in memory for printing).
    func sharingFinished() {
        if let kitURL { EmergencyKitFile.remove(kitURL, under: FileManager.default.temporaryDirectory) }
        kitURL = nil
    }

    /// Mac: writes the kit to the destination the user chose in the save panel.
    func saveKit(to url: URL) {
        prepareKit()
        guard let kitData else { return }
        do {
            try kitData.write(to: url, options: .atomic)
        } catch {
            errorMessage = String(localized: "L'Emergency Kit n'a pas pu être enregistré.")
        }
    }

    /// Drops the temporary file and wipes the PDF bytes (they hold the Secret Key in clear).
    func deleteKit() {
        sharingFinished()
        guard var bytes = kitData else { return }
        kitData = nil
        // Our copy is now the only reference, so the wipe happens in place.
        bytes.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            _ = memset_s(base, buffer.count, 0, buffer.count)
        }
    }

    // MARK: - Texts

    var biometryName: String { Self.biometryName }

    static let biometryName: String = {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default:
            #if os(macOS)
            return "Touch ID"
            #elseif os(visionOS)
            return "Optic ID"
            #else
            return "Face ID"
            #endif
        }
    }()

    /// SF Symbol of the biometry named by `biometryName`.
    static var biometrySymbol: String {
        switch biometryName {
        case "Touch ID": "touchid"
        case "Optic ID": "opticid"
        default: "faceid"
        }
    }

    static func railLabel(_ step: OnboardingStep) -> String {
        switch step {
        case .welcome: String(localized: "Bienvenue")
        case .device: String(localized: "Type d'appareil")
        case .password: String(localized: "Mot de passe maître")
        case .secretKey: "Secret Key"
        case .biometrics: biometryName
        case .visibleVaults: String(localized: "Coffres visibles")
        case .restore: "Emergency Kit"
        case .done: String(localized: "Terminé")
        case .pairMode: String(localized: "Type d'appareil")
        case .pairing: String(localized: "QR code")
        }
    }
}

/// Full-window onboarding: pages with progress dots on iPhone and iPad, a step rail in a native
/// sidebar on Mac (mockups `PhoneOnboarding` and `Onboarding`).
struct OnboardingFlow: View {
    @Environment(AppModel.self) private var app
    @Environment(\.scenePhase) private var scenePhase
    @State private var model: OnboardingModel?

    var body: some View {
        Group {
            if let model {
                #if os(macOS)
                MacOnboardingLayout(model: model)
                #elseif os(visionOS)
                // A floating glass card in the window.
                PhoneOnboardingLayout(model: model)
                    .padding(.vertical, 20)
                    .frame(maxWidth: 640)
                    .glassBackgroundEffect()
                    .padding(32)
                #else
                PhoneOnboardingLayout(model: model)
                #endif
            } else {
                // An empty Group never appears: keep a view so onAppear runs.
                Color.clear
            }
        }
        .onAppear {
            app.onboardingInProgress = true
            // Restore only when the store holds an account whose Secret Key this device lacks,
            // whatever the reason the onboarding is on screen.
            let restoreOnly = app.session.needsSecretKey && app.session.state != .noAccount
            if model == nil { model = OnboardingModel(model: app, restoreOnly: restoreOnly) }
        }
        .onChange(of: app.session.needsSecretKey) { _, needed in
            // "Créer un nouveau coffre": the restore-only flow gives way to the full onboarding.
            if !needed, app.session.state == .noAccount, model?.restoreOnly == true {
                model = OnboardingModel(model: app, restoreOnly: false)
            }
        }
        .onChange(of: app.session.state) { old, new in
            // A lock after the creation or restore unlocked the session (spec 4 point 5).
            if old == .unlocked, new != .unlocked, new != .unlocking { model?.sessionLocked() }
        }
        #if os(iOS)
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { model?.sceneWentToBackground() }
        }
        #endif
    }
}

// MARK: - iPhone and iPad

#if os(iOS) || os(visionOS)
private struct PhoneOnboardingLayout: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        VStack(spacing: 0) {
            topBar
                .padding(.horizontal, 16)
                .frame(height: 44)
            ScrollView {
                OnboardingStepContent(model: model)
                    .frame(maxWidth: 520, alignment: .leading)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 10)
                    .frame(maxWidth: .infinity)
            }
            #if os(iOS)
            .scrollDismissesKeyboard(.interactively)
            #endif
            bottomBar
                .frame(maxWidth: 520)
                .padding(.horizontal, 24)
                .padding(.bottom, 12)
        }
        .animation(.smooth(duration: 0.25), value: model.step)
    }

    private var topBar: some View {
        HStack {
            if model.canGoBack {
                Button {
                    model.back()
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.body.weight(.semibold))
                        .frame(width: 28, height: 28)
                }
                .buttonStyle(.glass)
                .buttonBorderShape(.circle)
                .accessibilityLabel(Text("Retour"))
                .accessibilityIdentifier("onboarding.back")
            } else {
                Color.clear.frame(width: 40, height: 40)
            }
            Spacer()
            ProgressDots(count: model.steps.count, current: model.stepIndex)
            Spacer()
            Color.clear.frame(width: 40, height: 40)
        }
    }

    @ViewBuilder private var bottomBar: some View {
        VStack(spacing: 10) {
            if let label = model.primaryLabel {
                Button {
                    Task { await model.primary() }
                } label: {
                    Group {
                        if model.busy {
                            ProgressView()
                        } else {
                            Text(label)
                        }
                    }
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .frame(height: 40)
                }
                .buttonStyle(.glassProminent)
                .buttonBorderShape(.capsule)
                .disabled(!model.primaryEnabled)
                .accessibilityIdentifier("onboarding.primary")
            }
            if model.canSkip {
                Button("Plus tard") { model.skip() }
                    .font(.body)
                    .frame(height: 40)
                    .accessibilityIdentifier("onboarding.skip")
            }
        }
    }
}

private struct ProgressDots: View {
    let count: Int
    let current: Int

    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<count, id: \.self) { index in
                Capsule()
                    .fill(index <= current ? Theme.accent : Color.secondary.opacity(0.25))
                    .frame(width: index == current ? 22 : 8, height: 8)
            }
        }
        .animation(.smooth, value: current)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Progression"))
        .accessibilityValue(Text("Étape \(current + 1) sur \(count)"))
    }
}
#endif

// MARK: - Mac

#if os(macOS)
private struct MacOnboardingLayout: View {
    @Bindable var model: OnboardingModel

    var body: some View {
        NavigationSplitView {
            StepRail(model: model)
                .frame(minWidth: 250)
                .navigationSplitViewColumnWidth(min: 280, ideal: 280, max: 280)
                .toolbar(removing: .sidebarToggle)
        } detail: {
            VStack(spacing: 0) {
                ScrollView {
                    OnboardingStepContent(model: model)
                        .frame(maxWidth: 560, alignment: .leading)
                        .padding(.horizontal, 56)
                        .padding(.top, 64)
                        .padding(.bottom, 24)
                        .frame(maxWidth: .infinity)
                }
                Divider()
                bottomBar
                    .padding(.horizontal, 32)
                    .frame(height: 68)
            }
            .animation(.smooth(duration: 0.25), value: model.step)
            .toolbar(removing: .title)
        }
        .navigationSplitViewStyle(.balanced)
    }

    private var bottomBar: some View {
        HStack(spacing: 10) {
            if model.canGoBack {
                Button("Retour") { model.back() }
                    .controlSize(.large)
                    .accessibilityIdentifier("onboarding.back")
            }
            Spacer()
            if model.step != .welcome, model.step != .done {
                if model.busy { ProgressView().controlSize(.small) }
                if model.canSkip {
                    Button("Plus tard") { model.skip() }
                        .controlSize(.large)
                        .accessibilityIdentifier("onboarding.skip")
                }
                if let label = model.primaryLabel {
                    Button(label) { Task { await model.primary() } }
                        .buttonStyle(.glassProminent)
                        .controlSize(.large)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!model.primaryEnabled)
                        .accessibilityIdentifier("onboarding.primary")
                }
            }
        }
    }
}

/// Step list of the mockup's left rail: number disc, check once done, current step in bold.
/// Plain colours, not the sidebar's vibrant styles: those also draw in the app's own window
/// renders (`Snapshot`), where dark vibrancy comes out black.
private struct StepRail: View {
    let model: OnboardingModel
    @Environment(\.colorScheme) private var scheme

    private var label: Color { scheme == .dark ? Color.white.opacity(0.85) : Color.black.opacity(0.85) }
    private var secondaryLabel: Color { scheme == .dark ? Color.white.opacity(0.55) : Color.black.opacity(0.5) }
    private var currentRow: Color { scheme == .dark ? Color.white.opacity(0.1) : Color.white }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                AppGlyph(size: 34).accessibilityHidden(true)
                Text("OnePass").font(.title3.bold()).foregroundStyle(label)
            }
            .padding(.horizontal, 6)
            .padding(.bottom, 22)

            let steps = model.steps
            let current = model.stepIndex
            ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                HStack(spacing: 12) {
                    ZStack {
                        if index <= current {
                            Circle().fill(Theme.accent)
                        } else {
                            Circle().strokeBorder(secondaryLabel.opacity(0.7), lineWidth: 1.5)
                        }
                        if index < current {
                            Image(systemName: "checkmark")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundStyle(.white)
                        } else {
                            Text("\(index + 1)")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundStyle(index == current ? Color.white : secondaryLabel)
                        }
                    }
                    .frame(width: 22, height: 22)
                    Text(OnboardingModel.railLabel(step))
                        .font(.system(size: 13.5, weight: index == current ? .bold : .medium))
                        .foregroundStyle(index > current ? secondaryLabel : label)
                        .lineLimit(1)
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 8)
                .frame(height: 36)
                .background {
                    if index == current {
                        RoundedRectangle(cornerRadius: 8, style: .continuous).fill(currentRow)
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(index == current ? .isSelected : [])
            }
            Spacer()
        }
        .padding(.horizontal, 10)
        .padding(.top, 8)
        .frame(maxHeight: .infinity, alignment: .top)
    }
}
#endif
