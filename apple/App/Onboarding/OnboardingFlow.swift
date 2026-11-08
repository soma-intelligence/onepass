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

/// The next step offered under an inline error: never only a message.
enum OnboardingErrorAction: Sendable {
    /// Runs the primary action again.
    case retry
    /// The system settings (iCloud sign-in, keychain).
    case openSettings
    /// "J'ai mon Emergency Kit": this iCloud already holds an account.
    case restore

    var label: String {
        switch self {
        case .retry: String(localized: "Réessayer")
        case .openSettings: String(localized: "onboarding.openSettings")
        case .restore: String(localized: "J'ai mon Emergency Kit")
        }
    }
}

/// One rule of the master password, shown as a checkmark that turns green once met.
struct PasswordRule: Identifiable, Sendable {
    let id: String
    let label: String
    let met: Bool
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
    /// Signing in to an added account whose iCloud zone is ambiguous: the account id printed on the
    /// Emergency Kit is asked (multi-account ruling P8).
    var needsAccountID: Bool { model.signInNeedsAccountID }
    var restoreAccountID: String {
        get { model.signInAccountID ?? "" }
        set { model.signInAccountID = newValue.isEmpty ? nil : newValue }
    }
    /// A scanned kit: its Secret Key, and the account id of a version 2 kit while adding an account.
    func acceptScannedKit(_ text: String) -> String? {
        guard let scan = EmergencyKit.parseKit(text) else { return nil }
        if model.addingAccount?.signIn == true, let id = scan.accountID { model.signInAccountID = id }
        restoreServer = scan.server
        return scan.secretKey
    }

    private(set) var busyMessage: String?
    var errorMessage: String? {
        didSet {
            if errorMessage == nil {
                errorAction = nil
            } else if errorMessage != oldValue {
                errorPulse &+= 1
            }
        }
    }
    /// The next step offered with `errorMessage` (set after it).
    private(set) var errorAction: OnboardingErrorAction?
    /// The creation was refused because this iCloud already holds an account (R13).
    private(set) var offerRestore = false

    /// Haptic and motion triggers for the layouts: a new error, a success worth feeling (account
    /// created, biometrics on, the end), and the direction of the last step change.
    private(set) var errorPulse = 0
    private(set) var successPulse = 0
    private(set) var movingForward = true

    /// The mode asked for on "J'ai déjà OnePass sur un autre appareil" (public included).
    var pairDeviceMode: FfiDeviceMode = .personal
    /// How this device meets the other one: it scans the code the other device shows, types it, or
    /// shows its own QR code for an iPhone or an iPad to scan.
    var pairMethod: PairMethod = PairMethod.preferred
    /// The code typed on the "Saisir le code" step (`XXXX-XXXX`, forgiving).
    var joinCode = ""
    /// The running pairing (new device side), from the QR step on.
    private(set) var pairing: PairingNewcomerFlow?

    /// How the new device meets the unlocked one (the first choice of the pairing steps).
    enum PairMethod: Equatable {
        /// Scan the QR code the other device shows (iPhone, iPad).
        case scan
        /// Type the code the other device shows.
        case type
        /// Show a QR code for the other device to scan (the first direction).
        case showCode

        @MainActor static var preferred: PairMethod { scanAvailable ? .scan : .type }

        /// A camera that reads QR codes (not on the Simulator, not on the Mac).
        @MainActor static var scanAvailable: Bool {
            #if os(iOS)
            SecretKeyScanner.isSupported
            #else
            false
            #endif
        }
    }

    /// The method actually used: a guest session has no code to scan or type.
    var effectivePairMethod: PairMethod { pairDeviceMode == .public ? .showCode : pairMethod }

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
    /// Where the new vault syncs (spec D.2): the OnePass server unless chosen otherwise. iCloud
    /// while mailbox signup is off in this build.
    var syncChoice: SyncChoice = .default
    var showSyncChoice = false
    var effectiveSyncChoice: SyncChoice { model.mailboxSignupEnabled ? syncChoice : .iCloud }
    var mailboxSignupEnabled: Bool { model.mailboxSignupEnabled }
    /// The server line of a self-host kit (scanned), or typed in "Mon serveur".
    var restoreServer: URL?
    var cloudKitEnabled: Bool { model.cloudKitEnabled }
    var busy: Bool { busyMessage != nil }

    // MARK: - Steps

    /// Secure Enclave present and the device is personal.
    var biometricsOffered: Bool { mode.biometricsAllowed && session.environment.biometrics.isAvailable }

    var steps: [OnboardingStep] {
        if path == .pair {
            // From the Emergency Kit screen of an account the sync brought: back leads there.
            var steps: [OnboardingStep] = [restoreOnly ? .restore : .welcome, .pairMode, .pairing]
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
        movingForward = false
        if restoreOnly, step == .pairMode {
            path = .restore
            step = .restore
            return
        }
        step = steps[index - 1]
    }

    private func advance() {
        errorMessage = nil
        let all = steps
        if let index = all.firstIndex(of: step), index + 1 < all.count {
            movingForward = true
            step = all[index + 1]
        }
    }

    func choose(_ path: OnboardingPath) {
        self.path = path
        errorMessage = nil
        offerRestore = false
        movingForward = true
        step = path == .pair ? .pairMode : .device
    }

    // MARK: - Primary action

    var passwordBits: Double { PasswordStrength.estimatedBits(password) }

    /// The Secret Key in display form, decoded on each read (never stored as a `String`).
    var secretKey: String? { credentials.secretKey?.string() }

    var confirmationMismatch: Bool { !confirmation.isEmpty && confirmation != password }
    var confirmationMatches: Bool { !confirmation.isEmpty && confirmation == password }

    /// At least this many characters, on top of the strength gate.
    static let masterPasswordMinimumLength = 12

    /// The rules shown under the fields, in order; all must be met.
    var passwordRules: [PasswordRule] {
        [
            PasswordRule(
                id: "length",
                label: String(localized: "onboarding.atLeastCharacters \(Self.masterPasswordMinimumLength)"),
                met: password.count >= Self.masterPasswordMinimumLength),
            PasswordRule(
                id: "strength",
                label: String(localized: "onboarding.strongEnoughForVault"),
                met: PasswordStrength.acceptsMasterPassword(password)),
            PasswordRule(
                id: "match",
                label: String(localized: "onboarding.confirmedBothMatch"),
                met: confirmationMatches),
        ]
    }

    /// "Continuer" once every rule holds: the length, the master password gate (five random words
    /// pass, `PasswordStrength.masterPasswordMinimumBits`) and both fields matching.
    var passwordAccepted: Bool { passwordRules.allSatisfy(\.met) }

    /// Why the primary button is off, said next to it.
    var primaryHint: String? {
        guard !busy, !primaryEnabled, primaryLabel != nil else { return nil }
        switch step {
        case .password:
            if password.isEmpty { return String(localized: "onboarding.choosePasswordOrTap") }
            let missing = Self.masterPasswordMinimumLength - password.count
            if missing > 0 {
                return missing == 1 ? String(localized: "onboarding.n1MoreCharacter") : String(localized: "onboarding.moreCharacters \(missing)")
            }
            if !PasswordStrength.acceptsMasterPassword(password) {
                return String(localized: "onboarding.notStrongEnoughYet")
            }
            if confirmation.isEmpty { return String(localized: "onboarding.confirmPassword") }
            return String(localized: "onboarding.bothEntriesMustMatch")
        case .secretKey:
            return String(localized: "onboarding.checkBoxOnceSecret")
        case .restore:
            if restoreKey.trimmingCharacters(in: .whitespaces).isEmpty {
                return String(localized: "onboarding.enterSecretKeyFrom")
            }
            return String(localized: "onboarding.enterMasterPassword")
        case .pairing:
            if pairing == nil, effectivePairMethod == .type {
                return String(localized: "onboarding.enterCodeShownOn")
            }
            return String(localized: "onboarding.enterMasterPassword")
        default:
            return nil
        }
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
        case .pairMode:
            switch effectivePairMethod {
            case .scan: String(localized: "onboarding.scanQrCode")
            case .type: String(localized: "onboarding.typeCode")
            case .showCode: String(localized: "onboarding.showQrCode")
            }
        case .pairing:
            switch pairing?.state {
            case .receivedFull, .importing: String(localized: "common.unlock")
            case .failed, .cancelled: String(localized: "onboarding.startOver")
            case nil where effectivePairMethod == .type: String(localized: "onboarding.join")
            default: nil
            }
        case .biometrics: String(localized: "Activer \(biometryName)")
        case .restore: String(localized: "common.unlock")
        case .done: String(localized: "app.openOnepass")
        default: String(localized: "common.continue")
        }
    }

    var primaryEnabled: Bool {
        guard !busy else { return false }
        switch step {
        case .password: return passwordAccepted
        case .secretKey: return kitStoredOffline
        // Enabled: the success shows for a moment before the next step.
        case .biometrics: return !biometricsEnabled
        case .restore: return !restoreKey.trimmingCharacters(in: .whitespaces).isEmpty && !restorePassword.isEmpty
        case .pairing:
            if pairing?.state == .receivedFull { return !restorePassword.isEmpty }
            if pairing == nil, effectivePairMethod == .type { return joinCodeValid }
            return true
        default: return true
        }
    }

    /// The typed code reads as a pairing code (8 characters of the alphabet).
    var joinCodeValid: Bool { (try? pairingRendezvousServiceName(code: joinCode)) != nil }

    var canSkip: Bool { step == .biometrics && !busy && !biometricsEnabled }

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
            if effectivePairMethod == .showCode { startPairing() }
            advance()
        case .pairing:
            if pairing?.state == .receivedFull {
                await unlockPaired()
            } else if effectivePairMethod == .showCode {
                startPairing()
            } else if pairing == nil {
                joinPairing(code: joinCode)
            } else {
                // Failed or cancelled: back to the code entry.
                stopPairing()
                errorMessage = nil
            }
        }
    }

    /// "Plus tard" on the biometric step: the first-unlock offer is not made again either.
    func skip() {
        if step == .biometrics { model.markBiometricOfferAnswered() }
        advance()
    }

    /// The button under an inline error.
    func performErrorAction() async {
        guard let action = errorAction else { return }
        switch action {
        case .retry:
            errorMessage = nil
            await primary()
        case .openSettings:
            #if os(iOS)
            if let url = URL(string: UIApplication.openSettingsURLString) {
                await UIApplication.shared.open(url)
            }
            #elseif os(macOS)
            if let url = URL(string: "x-apple.systempreferences:com.apple.systempreferences.AppleIDSettings") {
                NSWorkspace.shared.open(url)
            }
            #endif
        case .restore:
            switchToRestore()
        }
    }

    private func fail(_ message: String, next action: OnboardingErrorAction?) {
        errorMessage = message
        errorAction = action
    }

    // MARK: - Actions

    private func createAccount() async {
        let choice = effectiveSyncChoice
        let onICloud = choice == .iCloud
        busyMessage = cloudKitEnabled && onICloud ? String(localized: "onboarding.checkingIcloud") : String(localized: "onboarding.creatingVault")
        defer { busyMessage = nil }
        errorMessage = nil
        offerRestore = false
        if onICloud {
            guard await checkICloudBeforeCreation() else { return }
        } else {
            // The new vault must never reach iCloud: the iCloud sync stops before it exists.
            await model.prepareSync(for: choice)
        }
        busyMessage = String(localized: "onboarding.creatingVault")
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
            if !onICloud, let bytes = credentials.secretKey {
                // In the background: the account is usable at once, on this device (spec D.2, 3).
                let copy = bytes.withData { SecretBytes(copying: $0) }
                Task { await model.runMailboxSetup(secretKey: copy) }
            }
            successPulse &+= 1
            advance()
        } catch {
            // The fields were emptied on submission: the next step is typing the password again
            // (said in the message). A keychain refusal also offers the settings.
            fail(
                VaultError(error).localizedMessage + " " + String(localized: "onboarding.enterPasswordAgainTo"),
                next: error is KeychainError ? .openSettings : nil)
        }
    }

    /// iCloud signed in and holding no OnePass account yet; false after saying what to do.
    private func checkICloudBeforeCreation() async -> Bool {
        guard await model.iCloudAccountAvailable() else {
            fail(String(localized: "onboarding.signInToIcloud"), next: .openSettings)
            return false
        }
        do {
            if try await model.remoteHasAccount() {
                fail(String(localized: "onboarding.onepassAccountAlreadyExists"), next: .restore)
                offerRestore = true
                return false
            }
        } catch RemoteStoreError.accountUnavailable {
            fail(String(localized: "onboarding.signInToIcloud"), next: .openSettings)
            return false
        } catch {
            fail(String(localized: "onboarding.cantCheckIcloudCheck"), next: .retry)
            return false
        }
        return true
    }

    private func enrollBiometrics() async {
        busyMessage = String(localized: "onboarding.turningOn \(biometryName)")
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
            successPulse &+= 1
            busyMessage = nil
            // The success shows on this step for a moment, then the next one comes in.
            try? await Task.sleep(for: .milliseconds(1100))
            guard step == .biometrics else { return }
            advance()
        } catch {
            fail(VaultError(error).localizedMessage, next: .retry)
        }
    }

    private func restore() async {
        busyMessage = cloudKitEnabled ? String(localized: "onboarding.gettingVaultFromIcloud") : String(localized: "onboarding.lookingForAccount")
        defer { busyMessage = nil }
        errorMessage = nil
        if mailboxSignupEnabled || restoreServer != nil,
           let normalized = try? normalizeSecretKey(text: restoreKey) {
            busyMessage = String(localized: "onboarding.lookingForAccount")
            let key = SecretBytes(utf8: normalized)
            defer { key.wipe() }
            switch await model.locateAccount(secretKey: key, kitServer: restoreServer) {
            case .mailbox(let home):
                await restoreFromMailbox(home: home, secretKey: key)
                return
            case .iCloud:
                break
            case .notFound:
                fail(String(localized: "onboarding.restore.notFound"), next: nil)
                return
            case .offline:
                fail(String(localized: "onboarding.restore.offline"), next: .retry)
                return
            }
        }
        guard await model.iCloudAccountAvailable() else {
            fail(String(localized: "onboarding.signInToIcloud2"), next: .openSettings)
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
                fail(String(localized: "onboarding.noAccountFoundIn"), next: .openSettings)
                return
            }
        } catch RemoteStoreError.accountUnavailable {
            fail(String(localized: "onboarding.signInToIcloud2"), next: .openSettings)
            return
        } catch let error as AccountsError {
            fail(error.message, next: .retry)
            return
        } catch {
            fail(String(localized: "onboarding.cantReachIcloudCheck"), next: .retry)
            return
        }
        busyMessage = String(localized: "onboarding.unlocking")
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
        if !name.isEmpty { session.setProfile(name: name, photo: model.settings.profilePhoto) }
        #endif
        advance()
    }

    /// The account is on a mailbox: fetched with the recovery credential, unlocked with the
    /// password, then this device gets its own credential (spec D.4).
    private func restoreFromMailbox(home: MailboxHome, secretKey: SecretBytes) async {
        busyMessage = String(localized: "onboarding.unlocking")
        let typedPassword = credentials.submitRestore()
        defer { typedPassword.wipe() }
        let key = restoreKey
        do {
            try await model.restoreFromMailbox(home: home, secretKey: secretKey) { [session] in
                try await session.restore(secretKey: key, password: typedPassword)
            }
        } catch {
            errorMessage = VaultError(error).restoreMessage
            return
        }
        credentials.restored(password: typedPassword, keepPasswordForBiometrics: biometricsOffered)
        if !restoreOnly { session.setDeviceMode(mode) }
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

    /// iPhone and iPad: the code scanned on the other device's screen (a Mac shows an invite, it never
    /// scans): joins it in place of the QR this device showed.
    func joinInvite(_ text: String) {
        stopPairing()
        errorMessage = nil
        if pairDeviceMode != .public { mode = pairDeviceMode == .shared ? .shared : .personal }
        let flow = PairingNewcomerFlow(
            vault: session, mode: pairDeviceMode, invite: text, connector: LocalNetworkPairingConnector())
        pairing = flow
        flow.start()
    }

    /// Meets the unlocked device that shows a code: `code` is the scanned QR text or the typed code.
    /// The flow connects to the service the code names; the code comparison follows.
    func joinPairing(code: String) {
        stopPairing()
        errorMessage = nil
        if pairDeviceMode != .public { mode = pairDeviceMode == .shared ? .shared : .personal }
        let flow = PairingNewcomerFlow(vault: session, mode: pairDeviceMode, listener: LocalNetworkPairingListener())
        pairing = flow
        flow.join(code: code, connector: LocalNetworkPairingConnector())
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
        busyMessage = String(localized: "onboarding.unlocking")
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
            var server: URL?
            if case .selfHost(let url, _) = effectiveSyncChoice { server = url }
            kitData = try EmergencyKit.pdf(
                secretKey: secretKey, accountID: accountID,
                displayName: model.settings.displayName, createdAt: Date(), server: server)
        } catch {
            errorMessage = ErrorText.appending(error, to: String(localized: "onboarding.emergencyKitCouldntPrepared"))
        }
    }

    /// "Imprimer le kit": the system print panel, from memory.
    func printKit() {
        prepareKit()
        guard let kitData else { return }
        if !KitPrinter.print(kitData) {
            errorMessage = String(localized: "onboarding.noPrinterAvailableOn")
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
            errorMessage = ErrorText.appending(error, to: String(localized: "onboarding.emergencyKitCouldntPrepared"))
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
            errorMessage = ErrorText.appending(error, to: String(localized: "onboarding.emergencyKitCouldntSaved"))
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
        case .welcome: String(localized: "onboarding.welcome")
        case .device: String(localized: "onboarding.deviceType")
        case .password: String(localized: "Mot de passe maître")
        case .secretKey: "Secret Key"
        case .biometrics: biometryName
        case .visibleVaults: String(localized: "Coffres visibles")
        case .restore: "Emergency Kit"
        case .done: String(localized: "common.done")
        case .pairMode: String(localized: "onboarding.deviceType")
        case .pairing: String(localized: "onboarding.pairing")
        }
    }
}

/// Full-window onboarding: one step per screen with a thin progress line on iPhone and iPad, a
/// step rail in a native sidebar on Mac (mockups `PhoneOnboarding` and `Onboarding`).
struct OnboardingFlow: View {
    @Environment(AppModel.self) private var app
    @Environment(\.scenePhase) private var scenePhase
    @State private var model: OnboardingModel?
    /// The three cards before the welcome screen, on a first launch only.
    @State private var showIntro = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if let model {
                #if os(macOS)
                if showIntro {
                    OnboardingIntro(finish: finishIntro).transition(.opacity)
                } else {
                    MacOnboardingLayout(model: model).transition(.opacity)
                }
                #elseif os(visionOS)
                // A floating glass card in the window.
                Group {
                    if showIntro {
                        OnboardingIntro(finish: finishIntro).transition(.opacity)
                    } else {
                        PhoneOnboardingLayout(model: model).transition(.opacity)
                    }
                }
                .padding(.vertical, 20)
                .frame(maxWidth: 640)
                .glassBackgroundEffect()
                .padding(32)
                #else
                if showIntro {
                    OnboardingIntro(finish: finishIntro).transition(.opacity)
                } else {
                    PhoneOnboardingLayout(model: model).transition(.opacity)
                }
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
            if model == nil {
                // Before the model: its init consumes `onboardingStart`.
                showIntro = OnboardingIntro.shouldShow(for: app, restoreOnly: restoreOnly)
                model = OnboardingModel(model: app, restoreOnly: restoreOnly)
            }
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

    private func finishIntro() {
        OnboardingIntro.markSeen()
        withAnimation(reduceMotion ? .easeOut(duration: 0.2) : .smooth(duration: 0.35)) { showIntro = false }
    }
}

// MARK: - iPhone and iPad

#if os(iOS) || os(visionOS)
/// One step at a time, pushed in from the trailing edge (from the leading edge when going back)
/// on a critically damped spring, a fade with Reduce Motion. A thin progress line under the back
/// button, one primary action pinned at the bottom above the keyboard, and the reason it is off
/// said right above it.
private struct PhoneOnboardingLayout: View {
    @Bindable var model: OnboardingModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(spacing: 0) {
            topBar
                .padding(.horizontal, 16)
                .frame(height: 52)
            ZStack {
                ScrollView {
                    OnboardingStepContent(model: model)
                        .frame(maxWidth: 520, alignment: .leading)
                        .padding(.horizontal, 24)
                        .padding(.top, 20)
                        .padding(.bottom, 32)
                        .frame(maxWidth: .infinity)
                }
                #if os(iOS)
                .scrollDismissesKeyboard(.interactively)
                #endif
                .scrollBounceBehavior(.basedOnSize)
                .id(model.step)
                .transition(stepTransition)
            }
            // Content scrolled under the bottom bar stays out of it (the reason text sits there).
            .clipped()
            bottomBar
                .frame(maxWidth: 520)
                .padding(.horizontal, 24)
                .padding(.top, 8)
                .padding(.bottom, 12)
        }
        .animation(stepAnimation, value: model.step)
        #if os(iOS)
        .sensoryFeedback(.impact(weight: .light), trigger: model.step)
        .sensoryFeedback(.selection, trigger: model.mode)
        .sensoryFeedback(.success, trigger: model.successPulse)
        .sensoryFeedback(.error, trigger: model.errorPulse)
        .sensoryFeedback(trigger: model.kitStoredOffline) { _, stored in stored ? .success : .selection }
        #endif
    }

    private var stepTransition: AnyTransition {
        guard !reduceMotion else { return .opacity }
        let forward = model.movingForward
        return .asymmetric(
            insertion: .move(edge: forward ? .trailing : .leading).combined(with: .opacity),
            removal: .move(edge: forward ? .leading : .trailing).combined(with: .opacity))
    }

    private var stepAnimation: Animation {
        reduceMotion ? .easeOut(duration: 0.2) : .spring(duration: 0.5, bounce: 0)
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
                .accessibilityLabel(Text("common.back"))
                .accessibilityIdentifier("onboarding.back")
                .transition(.opacity)
            }
            Spacer()
        }
        .frame(height: 44)
        // Centered between the edges, clear of the back button.
        .overlay { OnboardingProgressLine(model: model) }
        .animation(.smooth(duration: 0.25), value: model.canGoBack)
    }

    @ViewBuilder private var bottomBar: some View {
        VStack(spacing: 12) {
            if let hint = model.primaryHint {
                Text(hint)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .transition(.opacity)
                    .id(hint)
                    .accessibilityIdentifier("onboarding.hint")
            }
            if let label = model.primaryLabel {
                Button {
                    Task { await model.primary() }
                } label: {
                    HStack(spacing: 10) {
                        if model.busy {
                            ProgressView().tint(.white)
                            Text(model.busyMessage ?? label)
                        } else {
                            Text(label)
                        }
                    }
                    .font(.headline)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .frame(maxWidth: .infinity)
                    .frame(height: 52)
                    // The busy label replaces the title at once (a crossfade mixed both words).
                    .transaction { $0.animation = nil }
                }
                .buttonStyle(.glassProminent)
                .buttonBorderShape(.capsule)
                // Busy keeps the prominent look (the spinner speaks), only taps are off.
                .disabled(!model.primaryEnabled && !model.busy)
                .allowsHitTesting(!model.busy)
                .accessibilityIdentifier("onboarding.primary")
            }
            if model.canSkip {
                Button("app.later") { model.skip() }
                    .font(.body.weight(.medium))
                    .frame(height: 40)
                    .accessibilityIdentifier("onboarding.skip")
            }
        }
        .animation(.smooth(duration: 0.25), value: model.primaryHint)
    }
}

/// Progress, quietly: a hairline under the navigation that fills as the steps go by. Hidden on
/// the first and the last screens.
private struct OnboardingProgressLine: View {
    let model: OnboardingModel

    var body: some View {
        let steps = model.steps
        let total = max(steps.count - 1, 1)
        let fraction = Double(model.stepIndex) / Double(total)
        let shown = model.step != .welcome && model.step != .done && steps.count > 2
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.primary.opacity(0.08))
                Capsule()
                    .fill(Theme.accent)
                    .frame(width: max(proxy.size.width * fraction, 3))
            }
        }
        .frame(height: 3)
        .frame(maxWidth: 160)
        .opacity(shown ? 1 : 0)
        .animation(.spring(duration: 0.5, bounce: 0), value: fraction)
        .animation(.easeOut(duration: 0.2), value: shown)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("onboarding.progress"))
        .accessibilityValue(Text("onboarding.stepOf \(model.stepIndex) \(total)"))
        .accessibilityHidden(!shown)
        .accessibilityIdentifier("onboarding.progress")
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
                Button("common.back") { model.back() }
                    .controlSize(.large)
                    .accessibilityIdentifier("onboarding.back")
            }
            Spacer()
            if let hint = model.primaryHint {
                Text(hint)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .accessibilityIdentifier("onboarding.hint")
            }
            if model.step != .welcome, model.step != .done {
                if model.busy { ProgressView().controlSize(.small) }
                if model.canSkip {
                    Button("app.later") { model.skip() }
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
