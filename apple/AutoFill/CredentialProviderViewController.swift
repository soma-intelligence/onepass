import AuthenticationServices
import OSLog
import SwiftUI
import VaultKit

#if os(iOS)
import UIKit

private typealias PlatformViewController = UIViewController
private typealias HostingController = UIHostingController
#else
import AppKit

private typealias PlatformViewController = NSViewController
private typealias HostingController = NSHostingController
#endif

/// The OnePass credential provider (spec 5). Every decision lives in VaultKit's `AutoFillModel`;
/// this controller only translates each system call into an `AutoFillRequest`, hosts
/// `AutoFillRootView` over the model, and turns the `AutoFillResult` back into the matching
/// `extensionContext` call.
///
/// One `VaultSession` and one `AutoFillModel` per request, built from the shared environment
/// without sync. The model locks the session before it completes, with one exception (owner ruling
/// of 2026-11-10): after Face ID / Touch ID, a filled password or code leaves its session to
/// `AutoFillUnlockWindow.shared` for 90 seconds, for the same site or app and the same account.
/// The `...WithoutUserInteraction` entry points never unlock: inside that window a password or a
/// code of the same service is answered from the kept session, everything else answers with
/// `AutoFillModel.resultWithoutUserInteraction` (password generation reads no vault data).
///
/// When the system dismisses the interface (or starts another request on this controller) before
/// the model completes, the request is abandoned: the session is locked and the late result of
/// the old model never reaches `extensionContext` (per-request token).
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private var hosting: PlatformViewController?
    private var model: AutoFillModel?
    private var session: VaultSession?
    /// Bumped by every request with an interface; a completion carrying an older token is dropped.
    private var requestToken = 0
    /// The current request was answered or abandoned: nothing more goes to `extensionContext`.
    private var requestEnded = true
    /// On screen: Face ID / Touch ID may start. Before that, iOS cancels it (systemCancel), which used
    /// up the one automatic attempt and left the password field (seen on the second sign-in step).
    /// The Mac waits the same way (MACAPP-10).
    private var appeared = false
    /// The `start` of a request prepared before the sheet came up.
    private var pendingStart: (() -> Void)?
    /// The unlock kept after Face ID / Touch ID: in this process's memory only.
    private var unlockWindow: AutoFillUnlockWindow { .shared }

    #if os(macOS)
    /// No nib: an `NSViewController` without one must create its own view.
    override func loadView() {
        view = NSView()
        preferredContentSize = NSSize(width: 440, height: 560)
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        appearedNow()
    }

    override func viewDidDisappear() {
        super.viewDidDisappear()
        appeared = false
        tearDown()
    }
    #else
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        appearedNow()
    }

    /// Dismissed by the system (or after completion): lock and forget the session.
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        appeared = false
        tearDown()
    }
    #endif

    private func appearedNow() {
        appeared = true
        let start = pendingStart
        pendingStart = nil
        start?()
    }

    // MARK: - Lists

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        begin(.credentialList(services: Self.services(serviceIdentifiers), passkey: nil))
    }

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        let passkey = PasskeyRequest(
            rpID: requestParameters.relyingPartyIdentifier,
            clientDataHash: requestParameters.clientDataHash,
            allowedCredentialIDs: requestParameters.allowedCredentials)
        begin(.credentialList(services: Self.services(serviceIdentifiers), passkey: passkey))
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        begin(.oneTimeCodeList(services: Self.services(serviceIdentifiers)))
    }

    // MARK: - Direct requests (QuickType suggestions)

    /// Inside the unlock window (Face ID less than 90 seconds ago, same service and account), a
    /// password or a one-time code is answered here, without interface. Otherwise the system is
    /// told to show it.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        guard let request = Self.directRequest(credentialRequest) else {
            answer(.cancelled(.credentialNotFound), for: nil)
            return
        }
        let window = unlockWindow
        // Nothing kept (the usual case, and always after the process was restarted): the normal path.
        guard window.isOpen else {
            answerWithoutInterface(request)
            return
        }
        let account = Self.accountScope(for: request)
        let ownAppIDs = Self.ownAppIDs()
        Task { @MainActor [weak self] in
            let filled = await AutoFillModel.resultFromUnlockWindow(
                for: request, window: window, account: account, ownAppIDs: ownAppIDs)
            guard let self else { return }
            if let filled {
                self.answer(filled, for: request)
            } else {
                self.answerWithoutInterface(request)
            }
        }
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        guard let request = Self.directRequest(credentialRequest) else {
            answer(.cancelled(.credentialNotFound), for: nil)
            return
        }
        begin(request)
    }

    // MARK: - Passkey registration

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = Self.registrationRequest(registrationRequest) else {
            answer(.cancelled(.failed), for: nil)
            return
        }
        begin(request)
    }

    /// Conditional registration (a site upgrading to a passkey automatically): always `.failed`
    /// (`resultWithoutUserInteraction`), ruling A9: never a passkey created without an explicit choice.
    override func performWithoutUserInteractionIfPossible(passkeyRegistration registrationRequest: ASPasskeyCredentialRequest) {
        guard let request = Self.registrationRequest(registrationRequest) else {
            answer(.cancelled(.failed), for: nil)
            return
        }
        noteRequestForUnlockWindow(request)
        answerWithoutInterface(request)
    }

    // MARK: - Configuration and text insertion

    override func prepareInterfaceForExtensionConfiguration() {
        begin(.configuration)
    }

    #if os(iOS)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        begin(.textToInsert)
    }

    // MARK: - Save and generate (iOS 26.2+)

    @available(iOS 26.2, *)
    override func prepareInterface(for savePasswordRequest: ASSavePasswordRequest) {
        begin(.savePassword(Self.saveRequest(savePasswordRequest)))
    }

    @available(iOS 26.2, *)
    override func performWithoutUserInteractionIfPossible(savePasswordRequest: ASSavePasswordRequest) {
        let request = AutoFillRequest.savePassword(Self.saveRequest(savePasswordRequest))
        noteRequestForUnlockWindow(request)
        answerWithoutInterface(request)
    }

    @available(iOS 26.2, *)
    override func performWithoutUserInteraction(generatePasswordsRequest: ASGeneratePasswordsRequest) {
        generatePasswords(generatePasswordsRequest)
    }

    /// Same answer as without interface: generation shows nothing and reads no vault data.
    @available(iOS 26.2, *)
    override func prepareInterface(for generatePasswordsRequest: ASGeneratePasswordsRequest) {
        generatePasswords(generatePasswordsRequest)
    }

    /// Ruling A10, spec G5: the field, confirmation and quirks rules through the core's
    /// `passwordForContext`, built with the profile chosen in the app (`GeneratorProfileStore`, "Fort"
    /// by default). The quirk string goes in its own, less trusted tier, as in the browser bridge.
    /// Unreadable or contradictory rules leave the profile alone. One `strong` password.
    @available(iOS 26.2, *)
    private func generatePasswords(_ request: ASGeneratePasswordsRequest) {
        let trimmed: (String?) -> String? = { rule in
            guard let rule = rule?.trimmingCharacters(in: .whitespacesAndNewlines), !rule.isEmpty else { return nil }
            return rule
        }
        let rules = [request.passwordFieldPasswordRules, request.confirmPasswordFieldPasswordRules]
            .compactMap(trimmed)
        let context = FfiPasswordContext(
            rules: rules, quirkRules: trimmed(request.passwordRulesFromQuirks), minLength: nil, maxLength: nil,
            hintText: nil)
        do {
            let generated = try passwordForContext(
                context: context, profile: GeneratorProfileStore.shared().profile.ffi)
            extensionContext.completeGeneratePasswordRequest(
                results: [ASGeneratedPassword(kind: .strong, value: generated.password)], completionHandler: nil)
        } catch {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
        }
    }
    #endif

    // MARK: - Request lifecycle

    /// A request with an interface: a fresh session and model, the root view, then `start` once the
    /// sheet is on screen. `slot`: the account picked in the switcher (nil: routing decides).
    private func begin(_ request: AutoFillRequest, slot: String? = nil) {
        tearDown()
        requestToken &+= 1
        requestEnded = false
        let token = requestToken
        let environment = Self.environment(for: request, slot: slot)
        // A request for another service or account ends the unlock window; one with an interface
        // always unlocks its own fresh session.
        Self.observeDeviceLock()
        if case .configuration = request {
            unlockWindow.end()
        } else {
            unlockWindow.requestArrived(for: request.primaryService, account: environment.settings.scope)
        }
        let session = VaultSession(environment: environment)
        let model = AutoFillModel(
            session: session, request: request, ownAppIDs: Self.ownAppIDs(),
            unlockWindow: Self.reusesUnlock ? unlockWindow : nil
        ) { [weak self] result in
            self?.finish(result, for: request, token: token)
        }
        self.session = session
        self.model = model
        host(AutoFillRootView(
            model: model, session: session, request: request,
            accounts: Self.accountChoices(for: request, current: slot)
        ) { [weak self] picked in
            // Another account: this session is locked and dropped first (one account at a time, M6).
            guard let self, token == self.requestToken, !self.requestEnded else { return }
            self.begin(request, slot: picked)
        })
        let start = { Task { await model.start() } }
        if appeared {
            _ = start()
        } else {
            pendingStart = { _ = start() }
        }
    }

    /// The shared store, settings and keychain service of the account that answers the request: the
    /// one picked in the switcher, else the one whose work domains claim its host, else the primary
    /// account (multi-account spec 8). In a Debug build after an isolated launch of the app (UI tests),
    /// the isolated ones (`UITestIsolation`).
    private static func environment(for request: AutoFillRequest, slot: String? = nil) -> VaultEnvironment {
        #if DEBUG
        if let isolated = UITestIsolation.extensionEnvironment() { return isolated }
        #endif
        if let slot { return VaultEnvironment.autoFill(slot: slot) }
        return VaultEnvironment.autoFill(for: request)
    }

    /// The accounts of the switcher (lists only, two accounts or more), the current one marked.
    private static func accountChoices(for request: AutoFillRequest, current: String?) -> AutoFillAccounts? {
        switch request {
        case .credentialList, .oneTimeCodeList, .credential(_, .password, _, _), .credential(_, .oneTimeCode, _, _):
            break
        default:
            return nil
        }
        #if DEBUG
        if UITestIsolation.extensionEnvironment() != nil { return nil }
        #endif
        let store = AccountDirectoryStore(container: .resolve())
        let accounts = store.autoFillAccounts()
        guard accounts.count > 1 else { return nil }
        return AutoFillAccounts(accounts: accounts, current: current ?? store.slot(for: request))
    }

    /// The settings scope of the account routing gives `request` (nil: the primary account), as
    /// the unlock window compares it with the account of the session it keeps.
    private static func accountScope(for request: AutoFillRequest) -> String? {
        let slot = AccountDirectoryStore(container: .resolve()).slot(for: request)
        return slot == AccountDirectoryStore.primarySlot ? nil : slot
    }

    /// False after an isolated launch of the app (UI tests, Debug builds): their requests each
    /// unlock on their own, as the tests assert, and the window is never opened.
    private static var reusesUnlock: Bool {
        #if DEBUG
        return !UITestIsolation.isMarked(container: .resolve())
        #else
        return true
        #endif
    }

    /// A request without interface that the window never answers: one for another service or
    /// account still ends it.
    private func noteRequestForUnlockWindow(_ request: AutoFillRequest) {
        guard unlockWindow.isOpen else { return }
        unlockWindow.requestArrived(for: request.primaryService, account: Self.accountScope(for: request))
    }

    /// The device locked: the unlock window ends at once (its session is locked, the keys dropped)
    /// when this process is running to hear it. Registered once per process. iOS posts the
    /// protected data notification when the device locks with a passcode; the Mac posts the screen
    /// lock one. A suspended process hears nothing: the window itself reads the device lock as a
    /// counter at each use (`DeviceLockSignal`), which is what refuses the fill.
    private static func observeDeviceLock() {
        guard !observingDeviceLock else { return }
        observingDeviceLock = true
        let end: @Sendable (Notification) -> Void = { _ in
            Task { @MainActor in AutoFillUnlockWindow.shared.end() }
        }
        #if os(iOS)
        _ = NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil, queue: .main, using: end)
        #else
        _ = DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main, using: end)
        _ = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main, using: end)
        #endif
    }

    private static var observingDeviceLock = false

    private func answerWithoutInterface(_ request: AutoFillRequest) {
        // A filled generated password waits in the account's keychain until a Login holds it (G3).
        var drafts: GeneratedPasswordDrafts?
        if case .savePassword(let save) = request, save.event == .generatedPasswordFilled {
            drafts = GeneratedPasswordDrafts(environment: Self.environment(for: request))
        }
        let result =
            AutoFillModel.resultWithoutUserInteraction(for: request, ownAppIDs: Self.ownAppIDs(), drafts: drafts)
            ?? .cancelled(.userInteractionRequired)
        answer(result, for: request)
    }

    /// Ends the current request with an interface, if any: an unfinished model is abandoned (session
    /// locked, no completion), the session is locked and dropped, and the view is removed. A
    /// session its model left to the unlock window is only dropped here: the window locks it.
    private func tearDown() {
        requestEnded = true
        pendingStart = nil
        model?.abandon()
        model = nil
        if let session, !unlockWindow.holds(session) {
            // The end of a request, not a lock of the account: no stamp for the other processes.
            session.lock(publishPending: false, stampsAccountLock: false)
        }
        session = nil
        guard let hosting else { return }
        #if os(iOS)
        hosting.willMove(toParent: nil)
        #endif
        hosting.view.removeFromSuperview()
        hosting.removeFromParent()
        self.hosting = nil
    }

    private func host(_ root: AutoFillRootView) {
        let controller = HostingController(rootView: root)
        addChild(controller)
        controller.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(controller.view)
        NSLayoutConstraint.activate([
            controller.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            controller.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            controller.view.topAnchor.constraint(equalTo: view.topAnchor),
            controller.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        #if os(iOS)
        controller.didMove(toParent: self)
        #endif
        hosting = controller
    }

    // MARK: - Results

    /// The model's completion: forwarded only for the current, still open request.
    private func finish(_ result: AutoFillResult, for request: AutoFillRequest, token: Int) {
        guard token == requestToken, !requestEnded else { return }
        requestEnded = true
        answer(result, for: request)
    }

    /// `AutoFillResult` to `extensionContext`. The configuration request always ends with
    /// `completeExtensionConfigurationRequest` (its screen ends with the model's `cancel`).
    private func answer(_ result: AutoFillResult, for request: AutoFillRequest?) {
        Self.log.info("answering: \(Self.kind(of: result), privacy: .public)")
        if case .configuration? = request {
            extensionContext.completeExtensionConfigurationRequest()
            return
        }
        switch result {
        case .password(let user, let password):
            extensionContext.completeRequest(
                withSelectedCredential: ASPasswordCredential(user: user, password: password), completionHandler: nil)
        case .oneTimeCode(let code):
            extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
        case .passkeyAssertion(let assertion, let rpID, let clientDataHash):
            let credential = ASPasskeyAssertionCredential(
                userHandle: assertion.userHandle, relyingParty: rpID, signature: assertion.signature,
                clientDataHash: clientDataHash, authenticatorData: assertion.authenticatorData,
                credentialID: assertion.credentialId)
            extensionContext.completeAssertionRequest(using: credential, completionHandler: nil)
        case .passkeyRegistration(let registration, let rpID, let clientDataHash):
            let credential = ASPasskeyRegistrationCredential(
                relyingParty: rpID, clientDataHash: clientDataHash, credentialID: registration.credentialId,
                attestationObject: registration.attestationObject)
            extensionContext.completeRegistrationRequest(using: credential, completionHandler: nil)
        case .text(let text):
            #if os(iOS)
            extensionContext.completeRequest(withTextToInsert: text, completionHandler: nil)
            #else
            // Unreachable: macOS has no text insertion request.
            cancel(.failed)
            #endif
        case .saved:
            #if os(iOS)
            if #available(iOS 26.2, *) {
                extensionContext.completeSavePasswordRequest(completionHandler: nil)
            } else {
                cancel(.failed)
            }
            #else
            // Unreachable: macOS has no save password request.
            cancel(.failed)
            #endif
        case .cancelled(let failure):
            cancel(failure)
        }
    }

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "autofill-extension")

    /// The result's kind for the log: never a value.
    private static func kind(of result: AutoFillResult) -> String {
        switch result {
        case .password: "password"
        case .oneTimeCode: "code"
        case .passkeyAssertion: "passkey assertion"
        case .passkeyRegistration: "passkey registration"
        case .text: "text"
        case .saved: "saved"
        case .cancelled(let failure): "cancelled \(failure)"
        }
    }

    private func cancel(_ failure: AutoFillFailure) {
        let code: ASExtensionError.Code =
            switch failure {
            case .userCanceled: .userCanceled
            case .userInteractionRequired: .userInteractionRequired
            case .credentialNotFound: .credentialIdentityNotFound
            case .excludedCredential: .matchedExcludedCredential
            case .failed: .failed
            }
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }

    // MARK: - System requests to AutoFillRequest

    /// Domains, URLs or App IDs as the system gives them, with their type (G2: an App ID is never
    /// read as a host) and display name (G12). The model matches them with the core.
    private static func services(_ identifiers: [ASCredentialServiceIdentifier]) -> [AutoFillService] {
        identifiers.filter { !$0.identifier.isEmpty }.map(service)
    }

    private static func service(_ identifier: ASCredentialServiceIdentifier) -> AutoFillService {
        if #available(iOS 26.2, macOS 26.2, *), identifier.type == .app {
            return .app(identifier.identifier, displayName: identifier.displayName)
        }
        return .site(identifier.identifier)
    }

    /// A QuickType suggestion. `recordIdentifier` is `"<vault id>:<item id>"`; a password or code
    /// request carries the identity's service (the Login must still match it); a passkey request
    /// carries the identity's credential id (the model refuses an empty allow list).
    private static func directRequest(_ request: any ASCredentialRequest) -> AutoFillRequest? {
        let recordID = request.credentialIdentity.recordIdentifier ?? ""
        // The host or app the identity was published for: the model checks the Login still matches it.
        let service = Self.service(request.credentialIdentity.serviceIdentifier)
        switch request.type {
        case .password:
            return .credential(recordID: recordID, kind: .password, passkey: nil, service: service)
        case .oneTimeCode:
            return .credential(recordID: recordID, kind: .oneTimeCode, passkey: nil, service: service)
        case .passkeyAssertion:
            guard let passkeyRequest = request as? ASPasskeyCredentialRequest,
                let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity
            else { return nil }
            let passkey = PasskeyRequest(
                rpID: identity.relyingPartyIdentifier, clientDataHash: passkeyRequest.clientDataHash,
                allowedCredentialIDs: [identity.credentialID])
            return .credential(recordID: identity.recordIdentifier ?? recordID, kind: .passkey, passkey: passkey)
        case .passkeyRegistration:
            return nil
        @unknown default:
            return nil
        }
    }

    /// A passkey creation. An empty algorithm list means the WebAuthn default (ES256 and RS256).
    private static func registrationRequest(_ request: any ASCredentialRequest) -> AutoFillRequest? {
        guard let passkeyRequest = request as? ASPasskeyCredentialRequest,
            let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity
        else { return nil }
        let algorithms = passkeyRequest.supportedAlgorithms
        return .passkeyRegistration(PasskeyRegistrationRequest(
            rpID: identity.relyingPartyIdentifier,
            userName: identity.userName,
            userHandle: identity.userHandle,
            clientDataHash: passkeyRequest.clientDataHash,
            excludedCredentialIDs: passkeyRequest.excludedCredentials?.map(\.credentialID) ?? [],
            supportsES256: algorithms.isEmpty || algorithms.contains(.ES256)))
    }

    #if os(iOS)
    /// An app service keeps its identifier; a domain or URL service becomes its host.
    @available(iOS 26.2, *)
    private static func saveRequest(_ request: ASSavePasswordRequest) -> SavePasswordRequest {
        let identifier = request.serviceIdentifier
        let isApp = identifier.type == .app
        let service: String
        if isApp {
            service = identifier.identifier
        } else if identifier.type == .URL, let host = URL(string: identifier.identifier)?.host(), !host.isEmpty {
            service = host
        } else {
            service = identifier.identifier
        }
        let event: SaveEvent =
            switch request.event {
            case .userInitiated: .userInitiated
            case .formDidDisappear: .formDidDisappear
            case .generatedPasswordFilled: .generatedPasswordFilled
            @unknown default: .formDidDisappear
            }
        // An app has no host: its display name is a better default title than its identifier.
        let title = request.title ?? (isApp ? identifier.displayName : nil)
        return SavePasswordRequest(
            service: service, serviceIsApp: isApp, user: request.credential.user,
            password: request.credential.password, title: title, event: event,
            displayName: isApp ? identifier.displayName : nil)
    }
    #endif

    /// The containing app's bundle identifier (this extension's minus `.autofill`), with and
    /// without the team prefix (`AppIdentifierPrefix` Info.plist key, absent from unsigned builds).
    private static func ownAppIDs() -> Set<String> {
        let bundleID = Bundle.main.bundleIdentifier ?? ""
        let suffix = ".autofill"
        let appID = bundleID.hasSuffix(suffix) ? String(bundleID.dropLast(suffix.count)) : bundleID
        var ids: Set<String> = [appID]
        if let raw = Bundle.main.object(forInfoDictionaryKey: "AppIdentifierPrefix") as? String {
            let prefix = raw.trimmingCharacters(in: .whitespaces)
            if !prefix.isEmpty, !prefix.contains("$(") {
                ids.insert((prefix.hasSuffix(".") ? prefix : prefix + ".") + appID)
            }
        }
        return ids
    }
}
