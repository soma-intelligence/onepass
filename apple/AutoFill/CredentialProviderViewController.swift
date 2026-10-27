import AuthenticationServices
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
/// without sync. The model locks the session before it completes; a session is never kept for a
/// later request. The `...WithoutUserInteraction` entry points never unlock: they answer with
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

    #if os(macOS)
    /// No nib: an `NSViewController` without one must create its own view.
    override func loadView() {
        view = NSView()
        preferredContentSize = NSSize(width: 440, height: 560)
    }

    override func viewDidDisappear() {
        super.viewDidDisappear()
        tearDown()
    }
    #else
    /// Dismissed by the system (or after completion): lock and forget the session.
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        tearDown()
    }
    #endif

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

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        guard let request = Self.directRequest(credentialRequest) else {
            answer(.cancelled(.credentialNotFound), for: nil)
            return
        }
        answerWithoutInterface(request)
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
        answerWithoutInterface(.savePassword(Self.saveRequest(savePasswordRequest)))
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

    /// Ruling A10: the field, confirmation and quirks rules through the core's
    /// `passwordFromRules`, else 20 random characters (the app generator's default). One `strong`
    /// password.
    @available(iOS 26.2, *)
    private func generatePasswords(_ request: ASGeneratePasswordsRequest) {
        let rules = [
            request.passwordFieldPasswordRules, request.confirmPasswordFieldPasswordRules,
            request.passwordRulesFromQuirks,
        ]
        .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
        let fallback = FfiPasswordRecipe.characters(length: 20, digits: true, symbols: true, avoidAmbiguous: false)
        do {
            let value = try passwordFromRules(rules: rules, fallback: fallback)
            extensionContext.completeGeneratePasswordRequest(
                results: [ASGeneratedPassword(kind: .strong, value: value)], completionHandler: nil)
        } catch {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
        }
    }
    #endif

    // MARK: - Request lifecycle

    /// A request with an interface: a fresh session and model, the root view, then `start`.
    private func begin(_ request: AutoFillRequest) {
        tearDown()
        requestToken &+= 1
        requestEnded = false
        let token = requestToken
        let session = VaultSession(environment: Self.environment())
        let model = AutoFillModel(session: session, request: request, ownAppIDs: Self.ownAppIDs()) {
            [weak self] result in
            self?.finish(result, for: request, token: token)
        }
        self.session = session
        self.model = model
        host(AutoFillRootView(model: model, session: session, request: request))
        Task { await model.start() }
    }

    /// The shared store, settings and keychain service; in a Debug build after an isolated launch of
    /// the app (UI tests), the isolated ones (`UITestIsolation`).
    private static func environment() -> VaultEnvironment {
        #if DEBUG
        if let isolated = UITestIsolation.extensionEnvironment() { return isolated }
        #endif
        return VaultEnvironment.live(sync: NoSync())
    }

    private func answerWithoutInterface(_ request: AutoFillRequest) {
        let result =
            AutoFillModel.resultWithoutUserInteraction(for: request, ownAppIDs: Self.ownAppIDs())
            ?? .cancelled(.userInteractionRequired)
        answer(result, for: request)
    }

    /// Ends the current request with an interface, if any: an unfinished model is abandoned (session
    /// locked, no completion), the session is locked and dropped, and the view is removed.
    private func tearDown() {
        requestEnded = true
        model?.abandon()
        model = nil
        session?.lock()
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

    /// Domains or URLs as the system gives them: the model matches them with the core.
    private static func services(_ identifiers: [ASCredentialServiceIdentifier]) -> [String] {
        identifiers.map(\.identifier).filter { !$0.isEmpty }
    }

    /// A QuickType suggestion. `recordIdentifier` is `"<vault id>:<item id>"`; a password or code
    /// request carries the identity's service (the Login must still match it); a passkey request
    /// carries the identity's credential id (the model refuses an empty allow list).
    private static func directRequest(_ request: any ASCredentialRequest) -> AutoFillRequest? {
        let recordID = request.credentialIdentity.recordIdentifier ?? ""
        // The host the identity was published for: the model checks the Login still matches it.
        let service = request.credentialIdentity.serviceIdentifier.identifier
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
            password: request.credential.password, title: title, event: event)
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
