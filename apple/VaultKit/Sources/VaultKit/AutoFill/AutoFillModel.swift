import Foundation
import Observation

/// Every decision of the AutoFill extension for one request (spec 5): which screen to show, when to
/// unlock, what to fill, save or create. The extension's view controller only translates system calls
/// into an `AutoFillRequest` and the `AutoFillResult` back into `extensionContext` calls.
///
/// One model and one `VaultSession` per request. `complete` is called exactly once: just before, the
/// session is locked, and `store-changed` is posted if this request wrote. Every call after that is
/// ignored. Errors are left in `session.lastError` for the interface; integrity failures show
/// `integrityFailure`, and a session locked meanwhile (auto-lock) goes back to the unlock screen.
///
/// One exception to the lock (owner ruling of 2026-11-10): a password or a code filled after Face ID
/// / Touch ID hands its session to the `AutoFillUnlockWindow` it was given, which keeps it 90
/// seconds for the same service and answers its next requests without interface
/// (`resultFromUnlockWindow`).
@MainActor
@Observable
public final class AutoFillModel {
    public enum Screen: Equatable, Sendable {
        /// Before `start`: the interface shows nothing yet.
        case starting
        /// No account, or a store that cannot be read: "open OnePass" and cancel.
        case noAccount
        /// This device has no Secret Key for the account: the app must restore it first.
        case needsSecretKey
        /// Master password field (Face ID was tried first when usable).
        case locked
        case integrityFailure(VaultError)
        /// Matches for the site first, `others` (every other Login) behind an explicit gesture.
        case list([FfiAutofillCandidate], others: [FfiAutofillCandidate])
        /// Logins of the relying party whose username is the same or empty, or a new item.
        case passkeyRegistration(suggestions: [FfiAutofillCandidate])
        /// Save sheet; `existing` is the Login of the same site and username ("Mettre à jour").
        case save(existing: FfiAutofillCandidate?)
        case textItems([FfiItemSummary])
        case textFields(FfiItem)
        case configuration
        /// The request is over (`complete` was called). Nothing from the vault is kept.
        case finished
    }

    public private(set) var screen: Screen = .starting
    /// `complete` was called: the request is over.
    public private(set) var isFinished = false
    /// The list was asked without any service (an app without associated domain, G8): every Login is
    /// a manual choice, so the list opens on the search with the Logins used last first.
    public private(set) var listWithoutService = false
    /// The configuration screen published the suggestions after an unlock (G10).
    public private(set) var suggestionsPublished = false

    @ObservationIgnored private let session: VaultSession
    @ObservationIgnored private let request: AutoFillRequest
    @ObservationIgnored private let ownAppIDs: Set<String>
    @ObservationIgnored private let onComplete: (AutoFillResult) -> Void
    @ObservationIgnored private var wrote = false
    /// The service each Login of the current list matched (`"<vault id>:<item id>"` to service): what a
    /// fill from the list remembers. `others` are not in it.
    @ObservationIgnored private var listedServices: [String: AutoFillService] = [:]
    /// The configuration screen asked for an unlock to publish the suggestions.
    @ObservationIgnored private var publishingFromConfiguration = false
    /// Where a session unlocked with Face ID / Touch ID is kept after a fill (nil: always locked).
    @ObservationIgnored private let unlockWindow: AutoFillUnlockWindow?
    /// The unlock of this request that Face ID / Touch ID made itself: when, and the session
    /// generation it opened (any lock or other unlock since moves the generation on). Never set by
    /// a master password.
    @ObservationIgnored private var biometricUnlock: (at: Date, generation: Int)?
    /// Where the generated passwords filled but not saved yet wait (G3).
    private var drafts: GeneratedPasswordDrafts { GeneratedPasswordDrafts(environment: session.environment) }
    /// The language dates and country names are inserted in (text insertion).
    @ObservationIgnored public var locale: Locale = .autoupdatingCurrent

    /// `ownAppIDs`: the containing app's bundle identifier, with and without the team prefix.
    /// `unlockWindow`: the provider's window (nil keeps a fresh session per request, locked at
    /// the end).
    public init(
        session: VaultSession, request: AutoFillRequest, ownAppIDs: Set<String>,
        unlockWindow: AutoFillUnlockWindow? = nil, complete: @escaping (AutoFillResult) -> Void
    ) {
        self.session = session
        self.request = request
        self.ownAppIDs = ownAppIDs
        self.unlockWindow = unlockWindow
        onComplete = complete
    }

    /// Answer to a `...WithoutUserInteraction` call without any session (the provider asks
    /// `resultFromUnlockWindow` first: outside that window, the extension is never unlocked outside
    /// a request). A save coming from OnePass itself, or of a generated password just filled,
    /// ends as saved without writing; a conditional passkey registration (automatic upgrade by the
    /// site) fails, since a passkey is never created without an explicit choice (ruling A9); everything
    /// else asks for the interface. Never nil today.
    ///
    /// A generated password just filled is kept in `drafts` (G3) until a Login holds it: the save
    /// request that should follow may never come.
    nonisolated public static func resultWithoutUserInteraction(
        for request: AutoFillRequest, ownAppIDs: Set<String>, drafts: GeneratedPasswordDrafts? = nil,
        now: Date = Date()
    ) -> AutoFillResult? {
        switch request {
        case .savePassword(let save) where isOwnApp(save, ownAppIDs):
            return .saved
        case .savePassword(let save) where save.event == .generatedPasswordFilled:
            keepDraft(save, in: drafts, now: now)
            return .saved
        case .passkeyRegistration:
            return .cancelled(.failed)
        default:
            return .cancelled(.userInteractionRequired)
        }
    }

    /// A filled generated password with something to keep (never an empty one).
    nonisolated private static func keepDraft(_ save: SavePasswordRequest, in drafts: GeneratedPasswordDrafts?, now: Date) {
        guard let drafts, !save.password.isEmpty, !save.service.isEmpty else { return }
        drafts.add(GeneratedPasswordDraft(save, at: now), now: now)
    }

    /// Default title of a saved Login: the system's suggestion, else the app's name or the service host.
    nonisolated public static func defaultTitle(for request: SavePasswordRequest) -> String {
        if let title = request.title?.trimmingCharacters(in: .whitespacesAndNewlines), !title.isEmpty {
            return title
        }
        if request.serviceIsApp { return request.typedService.shownName }
        return host(of: request.service)
    }

    // MARK: - Start and unlock

    /// First call. Requests that need no vault end here; otherwise shows the unlock screen and tries
    /// Face ID / Touch ID once when usable (ruling A2: cheaper than Argon2id in an extension).
    public func start() async {
        guard !isFinished else { return }
        switch request {
        case .configuration:
            screen = .configuration
            return
        case .savePassword(let save) where Self.isOwnApp(save, ownAppIDs):
            finish(.saved)
            return
        case .savePassword(let save) where save.event == .generatedPasswordFilled:
            // Kept until a Login holds it (G3): the next event should carry the same value.
            Self.keepDraft(save, in: drafts, now: session.environment.clock.now)
            finish(.saved)
            return
        case .passkeyRegistration(let registration) where !registration.supportsES256:
            finish(.cancelled(.failed))
            return
        default:
            break
        }
        if session.state == .unlocked {
            await proceed()
            return
        }
        showUnlockScreen()
        if screen == .locked, session.canUseBiometrics {
            await unlockWithBiometrics()
        }
    }

    /// `unlock(password:)` with a typed `String` (tests). The extension passes `SecretBytes`.
    public func unlock(password: String) async {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        await unlock(password: bytes)
    }

    /// Master password. A wrong password stays on `locked` (error and failure counter in the session).
    /// The caller wipes `password`.
    public func unlock(password: SecretBytes) async {
        guard !isFinished, screen == .locked else { return }
        try? await session.unlock(password: password)
        await afterUnlockAttempt()
    }

    /// Face ID / Touch ID. A refusal or cancel stays on `locked` (password field).
    public func unlockWithBiometrics() async {
        guard !isFinished, screen == .locked else { return }
        let before = session.generation
        do {
            try await session.unlockWithBiometrics()
            // Only this call's own success may open the unlock window. It did not throw, and it is
            // the unlock that opened the session: exactly one generation further (an unlock begins
            // one). A session already open leaves the generation alone; a master password typed
            // beside the system sheet begins its own unlock, supersedes this one and moves it
            // further. The state alone would credit Face ID with that password's unlock.
            if session.state == .unlocked, session.generation == before &+ 1 {
                biometricUnlock = (session.environment.clock.now, session.generation)
            }
        } catch {
            // Refused, cancelled or failed: whatever opens the session next is not this call.
        }
        await afterUnlockAttempt()
    }

    private func afterUnlockAttempt() async {
        guard !isFinished else { return }
        if session.state == .unlocked {
            await proceed()
        } else {
            showUnlockScreen()
        }
    }

    private func showUnlockScreen() {
        switch session.state {
        case .noAccount:
            screen = .noAccount
        case .failed(let failure):
            if case .integrity = failure { screen = .integrityFailure(failure) } else { screen = .noAccount }
        case .locked, .unlocking, .unlocked:
            screen = session.needsSecretKey ? .needsSecretKey : .locked
        }
    }

    /// Unlocked: the screen of the request, or a direct answer. First the generated passwords still
    /// waiting are saved (G3), and the identities are published when the store is behind the vault,
    /// or when this provider has not done so for a while (G10: QuickType works without opening the
    /// app).
    private func proceed() async {
        await saveWaitingDrafts()
        await publishIdentitiesIfNeeded()
        guard !isFinished, session.state == .unlocked else {
            recover(finishing: false)
            return
        }
        do {
            switch request {
            case .credentialList(let services, let passkey):
                screen = try await listScreen(services: services, passkey: passkey, oneTimeCode: false)
            case .oneTimeCodeList(let services):
                screen = try await listScreen(services: services, passkey: nil, oneTimeCode: true)
            case .credential(let recordID, let kind, let passkey, let service):
                try await fillDirectly(recordID: recordID, kind: kind, passkey: passkey, service: service)
            case .passkeyRegistration(let registration):
                try await prepareRegistration(registration)
            case .savePassword(let save):
                try await prepareSave(save)
            case .textToInsert:
                screen = .textItems(try await textItems())
            case .configuration:
                if publishingFromConfiguration {
                    await session.publishAutofillIdentitiesNow()
                    suggestionsPublished = true
                    publishingFromConfiguration = false
                }
                screen = .configuration
            }
        } catch {
            recover(finishing: true)
        }
    }

    // MARK: - Identities (G10, MACAPP-11)

    /// How long a publication from the provider holds before an unlock publishes again.
    nonisolated static let publishInterval: TimeInterval = 600
    nonisolated static let publishedAtKey = "onepass.autofill.providerPublishedAt"

    /// Publishes the identities (metadata only, the core's `autofillIdentities`: passwords, passkeys
    /// and one-time codes alike) after an unlock in the provider.
    ///
    /// Behind the vault (a sync applied while locked, a write whose publication never ended, the
    /// app never opened since): published now and waited for, at most the session's limit, before
    /// the request goes on, so the store is right when control goes back to the system. Otherwise
    /// once per `publishInterval` without waiting, which also refills a store the system emptied.
    /// An added account publishes nothing (its environment has `NoIdentityStore`, ruling P6,
    /// unchanged).
    private func publishIdentitiesIfNeeded() async {
        guard !isFinished, session.state == .unlocked, session.environment.settings.quickTypeSuggestions else { return }
        let defaults = session.environment.settings.baseDefaults
        let key = Self.publishedAtKey + (session.environment.settings.scope.map { ".\($0)" } ?? "")
        let now = session.environment.clock.now
        if session.autofillIdentitiesBehind {
            // A store that is off (an added account, the provider turned off) reads nothing.
            guard await session.environment.identityStore.isEnabled(), !isFinished else { return }
            await session.publishAutofillIdentitiesNow()
            defaults.set(now, forKey: key)
            return
        }
        let last = defaults.object(forKey: key) as? Date
        if let last, last <= now, now.timeIntervalSince(last) < Self.publishInterval { return }
        defaults.set(now, forKey: key)
        await session.publishAutofillIdentitiesSoon()
    }

    /// "Afficher mes comptes au-dessus du clavier" on the configuration screen: unlocks (Face ID /
    /// Touch ID first), publishes the identities, then shows the configuration screen again.
    public func publishSuggestionsFromConfiguration() async {
        guard !isFinished, case .configuration = request, screen == .configuration else { return }
        publishingFromConfiguration = true
        if session.state == .unlocked {
            await proceed()
            return
        }
        showUnlockScreen()
        if screen == .locked, session.canUseBiometrics {
            await unlockWithBiometrics()
        }
    }

    // MARK: - Generated passwords waiting (G3)

    /// Every live draft of this account but the one the current save request carries (its sheet
    /// decides): a Login of the same service and username with that password ends it; otherwise a
    /// new Login in the first visible vault. A Login with the same username and another password is
    /// never overwritten without the user (the site may have refused the change): the draft becomes
    /// a Login of its own, "<site> (mot de passe généré)". Best effort, never blocks the request.
    private func saveWaitingDrafts() async {
        let now = session.environment.clock.now
        var pending = drafts.load(now: now)
        if case .savePassword(let save) = request { pending.removeAll { $0.password == save.password } }
        guard !pending.isEmpty, let vaultID = session.vaults.first?.id else { return }
        for draft in pending {
            guard !isFinished, session.state == .unlocked else { return }
            do {
                try await store(draft.saveRequest, title: nil, vaultID: vaultID)
                drafts.remove(password: draft.password, service: draft.service, now: now)
            } catch {
                if session.state == .unlocked { session.lastError = nil }
            }
        }
    }

    /// After an error: a session no longer unlocked (integrity, auto-lock) shows its screen; otherwise
    /// the request ends with `.failed` when nothing can be shown, or keeps its screen.
    private func recover(finishing: Bool) {
        guard !isFinished else { return }
        if session.state != .unlocked {
            showUnlockScreen()
        } else if finishing {
            finish(.cancelled(.failed))
        }
    }

    // MARK: - Lists

    /// The matches of each service follow the core's plan for it (the Login used last there first),
    /// then the rest in the candidates' order.
    private func listScreen(
        services: [AutoFillService], passkey: PasskeyRequest?, oneTimeCode: Bool
    ) async throws -> Screen {
        var matches: [FfiAutofillCandidate] = []
        var seen = Set<String>()
        var served: [String: AutoFillService] = [:]
        if let passkey {
            for candidate in try await session.autofillCandidates(for: .site(passkey.rpID), includeAll: false) {
                let offered = offering(candidate)
                if !offered.passkeys.isEmpty, seen.insert(offered.itemId).inserted { matches.append(offered) }
            }
        }
        for service in services {
            let candidates = try await session.autofillCandidates(for: service, includeAll: false)
            // The plan only orders: without it, the candidates' order.
            let ranked = await plan(service: service, oneTimeCode: oneTimeCode).map { Self.ordered(candidates, by: $0) }
            for candidate in ranked ?? candidates where seen.insert(candidate.itemId).inserted {
                matches.append(offering(candidate))
                served["\(candidate.vaultId):\(candidate.itemId)"] = service
            }
        }
        let anchor: AutoFillService = services.first ?? passkey.map { AutoFillService.site($0.rpID) } ?? .site("")
        listWithoutService = services.isEmpty && passkey == nil
        var others = try await session.autofillCandidates(for: anchor, includeAll: true)
            .filter { !seen.contains($0.itemId) }
            .map(offering)
        if oneTimeCode {
            matches.removeAll { !$0.hasTotp }
            others.removeAll { !$0.hasTotp }
        }
        listedServices = served
        return .list(matches, others: others)
    }

    /// The core's plan for `service`, nil when it fails (the list then keeps the candidates' order).
    /// An integrity failure or a lock still shows through the session's state.
    private func plan(service: AutoFillService, oneTimeCode: Bool) async -> FfiAutofillPlan? {
        do {
            return try await session.autofillPlan(for: service, request: oneTimeCode ? .oneTimeCode : .password)
        } catch {
            if session.state == .unlocked { session.lastError = nil }
            return nil
        }
    }

    /// `candidates` with the plan's items first, in the plan's order; the others keep their order.
    nonisolated static func ordered(_ candidates: [FfiAutofillCandidate], by plan: FfiAutofillPlan) -> [FfiAutofillCandidate] {
        let position = Dictionary(plan.itemIds.enumerated().map { ($1, $0) }, uniquingKeysWith: { first, _ in first })
        return candidates.enumerated()
            .sorted { a, b in
                let pa = position[a.element.itemId] ?? Int.max
                let pb = position[b.element.itemId] ?? Int.max
                return pa != pb ? pa < pb : a.offset < b.offset
            }
            .map(\.element)
    }

    /// The candidate with only the passkeys this request accepts (none without a passkey request).
    private func offering(_ candidate: FfiAutofillCandidate) -> FfiAutofillCandidate {
        var candidate = candidate
        candidate.passkeys = passkeyRequest.map { Self.offered(candidate.passkeys, for: $0) } ?? []
        return candidate
    }

    private static func offered(_ refs: [FfiPasskeyRef], for request: PasskeyRequest) -> [FfiPasskeyRef] {
        refs.filter {
            $0.rpId.lowercased() == request.rpID.lowercased()
                && (request.allowedCredentialIDs.isEmpty || request.allowedCredentialIDs.contains($0.credentialId))
        }
    }

    private var passkeyRequest: PasskeyRequest? {
        switch request {
        case .credentialList(_, let passkey): passkey
        case .credential(_, .passkey, let passkey, _): passkey
        default: nil
        }
    }

    /// What `choose` fills: a password or a one-time code.
    private var listKind: FfiAutofillKind? {
        switch request {
        case .credentialList: .password
        case .oneTimeCodeList: .oneTimeCode
        case .credential(_, .password, _, _): .password
        case .credential(_, .oneTimeCode, _, _): .oneTimeCode
        default: nil
        }
    }

    /// A Login of the list: its username and password, or its current one-time code.
    /// Ignored unless `candidate` is on the current `list` screen.
    ///
    /// `alwaysForApp` ("Always use for this app", asked by the interface, never assumed): when
    /// `rememberableApp(for:)` names an app, its App ID is added to the Login's `apps` before the
    /// fill, so the next request of that app offers the Login as a match. A site is never bound,
    /// and a binding that cannot be written (a read-only vault) never stops the fill.
    public func choose(_ candidate: FfiAutofillCandidate, alwaysForApp: Bool = false) async {
        guard !isFinished, session.state == .unlocked, let kind = listKind, listed(candidate) != nil else { return }
        let app = alwaysForApp ? rememberableApp(for: candidate) : nil
        do {
            var item = try await session.loadItem(vaultID: candidate.vaultId, itemID: candidate.itemId)
            var service = listedServices["\(candidate.vaultId):\(candidate.itemId)"]
            let result: AutoFillResult
            if kind == .oneTimeCode {
                guard let code = try oneTimeCodeResult(item) else {
                    finish(.cancelled(.credentialNotFound))
                    return
                }
                result = code
            } else {
                result = passwordResult(item)
            }
            var bound = false
            if let app, let saved = await bind(item, to: app) {
                item = saved
                service = app
                bound = true
            }
            let published = await noteUse(item, service: service)
            // The app's new identity reaches the store before the session locks.
            if bound, !published { await session.publishAutofillIdentitiesNow() }
            finish(result)
        } catch {
            recover(finishing: false)
        }
    }

    // MARK: - "Always use for this app"

    /// The app a Login picked from the other items can be bound to: the first app the request
    /// names, when `candidate` is on the list and matched none of the request's services. Nil for
    /// a match (nothing to remember), a request of sites only, and a list without any service:
    /// only an App ID the system gave is ever bound, never a web domain.
    public func rememberableApp(for candidate: FfiAutofillCandidate) -> AutoFillService? {
        guard !isFinished, listKind != nil, case .list(_, let others) = screen,
            others.contains(where: { $0.vaultId == candidate.vaultId && $0.itemId == candidate.itemId }),
            listedServices["\(candidate.vaultId):\(candidate.itemId)"] == nil
        else { return nil }
        let services: [AutoFillService] =
            switch request {
            case .credentialList(let services, _): services
            case .oneTimeCodeList(let services): services
            default: []
            }
        return services.first { $0.isApp && !$0.identifier.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    /// Adds the App ID of `app` to the `apps` of `item` and saves it. Nil when nothing was saved
    /// (the error is cleared: the fill goes on without the binding).
    private func bind(_ item: FfiItem, to app: AutoFillService) async -> FfiItem? {
        guard !item.apps.contains(app.identifier) else { return item }
        var item = item
        item.apps.append(app.identifier)
        do {
            let saved = try await session.save(item)
            wrote = true
            return saved
        } catch {
            if session.state == .unlocked { session.lastError = nil }
            return nil
        }
    }

    // MARK: - New Login from the list (MACAPP-03)

    /// The list fills passwords (not codes): "Nouveau login" may be offered.
    public var canCreateLogin: Bool {
        guard case .list = screen, listKind == .password else { return false }
        return !session.vaults.isEmpty
    }

    /// A password for a new Login, with the generator profile chosen in the app ("Fort" by default).
    /// The list never sees the page's rules: the profile alone.
    public func generatedPassword() -> String? {
        let profile = GeneratorProfileStore(defaults: session.environment.settings.baseDefaults).profile
        let context = FfiPasswordContext(rules: [], quirkRules: nil, minLength: nil, maxLength: nil, hintText: nil)
        return try? passwordForContext(context: context, profile: profile.ffi).password
    }

    /// The e-mail of the first Identity, to prefill the username of a new Login (nil without one).
    public var suggestedUsername: String? {
        session.items(filter: .all, query: "", sort: .title)
            .first { $0.itemType == .identity && $0.subtitle.contains("@") }?
            .subtitle
    }

    /// "Nouveau login": writes a Login for the request's service (its host's URL, or the App ID for
    /// an app) with `user` and `password` in `vaultID`, then fills both, in one sheet and one unlock.
    /// Ignored (nothing written) unless the list fills passwords, `vaultID` is visible and
    /// `password` is not empty.
    public func createLogin(title: String, user: String, password: String, vaultID: String) async {
        guard !isFinished, session.state == .unlocked, canCreateLogin, isVisibleVault(vaultID),
            !password.isEmpty
        else { return }
        let service = request.primaryService.flatMap { $0.identifier.isEmpty ? nil : $0 }
        do {
            var item = try session.newItem(type: .login, vaultID: vaultID)
            let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
            item.title = trimmed.isEmpty ? (service?.shownName ?? Self.untitled) : trimmed
            Self.setField("username", to: .text(value: user), in: &item)
            Self.setField("password", to: .password(value: password), in: &item)
            if let service {
                if service.isApp {
                    item.apps = [service.identifier]
                } else {
                    let url = "https://\(Self.host(of: service.identifier))"
                    item.urls = [FfiUrl(label: "", url: url, rule: .domain, primary: true)]
                }
            }
            _ = try await session.save(item)
            wrote = true
            await session.publishAutofillIdentitiesNow()
            finish(.password(user: user, password: password))
        } catch {
            recover(finishing: false)
        }
    }

    nonisolated static let untitled = String(localized: "autoFill.newLogin", bundle: VaultKitStrings.bundle)

    /// A passkey of the list: the core signs the assertion. Ignored unless `ref` is offered for
    /// `candidate` on the current `list` screen.
    public func choosePasskey(_ ref: FfiPasskeyRef, in candidate: FfiAutofillCandidate) async {
        guard !isFinished, session.state == .unlocked, let passkey = passkeyRequest,
            listed(candidate)?.passkeys.contains(ref) == true, !Self.offered([ref], for: passkey).isEmpty
        else { return }
        do {
            finish(try await assertion(vaultID: candidate.vaultId, itemID: candidate.itemId, ref: ref, request: passkey))
        } catch {
            recover(finishing: false)
        }
    }

    /// The candidate of the current `list` screen with the same vault and item ids.
    private func listed(_ candidate: FfiAutofillCandidate) -> FfiAutofillCandidate? {
        guard case .list(let matches, let others) = screen else { return nil }
        return (matches + others).first { $0.vaultId == candidate.vaultId && $0.itemId == candidate.itemId }
    }

    /// A vault shown on this device (writes never go to a hidden vault).
    private func isVisibleVault(_ vaultID: String) -> Bool {
        session.vaults.contains { $0.id == vaultID }
    }

    // MARK: - Direct requests

    /// A QuickType suggestion. A record that cannot be filled goes back to the list (passwords,
    /// codes) or ends as `credentialNotFound` (passkeys). A password or a code is filled only while
    /// the Login still matches the identity's `service` (a stale identity store entry, for a Login
    /// whose URL changed since it was published, goes back to the list of that service).
    private func fillDirectly(
        recordID: String, kind: FfiAutofillKind, passkey: PasskeyRequest?, service: AutoFillService?
    ) async throws {
        var item = try await fillableLogin(recordID: recordID)
        let services = [service].compactMap { $0 }.filter { !$0.identifier.isEmpty }
        if kind != .passkey, let found = item, let service = services.first {
            let matching = try await session.autofillCandidates(for: service, includeAll: false)
            if !matching.contains(where: { $0.itemId == found.id && $0.vaultId == found.vaultId }) { item = nil }
        }
        switch kind {
        case .password:
            if let item {
                await noteUse(item, service: services.first)
                finish(passwordResult(item))
            } else {
                screen = try await listScreen(services: services, passkey: nil, oneTimeCode: false)
            }
        case .oneTimeCode:
            if let item, let result = try oneTimeCodeResult(item) {
                await noteUse(item, service: services.first)
                finish(result)
            } else {
                screen = try await listScreen(services: services, passkey: nil, oneTimeCode: true)
            }
        case .passkey:
            // The controller always passes the identity's credential id: no guess among several.
            guard let passkey, !passkey.allowedCredentialIDs.isEmpty, let item else {
                finish(.cancelled(.credentialNotFound))
                return
            }
            let candidates = try await session.autofillCandidates(for: .site(passkey.rpID), includeAll: false)
            guard let candidate = candidates.first(where: { $0.itemId == item.id && $0.vaultId == item.vaultId }),
                let ref = Self.offered(candidate.passkeys, for: passkey).first
            else {
                finish(.cancelled(.credentialNotFound))
                return
            }
            finish(try await assertion(vaultID: item.vaultId, itemID: item.id, ref: ref, request: passkey))
        }
    }

    /// The live Login named by `"<vault id>:<item id>"`, nil when malformed, missing, trashed,
    /// archived, hidden from AutoFill or in a vault hidden on this device.
    private func fillableLogin(recordID: String) async throws -> FfiItem? {
        let parts = recordID.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty,
            !session.hiddenVaultIDs.contains(parts[0])
        else { return nil }
        let item: FfiItem
        do {
            item = try await session.loadItem(vaultID: parts[0], itemID: parts[1])
        } catch {
            // Integrity failure or lock: not a missing record.
            guard session.state == .unlocked else { throw error }
            session.lastError = nil
            return nil
        }
        guard item.itemType == .login, item.trashedAt == nil, !item.archived, !item.hideFromAutofill else {
            return nil
        }
        return item
    }

    /// Remembers a fill of `service` by `item` (site memory: the next plans and identity ranks), before
    /// the credential goes back (the extension may be killed right after). Only when the core wrote
    /// (not throttled) does the request post `store-changed` and publish the new ranks before the
    /// session locks. Best effort: a failure never stops the fill; an integrity failure leaves its
    /// state as for any other call, any other error is cleared. Nil `service` (a Login from `others`,
    /// or a direct request without a service) remembers nothing. True when the identities were
    /// published.
    @discardableResult
    private func noteUse(_ item: FfiItem, service: AutoFillService?) async -> Bool {
        guard let service, !service.identifier.isEmpty, !isFinished else { return false }
        let written: Bool
        do {
            written = try await session.noteAutofillUse(recordID: "\(item.vaultId):\(item.id)", for: service)
        } catch {
            if session.state == .unlocked { session.lastError = nil }
            return false
        }
        guard written else { return false }
        wrote = true
        await session.publishAutofillIdentitiesNow()
        return true
    }

    private func assertion(
        vaultID: String, itemID: String, ref: FfiPasskeyRef, request: PasskeyRequest
    ) async throws -> AutoFillResult {
        let signed = try await session.passkeyAssertion(
            vaultID: vaultID, itemID: itemID, credentialID: ref.credentialId, clientDataHash: request.clientDataHash)
        return .passkeyAssertion(signed, rpID: request.rpID, clientDataHash: request.clientDataHash)
    }

    private func passwordResult(_ item: FfiItem) -> AutoFillResult {
        Self.passwordResult(item)
    }

    /// The username and password of a Login. A Login with neither that signs in with a provider
    /// gives the provider's relay address as the username when it has one, never a made-up
    /// password (spec 2026-11-03-ios-safari-autofill 5): the page's own "Sign in with" button does
    /// the rest.
    static func passwordResult(_ item: FfiItem) -> AutoFillResult {
        let user = fieldValue("username", in: item).flatMap(plainText) ?? ""
        let password = fieldValue("password", in: item).flatMap(plainText) ?? ""
        if user.isEmpty, password.isEmpty {
            let relay = item.loginMethods.lazy.compactMap { method -> String? in
                if case .provider(_, _, let relay?) = method, !relay.isEmpty { return relay }
                return nil
            }.first
            if let relay { return .password(user: relay, password: "") }
        }
        return .password(user: user, password: password)
    }

    /// The current code of the item's `totp` field, nil when it has none.
    private func oneTimeCodeResult(_ item: FfiItem) throws -> AutoFillResult? {
        guard case .otp(let secret)? = Self.fieldValue("totp", in: item), !secret.isEmpty else { return nil }
        return .oneTimeCode(try currentCode(secret))
    }

    private func currentCode(_ secret: String) throws -> String {
        let seconds = max(0, session.environment.clock.now.timeIntervalSince1970)
        return try totpNow(secretOrUri: secret, unixSeconds: UInt64(seconds)).code
    }

    // MARK: - Passkey registration

    private func prepareRegistration(_ registration: PasskeyRegistrationRequest) async throws {
        let candidates = try await session.autofillCandidates(for: .site(registration.rpID), includeAll: false)
        let excluded = Set(registration.excludedCredentialIDs)
        let holdsExcluded = candidates.contains { candidate in
            candidate.passkeys.contains { excluded.contains($0.credentialId) }
        }
        if holdsExcluded {
            finish(.cancelled(.excludedCredential))
            return
        }
        screen = .passkeyRegistration(
            suggestions: candidates.filter { $0.user.isEmpty || $0.user == registration.userName })
    }

    /// Creates the passkey in the Login `itemID`, or in a new Login of `vaultID` (ruling A9: always
    /// after an explicit choice). The key pair stays in the core. Ignored (nothing written, screen
    /// kept) unless `itemID` is nil or one of the shown suggestions in `vaultID`, and `vaultID` is a
    /// visible vault.
    public func registerPasskey(into itemID: String?, vaultID: String) async {
        guard !isFinished, session.state == .unlocked, case .passkeyRegistration(let registration) = request,
            case .passkeyRegistration(let suggestions) = screen, isVisibleVault(vaultID)
        else { return }
        if let itemID, !suggestions.contains(where: { $0.itemId == itemID && $0.vaultId == vaultID }) { return }
        do {
            let created = try await session.createPasskey(FfiPasskeyCreation(
                vaultId: vaultID, itemId: itemID, rpId: registration.rpID, userName: registration.userName,
                userHandle: registration.userHandle, clientDataHash: registration.clientDataHash,
                excludedCredentialIds: registration.excludedCredentialIDs))
            wrote = true
            await session.publishAutofillIdentitiesNow()
            finish(.passkeyRegistration(created, rpID: registration.rpID, clientDataHash: registration.clientDataHash))
        } catch {
            if VaultError(error) == VaultError(OnePassError.PasskeyExcluded) {
                finish(.cancelled(.excludedCredential))
            } else {
                recover(finishing: false)
            }
        }
    }

    // MARK: - Save

    /// Identical to a stored Login (same host, username and password): saved without a sheet (spec 7).
    /// Same site and username with another password: update sheet. Otherwise: new Login sheet.
    /// An app matches the Logins whose `apps` hold its App ID (G1), never a site.
    private func prepareSave(_ save: SavePasswordRequest) async throws {
        let match = try await existingLogin(for: save)
        if match.identical {
            drafts.remove(password: save.password, now: session.environment.clock.now)
            finish(.saved)
            return
        }
        screen = .save(existing: match.sameUser)
    }

    /// The Logins of the save's service with its username: `identical` when one already holds the
    /// password (a site Login must also have a URL of that very host), else the first of them.
    private func existingLogin(for save: SavePasswordRequest) async throws
        -> (identical: Bool, sameUser: FfiAutofillCandidate?)
    {
        let candidates = try await session.autofillCandidates(for: save.typedService, includeAll: false)
        let user = Self.normalizedUser(save.user)
        let sameUser = candidates.filter { Self.normalizedUser($0.user) == user }
        let host = Self.host(of: save.service)
        for candidate in sameUser {
            let item = try await session.loadItem(vaultID: candidate.vaultId, itemID: candidate.itemId)
            let password = Self.fieldValue("password", in: item).flatMap(Self.plainText)
            let sameService = save.serviceIsApp || item.urls.contains { Self.host(of: $0.url) == host }
            if password == save.password, sameService { return (true, nil) }
        }
        return (false, sameUser.first)
    }

    /// Writes `save` without a sheet (a waiting generated password): nothing when a Login already
    /// holds it, else always a new Login (never an overwrite), titled apart when a Login of the same
    /// service and username exists.
    private func store(_ save: SavePasswordRequest, title: String?, vaultID: String) async throws {
        let match = try await existingLogin(for: save)
        if match.identical { return }
        var title = title ?? ""
        if match.sameUser != nil {
            let base = title.isEmpty ? Self.defaultTitle(for: save) : title
            title = String(localized: "autoFill.generatedPasswordTitle \(base)", bundle: VaultKitStrings.bundle)
        }
        try await write(save, title: title, vaultID: vaultID, updating: nil)
    }

    /// The Login write of a save: the new password into `updating` (its old one goes to the history),
    /// or a new Login with the URL of the host (or the App ID for an app) in `vaultID`.
    private func write(_ save: SavePasswordRequest, title: String, vaultID: String, updating itemID: String?) async throws {
        if let itemID {
            var item = try await session.loadItem(vaultID: vaultID, itemID: itemID)
            Self.setField("password", to: .password(value: save.password), in: &item)
            _ = try await session.save(item)
        } else {
            var item = try session.newItem(type: .login, vaultID: vaultID)
            let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
            item.title = trimmed.isEmpty ? Self.defaultTitle(for: save) : trimmed
            Self.setField("username", to: .text(value: save.user), in: &item)
            Self.setField("password", to: .password(value: save.password), in: &item)
            if save.serviceIsApp {
                item.apps = [save.service]
            } else {
                let url = "https://\(Self.host(of: save.service))"
                item.urls = [FfiUrl(label: "", url: url, rule: .domain, primary: true)]
            }
            _ = try await session.save(item)
        }
        wrote = true
        await session.publishAutofillIdentitiesNow()
    }

    /// New Login (`updating` nil): `title` (default `defaultTitle`), URL `https://<host>` (or the app
    /// identifier for an app), username and password, in `vaultID`. Update: the new password replaces
    /// the old one, which goes to the password history (a Login without a password field gets one).
    /// Ignored (nothing written, screen kept) unless `vaultID` is a visible vault and `updating` is
    /// nil or the shown `existing` Login of `vaultID`.
    public func save(title: String, vaultID: String, updating itemID: String?) async {
        guard !isFinished, session.state == .unlocked, case .savePassword(let save) = request,
            case .save(let existing) = screen, isVisibleVault(vaultID)
        else { return }
        if let itemID, existing?.itemId != itemID || existing?.vaultId != vaultID { return }
        do {
            try await write(save, title: title, vaultID: vaultID, updating: itemID)
            drafts.remove(password: save.password, now: session.environment.clock.now)
            finish(.saved)
        } catch {
            recover(finishing: false)
        }
    }

    // MARK: - Text insertion

    /// Every live item of the visible vaults without Crypto Wallets (spec 5.4) nor the items hidden
    /// from AutoFill (ruling X3: never offered): Identities first (signup and address forms are what
    /// text insertion mostly serves), then the rest, each by title.
    private func textItems() async throws -> [FfiItemSummary] {
        let hidden = try await session.autofillHiddenRecordIDs()
        let items = session.items(filter: .all, query: "", sort: .title).filter {
            $0.itemType != .cryptoWallet && !hidden.contains("\($0.vaultId):\($0.id)")
        }
        return items.filter { $0.itemType == .identity } + items.filter { $0.itemType != .identity }
    }

    /// Back from the fields of an item to the item list.
    public func showTextItems() async {
        guard !isFinished, session.state == .unlocked, case .textToInsert = request else { return }
        do {
            let items = try await textItems()
            guard !isFinished else { return }
            screen = .textItems(items)
        } catch {
            recover(finishing: false)
        }
    }

    public func chooseText(item: FfiItemSummary) async {
        guard !isFinished, session.state == .unlocked, case .textToInsert = request,
            item.itemType != .cryptoWallet, !session.hiddenVaultIDs.contains(item.vaultId)
        else { return }
        do {
            let loaded = try await session.loadItem(vaultID: item.vaultId, itemID: item.id)
            guard !isFinished, !loaded.hideFromAutofill else { return }
            screen = .textFields(loaded)
        } catch {
            recover(finishing: false)
        }
    }

    /// The fields of `item` that can be inserted as text: every non-empty text-like field, concealed
    /// ones included (the user picks them explicitly); a date as the numeric date of `locale`; an
    /// address as one text row per non-empty part (id `<field id>.<part>`, the country by its name
    /// when it is a region code). Amounts, files, keys and passkeys are left out.
    public func insertableFields(of item: FfiItem) -> [FfiField] {
        item.sections.flatMap(\.fields).flatMap { field -> [FfiField] in
            switch field.value {
            case .date(let date):
                guard let text = Self.numericDate(date, locale: locale) else { return [] }
                return [Self.textRow(of: field, id: field.id, label: field.displayLabel, text: text)]
            case .address(let address):
                return addressParts(address).map { part, label, text in
                    Self.textRow(of: field, id: "\(field.id).\(part)", label: label, text: text)
                }
            default:
                return insertableText(field.value) == nil ? [] : [field]
            }
        }
    }

    /// Inserts the field's text (the current code for a one-time password field). Only a row
    /// `insertableFields` gives for the item on screen is inserted.
    public func insert(field: FfiField) async {
        guard !isFinished, session.state == .unlocked, case .textFields(let item) = screen,
            insertableFields(of: item).contains(field),
            let text = insertableText(field.value)
        else { return }
        finish(.text(text))
    }

    private static func textRow(of field: FfiField, id: String, label: String, text: String) -> FfiField {
        FfiField(
            id: id, label: label, kind: .text, value: .text(value: text),
            required: false, repeatable: false, autofill: field.autofill)
    }

    /// `12/04/1990` or `04/12/1990`: day, month and four-digit year in the order of `locale`.
    nonisolated static func numericDate(_ date: FfiDate, locale: Locale) -> String? {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .gmt
        guard let day = calendar.date(from: DateComponents(
            year: Int(date.year), month: Int(date.month), day: Int(date.day)))
        else { return nil }
        let formatter = DateFormatter()
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.locale = locale
        formatter.setLocalizedDateFormatFromTemplate("ddMMyyyy")
        return formatter.string(from: day)
    }

    /// The non-empty parts of `address`: (part id, label, text).
    private func addressParts(_ address: FfiAddress) -> [(String, String, String)] {
        let country = address.country.trimmingCharacters(in: .whitespaces)
        let countryName =
            country.count == 2 && country.allSatisfy(\.isLetter)
            ? locale.localizedString(forRegionCode: country.uppercased()) ?? country : country
        let parts: [(String, String, String)] = [
            ("line1", String(localized: "autoFill.address", bundle: VaultKitStrings.bundle), address.line1),
            ("line2", String(localized: "autoFill.addressLine2", bundle: VaultKitStrings.bundle), address.line2),
            ("city", String(localized: "autoFill.city", bundle: VaultKitStrings.bundle), address.city),
            ("postal_code", String(localized: "autoFill.postalCode", bundle: VaultKitStrings.bundle), address.postalCode),
            ("region", String(localized: "autoFill.region", bundle: VaultKitStrings.bundle), address.region),
            ("country", String(localized: "autoFill.country", bundle: VaultKitStrings.bundle), countryName),
        ]
        return parts.filter { !$0.2.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }

    private func insertableText(_ value: FfiFieldValue) -> String? {
        let text: String? =
            switch value {
            case .otp(let secret): secret.isEmpty ? nil : try? currentCode(secret)
            case .number(let number): String(number)
            default: Self.plainText(value)
            }
        return text?.isEmpty == false ? text : nil
    }

    // MARK: - End

    /// Cancel button (and the end of the configuration screen).
    /// On the save sheet, the user's no also drops a waiting generated password of that value (G3).
    public func cancel() {
        if case .savePassword(let save) = request, case .save = screen {
            drafts.remove(password: save.password, service: save.service, now: session.environment.clock.now)
        }
        finish(.cancelled(.userCanceled))
    }

    /// The system dismissed the interface or replaced the request: ends it like `finish` (session
    /// locked, `store-changed` posted if this request wrote) but never calls `complete`, since the
    /// request is no longer the extension's to answer. A pending unlock or write is dropped by the
    /// lock; every later call is ignored.
    public func abandon() {
        guard !isFinished else { return }
        isFinished = true
        screen = .finished
        session.lock(publishPending: false, stampsAccountLock: false)
        if wrote { session.environment.storeChanges.post() }
    }

    private func finish(_ result: AutoFillResult) {
        guard !isFinished else { return }
        isFinished = true
        screen = .finished
        if !keepUnlocked(after: result) { session.lock(publishPending: false, stampsAccountLock: false) }
        // The environment's notifier is `store-changed` in production (tests use their own name).
        if wrote { session.environment.storeChanges.post() }
        onComplete(result)
    }

    // MARK: - Unlock window (90 seconds, same service)

    /// A password or a code filled after Face ID / Touch ID: the session goes to the unlock window
    /// instead of being locked. Everything else (a cancel, a save, a passkey, a master password
    /// unlock, no window) locks as before; the window itself refuses a shared device, the setting
    /// turned off and a request without a service.
    private func keepUnlocked(after result: AutoFillResult) -> Bool {
        // Still the very unlock Face ID made: no lock and no other unlock since.
        guard let unlockWindow, let unlock = biometricUnlock, session.generation == unlock.generation
        else { return false }
        let unlockedAt = unlock.at
        switch result {
        case .password, .oneTimeCode: break
        default: return false
        }
        let services: [AutoFillService] =
            switch request {
            case .credentialList(let services, _): services
            case .oneTimeCodeList(let services): services
            case .credential(_, .password, _, let service?), .credential(_, .oneTimeCode, _, let service?): [service]
            default: []
            }
        return unlockWindow.open(session: session, services: services, method: .biometrics, unlockedAt: unlockedAt)
    }

    /// Answer to `provideCredentialWithoutUserInteraction` inside the unlock window: the password or
    /// the current code of the identity's Login, without interface and without a second Face ID,
    /// when `window` holds a session for the request's service and `account` (nil: the primary one).
    ///
    /// Nil is the normal path (`resultWithoutUserInteraction`, then the interface and Face ID): no
    /// window for that service, a passkey, a request without service, a Login marked `reprompt`,
    /// one that no longer matches the service, or any error. The session stays with the window.
    public static func resultFromUnlockWindow(
        for request: AutoFillRequest, window: AutoFillUnlockWindow, account: String?, ownAppIDs: Set<String>
    ) async -> AutoFillResult? {
        guard case .credential(_, let kind, nil, let service?) = request, kind != .passkey,
            let session = window.session(for: service, kind: kind, account: account)
        else { return nil }
        let model = AutoFillModel(session: session, request: request, ownAppIDs: ownAppIDs) { _ in }
        guard let result = await model.fillFromWindow() else { return nil }
        // Ended while the answer was read (the 90 seconds, a lock): the normal path.
        return window.holds(session) ? result : nil
    }

    /// The fill of a direct request on a session the unlock window keeps: never locks it, never
    /// shows a screen. Nil when the request cannot be answered this way.
    private func fillFromWindow() async -> AutoFillResult? {
        guard !isFinished, session.state == .unlocked,
            case .credential(let recordID, let kind, nil, let service?) = request
        else { return nil }
        do {
            // Extra protection (`reprompt`) always asks; a stale identity falls back to the list.
            guard let item = try await fillableLogin(recordID: recordID), !item.reprompt else { return nil }
            let matching = try await session.autofillCandidates(for: service, includeAll: false)
            guard matching.contains(where: { $0.itemId == item.id && $0.vaultId == item.vaultId }) else { return nil }
            let result: AutoFillResult
            switch kind {
            case .password:
                result = passwordResult(item)
            case .oneTimeCode:
                guard let code = try oneTimeCodeResult(item) else { return nil }
                result = code
            case .passkey:
                return nil
            }
            await noteUse(item, service: service)
            isFinished = true
            screen = .finished
            if wrote { session.environment.storeChanges.post() }
            return result
        } catch {
            if session.state == .unlocked { session.lastError = nil }
            return nil
        }
    }

    // MARK: - Helpers

    /// A username as compared to find the Login of a save request: trimmed, case-insensitive.
    nonisolated static func normalizedUser(_ user: String) -> String {
        user.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    nonisolated private static func isOwnApp(_ save: SavePasswordRequest, _ ownAppIDs: Set<String>) -> Bool {
        save.serviceIsApp && ownAppIDs.contains(save.service)
    }

    /// Lowercased host of a domain or URL (`example.com`, `https://www.example.com/login`).
    nonisolated static func host(of service: String) -> String {
        let trimmed = service.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("://"), let host = URL(string: trimmed)?.host(), !host.isEmpty {
            return host.lowercased()
        }
        if let host = URL(string: "https://" + trimmed)?.host(), !host.isEmpty {
            return host.lowercased()
        }
        return trimmed.lowercased()
    }

    private static func fieldValue(_ id: String, in item: FfiItem) -> FfiFieldValue? {
        item.sections.lazy.flatMap(\.fields).first { $0.id == id }?.value
    }

    /// Sets the field `id`; a missing field is appended to the Login section `main` (created if
    /// needed) with the template's label and kind.
    private static func setField(_ id: String, to value: FfiFieldValue, in item: inout FfiItem) {
        for s in item.sections.indices {
            if let f = item.sections[s].fields.firstIndex(where: { $0.id == id }) {
                item.sections[s].fields[f].value = value
                return
            }
        }
        let (label, kind): (String, FfiFieldType) =
            switch id {
            case "password": ("Mot de passe", .password)
            case "username": ("Identifiant", .text)
            default: (id, .text)
            }
        let field = FfiField(
            id: id, label: label, kind: kind, value: value, required: false, repeatable: false, autofill: true)
        if let main = item.sections.firstIndex(where: { $0.id == "main" }) {
            item.sections[main].fields.append(field)
        } else {
            item.sections.insert(FfiSection(id: "main", label: "Connexion", fields: [field]), at: 0)
        }
    }

    /// The string of a text-like value, nil for any other kind.
    private static func plainText(_ value: FfiFieldValue) -> String? {
        switch value {
        case .text(let v), .concealed(let v), .password(let v), .url(let v), .email(let v), .phone(let v),
            .menu(let v), .mnemonic(let v):
            v
        case .barcode(let v, _):
            v
        default:
            nil
        }
    }
}
