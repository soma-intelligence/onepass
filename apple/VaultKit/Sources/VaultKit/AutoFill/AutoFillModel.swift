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

    @ObservationIgnored private let session: VaultSession
    @ObservationIgnored private let request: AutoFillRequest
    @ObservationIgnored private let ownAppIDs: Set<String>
    @ObservationIgnored private let onComplete: (AutoFillResult) -> Void
    @ObservationIgnored private var wrote = false
    /// The service each Login of the current list matched (`"<vault id>:<item id>"` to service): what a
    /// fill from the list remembers. `others` are not in it.
    @ObservationIgnored private var listedServices: [String: String] = [:]

    /// `ownAppIDs`: the containing app's bundle identifier, with and without the team prefix.
    public init(
        session: VaultSession, request: AutoFillRequest, ownAppIDs: Set<String>,
        complete: @escaping (AutoFillResult) -> Void
    ) {
        self.session = session
        self.request = request
        self.ownAppIDs = ownAppIDs
        onComplete = complete
    }

    /// Answer to a `...WithoutUserInteraction` call (no session: the extension is never unlocked
    /// outside a request). A save coming from OnePass itself, or of a generated password just filled,
    /// ends as saved without writing; a conditional passkey registration (automatic upgrade by the
    /// site) fails, since a passkey is never created without an explicit choice (ruling A9); everything
    /// else asks for the interface. Never nil today.
    nonisolated public static func resultWithoutUserInteraction(
        for request: AutoFillRequest, ownAppIDs: Set<String>
    ) -> AutoFillResult? {
        switch request {
        case .savePassword(let save) where isOwnApp(save, ownAppIDs) || save.event == .generatedPasswordFilled:
            return .saved
        case .passkeyRegistration:
            return .cancelled(.failed)
        default:
            return .cancelled(.userInteractionRequired)
        }
    }

    /// Default title of a saved Login: the system's suggestion, else the service host.
    nonisolated public static func defaultTitle(for request: SavePasswordRequest) -> String {
        if let title = request.title?.trimmingCharacters(in: .whitespacesAndNewlines), !title.isEmpty {
            return title
        }
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
        case .savePassword(let save) where Self.isOwnApp(save, ownAppIDs) || save.event == .generatedPasswordFilled:
            // Own app, or a generated password just filled (the next event carries the same value).
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
        try? await session.unlockWithBiometrics()
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

    /// Unlocked: the screen of the request, or a direct answer.
    private func proceed() async {
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
                screen = .configuration
            }
        } catch {
            recover(finishing: true)
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
    private func listScreen(services: [String], passkey: PasskeyRequest?, oneTimeCode: Bool) async throws -> Screen {
        var matches: [FfiAutofillCandidate] = []
        var seen = Set<String>()
        var served: [String: String] = [:]
        if let passkey {
            for candidate in try await session.autofillCandidates(service: passkey.rpID, includeAll: false) {
                let offered = offering(candidate)
                if !offered.passkeys.isEmpty, seen.insert(offered.itemId).inserted { matches.append(offered) }
            }
        }
        for service in services {
            let candidates = try await session.autofillCandidates(service: service, includeAll: false)
            // The plan only orders: without it, the candidates' order.
            let ranked = await plan(service: service, oneTimeCode: oneTimeCode).map { Self.ordered(candidates, by: $0) }
            for candidate in ranked ?? candidates where seen.insert(candidate.itemId).inserted {
                matches.append(offering(candidate))
                served["\(candidate.vaultId):\(candidate.itemId)"] = service
            }
        }
        let anchor = services.first ?? passkey?.rpID ?? ""
        var others = try await session.autofillCandidates(service: anchor, includeAll: true)
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
    private func plan(service: String, oneTimeCode: Bool) async -> FfiAutofillPlan? {
        do {
            return try await session.autofillPlan(service: service, request: oneTimeCode ? .oneTimeCode : .password)
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
    public func choose(_ candidate: FfiAutofillCandidate) async {
        guard !isFinished, session.state == .unlocked, let kind = listKind, listed(candidate) != nil else { return }
        do {
            let item = try await session.loadItem(vaultID: candidate.vaultId, itemID: candidate.itemId)
            let service = listedServices["\(candidate.vaultId):\(candidate.itemId)"]
            if kind == .oneTimeCode {
                guard let result = try oneTimeCodeResult(item) else {
                    finish(.cancelled(.credentialNotFound))
                    return
                }
                await noteUse(item, service: service)
                finish(result)
            } else {
                await noteUse(item, service: service)
                finish(passwordResult(item))
            }
        } catch {
            recover(finishing: false)
        }
    }

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
        recordID: String, kind: FfiAutofillKind, passkey: PasskeyRequest?, service: String?
    ) async throws {
        var item = try await fillableLogin(recordID: recordID)
        let services = [service].compactMap { $0 }.filter { !$0.isEmpty }
        if kind != .passkey, let found = item, let service = services.first {
            let matching = try await session.autofillCandidates(service: service, includeAll: false)
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
            let candidates = try await session.autofillCandidates(service: passkey.rpID, includeAll: false)
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
    /// or a direct request without a service) remembers nothing.
    private func noteUse(_ item: FfiItem, service: String?) async {
        guard let service, !service.isEmpty, !isFinished else { return }
        let written: Bool
        do {
            written = try await session.noteAutofillUse(recordID: "\(item.vaultId):\(item.id)", service: service)
        } catch {
            if session.state == .unlocked { session.lastError = nil }
            return
        }
        guard written else { return }
        wrote = true
        await session.publishAutofillIdentitiesNow()
    }

    private func assertion(
        vaultID: String, itemID: String, ref: FfiPasskeyRef, request: PasskeyRequest
    ) async throws -> AutoFillResult {
        let signed = try await session.passkeyAssertion(
            vaultID: vaultID, itemID: itemID, credentialID: ref.credentialId, clientDataHash: request.clientDataHash)
        return .passkeyAssertion(signed, rpID: request.rpID, clientDataHash: request.clientDataHash)
    }

    private func passwordResult(_ item: FfiItem) -> AutoFillResult {
        .password(
            user: Self.fieldValue("username", in: item).flatMap(Self.plainText) ?? "",
            password: Self.fieldValue("password", in: item).flatMap(Self.plainText) ?? "")
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
        let candidates = try await session.autofillCandidates(service: registration.rpID, includeAll: false)
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
    private func prepareSave(_ save: SavePasswordRequest) async throws {
        // An app identifier is no domain: no site match for it.
        let candidates =
            save.serviceIsApp ? [] : try await session.autofillCandidates(service: save.service, includeAll: false)
        let user = Self.normalizedUser(save.user)
        let sameUser = candidates.filter { Self.normalizedUser($0.user) == user }
        let host = Self.host(of: save.service)
        for candidate in sameUser {
            let item = try await session.loadItem(vaultID: candidate.vaultId, itemID: candidate.itemId)
            let password = Self.fieldValue("password", in: item).flatMap(Self.plainText)
            if password == save.password, item.urls.contains(where: { Self.host(of: $0.url) == host }) {
                finish(.saved)
                return
            }
        }
        screen = .save(existing: sameUser.first)
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
            finish(.saved)
        } catch {
            recover(finishing: false)
        }
    }

    // MARK: - Text insertion

    /// Every live item of the visible vaults, by title, without Crypto Wallets (spec 5.4) nor the
    /// items hidden from AutoFill (ruling X3: never offered).
    private func textItems() async throws -> [FfiItemSummary] {
        let hidden = try await session.autofillHiddenRecordIDs()
        return session.items(filter: .all, query: "", sort: .title).filter {
            $0.itemType != .cryptoWallet && !hidden.contains("\($0.vaultId):\($0.id)")
        }
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
    /// ones included (the user picks them explicitly). Dates, addresses, amounts, files, keys and
    /// passkeys are left out.
    public func insertableFields(of item: FfiItem) -> [FfiField] {
        item.sections.flatMap(\.fields).filter { insertableText($0.value) != nil }
    }

    /// Inserts the field's text (the current code for a one-time password field).
    public func insert(field: FfiField) async {
        guard !isFinished, session.state == .unlocked, case .textFields(let item) = screen,
            item.sections.contains(where: { $0.fields.contains(field) }),
            let text = insertableText(field.value)
        else { return }
        finish(.text(text))
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
    public func cancel() {
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
        session.lock()
        if wrote { session.environment.storeChanges.post() }
    }

    private func finish(_ result: AutoFillResult) {
        guard !isFinished else { return }
        isFinished = true
        screen = .finished
        session.lock()
        // The environment's notifier is `store-changed` in production (tests use their own name).
        if wrote { session.environment.storeChanges.post() }
        onComplete(result)
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
