import Foundation
import Synchronization
import Testing

@testable import VaultKit

private let totpSecret = "JBSWY3DPEHPK3PXP"
private let loginUser = "camille@exemple.fr"
private let loginPassword = "Mot-de-passe-Atlas-7"
private let ownApp = "me.somalabs.onepass"

/// Results passed to `complete`, in order.
@MainActor
private final class Completions {
    var results: [AutoFillResult] = []
}

/// Counts the posts of a notifier.
private final class PostCounter: Sendable {
    let value = Mutex(0)
    var count: Int { value.withLock { $0 } }
}

/// One store with an account, a unique store-changed notification name, and helpers to build models
/// on fresh sessions (one per request, like the extension).
@MainActor
private final class Fixture {
    let h: SessionHarness
    let notifier = StoreChangeNotifier(name: "me.somalabs.onepass.tests.\(UUID().uuidString)")
    let environment: VaultEnvironment
    private var watchers: [Task<Void, Never>] = []

    init(identityStore: (any IdentityStoreClient)? = nil) throws {
        h = try SessionHarness()
        var environment = h.environment
        environment.storeChanges = notifier
        if let identityStore {
            environment.identityStore = identityStore
            // Far beyond the test: only an immediate publication can reach the store.
            environment.identityDebounce = .seconds(600)
        }
        self.environment = environment
    }

    func session() -> VaultSession { VaultSession(environment: environment) }

    /// Account plus a Login `https://example.com` with username, password and TOTP. The seeding
    /// session is returned unlocked.
    func seed() async throws -> (VaultSession, FfiItem) {
        let seed = session()
        _ = try await seed.createAccount(password: testPassword, displayName: "", mode: .personal)
        let login = try await addLogin(seed, title: "Exemple", url: "https://example.com", totp: totpSecret)
        return (seed, login)
    }

    func model(
        _ request: AutoFillRequest, session: VaultSession? = nil, ownAppIDs: Set<String> = [ownApp]
    ) -> (AutoFillModel, VaultSession, Completions) {
        let session = session ?? self.session()
        let completions = Completions()
        let model = AutoFillModel(session: session, request: request, ownAppIDs: ownAppIDs) {
            completions.results.append($0)
        }
        return (model, session, completions)
    }

    func watchPosts() -> PostCounter {
        let counter = PostCounter()
        let stream = notifier.changes()
        watchers.append(Task { for await _ in stream { counter.value.withLock { $0 += 1 } } })
        return counter
    }

    func written() -> Int { h.sync.events.filter { $0 == .written }.count }

    /// A vault hidden on this device holding a Login of `https://example.com` with a passkey.
    func hiddenVaultLogin(_ seed: VaultSession) async throws -> (vaultID: String, login: FfiItem, credential: Data) {
        try await seed.createVault(FfiVaultMeta(
            name: "Caché", icon: "folder", color: "orange", travelSafe: false, mcpAccess: false))
        let vault = try #require(seed.allVaults.first { $0.meta.name == "Caché" })
        let login = try await addLogin(
            seed, title: "Caché", url: "https://example.com", user: "cache", vaultID: vault.id)
        let passkey = try await seed.createPasskey(FfiPasskeyCreation(
            vaultId: vault.id, itemId: login.id, rpId: "example.com", userName: "cache",
            userHandle: Data([5, 6]), clientDataHash: Data(repeating: 9, count: 32), excludedCredentialIds: []))
        seed.setVaultHidden(vault.id, hidden: true)
        #expect(h.settings.hiddenVaultIDs == [vault.id])
        return (vault.id, login, passkey.credentialId)
    }

    func cleanUp() {
        watchers.forEach { $0.cancel() }
        h.cleanUp()
    }
}

/// A Login with username, password, one URL and optionally a TOTP secret.
@MainActor
@discardableResult
private func addLogin(
    _ session: VaultSession, title: String, url: String, user: String = loginUser,
    password: String = loginPassword, totp: String? = nil, vaultID: String? = nil
) async throws -> FfiItem {
    var item = try session.newItem(type: .login, vaultID: vaultID ?? session.allVaults[0].id)
    item.title = title
    for s in item.sections.indices {
        for f in item.sections[s].fields.indices {
            switch item.sections[s].fields[f].id {
            case "username": item.sections[s].fields[f].value = .text(value: user)
            case "password": item.sections[s].fields[f].value = .password(value: password)
            case "totp": if let totp { item.sections[s].fields[f].value = .otp(value: totp) }
            default: break
            }
        }
    }
    item.urls = [FfiUrl(label: "", url: url, rule: .domain, primary: true)]
    fillRequired(&item)
    return try await session.save(item)
}

private func field(_ id: String, in item: FfiItem) -> FfiFieldValue? {
    item.sections.flatMap(\.fields).first { $0.id == id }?.value
}

private func saveRequest(
    service: String, serviceIsApp: Bool = false, user: String = loginUser, password: String,
    title: String? = nil, event: SaveEvent = .formDidDisappear
) -> AutoFillRequest {
    .savePassword(SavePasswordRequest(
        service: service, serviceIsApp: serviceIsApp, user: user, password: password, title: title,
        event: event))
}

private let clientDataHash = Data(repeating: 7, count: 32)

@MainActor
@Suite("AutoFill model")
struct AutoFillModelTests {
    // MARK: - Unlock screens

    @Test func noAccountScreen() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (model, _, done) = f.model(.credentialList(services: ["example.com"], passkey: nil))
        await model.start()
        #expect(model.screen == .noAccount)
        model.cancel()
        #expect(done.results == [.cancelled(.userCanceled)])
        // Later calls are ignored.
        model.cancel()
        #expect(done.results.count == 1)
    }

    @Test func needsSecretKeyScreen() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        seed.lock()
        await seed.waitForReleasedSessions()
        try SecretKeyVault(keychain: f.h.keychain).remove(accountID: try #require(f.h.settings.accountID))

        let (model, session, done) = f.model(.credentialList(services: ["example.com"], passkey: nil))
        await model.start()
        #expect(model.screen == .needsSecretKey)
        model.cancel()
        #expect(done.results == [.cancelled(.userCanceled)])
        #expect(session.state == .locked)
    }

    @Test func integrityFailureScreen() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        seed.lock()
        await seed.waitForReleasedSessions()
        try resetStore(dbPath: f.h.environment.databaseURL.path)

        let (model, _, done) = f.model(.textToInsert)
        await model.start()
        let missing = VaultError.integrity(kind: VaultSession.accountMissingKind)
        #expect(model.screen == .integrityFailure(missing))
        model.cancel()
        #expect(done.results == [.cancelled(.userCanceled)])
    }

    @Test func biometricUnlockOnStart() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        try await seed.enrollBiometrics(password: testPassword)
        seed.lock()

        let (model, _, _) = f.model(.credentialList(services: ["example.com"], passkey: nil))
        await model.start()
        guard case .list(let matches, _) = model.screen else {
            Issue.record("expected the list, got \(model.screen)")
            return
        }
        #expect(matches.first?.itemId == login.id)
    }

    // MARK: - Passwords

    @Test func listAfterPasswordUnlock() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        let other = try await addLogin(seed, title: "Ailleurs", url: "https://ailleurs.org", user: "autre")
        seed.lock()

        let (model, session, done) = f.model(.credentialList(services: ["www.example.com"], passkey: nil))
        await model.start()
        #expect(model.screen == .locked)
        await model.unlock(password: testPassword)
        guard case .list(let matches, let others) = model.screen else {
            Issue.record("expected the list, got \(model.screen)")
            return
        }
        #expect(matches.first?.itemId == login.id)
        #expect(!matches.contains { $0.itemId == other.id })
        #expect(others.map(\.itemId) == [other.id])

        await model.choose(try #require(matches.first))
        #expect(done.results == [.password(user: loginUser, password: loginPassword)])
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty)
    }

    @Test func wrongPasswordStaysLocked() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        seed.lock()

        let (model, session, done) = f.model(.credentialList(services: ["example.com"], passkey: nil))
        await model.start()
        await model.unlock(password: "faux")
        #expect(model.screen == .locked)
        #expect(session.lastError == .wrongPassword)
        #expect(f.h.settings.failedUnlocks == 1)
        #expect(done.results.isEmpty)
    }

    @Test func startingUntilStart() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        seed.lock()

        let (model, _, _) = f.model(.credentialList(services: ["example.com"], passkey: nil))
        #expect(model.screen == .starting)
        await model.start()
        #expect(model.screen == .locked)
    }

    /// The system dismisses the extension while the master password is being checked: the session
    /// ends locked with nothing in memory, and `complete` is never called.
    @Test func abandonDuringUnlockEndsLockedWithoutCompleting() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        seed.lock()

        let (model, session, done) = f.model(.credentialList(services: ["example.com"], passkey: nil))
        await model.start()
        let unlocking = Task { await model.unlock(password: testPassword) }
        while session.state != .unlocking { await Task.yield() }
        model.abandon()
        #expect(model.isFinished)
        #expect(model.screen == .finished)
        await unlocking.value
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty && session.allVaults.isEmpty)
        #expect(model.screen == .finished)

        // Every later call is ignored.
        await model.unlock(password: testPassword)
        model.cancel()
        #expect(session.state == .locked)
        #expect(done.results.isEmpty)
    }

    @Test func directCredentialFillsRecord() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        let trashed = try await addLogin(seed, title: "Ancien", url: "https://example.com", user: "ancien")
        try await seed.trash(itemID: trashed.id, vaultID: trashed.vaultId)
        seed.lock()

        let (model, session, done) = f.model(
            .credential(recordID: "\(login.vaultId):\(login.id)", kind: .password, passkey: nil))
        await model.start()
        await model.unlock(password: testPassword)
        #expect(done.results == [.password(user: loginUser, password: loginPassword)])
        #expect(session.state == .locked)

        // Trashed, missing or malformed record: back to the list.
        for record in ["\(trashed.vaultId):\(trashed.id)", "\(login.vaultId):\(String(repeating: "0", count: 32))", "n'importe quoi"] {
            let (fallback, _, fallbackDone) = f.model(.credential(recordID: record, kind: .password, passkey: nil))
            await fallback.start()
            await fallback.unlock(password: testPassword)
            #expect(fallbackDone.results.isEmpty)
            guard case .list(_, let others) = fallback.screen else {
                Issue.record("expected the list for \(record), got \(fallback.screen)")
                continue
            }
            #expect(others.contains { $0.itemId == login.id })
            #expect(!others.contains { $0.itemId == trashed.id })
            fallback.cancel()
        }
    }

    // MARK: - One-time codes

    @Test func oneTimeCode() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        let noTotp = try await addLogin(seed, title: "Sans code", url: "https://example.com", user: "sans")
        seed.lock()

        let (model, _, done) = f.model(.oneTimeCodeList(services: ["example.com"]))
        await model.start()
        await model.unlock(password: testPassword)
        guard case .list(let matches, let others) = model.screen else {
            Issue.record("expected the list, got \(model.screen)")
            return
        }
        #expect(matches.map(\.itemId) == [login.id])
        #expect(!others.contains { $0.itemId == noTotp.id })

        // A candidate that is not on the screen is ignored.
        var unlisted = try #require(matches.first)
        unlisted.itemId = noTotp.id
        await model.choose(unlisted)
        #expect(done.results.isEmpty)

        await model.choose(try #require(matches.first))
        let expected = try totpNow(
            secretOrUri: totpSecret, unixSeconds: UInt64(f.h.clock.now.timeIntervalSince1970)).code
        #expect(done.results == [.oneTimeCode(expected)])
        #expect(expected.count == 6 && expected.allSatisfy(\.isNumber))
    }

    // MARK: - Passkeys

    @Test func passkeyRegistrationNewAndExisting() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        let vaultID = login.vaultId
        seed.lock()
        let posts = f.watchPosts()

        func registration(excluded: [Data] = [], es256: Bool = true) -> AutoFillRequest {
            .passkeyRegistration(PasskeyRegistrationRequest(
                rpID: "example.com", userName: loginUser, userHandle: Data([1, 2, 3, 4]),
                clientDataHash: clientDataHash, excludedCredentialIDs: excluded, supportsES256: es256))
        }

        // New Login.
        let (fresh, freshSession, freshDone) = f.model(registration())
        await fresh.start()
        await fresh.unlock(password: testPassword)
        let expected = try await suggestions(f, service: "example.com", ids: [login.id])
        #expect(fresh.screen == .passkeyRegistration(suggestions: expected))
        await fresh.registerPasskey(into: nil, vaultID: vaultID)
        guard case .passkeyRegistration(let created, let rpID, let hash) = try #require(freshDone.results.first) else {
            Issue.record("expected a registration, got \(freshDone.results)")
            return
        }
        #expect(created.itemId != login.id)
        #expect(rpID == "example.com" && hash == clientDataHash)
        #expect(freshSession.state == .locked)
        #expect(await eventually { posts.count >= 1 })

        // Into the existing Login.
        let (existing, _, existingDone) = f.model(registration())
        await existing.start()
        await existing.unlock(password: testPassword)
        await existing.registerPasskey(into: login.id, vaultID: vaultID)
        guard case .passkeyRegistration(let added, _, _) = try #require(existingDone.results.first) else {
            Issue.record("expected a registration, got \(existingDone.results)")
            return
        }
        #expect(added.itemId == login.id)

        // No ES256: fails without unlocking.
        let (noES256, noES256Session, noES256Done) = f.model(registration(es256: false))
        await noES256.start()
        #expect(noES256Done.results == [.cancelled(.failed)])
        #expect(noES256Session.state == .locked)

        // Excluded credential.
        let (excluded, _, excludedDone) = f.model(registration(excluded: [added.credentialId]))
        await excluded.start()
        await excluded.unlock(password: testPassword)
        #expect(excludedDone.results == [.cancelled(.excludedCredential)])
    }

    @Test func passkeyAssertionHonoursAllowList() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        let registration = try await seed.createPasskey(FfiPasskeyCreation(
            vaultId: login.vaultId, itemId: login.id, rpId: "example.com", userName: loginUser,
            userHandle: Data([1, 2, 3, 4]), clientDataHash: Data(repeating: 9, count: 32),
            excludedCredentialIds: []))
        seed.lock()
        let unknown = Data([0xDE, 0xAD, 0xBE, 0xEF])

        // An allow list naming another credential: the Login is listed without its passkey.
        let (restricted, _, _) = f.model(.credentialList(
            services: ["example.com"],
            passkey: PasskeyRequest(rpID: "example.com", clientDataHash: clientDataHash, allowedCredentialIDs: [unknown])))
        await restricted.start()
        await restricted.unlock(password: testPassword)
        guard case .list(let restrictedMatches, _) = restricted.screen else {
            Issue.record("expected the list, got \(restricted.screen)")
            return
        }
        #expect(restrictedMatches.first?.itemId == login.id)
        #expect(restrictedMatches.allSatisfy { $0.passkeys.isEmpty })
        // A passkey that is not offered on the screen is ignored.
        let hidden = FfiPasskeyRef(rpId: "example.com", userName: loginUser, credentialId: registration.credentialId)
        await restricted.choosePasskey(hidden, in: try #require(restrictedMatches.first))
        #expect(!restricted.isFinished)
        restricted.cancel()

        // No allow list: the passkey is offered and signs.
        let (open, _, openDone) = f.model(.credentialList(
            services: [],
            passkey: PasskeyRequest(rpID: "example.com", clientDataHash: clientDataHash, allowedCredentialIDs: [])))
        await open.start()
        await open.unlock(password: testPassword)
        guard case .list(let matches, _) = open.screen, let candidate = matches.first,
            let ref = candidate.passkeys.first
        else {
            Issue.record("expected a passkey in the list, got \(open.screen)")
            return
        }
        #expect(ref.credentialId == registration.credentialId)
        await open.choosePasskey(ref, in: candidate)
        guard case .passkeyAssertion(let assertion, let rpID, let hash) = try #require(openDone.results.first) else {
            Issue.record("expected an assertion, got \(openDone.results)")
            return
        }
        #expect(assertion.credentialId == registration.credentialId)
        #expect(rpID == "example.com" && hash == clientDataHash)

        // Direct request: an allow list without this credential, or a missing record.
        let record = "\(login.vaultId):\(login.id)"
        // An empty allow list is no answer for a direct request (the controller always names the credential).
        let missing = "\(login.vaultId):\(String(repeating: "0", count: 32))"
        for (recordID, allowed) in [(record, [unknown]), (record, []), (missing, [registration.credentialId])] {
            let (direct, _, directDone) = f.model(.credential(
                recordID: recordID, kind: .passkey,
                passkey: PasskeyRequest(rpID: "example.com", clientDataHash: clientDataHash, allowedCredentialIDs: allowed)))
            await direct.start()
            await direct.unlock(password: testPassword)
            #expect(directDone.results == [.cancelled(.credentialNotFound)])
        }

        // Direct request with the right credential: signed without a list.
        let (direct, _, directDone) = f.model(.credential(
            recordID: record, kind: .passkey,
            passkey: PasskeyRequest(
                rpID: "example.com", clientDataHash: clientDataHash, allowedCredentialIDs: [registration.credentialId])))
        await direct.start()
        await direct.unlock(password: testPassword)
        guard case .passkeyAssertion(let signed, _, _) = try #require(directDone.results.first) else {
            Issue.record("expected an assertion, got \(directDone.results)")
            return
        }
        #expect(signed.credentialId == registration.credentialId)
    }

    // MARK: - Save

    @Test func saveOwnAppIsSilent() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        seed.lock()
        await seed.waitForSyncNotifications()
        let posts = f.watchPosts()
        let events = f.h.sync.events

        let own = saveRequest(service: ownApp, serviceIsApp: true, password: "nouveau")
        #expect(AutoFillModel.resultWithoutUserInteraction(for: own, ownAppIDs: [ownApp]) == .saved)
        #expect(AutoFillModel.resultWithoutUserInteraction(
            for: saveRequest(service: "com.autre.app", serviceIsApp: true, password: "x"), ownAppIDs: [ownApp])
            == .cancelled(.userInteractionRequired))
        #expect(AutoFillModel.resultWithoutUserInteraction(
            for: saveRequest(service: "example.com", password: "x", event: .generatedPasswordFilled), ownAppIDs: [ownApp])
            == .saved)
        #expect(AutoFillModel.resultWithoutUserInteraction(
            for: .credentialList(services: ["example.com"], passkey: nil), ownAppIDs: [ownApp])
            == .cancelled(.userInteractionRequired))

        // With the interface: ends at once, never unlocked.
        let (model, session, done) = f.model(own)
        await model.start()
        #expect(done.results == [.saved])
        #expect(session.state == .locked)
        await session.waitForSyncNotifications()
        try await Task.sleep(for: .milliseconds(300))
        #expect(f.h.sync.events == events)
        #expect(posts.count == 0)
    }

    @Test func generatedPasswordFilledIsSilent() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        seed.lock()
        await seed.waitForSyncNotifications()
        let events = f.h.sync.events

        let (model, session, done) = f.model(
            saveRequest(service: "example.com", password: "Genere-789", event: .generatedPasswordFilled))
        await model.start()
        #expect(done.results == [.saved])
        #expect(session.state == .locked)
        await session.waitForSyncNotifications()
        #expect(f.h.sync.events == events)
    }

    @Test func saveIdenticalIsSilent() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        seed.lock()
        await seed.waitForSyncNotifications()
        let posts = f.watchPosts()
        let writes = f.written()

        let (model, session, done) = f.model(saveRequest(service: "example.com", password: loginPassword))
        await model.start()
        #expect(model.screen == .locked)
        await model.unlock(password: testPassword)
        #expect(done.results == [.saved])
        #expect(session.state == .locked)
        await session.waitForSyncNotifications()
        try await Task.sleep(for: .milliseconds(300))
        #expect(f.written() == writes)
        #expect(posts.count == 0)
    }

    @Test func saveNewAndUpdate() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        seed.lock()
        let posts = f.watchPosts()

        // New account.
        let (fresh, _, freshDone) = f.model(saveRequest(service: "nouveau.exemple.fr", password: "Neuf-123"))
        await fresh.start()
        await fresh.unlock(password: testPassword)
        #expect(fresh.screen == .save(existing: nil))
        await fresh.save(title: "", vaultID: login.vaultId, updating: nil)
        #expect(freshDone.results == [.saved])
        #expect(await eventually { posts.count >= 1 })

        // Same username, other password: update.
        let (update, _, updateDone) = f.model(saveRequest(service: "example.com", password: "Change-456"))
        await update.start()
        await update.unlock(password: testPassword)
        guard case .save(let existing?) = update.screen else {
            Issue.record("expected the update sheet, got \(update.screen)")
            return
        }
        #expect(existing.itemId == login.id)
        await update.save(title: "", vaultID: existing.vaultId, updating: existing.itemId)
        #expect(updateDone.results == [.saved])

        let check = f.session()
        try await check.unlock(password: testPassword)
        let created = try #require(check.summaries.first { $0.title == "nouveau.exemple.fr" })
        let item = try await check.loadItem(vaultID: created.vaultId, itemID: created.id)
        #expect(item.itemType == .login)
        #expect(item.urls.map(\.url) == ["https://nouveau.exemple.fr"])
        #expect(field("username", in: item) == .text(value: loginUser))
        #expect(field("password", in: item) == .password(value: "Neuf-123"))

        let updated = try await check.loadItem(vaultID: login.vaultId, itemID: login.id)
        #expect(field("password", in: updated) == .password(value: "Change-456"))
        let history = try await check.passwordHistory(vaultID: login.vaultId, itemID: login.id)
        #expect(!history.isEmpty)
        check.lock()
    }

    // MARK: - Text insertion

    @Test func textInsertionSkipsCryptoWallet() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        var walletDraft = try seed.newItem(type: .cryptoWallet, vaultID: login.vaultId)
        walletDraft.title = "Portefeuille"
        for s in walletDraft.sections.indices {
            for i in walletDraft.sections[s].fields.indices where walletDraft.sections[s].fields[i].id == "recovery_phrase" {
                walletDraft.sections[s].fields[i].value = .mnemonic(
                    value: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            }
        }
        fillRequired(&walletDraft)
        let wallet = try await seed.save(walletDraft)
        seed.lock()

        let (model, session, done) = f.model(.textToInsert)
        await model.start()
        await model.unlock(password: testPassword)
        guard case .textItems(let items) = model.screen else {
            Issue.record("expected the items, got \(model.screen)")
            return
        }
        #expect(items.contains { $0.id == login.id })
        #expect(!items.contains { $0.id == wallet.id || $0.itemType == .cryptoWallet })

        await model.chooseText(item: try #require(items.first { $0.id == login.id }))
        guard case .textFields(let item) = model.screen else {
            Issue.record("expected the fields, got \(model.screen)")
            return
        }
        let fields = model.insertableFields(of: item)
        #expect(fields.contains { $0.id == "password" })
        await model.insert(field: try #require(fields.first { $0.id == "username" }))
        #expect(done.results == [.text(loginUser)])
        #expect(session.state == .locked)
        // Nothing from the vault stays on the model.
        #expect(model.screen == .finished)
    }

    // MARK: - Guards on writes

    @Test func writesRequireShownTargets() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        let other = try await addLogin(seed, title: "Ailleurs", url: "https://ailleurs.org", user: "autre")
        let hidden = try await f.hiddenVaultLogin(seed)
        seed.lock()
        await seed.waitForSyncNotifications()
        let writes = f.written()

        // Passkey into a Login that is not a suggestion, or into a hidden vault: nothing written.
        let (registration, _, registrationDone) = f.model(.passkeyRegistration(PasskeyRegistrationRequest(
            rpID: "example.com", userName: loginUser, userHandle: Data([1]), clientDataHash: clientDataHash,
            excludedCredentialIDs: [], supportsES256: true)))
        await registration.start()
        await registration.unlock(password: testPassword)
        let shown = registration.screen
        await registration.registerPasskey(into: other.id, vaultID: other.vaultId)
        await registration.registerPasskey(into: hidden.login.id, vaultID: hidden.vaultID)
        await registration.registerPasskey(into: nil, vaultID: hidden.vaultID)
        await registration.registerPasskey(into: login.id, vaultID: hidden.vaultID)
        #expect(registrationDone.results.isEmpty)
        #expect(registration.screen == shown)
        registration.cancel()

        // New-Login sheet: no update of an arbitrary item, no hidden vault.
        let (fresh, _, freshDone) = f.model(saveRequest(service: "nouveau.exemple.fr", password: "Neuf-123"))
        await fresh.start()
        await fresh.unlock(password: testPassword)
        #expect(fresh.screen == .save(existing: nil))
        await fresh.save(title: "", vaultID: login.vaultId, updating: login.id)
        await fresh.save(title: "", vaultID: hidden.vaultID, updating: nil)
        #expect(freshDone.results.isEmpty)
        #expect(fresh.screen == .save(existing: nil))
        fresh.cancel()

        // Update sheet: only the shown Login, in its own vault.
        let (update, _, updateDone) = f.model(saveRequest(service: "example.com", password: "Change-456"))
        await update.start()
        await update.unlock(password: testPassword)
        guard case .save(let existing?) = update.screen else {
            Issue.record("expected the update sheet, got \(update.screen)")
            return
        }
        await update.save(title: "", vaultID: other.vaultId, updating: other.id)
        await update.save(title: "", vaultID: hidden.vaultID, updating: existing.itemId)
        #expect(updateDone.results.isEmpty)
        update.cancel()

        let check = f.session()
        await check.waitForSyncNotifications()
        #expect(f.written() == writes)
        try await check.unlock(password: testPassword)
        let otherNow = try await check.loadItem(vaultID: other.vaultId, itemID: other.id)
        #expect(field("password", in: otherNow) == .password(value: loginPassword))
        let loginNow = try await check.loadItem(vaultID: login.vaultId, itemID: login.id)
        #expect(field("password", in: loginNow) == .password(value: loginPassword))
        #expect(!check.summaries.contains { $0.title == "nouveau.exemple.fr" })
        check.lock()
    }

    @Test func updateAddsMissingPasswordField() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        var draft = try seed.newItem(type: .login, vaultID: seed.allVaults[0].id)
        draft.title = "Sans mot de passe"
        for s in draft.sections.indices {
            draft.sections[s].fields.removeAll { $0.id == "password" }
            for i in draft.sections[s].fields.indices where draft.sections[s].fields[i].id == "username" {
                draft.sections[s].fields[i].value = .text(value: "sans-mdp")
            }
        }
        draft.urls = [FfiUrl(label: "", url: "https://sans.exemple.fr", rule: .domain, primary: true)]
        fillRequired(&draft)
        let bare = try await seed.save(draft)
        #expect(field("password", in: bare) == nil)
        seed.lock()

        let (model, _, done) = f.model(saveRequest(service: "sans.exemple.fr", user: "sans-mdp", password: "Ajout-1"))
        await model.start()
        await model.unlock(password: testPassword)
        guard case .save(let existing?) = model.screen else {
            Issue.record("expected the update sheet, got \(model.screen)")
            return
        }
        await model.save(title: "", vaultID: existing.vaultId, updating: existing.itemId)
        #expect(done.results == [.saved])

        let check = f.session()
        try await check.unlock(password: testPassword)
        let item = try await check.loadItem(vaultID: bare.vaultId, itemID: bare.id)
        #expect(field("password", in: item) == .password(value: "Ajout-1"))
        check.lock()
    }

    // MARK: - Hidden vaults

    @Test func hiddenVaultRecordsAreNotFilled() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        let hidden = try await f.hiddenVaultLogin(seed)
        seed.lock()
        let record = "\(hidden.vaultID):\(hidden.login.id)"

        // Password: back to the list, without the hidden Login.
        let (password, _, passwordDone) = f.model(.credential(recordID: record, kind: .password, passkey: nil))
        await password.start()
        await password.unlock(password: testPassword)
        #expect(passwordDone.results.isEmpty)
        guard case .list(let matches, let others) = password.screen else {
            Issue.record("expected the list, got \(password.screen)")
            return
        }
        #expect(others.contains { $0.itemId == login.id })
        #expect(!(matches + others).contains { $0.itemId == hidden.login.id })
        password.cancel()

        // Passkey: not found.
        let (passkey, _, passkeyDone) = f.model(.credential(
            recordID: record, kind: .passkey,
            passkey: PasskeyRequest(rpID: "example.com", clientDataHash: clientDataHash, allowedCredentialIDs: [hidden.credential])))
        await passkey.start()
        await passkey.unlock(password: testPassword)
        #expect(passkeyDone.results == [.cancelled(.credentialNotFound)])

        // Text insertion: the hidden vault's items are not listed.
        let (text, _, _) = f.model(.textToInsert)
        await text.start()
        await text.unlock(password: testPassword)
        guard case .textItems(let items) = text.screen else {
            Issue.record("expected the items, got \(text.screen)")
            return
        }
        #expect(items.contains { $0.id == login.id })
        #expect(!items.contains { $0.vaultId == hidden.vaultID })
        text.cancel()
    }

    // MARK: - Final fix wave

    /// Ruling: a Login holding a passkey whose rp id is the requested host is a candidate even
    /// without a matching URL (the system verified the rp id).
    @Test func passkeyOfLoginWithoutURLIsFoundByRpID() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, _) = try await f.seed()
        var draft = try seed.newItem(type: .login, vaultID: seed.allVaults[0].id)
        draft.title = "Sans URL"
        fillRequired(&draft)
        let bare = try await seed.save(draft)
        let registration = try await seed.createPasskey(FfiPasskeyCreation(
            vaultId: bare.vaultId, itemId: bare.id, rpId: "passkeys.exemple.org", userName: "dominique",
            userHandle: Data([7, 7]), clientDataHash: Data(repeating: 9, count: 32), excludedCredentialIds: []))
        #expect(try await seed.loadItem(vaultID: bare.vaultId, itemID: bare.id).urls.isEmpty)
        seed.lock()
        let passkey = PasskeyRequest(
            rpID: "passkeys.exemple.org", clientDataHash: clientDataHash,
            allowedCredentialIDs: [registration.credentialId])

        let (direct, session, done) = f.model(
            .credential(recordID: "\(bare.vaultId):\(bare.id)", kind: .passkey, passkey: passkey))
        await direct.start()
        await direct.unlock(password: testPassword)
        guard case .passkeyAssertion(let signed, let rpID, _) = try #require(done.results.first) else {
            Issue.record("expected an assertion, got \(done.results)")
            return
        }
        #expect(signed.credentialId == registration.credentialId)
        #expect(rpID == "passkeys.exemple.org")
        #expect(session.state == .locked)

        // The manual list offers it among the matches too.
        let (list, _, _) = f.model(.credentialList(services: [], passkey: passkey))
        await list.start()
        await list.unlock(password: testPassword)
        guard case .list(let matches, _) = list.screen else {
            Issue.record("expected the list, got \(list.screen)")
            return
        }
        #expect(matches.map(\.itemId) == [bare.id])
        #expect(matches.first?.passkeys.map(\.credentialId) == [registration.credentialId])
        list.cancel()
    }

    /// A write of the extension reaches the system identity store before its session locks, without
    /// waiting for the debounce (which would then find the session locked).
    @Test func writesPublishIdentitiesBeforeLocking() async throws {
        let store = InMemoryIdentityStore()
        let f = try Fixture(identityStore: store)
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        seed.lock()
        await seed.waitForAutofillIdentities()
        #expect(store.identities.isEmpty)

        let (registration, registrationSession, registrationDone) = f.model(.passkeyRegistration(
            PasskeyRegistrationRequest(
                rpID: "example.com", userName: loginUser, userHandle: Data([1, 2, 3, 4]),
                clientDataHash: clientDataHash, excludedCredentialIDs: [], supportsES256: true)))
        await registration.start()
        await registration.unlock(password: testPassword)
        await registration.registerPasskey(into: login.id, vaultID: login.vaultId)
        guard case .passkeyRegistration(let created, _, _) = try #require(registrationDone.results.first) else {
            Issue.record("expected a registration, got \(registrationDone.results)")
            return
        }
        #expect(registrationSession.state == .locked)
        #expect(store.identities.contains { $0.kind == .passkey && $0.credentialId == created.credentialId })

        let (save, saveSession, saveDone) = f.model(saveRequest(service: "nouveau.exemple.fr", password: "Neuf-123"))
        await save.start()
        await save.unlock(password: testPassword)
        await save.save(title: "", vaultID: login.vaultId, updating: nil)
        #expect(saveDone.results == [.saved])
        #expect(saveSession.state == .locked)
        #expect(store.identities.contains { $0.kind == .password && $0.service == "nouveau.exemple.fr" })
        #expect(store.identities.contains { $0.kind == .passkey && $0.credentialId == created.credentialId })
    }

    /// Ruling X3: an item hidden from AutoFill is never offered, text insertion included.
    @Test func textInsertionSkipsItemsHiddenFromAutofill() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        var hidden = try await addLogin(seed, title: "Cachée", url: "https://cache.exemple.fr", user: "cache")
        hidden.hideFromAutofill = true
        hidden = try await seed.save(hidden)
        var noteDraft = try seed.newItem(type: .secureNote, vaultID: login.vaultId)
        noteDraft.title = "Note cachée"
        noteDraft.hideFromAutofill = true
        fillRequired(&noteDraft)
        let note = try await seed.save(noteDraft)
        seed.lock()

        let (model, _, _) = f.model(.textToInsert)
        await model.start()
        await model.unlock(password: testPassword)
        guard case .textItems(let items) = model.screen else {
            Issue.record("expected the items, got \(model.screen)")
            return
        }
        #expect(items.contains { $0.id == login.id })
        #expect(!items.contains { $0.id == hidden.id || $0.id == note.id })

        // Not on the list, and refused if asked anyway.
        var forged = try #require(items.first { $0.id == login.id })
        forged.id = hidden.id
        await model.chooseText(item: forged)
        #expect(model.screen == .textItems(items))

        await model.showTextItems()
        #expect(model.screen == .textItems(items))
        model.cancel()
    }

    /// A QuickType suggestion fills only while the Login still matches the identity's service: a
    /// stale identity (URL changed since it was published) goes back to the list.
    @Test func directFillRechecksTheService() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        seed.lock()
        let record = "\(login.vaultId):\(login.id)"

        let (current, _, currentDone) = f.model(
            .credential(recordID: record, kind: .password, passkey: nil, service: "example.com"))
        await current.start()
        await current.unlock(password: testPassword)
        #expect(currentDone.results == [.password(user: loginUser, password: loginPassword)])

        for kind in [FfiAutofillKind.password, .oneTimeCode] {
            let (stale, _, staleDone) = f.model(
                .credential(recordID: record, kind: kind, passkey: nil, service: "ancien.exemple.org"))
            await stale.start()
            await stale.unlock(password: testPassword)
            #expect(staleDone.results.isEmpty)
            guard case .list(let matches, let others) = stale.screen else {
                Issue.record("expected the list, got \(stale.screen)")
                continue
            }
            #expect(matches.isEmpty)
            #expect(others.contains { $0.itemId == login.id })
            stale.cancel()
        }
    }

    /// "Mettre à jour" finds the Login whatever the case and surrounding spaces of the username.
    @Test func saveFindsTheAccountCaseInsensitively() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (seed, login) = try await f.seed()
        seed.lock()

        let (update, _, _) = f.model(saveRequest(
            service: "example.com", user: "  Camille@Exemple.FR ", password: "Change-456"))
        await update.start()
        await update.unlock(password: testPassword)
        guard case .save(let existing?) = update.screen else {
            Issue.record("expected the update sheet, got \(update.screen)")
            return
        }
        #expect(existing.itemId == login.id)
        update.cancel()

        // Same password with another case of the username: identical, closed after the unlock.
        let (identical, _, identicalDone) = f.model(saveRequest(
            service: "example.com", user: "CAMILLE@exemple.fr", password: loginPassword))
        await identical.start()
        await identical.unlock(password: testPassword)
        #expect(identicalDone.results == [.saved])
    }

    /// Ruling: a conditional passkey registration (automatic upgrade) fails without interface.
    @Test func conditionalRegistrationFails() {
        let request = AutoFillRequest.passkeyRegistration(PasskeyRegistrationRequest(
            rpID: "example.com", userName: loginUser, userHandle: Data([1]), clientDataHash: clientDataHash,
            excludedCredentialIDs: [], supportsES256: true))
        #expect(AutoFillModel.resultWithoutUserInteraction(for: request, ownAppIDs: [ownApp]) == .cancelled(.failed))
        #expect(
            AutoFillModel.resultWithoutUserInteraction(for: .credentialList(services: [], passkey: nil), ownAppIDs: [])
                == .cancelled(.userInteractionRequired))
    }

    @Test func configurationNeedsNoUnlock() async throws {
        let f = try Fixture()
        defer { f.cleanUp() }
        let (model, _, done) = f.model(.configuration)
        await model.start()
        #expect(model.screen == .configuration)
        model.cancel()
        #expect(done.results == [.cancelled(.userCanceled)])
    }
}

/// The candidates of `service` restricted to `ids`, in order (expected suggestions).
@MainActor
private func suggestions(_ f: Fixture, service: String, ids: [String]) async throws -> [FfiAutofillCandidate] {
    let reader = f.session()
    try await reader.unlock(password: testPassword)
    defer { reader.lock() }
    return try await reader.autofillCandidates(service: service, includeAll: false)
        .filter { ids.contains($0.itemId) }
}
