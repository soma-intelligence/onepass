import Foundation
import Synchronization
import Testing

@testable import VaultKit

/// One temporary store, fake keychain, Secure Enclave, clock, pasteboard and sync.
@MainActor
final class SessionHarness {
    let dir: URL
    let suite: String
    let keychain: any KeychainStore
    let keyring = FakeEnclaveKeyring()
    let clock = FakeClock()
    let pasteboard = FakePasteboard()
    let sync = RecordingSync()
    let presence = FakePresence()
    let settings: VaultSettings
    let environment: VaultEnvironment

    /// Fast Argon2id parameters, accepted by the dev-fast-kdf test core only.
    static let fastKdf = FfiKdfParams(mKib: 8192, t: 1, p: 1)

    init(dir: URL? = nil, keychain: any KeychainStore = InMemoryKeychain()) throws {
        self.keychain = keychain
        let dir = dir ?? FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-session-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.dir = dir
        suite = "onepass.tests.\(UUID().uuidString)"
        settings = VaultSettings(defaults: UserDefaults(suiteName: suite)!)
        environment = VaultEnvironment(
            databaseURL: dir.appendingPathComponent("vault.sqlite"),
            keychain: keychain,
            biometrics: BiometricUnlock(keyring: keyring, keychain: keychain, clock: clock),
            settings: settings,
            sync: sync,
            clock: clock,
            pasteboard: pasteboard,
            accountKdf: Self.fastKdf,
            presence: presence)
    }

    func makeSession() -> VaultSession { VaultSession(environment: environment) }

    func cleanUp() {
        UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: dir)
    }
}

let testPassword = "Cheval agrafe 42 !"

@MainActor
@discardableResult
func addItem(
    _ session: VaultSession, title: String, type: FfiItemType = .secureNote, vaultID: String? = nil,
    tags: [String] = [], favorite: Bool = false
) async throws -> FfiItem {
    let vault = vaultID ?? session.allVaults[0].id
    var item = try session.newItem(type: type, vaultID: vault)
    item.title = title
    item.tags = tags
    item.favorite = favorite
    fillRequired(&item)
    return try await session.save(item)
}

/// Fictitious values for the template's required fields.
func fillRequired(_ item: inout FfiItem) {
    for s in item.sections.indices {
        for f in item.sections[s].fields.indices where item.sections[s].fields[f].required {
            let field = item.sections[s].fields[f]
            guard field.value == .empty else { continue }
            item.sections[s].fields[f].value = switch field.kind {
            case .concealed: .concealed(value: "valeur-fictive")
            case .password: .password(value: "motdepasse-fictif")
            case .email: .email(value: "camille.durand@exemple.fr")
            case .url: .url(value: "https://exemple.fr")
            default: .text(value: "Camille Durand")
            }
        }
    }
}

@MainActor
@Suite("Vault session")
struct VaultSessionTests {
    /// Messages are compared in French, the source language, whatever the machine's language.
    init() { VaultKitStrings.pinSourceLanguage() }

    /// The AutoFill extension must not create the shared store before the app migrated into it.
    @Test func missingStoreIsNoAccountAndIsNotCreated() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        #expect(session.state == .noAccount)
        await session.refresh()
        await session.reload()
        #expect(session.state == .noAccount)
        #expect(!FileManager.default.fileExists(atPath: h.environment.databaseURL.path))
    }

    /// Milestone 2's account lookup in the store (settings wiped) must not open, hence create, a
    /// missing store: an unlock with no account id and no store fails and leaves no file.
    @Test func unlockWithoutAccountIDNeverCreatesTheStore() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        #expect(h.settings.accountID == nil)
        await #expect(throws: VaultError.self) { try await session.unlock(password: testPassword) }
        #expect(!FileManager.default.fileExists(atPath: h.environment.databaseURL.path))
    }

    /// A store the app could not put in place (split by a failed migration): the session stays failed,
    /// "Réessayer" never opens or creates a store.
    @Test func refusedStoreStaysFailed() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        let failure = VaultError.other("Stockage indisponible")
        session.refuseStore(failure)
        #expect(session.state == .failed(failure))
        await session.refresh()
        await session.reload()
        #expect(session.state == .failed(failure))
        await #expect(throws: VaultError.self) { try await session.unlock(password: testPassword) }
        #expect(!FileManager.default.fileExists(atPath: h.environment.databaseURL.path))
    }

    @Test func createAccountStoresSecretKeyAndUnlocks() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        #expect(session.state == .noAccount)

        let secretKey = try await session.createAccount(
            password: testPassword, displayName: "Camille Durand", mode: .personal)
        #expect(session.state == .unlocked)
        let accountID = try #require(h.settings.accountID)
        #expect(try SecretKeyVault(keychain: h.keychain).load(accountID: accountID) == secretKey)
        #expect(h.settings.displayName == "Camille Durand")
        #expect(session.vaults.map(\.meta.name) == ["Personnel"])

        try await addItem(session, title: "Projet Atlas")
        #expect(session.summaries.map(\.title) == ["Projet Atlas"])

        session.lock()
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty && session.vaults.isEmpty && session.recents.isEmpty)

        try await session.unlock(password: testPassword)
        #expect(session.state == .unlocked)
        #expect(session.summaries.map(\.title) == ["Projet Atlas"])

        // A second session on the same store sees the account.
        let other = h.makeSession()
        #expect(other.state == .locked)
        await #expect(throws: VaultError.accountExists) {
            _ = try await other.createAccount(password: "autre", displayName: "", mode: .personal)
        }

        await session.waitForSyncNotifications()
        #expect(h.sync.events == [.unlocked, .written, .locked, .unlocked])
    }

    @Test func wrongPasswordCountsAndLocksOut() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()

        for attempt in 1...5 {
            await #expect(throws: VaultError.wrongPassword) { try await session.unlock(password: "faux") }
            #expect(h.settings.failedUnlocks == attempt)
            #expect(session.state == .locked)
        }
        #expect(h.settings.lockoutUntil == h.clock.now.addingTimeInterval(30))
        let until = try #require(h.settings.lockoutUntil)
        // Even the right password is refused before any Rust call.
        await #expect(throws: VaultError.lockedOut(until: until)) {
            try await session.unlock(password: testPassword)
        }
        #expect(h.settings.failedUnlocks == 5)

        h.clock.advance(31)
        await #expect(throws: VaultError.wrongPassword) { try await session.unlock(password: "faux") }
        #expect(h.settings.lockoutUntil == h.clock.now.addingTimeInterval(60))

        h.clock.advance(61)
        await #expect(throws: VaultError.wrongPassword) { try await session.unlock(password: "faux") }
        #expect(h.settings.lockoutUntil == h.clock.now.addingTimeInterval(300))

        h.clock.advance(301)
        await #expect(throws: VaultError.wrongPassword) { try await session.unlock(password: "faux") }
        #expect(h.settings.lockoutUntil == h.clock.now.addingTimeInterval(300))

        h.clock.advance(301)
        try await session.unlock(password: testPassword)
        #expect(session.state == .unlocked)
        #expect(h.settings.failedUnlocks == 0)
        #expect(h.settings.lockoutUntil == nil)
    }

    @Test func passwordIsNotTrimmed() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: " mot de passe ", displayName: "", mode: .personal)
        session.lock()
        await #expect(throws: VaultError.wrongPassword) { try await session.unlock(password: "mot de passe") }
        try await session.unlock(password: " mot de passe ")
        #expect(session.state == .unlocked)
    }

    @Test func lockDuringUnlockEndsLocked() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(session, title: "Projet Atlas")
        session.lock()

        let unlocking = Task { try await session.unlock(password: testPassword) }
        while session.state != .unlocking { await Task.yield() }
        session.lock()
        try await unlocking.value
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty && session.allVaults.isEmpty)

        // Lock while a save is held inside its core call.
        try await session.unlock(password: testPassword)
        var item = try session.newItem(type: .secureNote, vaultID: session.allVaults[0].id)
        item.title = "Note fictive"
        fillRequired(&item)
        let gate = CoreGate()
        session.coreWorkHook = gate.hook
        let saving = Task { try await session.save(item) }
        try await gate.waitUntilEntered()
        session.coreWorkHook = nil
        session.lock()
        #expect(session.state == .locked)
        gate.release()
        await #expect(throws: VaultError.passwordRequired) { _ = try await saving.value }
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty && session.allVaults.isEmpty && session.recents.isEmpty)
    }

    @Test func autoLockAfterDelayInBackground() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        #expect(h.settings.effectiveAutoLockSeconds == 900)

        session.scenePhaseChanged(.background)
        h.clock.advance(600)
        session.scenePhaseChanged(.active)
        #expect(session.state == .unlocked)

        session.scenePhaseChanged(.background)
        h.clock.advance(901)
        session.scenePhaseChanged(.active)
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty)

        // Inactivity in the foreground, reset by activity.
        try await session.unlock(password: testPassword)
        h.clock.advance(800)
        session.noteActivity()
        h.clock.advance(800)
        session.checkAutoLock()
        #expect(session.state == .unlocked)
        h.clock.advance(101)
        session.checkAutoLock()
        #expect(session.state == .locked)

        // "Jamais": never locks by itself.
        h.settings.autoLockDelay = .never
        try await session.unlock(password: testPassword)
        session.scenePhaseChanged(.background)
        h.clock.advance(86_400)
        session.scenePhaseChanged(.active)
        session.checkAutoLock()
        #expect(session.state == .unlocked)
    }

    /// M5: still in the background (a background task tick or a remote notification wake), the
    /// expired delay locks without waiting for the return to the foreground.
    @Test func backgroundWakePastTheDelayLocks() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.copy("valeur-fictive", concealed: true)
        session.scenePhaseChanged(.background)
        h.clock.advance(600)
        session.checkAutoLock()
        #expect(session.state == .unlocked)
        h.clock.advance(301)
        session.checkAutoLock()
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty && h.pasteboard.snapshot.contents == nil)
    }

    @Test func sharedModeAutoLocksAfterFiveMinutes() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        h.settings.autoLockDelay = .oneHour
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .shared)
        #expect(h.settings.deviceMode == .shared)
        #expect(!session.canUseBiometrics)

        h.clock.advance(299)
        session.checkAutoLock()
        #expect(session.state == .unlocked)
        h.clock.advance(2)
        session.checkAutoLock()
        #expect(session.state == .locked)

        try await session.unlock(password: testPassword)
        session.scenePhaseChanged(.background)
        h.clock.advance(301)
        session.scenePhaseChanged(.active)
        #expect(session.state == .locked)
    }

    @Test func filtersExcludeArchiveAndTrash() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let vault = session.allVaults[0].id
        let plain = try await addItem(session, title: "Banque fictive", type: .login)
        let favorite = try await addItem(session, title: "Atelier", tags: ["travail"], favorite: true)
        let archived = try await addItem(session, title: "Ancien badge")
        let trashed = try await addItem(session, title: "Brouillon")
        try await session.archive(itemID: archived.id, vaultID: vault)
        try await session.trash(itemID: trashed.id, vaultID: vault)

        func ids(_ filter: ItemFilter) -> Set<String> {
            Set(session.items(filter: filter, query: "", sort: .title).map(\.id))
        }
        #expect(ids(.all) == [plain.id, favorite.id])
        #expect(ids(.favorites) == [favorite.id])
        #expect(ids(.vault(vault)) == [plain.id, favorite.id])
        #expect(ids(.category(.login)) == [plain.id])
        #expect(ids(.tag("travail")) == [favorite.id])
        #expect(ids(.archive) == [archived.id])
        #expect(ids(.trash) == [trashed.id])
        #expect(session.items(filter: .all, query: "", sort: .title).map(\.title) == ["Atelier", "Banque fictive"])

        let counts = session.counts()
        #expect(counts.all == 2)
        #expect(counts.favorites == 1)
        #expect(counts.archive == 1)
        #expect(counts.trash == 1)
        #expect(counts.byVault[vault] == 2)
        #expect(counts.byType[.login] == 1)
        #expect(counts.byType[.secureNote] == 1)
        #expect(counts.byTag["travail"] == 1)

        try await session.restoreItem(itemID: trashed.id, vaultID: vault)
        try await session.unarchive(itemID: archived.id, vaultID: vault)
        try await session.setFavorite(false, itemID: favorite.id, vaultID: vault)
        #expect(ids(.all).count == 4)
        #expect(ids(.favorites).isEmpty)
        try await session.deletePermanently(itemID: plain.id, vaultID: vault)
        #expect(ids(.all).count == 3)

        let loaded = try await session.loadItem(vaultID: vault, itemID: favorite.id)
        #expect(loaded.title == "Atelier")
        #expect(session.recents == [favorite.id])
    }

    @Test func searchIgnoresAccentsAndCase() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(session, title: "Électricité Générale", tags: ["Maison"])
        try await addItem(session, title: "Projet Atlas")
        let found = session.items(filter: .all, query: "  electricite MAISON ", sort: .title)
        #expect(found.map(\.title) == ["Électricité Générale"])
        #expect(session.items(filter: .all, query: "atlas electricite", sort: .title).isEmpty)
    }

    @Test func hiddenVaultsAreNotListed() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .shared)
        try await session.createVault(FfiVaultMeta(
            name: "Projet Atlas", icon: "briefcase", color: "orange", travelSafe: false, mcpAccess: false))
        let atlas = try #require(session.allVaults.first { $0.meta.name == "Projet Atlas" })
        try await addItem(session, title: "Accès chantier", vaultID: atlas.id)
        #expect(session.vaults.count == 2)

        session.setVaultHidden(atlas.id, hidden: true)
        #expect(session.vaults.map(\.meta.name) == ["Personnel"])
        #expect(session.allVaults.count == 2)
        #expect(session.items(filter: .all, query: "", sort: .title).isEmpty)
        #expect(session.counts().all == 0)
        #expect(h.settings.hiddenVaultIDs == [atlas.id])

        try await session.updateVault(id: atlas.id, meta: FfiVaultMeta(
            name: "Projet Atlas 2", icon: "briefcase", color: "orange", travelSafe: false, mcpAccess: false))
        #expect(session.allVaults.contains { $0.meta.name == "Projet Atlas 2" })

        session.setVaultHidden(atlas.id, hidden: false)
        #expect(session.vaults.count == 2)
    }

    @Test func restoreOnSecondDatabaseWithSameRecords() async throws {
        let first = try SessionHarness()
        defer { first.cleanUp() }
        let session = first.makeSession()
        let secretKey = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await addItem(session, title: "Projet Atlas")
        session.lock()
        await session.waitForReleasedSessions()

        let second = try SessionHarness()
        defer { second.cleanUp() }
        for suffix in ["", "-wal", "-shm"] {
            let source = URL(fileURLWithPath: first.environment.databaseURL.path + suffix)
            guard FileManager.default.fileExists(atPath: source.path) else { continue }
            try FileManager.default.copyItem(
                at: source, to: URL(fileURLWithPath: second.environment.databaseURL.path + suffix))
        }
        let restored = second.makeSession()
        #expect(restored.state == .locked)
        #expect(restored.needsSecretKey)
        await #expect(throws: VaultError.wrongPassword) {
            try await restored.restore(secretKey: secretKey, password: "faux")
        }
        // Typed form: upper case, no dashes.
        let typed = secretKey.uppercased().replacingOccurrences(of: "-", with: " ")
        try await restored.restore(secretKey: typed, password: testPassword)
        #expect(restored.state == .unlocked)
        #expect(restored.summaries.map(\.title) == ["Projet Atlas"])
        #expect(!restored.needsSecretKey)
        let accountID = try #require(second.settings.accountID)
        #expect(try SecretKeyVault(keychain: second.keychain).load(accountID: accountID) == secretKey)
    }

    @Test func biometricUnlockFallsBackToPassword() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        #expect(!session.canUseBiometrics)
        await #expect(throws: VaultError.wrongPassword) { try await session.enrollBiometrics(password: "faux") }
        try await session.enrollBiometrics(password: testPassword)
        #expect(session.canUseBiometrics)
        #expect(h.settings.biometricsWanted)

        session.lock()
        try await session.unlockWithBiometrics()
        #expect(session.state == .unlocked)

        // Reboot: the enrollment is dropped and the password field is shown.
        session.lock()
        h.clock.reboot()
        await #expect(throws: VaultError.passwordRequired) { try await session.unlockWithBiometrics() }
        #expect(session.state == .locked)
        #expect(!session.canUseBiometrics)

        // The next password unlock enrolls again (biometrics still wanted).
        try await session.unlock(password: testPassword)
        #expect(session.canUseBiometrics)

        // Shared mode forbids biometrics and drops the enrollment.
        session.setDeviceMode(.shared)
        #expect(!session.canUseBiometrics)
        session.lock()
        await #expect(throws: VaultError.biometricsUnavailable) { try await session.unlockWithBiometrics() }
        #expect(session.state == .locked)
    }

    @Test func switchingToSharedClearsBiometricsWanted() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await session.enrollBiometrics(password: testPassword)
        #expect(h.settings.biometricsWanted)

        session.setDeviceMode(.shared)
        #expect(!h.settings.biometricsWanted)
        session.setDeviceMode(.personal)
        session.lock()
        try await session.unlock(password: testPassword)
        #expect(!session.canUseBiometrics)
    }

    @Test func lastVisibleVaultCannotBeHidden() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .shared)
        try await session.createVault(FfiVaultMeta(
            name: "Projet Atlas", icon: "briefcase", color: "orange", travelSafe: false, mcpAccess: false))
        let ids = session.allVaults.map(\.id)
        session.setVaultHidden(ids[0], hidden: true)
        session.setVaultHidden(ids[1], hidden: true)
        #expect(session.vaults.map(\.id) == [ids[1]])
        #expect(h.settings.hiddenVaultIDs == [ids[0]])
    }

    @Test func copyUsesConcealedLocalPasteboard() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        session.copy("valeur-fictive", concealed: true)
        #expect(h.pasteboard.snapshot.contents == "valeur-fictive")
        #expect(h.pasteboard.snapshot.concealed)
        #expect(h.pasteboard.snapshot.expiresAfter == 90)
    }

    @Test func coreErrorsMapWithoutValues() {
        #expect(VaultError(OnePassError.WrongPassword) == .wrongPassword)
        #expect(VaultError(OnePassError.Integrity(kind: "rollback")) == .integrity(kind: "rollback"))
        #expect(VaultError(OnePassError.Validation(field: "title", reason: "vide")) == .validation(field: "title", reason: "vide"))
        #expect(VaultError(OnePassError.Locked) == .passwordRequired)
        #expect(VaultError(OnePassError.Conflict) == .conflict)
        #expect(VaultError(BiometricError.passwordRequired(reason: .rebooted)) == .passwordRequired)
        #expect(!VaultError.integrity(kind: "rollback").localizedMessage.isEmpty)
        #expect(VaultError(OnePassError.InvalidInput(what: "account exists")) == .accountExists)
        #expect(VaultError(OnePassError.InvalidInput(what: "passkey")).localizedMessage == "Clé d'accès inconnue.")
        #expect(VaultError.validation(field: "content", reason: "is required").localizedMessage == "Champ obligatoire")
        #expect(VaultError.validation(field: "number", reason: "is not a valid card number").localizedMessage == "Numéro de carte invalide")
        #expect(VaultError.validation(field: "iban", reason: "is not a valid IBAN").localizedMessage == "IBAN invalide")
        #expect(VaultError.validation(field: "phrase", reason: "is not a valid recovery phrase").localizedMessage == "Phrase de récupération invalide")
        #expect(VaultError.validation(field: "nir", reason: "is not a valid national number").localizedMessage == "Numéro invalide")
        #expect(VaultError.validation(field: "title", reason: "must not be empty").localizedMessage == "Ne peut pas être vide")
        #expect(VaultError.validation(field: "x", reason: "something new").localizedMessage == "Valeur invalide")
    }
}

/// Holds a core call on its thread until released.
final class CoreGate: Sendable {
    private let entered = Mutex(false)
    private let semaphore = DispatchSemaphore(value: 0)

    var hook: @Sendable () -> Void {
        { [self] in
            entered.withLock { $0 = true }
            semaphore.wait()
        }
    }

    func waitUntilEntered() async throws {
        while !entered.withLock({ $0 }) { try await Task.sleep(for: .milliseconds(2)) }
    }

    func release() { semaphore.signal() }
}

@MainActor
@Suite("Vault session hardening")
struct VaultSessionHardeningTests {
    /// Messages are compared in French, the source language, whatever the machine's language.
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func concurrentPasswordChecksCannotBypassLockout() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()
        h.settings.failedUnlocks = 4

        let gate = CoreGate()
        session.coreWorkHook = gate.hook
        let first = Task { try await session.unlock(password: "faux") }
        try await gate.waitUntilEntered()
        session.coreWorkHook = nil
        await #expect(throws: VaultError.other("Une vérification du mot de passe est déjà en cours.")) {
            try await session.unlock(password: "faux")
        }
        gate.release()
        await #expect(throws: VaultError.wrongPassword) { try await first.value }
        #expect(h.settings.failedUnlocks == 5)
        let until = try #require(h.settings.lockoutUntil)
        await #expect(throws: VaultError.lockedOut(until: until)) { try await session.unlock(password: testPassword) }
    }

    /// Ruling R1: copying then switching app to paste must work, so leaving the foreground keeps
    /// the copied secret; the lock and the 90 s expiry still clear it.
    @Test func backgroundKeepsTheCopiedSecretUntilLockOrExpiry() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.copy("valeur-fictive", concealed: true)
        session.scenePhaseChanged(.inactive)
        session.scenePhaseChanged(.background)
        #expect(h.pasteboard.snapshot.contents == "valeur-fictive")
        session.lock()
        #expect(h.pasteboard.snapshot.contents == nil)

        try await session.unlock(password: testPassword)
        session.copy("valeur-fictive", concealed: true)
        session.scenePhaseChanged(.background)
        h.clock.advance(60)
        session.scenePhaseChanged(.active)
        #expect(h.pasteboard.snapshot.contents == "valeur-fictive")
        session.scenePhaseChanged(.background)
        h.clock.advance(31)
        session.scenePhaseChanged(.active)
        #expect(h.pasteboard.snapshot.contents == nil)
        #expect(session.state == .unlocked)
    }

    /// Revealed values are masked again when the scene goes to the background and on lock (views
    /// watch `concealGeneration`); `.inactive` masks too on iOS and visionOS, not on macOS (ruling
    /// R2); coming back to the foreground reveals nothing.
    @Test func revealResetsOnBackgroundAndLock() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        var last = session.concealGeneration

        session.scenePhaseChanged(.inactive)
        #if os(macOS)
        #expect(session.concealGeneration == last)
        #else
        #expect(session.concealGeneration != last)
        #endif
        last = session.concealGeneration

        session.scenePhaseChanged(.background)
        #expect(session.concealGeneration != last)
        last = session.concealGeneration

        session.scenePhaseChanged(.active)
        #expect(session.concealGeneration == last)

        session.lock()
        #expect(session.concealGeneration != last)
    }

    @Test func lockClearsOurClipboardValue() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.copy("valeur-fictive", concealed: true)
        session.lock()
        #expect(h.pasteboard.snapshot.contents == nil)

        try await session.unlock(password: testPassword)
        session.copy("valeur-fictive", concealed: true)
        h.pasteboard.externalWrite("copié ailleurs")
        session.lock()
        #expect(h.pasteboard.snapshot.contents == "copié ailleurs")
    }

    @Test func createAccountFailsWhenSecretKeyCannotBeStored() async throws {
        let h = try SessionHarness(keychain: FailingWriteKeychain())
        defer { h.cleanUp() }
        let session = h.makeSession()
        await #expect(throws: VaultError.other(VaultSession.secretKeyNotStoredOnCreate)) {
            _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        }
        #expect(session.state == .noAccount)
        #expect(session.summaries.isEmpty)
        #expect(!h.sync.events.contains(.unlocked))
        #expect(h.settings.accountID == nil)
        #expect(try !hasAccount(dbPath: h.environment.databaseURL.path))
        #expect(h.makeSession().state == .noAccount)
    }

    /// A Secret Key that cannot be read back is not stored: the creation is undone, never an
    /// account that asks for the Emergency Kit at the first lock.
    @Test func createAccountFailsWhenSecretKeyCannotBeReadBack() async throws {
        let h = try SessionHarness(keychain: WriteOnlyKeychain())
        defer { h.cleanUp() }
        let session = h.makeSession()
        await #expect(throws: VaultError.other(VaultSession.secretKeyNotStoredOnCreate)) {
            _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        }
        #expect(session.state == .noAccount)
        #expect(h.settings.accountID == nil)
        #expect(try !hasAccount(dbPath: h.environment.databaseURL.path))
    }

    @Test func lockWithSecretKeyPresentAsksOnlyThePassword() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()
        #expect(session.state == .locked)
        #expect(!session.needsSecretKey)
        await session.waitForReleasedSessions()
        let relaunched = h.makeSession()
        #expect(relaunched.state == .locked)
        #expect(!relaunched.needsSecretKey)
    }

    /// Bug 4: each Secret Key mistake has its own message, never "Valeur invalide".
    @Test func restoreExplainsSecretKeyMistakes() async throws {
        let first = try SessionHarness()
        defer { first.cleanUp() }
        let session = first.makeSession()
        let secretKey = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()
        await session.waitForReleasedSessions()
        let accountID = try #require(first.settings.accountID)
        try SecretKeyVault(keychain: first.keychain).remove(accountID: accountID)
        let restored = first.makeSession()
        #expect(restored.needsSecretKey)

        let format = VaultError.validation(field: "secretKey", reason: VaultError.secretKeyFormat)
        await #expect(throws: format) {
            try await restored.restore(secretKey: String(secretKey.dropLast(3)), password: testPassword)
        }
        await #expect(throws: format) {
            try await restored.restore(secretKey: "é" + String(secretKey.dropFirst()), password: testPassword)
        }
        #expect(format.localizedMessage
            == "Format de Secret Key incorrect : 53 caractères attendus (lettres et chiffres).")

        // One character changed: the check character catches it.
        var typo = Array(secretKey)
        typo[0] = typo[0] == "A" ? "C" : "A"
        let checksum = VaultError.validation(field: "secretKey", reason: VaultError.secretKeyChecksum)
        await #expect(throws: checksum) {
            try await restored.restore(secretKey: String(typo), password: testPassword)
        }
        #expect(checksum.localizedMessage
            == "Cette Secret Key contient une faute de frappe : vérifie chaque caractère sur ton Emergency Kit.")

        // A well formed key of another account.
        let other = try SessionHarness()
        defer { other.cleanUp() }
        let otherKey = try await other.makeSession().createAccount(
            password: testPassword, displayName: "", mode: .personal)
        await #expect(throws: VaultError.wrongPassword) {
            try await restored.restore(secretKey: otherKey, password: testPassword)
        }
        #expect(VaultError.wrongPassword.restoreMessage
            == "Cette Secret Key ne correspond pas à ce compte, ou le mot de passe est faux.")
        #expect(restored.state == .locked)
    }

    /// Review I3: the app's defaults were wiped but the store and the keychain still hold the
    /// account: the account id is read from the store, the lock screen asks the password only.
    @Test func wipedDefaultsWithKeyPresentAskOnlyThePassword() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        let accountID = try #require(h.settings.accountID)
        session.lock()
        await session.waitForReleasedSessions()

        UserDefaults(suiteName: h.suite)?.removePersistentDomain(forName: h.suite)
        #expect(h.settings.accountID == nil)
        let relaunched = h.makeSession()
        #expect(relaunched.state == .locked)
        #expect(!relaunched.needsSecretKey)
        try await relaunched.unlock(password: testPassword)
        #expect(relaunched.state == .unlocked)
        #expect(h.settings.accountID == accountID)
    }

    /// Bug 2: a device without the Secret Key can start over (after the typed confirmation).
    @Test func resetIsAllowedWhenTheSecretKeyIsMissing() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        session.lock()
        await #expect(throws: VaultError.other(VaultSession.recoveryRefused)) {
            try await session.resetForRecovery()
        }
        #expect(session.state == .locked)
        await session.waitForReleasedSessions()

        let accountID = try #require(h.settings.accountID)
        try SecretKeyVault(keychain: h.keychain).remove(accountID: accountID)
        let relaunched = h.makeSession()
        #expect(relaunched.needsSecretKey)
        try await relaunched.resetForRecovery()
        #expect(relaunched.state == .noAccount)
        #expect(!relaunched.needsSecretKey)
        #expect(h.settings.accountID == nil)
        #expect(try !hasAccount(dbPath: h.environment.databaseURL.path))
    }

    /// I2: the undone creation empties the store in place; a sync handle opened before (the app's
    /// coordinator) keeps working on the same file and sees the next, successful creation.
    @Test func undoneCreationResetsTheStoreUnderAnOpenHandle() async throws {
        let keychain = FailingWriteKeychain()
        let h = try SessionHarness(keychain: keychain)
        defer { h.cleanUp() }
        let handle = try openSyncStore(dbPath: h.environment.databaseURL.path)
        let session = h.makeSession()
        await #expect(throws: VaultError.other(VaultSession.secretKeyNotStoredOnCreate)) {
            _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        }
        #expect(session.state == .noAccount)
        #expect(FileManager.default.fileExists(atPath: h.environment.databaseURL.path))
        #expect(try handle.storeState() == .empty)
        #expect(try handle.pendingChanges().isEmpty)

        keychain.failWrites(false)
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        #expect(session.state == .unlocked)
        #expect(try handle.storeState() == .account)
        #expect(try !handle.pendingChanges().isEmpty)
    }

    /// C1: the store loses the account this device knew. The session reports an integrity failure,
    /// never `noAccount` (which would lead to creating a second account over the first).
    @Test func vanishedAccountIsAnIntegrityFailureNotNoAccount() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()
        await session.waitForReleasedSessions()

        try resetStore(dbPath: h.environment.databaseURL.path)
        await session.reload()
        let missing = VaultError.integrity(kind: VaultSession.accountMissingKind)
        #expect(session.state == .failed(missing))
        #expect(session.lastError == missing)
        #expect(h.makeSession().state == .failed(missing))
        await session.refresh()
        #expect(session.state == .failed(missing))
        #expect(missing.localizedMessage == "Données refusées : Le compte a disparu du stockage.")
    }

    /// I1: the throwaway password check never writes the device state. A save made while the check is
    /// in flight keeps its newer `last_seen` on disk: a later replay of the older manifest is never
    /// taken as the vault's state (spec 3.1: the device serves its verified copy, item included).
    @Test func passwordCheckKeepsTheNewerLastSeenOnDisk() async throws {
        let remote = InMemoryRemote()
        let a = try SyncDevice(remote: remote, name: "A")
        defer { a.cleanUp() }
        _ = try await a.session.createAccount(password: testPassword, displayName: "", mode: .personal)
        await a.sync()
        let vaultID = try #require(a.session.allVaults.first?.id)
        let manifest = RecordName(kind: 6, id: vaultID)
        let oldVersion = try #require(await remote.record(manifest)?.version)

        let gate = CoreGate()
        a.session.coreWorkHook = gate.hook
        let checking = Task { try await a.session.verifyMasterPassword(testPassword) }
        try await gate.waitUntilEntered()
        a.session.coreWorkHook = nil
        try await addItem(a.session, title: "Projet Atlas")
        gate.release()
        try await checking.value
        await a.sync()
        #expect(await remote.record(manifest)?.version != oldVersion)

        a.session.lock()
        await a.session.waitForReleasedSessions()
        await remote.replay(name: manifest, version: oldVersion)
        await a.coordinator.syncNow()
        try await a.session.unlock(password: testPassword)
        #expect(Set(a.session.summaries.map(\.title)) == ["Projet Atlas"])
        await a.sync()
        #expect(await a.coordinator.status == .waitingForServer)
    }

    @Test func restoreIsCancelledWhenSecretKeyCannotBeStored() async throws {
        let first = try SessionHarness()
        defer { first.cleanUp() }
        let session = first.makeSession()
        let secretKey = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()
        await session.waitForReleasedSessions()

        let keychain = FailingWriteKeychain()
        let second = try SessionHarness(keychain: keychain)
        defer { second.cleanUp() }
        for suffix in ["", "-wal", "-shm"] {
            let source = URL(fileURLWithPath: first.environment.databaseURL.path + suffix)
            guard FileManager.default.fileExists(atPath: source.path) else { continue }
            try FileManager.default.copyItem(
                at: source, to: URL(fileURLWithPath: second.environment.databaseURL.path + suffix))
        }
        let restored = second.makeSession()
        await #expect(throws: VaultError.other(VaultSession.secretKeyNotStoredOnRestore)) {
            try await restored.restore(secretKey: secretKey, password: testPassword)
        }
        #expect(restored.state == .locked)
        #expect(restored.needsSecretKey)
        #expect(!second.sync.events.contains(.unlocked))
        // The store is kept: once the keychain works, the restore goes through.
        keychain.failWrites(false)
        try await restored.restore(secretKey: secretKey, password: testPassword)
        #expect(restored.state == .unlocked)
    }

    @Test func unavailableKeychainIsNotAMissingSecretKey() async throws {
        let keychain = FailingReadKeychain()
        let h = try SessionHarness(keychain: keychain)
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()

        keychain.failReads(true)
        let relaunched = h.makeSession()
        #expect(relaunched.state == .locked)
        #expect(!relaunched.needsSecretKey)
        await #expect(throws: VaultError.other(KeychainError.unexpectedStatus(-25308).message)) {
            try await relaunched.unlock(password: testPassword)
        }
        #expect(!relaunched.needsSecretKey)
        #expect(relaunched.state == .locked)

        keychain.failReads(false)
        let accountID = try #require(h.settings.accountID)
        try SecretKeyVault(keychain: keychain).remove(accountID: accountID)
        #expect(h.makeSession().needsSecretKey)
    }

    @Test func storeErrorKeepsBiometricEnrollment() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await session.enrollBiometrics(password: testPassword)
        session.lock()
        await session.waitForReleasedSessions()

        // The store disappears (moved away): not a rejected AUK, the enrollment stays.
        let fm = FileManager.default
        let db = h.environment.databaseURL.path
        let aside = h.dir.appendingPathComponent("aside", isDirectory: true)
        try fm.createDirectory(at: aside, withIntermediateDirectories: true)
        let suffixes = ["", "-wal", "-shm"].filter { fm.fileExists(atPath: db + $0) }
        for suffix in suffixes {
            try fm.moveItem(atPath: db + suffix, toPath: aside.appendingPathComponent("vault.sqlite" + suffix).path)
        }
        await #expect(throws: VaultError.self) { try await session.unlockWithBiometrics() }
        #expect(session.state != .unlocked)
        #expect(h.environment.biometrics.isEnrolled(accountID: try #require(h.settings.accountID)))

        for suffix in ["", "-wal", "-shm"] where fm.fileExists(atPath: db + suffix) {
            try fm.removeItem(atPath: db + suffix)
        }
        for suffix in suffixes {
            try fm.moveItem(atPath: aside.appendingPathComponent("vault.sqlite" + suffix).path, toPath: db + suffix)
        }
        await session.refresh()
        try await session.unlockWithBiometrics()
        #expect(session.state == .unlocked)
    }
}
