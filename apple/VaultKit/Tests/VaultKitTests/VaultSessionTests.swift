import Foundation
import Testing

@testable import VaultKit

/// One temporary store, fake keychain, Secure Enclave, clock, pasteboard and sync.
@MainActor
final class SessionHarness {
    let dir: URL
    let suite: String
    let keychain = InMemoryKeychain()
    let keyring = FakeEnclaveKeyring()
    let clock = FakeClock()
    let pasteboard = FakePasteboard()
    let sync = RecordingSync()
    let settings: VaultSettings
    let environment: VaultEnvironment

    /// Fast Argon2id parameters, accepted by the dev-fast-kdf test core only.
    static let fastKdf = FfiKdfParams(mKib: 8192, t: 1, p: 1)

    init(dir: URL? = nil) throws {
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
            accountKdf: Self.fastKdf)
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

        // Lock while a save is in flight: whichever wins, nothing stays in memory.
        try await session.unlock(password: testPassword)
        var item = try session.newItem(type: .secureNote, vaultID: session.allVaults[0].id)
        item.title = "Note fictive"
        fillRequired(&item)
        let saving = Task { try await session.save(item) }
        session.lock()
        _ = try? await saving.value
        #expect(session.state == .locked)
        #expect(session.summaries.isEmpty && session.allVaults.isEmpty)
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
        #expect(!VaultError.integrity(kind: "rollback").message.isEmpty)
    }
}
