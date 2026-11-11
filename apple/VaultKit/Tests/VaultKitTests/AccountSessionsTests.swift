import Foundation
import Testing

@testable import VaultKit

/// One device with a primary account store and the added accounts of the directory, all on the same
/// fake keychain and Secure Enclave (the entries are named by account id, multi-account spec 2).
@MainActor
final class AccountsHarness {
    let folder: URL
    let suite: String
    let defaults: UserDefaults
    let keychain = InMemoryKeychain()
    let keyring = FakeEnclaveKeyring()
    let clock = FakeClock()
    let store: AccountDirectoryStore
    let accounts: AccountSessions

    init() throws {
        folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("onepass-accounts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        suite = "onepass.tests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
        store = AccountDirectoryStore(folder: folder)
        let (keychain, keyring, clock) = (keychain, keyring, clock)
        func environment(_ url: URL, _ settings: VaultSettings) -> VaultEnvironment {
            VaultEnvironment(
                databaseURL: url, keychain: keychain,
                biometrics: BiometricUnlock(keyring: keyring, keychain: keychain, clock: clock),
                settings: settings, sync: RecordingSync(), clock: clock, pasteboard: FakePasteboard(),
                accountKdf: SessionHarness.fastKdf, presence: FakePresence())
        }
        let primary = VaultSession(environment: environment(
            folder.appendingPathComponent("vault.sqlite"), VaultSettings(defaults: defaults)))
        accounts = AccountSessions(store: store, primary: primary, defaults: defaults) { _, url, settings in
            environment(url, settings)
        }
    }

    /// Creates the account of `slot`'s session and binds it.
    func createAccount(in slot: String, name: String) async throws {
        let session = try #require(accounts.session(for: slot))
        _ = try await session.createAccount(password: testPassword, displayName: name, mode: .personal)
        try accounts.finishAdding(slot)
    }

    func cleanUp() {
        accounts.lockAll()
        UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
        try? FileManager.default.removeItem(at: folder)
    }
}

@MainActor
@Suite("Accounts on one device", .serialized)
struct AccountSessionsTests {
    init() { VaultKitStrings.pinSourceLanguage() }

    @Test func aDeviceWithOneAccountWritesNoDirectory() throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        #expect(h.accounts.profiles.count == 1)
        #expect(h.accounts.profiles[0].isPrimary)
        #expect(h.accounts.active === h.accounts.primary)
        #expect(!h.accounts.hasSeveralAccounts)
        #expect(!FileManager.default.fileExists(atPath: h.folder.appendingPathComponent("accounts.json").path))
    }

    @Test func cancellingAnAddLeavesNothingBehind() throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let slot = try h.accounts.beginAdding(kind: .business, label: "Soma Labs", color: .orange)
        #expect(h.accounts.profiles.count == 2)
        #expect(h.accounts.session(for: slot)?.state == .noAccount)
        let folder = try #require(try h.store.slotFolder(slot: slot))
        #expect(FileManager.default.fileExists(atPath: folder.path))
        h.accounts.cancelAdding(slot)
        #expect(h.accounts.profiles.count == 1)
        #expect(!FileManager.default.fileExists(atPath: folder.path))
        #expect(h.accounts.session(for: slot) == nil)
    }

    @Test func aManagedAccountWaitsForItsServer() throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let kind = FfiAccountKind.managed(serverUrl: "https://onepass.example.org", orgId: String(repeating: "ab", count: 16))
        #expect(throws: AccountsError.serverUnavailable) {
            try h.accounts.beginAdding(kind: kind, label: "Org", color: .indigo)
        }
        #expect(h.accounts.profiles.count == 1)
    }

    @Test func twoAccountsLockAndUnlockApart() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        try await h.createAccount(in: "primary", name: "Quentin Caron")
        let work = try h.accounts.beginAdding(kind: .business, label: "Soma Labs", color: .orange)
        try await h.createAccount(in: work, name: "Quentin, Soma Labs")
        let personal = h.accounts.primary
        let business = try #require(h.accounts.session(for: work))

        // Separate accounts, separate Secret Keys, separate settings.
        let personalID = try #require(personal.environment.settings.accountID)
        let businessID = try #require(business.environment.settings.accountID)
        #expect(personalID != businessID)
        let keys = SecretKeyVault(keychain: h.keychain)
        #expect(try keys.load(accountID: personalID) != keys.load(accountID: businessID))
        #expect(h.accounts.profile(work)?.accountID == businessID)
        #expect(personal.environment.settings.displayName == "Quentin Caron")
        #expect(business.environment.settings.displayName == "Quentin, Soma Labs")

        // Switching keeps the previous account as it was; locking one leaves the other.
        try h.accounts.switchTo(work)
        #expect(h.accounts.active === business)
        #expect(personal.state == .unlocked)
        h.accounts.lock(work)
        #expect(business.state == .locked)
        #expect(personal.state == .unlocked)
        try await business.unlock(password: testPassword)
        h.accounts.lockAll()
        #expect(business.state == .locked)
        #expect(personal.state == .locked)

        // The choice survives a relaunch.
        #expect(try h.store.load().active == work)
    }

    @Test func removingAnAccountErasesOnlyIt() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        try await h.createAccount(in: "primary", name: "Quentin Caron")
        let work = try h.accounts.beginAdding(kind: .business, label: "Soma Labs", color: .orange)
        try await h.createAccount(in: work, name: "Soma")
        let personalID = try #require(h.accounts.primary.environment.settings.accountID)
        let business = try #require(h.accounts.session(for: work))
        let businessID = try #require(business.environment.settings.accountID)
        let folder = try #require(try h.store.slotFolder(slot: work))
        try h.accounts.switchTo(work)

        #expect(throws: AccountsError.primaryAccount) { try h.accounts.remove("primary") }
        try h.accounts.remove(work)

        let keys = SecretKeyVault(keychain: h.keychain)
        #expect(try keys.load(accountID: businessID) == nil)
        #expect(try keys.load(accountID: personalID) != nil)
        #expect(!FileManager.default.fileExists(atPath: folder.path))
        #expect(h.accounts.profiles.count == 1)
        #expect(h.accounts.activeSlot == "primary")
        #expect(business.state != .unlocked)
        #expect(h.accounts.primary.state == .unlocked)
        // Its settings scope is gone, the primary account's is intact.
        let prefix = ScopedDefaults.prefix(forSlot: work)
        #expect(!h.defaults.dictionaryRepresentation().keys.contains { $0.hasPrefix(prefix) })
        #expect(h.accounts.primary.environment.settings.accountID == personalID)
    }

    @Test func theUnifiedSearchIsChosenAndSeesOnlyUnlockedAccounts() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        try await h.createAccount(in: "primary", name: "Quentin Caron")
        try await addItem(h.accounts.primary, title: "Banque perso")
        let work = try h.accounts.beginAdding(kind: .business, label: "Soma Labs", color: .orange)
        try await h.createAccount(in: work, name: "Soma")
        let business = try #require(h.accounts.session(for: work))
        try await addItem(business, title: "Banque pro")

        // Off by default: nothing crosses accounts.
        #expect(h.accounts.unifiedResults(query: "Banque").isEmpty)

        try h.accounts.setUnifiedSearch(true)
        let both = h.accounts.unifiedResults(query: "Banque")
        #expect(Set(both.map(\.summary.title)) == ["Banque perso", "Banque pro"])
        #expect(both.first { $0.summary.title == "Banque pro" }?.account.slot == work)

        h.accounts.lock(work)
        let personalOnly = h.accounts.unifiedResults(query: "Banque")
        #expect(personalOnly.map(\.summary.title) == ["Banque perso"])
        #expect(personalOnly.allSatisfy { $0.account.isPrimary })
    }

    @Test func autofillRoutesAWorkDomainToItsAccount() throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let work = try h.accounts.beginAdding(kind: .business, label: "Soma Labs", color: .orange)
        try h.accounts.update(work, label: "Soma Labs", color: .orange, workDomains: ["SomaLabs.me"])
        #expect(h.accounts.profile(work)?.workDomains == ["somalabs.me"])
        #expect(h.accounts.route(host: "app.somalabs.me") == work)
        #expect(h.accounts.route(host: "evilsomalabs.me") == "primary")
        #expect(h.accounts.route(host: "github.com") == "primary")
        // A domain is claimed by one account only.
        #expect(throws: AccountsError.self) {
            try h.accounts.update("primary", label: "", color: .blue, workDomains: ["somalabs.me"])
        }
    }

    /// "Lock everything" ends the unlock the AutoFill provider may keep for every account, also one
    /// whose session was never made in this launch of the app.
    @Test func lockAllStampsAccountsWithoutASessionToo() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        try await h.createAccount(in: "primary", name: "Quentin Caron")
        let work = try h.accounts.beginAdding(kind: .business, label: "Soma Labs", color: .orange)
        try await h.createAccount(in: work, name: "Quentin, Soma Labs")
        h.accounts.lockAll()

        // A new launch: only the primary account's session exists.
        let relaunched = AccountSessions(store: h.store, primary: h.accounts.primary, defaults: h.defaults) { _, _, _ in
            h.accounts.primary.environment
        }
        #expect(relaunched.madeSession(work) == nil)
        let stamps = SharedAccountLockStamps()
        let workSettings = VaultSettings(defaults: h.defaults, scope: work)
        let primarySettings = h.accounts.primary.environment.settings
        let before = try #require(stamps.latest(for: workSettings))
        let beforePrimary = try #require(stamps.latest(for: primarySettings))

        h.clock.advance(60)
        relaunched.lockAll()
        let after = try #require(stamps.latest(for: workSettings))
        #expect(after.mark != before.mark)
        #expect(after.lockedAt == h.clock.now)
        #expect(relaunched.madeSession(work) == nil)
        // The primary account, whose session exists, stamps its own lock as before.
        #expect(stamps.latest(for: primarySettings)?.mark != beforePrimary.mark)
    }

    @Test func aStoreHoldingAnotherAccountIsRefused() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let a = try h.accounts.beginAdding(kind: .business, label: "A", color: .orange)
        try await h.createAccount(in: a, name: "A")
        let b = try h.accounts.beginAdding(kind: .business, label: "B", color: .teal)
        try await h.createAccount(in: b, name: "B")
        let session = try #require(h.accounts.session(for: b))
        try await session.unlock(password: testPassword)
        h.accounts.lockAll()

        #expect(throws: Never.self) { try h.store.checkBinding(slot: a) }
        // Swap the two stores on disk, with their -wal and -shm files (M4): both are refused.
        let folderA = try #require(try h.store.slotFolder(slot: a))
        let folderB = try #require(try h.store.slotFolder(slot: b))
        let tmp = folderA.deletingLastPathComponent().appendingPathComponent("swap")
        try FileManager.default.moveItem(at: folderA, to: tmp)
        try FileManager.default.moveItem(at: folderB, to: folderA)
        try FileManager.default.moveItem(at: tmp, to: folderB)
        #expect(throws: (any Error).self) { try h.store.checkBinding(slot: a) }
        #expect(throws: (any Error).self) { try h.store.checkBinding(slot: b) }
    }

    @Test func settingsScopesDoNotSeeEachOther() throws {
        let suite = "onepass.tests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let primary = VaultSettings(defaults: defaults)
        let slot = String(repeating: "c", count: 32)
        let added = VaultSettings(defaults: defaults, scope: slot)
        primary.displayName = "Quentin Caron"
        primary.autoLockDelay = .oneHour
        added.displayName = "Soma Labs"
        #expect(primary.displayName == "Quentin Caron")
        #expect(added.displayName == "Soma Labs")
        #expect(added.autoLockDelay == .platformDefault)
        // The primary account keeps the keys it always had.
        #expect(defaults.string(forKey: "onepass.displayName") == "Quentin Caron")
        #expect(defaults.string(forKey: "onepass.acct.\(slot).onepass.displayName") == "Soma Labs")
        #expect(added.scope == slot)
        #expect(primary.scope == nil)
        added.removeAll()
        #expect(added.displayName == "")
        #expect(primary.displayName == "Quentin Caron")
        primary.removeAll()
        #expect(primary.displayName == "Quentin Caron")
    }
}
