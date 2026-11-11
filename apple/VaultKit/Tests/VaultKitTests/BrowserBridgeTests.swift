#if os(macOS)
import Foundation
import OnePassCore
import Synchronization
import Testing

@testable import VaultKit

/// The paired browser and the page of these tests.
extension BrowserBridge {
    static let testPairing = "aa11"
    static let testSite = "atlas-cloud.test"

    func askUnlock() { unlockRequested(pairing: Self.testPairing, host: Self.testSite) }

    func reprompt(slot: String = "primary") async -> Bool {
        await confirmReprompt(slot: slot, pairing: Self.testPairing, host: Self.testSite)
    }
}

/// A keyring that remembers the reason of each biometric check.
final class PromptKeyring: EnclaveKeyring {
    let inner: FakeEnclaveKeyring
    private let seen = Mutex<[String]>([])
    var prompts: [String] { seen.withLock { $0 } }

    init(_ inner: FakeEnclaveKeyring) { self.inner = inner }

    var isAvailable: Bool { inner.isAvailable }
    var canStoreKeys: Bool { inner.canStoreKeys }
    func createKey(tag: String, allowWatch: Bool) throws { try inner.createKey(tag: tag, allowWatch: allowWatch) }
    func encrypt(_ data: Data, tag: String) throws -> Data { try inner.encrypt(data, tag: tag) }
    func decrypt(_ data: Data, tag: String, prompt: String) async throws -> Data {
        seen.withLock { $0.append(prompt) }
        return try await inner.decrypt(data, tag: tag, prompt: prompt)
    }
    func deleteKey(tag: String) throws { try inner.deleteKey(tag: tag) }
}

@MainActor
@Suite("Browser bridge")
struct BrowserBridgeTests {
    func pairing(
        _ id: String, key: UInt8 = 1, at: UInt64 = 100, extensionId: String = "abc", verified: String = ""
    ) -> FfiBridgePairing {
        FfiBridgePairing(
            pairingId: id, key: Data(repeating: key, count: 32), extName: "OnePass", browser: "Chrome",
            extensionId: extensionId, verifiedBrowser: verified, createdAt: at, lastUsed: at)
    }

    @Test func automaticPairingsKeepTheVerifiedBrowser() {
        let store = BridgePairingStore(keychain: InMemoryKeychain())
        store.add(pairing("aa", verified: "Google Chrome"))
        store.add(pairing("bb"))
        let loaded = store.load()
        #expect(loaded.first { $0.pairingId == "aa" }?.verifiedBrowser == "Google Chrome")
        #expect(loaded.first { $0.pairingId == "bb" }?.verifiedBrowser == "")
    }

    @Test func itemsWrittenBeforeAutomaticPairingStillLoad() throws {
        let keychain = InMemoryKeychain()
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        let old = #"[{"pairingId":"aa","key":"\#(key)","extName":"x","browser":"y","extensionId":"z","createdAt":1,"lastUsed":1}]"#
        try keychain.write(BridgePairingStore.key, Data(old.utf8))
        let loaded = BridgePairingStore(keychain: keychain).load()
        #expect(loaded.map(\.verifiedBrowser) == [""])
    }

    @Test func forgettingBlocksTheExtensionUntilACodePairing() {
        let store = BridgePairingStore(keychain: InMemoryKeychain())
        store.add(pairing("aa", extensionId: "ext1", verified: "Google Chrome"))
        #expect(store.forget("aa") == "ext1")
        #expect(store.load().isEmpty)
        #expect(store.blockedAuto() == ["ext1"])
        // Forgetting twice, or an unknown id, blocks nothing more.
        #expect(store.forget("aa") == nil)
        #expect(store.blockedAuto() == ["ext1"])
        // An automatic pairing never lifts a block (the app refuses it anyway).
        store.add(pairing("bb", extensionId: "ext1", verified: "Google Chrome"))
        #expect(store.blockedAuto() == ["ext1"])
        // A code pairing approved with Touch ID does.
        store.add(pairing("cc", extensionId: "ext1"))
        #expect(store.blockedAuto().isEmpty)
    }

    @Test func allowAgainLiftsTheBlock() {
        let store = BridgePairingStore(keychain: InMemoryKeychain())
        store.add(pairing("aa", extensionId: "ext1"))
        store.add(pairing("bb", extensionId: "safari"))
        _ = store.forget("aa")
        _ = store.forget("bb")
        #expect(store.blockedAuto() == ["ext1", "safari"])
        store.allowAuto("ext1")
        #expect(store.blockedAuto() == ["safari"])
    }

    @Test func unlockLinkIsExactlyOnepassUnlock() {
        #expect(BrowserBridge.unlockURL.absoluteString == "onepass://unlock")
        #expect(BrowserBridge.isUnlockLink(URL(string: "onepass://unlock")!))
        for s in [
            "onepass://unlock?x=1", "onepass://unlock/", "onepass://unlock#a", "onepass://generator",
            "other://unlock", "onepass://user@unlock",
        ] {
            #expect(!BrowserBridge.isUnlockLink(URL(string: s)!), "\(s)")
        }
    }

    @Test func pairingsLiveInOneKeychainItem() throws {
        let keychain = InMemoryKeychain()
        let store = BridgePairingStore(keychain: keychain)
        #expect(store.load().isEmpty)
        store.add(pairing("aa"))
        store.add(pairing("bb", key: 2))
        store.add(pairing("aa", key: 3))
        let loaded = store.load()
        #expect(loaded.map(\.pairingId).sorted() == ["aa", "bb"])
        #expect(loaded.first { $0.pairingId == "aa" }?.key == Data(repeating: 3, count: 32))
        // Keys are never written in clear: base64 in one item.
        let raw = try #require(try keychain.read(BridgePairingStore.key))
        #expect(String(decoding: raw, as: UTF8.self).contains(Data(repeating: 3, count: 32).base64EncodedString()))
        store.remove("aa")
        #expect(store.load().map(\.pairingId) == ["bb"])
    }

    @Test func lastUseIsWrittenAtMostHourly() {
        let store = BridgePairingStore(keychain: InMemoryKeychain())
        store.add(pairing("aa", at: 1000))
        store.touch("aa", at: 1000 + 60)
        #expect(store.load()[0].lastUsed == 1000)
        store.touch("aa", at: 1000 + BridgePairingStore.touchInterval)
        #expect(store.load()[0].lastUsed == 1000 + BridgePairingStore.touchInterval)
        store.touch("zz", at: 99_999)
        #expect(store.load().count == 1)
    }

    @Test func malformedKeysAreDropped() throws {
        let keychain = InMemoryKeychain()
        let bad = #"[{"pairingId":"aa","key":"AAEC","extName":"x","browser":"y","extensionId":"z","createdAt":1,"lastUsed":1}]"#
        try keychain.write(BridgePairingStore.key, Data(bad.utf8))
        #expect(BridgePairingStore(keychain: keychain).load().isEmpty)
    }

    @Test func allowedExtensionsFromTheBuildSetting() {
        #expect(BrowserBridge.allowedExtensions("onepass@somalabs.me abcdefghijklmnopabcdefghijklmnop")
            == ["onepass@somalabs.me", "abcdefghijklmnopabcdefghijklmnop"])
        #expect(BrowserBridge.allowedExtensions("a, b") == ["a", "b"])
        #expect(BrowserBridge.allowedExtensions(["a", " "]) == ["a"])
        #expect(BrowserBridge.allowedExtensions("$(ONEPASS_BROWSER_EXTENSIONS)") == [])
        #expect(BrowserBridge.allowedExtensions(nil) == [])
    }

    @Test func coreSessionIsReportedOnUnlockAndLock() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        var seen: [Bool] = []
        session.coreSessionChanged = { seen.append($0 != nil) }
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        session.lock()
        #expect(seen == [true, false])
    }

    /// A bridge on the harness session, serving a bridge server that does not listen (an unsigned
    /// test cannot): it follows the unlocks and locks as a started one does.
    func bridge(_ h: SessionHarness, _ session: VaultSession) -> BrowserBridge {
        let local = SharedContainer(root: h.dir, isShared: false, defaultsSuite: nil)
        let bridge = BrowserBridge(session: session, container: local, keychain: InMemoryKeychain())
        bridge.adopt(bridge.makeServer(allowed: [], journal: h.dir.appendingPathComponent("bridge-audit.jsonl")))
        return bridge
    }

    /// A Mac with a personal (primary) account and a work account, both unlocked, and their bridge.
    func twoAccounts(_ h: AccountsHarness) async throws -> (work: String, bridge: BrowserBridge) {
        try await h.createAccount(in: "primary", name: "Camille")
        let work = try h.accounts.beginAdding(kind: .business, label: "Atlas", color: .orange)
        try await h.createAccount(in: work, name: "Camille, Atlas")
        // The user made the work account available in browsers (off by default).
        h.accounts.setAvailableInBrowsers(work, true)
        let local = SharedContainer(root: h.folder, isShared: false, defaultsSuite: nil)
        let bridge = BrowserBridge(
            session: h.accounts.primary, accounts: h.accounts, container: local, keychain: InMemoryKeychain())
        bridge.adopt(bridge.makeServer(allowed: [], journal: h.folder.appendingPathComponent("bridge-audit.jsonl")))
        return (work, bridge)
    }

    func presence(_ session: VaultSession) throws -> FakePresence {
        try #require(session.environment.presence as? FakePresence)
    }

    /// Lets the main actor run what a directory change scheduled, until `done`.
    func eventually(_ done: () -> Bool) async {
        for _ in 0..<500 where !done() { try? await Task.sleep(for: .milliseconds(10)) }
    }

    @Test func oneAccountIsServedAsBefore() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "Camille", mode: .personal)
        let bridge = bridge(h, session)
        #expect(bridge.published == [.init(slot: "primary", name: "OnePass", unlocked: true, excluded: [])])
        session.lock()
        #expect(bridge.published == [.init(slot: "primary", name: "OnePass", unlocked: false, excluded: [])])
    }

    @Test func everySignedInAccountIsToldWithItsOwnLock() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let (work, bridge) = try await twoAccounts(h)
        let business = try #require(h.accounts.session(for: work))
        #expect(
            bridge.published == [
                .init(slot: "primary", name: "Camille", unlocked: true, excluded: []),
                .init(slot: work, name: "Atlas", unlocked: true, excluded: []),
            ])

        // The work account locks, then unlocks: told at once, the primary account untouched.
        h.accounts.lock(work)
        #expect(bridge.published.map(\.unlocked) == [true, false])
        try await business.unlock(password: testPassword)
        #expect(bridge.published.map(\.unlocked) == [true, true])

        // The primary account locks: it is listed without a session (the browsers see a locked
        // app), the work account keeps its own state.
        h.accounts.primary.lock()
        #expect(bridge.published.map(\.unlocked) == [false, true])
        h.accounts.lockAll()
        #expect(bridge.published.map(\.unlocked) == [false, false])
    }

    @Test func hiddenVaultsAreToldPerAccount() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let (work, bridge) = try await twoAccounts(h)
        let business = try #require(h.accounts.session(for: work))
        try await business.createVault(FfiVaultMeta(name: "Clients", icon: "folder", color: "blue", travelSafe: false, mcpAccess: false))
        let hidden = try #require(business.allVaults.first { $0.meta.name == "Clients" }?.id)
        business.setVaultHidden(hidden, hidden: true)
        #expect(bridge.published.map(\.excluded) == [[], [hidden]])
        business.setVaultHidden(hidden, hidden: false)
        #expect(bridge.published.map(\.excluded) == [[], []])
    }

    @Test func accountsAddedRenamedAndRemovedAreToldAgain() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let (work, bridge) = try await twoAccounts(h)

        // A new slot is not signed in yet: not served until its account is bound.
        let side = try h.accounts.beginAdding(kind: .business, label: "Borealis", color: .teal)
        await eventually { h.accounts.profiles.count == 3 && bridge.published.count == 2 }
        #expect(bridge.published.map(\.slot) == ["primary", work])
        try await h.createAccount(in: side, name: "Camille, Borealis")
        await eventually { h.accounts.profile(side)?.accountID != nil }
        #expect(bridge.published.map(\.slot) == ["primary", work])
        h.accounts.setAvailableInBrowsers(side, true)
        #expect(bridge.published.map(\.slot) == ["primary", work, side])
        #expect(bridge.published.map(\.unlocked) == [true, true, true])

        try h.accounts.update(work, label: "Atlas Cloud", color: .orange, workDomains: ["atlas-cloud.test"])
        await eventually { bridge.published.map(\.name).contains("Atlas Cloud") }
        #expect(bridge.published.map(\.name) == ["Camille", "Atlas Cloud", "Borealis"])

        try h.accounts.remove(side)
        await eventually { bridge.published.count == 2 }
        #expect(bridge.published.map(\.slot) == ["primary", work])
    }

    @Test func repromptIsConfirmedOnTheAccountOfTheItem() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let (work, bridge) = try await twoAccounts(h)
        let personal = h.accounts.primary
        let business = try #require(h.accounts.session(for: work))
        try await personal.enrollBiometrics(password: testPassword)
        try await business.enrollBiometrics(password: testPassword)

        // Through the delegate, as the bridge threads call it.
        let delegate = BrowserBridge.Delegate(owner: bridge, store: BridgePairingStore(keychain: InMemoryKeychain()))
        let ok = await Task.detached { delegate.confirmReprompt(slot: work, vaultId: "", itemId: "", pairingId: "aa11", originHost: nil) }.value
        #expect(ok)
        #expect(try presence(business).prompts == 1)
        #expect(try presence(personal).prompts == 0)
        let mine = await bridge.reprompt(slot: "primary")
        #expect(mine)
        #expect(try presence(personal).prompts == 1)

        // A locked account, or one this Mac does not hold, refuses without asking.
        h.accounts.lock(work)
        let locked = await bridge.reprompt(slot: work)
        #expect(!locked)
        let unknown = await bridge.reprompt(slot: "ffffffffffffffffffffffffffffffff")
        #expect(!unknown)
        #expect(try presence(business).prompts == 1)
    }

    /// The credit of the unlock the browser asked for is the primary account's alone.
    @Test func unlockCreditAnswersOnlyThePrimaryAccount() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let (work, bridge) = try await twoAccounts(h)
        let personal = h.accounts.primary
        let business = try #require(h.accounts.session(for: work))
        try await personal.enrollBiometrics(password: testPassword)
        try await business.enrollBiometrics(password: testPassword)
        personal.lock()
        bridge.askUnlock()
        bridge.biometricUnlockRunning = true
        try await personal.unlockWithBiometrics()
        bridge.biometricUnlockRunning = false

        let other = await bridge.reprompt(slot: work)
        #expect(other)
        #expect(try presence(business).prompts == 1)
        let first = await bridge.reprompt(slot: "primary")
        #expect(first)
        #expect(try presence(personal).prompts == 0)
        let second = await bridge.reprompt(slot: "primary")
        #expect(second)
        #expect(try presence(personal).prompts == 1)

        // An added account's own unlock grants nothing, even while a request waits.
        h.accounts.lockAll()
        bridge.askUnlock()
        bridge.biometricUnlockRunning = true
        try await business.unlockWithBiometrics()
        bridge.biometricUnlockRunning = false
        let added = await bridge.reprompt(slot: work)
        #expect(added)
        #expect(try presence(business).prompts == 2)
    }

    @Test func aWriteReloadsTheAccountThatWasWritten() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let (work, bridge) = try await twoAccounts(h)
        let personal = h.accounts.primary
        let business = try #require(h.accounts.session(for: work))
        let (before, beforeWork) = (personal.externalChangeRevision, business.externalChangeRevision)
        let delegate = BrowserBridge.Delegate(owner: bridge, store: BridgePairingStore(keychain: InMemoryKeychain()))

        // No vault id (a forgotten site): the whole account reloads, the other one does not.
        delegate.vaultChanged(slot: work, vaultId: nil)
        await eventually { business.externalChangeRevision != beforeWork }
        #expect(business.externalChangeRevision == beforeWork &+ 1)
        #expect(personal.externalChangeRevision == before)

        let vault = try #require(personal.allVaults.first?.id)
        delegate.vaultChanged(slot: "primary", vaultId: vault)
        await eventually { personal.externalChangeRevision != before }
        #expect(personal.externalChangeRevision == before &+ 1)
        #expect(business.externalChangeRevision == beforeWork &+ 1)

        // A slot this Mac does not hold changes nothing.
        delegate.vaultChanged(slot: "ffffffffffffffffffffffffffffffff", vaultId: nil)
        try? await Task.sleep(for: .milliseconds(50))
        #expect(personal.externalChangeRevision == before &+ 1)
        #expect(business.externalChangeRevision == beforeWork &+ 1)
    }

    @Test func aFillRestartsTheIdleDelayOfItsAccountOnly() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        let (work, bridge) = try await twoAccounts(h)
        let personal = h.accounts.primary
        let business = try #require(h.accounts.session(for: work))

        // The work account served the fill: it stays open, the primary one runs out.
        h.clock.advance(800)
        bridge.fillServed(account: work)
        bridge.fillServed(account: "ffffffffffffffffffffffffffffffff")
        h.clock.advance(800)
        h.accounts.checkAutoLock()
        #expect(business.state == .unlocked)
        #expect(personal.state == .locked)

        // Through the delegate, as the bridge threads report a served secret.
        try await personal.unlock(password: testPassword)
        h.clock.advance(800)
        let delegate = BrowserBridge.Delegate(owner: bridge, store: BridgePairingStore(keychain: InMemoryKeychain()))
        delegate.fillServed(slot: "primary", pairingId: BrowserBridge.testPairing, kind: "fill_login")
        try? await Task.sleep(for: .milliseconds(100))
        h.clock.advance(800)
        h.accounts.checkAutoLock()
        #expect(personal.state == .unlocked)
        #expect(business.state == .locked)
    }

    /// An added account reaches the browsers only once its own switch is on.
    @Test func anAddedAccountIsToldOnlyOnceMadeAvailableInBrowsers() async throws {
        let h = try AccountsHarness()
        defer { h.cleanUp() }
        try await h.createAccount(in: "primary", name: "Camille")
        let work = try h.accounts.beginAdding(kind: .business, label: "Atlas", color: .orange)
        try await h.createAccount(in: work, name: "Camille, Atlas")
        #expect(h.accounts.isAvailableInBrowsers("primary"))
        #expect(!h.accounts.isAvailableInBrowsers(work))
        let local = SharedContainer(root: h.folder, isShared: false, defaultsSuite: nil)
        let bridge = BrowserBridge(
            session: h.accounts.primary, accounts: h.accounts, container: local, keychain: InMemoryKeychain())
        bridge.adopt(bridge.makeServer(allowed: [], journal: h.folder.appendingPathComponent("bridge-audit.jsonl")))
        #expect(bridge.published.map(\.slot) == ["primary"])

        // On, then off: told in the same turn, no wait.
        h.accounts.setAvailableInBrowsers(work, true)
        #expect(bridge.published.map(\.slot) == ["primary", work])
        #expect(bridge.published.map(\.unlocked) == [true, true])
        h.accounts.setAvailableInBrowsers(work, false)
        #expect(bridge.published.map(\.slot) == ["primary"])
        // The primary account cannot be taken out. The choice is kept with the account's own
        // settings: read back by another instance, gone when the account leaves the device.
        h.accounts.setAvailableInBrowsers("primary", false)
        #expect(h.accounts.isAvailableInBrowsers("primary"))
        h.accounts.setAvailableInBrowsers(work, true)
        let again = AccountSessions(store: h.store, primary: h.accounts.primary, defaults: h.defaults) { _, _, _ in
            h.accounts.primary.environment
        }
        #expect(again.isAvailableInBrowsers(work))
        try h.accounts.remove(work)
        #expect(!again.isAvailableInBrowsers(work))
    }

    /// The fills served to the browsers keep a vault open for 12 hours after its unlock, no longer.
    @Test func servedFillsStopExtendingTheDelayAfterTwelveHours() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let bridge = bridge(h, session)
        #expect(BrowserBridge.fillWindow == 12 * 3600)
        // A fill every 800 s (the delay is 900 s): open for the whole window.
        for _ in 0..<54 {
            h.clock.advance(800)
            bridge.fillServed()
            session.checkAutoLock()
        }
        #expect(session.state == .unlocked)
        // Past it, the fills go on and the delay runs out all the same.
        h.clock.advance(800)
        bridge.fillServed()
        session.checkAutoLock()
        #expect(session.state == .unlocked)
        h.clock.advance(800)
        bridge.fillServed()
        session.checkAutoLock()
        #expect(session.state == .locked)
    }

    @Test func theUserBackInTheAppStartsTheWindowAgain() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let bridge = bridge(h, session)
        for _ in 0..<53 {
            h.clock.advance(800)
            bridge.fillServed()
        }
        // The user comes to the app at 11 h 47: fills count for 12 more hours.
        bridge.userPresent(slot: "primary")
        for _ in 0..<54 {
            h.clock.advance(800)
            bridge.fillServed()
            session.checkAutoLock()
        }
        #expect(session.state == .unlocked)
        h.clock.advance(1600)
        bridge.fillServed()
        session.checkAutoLock()
        #expect(session.state == .locked)
        // A locked account has no window to start.
        bridge.userPresent(slot: "primary")
        bridge.fillServed()
        #expect(session.state == .locked)
    }

    /// The credit of the unlock belongs to the browser that asked and the site it asked for.
    @Test func unlockCreditIsBoundToItsBrowserAndSite() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await lockedWithBiometrics(h)
        let bridge = bridge(h, session)
        bridge.askUnlock()
        bridge.biometricUnlockRunning = true
        try await session.unlockWithBiometrics()
        bridge.biometricUnlockRunning = false

        // Another paired browser, another site, no site: Touch ID, and the credit is not theirs.
        let otherBrowser = await bridge.confirmReprompt(slot: "primary", pairing: "bb22", host: BrowserBridge.testSite)
        #expect(otherBrowser)
        #expect(h.presence.prompts == 1)
        let otherSite = await bridge.confirmReprompt(
            slot: "primary", pairing: BrowserBridge.testPairing, host: "borealis-bank.test")
        #expect(otherSite)
        #expect(h.presence.prompts == 2)
        let noSite = await bridge.confirmReprompt(slot: "primary", pairing: BrowserBridge.testPairing, host: nil)
        #expect(noSite)
        #expect(h.presence.prompts == 3)
        // The browser that asked, for the site it asked for: no second prompt, once.
        let mine = await bridge.reprompt()
        #expect(mine)
        #expect(h.presence.prompts == 3)
        let again = await bridge.reprompt()
        #expect(again)
        #expect(h.presence.prompts == 4)
    }

    @Test func unlockAskedWithoutASiteGrantsNoCredit() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await lockedWithBiometrics(h)
        let bridge = bridge(h, session)
        bridge.unlockRequested(pairing: BrowserBridge.testPairing, host: nil)
        bridge.biometricUnlockRunning = true
        try await session.unlockWithBiometrics()
        bridge.biometricUnlockRunning = false
        let ok = await bridge.reprompt()
        #expect(ok)
        #expect(h.presence.prompts == 1)
    }

    /// The Touch ID that answers a browser's unlock names the site it is for.
    @Test func touchIDReasonNamesTheSiteTheBrowserAskedFor() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        _ = try await lockedWithBiometrics(h)
        let keyring = PromptKeyring(h.keyring)
        var environment = h.environment
        environment.biometrics = BiometricUnlock(keyring: keyring, keychain: h.keychain, clock: h.clock)
        let session = VaultSession(environment: environment)
        let bridge = bridge(h, session)
        let usual = VaultSession.unlockPrompt

        bridge.askUnlock()
        try await session.unlockWithBiometrics()
        let named = try #require(keyring.prompts.last)
        #expect(named != usual)
        #expect(named.contains(BrowserBridge.testSite))
        // One use: the user's own next unlock reads as usual.
        session.lock()
        try await session.unlockWithBiometrics()
        #expect(keyring.prompts.last == usual)

        // No site, or something that is not a host: the usual wording.
        session.lock()
        bridge.unlockRequested(pairing: BrowserBridge.testPairing, host: nil)
        try await session.unlockWithBiometrics()
        #expect(keyring.prompts.last == usual)
        session.lock()
        bridge.unlockRequested(pairing: BrowserBridge.testPairing, host: "atlas-cloud.test to pay Mallory")
        try await session.unlockWithBiometrics()
        #expect(keyring.prompts.last == usual)

        // Asked, then nothing for longer than the extension waits: the usual wording again.
        session.lock()
        bridge.askUnlock()
        h.clock.advance(BridgeUnlockCredit.requestWindow + 1)
        try await session.unlockWithBiometrics()
        #expect(keyring.prompts.last == usual)
    }

    /// An account with biometrics enrolled, locked.
    func lockedWithBiometrics(_ h: SessionHarness) async throws -> VaultSession {
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        try await session.enrollBiometrics(password: testPassword)
        session.lock()
        return session
    }

    @Test func servedFillRestartsTheIdleDelay() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let bridge = bridge(h, session)
        #expect(h.settings.effectiveAutoLockSeconds == 900)
        h.clock.advance(800)
        bridge.fillServed()
        h.clock.advance(800)
        session.checkAutoLock()
        #expect(session.state == .unlocked)
        // No fill since: the delay runs out as before.
        h.clock.advance(101)
        session.checkAutoLock()
        #expect(session.state == .locked)
        // Nothing to keep open once locked.
        bridge.fillServed()
        #expect(session.state == .locked)
    }

    /// The app hidden behind the browser, or its window closed: fills still count as use.
    @Test func servedFillRestartsTheIdleDelayBehindTheBrowser() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        let bridge = bridge(h, session)
        session.scenePhaseChanged(.background)
        h.clock.advance(800)
        bridge.fillServed()
        h.clock.advance(800)
        session.checkAutoLock()
        #expect(session.state == .unlocked)
        h.clock.advance(101)
        session.checkAutoLock()
        #expect(session.state == .locked)
        // Activity noted by anything else in the background still does not hold the vault open.
        try await session.unlock(password: testPassword)
        session.scenePhaseChanged(.background)
        h.clock.advance(800)
        session.noteActivity()
        h.clock.advance(101)
        session.checkAutoLock()
        #expect(session.state == .locked)
    }

    @Test func requestBeforeTheAppListensIsNotLost() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        let bridge = bridge(h, session)
        bridge.askUnlock()
        var seen: [BrowserBridge.Attention] = []
        bridge.attentionRequested = { seen.append($0) }
        #expect(seen == [.unlock])
        // Delivered once, then as they come.
        bridge.attentionRequested = { seen.append($0) }
        #expect(seen == [.unlock])
        bridge.askUnlock()
        #expect(seen == [.unlock, .unlock])
    }

    @Test func biometricUnlockAskedByTheBrowserAnswersOneReprompt() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await lockedWithBiometrics(h)
        let bridge = bridge(h, session)
        bridge.askUnlock()
        bridge.biometricUnlockRunning = true
        try await session.unlockWithBiometrics()
        bridge.biometricUnlockRunning = false
        #expect(session.state == .unlocked)
        let first = await bridge.reprompt()
        #expect(first)
        #expect(h.presence.prompts == 0)
        // One use: the next protected item asks for Touch ID.
        let second = await bridge.reprompt()
        #expect(second)
        #expect(h.presence.prompts == 1)
    }

    @Test func masterPasswordUnlockStillAsksForReprompt() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await lockedWithBiometrics(h)
        let bridge = bridge(h, session)
        bridge.askUnlock()
        try await session.unlock(password: testPassword)
        let ok = await bridge.reprompt()
        #expect(ok)
        #expect(h.presence.prompts == 1)
    }

    @Test func unlockOfTheUsersOwnStillAsksForReprompt() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await lockedWithBiometrics(h)
        let bridge = bridge(h, session)
        bridge.biometricUnlockRunning = true
        try await session.unlockWithBiometrics()
        bridge.biometricUnlockRunning = false
        let ok = await bridge.reprompt()
        #expect(ok)
        #expect(h.presence.prompts == 1)
    }

    @Test func repromptCreditLastsTenSecondsAndDiesWithTheLock() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await lockedWithBiometrics(h)
        let bridge = bridge(h, session)
        bridge.askUnlock()
        bridge.biometricUnlockRunning = true
        try await session.unlockWithBiometrics()
        bridge.biometricUnlockRunning = false
        h.clock.advance(BridgeUnlockCredit.lifetime + 1)
        let late = await bridge.reprompt()
        #expect(late)
        #expect(h.presence.prompts == 1)

        // Locked again before the credit is used: the next unlock (master password) owes the prompt.
        session.lock()
        bridge.askUnlock()
        bridge.biometricUnlockRunning = true
        try await session.unlockWithBiometrics()
        bridge.biometricUnlockRunning = false
        session.lock()
        try await session.unlock(password: testPassword)
        let afterLock = await bridge.reprompt()
        #expect(afterLock)
        #expect(h.presence.prompts == 2)
    }

    @Test func pairingRequestWaitsForTheUnlockInsteadOfBeingRefused() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await lockedWithBiometrics(h)
        let bridge = bridge(h, session)
        var seen: [BrowserBridge.Attention] = []
        bridge.attentionRequested = { seen.append($0) }
        bridge.show(
            FfiBridgePairingRequest(
                requestId: 7, extName: "OnePass", browser: "Chrome", extensionId: "abc", code: "123 456"))
        #expect(seen == [.pairing])
        // Locked when "Approuver" is tapped: no prompt, nothing answered, the sheet stays.
        await bridge.approve(7)
        #expect(bridge.requests.map(\.id) == [7])
        #expect(h.presence.prompts == 0)

        // Locked while Touch ID is up: not the user's refusal either.
        try await session.unlock(password: testPassword)
        h.presence.hold()
        let approving = Task { await bridge.approve(7) }
        while h.presence.pending == 0 { await Task.yield() }
        session.lock()
        h.presence.release()
        await approving.value
        #expect(bridge.requests.map(\.id) == [7])

        // Unlocked and confirmed: answered, the sheet goes.
        try await session.unlock(password: testPassword)
        await bridge.approve(7)
        #expect(bridge.requests.isEmpty)
        #expect(h.presence.prompts == 2)
    }

    @Test func refusedTouchIDRefusesThePairing() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await lockedWithBiometrics(h)
        try await session.unlock(password: testPassword)
        let bridge = bridge(h, session)
        bridge.show(
            FfiBridgePairingRequest(
                requestId: 8, extName: "OnePass", browser: "Chrome", extensionId: "abc", code: "123 456"))
        h.presence.answer(false)
        await bridge.approve(8)
        #expect(bridge.requests.isEmpty)
    }

    @Test func unsharedContainerNeverStartsTheBridge() throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = h.makeSession()
        let local = SharedContainer(root: FileManager.default.temporaryDirectory, isShared: false, defaultsSuite: nil)
        let bridge = BrowserBridge(session: session, container: local, keychain: InMemoryKeychain())
        bridge.start()
        #expect(!bridge.isRunning)
    }
}
#endif
