#if os(macOS)
import Foundation
import OnePassCore
import Testing

@testable import VaultKit

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
