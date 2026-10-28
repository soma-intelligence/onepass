#if os(macOS)
import Foundation
import OnePassCore
import Testing

@testable import VaultKit

@MainActor
@Suite("Browser bridge")
struct BrowserBridgeTests {
    func pairing(_ id: String, key: UInt8 = 1, at: UInt64 = 100) -> FfiBridgePairing {
        FfiBridgePairing(
            pairingId: id, key: Data(repeating: key, count: 32), extName: "OnePass", browser: "Chrome",
            extensionId: "abc", createdAt: at, lastUsed: at)
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
