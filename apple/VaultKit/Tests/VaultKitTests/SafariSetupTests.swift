import Foundation
import OnePassCore
import Testing

@testable import VaultKit

/// Turning the Safari extension on (MS-02, IOSSAF-13): its identifier, the iOS pairing signal, the card.
@Suite("Safari setup")
struct SafariSetupTests {
    @Test func identifierIsTheAppsOwnPlusSafari() {
        #expect(SafariSetup.extensionIdentifier(appBundleID: "me.somalabs.onepass") == "me.somalabs.onepass.safari")
        #expect(SafariSetup.extensionIdentifier(appBundleID: "me.somalabs.onepass.dev") == "me.somalabs.onepass.dev.safari")
        #expect(SafariSetup.extensionIdentifier(appBundleID: nil) == nil)
        #expect(SafariSetup.extensionIdentifier(appBundleID: "") == nil)
    }

    @Test func noPairingListMeansNotSeenYet() {
        #expect(!SafariSetup.extensionHasPaired(keychain: InMemoryKeychain()))
    }

    @Test func aPairingTheExtensionStoredIsTheSignal() throws {
        let keychain = InMemoryKeychain()
        let store = BridgePairingStore(keychain: keychain)
        store.add(
            FfiBridgePairing(
                pairingId: "p1", key: Data(repeating: 7, count: 32), extName: "OnePass", browser: "Safari",
                extensionId: "ext", verifiedBrowser: "Safari", createdAt: 1, lastUsed: 1))
        #expect(SafariSetup.extensionHasPaired(keychain: keychain))
        // Forgotten: the signal goes with it (the card may come back).
        store.forget("p1")
        #expect(!SafariSetup.extensionHasPaired(keychain: keychain))
    }

    @Test func garbageIsNoSignal() throws {
        let keychain = InMemoryKeychain()
        try keychain.write(BridgePairingStore.key, Data("{\"not\":\"a list\"}".utf8))
        #expect(!SafariSetup.extensionHasPaired(keychain: keychain))
        try keychain.write(BridgePairingStore.key, Data("[]".utf8))
        #expect(!SafariSetup.extensionHasPaired(keychain: keychain))
    }

    @Test func cardShowsOnlyWhileOffAndNotClosed() {
        #expect(SafariSetup.showsCard(dismissed: false, extensionOn: false))
        #expect(!SafariSetup.showsCard(dismissed: true, extensionOn: false))
        #expect(!SafariSetup.showsCard(dismissed: false, extensionOn: true))
        #expect(!SafariSetup.showsCard(dismissed: false, extensionOn: nil))
    }
}

/// Back to the browser after an unlock it asked for (MS-03).
@Suite("Safari setup: return to the browser")
struct SafariSetupBrowserReturnTests {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    @Test func unlockSoonAfterTheRequestReturns() {
        var r = BrowserReturn()
        r.arm(now: t0)
        let r1 = r.consume(now: t0.addingTimeInterval(5))
        #expect(r1)
        // Consumed: the next unlock stays in the app.
        let r2 = r.consume(now: t0.addingTimeInterval(6))
        #expect(!r2)
    }

    @Test func noRequestNoReturn() {
        var r = BrowserReturn()
        let r3 = r.consume(now: t0)
        #expect(!r3)
    }

    @Test func tooLateTheExtensionStoppedWaiting() {
        var r = BrowserReturn()
        r.arm(now: t0)
        let r4 = r.consume(now: t0.addingTimeInterval(BrowserReturn.window))
        #expect(r4)
        r.arm(now: t0)
        let r5 = r.consume(now: t0.addingTimeInterval(BrowserReturn.window + 1))
        #expect(!r5)
        // A late unlock still clears it.
        let r6 = r.consume(now: t0.addingTimeInterval(1))
        #expect(!r6)
    }

    @Test func openedByHandCancels() {
        var r = BrowserReturn()
        r.arm(now: t0)
        r.cancel()
        let r7 = r.consume(now: t0.addingTimeInterval(1))
        #expect(!r7)
    }
}
