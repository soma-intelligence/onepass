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

    /// Cold launch: the link starts the app and Touch ID answers before the extension's bridge
    /// session is up, so the browser's request comes after the unlock.
    @Test func requestRightAfterALinkUnlockReturnsOnce() {
        var r = BrowserReturn()
        r.linkOpened(now: t0)
        let atUnlock = r.consume(now: t0.addingTimeInterval(2))
        #expect(!atUnlock)
        let late = r.confirmLate(now: t0.addingTimeInterval(4))
        #expect(late)
        let twice = r.confirmLate(now: t0.addingTimeInterval(5))
        #expect(!twice)
    }

    @Test func linkAloneNeverReturns() {
        var r = BrowserReturn()
        r.linkOpened(now: t0)
        let atUnlock = r.consume(now: t0.addingTimeInterval(2))
        #expect(!atUnlock)
        // No request from a paired browser: the app stays in front.
        let nextUnlock = r.consume(now: t0.addingTimeInterval(3))
        #expect(!nextUnlock)
    }

    @Test func lateRequestOnlyRightAfterTheUnlock() {
        var r = BrowserReturn()
        r.linkOpened(now: t0)
        _ = r.consume(now: t0.addingTimeInterval(2))
        let tooLate = r.confirmLate(now: t0.addingTimeInterval(2 + BrowserReturn.lateWindow + 1))
        #expect(!tooLate)
        // Without the link, or with a link too old at the unlock, a request while unlocked hides nothing.
        var own = BrowserReturn()
        _ = own.consume(now: t0)
        let ownUnlock = own.confirmLate(now: t0.addingTimeInterval(1))
        #expect(!ownUnlock)
        var old = BrowserReturn()
        old.linkOpened(now: t0)
        _ = old.consume(now: t0.addingTimeInterval(BrowserReturn.window + 1))
        let oldLink = old.confirmLate(now: t0.addingTimeInterval(BrowserReturn.window + 2))
        #expect(!oldLink)
    }

    @Test func openedByHandCancelsTheLateReturnToo() {
        var r = BrowserReturn()
        r.linkOpened(now: t0)
        _ = r.consume(now: t0.addingTimeInterval(1))
        r.cancel()
        let late = r.confirmLate(now: t0.addingTimeInterval(2))
        #expect(!late)
    }

    /// Warm path: the link and the bridge request both come before the unlock, which returns once.
    @Test func linkThenRequestReturnsAtTheUnlockOnly() {
        var r = BrowserReturn()
        r.linkOpened(now: t0)
        r.arm(now: t0.addingTimeInterval(1))
        let atUnlock = r.consume(now: t0.addingTimeInterval(3))
        #expect(atUnlock)
        let late = r.confirmLate(now: t0.addingTimeInterval(4))
        #expect(!late)
    }
}
