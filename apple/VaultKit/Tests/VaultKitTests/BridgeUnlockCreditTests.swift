import Foundation
import Testing

@testable import VaultKit

/// One Touch ID for a locked vault and a `reprompt` item: the biometric unlock the browser asked for
/// answers the first presence check of the same paired client for the same site.
@Suite("Bridge unlock credit")
struct BridgeUnlockCreditTests {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    let safari = "aa11"
    let chrome = "bb22"
    let site = "atlas-cloud.test"

    /// A credit granted to `safari` for `site` at `t0`.
    func granted() -> BridgeUnlockCredit {
        var c = BridgeUnlockCredit()
        c.unlockRequested(now: t0, pairing: safari, host: site)
        c.unlocked(biometric: true, now: t0)
        return c
    }

    @Test func biometricUnlockAskedByTheBrowserGrantsOneUse() {
        var c = BridgeUnlockCredit()
        c.unlockRequested(now: t0, pairing: safari, host: site)
        #expect(c.requestedHost(now: t0.addingTimeInterval(1)) == site)
        c.unlocked(biometric: true, now: t0.addingTimeInterval(3))
        #expect(c.requestedHost(now: t0.addingTimeInterval(4)) == nil)
        let first = c.consume(now: t0.addingTimeInterval(5), pairing: safari, host: site)
        #expect(first)
        // One credit, one use: the next protected item asks again.
        let second = c.consume(now: t0.addingTimeInterval(6), pairing: safari, host: site)
        #expect(!second)
    }

    @Test func anotherPairedBrowserCannotSpendIt() {
        var c = granted()
        let other = c.consume(now: t0.addingTimeInterval(1), pairing: chrome, host: site)
        #expect(!other)
        // Not spent by the stranger: the browser that asked still has it.
        let mine = c.consume(now: t0.addingTimeInterval(2), pairing: safari, host: site)
        #expect(mine)
    }

    @Test func anotherSiteCannotSpendIt() {
        var c = granted()
        let other = c.consume(now: t0.addingTimeInterval(1), pairing: safari, host: "borealis-bank.test")
        #expect(!other)
        let sub = c.consume(now: t0.addingTimeInterval(1), pairing: safari, host: "login.atlas-cloud.test")
        #expect(!sub)
        let mine = c.consume(now: t0.addingTimeInterval(2), pairing: safari, host: "Atlas-Cloud.test.")
        #expect(mine)
    }

    @Test func noHostOnEitherSideMeansNoCredit() {
        // The unlock named no page (an older extension): nothing is granted.
        var c = BridgeUnlockCredit()
        c.unlockRequested(now: t0, pairing: safari, host: nil)
        #expect(c.requestedHost(now: t0) == nil)
        c.unlocked(biometric: true, now: t0)
        let used = c.consume(now: t0.addingTimeInterval(1), pairing: safari, host: site)
        #expect(!used)
        // The request names no page (reveal, a code from the extension's own window): the normal
        // prompt, and the credit stays for the page it was granted for.
        var d = granted()
        let noHost = d.consume(now: t0.addingTimeInterval(1), pairing: safari, host: nil)
        #expect(!noHost)
        let mine = d.consume(now: t0.addingTimeInterval(2), pairing: safari, host: site)
        #expect(mine)
        // No pairing id, no credit either.
        var e = BridgeUnlockCredit()
        e.unlockRequested(now: t0, pairing: "", host: site)
        e.unlocked(biometric: true, now: t0)
        let blank = e.consume(now: t0.addingTimeInterval(1), pairing: "", host: site)
        #expect(!blank)
    }

    @Test func hostsThatAreNotHostsAreNoHost() {
        #expect(BridgeUnlockCredit.host("Example.COM.") == "example.com")
        #expect(BridgeUnlockCredit.host("xn--caf-dma.example") == "xn--caf-dma.example")
        for bad in ["", ".", "exa mple.com", "example.com/login", "example.com:443", "[::1]", "a\nb", "exämple.com"] {
            #expect(BridgeUnlockCredit.host(bad) == nil, "\(bad)")
        }
        #expect(BridgeUnlockCredit.host(String(repeating: "a", count: 254)) == nil)
        #expect(BridgeUnlockCredit.host(nil) == nil)
    }

    @Test func theLatestRequestIsTheOneThatCounts() {
        var c = BridgeUnlockCredit()
        c.unlockRequested(now: t0, pairing: safari, host: site)
        c.unlockRequested(now: t0.addingTimeInterval(1), pairing: chrome, host: "borealis-bank.test")
        #expect(c.requestedHost(now: t0.addingTimeInterval(2)) == "borealis-bank.test")
        c.unlocked(biometric: true, now: t0.addingTimeInterval(3))
        let first = c.consume(now: t0.addingTimeInterval(4), pairing: safari, host: site)
        #expect(!first)
        let latest = c.consume(now: t0.addingTimeInterval(4), pairing: chrome, host: "borealis-bank.test")
        #expect(latest)
    }

    @Test func expiresTenSecondsAfterTheUnlock() {
        var c = granted()
        let onTime = c.consume(now: t0.addingTimeInterval(BridgeUnlockCredit.lifetime), pairing: safari, host: site)
        #expect(onTime)
        var d = granted()
        let late = d.consume(now: t0.addingTimeInterval(BridgeUnlockCredit.lifetime + 1), pairing: safari, host: site)
        #expect(!late)
        // Gone with the late try too.
        let again = d.consume(now: t0.addingTimeInterval(1), pairing: safari, host: site)
        #expect(!again)
    }

    @Test func masterPasswordUnlockGrantsNothing() {
        var c = BridgeUnlockCredit()
        c.unlockRequested(now: t0, pairing: safari, host: site)
        c.unlocked(biometric: false, now: t0.addingTimeInterval(3))
        let used = c.consume(now: t0.addingTimeInterval(4), pairing: safari, host: site)
        #expect(!used)
        // The request is spent: a later biometric unlock of the user's own grants nothing either.
        c.unlocked(biometric: true, now: t0.addingTimeInterval(20))
        let later = c.consume(now: t0.addingTimeInterval(21), pairing: safari, host: site)
        #expect(!later)
    }

    @Test func unlockOfTheUsersOwnGrantsNothing() {
        var c = BridgeUnlockCredit()
        c.unlocked(biometric: true, now: t0)
        let used = c.consume(now: t0.addingTimeInterval(1), pairing: safari, host: site)
        #expect(!used)
    }

    @Test func requestTooOldGrantsNothing() {
        var c = BridgeUnlockCredit()
        c.unlockRequested(now: t0, pairing: safari, host: site)
        #expect(c.requestedHost(now: t0.addingTimeInterval(BridgeUnlockCredit.requestWindow + 1)) == nil)
        c.unlocked(biometric: true, now: t0.addingTimeInterval(BridgeUnlockCredit.requestWindow + 1))
        let used = c.consume(now: t0.addingTimeInterval(BridgeUnlockCredit.requestWindow + 2), pairing: safari, host: site)
        #expect(!used)
    }

    @Test func lockClearsTheCreditAndTheRequest() {
        var c = granted()
        c.clear()
        let used = c.consume(now: t0.addingTimeInterval(1), pairing: safari, host: site)
        #expect(!used)
        c.unlockRequested(now: t0, pairing: safari, host: site)
        c.clear()
        c.unlocked(biometric: true, now: t0.addingTimeInterval(1))
        let afterLock = c.consume(now: t0.addingTimeInterval(2), pairing: safari, host: site)
        #expect(!afterLock)
    }
}
