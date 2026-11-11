import Foundation
import Synchronization
import Testing
import notify

@testable import VaultKit

/// A device lock signal the test drives: `lock()` is a lock (or unlock) of the device.
final class FakeDeviceLockSignal: DeviceLockSignal {
    private final class Watch: DeviceLockWatch {
        let changedFlag = Mutex(false)
        func changed() -> Bool { changedFlag.withLock { $0 } }
    }

    private let state = Mutex((registers: true, watches: [Watch]()))

    /// False: the system refuses the registration.
    var registers: Bool {
        get { state.withLock { $0.registers } }
        set { state.withLock { $0.registers = newValue } }
    }
    var watchCount: Int { state.withLock { $0.watches.count } }

    func watch() -> (any DeviceLockWatch)? {
        state.withLock { state in
            guard state.registers else { return nil }
            let watch = Watch()
            state.watches.append(watch)
            return watch
        }
    }

    func lock() {
        for watch in state.withLock({ $0.watches }) { watch.changedFlag.withLock { $0 = true } }
    }
}

/// Lock stamps in memory, by account scope (nil: the primary account).
final class FakeAccountLockStamps: AccountLockStamps {
    private let stamps = Mutex([String: AccountLockStamp]())

    func latest(for settings: VaultSettings) -> AccountLockStamp? {
        stamps.withLock { $0[settings.scope ?? ""] }
    }

    func record(account: String?, at date: Date) {
        stamps.withLock { $0[account ?? ""] = AccountLockStamp(lockedAt: date, mark: UUID().uuidString) }
    }
}

/// The unlock the AutoFill provider keeps after Face ID / Touch ID: 90 seconds, one service, one
/// account, in memory only.
@MainActor
@Suite("AutoFill unlock window")
struct AutoFillUnlockWindowTests {
    /// An unlocked session of a new account.
    private func unlocked(_ h: SessionHarness) async throws -> VaultSession {
        let session = h.makeSession()
        _ = try await session.createAccount(password: testPassword, displayName: "", mode: .personal)
        return session
    }

    /// A window on injected lock sources (never the Mac's own screen lock).
    private func makeWindow(
        stamps: any AccountLockStamps = FakeAccountLockStamps(), signal: FakeDeviceLockSignal = FakeDeviceLockSignal()
    ) -> AutoFillUnlockWindow {
        AutoFillUnlockWindow(lockStamps: stamps, deviceLock: signal)
    }

    private func open(
        _ window: AutoFillUnlockWindow, _ session: VaultSession, _ h: SessionHarness,
        services: [AutoFillService] = ["example.com"], method: AutoFillUnlockMethod = .biometrics
    ) -> Bool {
        window.open(session: session, services: services, method: method, unlockedAt: h.clock.now)
    }

    @Test func grantedOnlyAfterBiometrics() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()

        #expect(!open(window, session, h, method: .masterPassword))
        #expect(!window.isOpen)
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)

        #expect(open(window, session, h))
        #expect(window.isOpen)
        #expect(window.holds(session))
        #expect(window.session(for: "example.com", kind: .password, account: nil) === session)
        #expect(window.session(for: "example.com", kind: .oneTimeCode, account: nil) === session)
        session.lock()
    }

    @Test func needsAnUnlockedSessionAndAService() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        // No service (an app without identifier): nothing to scope the window to.
        #expect(!open(window, session, h, services: []))
        #expect(!open(window, session, h, services: [.site("")]))
        session.lock()
        #expect(!open(window, session, h))
        #expect(!window.isOpen)
    }

    /// The same site by its registrable domain (the core's Public Suffix List), the exact host
    /// where the core names none (an address, localhost, an unknown suffix), or the same App ID;
    /// never an App ID read as a host.
    @Test func scopedToTheSiteOrApp() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let scope = AutoFillUnlockWindow.scope(of:)
        #expect(scope("Example.com") == scope("https://example.com/login"))
        #expect(scope("example.com.") == scope("example.com"))
        #expect(scope("example.com") != scope("example.org"))
        // The hosts of one registrable domain are one service.
        #expect(scope("login.example.com") == scope("https://www.example.com/a"))
        #expect(scope("a.example.co.uk") == scope("b.example.co.uk"))
        // A public suffix is nobody's site: two names under it are two services.
        #expect(scope("a.co.tz") != scope("b.co.tz"))
        #expect(scope("a.example.co.uk") != scope("other.co.uk"))
        #expect(scope("a.github.io") != scope("b.github.io"))
        // An IP literal is its whole host, never its last labels.
        #expect(scope("192.168.1.10") != scope("10.0.1.10"))
        #expect(scope("192.168.1.10") == scope("http://192.168.1.10:8080/"))
        #expect(scope("https://[::1]:8443/") != scope("https://[::2]:8443/"))
        // No registrable domain: the exact host.
        #expect(scope("localhost") == scope("http://localhost:3000/"))
        #expect(scope("localhost") != scope("a.localhost"))
        #expect(scope("nas.local") != scope("printer.local"))
        #expect(scope("a.test") != scope("b.test"))
        #expect(scope(.app("com.example.chat")) != scope(.site("com.example.chat")))
        #expect(scope(.site("")) == nil)

        let session = try await unlocked(h)
        let window = makeWindow()
        #expect(open(window, session, h, services: ["login.example.com"]))
        #expect(window.session(for: "https://www.example.com/next", kind: .password, account: nil) === session)
        #expect(window.session(for: "www.example.org", kind: .password, account: nil) == nil)
        #expect(session.state == .locked)
        try await session.unlock(password: testPassword)

        // An address: only that very host.
        #expect(open(window, session, h, services: ["192.168.1.10"]))
        #expect(window.session(for: "192.168.1.10", kind: .password, account: nil) === session)
        #expect(window.session(for: "10.0.1.10", kind: .password, account: nil) == nil)
        #expect(session.state == .locked)
        try await session.unlock(password: testPassword)

        let app = makeWindow()
        #expect(open(app, session, h, services: [.app("com.example.chat")]))
        #expect(app.session(for: .app("com.example.chat"), kind: .password, account: nil) === session)
        session.lock()
    }

    @Test func clearedByAnotherService() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        #expect(open(window, session, h))

        #expect(window.session(for: "ailleurs.org", kind: .password, account: nil) == nil)
        #expect(!window.isOpen)
        // The keys went with the window.
        #expect(session.state == .locked)
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
    }

    /// Every request tells the window: one for another service or account ends it, one without a
    /// service or for the same one leaves it.
    @Test func requestsForAnotherServiceOrAccountEndIt() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        #expect(open(window, session, h))
        window.requestArrived(for: nil, account: nil)
        window.requestArrived(for: "https://example.com/", account: nil)
        #expect(window.holds(session))
        window.requestArrived(for: .app("com.example.chat"), account: nil)
        #expect(!window.isOpen)
        #expect(session.state == .locked)

        try await session.unlock(password: testPassword)
        #expect(open(window, session, h))
        window.requestArrived(for: "example.com", account: "b")
        #expect(!window.isOpen)
        #expect(session.state == .locked)
    }

    @Test func scopedToTheAccount() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        #expect(open(window, session, h))
        // The session is the primary account's: an added account's request is not answered.
        #expect(window.session(for: "example.com", kind: .password, account: "b") == nil)
        #expect(!window.isOpen)
        #expect(session.state == .locked)
    }

    @Test func expiresAfterNinetySeconds() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        #expect(AutoFillUnlockWindow.duration == 90)
        let session = try await unlocked(h)
        let window = makeWindow()
        #expect(open(window, session, h))

        h.clock.advance(89)
        #expect(window.session(for: "example.com", kind: .password, account: nil) === session)
        h.clock.advance(1)
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(!window.isOpen)
        #expect(session.state == .locked)

        // The 90 seconds run from the unlock, not from the end of the request.
        try await session.unlock(password: testPassword)
        #expect(!window.open(
            session: session, services: ["example.com"], method: .biometrics,
            unlockedAt: h.clock.now.addingTimeInterval(-90)))
        #expect(window.open(
            session: session, services: ["example.com"], method: .biometrics,
            unlockedAt: h.clock.now.addingTimeInterval(-60)))
        h.clock.advance(30)
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(session.state == .locked)

        // A clock set back never stretches the window.
        try await session.unlock(password: testPassword)
        #expect(open(window, session, h))
        h.clock.advance(-10)
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(session.state == .locked)
    }

    @Test func offInSharedMode() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        h.settings.deviceMode = .shared
        #expect(!open(window, session, h))
        #expect(!window.isOpen)

        // Turned shared while open: ended at the next lookup.
        h.settings.deviceMode = .personal
        #expect(open(window, session, h))
        h.settings.deviceMode = .shared
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(session.state == .locked)
    }

    @Test func offWhenTheSettingIsOff() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        // On by default.
        #expect(h.settings.autofillUnlockReuse)
        let session = try await unlocked(h)
        let window = makeWindow()
        h.settings.autofillUnlockReuse = false
        #expect(!open(window, session, h))

        h.settings.autofillUnlockReuse = true
        #expect(open(window, session, h))
        h.settings.autofillUnlockReuse = false
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(!window.isOpen)
        #expect(session.state == .locked)
    }

    /// A passkey is never served from the window (user verification is real per assertion); the
    /// window stays for the passwords and codes of the service.
    @Test func neverForPasskeys() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        #expect(open(window, session, h))
        #expect(window.session(for: "example.com", kind: .passkey, account: nil) == nil)
        #expect(window.holds(session))
        #expect(window.session(for: "example.com", kind: .password, account: nil) === session)
        session.lock()
    }

    @Test func endLocksAndALockedSessionIsDropped() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        #expect(open(window, session, h))
        window.end()
        #expect(session.state == .locked)
        #expect(!window.holds(session))

        // Locked elsewhere (auto-lock): nothing to serve.
        try await session.unlock(password: testPassword)
        #expect(open(window, session, h))
        session.lock()
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(!window.isOpen)
    }

    /// One window: a new one replaces the last, whose session is locked.
    @Test func aNewWindowReplacesTheLast() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let first = try await unlocked(h)
        let second = h.makeSession()
        try await second.unlock(password: testPassword)
        let window = makeWindow()
        #expect(open(window, first, h))
        #expect(open(window, second, h, services: ["ailleurs.org"]))
        #expect(first.state == .locked)
        #expect(window.holds(second))
        #expect(window.session(for: "ailleurs.org", kind: .password, account: nil) === second)
        second.lock()
    }

    // MARK: - Locks (the app's, the device's)

    /// A lock of the account after the grant (Lock button, auto-lock, "lock everything", in the
    /// app's process) ends the window at its next use; another account's lock does not.
    @Test func aLockOfTheAccountAfterTheGrantEndsIt() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let stamps = FakeAccountLockStamps()
        // A lock before the unlock is no reason to refuse.
        stamps.record(account: nil, at: h.clock.now.addingTimeInterval(-30))
        let window = makeWindow(stamps: stamps)
        #expect(open(window, session, h))

        h.clock.advance(5)
        stamps.record(account: "b", at: h.clock.now)
        #expect(window.session(for: "example.com", kind: .password, account: nil) === session)

        stamps.record(account: nil, at: h.clock.now)
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(!window.isOpen)
        #expect(session.state == .locked)
    }

    /// A lock between the Face ID and the end of the request: nothing is kept.
    @Test func aLockBetweenTheUnlockAndTheGrantRefusesIt() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let stamps = FakeAccountLockStamps()
        let unlockedAt = h.clock.now
        h.clock.advance(3)
        stamps.record(account: nil, at: h.clock.now)
        let window = makeWindow(stamps: stamps)
        #expect(!window.open(session: session, services: ["example.com"], method: .biometrics, unlockedAt: unlockedAt))
        #expect(!window.isOpen)
        session.lock()
    }

    /// The real stamps: every lock of a session writes one for its account in the shared suite,
    /// except the provider's own end-of-request locks.
    @Test func sessionLocksStampTheirAccount() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let stamps = SharedAccountLockStamps()
        let app = try await unlocked(h)
        #expect(stamps.latest(for: h.settings) == nil)

        // The provider's session of the same account, kept by the window.
        let provider = h.makeSession()
        try await provider.unlock(password: testPassword)
        let window = makeWindow(stamps: stamps)
        #expect(open(window, provider, h))

        // A request of the provider ends: its own lock is not a lock of the account.
        let request = h.makeSession()
        try await request.unlock(password: testPassword)
        request.lock(publishPending: false, stampsAccountLock: false)
        #expect(stamps.latest(for: h.settings) == nil)
        #expect(window.session(for: "example.com", kind: .password, account: nil) === provider)

        // The app locks (in its own process, here its own session): the window is dead.
        h.clock.advance(2)
        app.lock()
        let stamp = try #require(stamps.latest(for: h.settings))
        #expect(stamp.lockedAt == h.clock.now)
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(provider.state == .locked)

        // Per account: an added account's stamp is its own.
        let added = VaultSettings(defaults: h.settings.baseDefaults, scope: "b")
        #expect(stamps.latest(for: added) == nil)
        SharedAccountLockStamps.record(for: added, at: h.clock.now)
        #expect(stamps.latest(for: added) != nil)
        #expect(stamps.latest(for: h.settings) == stamp)

        // A lock while already locked (the Lock control with OnePass locked) stamps again.
        app.lock()
        #expect(stamps.latest(for: h.settings)?.mark != stamp.mark)
    }

    /// The other ways a session drops its keys stamp too: a revoked device, a deleted account.
    @Test func revocationAndDeletionStampTheAccount() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let stamps = SharedAccountLockStamps()
        let session = try await unlocked(h)
        session.lockRevokedDevice()
        let revoked = try #require(stamps.latest(for: h.settings))

        let other = try SessionHarness()
        defer { other.cleanUp() }
        let doomed = try await unlocked(other)
        try await doomed.deleteAccount(password: testPassword)
        #expect(stamps.latest(for: other.settings) != nil)
        #expect(stamps.latest(for: h.settings) == revoked)
    }

    /// A lock (or unlock) of the device since the grant ends the window, read as a counter at the
    /// next use: it holds across a suspension of the process.
    @Test func aDeviceLockSinceTheGrantEndsIt() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let signal = FakeDeviceLockSignal()
        let window = makeWindow(signal: signal)
        #expect(open(window, session, h))
        #expect(signal.watchCount == 1)
        #expect(window.session(for: "example.com", kind: .password, account: nil) === session)

        signal.lock()
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(!window.isOpen)
        #expect(session.state == .locked)

        // A new grant watches from its own start: the old lock does not count against it.
        try await session.unlock(password: testPassword)
        #expect(open(window, session, h))
        #expect(window.session(for: "example.com", kind: .password, account: nil) === session)
        session.lock()
    }

    /// The system refuses the registration: never a window (fail closed).
    @Test func noWindowWithoutTheDeviceLockSignal() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let signal = FakeDeviceLockSignal()
        signal.registers = false
        let window = makeWindow(signal: signal)
        #expect(!open(window, session, h))
        #expect(!window.isOpen)
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        session.lock()
    }

    /// The Darwin counter behind the iOS signal: a post made after the registration is seen at the
    /// next check, with no callback in between, and stays seen.
    @Test func darwinCounterSeesAPostMadeMeanwhile() async throws {
        let name = "me.somalabs.onepass.tests.\(UUID().uuidString)"
        let watch = try #require(DarwinNotifyWatch(name: name))
        #expect(!watch.changed())
        #expect(!watch.changed())
        notify_post(name)
        #expect(await eventually { watch.changed() })
        #expect(watch.changed())
        // A watch made after the post starts clean.
        #expect(try #require(DarwinNotifyWatch(name: name)).changed() == false)
    }

    /// The system signal registers here and reports no lock on its own.
    @Test func systemSignalRegisters() throws {
        let watch = try #require(SystemDeviceLockSignal().watch())
        _ = watch.changed()
    }

    /// With the Apple Watch allowed to unlock (Mac), the Secure Enclave key opens for the Watch as
    /// for Touch ID and nothing tells them apart: no window.
    @Test func offWhenTheWatchMayUnlock() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        h.settings.allowWatchUnlock = true
        #expect(!open(window, session, h))
        h.settings.allowWatchUnlock = false
        #expect(open(window, session, h))
        h.settings.allowWatchUnlock = true
        #expect(window.session(for: "example.com", kind: .password, account: nil) == nil)
        #expect(session.state == .locked)
    }

    /// Memory pressure drops the kept session at once.
    @Test func memoryPressureEndsIt() async throws {
        let h = try SessionHarness()
        defer { h.cleanUp() }
        let session = try await unlocked(h)
        let window = makeWindow()
        #expect(open(window, session, h))
        window.memoryPressure()
        #expect(!window.isOpen)
        #expect(session.state == .locked)
    }
}
