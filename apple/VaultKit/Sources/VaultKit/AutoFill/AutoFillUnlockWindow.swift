import Foundation

/// How the session of an AutoFill request was unlocked.
public enum AutoFillUnlockMethod: Sendable, Equatable {
    case biometrics
    case masterPassword
}

extension VaultSettings {
    /// "Rester déverrouillé 90 secondes" in the AutoFill provider (default on): after Face ID or
    /// Touch ID there, the passwords and codes of the same site or app are filled without asking
    /// again for 90 seconds. Per account, in the suite the app and the provider share.
    public var autofillUnlockReuse: Bool {
        get { baseDefaults.object(forKey: unlockReuseKey) as? Bool ?? true }
        set { baseDefaults.set(newValue, forKey: unlockReuseKey) }
    }

    private var unlockReuseKey: String {
        "onepass.autofill.unlockReuse" + (scope.map { ".\($0)" } ?? "")
    }
}

/// The unlock the AutoFill provider keeps after Face ID / Touch ID (owner ruling of 2026-11-10,
/// which replaces "a fresh session per request" for this one case).
///
/// One unlocked session at most, for `duration` seconds counted from the biometric unlock, scoped
/// to the services of the request that unlocked (the registrable domain of a site, or an App ID)
/// and to its account. Inside it, a password or one-time code request of that service is answered
/// without interface (`AutoFillModel.resultFromUnlockWindow`). Never opened after a master password, on a
/// shared device, with the setting off, when the Apple Watch may unlock (the Secure Enclave key
/// then opens for the Watch as for Touch ID and nothing tells them apart), or when the device lock
/// signal cannot be watched; never serves a passkey.
///
/// It ends at `duration`, on a request for another service or account, on a lock of the account
/// made anywhere (`AccountLockStamps`: the app's Lock button, auto-lock, "lock everything", a
/// revoked device, an erased account), on a lock of the device (`DeviceLockSignal`), under memory
/// pressure, and with the process: memory only, nothing about it is written to disk or to the
/// keychain. Ending locks the session, which drops its keys as at the end of any request. Every
/// one of these is checked again at each use, whatever ran or did not run in between.
///
/// Residual: iOS suspends the provider's process seconds after a request, and nothing runs in a
/// suspended process. The `expiry` task, the memory pressure source and the provider's own lock
/// observers then act only when the process next runs, so the unlocked session (its keys) can
/// stay in the suspended process's memory past the 90 seconds, until it resumes, the next request
/// arrives or the system reclaims it. No fill is possible meanwhile: the checks above run before
/// any answer. Dropping the session when the system announces the suspension would close this,
/// and would also end the window before the next page asks, which is the whole case it serves.
@MainActor
public final class AutoFillUnlockWindow {
    public nonisolated static let duration: TimeInterval = 90

    /// The window of the provider process.
    public static let shared = AutoFillUnlockWindow()

    private struct Held {
        let session: VaultSession
        let scopes: Set<String>
        let account: String?
        let unlockedAt: Date
        /// The same end on a clock nobody can set: whichever comes first ends the window.
        let deadline: ContinuousClock.Instant
        /// The account's lock stamp at the grant: any other one since is a lock.
        let lockMark: String?
        /// Lock state changes of the device since the grant.
        let deviceLock: any DeviceLockWatch
    }

    private var held: Held?
    /// Ends the window on time when no request comes (a suspended process runs it when it resumes;
    /// every lookup checks the time itself).
    private var expiry: Task<Void, Never>?
    private let lockStamps: any AccountLockStamps
    private let deviceLockSignal: any DeviceLockSignal
    /// Drops the session when the system is short of memory (made at the first grant).
    private var pressure: (any DispatchSourceMemoryPressure)?

    /// `lockStamps`: the locks of the account made elsewhere; `deviceLock`: the device's own lock.
    public init(
        lockStamps: any AccountLockStamps = SharedAccountLockStamps(),
        deviceLock: any DeviceLockSignal = SystemDeviceLockSignal()
    ) {
        self.lockStamps = lockStamps
        deviceLockSignal = deviceLock
    }

    public var isOpen: Bool { held != nil }

    /// `session` is the one kept: its owner must not lock it.
    public func holds(_ session: VaultSession) -> Bool {
        held?.session === session
    }

    /// What two services must share to be the same one: for a site, its registrable domain by the
    /// core's Public Suffix List (`login.example.com` and `www.example.com` are one service,
    /// `a.co.tz` and `b.co.tz` are two); the exact host (lowercased, without port or final dot)
    /// where the core names none: an IP literal, `localhost`, an unknown suffix. For an app, its
    /// App ID. Nil without identifier.
    public nonisolated static func scope(of service: AutoFillService) -> String? {
        let identifier = service.identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !identifier.isEmpty else { return nil }
        if service.isApp { return "app:" + identifier }
        var host = AutoFillModel.host(of: identifier)
        while host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty else { return nil }
        // The core takes a host only (never a URL) and answers nil rather than guess.
        return "site:" + (registrableDomain(host: host) ?? host)
    }

    /// Keeps `session` for the rest of the 90 seconds that began at `unlockedAt`. False (nothing
    /// kept, the caller locks as usual) unless the unlock was biometric, the session is unlocked,
    /// the setting is on, the device is personal, a service scopes the window, time is left, the
    /// account was not locked since `unlockedAt` and the device lock signal can be watched.
    /// A window already open is ended first.
    @discardableResult
    public func open(
        session: VaultSession, services: [AutoFillService], method: AutoFillUnlockMethod, unlockedAt: Date
    ) -> Bool {
        let settings = session.environment.settings
        let scopes = Set(services.compactMap(Self.scope(of:)))
        let now = session.environment.clock.now
        let left = Self.duration - now.timeIntervalSince(unlockedAt)
        guard method == .biometrics, session.state == .unlocked, Self.allowed(settings), !scopes.isEmpty,
            now >= unlockedAt, left > 0
        else { return false }
        // Locked elsewhere between the Face ID and now: that lock wins.
        let stamp = lockStamps.latest(for: settings)
        if let stamp, stamp.lockedAt > unlockedAt { return false }
        // No way to see the device lock: no window.
        guard let deviceLock = deviceLockSignal.watch() else { return false }
        if held?.session !== session { end() }
        expiry?.cancel()
        held = Held(
            session: session, scopes: scopes, account: settings.scope, unlockedAt: unlockedAt,
            deadline: ContinuousClock.now + .seconds(left), lockMark: stamp?.mark, deviceLock: deviceLock)
        watchMemoryPressure()
        expiry = Task { [weak self] in
            try? await Task.sleep(for: .seconds(left))
            guard !Task.isCancelled else { return }
            self?.endIfExpired()
        }
        return true
    }

    /// The kept session when it may answer a `kind` request of `service` for `account` (nil: the
    /// primary account). A request for another service or account ends the window, as does time, a
    /// session locked meanwhile, a lock of the account or of the device since the grant, the
    /// setting turned off or the device turned shared. A passkey is never served and leaves the
    /// window as it is.
    public func session(for service: AutoFillService, kind: FfiAutofillKind, account: String?) -> VaultSession? {
        requestArrived(for: service, account: account)
        guard let held, kind != .passkey else { return nil }
        return held.session
    }

    /// Every request the provider receives: one for another service or account ends the window;
    /// one without a service (text insertion) leaves it.
    public func requestArrived(for service: AutoFillService?, account: String?) {
        guard let held else { return }
        guard isLive(held) else {
            end()
            return
        }
        guard let service else { return }
        guard held.account == account, let scope = Self.scope(of: service), held.scopes.contains(scope) else {
            end()
            return
        }
    }

    /// Locks the kept session (its keys are dropped) and forgets it.
    public func end() {
        expiry?.cancel()
        expiry = nil
        guard let held else { return }
        self.held = nil
        // The provider's own lock: not a lock of the account for the other processes.
        held.session.lock(publishPending: false, stampsAccountLock: false)
    }

    private func endIfExpired() {
        guard let held, !isLive(held) else { return }
        end()
    }

    /// The system is short of memory: the kept session goes first.
    func memoryPressure() {
        end()
    }

    private func watchMemoryPressure() {
        guard pressure == nil else { return }
        let source = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: .main)
        source.setEventHandler { [weak self] in
            MainActor.assumeIsolated { self?.memoryPressure() }
        }
        source.resume()
        pressure = source
    }

    private func isLive(_ held: Held) -> Bool {
        let settings = held.session.environment.settings
        let now = held.session.environment.clock.now
        return held.session.state == .unlocked && Self.allowed(settings)
            && now >= held.unlockedAt && now.timeIntervalSince(held.unlockedAt) < Self.duration
            && ContinuousClock.now < held.deadline
            // No lock of the account (any process) and none of the device since the grant.
            && lockStamps.latest(for: settings)?.mark == held.lockMark
            && !held.deviceLock.changed()
    }

    /// Personal device, setting on, and no Apple Watch in the biometric path (Mac: with the Watch
    /// allowed, an approval on the wrist opens the same key as Touch ID, and the window is for
    /// biometry on the device itself).
    private nonisolated static func allowed(_ settings: VaultSettings) -> Bool {
        settings.autofillUnlockReuse && settings.deviceMode == .personal && !settings.allowWatchUnlock
    }
}
