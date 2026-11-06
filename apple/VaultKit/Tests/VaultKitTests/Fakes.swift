import Foundation
import Synchronization

@testable import VaultKit

/// Fake Secure Enclave: reversible obfuscation, key invalidation on demand.
final class FakeEnclaveKeyring: EnclaveKeyring {
    private struct State {
        var keys: Set<String> = []
        var invalidated = false
        var nextError: EnclaveError?
        var created = 0
        var duringDecrypt: (@Sendable () -> Void)?
    }
    private let state = Mutex(State())
    let available: Bool
    let storesKeys: Bool

    init(available: Bool = true, storesKeys: Bool = true) {
        self.available = available
        self.storesKeys = storesKeys
    }

    var isAvailable: Bool { available }
    var canStoreKeys: Bool { storesKeys }

    func invalidate() { state.withLock { $0.invalidated = true } }
    func failNextDecrypt(with error: EnclaveError) { state.withLock { $0.nextError = error } }
    /// Runs while the next decryption "shows the system sheet" (another process writing meanwhile).
    func duringNextDecrypt(_ action: @escaping @Sendable () -> Void) { state.withLock { $0.duringDecrypt = action } }
    /// Keys created so far (a new enrollment creates one).
    var createdKeys: Int { state.withLock { $0.created } }
    func hasKey(tag: String) -> Bool { state.withLock { $0.keys.contains(tag) } }

    func createKey(tag: String, allowWatch: Bool) throws {
        state.withLock {
            $0.keys.insert(tag)
            $0.invalidated = false
            $0.created += 1
        }
    }

    func encrypt(_ data: Data, tag: String) throws -> Data {
        guard hasKey(tag: tag) else { throw EnclaveError.keyInvalidated }
        return Data(data.map { $0 ^ 0x5A }) + Data("enc".utf8)
    }

    func decrypt(_ data: Data, tag: String, prompt: String) async throws -> Data {
        let during = state.withLock { s -> (@Sendable () -> Void)? in
            defer { s.duringDecrypt = nil }
            return s.duringDecrypt
        }
        during?()
        let (known, invalidated, next) = state.withLock { s -> (Bool, Bool, EnclaveError?) in
            let e = s.nextError
            s.nextError = nil
            return (s.keys.contains(tag), s.invalidated, e)
        }
        if let next { throw next }
        guard known, !invalidated else { throw EnclaveError.keyInvalidated }
        return Data(data.dropLast(3).map { $0 ^ 0x5A })
    }

    func deleteKey(tag: String) throws {
        state.withLock { _ = $0.keys.remove(tag) }
    }
}

final class FakeClock: BootClock {
    private let state: Mutex<(boot: String, bootTime: Date?, now: Date)>

    init(boot: String = "boot-1", now: Date = Date(timeIntervalSince1970: 2_000_000), bootTime: Date? = nil) {
        state = Mutex((boot, bootTime ?? now.addingTimeInterval(-3600), now))
    }

    var bootSessionID: String { state.withLock { $0.boot } }
    var bootTime: Date? { state.withLock { $0.bootTime } }
    var now: Date { state.withLock { $0.now } }
    func advance(_ seconds: TimeInterval) { state.withLock { $0.now = $0.now.addingTimeInterval(seconds) } }
    /// A new boot session id and a boot time a minute ago.
    func reboot() {
        state.withLock {
            $0.boot = "boot-" + UUID().uuidString
            $0.bootTime = $0.now.addingTimeInterval(-60)
        }
    }
    func setBoot(_ id: String) { state.withLock { $0.boot = id } }
    func setBootTime(_ time: Date?) { state.withLock { $0.bootTime = time } }
}

/// Keychain whose reads can fail (locked keychain).
final class FailingReadKeychain: KeychainStore {
    let inner = InMemoryKeychain()
    private let failing = Mutex(false)
    func failReads(_ on: Bool) { failing.withLock { $0 = on } }
    func read(_ key: String) throws -> Data? {
        if failing.withLock({ $0 }) { throw KeychainError.unexpectedStatus(-25308) }
        return try inner.read(key)
    }
    func write(_ key: String, _ data: Data) throws { try inner.write(key, data) }
    func delete(_ key: String) throws { try inner.delete(key) }
}

/// Keychain whose writes fail (unsigned iOS build: no keychain access, -34018).
final class FailingWriteKeychain: KeychainStore {
    let inner = InMemoryKeychain()
    private let failing = Mutex(true)
    func failWrites(_ on: Bool) { failing.withLock { $0 = on } }
    func read(_ key: String) throws -> Data? { try inner.read(key) }
    func write(_ key: String, _ data: Data) throws {
        if failing.withLock({ $0 }) { throw KeychainError.unexpectedStatus(-34018) }
        try inner.write(key, data)
    }
    func delete(_ key: String) throws { try inner.delete(key) }
}

/// Pasteboard double: tracks its own change count like `NSPasteboard`.
final class FakePasteboard: PasteboardWriter {
    struct State {
        var contents: String?
        var concealed = false
        var expiresAfter: TimeInterval?
        var changeCount = 0
        var ownChange: Int?
    }
    private let state = Mutex(State())

    var snapshot: State { state.withLock { $0 } }

    func write(_ s: String, concealed: Bool, expiresAfter: TimeInterval) {
        state.withLock {
            $0.contents = s
            $0.concealed = concealed
            $0.expiresAfter = expiresAfter
            $0.changeCount += 1
            $0.ownChange = $0.changeCount
        }
    }

    func clearIfUnchanged() {
        state.withLock {
            guard $0.ownChange == $0.changeCount else { return }
            $0.contents = nil
            $0.changeCount += 1
            $0.ownChange = nil
        }
    }

    /// Another app copies something.
    func externalWrite(_ s: String) {
        state.withLock {
            $0.contents = s
            $0.changeCount += 1
        }
    }
}

/// Records the sync notifications, in order.
final class RecordingSync: SyncTrigger {
    enum Event: Equatable { case written, unlocked, locked }
    private let log = Mutex<[Event]>([])
    var events: [Event] { log.withLock { $0 } }

    func localChangesWritten() async { log.withLock { $0.append(.written) } }
    func sessionUnlocked(_ session: Session) async { log.withLock { $0.append(.unlocked) } }
    func sessionLocked() async { log.withLock { $0.append(.locked) } }
}

/// Answers the presence prompt with a preset result and counts the prompts: `prompts` for the
/// device owner check (biometrics or passcode), `biometricPrompts` for the biometrics-only one. After
/// `hold()`, a prompt waits until `release()` (a user still looking at Face ID).
final class FakePresence: PresenceChecker {
    private struct State {
        var answer = true
        var prompts = 0
        var biometricPrompts = 0
        var held = false
        var waiting: [CheckedContinuation<Void, Never>] = []
    }
    private let state = Mutex(State())
    var prompts: Int { state.withLock { $0.prompts } }
    var biometricPrompts: Int { state.withLock { $0.biometricPrompts } }
    /// Prompts waiting for `release()`.
    var pending: Int { state.withLock { $0.waiting.count } }
    func answer(_ value: Bool) { state.withLock { $0.answer = value } }
    func hold() { state.withLock { $0.held = true } }
    func release() {
        let waiting = state.withLock { s in
            s.held = false
            defer { s.waiting = [] }
            return s.waiting
        }
        for w in waiting { w.resume() }
    }

    func confirm(prompt: String) async -> Bool {
        state.withLock { $0.prompts += 1 }
        return await answered()
    }

    func confirmWithBiometrics(prompt: String) async -> Bool {
        state.withLock { $0.biometricPrompts += 1 }
        return await answered()
    }

    private func answered() async -> Bool {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            let go = state.withLock { s -> Bool in
                guard s.held else { return true }
                s.waiting.append(c)
                return false
            }
            if go { c.resume() }
        }
        return state.withLock { $0.answer }
    }
}

/// Keychain whose writes report success but land where reads never look (the Debug fallback bug:
/// written to the file keychain, looked up in the data protection keychain only).
final class WriteOnlyKeychain: KeychainStore {
    func read(_ key: String) throws -> Data? { nil }
    func write(_ key: String, _ data: Data) throws {}
    func delete(_ key: String) throws {}
}

/// Scripted `MailboxSyncing`: each round answers the next scripted report (then `Idle`), records the
/// session it got, and can block until released.
final class FakeMailboxSync: MailboxSyncing {
    private struct State {
        var reports: [FfiRoundReport] = []
        var sessions: [Bool] = []
        var rounds = 0
        var running = 0
        var maxRunning = 0
        var gate: CheckedContinuation<Void, Never>?
        var holdNext = false
        var wakes: [@Sendable () -> Void] = []
        var wakeStops = 0
        var calls: [String] = []
        var failGrant: Error?
        var failLocator: Error?
        var locators: [Data] = []
        var grants: [(Data, FfiCredentialRole)] = []
        var pushes: [(FfiPushKind, Data)] = []
    }
    private let state = Mutex(State())

    static func report(
        _ status: FfiRoundStatus, changed: Bool = false, retryAfter: UInt32? = nil, rerun: Bool = false
    ) -> FfiRoundReport {
        FfiRoundReport(status: status, changed: changed, rebased: [], retryAfterSeconds: retryAfter, rerun: rerun)
    }

    func script(_ reports: [FfiRoundReport]) { state.withLock { $0.reports += reports } }
    /// The next round waits for `release()`.
    func holdNextRound() { state.withLock { $0.holdNext = true } }
    func release() {
        let gate = state.withLock { s -> CheckedContinuation<Void, Never>? in
            defer { s.gate = nil }
            return s.gate
        }
        gate?.resume()
    }

    var rounds: Int { state.withLock { $0.rounds } }
    var maxRunning: Int { state.withLock { $0.maxRunning } }
    /// Per round: whether a session was passed.
    var sessions: [Bool] { state.withLock { $0.sessions } }
    var wakeListeners: Int { state.withLock { $0.wakes.count } }
    var wakeStops: Int { state.withLock { $0.wakeStops } }
    var calls: [String] { state.withLock { $0.calls } }
    var locators: [Data] { state.withLock { $0.locators } }
    var grantedKeys: [Data] { state.withLock { $0.grants.map(\.0) } }
    var pushes: [(FfiPushKind, Data)] { state.withLock { $0.pushes } }

    /// Fires every wake listener started.
    func wake() {
        for w in state.withLock({ $0.wakes }) { w() }
    }

    func runRound(session: Session?, now: Int64) async -> FfiRoundReport {
        let hold = state.withLock { s -> Bool in
            s.rounds += 1
            s.running += 1
            s.maxRunning = max(s.maxRunning, s.running)
            s.sessions.append(session != nil)
            s.calls.append("round")
            defer { s.holdNext = false }
            return s.holdNext
        }
        if hold {
            await withCheckedContinuation { c in state.withLock { $0.gate = c } }
        }
        return state.withLock { s in
            s.running -= 1
            return s.reports.isEmpty ? Self.report(.idle) : s.reports.removeFirst()
        }
    }

    func wakeInfo() async throws -> FfiWakeInfo {
        FfiWakeInfo(realtimeUrl: "wss://localhost/realtime/v1", publishableKey: "pk", topic: String(repeating: "0", count: 32))
    }

    func startWake(_ onWake: @escaping @Sendable () -> Void) async throws -> any WakeStopping {
        state.withLock { $0.wakes.append(onWake) }
        return Stopper(owner: self)
    }

    fileprivate func stopped() {
        state.withLock {
            $0.wakeStops += 1
            $0.wakes.removeAll()
        }
    }

    func setPushToken(kind: FfiPushKind, token: Data) async throws {
        state.withLock {
            $0.calls.append("push")
            $0.pushes.append((kind, token))
        }
    }

    func failNextGrant(_ error: Error) { state.withLock { $0.failGrant = error } }

    func grant(publicKey: Data, role: FfiCredentialRole, label: Data) async throws -> String {
        try state.withLock { s in
            s.calls.append("grant")
            if let e = s.failGrant {
                s.failGrant = nil
                throw e
            }
            s.grants.append((publicKey, role))
        }
        return publicKey.prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    func failNextLocator(_ error: Error) { state.withLock { $0.failLocator = error } }

    func setLocator(_ locator: Data) async throws {
        try state.withLock { s in
            s.calls.append("locator")
            if let e = s.failLocator {
                s.failLocator = nil
                throw e
            }
            s.locators.append(locator)
        }
    }

    func abandon() async throws {
        state.withLock { $0.calls.append("abandon") }
    }

    private struct Stopper: WakeStopping {
        let owner: FakeMailboxSync
        func stop() { owner.stopped() }
    }
}

/// Scripted `MailboxProvisioning`: counts the calls, creates mailboxes with fresh ids, opens the
/// one `FakeMailboxSync` for every mailbox.
final class FakeMailboxProvisioning: MailboxProvisioning {
    private struct State {
        var calls: [String] = []
        var created = 0
        var failNext: [String: Error] = [:]
        var openedSeeds: [Data] = []
        var located: [String: [String]] = [:]
    }
    private let state = Mutex(State())
    let sync = FakeMailboxSync()

    var calls: [String] { state.withLock { $0.calls } }
    var mailboxesCreated: Int { state.withLock { $0.created } }
    var openedSeeds: [Data] { state.withLock { $0.openedSeeds } }

    /// The next call named `call` ("check", "credential", "create", "open") throws `error`.
    func failNext(_ call: String, _ error: Error) { state.withLock { $0.failNext[call] = error } }

    private func enter(_ call: String) throws {
        try state.withLock { s in
            s.calls.append(call)
            if let e = s.failNext.removeValue(forKey: call) { throw e }
        }
    }

    func check(_ endpoint: FfiMailboxEndpoint) async throws -> FfiMailboxServerInfo {
        try enter("check")
        return FfiMailboxServerInfo(openSignup: true)
    }

    func generateCredential() async throws -> FfiMailboxCredential {
        try enter("credential")
        let seed = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        return FfiMailboxCredential(seed: seed, publicKey: Data(seed.reversed()), id: String(repeating: "c", count: 32))
    }

    func create(_ endpoint: FfiMailboxEndpoint, seed: Data, invite: String?) async throws -> FfiMailboxHome {
        try enter("create")
        let n = state.withLock { s -> Int in
            s.created += 1
            return s.created
        }
        return FfiMailboxHome(baseUrl: endpoint.baseUrl, mailboxId: String(format: "%032x", n), incarnation: 1)
    }

    func open(_ home: MailboxHome, seed: Data) async throws -> any MailboxSyncing {
        try enter("open")
        state.withLock { $0.openedSeeds.append(seed) }
        return sync
    }

    /// `locate` on `baseURL` answers `ids`.
    func register(_ ids: [String], at baseURL: URL) { state.withLock { $0.located[baseURL.absoluteString] = ids } }

    func locate(_ endpoint: FfiMailboxEndpoint, locator: Data) async throws -> [String] {
        try enter("locate \(endpoint.baseUrl)")
        return state.withLock { $0.located[endpoint.baseUrl] ?? [] }
    }
}

/// Scripted `ZoneSyncing` (sharing plan 4, Task 5): each zone round answers the next scripted report
/// (then an empty one), records the order of calls against a shared log, and keeps the wake
/// listeners and push targets it was given.
final class FakeZoneSync: ZoneSyncing {
    private struct State {
        var reports: [FfiZoneRoundReport] = []
        var rounds = 0
        var sessions: [Bool] = []
        var topics: [FfiZoneWake] = []
        var wakes: [String: @Sendable () -> Void] = [:]
        var targets: [(String, Data, Data)] = []
        var failTarget: Set<String> = []
    }
    private let state = Mutex(State())
    /// Runs at the start of each zone round (tests check what ran before it).
    private let onRound: (@Sendable () -> Void)?

    init(onRound: (@Sendable () -> Void)? = nil) {
        self.onRound = onRound
    }

    static func zone(_ kind: FfiZoneKind, _ byte: UInt8 = 1) -> FfiZone {
        FfiZone(kind: kind, id: kind == .private ? nil : String(repeating: String(format: "%02x", byte), count: 16))
    }

    static func report(
        zones: [(FfiZone, FfiRoundStatus)] = [], refusals: [FfiZoneRefusal] = [], quotaFull: [FfiZone] = [],
        changed: Bool = false, retryAfter: UInt32? = nil, rerun: Bool = false, actions: UInt32 = 0
    ) -> FfiZoneRoundReport {
        FfiZoneRoundReport(
            zones: zones.map { FfiZoneStatus(zone: $0.0, status: $0.1) }, actionsDone: actions,
            refusals: refusals, quotaFull: quotaFull, changed: changed, retryAfterSeconds: retryAfter, rerun: rerun)
    }

    static func wake(_ mailboxByte: UInt8, zone: FfiZone) -> FfiZoneWake {
        FfiZoneWake(
            zone: zone, mailboxId: String(repeating: String(format: "%02x", mailboxByte), count: 16),
            wake: FfiWakeInfo(realtimeUrl: "wss://localhost/realtime/v1", publishableKey: "pk",
                              topic: String(repeating: String(format: "%02x", mailboxByte), count: 16)))
    }

    func script(_ reports: [FfiZoneRoundReport]) { state.withLock { $0.reports += reports } }
    func setTopics(_ topics: [FfiZoneWake]) { state.withLock { $0.topics = topics } }
    func failTarget(mailbox: String) { state.withLock { _ = $0.failTarget.insert(mailbox) } }

    var rounds: Int { state.withLock { $0.rounds } }
    var sessions: [Bool] { state.withLock { $0.sessions } }
    var wakeListeners: Int { state.withLock { $0.wakes.count } }
    /// Push targets set: mailbox id, tag, token.
    var targets: [(String, Data, Data)] { state.withLock { $0.targets } }

    /// Fires the wake listener of one mailbox.
    func wake(mailbox: String) {
        state.withLock { $0.wakes[mailbox] }?()
    }

    func runRound(session: Session?, now: Int64) async -> FfiZoneRoundReport {
        onRound?()
        return state.withLock { s in
            s.rounds += 1
            s.sessions.append(session != nil)
            return s.reports.isEmpty ? Self.report() : s.reports.removeFirst()
        }
    }

    func wakeTopics() async -> [FfiZoneWake] { state.withLock { $0.topics } }

    func startWake(_ info: FfiWakeInfo, onWake: @escaping @Sendable () -> Void) async throws -> any WakeStopping {
        state.withLock { $0.wakes[info.topic] = onWake }
        return Stopper(owner: self, topic: info.topic)
    }

    fileprivate func stopped(_ topic: String) {
        state.withLock { _ = $0.wakes.removeValue(forKey: topic) }
    }

    func setPushTarget(mailboxID: String, tag: Data, kind: FfiPushKind, token: Data) async throws {
        try state.withLock { s in
            if s.failTarget.contains(mailboxID) { throw OnePassError.MailboxUnavailable(reason: "offline") }
            s.targets.append((mailboxID, tag, token))
        }
    }

    private struct Stopper: WakeStopping {
        let owner: FakeZoneSync
        let topic: String
        func stop() { owner.stopped(topic) }
    }
}

/// An ordered log of calls shared by several fakes.
final class CallLog: Sendable {
    private let entries = Mutex<[String]>([])
    func append(_ entry: String) { entries.withLock { $0.append(entry) } }
    var all: [String] { entries.withLock { $0 } }
}
