import Foundation
import Synchronization

@testable import VaultKit

/// Fake Secure Enclave: reversible obfuscation, key invalidation on demand.
final class FakeEnclaveKeyring: EnclaveKeyring {
    private struct State {
        var keys: Set<String> = []
        var invalidated = false
        var nextError: EnclaveError?
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
    func hasKey(tag: String) -> Bool { state.withLock { $0.keys.contains(tag) } }

    func createKey(tag: String, allowWatch: Bool) throws {
        state.withLock {
            $0.keys.insert(tag)
            $0.invalidated = false
        }
    }

    func encrypt(_ data: Data, tag: String) throws -> Data {
        guard hasKey(tag: tag) else { throw EnclaveError.keyInvalidated }
        return Data(data.map { $0 ^ 0x5A }) + Data("enc".utf8)
    }

    func decrypt(_ data: Data, tag: String, prompt: String) async throws -> Data {
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
    private let state: Mutex<(boot: String, now: Date)>

    init(boot: String = "boot-1", now: Date = Date(timeIntervalSince1970: 2_000_000)) {
        state = Mutex((boot, now))
    }

    var bootSessionID: String { state.withLock { $0.boot } }
    var now: Date { state.withLock { $0.now } }
    func advance(_ seconds: TimeInterval) { state.withLock { $0.now = $0.now.addingTimeInterval(seconds) } }
    func reboot() { state.withLock { $0.boot = "boot-" + UUID().uuidString } }
    func setBoot(_ id: String) { state.withLock { $0.boot = id } }
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
