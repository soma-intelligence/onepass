import Foundation
import Synchronization

@testable import VaultKit

/// Fake Secure Enclave: reversible obfuscation, key invalidation on demand.
final class FakeEnclaveKeyring: EnclaveKeyring {
    private struct State {
        var keys: Set<String> = []
        var invalidated = false
        var cancelNext = false
    }
    private let state = Mutex(State())
    let available: Bool

    init(available: Bool = true) { self.available = available }

    var isAvailable: Bool { available }

    func invalidate() { state.withLock { $0.invalidated = true } }
    func cancelNextDecrypt() { state.withLock { $0.cancelNext = true } }
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
        let (known, invalidated, cancel) = state.withLock { s -> (Bool, Bool, Bool) in
            let c = s.cancelNext
            s.cancelNext = false
            return (s.keys.contains(tag), s.invalidated, c)
        }
        if cancel { throw EnclaveError.cancelled }
        guard known, !invalidated else { throw EnclaveError.keyInvalidated }
        return Data(data.dropLast(3).map { $0 ^ 0x5A })
    }

    func deleteKey(tag: String) throws {
        state.withLock { _ = $0.keys.remove(tag) }
    }
}

final class FakeClock: BootClock {
    private let state: Mutex<(boot: Date, now: Date)>

    init(boot: Date = Date(timeIntervalSince1970: 1_000_000), now: Date = Date(timeIntervalSince1970: 2_000_000)) {
        state = Mutex((boot, now))
    }

    var bootTime: Date { state.withLock { $0.boot } }
    var now: Date { state.withLock { $0.now } }
    func advance(_ seconds: TimeInterval) { state.withLock { $0.now = $0.now.addingTimeInterval(seconds) } }
    func reboot() { state.withLock { $0.boot = $0.now.addingTimeInterval(-10) } }
}
