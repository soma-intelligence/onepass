import Foundation
import Synchronization

/// Keychain double for tests and previews. Never persists anything.
public final class InMemoryKeychain: KeychainStore {
    private let storage = Mutex<[String: Data]>([:])
    private let afterFirstUnlock = Mutex<Set<String>>([])

    public init() {}

    public func read(_ key: String) throws -> Data? {
        storage.withLock { $0[key] }
    }

    public func write(_ key: String, _ data: Data) throws {
        storage.withLock { $0[key] = data }
        afterFirstUnlock.withLock { _ = $0.remove(key) }
    }

    public func writeAfterFirstUnlock(_ key: String, _ data: Data) throws {
        storage.withLock { $0[key] = data }
        afterFirstUnlock.withLock { _ = $0.insert(key) }
    }

    /// Tests: whether `key` was last written readable after the first unlock.
    public func isAfterFirstUnlock(_ key: String) -> Bool {
        afterFirstUnlock.withLock { $0.contains(key) }
    }

    /// Tests: every key held.
    public var keys: Set<String> {
        storage.withLock { Set($0.keys) }
    }

    public func contains(_ key: String) throws -> Bool {
        storage.withLock { $0[key] != nil }
    }

    public func delete(_ key: String) throws {
        storage.withLock { _ = $0.removeValue(forKey: key) }
        afterFirstUnlock.withLock { _ = $0.remove(key) }
    }
}
