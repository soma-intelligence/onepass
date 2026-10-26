import Foundation
import Synchronization

/// Keychain double for tests and previews. Never persists anything.
public final class InMemoryKeychain: KeychainStore {
    private let storage = Mutex<[String: Data]>([:])

    public init() {}

    public func read(_ key: String) throws -> Data? {
        storage.withLock { $0[key] }
    }

    public func write(_ key: String, _ data: Data) throws {
        storage.withLock { $0[key] = data }
    }

    public func contains(_ key: String) throws -> Bool {
        storage.withLock { $0[key] != nil }
    }

    public func delete(_ key: String) throws {
        storage.withLock { _ = $0.removeValue(forKey: key) }
    }
}
