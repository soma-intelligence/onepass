import Foundation
import Security
import Synchronization

/// Where the watch keeps its key pair and the last accepted payload generation. The public key
/// is kept next to the secret: the watch resends it to the iPhone on every start.
public protocol WatchKeyStore: Sendable {
    func loadSecret() throws -> Data?
    func saveSecret(_ secret: Data) throws
    func loadPublicKey() throws -> Data?
    func savePublicKey(_ publicKey: Data) throws
    /// 0 when none was saved. Throws when the store cannot be read: the caller must then refuse
    /// every payload (a read failure must never lower the replay floor).
    func loadGeneration() throws -> UInt64
    func saveGeneration(_ g: UInt64) throws
    func deleteAll() throws
}

public enum WatchKeyStoreError: Error, Equatable {
    /// No passcode on the watch: `WhenPasscodeSetThisDeviceOnly` items cannot be created.
    case passcodeRequired
    case keychain(OSStatus)
}

/// Generic password items in the data protection keychain (service `me.somalabs.onepass.watch`),
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`: never backed up, never synced, unreadable
/// while the watch is locked, and impossible to create without a passcode.
public struct SystemWatchKeyStore: WatchKeyStore {
    public static let service = "me.somalabs.onepass.watch"
    private enum Account: String, CaseIterable {
        case secret, publicKey = "public", generation
    }

    public init() {}

    public func loadSecret() throws -> Data? { try read(.secret) }
    public func saveSecret(_ secret: Data) throws { try write(secret, to: .secret) }
    public func loadPublicKey() throws -> Data? { try read(.publicKey) }
    public func savePublicKey(_ publicKey: Data) throws { try write(publicKey, to: .publicKey) }

    public func loadGeneration() throws -> UInt64 {
        guard let data = try read(.generation) else { return 0 }
        guard data.count == 8 else { throw WatchKeyStoreError.keychain(errSecDecode) }
        return data.withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(as: UInt64.self)) }
    }

    public func saveGeneration(_ g: UInt64) throws {
        try write(withUnsafeBytes(of: g.bigEndian) { Data($0) }, to: .generation)
    }

    public func deleteAll() throws {
        for account in Account.allCases {
            let status = SecItemDelete(query(account) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw WatchKeyStoreError.keychain(status)
            }
        }
    }

    private func query(_ account: Account) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account.rawValue,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private func read(_ account: Account) throws -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw WatchKeyStoreError.keychain(status)
        }
    }

    /// Updates in place (never a window without the item, which would reset the generation),
    /// and adds with the accessibility class only when the item does not exist yet.
    private func write(_ data: Data, to account: Account) throws {
        let updated = SecItemUpdate(
            query(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updated == errSecSuccess { return }
        guard updated == errSecItemNotFound else { throw WatchKeyStoreError.keychain(updated) }
        var add = query(account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        switch status {
        case errSecSuccess: return
        case errSecDecode, errSecParam, errSecNotAvailable: throw WatchKeyStoreError.passcodeRequired
        default: throw WatchKeyStoreError.keychain(status)
        }
    }
}

/// In-memory store for tests and previews. `passcodeSet: false` behaves like a watch without a
/// passcode: every save throws `passcodeRequired`.
public final class InMemoryWatchKeyStore: WatchKeyStore {
    private struct State {
        var secret: Data?
        var publicKey: Data?
        var generation: UInt64 = 0
    }

    private struct Switches {
        var passcodeSet: Bool
        var isLocked = false
        var generationReadFails = false
        var deleteFails = false
    }

    private let state = Mutex(State())
    private let switches: Mutex<Switches>

    public init(passcodeSet: Bool = true) {
        switches = Mutex(Switches(passcodeSet: passcodeSet))
    }

    /// Whether the simulated watch has a passcode (settable: the user may add one later).
    public var passcodeSet: Bool {
        get { switches.withLock { $0.passcodeSet } }
        set { switches.withLock { $0.passcodeSet = newValue } }
    }

    /// A locked watch: every read throws, as the keychain does for `WhenPasscodeSet` items.
    public var isLocked: Bool {
        get { switches.withLock { $0.isLocked } }
        set { switches.withLock { $0.isLocked = newValue } }
    }

    /// Only the generation read throws.
    public var generationReadFails: Bool {
        get { switches.withLock { $0.generationReadFails } }
        set { switches.withLock { $0.generationReadFails = newValue } }
    }

    /// Only `deleteAll()` throws (and deletes nothing).
    public var deleteFails: Bool {
        get { switches.withLock { $0.deleteFails } }
        set { switches.withLock { $0.deleteFails = newValue } }
    }

    public func loadSecret() throws -> Data? {
        try requireUnlocked()
        return state.withLock { $0.secret }
    }

    public func loadPublicKey() throws -> Data? {
        try requireUnlocked()
        return state.withLock { $0.publicKey }
    }

    public func loadGeneration() throws -> UInt64 {
        try requireUnlocked()
        if generationReadFails { throw WatchKeyStoreError.keychain(errSecInteractionNotAllowed) }
        return state.withLock { $0.generation }
    }

    public func saveSecret(_ secret: Data) throws {
        try requirePasscode()
        state.withLock { $0.secret = secret }
    }

    public func savePublicKey(_ publicKey: Data) throws {
        try requirePasscode()
        state.withLock { $0.publicKey = publicKey }
    }

    public func saveGeneration(_ g: UInt64) throws {
        try requirePasscode()
        state.withLock { $0.generation = g }
    }

    public func deleteAll() throws {
        if deleteFails { throw WatchKeyStoreError.keychain(errSecInteractionNotAllowed) }
        state.withLock { $0 = State() }
    }

    private func requireUnlocked() throws {
        if isLocked { throw WatchKeyStoreError.keychain(errSecInteractionNotAllowed) }
    }

    private func requirePasscode() throws {
        try requireUnlocked()
        if !passcodeSet { throw WatchKeyStoreError.passcodeRequired }
    }
}
