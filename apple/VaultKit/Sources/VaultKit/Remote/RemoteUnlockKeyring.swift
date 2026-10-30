import Foundation
import LocalAuthentication
import Security
import os

/// A read behind Face ID of the current biometric set.
public enum KeyringRead: Sendable, Equatable {
    case found(Data)
    /// No such item: never written, or invalidated by a change of the biometric set (a face or an
    /// alternate appearance added, Face ID reset). Asking again will not bring it back.
    case missing
    /// Face ID failed, was cancelled or is unavailable: asking again may work.
    case refused
}

/// The phone's half of the remote unlock (agent-ready spec 6.1): `K_r` of each enrolled Mac. Every
/// read is a Face ID of the current biometric set; nothing is ever logged.
public protocol RemoteUnlockKeyring: Sendable {
    /// Stores `key` for `mac`, replacing an earlier one.
    func save(_ key: Data, for mac: String) throws
    /// `K_r` of `mac` behind Face ID.
    func read(for mac: String, prompt: String) async -> KeyringRead
    func delete(for mac: String) throws
    /// The Macs this phone holds a key for (no Face ID: attributes only).
    func macs() throws -> [String]
}

/// What a Face ID of the current set answered.
public enum FaceIDCheck: Sendable, Equatable {
    case confirmed
    case refused
    /// The biometric set changed since the gate was armed: `arm()` again (vault open, fresh Face ID).
    case invalidated
}

/// A presence check that tells a refusal from a biometric set that changed (agent-ready spec 5.3:
/// Face ID with `.biometryCurrentSet`).
public protocol FaceIDGate: PresenceChecker {
    func check(prompt: String) async -> FaceIDCheck
    /// Writes the gate again for the current biometric set.
    func arm() throws
    func disarm() throws
}

extension FaceIDGate {
    public func confirm(prompt: String) async -> Bool { await check(prompt: prompt) == .confirmed }
    public func confirmWithBiometrics(prompt: String) async -> Bool { await check(prompt: prompt) == .confirmed }
}

/// `RemoteUnlockKeyring` in the data protection keychain of this iPhone: generic passwords guarded
/// by `.biometryCurrentSet` (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, never
/// synchronizable), in their own service of the app's default access group, so no extension and no
/// other device reads them. A new face or appearance makes them unreadable: the Mac enrolls again.
///
/// The same protection guards a presence item (`gate`): reading it is the Face ID every remote
/// answer asks (`CurrentBiometryPresence`).
public struct SystemRemoteUnlockKeyring: RemoteUnlockKeyring {
    static let service = "me.somalabs.onepass.remote-unlock-phone"
    static let keyPrefix = "kr."
    static let gateAccount = "gate"
    /// This device only, and only while a passcode is set (removing it erases the items).
    public static var protection: CFString { kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly }
    /// Face ID (or Touch ID) of the biometric set enrolled when the item was written.
    public static let accessFlags: SecAccessControlCreateFlags = .biometryCurrentSet
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "remote")

    public init() {}

    /// The attributes every item is written with (the tests check them). Throws rather than ever
    /// returning attributes without the access control.
    static func itemAttributes(for mac: String) throws -> [String: Any] {
        try attributes(account: keyPrefix + mac)
    }

    private static func attributes(account: String) throws -> [String: Any] {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, protection, accessFlags, &error) else {
            _ = error?.takeRetainedValue()
            throw KeychainError.unexpectedStatus(errSecParam)
        }
        var query = baseQuery(account: account)
        query[kSecAttrSynchronizable as String] = false
        query[kSecAttrAccessControl as String] = access
        return query
    }

    private static func baseQuery(account: String?) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let account { query[kSecAttrAccount as String] = account }
        return query
    }

    public func save(_ key: Data, for mac: String) throws {
        try Self.write(key, account: Self.keyPrefix + mac)
    }

    public func read(for mac: String, prompt: String) async -> KeyringRead {
        await Self.read(account: Self.keyPrefix + mac, prompt: prompt)
    }

    public func delete(for mac: String) throws {
        try Self.delete(account: Self.keyPrefix + mac)
    }

    public func macs() throws -> [String] {
        var query = Self.baseQuery(account: nil)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            let items = result as? [[String: Any]] ?? []
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
                .filter { $0.hasPrefix(Self.keyPrefix) }
                .map { String($0.dropFirst(Self.keyPrefix.count)) }
        case errSecItemNotFound:
            return []
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }

    // MARK: - Presence item

    /// Writes the presence item again (enabling approvals on this iPhone, or after a biometric
    /// change made the old one unreadable).
    public func armPresence() throws {
        try Self.write(Data((0..<16).map { _ in UInt8.random(in: 0...255) }), account: Self.gateAccount)
    }

    public func disarmPresence() throws {
        try Self.delete(account: Self.gateAccount)
    }

    /// Face ID of the current set, read on the presence item.
    public func checkPresence(prompt: String) async -> FaceIDCheck {
        switch await Self.read(account: Self.gateAccount, prompt: prompt) {
        case .found: .confirmed
        case .missing: .invalidated
        case .refused: .refused
        }
    }

    // MARK: - Keychain

    private static func write(_ data: Data, account: String) throws {
        // Built first: without its access control, nothing is written (nor the old item erased).
        var add = try attributes(account: account)
        add[kSecValueData as String] = data
        // An access control cannot be updated in place: the item is replaced.
        try delete(account: account)
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    private static func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    /// The read blocks while Face ID is up: off the caller's thread, and dismissed on cancel.
    private static func read(account: String, prompt: String) async -> KeyringRead {
        let context = LAContext()
        context.localizedReason = prompt
        let box = UncheckedContext(context)
        return await withTaskCancellationHandler {
            await Task.detached(priority: .userInitiated) { () -> KeyringRead in
                var query = baseQuery(account: account)
                query[kSecReturnData as String] = true
                query[kSecMatchLimit as String] = kSecMatchLimitOne
                query[kSecUseAuthenticationContext as String] = box.context
                var result: CFTypeRef?
                let status = SecItemCopyMatching(query as CFDictionary, &result)
                switch status {
                case errSecSuccess:
                    guard let data = result as? Data else { return .refused }
                    return .found(data)
                case errSecItemNotFound:
                    return .missing
                default:
                    if status != errSecUserCanceled && status != errSecAuthFailed {
                        log.error("remote unlock keychain read failed: \(status, privacy: .public)")
                    }
                    return .refused
                }
            }.value
        } onCancel: {
            box.context.invalidate()
        }
    }

    /// `LAContext` is thread safe for these calls but not `Sendable`.
    private struct UncheckedContext: @unchecked Sendable {
        let context: LAContext
        init(_ context: LAContext) { self.context = context }
    }
}

/// Every remote answer and every enrollment asks this presence (agent-ready spec 5.3): Face ID of the
/// current biometric set, proven by reading the keyring's presence item. Never the passcode.
public struct CurrentBiometryPresence: FaceIDGate {
    private let keyring: SystemRemoteUnlockKeyring

    public init(keyring: SystemRemoteUnlockKeyring = SystemRemoteUnlockKeyring()) {
        self.keyring = keyring
    }

    public func check(prompt: String) async -> FaceIDCheck {
        await keyring.checkPresence(prompt: prompt)
    }

    public func arm() throws {
        try keyring.armPresence()
    }

    public func disarm() throws {
        try keyring.disarmPresence()
    }
}
