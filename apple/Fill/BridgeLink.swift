import AppKit
import FillKit
import Foundation
import OnePassCore
import Security
import os

/// The helper's link to the Mac app's bridge (spec 2026-11-23-mac-fill-anywhere-design, BridgeClient):
/// `DesktopFillClient` over `bridge.sock` in the App Group container. The Rust client checks both
/// code signatures, sends the opening frame `{"onepass_relay":1}`, pairs once without a code and
/// keeps one connection. Every FFI call blocks (a fill may wait for Touch ID in the app), so they
/// run one at a time on a serial queue, never on the main actor, and the answer comes back here.
@MainActor
final class BridgeLink {
    enum LinkError: Error, Equatable {
        /// `FieldKind.other`: no value of a login fills it.
        case unsupportedField
    }

    private let worker: Worker
    /// The last error of a call, for the log and the next tasks' UI. Never holds a value.
    private(set) var lastError: (any Error)?

    init(bundle: Bundle = .main) {
        worker = Worker(socketPath: Self.socketPath(bundle: bundle), store: KeychainFillPairingStore(bundle: bundle))
    }

    /// Whether the app runs and its vault is unlocked. A failure to reach the app (unsigned build,
    /// helper blocked by the user, protocol error) reads as `appClosed` and is kept in `lastError`.
    func status() async -> FfiFillStatus {
        await answer { try $0.status() }
    }

    /// Brings the app forward to unlock; answers the state that follows (`locked` until the user
    /// unlocked there).
    func unlock() async -> FfiFillStatus {
        await answer { try $0.unlock() }
    }

    /// The logins for `target`: the page's, or the app's (its remembered entries first).
    func candidates(for target: FillTarget) async throws -> [FfiFillCandidate] {
        try await call { client in
            switch target {
            case .url(let url):
                return try client.listForUrl(url: url.absoluteString)
            case .app(let bundleID, let windowTitle):
                return try client.listForApp(bundleId: bundleID, windowTitle: windowTitle)
            }
        }
    }

    /// The one value of `field` for the picked login. `appName` names the app in the remembered
    /// entry and the key usage log (`appName(pid:)` gives it from the field's process); the bundle
    /// id or the page's host stands in when nil. `remember` applies to an app target only.
    func value(
        target: FillTarget, itemID: String, field: FieldKind, remember: Bool, appName: String? = nil
    ) async throws -> SecretBuffer {
        let ffiTarget = Self.ffiTarget(target, appName: appName)
        guard let ffiField = Self.ffiField(field) else {
            lastError = LinkError.unsupportedField
            throw LinkError.unsupportedField
        }
        return try await call { client in
            // The FFI object holds the value in `Zeroizing`; it dies at the end of this closure,
            // right after the copy into the buffer.
            let secret = try client.fill(target: ffiTarget, itemId: itemID, field: ffiField, remember: remember)
            return SecretBuffer(secret)
        }
    }

    /// The localized name of the app running as `pid`.
    static func appName(pid: pid_t) -> String? {
        NSRunningApplication(processIdentifier: pid)?.localizedName
    }

    nonisolated static func ffiTarget(_ target: FillTarget, appName: String?) -> FfiFillTarget {
        switch target {
        case .url(let url): .url(url: url.absoluteString, appName: appName)
        case .app(let bundleID, _): .app(bundleId: bundleID, appName: appName)
        }
    }

    nonisolated static func ffiField(_ kind: FieldKind) -> FfiFillField? {
        switch kind {
        case .password: .password
        case .username: .username
        case .oneTimeCode: .totp
        case .other: nil
        }
    }

    /// `<App Group container>/bridge.sock`, the group from the `OnePassAppGroup` Info.plist key
    /// (`$(ONEPASS_APP_GROUP)`, the group of the entitlements, as in the app's `SharedContainer`).
    nonisolated static func socketPath(bundle: Bundle) -> String? {
        guard let raw = bundle.object(forInfoDictionaryKey: "OnePassAppGroup") as? String else { return nil }
        let group = raw.trimmingCharacters(in: .whitespaces)
        guard !group.isEmpty, !group.contains("$("),
            let dir = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
        else { return nil }
        return dir.appendingPathComponent("bridge.sock").path
    }

    private func answer(_ body: @escaping @Sendable (DesktopFillClient) throws -> FfiFillStatus) async
        -> FfiFillStatus
    {
        do {
            return try await call(body)
        } catch {
            return .appClosed
        }
    }

    private func call<T: Sendable>(_ body: @escaping @Sendable (DesktopFillClient) throws -> T) async throws -> T {
        do {
            let result = try await worker.run(body)
            lastError = nil
            return result
        } catch {
            lastError = error
            Self.log.error("bridge call failed: \(String(describing: error), privacy: .public)")
            throw error
        }
    }

    private static let log = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "bridge")

    /// Owns the client and the serial queue every FFI call runs on. The client is touched on that
    /// queue only, which is what makes the unchecked conformance hold.
    private final class Worker: @unchecked Sendable {
        private let queue = DispatchQueue(label: "me.somalabs.onepass.fill.bridge", qos: .userInitiated)
        private let socketPath: String?
        private let store: any FillPairingStore
        private var client: DesktopFillClient?

        init(socketPath: String?, store: any FillPairingStore) {
            self.socketPath = socketPath
            self.store = store
        }

        func run<T: Sendable>(_ body: @escaping @Sendable (DesktopFillClient) throws -> T) async throws -> T {
            try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    do {
                        continuation.resume(returning: try body(self.connected()))
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        }

        /// The client, connected on first use. A failed connect (helper blocked, unsigned build) is
        /// tried again on the next call: the user may allow the helper meanwhile.
        private func connected() throws -> DesktopFillClient {
            if let client { return client }
            guard let socketPath else { throw OnePassError.AppClosed }
            let made = try DesktopFillClient.connect(socketPath: socketPath, store: store)
            client = made
            return made
        }
    }
}

/// One filled value, copied out of `FfiSecretValue` into memory this object owns and overwrites
/// with `memset_s` when it is released. Not Codable, and nothing prints it.
final class SecretBuffer: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    // Written once in `init`, zeroed and freed in `deinit`, read only through `withValue`.
    private let bytes: UnsafeMutableRawBufferPointer

    init(_ secret: FfiSecretValue) {
        // `value()` hands over a Swift String, a copy that cannot be zeroed: it lives only for this
        // statement.
        var utf8 = Array(secret.value().utf8)
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: max(utf8.count, 1), alignment: 1)
        buffer.initializeMemory(as: UInt8.self, repeating: 0)
        utf8.withUnsafeBytes { buffer.copyMemory(from: $0) }
        // The staging array is wiped too.
        utf8.withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress { _ = memset_s(base, raw.count, 0, raw.count) }
        }
        bytes = buffer
        count = utf8.count
    }

    /// The value's length in UTF-8 bytes.
    let count: Int

    /// Runs `body` with the value. The `String` is a temporary copy: Accessibility and `CGEvent`
    /// take a `String`, so this copy is unavoidable and Swift cannot zero it. Keep it inside `body`.
    func withValue<T>(_ body: (String) throws -> T) rethrows -> T {
        let view = UnsafeRawBufferPointer(rebasing: bytes[0..<count])
        return try body(String(decoding: view, as: UTF8.self))
    }

    var description: String { "SecretBuffer(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: [], displayStyle: .class) }

    deinit {
        if let base = bytes.baseAddress { _ = memset_s(base, bytes.count, 0, bytes.count) }
        bytes.deallocate()
    }
}

/// The helper's pairing record (pairing id and key), in one keychain item of its own: service
/// `<bundle id>.pairing`, in the shared access group the entitlements name, readable after the
/// first unlock and never leaving this Mac. A save overwrites the item.
final class KeychainFillPairingStore: FillPairingStore, @unchecked Sendable {
    private let service: String
    private let accessGroup: String?
    private static let account = "pairing"
    private static let log = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "me.somalabs.onepass.fill", category: "pairing")

    init(bundle: Bundle = .main) {
        service = (bundle.bundleIdentifier ?? "me.somalabs.onepass.fill") + ".pairing"
        accessGroup = Self.sharedAccessGroup(bundle: bundle)
    }

    func load() -> Data? {
        var query = base()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            if status != errSecItemNotFound {
                Self.log.error("pairing record not read, status \(status, privacy: .public)")
            }
            return nil
        }
        return result as? Data
    }

    func save(record: Data) {
        let update: [String: Any] = [
            kSecValueData as String: record,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(base() as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = base()
            add.merge(update) { $1 }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        if status != errSecSuccess {
            Self.log.error("pairing record not saved, status \(status, privacy: .public)")
        }
    }

    private func base() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.account,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    /// `<AppIdentifierPrefix><OnePassKeychainGroup>` from the Info.plist keys, as the app's
    /// `VaultEnvironment.sharedAccessGroup`; nil in an unsigned build (no prefix).
    static func sharedAccessGroup(bundle: Bundle) -> String? {
        func key(_ name: String) -> String? {
            guard let raw = bundle.object(forInfoDictionaryKey: name) as? String else { return nil }
            let value = raw.trimmingCharacters(in: .whitespaces)
            return value.isEmpty || value.contains("$(") ? nil : value
        }
        guard let prefix = key("AppIdentifierPrefix"), let group = key("OnePassKeychainGroup") else { return nil }
        return (prefix.hasSuffix(".") ? prefix : prefix + ".") + group
    }
}
