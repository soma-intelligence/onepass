import Foundation
import Security

/// What `VaultSession` tells the sync layer. The real implementation is `SyncCoordinator`.
public protocol SyncTrigger: Sendable {
    func localChangesWritten() async
    func sessionUnlocked(_ session: Session) async
    func sessionLocked() async
}

/// No sync (tests, unsigned builds).
public struct NoSync: SyncTrigger {
    public init() {}
    public func localChangesWritten() async {}
    public func sessionUnlocked(_ session: Session) async {}
    public func sessionLocked() async {}
}

/// Everything `VaultSession` depends on, injected.
public struct VaultEnvironment: Sendable {
    public var databaseURL: URL
    public var keychain: any KeychainStore
    public var biometrics: BiometricUnlock
    public var settings: VaultSettings
    public var sync: any SyncTrigger
    public var clock: any BootClock
    public var pasteboard: any PasteboardWriter
    /// Argon2id parameters for new accounts; nil = the core default (tests pass fast ones).
    public var accountKdf: FfiKdfParams?

    public init(
        databaseURL: URL, keychain: any KeychainStore, biometrics: BiometricUnlock,
        settings: VaultSettings, sync: any SyncTrigger, clock: any BootClock,
        pasteboard: any PasteboardWriter, accountKdf: FfiKdfParams? = nil
    ) {
        self.databaseURL = databaseURL
        self.keychain = keychain
        self.biometrics = biometrics
        self.settings = settings
        self.sync = sync
        self.clock = clock
        self.pasteboard = pasteboard
        self.accountKdf = accountKdf
    }

    /// Suffix of the shared keychain access group `$(AppIdentifierPrefix)me.somalabs.onepass.shared`.
    public static let sharedGroupSuffix = "me.somalabs.onepass.shared"

    /// The app's environment: store in `Application Support/OnePass/vault.sqlite`, system keychain in
    /// the shared access group, Secure Enclave biometrics, system pasteboard, no sync (Task 8 plugs it).
    public static func live(sync: any SyncTrigger = NoSync()) -> VaultEnvironment {
        let settings = VaultSettings()
        let clock = SystemClock()
        let group = sharedAccessGroup()
        let keychain = SystemKeychain(accessGroup: group)
        let keyring = SecureEnclaveKeyring(accessGroup: group, allowWatch: settings.allowWatchUnlock)
        return VaultEnvironment(
            databaseURL: defaultDatabaseURL(),
            keychain: keychain,
            biometrics: BiometricUnlock(keyring: keyring, keychain: keychain, clock: clock),
            settings: settings,
            sync: sync,
            clock: clock,
            pasteboard: SystemPasteboard())
    }

    /// `Application Support/OnePass/vault.sqlite`. The folder is created on first use; on iOS it is
    /// `NSFileProtectionCompleteUntilFirstUserAuthentication` so sync can run while the device is locked
    /// (the store content is already encrypted by the core).
    public static func defaultDatabaseURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let folder = base.appendingPathComponent("OnePass", isDirectory: true)
        var attributes: [FileAttributeKey: Any] = [:]
        #if os(iOS)
        attributes[.protectionKey] = FileProtectionType.completeUntilFirstUserAuthentication
        #endif
        try? FileManager.default.createDirectory(
            at: folder, withIntermediateDirectories: true, attributes: attributes)
        #if os(iOS)
        try? FileManager.default.setAttributes(attributes, ofItemAtPath: folder.path)
        #endif
        return folder.appendingPathComponent("vault.sqlite")
    }

    /// `<prefix>me.somalabs.onepass.shared`, or nil when the prefix is unknown (unsigned build).
    /// The prefix comes from the `AppIdentifierPrefix` Info.plist key (the apps set it to
    /// `$(AppIdentifierPrefix)`), else from the default access group the keychain gives this app.
    public static func sharedAccessGroup(bundle: Bundle = .main) -> String? {
        guard let prefix = appIdentifierPrefix(bundle: bundle) else { return nil }
        return prefix + sharedGroupSuffix
    }

    static func appIdentifierPrefix(bundle: Bundle) -> String? {
        if let value = bundle.object(forInfoDictionaryKey: "AppIdentifierPrefix") as? String {
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty, !trimmed.contains("$(") {
                return trimmed.hasSuffix(".") ? trimmed : trimmed + "."
            }
        }
        return keychainDefaultPrefix()
    }

    /// Reads the access group of a probe item: its first component is the team prefix.
    private static func keychainDefaultPrefix() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "me.somalabs.onepass.prefix-probe",
            kSecAttrAccount as String: "prefix-probe",
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnAttributes as String: true,
        ]
        var result: CFTypeRef?
        var status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            var add = query
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, &result)
        }
        guard status == errSecSuccess,
            let attributes = result as? [String: Any],
            let group = attributes[kSecAttrAccessGroup as String] as? String,
            let dot = group.firstIndex(of: ".")
        else { return nil }
        return String(group[...dot])
    }
}
