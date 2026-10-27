import Foundation
import Security

/// What `VaultSession` tells the sync layer. The real implementation is `SyncCoordinator`.
public protocol SyncTrigger: Sendable {
    func localChangesWritten() async
    func sessionUnlocked(_ session: Session) async
    func sessionLocked() async
    /// Runs `reset` (which empties the local store) with exclusive access to the store, then forgets
    /// whatever the sync layer kept about it. Default: runs it on the core thread.
    func resetStore(with reset: @escaping @Sendable () throws -> Void) async throws
    /// A safe exit issued its restore epoch on the session handed over by `sessionUnlocked`: the sync
    /// layer pushes it and follows it until the server serves this device's state. Default: nothing.
    func safeExitIssued(_ exit: SafeExit) async
}

extension SyncTrigger {
    public func safeExitIssued(_ exit: SafeExit) async {}

    public func resetStore(with reset: @escaping @Sendable () throws -> Void) async throws {
        try await CoreThread.run(reset)
    }
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
    /// Confirms the user before a `reprompt` item shows its secrets.
    public var presence: any PresenceChecker
    /// The system credential identity store (QuickType suggestions). `NoIdentityStore` by default.
    public var identityStore: any IdentityStoreClient
    /// Debounce of the identity store refresh (tests shorten it).
    public var identityDebounce: Duration = .seconds(1)
    /// Darwin notification of a write by another process (the AutoFill extension).
    public var storeChanges = StoreChangeNotifier()

    public init(
        databaseURL: URL, keychain: any KeychainStore, biometrics: BiometricUnlock,
        settings: VaultSettings, sync: any SyncTrigger, clock: any BootClock,
        pasteboard: any PasteboardWriter, accountKdf: FfiKdfParams? = nil,
        presence: any PresenceChecker = SystemPresenceChecker(),
        identityStore: any IdentityStoreClient = NoIdentityStore()
    ) {
        self.databaseURL = databaseURL
        self.keychain = keychain
        self.biometrics = biometrics
        self.settings = settings
        self.sync = sync
        self.clock = clock
        self.pasteboard = pasteboard
        self.accountKdf = accountKdf
        self.presence = presence
        self.identityStore = identityStore
    }

    /// Suffix of the shared keychain access group `$(AppIdentifierPrefix)me.somalabs.onepass.shared`.
    public static let sharedGroupSuffix = "me.somalabs.onepass.shared"

    /// The app's environment: store and settings in the shared container (App Group, or the milestone 2
    /// locations without one), system keychain in the shared access group, Secure Enclave biometrics,
    /// system pasteboard, system credential identity store, no sync (Task 8 plugs it).
    ///
    /// UI tests and screenshots (Debug builds of the app) pass their own store, settings and keychain
    /// service so they never touch the user's: `databaseURL`, `settings`, `keychainService` (each one
    /// replaces what `container` would give).
    public static func live(
        sync: any SyncTrigger = NoSync(), container: SharedContainer = .resolve(), databaseURL: URL? = nil,
        settings: VaultSettings? = nil, keychainService: String = SystemKeychain.defaultService
    ) -> VaultEnvironment {
        let settings = settings ?? VaultSettings(defaults: container.defaults)
        let clock = SystemClock()
        let group = sharedAccessGroup()
        let keychain = SystemKeychain(service: keychainService, accessGroup: group)
        let keyring = SecureEnclaveKeyring(accessGroup: group, allowWatch: settings.allowWatchUnlock)
        return VaultEnvironment(
            databaseURL: databaseURL ?? container.databaseURL,
            keychain: keychain,
            biometrics: BiometricUnlock(keyring: keyring, keychain: keychain, clock: clock),
            settings: settings,
            sync: sync,
            clock: clock,
            pasteboard: SystemPasteboard(),
            identityStore: SystemIdentityStore())
    }

    /// The store path of `SharedContainer.resolve()`. The folder is created on first use; on iOS it is
    /// `NSFileProtectionCompleteUntilFirstUserAuthentication` so sync can run while the device is locked
    /// (the store content is already encrypted by the core).
    public static func defaultDatabaseURL() -> URL {
        SharedContainer.resolve().databaseURL
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
