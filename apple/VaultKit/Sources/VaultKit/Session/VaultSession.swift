import Foundation
import Observation
import os

/// The app's state machine: account creation, unlock (password, biometrics, Secret Key restore),
/// lock and auto-lock, vault and item lists (summaries only, no secret), item operations, clipboard.
///
/// Heavy Rust calls (Argon2id, decryption) run off the main actor on `CoreThread` (a detached task's
/// 512 KiB stack is too small for the core's signature checks). Every lock bumps `generation`:
/// a call that comes back after a lock drops its result (and locks the session it opened), so the
/// final state after a lock is always `locked` with nothing in memory.
@MainActor
@Observable
public final class VaultSession {
    public enum State: Equatable, Sendable {
        case noAccount, locked, unlocking, unlocked
        case failed(VaultError)
    }

    public private(set) var state: State = .noAccount
    /// Every vault, hidden ones included (settings screen).
    public private(set) var allVaults: [FfiVault] = []
    /// Every item summary, archived and trashed ones included. Use `items(filter:query:sort:)` for lists.
    public private(set) var summaries: [FfiItemSummary] = []
    /// Recently opened item ids, newest first. Memory only, emptied on lock.
    public private(set) var recents: [String] = []
    public var lastError: VaultError?
    public private(set) var hiddenVaultIDs: Set<String>
    /// The store holds an account but this device has no Secret Key for it: use `restore`.
    public private(set) var needsSecretKey = false
    /// Bumped after the lists were reloaded for a write of another process (the AutoFill extension):
    /// an open item detail reloads, or warns its editor before a save overwrites the new version,
    /// exactly as for a remote change set.
    public private(set) var externalChangeRevision = 0
    /// Bumped on lock, when the scene goes to the background, and on iOS, iPadOS and visionOS when it
    /// becomes inactive (app switcher snapshot; not on macOS, where switching apps would re-mask all the
    /// time): views mask every revealed value again when it changes (`FieldRow`, the item editor).
    public private(set) var concealGeneration = 0
    /// Bumped each time the summaries are replaced (unlock, write, reload): "À proximité" asks
    /// `nearbyItems` again on it.
    public private(set) var summariesRevision = 0

    /// Vaults shown in the sidebar (hidden ones left out).
    public var vaults: [FfiVault] { allVaults.filter { !hiddenVaultIDs.contains($0.id) } }

    @ObservationIgnored public let environment: VaultEnvironment
    @ObservationIgnored private var session: Session? {
        didSet { if session !== oldValue { coreSessionChanged?(session) } }
    }
    /// Told each time the core session is installed or dropped (unlock, lock, failure): the Mac
    /// browser bridge serves the very same session, so a lock here locks the bridge.
    @ObservationIgnored public var coreSessionChanged: ((Session?) -> Void)?
    /// Told when the vaults hidden from AutoFill change (the bridge hides them too).
    @ObservationIgnored public var hiddenVaultsChanged: ((Set<String>) -> Void)?
    @ObservationIgnored private var generation = 0
    @ObservationIgnored private var autoLock: AutoLock
    @ObservationIgnored private var autoLockTimer: Task<Void, Never>?
    @ObservationIgnored private var syncChain: Task<Void, Never>?
    @ObservationIgnored private let clipboard: Clipboard
    /// A master password check (Argon2id) is running: a second one waits its turn, so concurrent
    /// calls cannot slip past the failure throttle.
    @ObservationIgnored private var passwordCheckInFlight = false
    /// Tests: runs on the core thread before each core call, to hold a call in flight.
    @ObservationIgnored var coreWorkHook: (@Sendable () -> Void)?
    /// Sessions being locked on the core thread, in order.
    @ObservationIgnored private var releaseChain: Task<Void, Never>?
    /// Bumped when the biometric enrollment may have changed (`canUseBiometrics` reads the keychain).
    private var biometricsRevision = 0
    /// Publishes the AutoFill identities to the system store (debounced).
    @ObservationIgnored private let identitySync: IdentityStoreSync
    /// Identity store requests (refresh, clear), forwarded in order.
    @ObservationIgnored private var identityChain: Task<Void, Never>?
    /// Set by `refuseStore`: every read of the store ends in this failure.
    @ObservationIgnored private var refusedStore: VaultError?
    /// Observes `StoreChangeNotifier`; cancelled on deinit (the extension makes one session per request).
    @ObservationIgnored private(set) var storeChangeObserver: Task<Void, Never>?
    /// Places of the items, read once per item version (memory only, emptied on lock).
    @ObservationIgnored private var locationIndex = LocationIndex()

    static let maxRecents = 20
    nonisolated static let trashRetentionDays: UInt32 = 30
    static let unlockPrompt = "Déverrouiller OnePass"
    nonisolated static let personalVault = FfiVaultMeta(
        name: "Personnel", icon: "person", color: "blue", travelSafe: false, mcpAccess: false)
    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "session")

    public init(environment: VaultEnvironment) {
        self.environment = environment
        hiddenVaultIDs = environment.settings.hiddenVaultIDs
        autoLock = AutoLock(now: environment.clock.now)
        clipboard = Clipboard(pasteboard: environment.pasteboard, clock: environment.clock)
        identitySync = IdentityStoreSync(client: environment.identityStore, debounce: environment.identityDebounce)
        evaluateStoredAccount()
        observeStoreChanges()
    }

    isolated deinit {
        storeChangeObserver?.cancel()
    }

    private var settings: VaultSettings { environment.settings }
    private var biometrics: BiometricUnlock { environment.biometrics }
    private var secretKeys: SecretKeyVault { SecretKeyVault(keychain: environment.keychain) }
    private var dbPath: String { environment.databaseURL.path }

    // MARK: - State

    /// Unlocked: reloads vaults and summaries. Otherwise re-reads the store (`noAccount` or `locked`),
    /// which is also how the "Données refusées" screen retries.
    public func refresh() async {
        if state == .unlocked, let session {
            let gen = generation
            do {
                let snapshot = try await background { try Self.load(session, purge: false) }
                if gen == generation { apply(snapshot) }
            } catch {
                _ = handle(error, generation: gen)
            }
        } else if state != .unlocking {
            evaluateStoredAccount()
        }
    }

    /// After a remote change set or a rebase (`SyncCoordinator.remoteChanges()`). Unlocked: reloads vaults
    /// and summaries (an integrity error ends in `.failed(.integrity)` with nothing in memory). No account
    /// or locked: re-reads the store, a fetch may have brought the account. Unlocking or failed: unchanged
    /// (only `refresh` retries after "Données refusées").
    public func reload() async {
        switch state {
        case .unlocked:
            await refresh()
            refreshAutofillIdentities()
        case .noAccount, .locked: evaluateStoredAccount()
        case .unlocking, .failed: break
        }
    }

    /// Re-reads what the store holds. An account this device knew (pinned by the core, or named in
    /// the settings) that disappeared from the store is an integrity failure, never "no account": the
    /// onboarding would otherwise invite the user to create a second account over the first one.
    ///
    /// A missing database file is read as an empty store without calling the core, which would create
    /// it: the AutoFill extension must never create the shared store before the app migrated the
    /// milestone 2 one into it (the migration skips an existing store holding an account).
    private func evaluateStoredAccount() {
        if let refusedStore {
            state = .failed(refusedStore)
            lastError = refusedStore
            return
        }
        do {
            var found = FfiStoreState.empty
            if FileManager.default.fileExists(atPath: dbPath) { found = try storeState(dbPath: dbPath) }
            switch found {
            case .account:
                state = .locked
                needsSecretKey = secretKeyPresence() == .missing
            case .pinnedButMissing:
                enterAccountMissing()
            case .empty:
                if settings.accountID != nil {
                    enterAccountMissing()
                } else {
                    state = .noAccount
                    needsSecretKey = false
                }
            }
        } catch {
            let failure = VaultError(error)
            state = .failed(failure)
            lastError = failure
        }
    }

    /// The app could not put its store in a usable place (the shared container migration failed and
    /// could not be undone): the session stays in `.failed(failure)` for this launch, and "Réessayer"
    /// never opens or creates a store.
    public func refuseStore(_ failure: VaultError) {
        lock()
        refusedStore = failure
        evaluateStoredAccount()
    }

    /// Refused store (`refuseStore`): nothing may open or create it.
    private func checkStoreUsable() throws {
        if let refusedStore { throw fail(refusedStore) }
    }

    private func enterAccountMissing() {
        let failure = VaultError.integrity(kind: Self.accountMissingKind)
        needsSecretKey = false
        state = .failed(failure)
        lastError = failure
    }

    /// Integrity kind of an account that disappeared from the store (same as the core's refusal of a
    /// new account over a pinned one).
    nonisolated public static let accountMissingKind = "account_missing"

    /// The account is missing from the store (`account_missing`).
    public var isAccountMissing: Bool {
        state == .failed(.integrity(kind: Self.accountMissingKind))
    }

    /// Way out of "Le compte a disparu du stockage", once the user confirmed that the unreadable local
    /// copy is cleared ("Restaurer avec mon Emergency Kit" or "Repartir de zéro"). Only from that
    /// state. The store is emptied in one transaction, device state included (the pin goes: the next
    /// unlock pins again), with the sync layer holding the store; the Secret Key and the biometric
    /// enrollment of the vanished account are removed; the account id, name, failure throttle and
    /// biometric wish are cleared. Ends in `.noAccount`: the app then shows the Emergency Kit restore
    /// (the data comes back from iCloud) or the onboarding. Nothing in iCloud is deleted. The system
    /// identity store is emptied too: the vanished account's suggestions must not stay above the
    /// keyboard.
    ///
    /// Also allowed on a locked device that definitely lacks the Secret Key of the account in the
    /// store (`needsSecretKey`): "Créer un nouveau coffre" from the Emergency Kit screen, confirmed by
    /// typing EFFACER. The local copy, unreadable without the key, is emptied the same way.
    public func resetForRecovery() async throws {
        let missing = isAccountMissing
        guard missing || (state == .locked && needsSecretKey) else { throw fail(.other(Self.recoveryRefused)) }
        let path = dbPath
        generation &+= 1
        do {
            try await environment.sync.resetStore {
                if missing { try resetStoreForRecovery(dbPath: path) } else { try resetStore(dbPath: path) }
            }
        } catch {
            Self.log.error("store not reset for recovery")
            evaluateStoredAccount()
            throw fail(VaultError(error))
        }
        if let accountID = settings.accountID {
            do {
                try secretKeys.remove(accountID: accountID)
            } catch {
                Self.log.error("Secret Key of the missing account not removed")
            }
            biometrics.disable(accountID: accountID)
        }
        settings.accountID = nil
        settings.displayName = ""
        settings.biometricsWanted = false
        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        biometricsRevision += 1
        clearAutofillIdentities()
        evaluateStoredAccount()
        if state == .noAccount { lastError = nil }
    }

    nonisolated static let recoveryRefused =
        "Cette action n'est possible que lorsque le compte a disparu du stockage ou que sa Secret Key manque."

    private enum Presence { case present, missing, unknown }

    /// Presence only, nothing loaded. `unknown` when the keychain cannot answer (device locked at a
    /// background launch, for example) or the account cannot be named: that is not a missing
    /// Secret Key.
    private func secretKeyPresence() -> Presence {
        guard let accountID = knownAccountID() else { return .unknown }
        do {
            return try secretKeys.contains(accountID: accountID) ? .present : .missing
        } catch {
            return .unknown
        }
    }

    /// The account of this device: from the settings, else (settings wiped, store kept) the account
    /// the store shows, adopted into the settings once this device's keychain holds its Secret Key.
    /// Nil when it cannot be told. A missing or refused store is never opened (opening would create
    /// it, and the AutoFill extension must never create the shared store).
    private func knownAccountID() -> String? {
        if let accountID = settings.accountID { return accountID }
        guard refusedStore == nil, FileManager.default.fileExists(atPath: dbPath),
            let stored = try? openSyncStore(dbPath: dbPath).accountId()
        else { return nil }
        if (try? secretKeys.contains(accountID: stored)) == true { settings.accountID = stored }
        return stored
    }

    /// The stored Secret Key for an unlock, in a wipeable buffer (the caller wipes it). Missing:
    /// `needsSecretKey`. Keychain error: thrown as is.
    private func loadSecretKey() throws -> (accountID: String, secretKey: SecretBytes) {
        let missing = VaultError.other("La Secret Key de ce compte n'est pas sur cet appareil : utilise ton Emergency Kit.")
        guard let accountID = knownAccountID() else {
            needsSecretKey = true
            throw fail(missing)
        }
        let secretKey: SecretBytes?
        do {
            secretKey = try secretKeys.loadBytes(accountID: accountID)
        } catch {
            throw fail(VaultError(error))
        }
        // Unreadable (not UTF-8) counts as missing, as before.
        guard let secretKey, secretKey.isValidUTF8 else {
            needsSecretKey = true
            throw fail(missing)
        }
        return (accountID, secretKey)
    }

    // MARK: - Account creation and unlock

    /// `createAccount(password:displayName:mode:)` with a typed `String` (tests, debug data). The app
    /// passes `SecretBytes`.
    public func createAccount(password: String, displayName: String, mode: DeviceMode) async throws -> String {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        let secretKey = try await createAccount(password: bytes, displayName: displayName, mode: mode)
        defer { secretKey.wipe() }
        return secretKey.string() ?? ""
    }

    /// Creates the account and its "Personnel" vault, stores the Secret Key in the keychain and
    /// unlocks. Returns the Secret Key in display form (the caller wipes it), to show once and put in
    /// the Emergency Kit. The password crosses the FFI as bytes (`create_account_bytes`); the caller
    /// wipes `password`.
    public func createAccount(password: SecretBytes, displayName: String, mode: DeviceMode) async throws
        -> SecretBytes
    {
        try checkStoreUsable()
        if session != nil || state == .locked { throw fail(.accountExists) }
        let path = dbPath
        let kdf = environment.accountKdf
        let gen = beginUnlocking()
        let created: Created
        do {
            created = try await background {
                if try hasAccount(dbPath: path) { throw VaultError.accountExists }
                let account = try password.withData { bytes in
                    try kdf.map { try createAccountWithKdfBytes(dbPath: path, password: bytes, kdf: $0) }
                        ?? createAccountBytes(dbPath: path, password: bytes)
                }
                // The core hands the Secret Key back as a `String` (UniFFI lift): copied into a wipeable
                // buffer at once, the `String` dies with this closure (R5).
                let secretKey = SecretBytes(utf8: account.secretKey)
                do {
                    if try account.session.vaults().isEmpty {
                        _ = try account.session.createVault(meta: Self.personalVault)
                    }
                    return Created(
                        session: account.session, secretKey: secretKey, accountID: account.accountId,
                        snapshot: try Self.load(account.session, purge: false))
                } catch {
                    secretKey.wipe()
                    account.session.lock()
                    throw error
                }
            }
        } catch {
            if gen == generation { evaluateStoredAccount() }
            throw fail(VaultError(error))
        }

        // The account exists now: keep its Secret Key even if a lock came in meanwhile. Without it
        // the account could never be unlocked again: the creation is undone (no session, no sync).
        do {
            try secretKeys.store(created.secretKey, accountID: created.accountID)
        } catch {
            Self.log.error("Secret Key not stored in the keychain, account creation undone")
            let path = dbPath
            do {
                // The file stays in place (the sync handle has it open): its tables are emptied.
                try await CoreThread.run {
                    created.session.lock()
                    try resetStore(dbPath: path)
                }
            } catch {
                Self.log.error("store not reset after an undone account creation")
            }
            created.secretKey.wipe()
            evaluateStoredAccount()
            throw fail(.other(Self.secretKeyNotStoredOnCreate))
        }
        settings.accountID = created.accountID
        settings.displayName = displayName
        settings.deviceMode = mode
        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        if !mode.biometricsAllowed { disableBiometrics() }
        needsSecretKey = secretKeyPresence() == .missing

        guard gen == generation else {
            release(created.session)
            return created.secretKey
        }
        install(created.session, created.snapshot)
        return created.secretKey
    }

    /// `unlock(password:)` with a typed `String` (tests, debug data). The app passes `SecretBytes`.
    public func unlock(password: String) async throws {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        try await unlock(password: bytes)
    }

    /// Master password unlock. The password is passed as typed (never trimmed): the core normalizes it.
    /// The caller wipes `password`.
    public func unlock(password: SecretBytes) async throws {
        if state == .unlocked { return }
        try checkStoreUsable()
        try checkLockout()
        let stored = try loadSecretKey()
        defer { stored.secretKey.wipe() }
        try await passwordUnlock(password: password, secretKey: stored.secretKey, storeSecretKey: false)
    }

    /// `restore(secretKey:password:)` with a typed `String` password (tests).
    public func restore(secretKey: String, password: String) async throws {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        try await restore(secretKey: secretKey, password: bytes)
    }

    /// New device (or wiped keychain) with a store that already holds the account:
    /// Secret Key typed from the Emergency Kit plus master password. The typed Secret Key is a
    /// `String` (text field, and `normalize_secret_key` takes and returns one): its normalized form goes
    /// into a wipeable buffer at once.
    public func restore(secretKey: String, password: SecretBytes) async throws {
        if state == .unlocked { return }
        try checkStoreUsable()
        try checkLockout()
        let normalized: SecretBytes
        do {
            normalized = SecretBytes(utf8: try Self.normalizedSecretKey(secretKey))
        } catch {
            throw fail(VaultError(error))
        }
        defer { normalized.wipe() }
        try await passwordUnlock(password: password, secretKey: normalized, storeSecretKey: true)
    }

    /// The canonical form of a typed Secret Key, or a `secretKey` validation error naming what is
    /// wrong: its format (length, a character that is neither a letter nor a digit) or its check
    /// character (a typo). A well formed key of another account only fails at the unlock.
    nonisolated static func normalizedSecretKey(_ text: String) throws -> String {
        let allowed = text.unicodeScalars.allSatisfy {
            ($0.isASCII && CharacterSet.alphanumerics.contains($0)) || $0 == "-"
                || CharacterSet.whitespacesAndNewlines.contains($0)
        }
        guard allowed else { throw VaultError.validation(field: "secretKey", reason: VaultError.secretKeyFormat) }
        do {
            return try normalizeSecretKey(text: text)
        } catch OnePassError.InvalidInput(let what) where what == "secret key checksum" {
            throw VaultError.validation(field: "secretKey", reason: VaultError.secretKeyChecksum)
        } catch {
            throw VaultError.validation(field: "secretKey", reason: VaultError.secretKeyFormat)
        }
    }

    /// The password and the Secret Key stay in their buffers (wiped by the caller) and cross the FFI as
    /// temporary `Data` copies wiped when the call returns (`unlock_with_password_bytes`).
    private func passwordUnlock(password: SecretBytes, secretKey: SecretBytes, storeSecretKey: Bool) async throws {
        try beginPasswordCheck()
        defer { passwordCheckInFlight = false }
        let path = dbPath
        let gen = beginUnlocking()
        let opened: Opened
        do {
            opened = try await background {
                var unlocked = try Self.withBytes(password, secretKey) { password, secretKey in
                    try unlockWithPasswordBytes(dbPath: path, password: password, secretKey: secretKey)
                }
                let auk = SecretBytes(taking: &unlocked.auk)
                do {
                    return Opened(
                        session: unlocked.session, accountID: unlocked.session.accountId(),
                        snapshot: try Self.load(unlocked.session, purge: true), auk: auk)
                } catch {
                    auk.wipe()
                    unlocked.session.lock()
                    throw error
                }
            }
        } catch {
            throw unlockFailed(error, generation: gen)
        }
        defer { opened.auk.wipe() }

        if storeSecretKey {
            // Without the Secret Key in the keychain this device could not unlock again: the session
            // is dropped (no sync starts). The store is kept: it may hold the only local copy.
            do {
                try secretKeys.store(secretKey, accountID: opened.accountID)
            } catch {
                Self.log.error("Secret Key not stored in the keychain, restore cancelled")
                _ = try? await CoreThread.run { opened.session.lock() }
                if gen == generation { evaluateStoredAccount() }
                throw fail(.other(Self.secretKeyNotStoredOnRestore))
            }
            settings.accountID = opened.accountID
        }
        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        afterPasswordUnlock(accountID: opened.accountID, auk: opened.auk)
        needsSecretKey = secretKeyPresence() == .missing

        guard gen == generation else {
            release(opened.session)
            return
        }
        install(opened.session, opened.snapshot)
    }

    /// Spec 4 point 3: restart the 14 day clock, and enroll again when biometrics are wanted but the
    /// enrollment was dropped (reboot, expiry, biometry change).
    private func afterPasswordUnlock(accountID: String, auk: SecretBytes) {
        try? biometrics.notePasswordUnlock(accountID: accountID)
        if settings.biometricsWanted, settings.deviceMode.biometricsAllowed, biometrics.isAvailable,
            !biometrics.isEnrolled(accountID: accountID)
        {
            let allowWatch = settings.allowWatchUnlock
            try? auk.withData { try biometrics.enroll(auk: $0, accountID: accountID, allowWatch: allowWatch) }
        }
        biometricsRevision += 1
    }

    /// Face ID, Touch ID or Apple Watch. Any refusal (reboot, 14 days, biometry change, cancel) ends in
    /// `locked` with `VaultError.passwordRequired`, so the UI shows the password field.
    public func unlockWithBiometrics() async throws {
        if state == .unlocked { return }
        try checkStoreUsable()
        guard settings.deviceMode.biometricsAllowed, biometrics.isAvailable else {
            throw fail(.biometricsUnavailable)
        }
        guard let accountID = settings.accountID else { throw fail(.passwordRequired) }
        let gen = beginUnlocking()
        let key: SecretBytes
        do {
            var auk = try await biometrics.unlock(accountID: accountID, prompt: Self.unlockPrompt)
            key = SecretBytes(taking: &auk)
        } catch {
            biometricsRevision += 1
            if gen == generation { state = .locked }
            throw fail(.passwordRequired)
        }
        defer { key.wipe() }
        guard gen == generation else { return }

        let path = dbPath
        let opened: (session: Session, snapshot: Snapshot)
        do {
            opened = try await background {
                let session = try key.withData { try unlockWithAuk(dbPath: path, auk: $0) }
                do {
                    return (session, try Self.load(session, purge: true))
                } catch {
                    session.lock()
                    throw error
                }
            }
        } catch {
            let failure = VaultError(error)
            if case .integrity = failure, gen == generation { throw enterFailed(failure) }
            // Only a rejected AUK drops the enrollment; a store error keeps it for the next try.
            let rejected = (error as? OnePassError).map { $0 == .WrongPassword || $0 == .Crypto } ?? false
            if rejected {
                biometrics.disable(accountID: accountID)
                biometricsRevision += 1
            }
            if gen == generation {
                if rejected { state = .locked } else { evaluateStoredAccount() }
            }
            throw fail(rejected ? .passwordRequired : failure)
        }
        guard gen == generation else {
            release(opened.session)
            return
        }
        install(opened.session, opened.snapshot)
    }

    /// `enrollBiometrics(password:)` with a typed `String` (tests).
    public func enrollBiometrics(password: String) async throws {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        try await enrollBiometrics(password: bytes)
    }

    /// Checks the master password, then wraps the AUK with the Secure Enclave. Personal mode only.
    /// The caller wipes `password`.
    public func enrollBiometrics(password: SecretBytes) async throws {
        guard settings.deviceMode.biometricsAllowed, biometrics.isAvailable else {
            throw fail(.biometricsUnavailable)
        }
        try checkLockout()
        let (accountID, secretKey) = try loadSecretKey()
        defer { secretKey.wipe() }
        try beginPasswordCheck()
        defer { passwordCheckInFlight = false }
        let path = dbPath
        let auk: SecretBytes
        do {
            // `verify_password` never writes the device state: the live session may be moving
            // `last_seen` forward meanwhile (Settings while unlocked).
            auk = try await background {
                var bytes = try Self.withBytes(password, secretKey) { password, secretKey in
                    try verifyPasswordBytes(dbPath: path, password: password, secretKey: secretKey)
                }
                return SecretBytes(taking: &bytes)
            }
        } catch {
            let failure = VaultError(error)
            if failure == .wrongPassword { recordFailedUnlock() }
            throw fail(failure)
        }
        defer { auk.wipe() }
        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        do {
            let allowWatch = settings.allowWatchUnlock
            try auk.withData { try biometrics.enroll(auk: $0, accountID: accountID, allowWatch: allowWatch) }
        } catch {
            biometricsRevision += 1
            throw fail(VaultError(error))
        }
        settings.biometricsWanted = true
        biometricsRevision += 1
    }

    /// Biometric unlock is enrolled, allowed by the device mode and possible on this hardware.
    public var canUseBiometrics: Bool {
        _ = biometricsRevision
        guard settings.deviceMode.biometricsAllowed, biometrics.isAvailable,
            let accountID = settings.accountID
        else { return false }
        return biometrics.isEnrolled(accountID: accountID)
    }

    /// Turns biometric unlock off (keeps nothing in the keychain or the Secure Enclave).
    public func disableBiometrics() {
        settings.biometricsWanted = false
        if let accountID = settings.accountID { biometrics.disable(accountID: accountID) }
        biometricsRevision += 1
    }

    /// Shared mode drops the biometric enrollment and caps auto-lock at 5 minutes.
    public func setDeviceMode(_ mode: DeviceMode) {
        settings.deviceMode = mode
        if !mode.biometricsAllowed {
            // Not wanted any more either: back in personal mode, a password unlock must not enroll again.
            settings.biometricsWanted = false
            if let accountID = settings.accountID { biometrics.disable(accountID: accountID) }
        }
        biometricsRevision += 1
        refreshAutofillIdentities()
    }

    /// At least one vault stays visible: hiding the last visible vault is refused (no change).
    public func setVaultHidden(_ vaultID: String, hidden: Bool) {
        if hidden, !allVaults.contains(where: { $0.id != vaultID && !hiddenVaultIDs.contains($0.id) }) { return }
        var ids = hiddenVaultIDs
        if hidden { ids.insert(vaultID) } else { ids.remove(vaultID) }
        settings.hiddenVaultIDs = ids
        hiddenVaultIDs = ids
        hiddenVaultsChanged?(ids)
        refreshAutofillIdentities()
    }

    // MARK: - Lock

    /// Drops the keys, every summary and recent id, and tells the sync layer.
    public func lock() {
        generation &+= 1
        let wasOpen = session != nil || state == .unlocking || state == .unlocked
        if let session {
            self.session = nil
            release(session)
        }
        clearMemory()
        clipboard.clear()
        concealRevealed()
        // A debounced identity refresh would find the session locked: drop it (what was published
        // stays, suggestions work while locked).
        let sync = identitySync
        enqueueIdentity { await sync.dropPending() }
        if state == .unlocked || state == .unlocking { state = .locked }
        if wasOpen { notifySync { await $0.sessionLocked() } }
    }

    private func clearMemory() {
        summaries = []
        allVaults = []
        recents = []
        locationIndex = LocationIndex()
        autoLockTimer?.cancel()
        autoLockTimer = nil
    }

    // MARK: - Auto-lock

    /// Any user interaction: restarts the inactivity delay.
    public func noteActivity() {
        autoLock.noteActivity(environment.clock.now)
    }

    public func scenePhaseChanged(_ phase: ScenePhaseKind) {
        let now = environment.clock.now
        switch phase {
        case .background:
            autoLock.enterBackground(now)
            concealRevealed()
            // The clipboard is kept (copy, then switch app to paste): it clears on lock and after 90 s.
        case .active:
            let expired = autoLock.becomeActive(now, delay: settings.effectiveAutoLockSeconds)
            if state == .unlocked, expired { lock() }
            clipboard.clearIfExpired()
        case .inactive:
            #if !os(macOS)
            concealRevealed()
            #endif
        }
    }

    /// Every revealed value is masked again (views watch `concealGeneration`).
    private func concealRevealed() {
        concealGeneration &+= 1
    }

    /// Locks when the inactivity delay has passed (the timer calls it; tests call it after moving the clock).
    public func checkAutoLock() {
        guard state == .unlocked else { return }
        if autoLock.isExpired(environment.clock.now, delay: settings.effectiveAutoLockSeconds) { lock() }
    }

    private func startAutoLockTimer() {
        autoLockTimer?.cancel()
        let gen = generation
        autoLockTimer = Task { [weak self] in
            while true {
                guard let wait = self?.nextAutoLockWait(generation: gen) else { return }
                try? await Task.sleep(for: .seconds(wait))
                if Task.isCancelled { return }
                self?.checkAutoLock()
            }
        }
    }

    /// Seconds before the next check; nil stops the timer. "Jamais" re-checks every minute
    /// (the setting may change).
    private func nextAutoLockWait(generation gen: Int) -> TimeInterval? {
        guard gen == generation, state == .unlocked else { return nil }
        let remaining = autoLock.remaining(environment.clock.now, delay: settings.effectiveAutoLockSeconds)
        return max(1, remaining ?? 60)
    }

    // MARK: - Lists

    /// Filtered, searched and sorted summaries, without hidden vaults.
    public func items(filter: ItemFilter, query: String, sort: ItemSort) -> [FfiItemSummary] {
        let visible = summaries.filter { !hiddenVaultIDs.contains($0.vaultId) && filter.matches($0) }
        return sort.sorted(ItemSearch.filter(visible, query: query))
    }

    public func counts() -> ItemCounts {
        ItemCounts(summaries.filter { !hiddenVaultIDs.contains($0.vaultId) })
    }

    /// "À proximité": active items of visible vaults with a place within `radius` meters of
    /// `origin`, closest first. Only items new or modified since the last call are decrypted (one
    /// core call for all of them); the rest comes from the in-memory index. An item that cannot be
    /// read is left out and read again next time: a passing error (a sync applying) never hides it
    /// for good (its detail reports a lasting error when opened).
    public func nearbyItems(from origin: GeoPoint, within radius: Double = LocationIndex.nearbyRadius) async throws
        -> [NearbyItem]
    {
        let active = summaries.filter { !hiddenVaultIDs.contains($0.vaultId) && ItemFilter.nearby.matches($0) }
        let stale = locationIndex.needsLoading(active).map { ($0.vaultId, $0.id, $0.updatedAt) }
        if !stale.isEmpty {
            let loaded = try await read { session in
                var out: [String: LocationIndex.Entry] = [:]
                // Taken before reading: an edit landing during the read keeps the entry stale.
                let readAt = Int64(Date().timeIntervalSince1970.rounded(.down))
                for (vaultID, itemID, updatedAt) in stale {
                    guard let item = try? session.item(vaultId: vaultID, itemId: itemID) else { continue }
                    out[itemID] = LocationIndex.Entry(
                        updatedAt: updatedAt, points: LocationIndex.points(of: item), readAt: readAt)
                }
                return out
            }
            locationIndex.update(loaded, keeping: summaries)
        }
        // Summaries may have changed during the read: the current ones decide what is listed.
        let current = summaries.filter { !hiddenVaultIDs.contains($0.vaultId) && ItemFilter.nearby.matches($0) }
        return locationIndex.nearby(current, from: origin, within: radius)
    }

    // MARK: - Items

    /// The full item, for the detail view only (which forgets it when closed).
    public func loadItem(vaultID: String, itemID: String) async throws -> FfiItem {
        let item = try await read { try $0.item(vaultId: vaultID, itemId: itemID) }
        recents.removeAll { $0 == itemID }
        recents.insert(itemID, at: 0)
        if recents.count > Self.maxRecents { recents.removeLast(recents.count - Self.maxRecents) }
        return item
    }

    /// An empty item of this type, not stored until `save`.
    public func newItem(type: FfiItemType, vaultID: String) throws -> FfiItem {
        guard let session else { throw fail(.passwordRequired) }
        noteActivity()
        do {
            return try session.newItem(vaultId: vaultID, itemType: type, title: "")
        } catch {
            throw handle(error, generation: generation)
        }
    }

    /// Validates and writes; returns the item as stored.
    public func save(_ item: FfiItem) async throws -> FfiItem {
        try await write { try $0.saveItem(item: item) }
    }

    public func trash(itemID: String, vaultID: String) async throws {
        try await write { try $0.trashItem(vaultId: vaultID, itemId: itemID) }
    }

    public func restoreItem(itemID: String, vaultID: String) async throws {
        try await write { try $0.restoreItem(vaultId: vaultID, itemId: itemID) }
    }

    public func archive(itemID: String, vaultID: String) async throws {
        try await write { try $0.archiveItem(vaultId: vaultID, itemId: itemID) }
    }

    public func unarchive(itemID: String, vaultID: String) async throws {
        try await write { try $0.unarchiveItem(vaultId: vaultID, itemId: itemID) }
    }

    public func deletePermanently(itemID: String, vaultID: String) async throws {
        try await write { try $0.deleteItem(vaultId: vaultID, itemId: itemID) }
        recents.removeAll { $0 == itemID }
    }

    public func move(itemID: String, from source: String, to destination: String) async throws {
        try await write { try $0.moveItem(itemId: itemID, fromVault: source, toVault: destination) }
    }

    public func setFavorite(_ favorite: Bool, itemID: String, vaultID: String) async throws {
        try await write { try $0.setFavorite(vaultId: vaultID, itemId: itemID, favorite: favorite) }
    }

    public func createVault(_ meta: FfiVaultMeta) async throws {
        _ = try await write { try $0.createVault(meta: meta) }
    }

    public func updateVault(id: String, meta: FfiVaultMeta) async throws {
        _ = try await write { try $0.updateVault(vaultId: id, meta: meta) }
    }

    public func passwordHistory(vaultID: String, itemID: String) async throws -> [FfiHistoryEntry] {
        try await read { try $0.passwordHistory(vaultId: vaultID, itemId: itemID) }
    }

    // MARK: - Clipboard

    /// Local only, concealed if asked, cleared after 90 s unless something else was copied.
    public func copy(_ value: String, concealed: Bool) {
        clipboard.copy(value, concealed: concealed)
        noteActivity()
    }

    // MARK: - Reprompt

    /// `reprompt` items: when biometric unlock is enrolled, Face ID / Touch ID (or the device
    /// passcode) confirms the user. False means: ask the master password (`verifyMasterPassword`).
    public func confirmUserPresence(prompt: String) async -> Bool {
        guard state == .unlocked, canUseBiometrics else { return false }
        let gen = generation
        let confirmed = await environment.presence.confirm(prompt: prompt)
        guard confirmed, gen == generation, state == .unlocked else { return false }
        noteActivity()
        return true
    }

    /// `verifyMasterPassword(_:)` with a typed `String` (tests).
    public func verifyMasterPassword(_ password: String) async throws {
        let bytes = SecretBytes(utf8: password)
        defer { bytes.wipe() }
        try await verifyMasterPassword(bytes)
    }

    /// Checks the master password without touching the open session (`verify_password`: no session,
    /// no device state written, so a save meanwhile keeps its newer `last_seen` on disk). Counts toward
    /// the failure throttle like an unlock. The caller wipes `password`.
    public func verifyMasterPassword(_ password: SecretBytes) async throws {
        guard state == .unlocked else { throw fail(.passwordRequired) }
        try checkLockout()
        let secretKey = try loadSecretKey().secretKey
        defer { secretKey.wipe() }
        try beginPasswordCheck()
        defer { passwordCheckInFlight = false }
        let path = dbPath
        let gen = generation
        do {
            try await background {
                var auk = try Self.withBytes(password, secretKey) { password, secretKey in
                    try verifyPasswordBytes(dbPath: path, password: password, secretKey: secretKey)
                }
                SecretBytes(taking: &auk).wipe()
            }
        } catch {
            let failure = VaultError(error)
            if failure == .wrongPassword { recordFailedUnlock() }
            throw fail(failure)
        }
        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        guard gen == generation, state == .unlocked else { throw fail(.passwordRequired) }
        noteActivity()
    }

    // MARK: - AutoFill

    // Execution ruling: the AutoFill extension reuses `VaultSession` (same unlock, failure counter,
    // biometric policy and integrity handling) instead of a separate `AutoFillUnlocker`.

    /// The Logins matching `service` (a domain or URL from the system), best match first; `includeAll`
    /// appends every other Login (explicit choice). Hidden vaults are left out.
    public func autofillCandidates(service: String, includeAll: Bool) async throws -> [FfiAutofillCandidate] {
        let excluded = excludedVaultIDs
        return try await read {
            try $0.autofillCandidates(service: service, includeAll: includeAll, excludedVaultIds: excluded)
        }
    }

    /// Creates a passkey (key pair generated and kept by the core) in an existing Login or a new one,
    /// then reloads the lists and publishes the new identity. `.other` when the relying party already
    /// holds one of `excludedCredentialIds` (`PasskeyExcluded`).
    public func createPasskey(_ request: FfiPasskeyCreation) async throws -> FfiPasskeyRegistration {
        try await write { try $0.createPasskey(request: request) }
    }

    /// Signs a passkey assertion with the passkey `credentialID` of a live Login (signature by the core).
    public func passkeyAssertion(
        vaultID: String, itemID: String, credentialID: Data, clientDataHash: Data
    ) async throws -> FfiPasskeyAssertion {
        try await read {
            try $0.passkeyAssertion(
                vaultId: vaultID, itemId: itemID, credentialId: credentialID, clientDataHash: clientDataHash)
        }
    }

    /// Publishes the AutoFill identities (debounced). Does nothing unless unlocked with the
    /// "Suggestions au-dessus du clavier" setting on. A lock keeps what was published: suggestions
    /// must work while OnePass is locked.
    public func refreshAutofillIdentities() {
        guard state == .unlocked, let session, settings.quickTypeSuggestions else { return }
        let excluded = excludedVaultIDs
        let settings = settings
        let sync = identitySync
        enqueueIdentity {
            await sync.schedule {
                // The setting may have been turned off meanwhile; a locked session throws.
                guard settings.quickTypeSuggestions else { throw CancellationError() }
                return try await CoreThread.run { try session.autofillIdentities(excludedVaultIds: excluded) }
            }
        }
    }

    // MARK: - Safe exits (spec 3.3)

    /// The safe exits can run: unlocked (sync refused remote data, the vault is served from this
    /// device's copy), or "Données refusées" for anything but a missing account.
    public var safeExitAvailable: Bool {
        switch state {
        case .unlocked: true
        case .failed(.integrity(let kind)): kind != Self.accountMissingKind
        default: false
        }
    }

    /// "Exporter une sauvegarde chiffrée": an encrypted OnePass archive of what this device serves
    /// (every vault, its verified copy when the server is behind), readable with `passphrase` (strength
    /// checked by the core) or the account. Asks the master password first. The caller wipes both
    /// buffers and saves the bytes. Nothing changes in the store or the state.
    public func exportEncryptedBackup(password: SecretBytes, passphrase: SecretBytes) async throws -> Data {
        let kdf = environment.accountKdf
        return try await withConfirmedSession(password: password, reopen: false) { session in
            try passphrase.withData { phrase in
                try kdf.map { try session.exportEncryptedBackupWithKdf(passphrase: phrase, kdf: $0) }
                    ?? session.exportEncryptedBackup(passphrase: phrase)
            }
        }
    }

    /// Publishes the AutoFill identities now, without the debounce, and returns once the system store
    /// was replaced (after every identity request sent before). For the AutoFill extension after a
    /// write: its session locks right after, and a debounced refresh would then find it locked, leaving
    /// the new identity out of the store until the next app unlock. Does nothing unless unlocked with
    /// the "Suggestions au-dessus du clavier" setting on.
    public func publishAutofillIdentitiesNow() async {
        guard state == .unlocked, let session, settings.quickTypeSuggestions else { return }
        let excluded = excludedVaultIDs
        let settings = settings
        let sync = identitySync
        enqueueIdentity {
            guard settings.quickTypeSuggestions,
                let list = try? await CoreThread.run({ try session.autofillIdentities(excludedVaultIds: excluded) })
            else { return }
            await sync.replaceNow(list)
        }
        await identityChain?.value
    }

    /// Record ids (`"<vault id>:<item id>"`) of the items hidden from AutoFill, every type included.
    public func autofillHiddenRecordIDs() async throws -> Set<String> {
        Set(try await read { try $0.autofillHiddenRecordIds() })
    }

    /// "Suggestions au-dessus du clavier": off empties the system store, on publishes again (if unlocked).
    public func setQuickTypeSuggestions(_ on: Bool) {
        settings.quickTypeSuggestions = on
        if on {
            refreshAutofillIdentities()
        } else {
            clearAutofillIdentities()
        }
    }

    /// Empties the system identity store (setting turned off, account reset or erased).
    public func clearAutofillIdentities() {
        let sync = identitySync
        enqueueIdentity { await sync.clear() }
    }

    /// Tests: waits until every identity store request sent so far has run.
    func waitForAutofillIdentities() async {
        await identityChain?.value
        await identitySync.waitForIdle()
    }

    private var excludedVaultIDs: [String] { hiddenVaultIDs.sorted() }

    private func enqueueIdentity(_ op: @escaping @Sendable () async -> Void) {
        let previous = identityChain
        identityChain = Task {
            await previous?.value
            await op()
        }
    }

    /// Another process (the AutoFill extension) wrote to the store. Unlocked: reload the lists, then
    /// (unless the reload failed) let the sync layer send the change. Not unlocked: only tell the sync
    /// layer, pending rows push without unlocking. VaultSession itself never posts: the AutoFill model
    /// posts through `environment.storeChanges` after a write, once its session is locked. The
    /// extension session then receives its own post while locked, which only signals the sync layer
    /// and never posts again, so this cannot loop.
    private func observeStoreChanges() {
        let changes = environment.storeChanges.changes()
        storeChangeObserver = Task { [weak self] in
            for await _ in changes {
                guard let self else { return }
                await self.storeChanged()
            }
        }
    }

    /// The browser bridge wrote to the vault (a login saved from the extension): reload the lists,
    /// then push, exactly as for a write of the AutoFill extension.
    public func bridgeWroteVault() async {
        await storeChanged()
    }

    private func storeChanged() async {
        if state == .unlocked {
            await reloadAfterExternalChange()
            guard state == .unlocked else { return }
        }
        notifySync { await $0.localChangesWritten() }
    }

    /// Unlocked: reloads the lists for a write another process may have made (store-changed
    /// notification, or the app coming back to the foreground in case that notification was lost),
    /// then bumps `externalChangeRevision`. Otherwise does nothing.
    public func reloadAfterExternalChange() async {
        guard state == .unlocked else { return }
        await reload()
        if state == .unlocked { externalChangeRevision &+= 1 }
    }

    /// "Garder la version de cet appareil" or "Prendre la version d'iCloud": asks the master password,
    /// issues the signed restore epoch (`keep_this_device`, `take_server`), reloads (from "Données
    /// refusées", the vault opens when it now loads) and hands the epoch to the sync layer, which pushes
    /// it and follows it until the server serves it back. `takeServer` drops every local change not
    /// sent yet: the UI offers the export first.
    public func runSafeExit(_ exit: SafeExit, password: SecretBytes) async throws {
        _ = try await withConfirmedSession(password: password, reopen: true) { session in
            switch exit {
            case .keepThisDevice: try session.keepThisDevice()
            case .takeServer: try session.takeServer()
            }
        }
        notifySync { await $0.safeExitIssued(exit) }
    }

    /// Checks the master password and runs `op` on a session. Unlocked: `verify_password_bytes`, then
    /// the open session (the lists are reloaded when `reopen`). "Données refusées": the password opens
    /// a session (`unlock_with_password_bytes`) for `op`; with `reopen`, the vault is installed when it
    /// loads now, otherwise the session is dropped and the screen stays. Wrong passwords count toward
    /// the throttle. Errors of `op` never drop an open session.
    private func withConfirmedSession<T: Sendable>(
        password: SecretBytes, reopen: Bool, _ op: @escaping @Sendable (Session) throws -> T
    ) async throws -> T {
        guard safeExitAvailable else { throw fail(.passwordRequired) }
        try checkStoreUsable()
        try checkLockout()
        let secretKey = try loadSecretKey().secretKey
        defer { secretKey.wipe() }
        try beginPasswordCheck()
        defer { passwordCheckInFlight = false }
        let path = dbPath
        let gen = generation
        let open = state == .unlocked ? session : nil
        // The password check and `op` run in one core call; `op`'s outcome is kept apart, so a right
        // password resets the throttle even when the exit itself is refused.
        let result: (outcome: Result<T, any Error>, session: Session, snapshot: Snapshot?)
        do {
            result = try await background {
                if let open {
                    var auk = try Self.withBytes(password, secretKey) { password, secretKey in
                        try verifyPasswordBytes(dbPath: path, password: password, secretKey: secretKey)
                    }
                    SecretBytes(taking: &auk).wipe()
                    return (Result { try op(open) }, open, nil)
                }
                var unlocked = try Self.withBytes(password, secretKey) { password, secretKey in
                    try unlockWithPasswordBytes(dbPath: path, password: password, secretKey: secretKey)
                }
                SecretBytes(taking: &unlocked.auk).wipe()
                let session = unlocked.session
                let outcome = Result { try op(session) }
                guard case .success = outcome else {
                    session.lock()
                    return (outcome, session, nil)
                }
                return (outcome, session, reopen ? try? Self.load(session, purge: false) : nil)
            }
        } catch {
            let failure = VaultError(error)
            if failure == .wrongPassword { recordFailedUnlock() }
            throw fail(failure)
        }
        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        let value: T
        do {
            value = try result.outcome.get()
        } catch {
            throw fail(VaultError(error))
        }
        if open != nil {
            if reopen { await refresh() }
            noteActivity()
        } else if gen == generation, safeExitAvailable, let snapshot = result.snapshot {
            install(result.session, snapshot)
        } else {
            release(result.session)
        }
        return value
    }

    // MARK: - Plumbing

    /// Lists loaded after an unlock or a write.
    struct Snapshot: Sendable {
        var vaults: [FfiVault]
        var summaries: [FfiItemSummary]
        var purged: UInt32 = 0
    }

    private struct Opened: Sendable {
        var session: Session
        var accountID: String
        var snapshot: Snapshot
        let auk: SecretBytes
    }

    private struct Created: Sendable {
        var session: Session
        let secretKey: SecretBytes
        var accountID: String
        var snapshot: Snapshot
    }

    /// Both secrets as temporary `Data` copies, wiped when `body` returns (`SecretBytes.withData`).
    nonisolated private static func withBytes<T>(
        _ first: SecretBytes, _ second: SecretBytes, _ body: (Data, Data) throws -> T
    ) rethrows -> T {
        try first.withData { a in try second.withData { b in try body(a, b) } }
    }

    nonisolated private static func load(_ session: Session, purge: Bool) throws -> Snapshot {
        let purged = purge ? try session.purgeTrash(olderThanDays: trashRetentionDays) : 0
        return Snapshot(vaults: try session.vaults(), summaries: try session.itemSummaries(), purged: purged)
    }

    private func background<T: Sendable>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
        let hook = coreWorkHook
        return try await CoreThread.run {
            hook?()
            return try work()
        }
    }

    /// `Session.lock()` waits for a core call in flight (save, purge...): never on the main actor.
    private func release(_ session: Session) {
        let previous = releaseChain
        releaseChain = Task {
            await previous?.value
            _ = try? await CoreThread.run { session.lock() }
        }
    }

    /// A new unlock supersedes any one in flight.
    private func beginUnlocking() -> Int {
        generation &+= 1
        lastError = nil
        state = .unlocking
        return generation
    }

    nonisolated static var secretKeyNotStoredOnCreate: String {
        String(
            localized: "Impossible de ranger la Secret Key dans le trousseau de cet appareil. Le coffre n'a pas été créé.",
            bundle: VaultKitStrings.bundle)
    }
    nonisolated static var secretKeyNotStoredOnRestore: String {
        String(
            localized: "Impossible de ranger la Secret Key dans le trousseau de cet appareil. La connexion a été annulée.",
            bundle: VaultKitStrings.bundle)
    }

    private func install(_ session: Session, _ snapshot: Snapshot) {
        self.session = session
        apply(snapshot)
        state = .unlocked
        lastError = nil
        autoLock = AutoLock(now: environment.clock.now)
        startAutoLockTimer()
        notifySync { await $0.sessionUnlocked(session) }
        if snapshot.purged > 0 { notifySync { await $0.localChangesWritten() } }
        refreshAutofillIdentities()
    }

    private func apply(_ snapshot: Snapshot) {
        allVaults = snapshot.vaults
        summaries = snapshot.summaries
        summariesRevision &+= 1
        let known = Set(snapshot.summaries.map(\.id))
        recents.removeAll { !known.contains($0) }
    }

    private func checkLockout() throws {
        if let until = settings.lockoutUntil, until > environment.clock.now {
            throw fail(.lockedOut(until: until))
        }
    }

    /// After 5 failures: 30 s, then 60 s, then 300 s for every later failure.
    private func recordFailedUnlock() {
        let count = settings.recordFailedUnlock()
        guard count >= 5 else { return }
        let wait: TimeInterval = count == 5 ? 30 : count == 6 ? 60 : 300
        settings.lockoutUntil = environment.clock.now.addingTimeInterval(wait)
    }

    private func unlockFailed(_ error: any Error, generation gen: Int) -> VaultError {
        let failure = VaultError(error)
        if case .integrity = failure, gen == generation { return enterFailed(failure) }
        if failure == .wrongPassword {
            recordFailedUnlock()
            if gen == generation { state = .locked }
        } else if gen == generation {
            // Store or keychain trouble: the account may be gone or unreadable, re-read the store.
            evaluateStoredAccount()
        }
        return fail(failure)
    }

    private func beginPasswordCheck() throws {
        guard !passwordCheckInFlight else {
            throw fail(.other(String(localized: "Une vérification du mot de passe est déjà en cours.", bundle: VaultKitStrings.bundle)))
        }
        passwordCheckInFlight = true
    }

    /// Records the error for the UI and returns it.
    private func fail(_ failure: VaultError) -> VaultError {
        lastError = failure
        return failure
    }

    /// "Données refusées": keys dropped, nothing in memory, state `failed` until `refresh`.
    private func enterFailed(_ failure: VaultError) -> VaultError {
        let wasOpen = session != nil
        generation &+= 1
        if let session {
            self.session = nil
            release(session)
        }
        clearMemory()
        clipboard.clear()
        concealRevealed()
        state = .failed(failure)
        lastError = failure
        if wasOpen { notifySync { await $0.sessionLocked() } }
        return failure
    }

    private func handle(_ error: any Error, generation gen: Int) -> VaultError {
        let failure = VaultError(error)
        if case .integrity = failure, gen == generation { return enterFailed(failure) }
        lastError = failure
        return failure
    }

    func read<T: Sendable>(_ op: @escaping @Sendable (Session) throws -> T) async throws -> T {
        guard let session else { throw fail(.passwordRequired) }
        let gen = generation
        noteActivity()
        let value: T
        do {
            value = try await background { try op(session) }
        } catch {
            throw handle(error, generation: gen)
        }
        guard gen == generation else { throw fail(.passwordRequired) }
        return value
    }

    /// Runs a write, reloads the lists, tells the sync layer.
    @discardableResult
    func write<T: Sendable>(_ op: @escaping @Sendable (Session) throws -> T) async throws -> T {
        guard let session else { throw fail(.passwordRequired) }
        let gen = generation
        noteActivity()
        let result: (value: T, snapshot: Snapshot)
        do {
            result = try await background {
                // No retry here: the core already retries a conflicting write once (spec 8).
                let value = try op(session)
                return (value, try Self.load(session, purge: false))
            }
        } catch {
            throw handle(error, generation: gen)
        }
        guard gen == generation else { throw fail(.passwordRequired) }
        apply(result.snapshot)
        notifySync { await $0.localChangesWritten() }
        refreshAutofillIdentities()
        return result.value
    }

    /// Sync notifications run in order, off the caller.
    private func notifySync(_ op: @escaping @Sendable (any SyncTrigger) async -> Void) {
        let previous = syncChain
        let sync = environment.sync
        syncChain = Task {
            await previous?.value
            await op(sync)
        }
    }

    /// Tests: waits until every dropped session has been locked by the core (connection closed).
    func waitForReleasedSessions() async {
        await releaseChain?.value
    }

    /// Tests: waits until every sync notification sent so far has been delivered.
    func waitForSyncNotifications() async {
        await syncChain?.value
    }
}
