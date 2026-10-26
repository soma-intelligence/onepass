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

    /// Vaults shown in the sidebar (hidden ones left out).
    public var vaults: [FfiVault] { allVaults.filter { !hiddenVaultIDs.contains($0.id) } }

    @ObservationIgnored public let environment: VaultEnvironment
    @ObservationIgnored private var session: Session?
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
        evaluateStoredAccount()
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

    private func evaluateStoredAccount() {
        do {
            let exists = try hasAccount(dbPath: dbPath)
            state = exists ? .locked : .noAccount
            needsSecretKey = exists && secretKeyPresence() == .missing
        } catch {
            let failure = VaultError(error)
            state = .failed(failure)
            lastError = failure
        }
    }

    private enum Presence { case present, missing, unknown }

    /// Presence only, nothing loaded. `unknown` when the keychain cannot answer (device locked at a
    /// background launch, for example): that is not a missing Secret Key.
    private func secretKeyPresence() -> Presence {
        guard let accountID = settings.accountID else { return .missing }
        do {
            return try secretKeys.contains(accountID: accountID) ? .present : .missing
        } catch {
            return .unknown
        }
    }

    /// The stored Secret Key for an unlock. Missing: `needsSecretKey`. Keychain error: thrown as is.
    private func loadSecretKey() throws -> (accountID: String, secretKey: String) {
        let missing = VaultError.other("La Secret Key de ce compte n'est pas sur cet appareil : utilisez votre Emergency Kit.")
        guard let accountID = settings.accountID else {
            needsSecretKey = true
            throw fail(missing)
        }
        let secretKey: String?
        do {
            secretKey = try secretKeys.load(accountID: accountID)
        } catch {
            throw fail(VaultError(error))
        }
        guard let secretKey else {
            needsSecretKey = true
            throw fail(missing)
        }
        return (accountID, secretKey)
    }

    // MARK: - Account creation and unlock

    /// Creates the account and its "Personnel" vault, stores the Secret Key in the keychain and
    /// unlocks. Returns the Secret Key in display form, to show once and put in the Emergency Kit.
    public func createAccount(password: String, displayName: String, mode: DeviceMode) async throws -> String {
        if session != nil || state == .locked { throw fail(.accountExists) }
        let path = dbPath
        let kdf = environment.accountKdf
        let gen = beginUnlocking()
        let created: Created
        do {
            created = try await background {
                if try hasAccount(dbPath: path) { throw VaultError.accountExists }
                let account = try kdf.map { try createAccountWithKdf(dbPath: path, password: password, kdf: $0) }
                    ?? OnePassCore.createAccount(dbPath: path, password: password)
                do {
                    if try account.session.vaults().isEmpty {
                        _ = try account.session.createVault(meta: Self.personalVault)
                    }
                    return Created(
                        session: account.session, secretKey: account.secretKey, accountID: account.accountId,
                        snapshot: try Self.load(account.session, purge: false))
                } catch {
                    account.session.lock()
                    throw error
                }
            }
        } catch {
            if gen == generation { evaluateStoredAccount() }
            throw fail(VaultError(error))
        }

        // The account exists now: keep its Secret Key even if a lock came in meanwhile.
        do {
            try secretKeys.store(created.secretKey, accountID: created.accountID)
        } catch {
            Self.log.error("Secret Key not stored in the keychain")
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

    /// Master password unlock. The password is passed as typed (never trimmed): the core normalizes it.
    public func unlock(password: String) async throws {
        if state == .unlocked { return }
        try checkLockout()
        let stored = try loadSecretKey()
        try await passwordUnlock(password: password, secretKey: stored.secretKey, storeSecretKey: false)
    }

    /// New device (or wiped keychain) with a store that already holds the account:
    /// Secret Key typed from the Emergency Kit plus master password.
    public func restore(secretKey: String, password: String) async throws {
        if state == .unlocked { return }
        try checkLockout()
        let normalized: String
        do {
            normalized = try normalizeSecretKey(text: secretKey)
        } catch {
            throw fail(.validation(field: "secretKey", reason: "Cette Secret Key n'a pas le bon format."))
        }
        try await passwordUnlock(password: password, secretKey: normalized, storeSecretKey: true)
    }

    private func passwordUnlock(password: String, secretKey: String, storeSecretKey: Bool) async throws {
        try beginPasswordCheck()
        defer { passwordCheckInFlight = false }
        let path = dbPath
        let gen = beginUnlocking()
        let opened: Opened
        do {
            opened = try await background {
                var unlocked = try unlockWithPassword(dbPath: path, password: password, secretKey: secretKey)
                let auk = SecretBytes(copying: unlocked.auk)
                Self.wipe(&unlocked.auk)
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

        settings.resetFailedUnlocks()
        settings.lockoutUntil = nil
        if storeSecretKey {
            do {
                try secretKeys.store(secretKey, accountID: opened.accountID)
            } catch {
                Self.log.error("Secret Key not stored in the keychain")
            }
            settings.accountID = opened.accountID
        }
        afterPasswordUnlock(accountID: opened.accountID, auk: opened.auk.data)
        needsSecretKey = secretKeyPresence() == .missing

        guard gen == generation else {
            release(opened.session)
            return
        }
        install(opened.session, opened.snapshot)
    }

    /// Spec 4 point 3: restart the 14 day clock, and enroll again when biometrics are wanted but the
    /// enrollment was dropped (reboot, expiry, biometry change).
    private func afterPasswordUnlock(accountID: String, auk: Data) {
        try? biometrics.notePasswordUnlock(accountID: accountID)
        if settings.biometricsWanted, settings.deviceMode.biometricsAllowed, biometrics.isAvailable,
            !biometrics.isEnrolled(accountID: accountID)
        {
            try? biometrics.enroll(auk: auk, accountID: accountID, allowWatch: settings.allowWatchUnlock)
        }
        biometricsRevision += 1
    }

    /// Face ID, Touch ID or Apple Watch. Any refusal (reboot, 14 days, biometry change, cancel) ends in
    /// `locked` with `VaultError.passwordRequired`, so the UI shows the password field.
    public func unlockWithBiometrics() async throws {
        if state == .unlocked { return }
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
                let session = try unlockWithAuk(dbPath: path, auk: key.data)
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

    /// Checks the master password, then wraps the AUK with the Secure Enclave. Personal mode only.
    public func enrollBiometrics(password: String) async throws {
        guard settings.deviceMode.biometricsAllowed, biometrics.isAvailable else {
            throw fail(.biometricsUnavailable)
        }
        try checkLockout()
        let (accountID, secretKey) = try loadSecretKey()
        try beginPasswordCheck()
        defer { passwordCheckInFlight = false }
        let path = dbPath
        let auk: SecretBytes
        do {
            auk = try await background {
                var unlocked = try unlockWithPassword(dbPath: path, password: password, secretKey: secretKey)
                let auk = SecretBytes(copying: unlocked.auk)
                Self.wipe(&unlocked.auk)
                unlocked.session.lock()
                return auk
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
            try biometrics.enroll(auk: auk.data, accountID: accountID, allowWatch: settings.allowWatchUnlock)
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
        if !mode.biometricsAllowed, let accountID = settings.accountID {
            biometrics.disable(accountID: accountID)
        }
        biometricsRevision += 1
    }

    public func setVaultHidden(_ vaultID: String, hidden: Bool) {
        var ids = hiddenVaultIDs
        if hidden { ids.insert(vaultID) } else { ids.remove(vaultID) }
        settings.hiddenVaultIDs = ids
        hiddenVaultIDs = ids
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
        if state == .unlocked || state == .unlocking { state = .locked }
        if wasOpen { notifySync { await $0.sessionLocked() } }
    }

    private func clearMemory() {
        summaries = []
        allVaults = []
        recents = []
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
        case .active:
            let expired = autoLock.becomeActive(now, delay: settings.effectiveAutoLockSeconds)
            if state == .unlocked, expired { lock() }
            clipboard.clearIfExpired()
        case .inactive:
            break
        }
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
        var secretKey: String
        var accountID: String
        var snapshot: Snapshot
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

    /// Overwrites the bytes of this buffer (in place when it is the only reference). Copies made by the
    /// bindings or the core are out of reach (R5).
    nonisolated static func wipe(_ data: inout Data) {
        data.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            _ = memset_s(base, buffer.count, 0, buffer.count)
        }
    }

    /// A new unlock supersedes any one in flight.
    private func beginUnlocking() -> Int {
        generation &+= 1
        lastError = nil
        state = .unlocking
        return generation
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
    }

    private func apply(_ snapshot: Snapshot) {
        allVaults = snapshot.vaults
        summaries = snapshot.summaries
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
            throw fail(.other("Une vérification du mot de passe est déjà en cours."))
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

    private func read<T: Sendable>(_ op: @escaping @Sendable (Session) throws -> T) async throws -> T {
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
    private func write<T: Sendable>(_ op: @escaping @Sendable (Session) throws -> T) async throws -> T {
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

/// The AUK in one heap buffer referenced once, so `wipe()` overwrites the only copy we hold.
/// Accessed by one thread at a time (core thread, then main actor).
final class SecretBytes: @unchecked Sendable {
    private(set) var data: Data

    /// Fresh buffer with the same bytes (the caller wipes its own).
    init(copying source: Data) {
        data = source.withUnsafeBytes { Data($0) }
    }

    /// Takes the buffer; `source` is left empty so this is the only reference.
    init(taking source: inout Data) {
        data = source
        source = Data()
    }

    func wipe() { VaultSession.wipe(&data) }

    deinit { wipe() }
}
