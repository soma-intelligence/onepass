import Foundation
import GlanceKit
import Observation
import Security
import SwiftUI
import VaultKit
import os

/// An item of a vault, for navigation (the full item is loaded by the detail view only).
struct ItemRef: Hashable, Sendable {
    var vaultID: String
    var itemID: String
}

/// Owns the vault session, the sync coordinator, the site icon loader and the navigation state.
/// One per process: every window of the app shares it (spec 6.3).
@MainActor
@Observable
final class AppModel {
    let session: VaultSession
    @ObservationIgnored let coordinator: SyncCoordinator?
    /// Widget snapshot (and, from Task 8, the watch payload) while unlocked.
    @ObservationIgnored let companion: CompanionCoordinator
    @ObservationIgnored let iconLoader: SiteIconLoader
    @ObservationIgnored private let remote: (any RemoteRecordStore)?

    /// Built with `ONEPASS_CLOUDKIT` (signed Release-CloudKit configuration, ruling R8).
    let cloudKitEnabled: Bool
    private(set) var syncStatus: SyncStatus = .disabled
    /// Remote deletions the store refused (core log, 100 at most), for Réglages > Sync.
    private(set) var ignoredDeletionCount = 0
    /// Where the onboarding starts after "Restaurer avec mon Emergency Kit" (read once by the
    /// onboarding model).
    var onboardingStart: OnboardingPath?

    /// The onboarding stays on screen until "Ouvrir OnePass", even though the account creation
    /// already unlocked the session.
    var onboardingInProgress = false

    // Navigation (filled by the browse screens).
    var selection: ItemFilter = .all
    var selectedItem: ItemRef?
    var editing = false
    /// A new item's editor, shown in place of the detail until saved or cancelled.
    var newItemDraft: ItemDraft?
    /// Reported by the editor on screen: its draft has unsaved changes.
    var editorDirty = false
    /// An action that would drop a dirty draft, waiting for "Abandonner les modifications ?".
    var pendingDiscard: GuardedAction?
    /// iPhone and iPad: the settings sheet (the Mac has its own `Settings` window).
    var showSettings = false
    /// Bumped on every settings change made through `updateSettings`, so views that show a setting
    /// (stored in `UserDefaults`, not observable) redraw.
    private(set) var settingsRevision = 0
    /// ⌘N: the type picker of a new item.
    var showNewItemPicker = false
    // Menu commands handled by the views on screen (bumped, observed with `onChange`).
    var editRequest = 0
    var saveRequest = 0
    var searchFocusRequest = 0
    /// Bumped after each remote change set is applied: an open item detail reloads (or warns its
    /// editor) on it.
    private(set) var remoteRevision = 0
    /// Short confirmation shown at the bottom of the browse screens ("Mis à la corbeille").
    private(set) var toast: String?
    /// OnePass is the system AutoFill provider; nil until the first read. Read again on every return
    /// to the foreground and after an activation request.
    private(set) var autofillEnabled: Bool?

    // Routes from outside the app (widgets, Controls, App Intents).
    /// A route that arrived while locked: runs right after the next unlock.
    private(set) var pendingRoute: AppRoute?
    /// The standalone password generator ("Générer un mot de passe" Control).
    var showGenerator = false
    /// "Copier le code à usage unique" without biometrics: the item whose code waits for the
    /// master password.
    var totpPasswordRequest: ItemRef?
    /// The master password sheet of `totpPasswordRequest` actually appeared.
    @ObservationIgnored var totpPromptShown = false
    /// The waiting route was queued while locked, so the coming unlock is made for it (ruling W13).
    @ObservationIgnored private var pendingRouteFresh = false
    /// When the waiting route was queued (an abandoned copy request expires).
    @ObservationIgnored private var pendingRouteAt = Date.distantPast
    /// When the session last became unlocked (lock requests from a Control older than this are spent).
    @ObservationIgnored private(set) var lastUnlockAt: Date?
    /// What the browse screens should bring forward (iPhone: the tab to select). Cleared by the
    /// screen that handled it.
    var browseReveal: BrowseReveal?

    enum BrowseReveal: Equatable {
        case item(ItemRef)
        case search
    }

    /// "Verrouiller OnePass" Control: shared with the widget extension through the App Group.
    @ObservationIgnored private let lockSignal = LockSignal(
        defaults: UserDefaults(suiteName: AppGroup.identifier) ?? .standard)
    @ObservationIgnored private var lockObservation: LockSignalObservation?
    /// Requests older than this process are spent: an app that was not running held no key.
    @ObservationIgnored private let launchedAt = Date.now
    /// The newest request seen while not unlocked (spent: there was nothing to lock).
    @ObservationIgnored private var spentLockRequest: Date?

    @ObservationIgnored private var tasks: [Task<Void, Never>] = []
    @ObservationIgnored private var started = false
    /// One automatic biometric attempt per app activation, whatever the number of windows.
    @ObservationIgnored private var autoBiometricsPending = true

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "app")

    init() {
        // Resolved once per launch (the probe touches the disk): the same value serves the reset,
        // the migration, the sync store and the session.
        let resolved = SharedContainer.resolve()
        #if DEBUG
        let wasReset = DebugReset.applyIfRequested()
        #endif
        Self.sweepEmergencyKits()
        #if DEBUG
        let demo = DemoData.requested ? DemoData.environment() : nil
        let isolated = TestIsolation.isActive
        #else
        let demo: VaultEnvironment? = nil
        let isolated = false
        #endif
        var coordinator: SyncCoordinator?
        #if ONEPASS_CLOUDKIT
        let remote: (any RemoteRecordStore)? = demo == nil
            ? CloudKitRemote(containerIdentifier: "iCloud.me.somalabs.onepass") : nil
        cloudKitEnabled = demo == nil
        #else
        let remote: (any RemoteRecordStore)? = nil
        cloudKitEnabled = false
        #endif
        let environment: VaultEnvironment
        if let demo {
            // Demonstration store (Debug): temporary database, no sync.
            environment = demo
        } else {
            // Before anything opens the store: the extension and the app share the moved database.
            // UI tests (Debug, `TestIsolation`) never move nor open the user's store.
            #if DEBUG
            let container = isolated ? resolved : Self.migrateToSharedContainer(resolved)
            let databaseURL = isolated ? TestIsolation.databaseURL : container.databaseURL
            #else
            let container = Self.migrateToSharedContainer(resolved)
            let databaseURL = container.databaseURL
            #endif
            do {
                let store = try openSyncStore(dbPath: databaseURL.path)
                coordinator = SyncCoordinator(store: store, remote: isolated ? nil : remote)
            } catch {
                Self.log.error("sync store not opened, sync disabled")
            }
            #if DEBUG
            if isolated {
                // UI tests: their own store, settings and keychain service (never the user's), and
                // nothing published to the system identity store.
                var isolatedEnvironment = VaultEnvironment.live(
                    sync: coordinator ?? NoSync(), container: container, databaseURL: databaseURL,
                    settings: VaultSettings(defaults: TestIsolation.defaults),
                    keychainService: TestIsolation.keychainService)
                isolatedEnvironment.identityStore = NoIdentityStore()
                environment = isolatedEnvironment
            } else {
                environment = VaultEnvironment.live(sync: coordinator ?? NoSync(), container: container)
            }
            #else
            // `live` uses the same container as the sync store.
            environment = VaultEnvironment.live(sync: coordinator ?? NoSync(), container: container)
            #endif
        }
        self.coordinator = coordinator
        self.remote = remote
        session = VaultSession(environment: environment)
        // Demo data never reaches the widgets.
        companion = CompanionCoordinator(
            session: session, glanceStore: demo == nil && !isolated ? GlanceStore.shared() : nil,
            phone: demo == nil && !isolated ? CompanionCoordinator.makePhone(session: session) : nil)
        #if DEBUG
        // A wiped account must not leave its identities in the system store.
        if wasReset { session.clearAutofillIdentities() }
        #endif

        let settings = environment.settings
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        iconLoader = SiteIconLoader(
            cacheDirectory: caches.appendingPathComponent("OnePass/SiteIcons", isDirectory: true),
            enabled: { settings.siteIconsEnabled })
        onboardingInProgress = session.state == .noAccount
    }

    var settings: VaultSettings { session.environment.settings }

    /// The milestone 2 store location (`Application Support/OnePass/vault.sqlite` of the app's own
    /// container) and settings (`UserDefaults.standard`).
    nonisolated static var legacyContainer: SharedContainer {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return SharedContainer(root: support, isShared: false, defaultsSuite: nil)
    }

    /// Moves the milestone 2 store and settings into the shared container (ruling A3). If the move
    /// fails, this launch keeps the legacy store and settings (the database file moves last, so it is
    /// still in place): the vault stays usable in the app, and the AutoFill extension sees no vault
    /// until a later launch completes the move.
    private static func migrateToSharedContainer(_ container: SharedContainer) -> SharedContainer {
        guard container.isShared else { return container }
        let legacy = legacyContainer
        do {
            try SharedContainerMigration.run(
                from: legacy.databaseURL, legacyDefaults: .standard, to: container)
            return container
        } catch {
            log.error("shared container migration failed, legacy store kept for this launch")
            return legacy
        }
    }

    /// Starts listening to the sync layer and runs a first round. Called once by the root view.
    func start() {
        guard !started else { return }
        started = true
        IntentBridge.model = self
        #if DEBUG
        if DemoData.requested {
            seedDemoData()
        } else {
            seedAccountIfRequested()
            openDebugItemIfRequested()
        }
        #endif
        #if os(iOS)
        // A "Verrouiller OnePass" Control while the app runs: the Darwin notification locks now.
        lockObservation = LockSignal.observe { [weak self] in
            Task { @MainActor in self?.lockIfRequested() }
        }
        trackUnlocks()
        lockIfRequested()
        #endif
        companion.start()
        tasks.append(Task { [weak self] in await self?.refreshAutoFillStatus() })
        guard let coordinator else { return }
        tasks.append(Task { [weak self] in
            for await _ in await coordinator.remoteChanges() {
                await self?.session.reload()
                self?.remoteRevision &+= 1
            }
        })
        tasks.append(Task { [weak self] in
            for await status in await coordinator.statusUpdates() {
                self?.syncStatus = status
                self?.ignoredDeletionCount = await coordinator.ignoredDeletionCount
            }
        })
        tasks.append(Task { await coordinator.syncNow() })
    }

    /// The app's aggregate scene phase (forwarded from `OnePassApp`), not a single window's.
    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            autoBiometricsPending = true
            session.scenePhaseChanged(.active)
            // A lock asked by a Control while the app was in the background or not notified.
            lockIfRequested()
            companion.sessionChanged()
            if let coordinator { Task { await coordinator.syncNow() } }
            // The provider may have been turned on or off in the system settings meanwhile.
            Task { await refreshAutoFillStatus() }
        case .inactive:
            session.scenePhaseChanged(.inactive)
        case .background:
            session.scenePhaseChanged(.background)
            #if os(iOS) || os(visionOS)
            lockWhileBackgroundTimeLasts()
            #endif
        @unknown default:
            break
        }
    }

    #if os(iOS) || os(visionOS)
    @ObservationIgnored private var backgroundLock: Task<Void, Never>?
    @ObservationIgnored private var backgroundTaskID: UIBackgroundTaskIdentifier = .invalid

    /// iOS suspends the app soon after it leaves the screen, and the in-process auto-lock timer with
    /// it. While the system grants background time, the delay is checked every second, so a short
    /// delay (shared mode, 1 minute) locks without waiting for the return to the foreground. Past
    /// that, a background wake (remote notification) or the return locks first.
    private func lockWhileBackgroundTimeLasts() {
        guard session.state == .unlocked, backgroundLock == nil else { return }
        backgroundTaskID = UIApplication.shared.beginBackgroundTask(withName: "OnePass auto-lock") { [weak self] in
            MainActor.assumeIsolated { self?.endBackgroundLock() }
        }
        backgroundLock = Task { [weak self] in
            while let self, !Task.isCancelled, self.session.state == .unlocked,
                UIApplication.shared.applicationState == .background
            {
                self.session.checkAutoLock()
                try? await Task.sleep(for: .seconds(1))
            }
            self?.endBackgroundLock()
        }
    }

    private func endBackgroundLock() {
        backgroundLock?.cancel()
        backgroundLock = nil
        if backgroundTaskID != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTaskID)
            backgroundTaskID = .invalid
        }
    }
    #endif

    #if DEBUG
    /// Screenshots: `-OnePassDebugSeedAccount YES` (with `-OnePassTestIsolation YES`) creates a fictional account (Camille Durand) when
    /// none exists, then locks, so the lock screen can be captured. Debug builds only.
    private func seedAccountIfRequested() {
        // `TestIsolation` is forced by this flag: never creates an account in the user's store.
        guard UserDefaults.standard.bool(forKey: "OnePassDebugSeedAccount"), TestIsolation.isActive,
            session.state == .noAccount
        else { return }
        Task {
            _ = try? await session.createAccount(
                password: "ruisseau-tapis-orage-comete", displayName: "Camille Durand", mode: .personal)
            onboardingInProgress = false
            session.lock()
        }
    }
    #endif

    /// True once per app activation: the lock screen of the first window that asks may try
    /// biometric unlock automatically.
    func takeAutomaticBiometricAttempt() -> Bool {
        defer { autoBiometricsPending = false }
        return autoBiometricsPending
    }

    /// CloudKit build: whether an iCloud account is signed in. Unsigned build: true (local only).
    func iCloudAccountAvailable() async -> Bool {
        guard cloudKitEnabled, let remote else { return true }
        return await remote.accountAvailable()
    }

    /// Emergency Kit PDFs left in the temporary folder by a previous run (killed during the step).
    private static func sweepEmergencyKits() {
        let tmp = FileManager.default.temporaryDirectory
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? []
        for name in entries where name.hasPrefix("kit-") {
            try? FileManager.default.removeItem(at: tmp.appendingPathComponent(name, isDirectory: true))
        }
    }

    /// Spec 7: the creation is refused when this iCloud already holds an account (ruling R13).
    /// No CloudKit: always false.
    func remoteHasAccount() async throws -> Bool {
        guard cloudKitEnabled, let coordinator else { return false }
        let found = try await coordinator.remoteHasAccount()
        await session.reload()
        return found
    }

    /// "Créer un nouveau coffre" on the Emergency Kit screen of a device without its Secret Key:
    /// offered only when iCloud holds no account (always without sync).
    func newVaultOffer() async -> NewVaultOffer {
        guard cloudKitEnabled, let coordinator else { return .offered }
        let offer = await coordinator.newVaultOffer()
        await session.reload()
        return offer
    }

    /// "Réessayer" on "Données refusées": a complete fetch from scratch, then the store is read again.
    func retryAfterFailure() async {
        await coordinator?.refetchFromScratch()
        await session.reload()
        if case .failed = session.state { await session.refresh() }
    }

    // MARK: - Account missing

    /// "Restaurer avec mon Emergency Kit" on "Le compte a disparu du stockage", confirmed: the
    /// unreadable local copy is cleared, then the Emergency Kit restore opens (CloudKit: the data comes
    /// back from iCloud).
    func recoverWithEmergencyKit() async throws {
        try await session.resetForRecovery()
        onboardingStart = .restore
        onboardingInProgress = true
    }

    /// "Repartir de zéro", confirmed by typing EFFACER: the local copy is cleared and the onboarding
    /// starts over. Nothing in iCloud is deleted.
    func startOver() async throws {
        try await session.resetForRecovery()
        onboardingStart = nil
        onboardingInProgress = true
    }

    // MARK: - iCloud account change

    /// What the zone of the signed-in iCloud account holds (thrown errors: network, no account).
    func checkAccountChange() async throws -> AccountChangeCheck {
        guard let coordinator else { throw RemoteStoreError.accountUnavailable }
        return try await coordinator.checkAccountChange()
    }

    /// "Utiliser ce compte iCloud", after the zone check (and the confirmation for an empty zone).
    func acceptAccountChange(expected: AccountChangeCheck) async -> AccountChangeOutcome {
        guard let coordinator else {
            return .failed(String(localized: "La synchronisation iCloud n'est pas active dans ce build."))
        }
        return await coordinator.acceptAccountChange(expected: expected)
    }

    // MARK: - Refused remote deletions

    func ignoredDeletions() async -> [FfiIgnoredDeletion] {
        guard let coordinator else { return [] }
        return (try? await coordinator.ignoredDeletions()) ?? []
    }

    func clearIgnoredDeletions() async {
        guard let coordinator else { return }
        try? await coordinator.clearIgnoredDeletions()
        ignoredDeletionCount = await coordinator.ignoredDeletionCount
    }

    #if DEBUG
    /// Screenshots of the sync banners in demo mode (no coordinator there).
    func debugSetSyncStatus(_ status: SyncStatus) {
        syncStatus = status
    }
    #endif

    /// Lock now, without asking. Explicit locks go through `perform(.lock)`.
    func lock() {
        resetNavigation()
        session.lock()
    }

    /// Locks when a "Verrouiller OnePass" request is newer than the last unlock, this launch and
    /// any request already seen while locked. iOS only (the Controls exist only there).
    func lockIfRequested() {
        #if os(iOS)
        let request = lockSignal.lastRequest
        guard session.state == .unlocked else {
            // Nothing to lock: this request is spent, the next unlock must not undo itself.
            if let request { spentLockRequest = max(spentLockRequest ?? request, request) }
            return
        }
        let baseline = [lastUnlockAt, spentLockRequest].compactMap { $0 }.max()
        guard LockSignal.shouldLock(request: request, unlockedAt: baseline, launchedAt: launchedAt) else { return }
        Self.log.info("lock requested from a Control")
        lock()
        #endif
    }

    #if os(iOS)
    /// Stamps `lastUnlockAt` from the model itself, whatever view is on screen.
    private func trackUnlocks() {
        withObservationTracking {
            _ = session.state
        } onChange: { [weak self] in
            // Called before the change: the new state is read on the next main actor turn.
            Task { @MainActor in
                guard let self else { return }
                let unlocked = self.session.state == .unlocked
                if unlocked, self.wasLocked { self.lastUnlockAt = .now }
                self.wasLocked = !unlocked
                self.trackUnlocks()
            }
        }
    }
    /// The session was not unlocked at the last observed change.
    @ObservationIgnored private var wasLocked = true
    #endif

    /// The session state changed (root view): records the unlock time, runs a waiting route,
    /// refreshes the widgets.
    func sessionStateChanged(_ state: VaultSession.State) {
        if state == .unlocked {
            consumePendingRoute()
        } else {
            resetNavigation()
        }
        companion.sessionChanged()
    }

    // MARK: - Routes from outside the app

    /// A deep link (`onepass://`), from a widget, a Control or the system.
    func open(_ link: OnePassLink) {
        handle(.link(link))
    }

    /// Runs the route now when unlocked, else keeps it for after the unlock (the newest wins).
    func handle(_ route: AppRoute) {
        guard session.state == .unlocked, !onboardingInProgress else {
            pendingRoute = route
            pendingRouteFresh = IntentAuthentication.isFreshUnlockRequest(
                state: session.state, onboarding: onboardingInProgress)
            pendingRouteAt = .now
            return
        }
        run(route, freshUnlock: false)
    }

    /// After an unlock: the waiting route, if any.
    func consumePendingRoute() {
        guard session.state == .unlocked, !onboardingInProgress, let route = pendingRoute else { return }
        pendingRoute = nil
        // A copy request left waiting more than 2 minutes was abandoned: no code copied later.
        if case .copyTotp = route, Date.now.timeIntervalSince(pendingRouteAt) > 120 {
            showToast(String(localized: "Demande de copie expirée"))
            return
        }
        run(route, freshUnlock: pendingRouteFresh)
    }

    private func run(_ route: AppRoute, freshUnlock: Bool) {
        switch route {
        case .link(.item(let vaultID, let itemID)):
            let ref = ItemRef(vaultID: vaultID, itemID: itemID)
            guard session.summaries.contains(where: { $0.id == itemID && $0.vaultId == vaultID }),
                !session.hiddenVaultIDs.contains(vaultID)
            else {
                showToast(String(localized: "Élément introuvable"))
                return
            }
            perform(.reveal(ref))
        case .link(.generator):
            showSettings = false
            showGenerator = true
        case .link(.search):
            showSettings = false
            browseReveal = .search
            searchFocusRequest &+= 1
        case .copyTotp(let ref):
            Task { await copyTotp(ref, freshUnlock: freshUnlock) }
        }
    }

    /// "Copier le code à usage unique" (App Intent, ruling W13): an unlock made for this request
    /// is enough; otherwise Face ID, Touch ID or the device passcode, else the master password.
    func copyTotp(_ ref: ItemRef, freshUnlock: Bool) async {
        if !freshUnlock {
            guard await session.confirmUserPresence(prompt: String(localized: "Copier le code à usage unique"))
            else {
                await requestTotpPassword(ref)
                return
            }
        }
        await copyTotpCode(ref)
    }

    /// Shows the master password sheet: the sheets the model owns close first, and the prompt comes
    /// once their dismissal is over. A sheet it cannot close (an item being created, a vault
    /// editor) keeps it from appearing: a message says so instead.
    private func requestTotpPassword(_ ref: ItemRef) async {
        // The prompt for this item is already up: keep it, do not restart its 1 s check.
        if totpPasswordRequest == ref { return }
        let covered = showSettings || showGenerator || showNewItemPicker
        showSettings = false
        showGenerator = false
        showNewItemPicker = false
        if covered {
            try? await Task.sleep(for: .milliseconds(700))
        } else {
            await Task.yield()
        }
        guard session.state == .unlocked else { return }
        totpPromptShown = false
        totpPasswordRequest = ref
        try? await Task.sleep(for: .seconds(1))
        if totpPasswordRequest == ref, !totpPromptShown {
            totpPasswordRequest = nil
            showToast(String(localized: "Ouvre OnePass pour copier le code"))
        }
    }

    /// Copies the item's current one-time code with the OnePass clipboard (90 s, local only).
    func copyTotpCode(_ ref: ItemRef) async {
        guard session.state == .unlocked else { return }
        let noCode = String(localized: "Cet élément n'a pas de code à usage unique")
        guard !session.hiddenVaultIDs.contains(ref.vaultID) else {
            showToast(noCode)
            return
        }
        let item: FfiItem
        do {
            item = try await session.loadItem(vaultID: ref.vaultID, itemID: ref.itemID)
        } catch {
            Self.log.error("one-time code: item not loaded")
            showToast(noCode)
            return
        }
        guard item.trashedAt == nil, let secret = firstOtpValue(of: item) else {
            showToast(noCode)
            return
        }
        let totp: FfiTotpCode
        do {
            totp = try totpNow(secretOrUri: secret, unixSeconds: UInt64(Date.now.timeIntervalSince1970))
        } catch {
            Self.log.error("one-time code: secret refused by the core")
            showToast(noCode)
            return
        }
        session.copy(totp.code, concealed: true)
        showToast(String(localized: "Code copié"))
    }

    /// Drops every item-bearing navigation state (the new item's draft holds typed values).
    /// Also run when the session leaves `unlocked` on its own (auto-lock, background, failure).
    func resetNavigation() {
        selectedItem = nil
        editing = false
        newItemDraft = nil
        editorDirty = false
        pendingDiscard = nil
        showNewItemPicker = false
        showSettings = false
        showGenerator = false
        browseReveal = nil
        totpPasswordRequest = nil
    }

    /// Changes a local setting and restarts the auto-lock clock (a new delay applies from now).
    func updateSettings(_ change: (VaultSettings) -> Void) {
        change(settings)
        settingsChanged()
    }

    /// A setting changed through the session (biometrics, device mode): redraws the settings pages.
    func settingsChanged() {
        settingsRevision &+= 1
        session.noteActivity()
    }

    // MARK: - AutoFill

    /// Reads the provider state. When it turns on, the identities are published again: refreshes made
    /// while the provider was off were dropped by the system store.
    func refreshAutoFillStatus() async {
        let enabled = await providerEnabled()
        let turnedOn = enabled && autofillEnabled != true
        autofillEnabled = enabled
        if turnedOn { session.refreshAutofillIdentities() }
    }

    /// "Activer OnePass": the system prompt, then the state is read again.
    func requestAutoFillActivation() async {
        #if DEBUG
        // Demo data: the in-memory store stands for the system, nothing is asked.
        if let demo = session.environment.identityStore as? InMemoryIdentityStore {
            demo.enabled = true
            await refreshAutoFillStatus()
            return
        }
        #endif
        _ = await AutoFillStatus.requestActivation()
        await refreshAutoFillStatus()
    }

    /// The tip card of Accueil and of the sidebar: while the provider is off, until closed once.
    var showsAutoFillTip: Bool {
        _ = settingsRevision
        return autofillEnabled == false && !settings.autofillTipDismissed
    }

    func dismissAutoFillTip() {
        updateSettings { $0.autofillTipDismissed = true }
    }

    private func providerEnabled() async -> Bool {
        #if DEBUG
        if let demo = session.environment.identityStore as? InMemoryIdentityStore { return await demo.isEnabled() }
        #endif
        return await AutoFillStatus.isEnabled()
    }

    // MARK: - Navigation guarded by the editor

    /// What would replace an editor with unsaved changes.
    enum GuardedAction: Equatable {
        case lock
        case select(ItemRef?)
        case newItem(FfiItemType)
        /// A deep link to an item: shown in the full list (iPhone: the Éléments tab).
        case reveal(ItemRef)
    }

    /// An item editor (existing or new item) is on screen.
    var isEditing: Bool { editing || newItemDraft != nil }

    /// Runs the action, or asks first when it would drop a dirty draft (rule of Task 13).
    func perform(_ action: GuardedAction) {
        if isEditing, editorDirty {
            if case .select(let ref) = action, ref == selectedItem, newItemDraft == nil { return }
            pendingDiscard = action
            return
        }
        apply(action)
    }

    /// "Abandonner" in the confirmation.
    func confirmDiscard() {
        guard let action = pendingDiscard else { return }
        pendingDiscard = nil
        apply(action)
    }

    private func apply(_ action: GuardedAction) {
        switch action {
        case .lock:
            lock()
        case .select(let ref):
            newItemDraft = nil
            if ref != selectedItem { editing = false }
            editorDirty = false
            selectedItem = ref
        case .newItem(let type):
            startNewItem(type)
        case .reveal(let ref):
            newItemDraft = nil
            showNewItemPicker = false
            showSettings = false
            showGenerator = false
            editing = false
            editorDirty = false
            // The list that holds it (split view), so `keepSelection` does not drop it.
            let summary = session.summaries.first { $0.id == ref.itemID && $0.vaultId == ref.vaultID }
            if let summary, !selection.matches(summary) {
                selection = summary.trashedAt != nil ? .trash : summary.archived ? .archive : .all
            }
            browseReveal = .item(ref)
            selectedItem = ref
        }
    }

    /// iPhone (tabs): the vault whose list is open in the visible tab, set by `PhoneTabsView`.
    var phoneBrowsedVault: String?

    /// The vault of a new item: the vault shown in the list (iPhone: the vault list open in the
    /// visible tab), else the first visible one.
    var vaultForNewItem: String? {
        if let id = phoneBrowsedVault, session.vaults.contains(where: { $0.id == id }) { return id }
        if case .vault(let id) = selection, session.vaults.contains(where: { $0.id == id }) { return id }
        return session.vaults.first?.id
    }

    private func startNewItem(_ type: FfiItemType) {
        guard let vaultID = vaultForNewItem else { return }
        do {
            let item = try session.newItem(type: type, vaultID: vaultID)
            editing = false
            editorDirty = false
            newItemDraft = ItemDraft(item: item)
        } catch {
            Self.log.error("new item not created")
        }
    }

    /// The new item's editor closed: shows the saved item, or what was shown before.
    func finishNewItem(_ saved: FfiItem?) {
        newItemDraft = nil
        editorDirty = false
        if let saved { selectedItem = ItemRef(vaultID: saved.vaultId, itemID: saved.id) }
    }

    /// ⌘⌫: the selected item goes to Supprimés récemment (not while editing, not twice).
    var canTrashSelection: Bool {
        guard !isEditing, let ref = selectedItem else { return false }
        return session.summaries.contains { $0.id == ref.itemID && $0.trashedAt == nil }
    }

    func trashSelection() {
        guard canTrashSelection, let ref = selectedItem else { return }
        trash(ref)
    }

    /// No confirmation (the item stays 30 days in Supprimés récemment): a toast says it happened.
    func trash(_ ref: ItemRef) {
        let title = session.summaries.first { $0.id == ref.itemID }?.title ?? ""
        Task {
            do {
                try await session.trash(itemID: ref.itemID, vaultID: ref.vaultID)
                if selectedItem == ref, !isEditing { selectedItem = nil }
                showToast(String(localized: "« \(title) » mis à la corbeille"))
            } catch {
                showToast(VaultError(error).localizedMessage)
            }
        }
    }

    func showToast(_ text: String) {
        toast = text
        Task {
            try? await Task.sleep(for: .seconds(2))
            if toast == text { toast = nil }
        }
    }

    /// The list changed (filter, search, remote reload): a selected item that is no longer in it
    /// is dropped, unless its editor is open.
    func keepSelection(in visibleItemIDs: Set<String>) {
        guard !isEditing, let ref = selectedItem, !visibleItemIDs.contains(ref.itemID) else { return }
        perform(.select(nil))
    }

    /// Defaults of the browse screens (list order): the demo's own suite in demo mode.
    static var browseDefaults: UserDefaults {
        #if DEBUG
        if DemoData.requested { return DemoData.defaults }
        #endif
        return .standard
    }

    /// Initials for the account badge ("Camille Durand" gives "CD"), empty without a name.
    var initials: String {
        let words = settings.displayName.split(whereSeparator: { $0.isWhitespace || $0 == "-" })
        return words.prefix(2).compactMap { $0.first.map { String($0).uppercased() } }.joined()
    }
}

#if DEBUG
/// `-OnePassTestIsolation YES` (UI tests, screenshot runs and the Debug item helpers, Debug builds only): the app uses a store
/// in `<tmp>/OnePassUITest`, the `me.somalabs.onepass.uitest` defaults suite and the
/// `me.somalabs.onepass.uitest` keychain service, never the user's store, settings or Secret Keys.
/// No sync, no widget or watch data.
enum TestIsolation {
    static let keychainService = "me.somalabs.onepass.uitest"
    static let suiteName = "me.somalabs.onepass.uitest"

    /// Also forced by the Debug helpers that create or unlock a fictional account
    /// (`-OnePassDebugItem`, `-OnePassDebugNewItem`, `-OnePassDebugSeedAccount`): they never touch
    /// the user's store.
    static var isActive: Bool {
        let defaults = UserDefaults.standard
        return defaults.bool(forKey: "OnePassTestIsolation") || defaults.bool(forKey: "OnePassDebugSeedAccount")
            || defaults.string(forKey: "OnePassDebugItem") != nil
            || defaults.string(forKey: "OnePassDebugNewItem") != nil
    }

    static var folder: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("OnePassUITest", isDirectory: true)
    }

    static var databaseURL: URL {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder.appendingPathComponent("vault.sqlite")
    }

    /// `UserDefaults` is thread safe; the type is just not marked `Sendable` in this SDK.
    nonisolated(unsafe) static let defaults: UserDefaults = UserDefaults(suiteName: suiteName) ?? .standard

    /// Empties the isolated store, settings and keychain service (both keychains: the file one is
    /// the Debug fallback of an ad hoc signed build).
    static func wipe() {
        // The Secure Enclave key of the test account (biometric unlock), named after its id.
        if let accountID = UserDefaults(suiteName: suiteName)?.string(forKey: "onepass.accountID") {
            let tag = "me.somalabs.onepass.auk.\(accountID)"
            try? SecureEnclaveKeyring(accessGroup: VaultEnvironment.sharedAccessGroup()).deleteKey(tag: tag)
            try? SecureEnclaveKeyring(accessGroup: nil).deleteKey(tag: tag)
        }
        try? FileManager.default.removeItem(at: folder)
        UserDefaults(suiteName: suiteName)?.removePersistentDomain(forName: suiteName)
        for legacy in [false, true] {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
            ]
            if !legacy { query[kSecUseDataProtectionKeychain as String] = true }
            SecItemDelete(query as CFDictionary)
        }
    }
}

/// UI tests, with `-OnePassTestIsolation YES` only: `-OnePassUITestReset YES` starts from an empty
/// isolated store (also how a test cleans up after itself: a last launch with it, then terminate).
/// Without isolation it is ignored: the user's store, settings and keychain are never wiped.
/// Returns whether it ran (the caller then empties the identity store of the session).
enum DebugReset {
    @discardableResult
    static func applyIfRequested() -> Bool {
        guard UserDefaults.standard.bool(forKey: "OnePassUITestReset") else { return false }
        guard TestIsolation.isActive else {
            Logger(subsystem: "me.somalabs.onepass", category: "app")
                .error("UI test reset ignored without -OnePassTestIsolation")
            return false
        }
        TestIsolation.wipe()
        return true
    }
}
#endif
