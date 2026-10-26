import Foundation
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
    @ObservationIgnored let iconLoader: SiteIconLoader
    @ObservationIgnored private let remote: (any RemoteRecordStore)?

    /// Built with `ONEPASS_CLOUDKIT` (signed Release-CloudKit configuration, ruling R8).
    let cloudKitEnabled: Bool
    private(set) var syncStatus: SyncStatus = .disabled

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

    @ObservationIgnored private var tasks: [Task<Void, Never>] = []
    @ObservationIgnored private var started = false
    /// One automatic biometric attempt per app activation, whatever the number of windows.
    @ObservationIgnored private var autoBiometricsPending = true

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "app")

    init() {
        #if DEBUG
        DebugReset.applyIfRequested()
        #endif
        Self.sweepEmergencyKits()
        #if DEBUG
        let demo = DemoData.requested ? DemoData.environment() : nil
        #else
        let demo: VaultEnvironment? = nil
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
            let databaseURL = VaultEnvironment.defaultDatabaseURL()
            do {
                let store = try openSyncStore(dbPath: databaseURL.path)
                coordinator = SyncCoordinator(store: store, remote: remote)
            } catch {
                Self.log.error("sync store not opened, sync disabled")
            }
            // `live` uses the same `defaultDatabaseURL()` as the sync store.
            environment = VaultEnvironment.live(sync: coordinator ?? NoSync())
        }
        self.coordinator = coordinator
        self.remote = remote
        session = VaultSession(environment: environment)

        let settings = environment.settings
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        iconLoader = SiteIconLoader(
            cacheDirectory: caches.appendingPathComponent("OnePass/SiteIcons", isDirectory: true),
            enabled: { settings.siteIconsEnabled })
        onboardingInProgress = session.state == .noAccount
    }

    var settings: VaultSettings { session.environment.settings }

    /// Starts listening to the sync layer and runs a first round. Called once by the root view.
    func start() {
        guard !started else { return }
        started = true
        #if DEBUG
        if DemoData.requested {
            seedDemoData()
        } else {
            seedAccountIfRequested()
            openDebugItemIfRequested()
        }
        #endif
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
            if let coordinator { Task { await coordinator.syncNow() } }
        case .inactive:
            session.scenePhaseChanged(.inactive)
        case .background:
            session.scenePhaseChanged(.background)
            #if os(iOS)
            lockWhileBackgroundTimeLasts()
            #endif
        @unknown default:
            break
        }
    }

    #if os(iOS)
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
    /// Screenshots: `-OnePassDebugSeedAccount YES` creates a fictional account (Camille Durand) when
    /// none exists, then locks, so the lock screen can be captured. Debug builds only.
    private func seedAccountIfRequested() {
        guard UserDefaults.standard.bool(forKey: "OnePassDebugSeedAccount"), session.state == .noAccount
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

    /// "Réessayer" on "Données refusées": a complete fetch from scratch, then the store is read again.
    func retryAfterFailure() async {
        await coordinator?.refetchFromScratch()
        await session.reload()
        if case .failed = session.state { await session.refresh() }
    }

    /// Lock now, without asking. Explicit locks go through `perform(.lock)`.
    func lock() {
        resetNavigation()
        session.lock()
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

    // MARK: - Navigation guarded by the editor

    /// What would replace an editor with unsaved changes.
    enum GuardedAction: Equatable {
        case lock
        case select(ItemRef?)
        case newItem(FfiItemType)
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
/// `-OnePassUITestReset YES` (UI tests, Task 17): wipes the store, the settings and this app's
/// keychain items before anything is opened. Debug builds only.
enum DebugReset {
    static func applyIfRequested() {
        guard UserDefaults.standard.bool(forKey: "OnePassUITestReset") else { return }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.removeItem(at: base.appendingPathComponent("OnePass", isDirectory: true))
        if let domain = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: domain)
        }
        // Only the service VaultKit writes to, in both keychains (the legacy one is the Debug fallback).
        for legacy in [false, true] {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "me.somalabs.onepass",
            ]
            if !legacy { query[kSecUseDataProtectionKeychain as String] = true }
            SecItemDelete(query as CFDictionary)
        }
    }
}
#endif
