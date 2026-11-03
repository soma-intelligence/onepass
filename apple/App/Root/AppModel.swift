import Foundation
import GlanceKit
import ImageIO
import LocalAuthentication
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
    /// Every account of the device and their sessions (multi-account spec 6).
    let accounts: AccountSessions
    /// The session of the account shown. Process-wide services (widgets, watch, browser bridge, agents,
    /// phone approvals) stay on the primary account (ruling P7).
    var session: VaultSession { accounts.active }
    /// The primary account's session.
    var primarySession: VaultSession { accounts.primary }
    @ObservationIgnored let accountLink: AccountModelLink
    /// The account being added (its onboarding is on screen), nil otherwise.
    var addingAccount: AddingAccount? {
        didSet { if addingAccount == nil { signInAccountID = nil; signInNeedsAccountID = false } }
    }
    /// Signing in to an added account: the account id of its Emergency Kit (scanned from a version 2
    /// QR code, or typed from the printed kit), which names its iCloud zone (ruling P8).
    var signInAccountID: String?
    /// Several accounts of this iCloud are missing from this device: the restore step asks the id.
    var signInNeedsAccountID = false
    /// The sync listeners of the added accounts, by slot.
    @ObservationIgnored var accountTasks: [String: [Task<Void, Never>]] = [:]
    /// The iCloud coordinator, for an account that syncs with iCloud (nil on the mailbox).
    @ObservationIgnored let coordinator: SyncCoordinator?
    /// The mailbox coordinator, for an account on a OnePass server (cross-platform spec D.3).
    @ObservationIgnored private(set) var mailbox: MailboxSyncCoordinator?
    /// What the session's sync goes through: the current coordinator of either kind.
    @ObservationIgnored let router: SyncRouter?
    /// "Serveur OnePass", the host of a self-host, or "iCloud" (Réglages > Sync).
    private(set) var syncBackendName: String
    /// The sync store and its database, for the mailbox setup.
    @ObservationIgnored private let syncStore: SyncStoreHandle?
    @ObservationIgnored private let syncDatabaseURL: URL?
    /// The choice a new account's setup resumes with (`SyncBackendState.pendingSetup`).
    @ObservationIgnored private var pendingSetupChoice: SyncChoice?
    /// Widget snapshot (and, from Task 8, the watch payload) while unlocked.
    @ObservationIgnored let companion: CompanionCoordinator
    @ObservationIgnored let iconLoader: SiteIconLoader
    /// The SSH agent and the MCP server the Mac app serves (milestone 7), and their questions.
    let developer = DeveloperHosts()
    #if os(macOS)
    /// The browser extensions' bridge (Safari, Chrome, Firefox): signed builds with their App Group
    /// container only; never with demo data or a UI test store.
    let browserBridge: BrowserBridge?
    @ObservationIgnored private var approvalPanel: ApprovalPanelController?
    /// The iPhone that approves the agents' requests and unlocks for them (agent-ready spec 5 to 7),
    /// with the remote unlock coordinator (CloudKit builds only).
    let phoneApprovals: PhoneApprovals
    /// "Installer dans un agent": the bundled relay's `install` (spec 8).
    let agentInstaller: AgentInstaller
    #endif
    @ObservationIgnored private let remote: (any RemoteRecordStore)?
    #if os(iOS)
    /// The requests of the Mac's agents this iPhone answers (agent-ready spec 5 to 7). Its transport
    /// exists in the CloudKit build only; the Agents page says so otherwise.
    let phoneAgents: PhoneAgents?
    #endif

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
    #if DEBUG
    /// Demo data (`-OnePassDemoData`): its account is being made and filled. The root shows a
    /// plain progress screen meanwhile, never the onboarding (the creation takes seconds with the
    /// real Argon2id, minutes on a busy Mac).
    var demoPreparing = false
    #endif
    /// A guest session lent by another device (spec 2b 5.4): its own root, nothing on disk.
    var publicSession: PublicSession?

    // Navigation (filled by the browse screens).
    var selection: ItemFilter = .all {
        // Another filter ends a Watchtower list ("Voir les éléments").
        didSet { if selection != oldValue { watchtowerFilter = nil } }
    }
    /// "Voir les éléments" of a Watchtower card: the list shows only these items (within
    /// `selection`, set to `.all`). Cleared by any other filter, a reveal or a lock.
    var watchtowerFilter: WatchtowerListFilter?
    /// Watchtower report, computed off the main actor and kept until the data changes.
    let watchtower = WatchtowerModel()
    /// Watch-only crypto balances of this account (spec 2026-11-02-crypto-watch). Emptied on lock.
    let cryptoWatch = CryptoWatch()
    /// "Are you travelling?" (spec 2026-11-02): learned places and the suggestion card.
    let travel = TravelDetection()
    /// The Travel Mode sheet, opened by the suggestion card ("Oui", "Désactiver").
    var travelSheet: TravelSheetRequest?
    var selectedItem: ItemRef?
    var editing = false
    /// A new item's editor, shown in place of the detail until saved or cancelled.
    var newItemDraft: ItemDraft?
    /// What the main window shows right of the sidebar: the item list and detail, or a full page
    /// (Watchtower, Développeur). Choosing an item filter in the sidebar goes back to `.items`.
    var page: BrowsePage = .items
    /// Reported by the editor on screen: its draft has unsaved changes.
    var editorDirty = false
    /// An action that would drop a dirty draft, waiting for "Abandonner les modifications ?".
    var pendingDiscard: GuardedAction?
    /// iPhone and iPad: the settings sheet (the Mac has its own `Settings` window).
    var showSettings = false
    /// The settings page to show next time the settings open (Développeur page cards).
    var settingsPageRequest: SettingsPage?
    /// Bumped on every settings change made through `updateSettings`, so views that show a setting
    /// (stored in `UserDefaults`, not observable) redraw.
    private(set) var settingsRevision = 0
    /// ⌘N: the type picker of a new item.
    var showNewItemPicker = false
    /// ⌘⇧I (Fichier > Importer…): the import sheet.
    var showImport = false
    /// Account panel > Ajouter un compte: the sheet of a new account (multi-account spec 7).
    var showAddAccount = false
    /// Account panel > Rechercher dans tous les comptes (when the user chose the unified view).
    var showAllAccountsSearch = false
    /// Mac account menu > Configurer un appareil…: the invite the new device scans.
    var showDeviceSetup = false
    #if DEBUG
    /// `-OnePassDebugImport <path>`: the file the import sheet reads once it opens.
    var debugImportURL: URL?
    #endif
    /// Fichier > Restaurer une sauvegarde… (and Réglages > Général).
    var showRestore = false
    /// Fichier > Configurer un appareil… (Mac): the window that shows the pairing code.
    var showHostDevice = false
    // Menu commands handled by the views on screen (bumped, observed with `onChange`).
    var editRequest = 0
    var saveRequest = 0
    var searchFocusRequest = 0 {
        // ⌘F searches the items: a full page gives way to the list.
        didSet { page = .items }
    }
    /// Bumped after each remote change set is applied: an open item detail reloads (or warns its
    /// editor) on it.
    var remoteRevision = 0
    /// Short confirmation shown at the bottom of the browse screens ("Mis à la corbeille").
    private(set) var toast: Toast?
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
    /// The accounts of a verification code link, shown by the "Ajouter un code" sheet.
    var otpLinkRequest: OtpLinkRequest?
    /// The camera reading a verification code QR code (iPhone account menu).
    var showOtpScanner = false
    /// The waiting route was queued while locked, so the coming unlock is made for it (ruling W13).
    @ObservationIgnored private var pendingRouteFresh = false
    /// When the waiting route was queued (an abandoned copy request or code link expires).
    @ObservationIgnored private var pendingRouteAt = Date.distantPast
    /// Drops a waiting code link once expired, so its secret does not stay in memory while locked.
    @ObservationIgnored private var pendingRouteExpiry: Task<Void, Never>?
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
    /// "Utiliser Touch ID pour déverrouiller ?" after a password unlock (once per account and device).
    /// Replacing or dropping it wipes the password it holds.
    var biometricOffer: BiometricOffer? {
        didSet { if oldValue?.id != biometricOffer?.id { oldValue?.password.wipe() } }
    }

    private static let log = Logger(subsystem: "me.somalabs.onepass", category: "app")

    init() {
        // Resolved once per launch (the probe touches the disk): the same value serves the reset,
        // the migration, the sync store and the session.
        let resolved = SharedContainer.resolve()
        #if DEBUG
        let wasReset = DebugReset.applyIfRequested()
        // The AutoFill extension opens the isolated store while the last launch was isolated.
        if TestIsolation.isActive {
            UITestIsolation.markActive(container: resolved)
        } else {
            UITestIsolation.clearMarker(container: resolved)
        }
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
        var mailbox: MailboxSyncCoordinator?
        var router: SyncRouter?
        var syncBackendName = "iCloud"
        var syncStore: SyncStoreHandle?
        var syncDatabaseURL: URL?
        var pendingSetupChoice: SyncChoice?
        var storeSplit = false
        #if ONEPASS_CLOUDKIT
        let remote: (any RemoteRecordStore)? = demo == nil
            ? CloudKitRemote(containerIdentifier: Self.cloudKitContainer) : nil
        cloudKitEnabled = demo == nil
        #else
        let remote: (any RemoteRecordStore)? = nil
        cloudKitEnabled = false
        #endif
        var environment: VaultEnvironment
        if let demo {
            // Demonstration store (Debug): temporary database, no sync.
            environment = demo
        } else {
            // Before anything opens the store: the extension and the app share the moved database.
            // UI tests (Debug, `TestIsolation`) never move nor open the user's store.
            #if DEBUG
            let migrated = isolated ? resolved : Self.migrateToSharedContainer(resolved)
            #else
            let migrated = Self.migrateToSharedContainer(resolved)
            #endif
            if let container = migrated {
                #if DEBUG
                let databaseURL = isolated ? TestIsolation.databaseURL : container.databaseURL
                #else
                let databaseURL = container.databaseURL
                #endif
                var store: SyncStoreHandle?
                do {
                    store = try openSyncStore(dbPath: databaseURL.path)
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
                if let store {
                    let backend: SyncBackendState
                    do {
                        backend = try SyncBackendState.readNow(store: store)
                    } catch {
                        Self.log.error("sync backend unreadable, sync disabled")
                        backend = .pendingSetup(.default)
                    }
                    syncBackendName = backend.displayName(hosted: MailboxEndpoints.hosted())
                    switch backend {
                    case .iCloud:
                        let iCloud = SyncCoordinator(store: store, remote: isolated ? nil : remote)
                        coordinator = iCloud
                        router = SyncRouter(current: iCloud)
                    case .mailbox(let home):
                        mailbox = Self.openMailbox(
                            home: home, databaseURL: databaseURL, keychain: environment.keychain,
                            serverName: syncBackendName)
                        router = mailbox.map { SyncRouter(current: $0) }
                    case .pendingSetup(let choice):
                        // Nothing leaves the device until the setup, resumed by `start`, is done.
                        pendingSetupChoice = choice
                        router = SyncRouter(current: PendingSync())
                    }
                    syncStore = store
                    syncDatabaseURL = databaseURL
                    environment.sync = router ?? NoSync()
                }
            } else {
                // Split store: nothing is opened (no sync store), the session is refused below.
                storeSplit = true
                environment = VaultEnvironment.live(sync: NoSync(), container: resolved)
            }
        }
        self.coordinator = coordinator
        self.mailbox = mailbox
        self.router = router
        self.syncBackendName = syncBackendName
        self.syncStore = syncStore
        self.syncDatabaseURL = syncDatabaseURL
        self.pendingSetupChoice = pendingSetupChoice
        self.remote = remote
        let session = VaultSession(environment: environment)
        if storeSplit { session.refuseStore(.other(Self.storeSplitMessage)) }
        let accountLink = AccountModelLink()
        self.accountLink = accountLink
        accounts = AccountSessions(
            store: AccountDirectoryStore(folder: environment.databaseURL.deletingLastPathComponent()),
            primary: session, defaults: environment.settings.baseDefaults,
            makeEnvironment: Self.accountEnvironment(
                primary: environment, remote: storeSplit ? nil : remote,
                containerIdentifier: Self.cloudKitContainer, link: accountLink))
        #if os(iOS)
        #if ONEPASS_CLOUDKIT
        let remoteChannel: (any RemoteChannel)? = demo == nil && !isolated ? CloudKitRemoteChannel(containerIdentifier: Self.cloudKitContainer) : nil
        #else
        let remoteChannel: (any RemoteChannel)? = nil
        #endif
        phoneAgents = storeSplit ? nil : PhoneAgents(
            vault: session, channel: remoteChannel, sharedDefaults: UserDefaults(suiteName: AppGroup.identifier))
        #endif
        #if os(macOS)
        browserBridge =
            demo == nil && !isolated && !storeSplit && resolved.isShared
            ? BrowserBridge(session: session, container: resolved) : nil
        #if ONEPASS_CLOUDKIT
        let macChannel: (any RemoteChannel)? = demo == nil && !isolated && !storeSplit ? CloudKitRemoteChannel(containerIdentifier: Self.cloudKitContainer) : nil
        #else
        let macChannel: (any RemoteChannel)? = nil
        #endif
        let hosts = developer
        let vault = session
        let unlockCoordinator = macChannel.map { RemoteUnlockCoordinator(vault: vault, hosts: hosts, channel: $0) }
        phoneApprovals = PhoneApprovals(vault: vault, hosts: hosts, coordinator: unlockCoordinator)
        #if DEBUG
        // Demo data and UI tests never run the real relay against the real home.
        agentInstaller = demo != nil || isolated
            ? AgentInstaller(paths: developer.paths, home: URL(fileURLWithPath: "/Users/camille"), runner: DemoHelperRunner())
            : AgentInstaller(paths: developer.paths)
        #else
        agentInstaller = AgentInstaller(paths: developer.paths)
        #endif
        #endif
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
        #if DEBUG
        demoPreparing = demo != nil && session.state == .noAccount
        #endif
        accountLink.model = self
    }

    /// Read through the session's `profileRevision`: a view showing the name or photo redraws when
    /// the synced profile changes.
    var settings: VaultSettings {
        _ = session.profileRevision
        return session.environment.settings
    }

    /// The CloudKit container of this build: the `OnePassCloudKitContainer` Info.plist key
    /// (`ONEPASS_CLOUDKIT_CONTAINER`, `iCloud.me.somalabs.onepass` by default; a fork or a personal
    /// team signs with its own).
    nonisolated static var cloudKitContainer: String {
        let value = (Bundle.main.object(forInfoDictionaryKey: "OnePassCloudKitContainer") as? String)?
            .trimmingCharacters(in: .whitespaces) ?? ""
        return value.isEmpty || value.contains("$(") ? "iCloud.me.somalabs.onepass" : value
    }

    /// The milestone 2 store location (`Application Support/OnePass/vault.sqlite` of the app's own
    /// container) and settings (`UserDefaults.standard`).
    nonisolated static var legacyContainer: SharedContainer {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return SharedContainer(root: support, isShared: false, defaultsSuite: nil)
    }

    /// Moves the milestone 2 store and settings into the shared container (ruling A3). If the move
    /// fails, the migration has put back every file it moved (database, `-wal` and `-shm` together),
    /// and this launch keeps the legacy store and settings: the vault stays usable in the app. The
    /// AutoFill extension finds no shared store and never creates one (it shows "open OnePass"), so a
    /// later launch completes the move; an empty shared store left by an older extension is set aside.
    /// Nil when the files could not be put back either (store split between the two folders): no store
    /// is opened this launch, the session shows "Données refusées".
    private static func migrateToSharedContainer(_ container: SharedContainer) -> SharedContainer? {
        guard container.isShared else { return container }
        let legacy = legacyContainer
        do {
            try SharedContainerMigration.run(
                from: legacy.databaseURL, legacyDefaults: .standard, to: container)
            return container
        } catch SharedContainerMigrationError.rollbackFailed {
            // The legacy database lost its sidecars and the shared folder has no database: opening
            // either one would lose writes or invite a new account. Nothing is opened this launch.
            log.fault("shared container migration failed and could not be undone, no store opened")
            return nil
        } catch {
            log.error("shared container migration failed, legacy store kept for this launch")
            return legacy
        }
    }

    /// Shown on "Données refusées" when the store is split between the two folders.
    static var storeSplitMessage: String { String(localized:
        "Le déplacement du stockage vers le dossier partagé avec l'extension AutoFill a échoué et n'a pas pu être annulé. Aucune donnée n'est ouverte pour éviter toute perte. Quitte puis relance OnePass : le déplacement reprend au lancement suivant.") }

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
        // Captures (`-OnePassDemoPage watchtower|developer`): opens that page at launch.
        switch UserDefaults.standard.string(forKey: "OnePassDemoPage") {
        case "watchtower": page = .watchtower
        case "developer": page = .developer
        case "crypto": page = .crypto
        // Travel screenshots: Réglages > Travel Mode in its sheet.
        case "travel": travelSheet = .exit
        default: break
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
        #if os(iOS)
        // Nothing stays after a quit: the records that expired meanwhile are erased (spec 5.2).
        if let phoneAgents { tasks.append(Task { await phoneAgents.purgeExpired() }) }
        #endif
        #if os(macOS)
        // Before any device refresh, forget or gate use: reads the enrollment, erases the expired
        // records of a quit or a sleep, and holds the MCP socket of a locked, enrolled Mac.
        let phoneApprovals = self.phoneApprovals
        tasks.append(Task { await phoneApprovals.start() })
        if let browserBridge {
            browserBridge.start()
            // "Déverrouiller dans OnePass" from an extension: the app comes forward on its lock screen.
            tasks.append(Task { [weak self] in
                for await _ in NotificationCenter.default.notifications(named: BrowserBridge.unlockRequestedNotification) {
                    self?.showForUnlock()
                }
            })
        }
        #endif
        tasks.append(Task { [weak self] in await self?.refreshAutoFillStatus() })
        guard let router else { return }
        let coordinator = coordinator
        tasks.append(Task { [weak self] in
            for await _ in await router.remoteChanges() {
                await self?.primarySession.reload()
                self?.remoteRevision &+= 1
            }
        })
        tasks.append(Task { [weak self] in
            for await status in await router.statusUpdates() {
                self?.syncStatus = status
                if let coordinator { self?.ignoredDeletionCount = await coordinator.ignoredDeletionCount }
            }
        })
        tasks.append(Task { await router.syncNow() })
        if let mailbox { tasks.append(Task { await mailbox.enterForeground() }) }
    }

    /// New accounts may go to a mailbox (X1b Task 6). Off until the founder opens the hosted
    /// server: the build setting ONEPASS_MAILBOX_SIGNUP (Info.plist `OnePassMailboxSignup`).
    var mailboxSignupEnabled: Bool {
        (Bundle.main.object(forInfoDictionaryKey: "OnePassMailboxSignup") as? String) == "YES"
            && syncStore != nil
    }

    /// Before a new account is created with `choice`: a mailbox choice stops the iCloud sync at
    /// once, so the new vault never reaches iCloud.
    func prepareSync(for choice: SyncChoice) async {
        guard choice != .iCloud, let syncStore, let router else { return }
        try? await SyncBackendState.write(.pendingSetup(choice), store: syncStore)
        pendingSetupChoice = choice
        await router.switchTo(PendingSync())
        syncBackendName = SyncBackendState.pendingSetup(choice).displayName(hosted: MailboxEndpoints.hosted())
    }

    /// Where the account of `secretKey` lives (spec D.4): the kit's server, the OnePass server,
    /// then iCloud.
    func locateAccount(secretKey: SecretBytes, kitServer: URL?) async -> RestoreSource {
        let restore = MailboxRestore(
            provisioning: FfiMailboxProvisioning(databasePath: syncDatabaseURL?.path ?? ""),
            credentials: MailboxCredentialStore(keychain: session.environment.keychain))
        let cloudKit = cloudKitEnabled
        return await restore.locate(secretKey: secretKey, kitServer: kitServer) { @MainActor [weak self] in
            guard cloudKit, let self else { return false }
            return (try? await self.remoteHasAccount()) ?? false
        }
    }

    /// Restore an account kept on `home`: the iCloud sync stops first (the vault must not reach
    /// it), the mailbox is fetched, `unlock` runs, then the router switches to this device's client.
    func restoreFromMailbox(
        home: MailboxHome, secretKey: SecretBytes, unlock: @escaping @MainActor () async throws -> Void
    ) async throws {
        guard let syncStore, let syncDatabaseURL, let router else { throw OnePassError.Store }
        await router.switchTo(PendingSync())
        let restore = MailboxRestore(
            provisioning: FfiMailboxProvisioning(databasePath: syncDatabaseURL.path),
            credentials: MailboxCredentialStore(keychain: session.environment.keychain))
        let client = try await session.restoreMailbox(
            restore, home: home, secretKey: secretKey, store: syncStore, unlock: unlock)
        syncBackendName = SyncBackendState.mailbox(home).displayName(hosted: MailboxEndpoints.hosted())
        let coordinator = MailboxSyncCoordinator(sync: client, serverName: syncBackendName)
        mailbox = coordinator
        await router.switchTo(coordinator)
        await coordinator.enterForeground()
    }

    /// The migration of this iCloud account to a mailbox (spec D.5); nil for an account that is
    /// not on iCloud with a remote.
    func mailboxMigration() -> MailboxMigration? {
        guard let coordinator, let remote, let syncStore, let syncDatabaseURL, let router else { return nil }
        let keychain = session.environment.keychain
        let credentials = MailboxCredentialStore(keychain: keychain)
        let provisioning = FfiMailboxProvisioning(databasePath: syncDatabaseURL.path)
        let parts = MailboxMigration.Parts(
            setup: MailboxSetup(provisioning: provisioning, credentials: credentials, store: syncStore),
            provisioning: provisioning, credentials: credentials, remote: remote, cloudKit: coordinator,
            router: router,
            makeCoordinator: { sync, home in
                let name = SyncBackendState.mailbox(home).displayName(hosted: MailboxEndpoints.hosted())
                return MailboxSyncCoordinator(sync: sync, serverName: name)
            })
        return MailboxMigration(store: syncStore, parts: parts)
    }

    /// "Passer au serveur OnePass": the migration of this account, on its gesture.
    func migrateToMailbox(choice: SyncChoice) async -> MailboxMigration.Outcome {
        guard let migration = mailboxMigration() else { return .failed(String(localized: "settings.sync.migrate.unavailable")) }
        if let blocker = await session.migrationBlocker(migration, status: syncStatus) { return .blocked(blocker) }
        guard let accountID = settings.accountID,
              let key = try? SecretKeyVault(keychain: session.environment.keychain).loadBytes(accountID: accountID)
        else { return .blocked(.locked) }
        let outcome = await session.migrate(migration, choice: choice, secretKey: key)
        if case .done(let home) = outcome {
            syncBackendName = SyncBackendState.mailbox(home).displayName(hosted: MailboxEndpoints.hosted())
            await adoptRouterMailbox()
        }
        return outcome
    }

    /// The mailbox coordinator the router switched to, for the scene phases and the wake.
    /// The system gave an APNs token: an account on a mailbox registers it (once per token,
    /// X1b Task 10). An iCloud account needs nothing (CloudKit pushes on its own).
    func didRegisterPush(token: Data) {
        guard let mailbox, let syncStore else { return }
        let push = PushRegistration(sync: mailbox.client, store: syncStore)
        Task { await push.didRegister(token: token) }
    }

    /// A background push (CloudKit or the mailbox's silent wake): one round through the router,
    /// cut at the push budget.
    func silentPush() async -> Bool {
        guard let router, let syncStore, let mailbox else {
            if let coordinator { await coordinator.syncNow() }
            return coordinator != nil
        }
        let push = PushRegistration(sync: mailbox.client, store: syncStore)
        return await push.didReceiveSilent { await router.syncNow() }
    }

    private func adoptRouterMailbox() async {
        guard let router, let next = await router.coordinator as? MailboxSyncCoordinator else { return }
        mailbox = next
        await next.enterForeground()
    }

    /// At unlock: a migration cut after its claim finishes its upload.
    private func resumeMigration() {
        guard let migration = mailboxMigration() else { return }
        Task {
            if case .done(let home) = await session.resumeMigration(migration) {
                syncBackendName = SyncBackendState.mailbox(home).displayName(hosted: MailboxEndpoints.hosted())
                await adoptRouterMailbox()
            }
        }
    }

    /// A setup cut off (offline, app quit) resumes at the next unlock, with the Secret Key from
    /// this device's keychain.
    private func resumeMailboxSetup() {
        guard pendingSetupChoice != nil, let accountID = settings.accountID else { return }
        let vault = SecretKeyVault(keychain: session.environment.keychain)
        guard let key = try? vault.loadBytes(accountID: accountID) else { return }
        Task { await runMailboxSetup(secretKey: key) }
    }

    /// Run (or resume) the mailbox setup of the unlocked account. On success the router switches
    /// to the mailbox coordinator; offline, the account stays on this device and the next launch
    /// or unlock tries again.
    @discardableResult
    func runMailboxSetup(secretKey: SecretBytes) async -> MailboxSetupOutcome? {
        guard let choice = pendingSetupChoice, let syncStore, let syncDatabaseURL, let router else { return nil }
        let setup = MailboxSetup(
            provisioning: FfiMailboxProvisioning(databasePath: syncDatabaseURL.path),
            credentials: MailboxCredentialStore(keychain: session.environment.keychain), store: syncStore)
        guard let outcome = await session.runMailboxSetup(setup, choice: choice, secretKey: secretKey) else {
            return nil
        }
        if case .ready(let home) = outcome {
            pendingSetupChoice = nil
            syncBackendName = SyncBackendState.mailbox(home).displayName(hosted: MailboxEndpoints.hosted())
            if let opened = Self.openMailbox(
                home: home, databaseURL: syncDatabaseURL, keychain: session.environment.keychain,
                serverName: syncBackendName) {
                mailbox = opened
                await router.switchTo(opened)
                await opened.enterForeground()
            }
        }
        return outcome
    }

    /// The mailbox client of an account on a OnePass server, signed by this device's credential.
    /// Without its seed (Keychain restored elsewhere, item deleted) nothing syncs and the log says so.
    private static func openMailbox(
        home: MailboxHome, databaseURL: URL, keychain: any KeychainStore, serverName: String
    ) -> MailboxSyncCoordinator? {
        do {
            guard let seed = try MailboxCredentialStore(keychain: keychain).seed(mailboxID: home.mailboxID) else {
                log.error("mailbox credential missing, sync disabled")
                return nil
            }
            let sync = try seed.withData {
                try MailboxSync.open(
                    dbPath: databaseURL.path, endpoint: home.endpoint, mailboxId: home.mailboxID, credentialSeed: $0)
            }
            return MailboxSyncCoordinator(sync: FfiMailboxSyncAdapter(sync: sync), serverName: serverName)
        } catch {
            log.error("mailbox client not opened, sync disabled")
            return nil
        }
    }

    /// The app's aggregate scene phase (forwarded from `OnePassApp`), not a single window's.
    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            autoBiometricsPending = true
            accounts.scenePhaseChanged(.active)
            // A lock asked by a Control while the app was in the background or not notified.
            lockIfRequested()
            companion.sessionChanged()
            // An item saved by the AutoFill extension appears even if its store-changed notification
            // was lost (sent while the app was suspended).
            if session.state == .unlocked { Task { await session.reloadAfterExternalChange() } }
            if let mailbox {
                Task { await mailbox.enterForeground() }
            } else if let router {
                Task { await router.syncNow() }
            }
            // The provider may have been turned on or off in the system settings meanwhile.
            Task { await refreshAutoFillStatus() }
            #if os(macOS)
            // A browser installed or launched for the first time meanwhile gets its manifest.
            if let browserBridge, browserBridge.isRunning { browserBridge.refreshManifests() }
            #endif
            travel.appMovedToBackground(false)
            travel.check(travelling: session.state == .unlocked ? session.isTravelling : nil)
        case .inactive:
            accounts.scenePhaseChanged(.inactive)
        case .background:
            travel.appMovedToBackground(true)
            // A guest session never survives the app leaving the screen (ruling A7).
            publicSession?.end()
            dropPendingOtpLink()
            accounts.scenePhaseChanged(.background)
            if let mailbox { Task { await mailbox.enterBackground() } }
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
        guard accounts.anyUnlocked, backgroundLock == nil else { return }
        backgroundTaskID = UIApplication.shared.beginBackgroundTask(withName: "OnePass auto-lock") { [weak self] in
            MainActor.assumeIsolated { self?.endBackgroundLock() }
        }
        backgroundLock = Task { [weak self] in
            while let self, !Task.isCancelled, self.accounts.anyUnlocked,
                UIApplication.shared.applicationState == .background
            {
                self.accounts.checkAutoLock()
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
            // Travel screenshots (`-OnePassDebugTravelItems YES`): one login hidden in Travel Mode,
            // one behind extra protection, and the vault stays open.
            if UserDefaults.standard.bool(forKey: "OnePassDebugTravelItems") {
                await seedTravelItems()
                return
            }
            session.lock()
        }
    }

    private func seedTravelItems() async {
        guard let vault = session.allVaults.first else { return }
        for (title, user, hidden) in [("Banque", "camille@banque.example", true), ("Mail", "camille@mail.example", false)] {
            guard var item = try? session.newItem(type: .login, vaultID: vault.id) else { continue }
            item.title = title
            for s in item.sections.indices {
                for f in item.sections[s].fields.indices where item.sections[s].fields[f].id == "username" {
                    item.sections[s].fields[f].value = .text(value: user)
                }
            }
            item.travelHidden = hidden
            item.travelGuard = !hidden
            _ = try? await session.save(item)
        }
    }
    #endif

    /// True once per app activation: the lock screen of the first window that asks may try
    /// biometric unlock automatically.
    func takeAutomaticBiometricAttempt() -> Bool {
        defer { autoBiometricsPending = false }
        #if DEBUG
        // Captures of the demo lock screen: no system biometric sheet over it.
        if UserDefaults.standard.bool(forKey: "OnePassDemoNoAutoBiometrics") { return false }
        #endif
        return autoBiometricsPending
    }

    // MARK: - Biometric unlock

    /// Turns biometric unlock on: checks the master password and wraps the key with the Secure
    /// Enclave (`enrollBiometrics`), then asks for Touch ID, Face ID or the Watch once, so the
    /// user knows it works. A refused or cancelled check turns it back off. Already enrolled (the
    /// session enrolled again after the password unlock): nothing more is asked.
    func enableBiometrics(password: SecretBytes) async throws {
        if session.canUseBiometrics {
            settings.biometricsWanted = true
            settingsChanged()
            return
        }
        try await session.enrollBiometrics(password: password)
        guard await confirmBiometry() else {
            session.disableBiometrics()
            settingsChanged()
            throw VaultError.other(String(localized: "\(OnboardingModel.biometryName) n'a pas été confirmé : rien n'a été activé."))
        }
        settingsChanged()
    }

    /// One biometric check (no key involved). The demo answers like its simulated Secure Enclave.
    private func confirmBiometry() async -> Bool {
        let reason = String(localized: "Activer le déverrouillage avec \(OnboardingModel.biometryName)")
        #if DEBUG
        if DemoData.requested { return await DemoPresenceChecker().confirm(prompt: reason) }
        #endif
        let context = LAContext()
        var policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
        #if os(macOS)
        if settings.allowWatchUnlock { policy = .deviceOwnerAuthenticationWithBiometricsOrCompanion }
        #endif
        guard context.canEvaluatePolicy(policy, error: nil) else { return false }
        return (try? await context.evaluatePolicy(policy, localizedReason: reason)) ?? false
    }

    /// The first-unlock offer applies: personal device, biometrics possible here but not enrolled, and
    /// either the offer never answered for this account on this device, or biometric unlock was on
    /// and its enrollment is gone (keychain group change, new Face ID set): it is offered again.
    var biometricOfferDue: Bool {
        guard let accountID = settings.accountID, settings.deviceMode.biometricsAllowed,
            session.environment.biometrics.isAvailable, !session.canUseBiometrics
        else { return false }
        if settings.biometricsWanted { return true }
        return !Self.browseDefaults.bool(forKey: Self.biometricOfferKey(accountID))
    }

    /// Right after a password unlock: keeps the typed password, in a wipeable buffer the offer owns,
    /// until the offer is answered or the app locks (the onboarding keeps it the same way until its
    /// biometric step).
    func offerBiometrics(password: SecretBytes) {
        biometricOffer = BiometricOffer(password: password)
    }

    /// "Activer" or "Plus tard": either way the offer is not made again on this device.
    func answerBiometricOffer(accept: Bool) {
        guard let offer = biometricOffer else { return }
        guard accept else {
            biometricOffer = nil
            markBiometricOfferAnswered()
            return
        }
        // Enrolled meanwhile (the session's own enrollment after the unlock): nothing to ask.
        if session.canUseBiometrics {
            biometricOffer = nil
            markBiometricOfferAnswered()
            return
        }
        // Taken out of the offer first (dropping the offer wipes its buffer): wiped once enrolled.
        let password = offer.password.withUnsafeBytes { SecretBytes(copying: $0) }
        biometricOffer = nil
        markBiometricOfferAnswered()
        Task {
            defer { password.wipe() }
            do {
                try await enableBiometrics(password: password)
                showToast(String(localized: "\(OnboardingModel.biometryName) activé"))
            } catch {
                showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    /// The onboarding's biometric step counts as the offer.
    func markBiometricOfferAnswered() {
        guard let accountID = settings.accountID else { return }
        Self.browseDefaults.set(true, forKey: Self.biometricOfferKey(accountID))
    }

    private static func biometricOfferKey(_ accountID: String) -> String {
        "onepass.biometricOfferAnswered.\(accountID)"
    }

    /// CloudKit build: whether an iCloud account is signed in. Unsigned build: true (local only).
    func iCloudAccountAvailable() async -> Bool {
        guard cloudKitEnabled, let remote else { return true }
        return await remote.accountAvailable()
    }

    /// Emergency Kit PDFs and encrypted backups left in the temporary folder by a previous run
    /// (killed while the share sheet was open).
    private static func sweepEmergencyKits() {
        EmergencyKitFile.sweep(in: FileManager.default.temporaryDirectory)
        EncryptedBackupFile.sweep(in: FileManager.default.temporaryDirectory)
        PlaintextExportFile.sweep(in: FileManager.default.temporaryDirectory)
    }

    /// Spec 7: the creation is refused when this iCloud already holds an account (ruling R13).
    /// No CloudKit: always false.
    func remoteHasAccount() async throws -> Bool {
        guard cloudKitEnabled, let coordinator = try await activeCoordinator(forSignIn: true) else { return false }
        let found = try await coordinator.remoteHasAccount()
        await session.reload()
        return found
    }

    /// "Créer un nouveau coffre" on the Emergency Kit screen of a device without its Secret Key:
    /// offered only when iCloud holds no account (always without sync).
    func newVaultOffer() async -> NewVaultOffer {
        guard cloudKitEnabled, let coordinator = try? await activeCoordinator() else { return .offered }
        let offer = await coordinator.newVaultOffer()
        await session.reload()
        return offer
    }

    /// "Réessayer" on "Données refusées": a complete fetch from scratch, then the store is read again.
    func retryAfterFailure() async {
        await (try? activeCoordinator())?.refetchFromScratch()
        await session.reload()
        if case .failed = session.state { await session.refresh() }
    }

    // MARK: - Safe exits (spec 3.3)

    /// "Exporter une sauvegarde chiffrée": the archive bytes (the caller saves them through the
    /// warning-first save flow). Both buffers are wiped here.
    func exportEncryptedBackup(password: SecretBytes, passphrase: SecretBytes) async throws -> Data {
        defer {
            password.wipe()
            passphrase.wipe()
        }
        return try await session.exportEncryptedBackup(password: password, passphrase: passphrase)
    }

    /// "Garder la version de cet appareil" or "Prendre la version d'iCloud", master password checked.
    /// The coordinator follows the epoch: `syncStatus` stays `.waitingForServer` until every vault is
    /// `Ok` (`safeExitSettled`). The buffer is wiped here.
    func runSafeExit(_ exit: SafeExit, password: SecretBytes) async throws {
        defer { password.wipe() }
        try await session.runSafeExit(exit, password: password)
    }

    /// The safe exit converged: the coordinator reports idle (every vault `Ok`), never before.
    var safeExitSettled: Bool {
        if case .idle = syncStatus { return true }
        return !cloudKitEnabled && session.state == .unlocked
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
        dropPendingOtpLink()
        session.lock()
    }

    /// Locks when a "Verrouiller OnePass" request is newer than the last unlock, this launch and
    /// any request already seen while locked. iOS only (the Controls exist only there).
    func lockIfRequested() {
        #if os(iOS)
        let request = lockSignal.lastRequest
        guard accounts.anyUnlocked else {
            // Nothing to lock: this request is spent, the next unlock must not undo itself.
            if let request { spentLockRequest = max(spentLockRequest ?? request, request) }
            return
        }
        let baseline = [lastUnlockAt, spentLockRequest].compactMap { $0 }.max()
        guard LockSignal.shouldLock(request: request, unlockedAt: baseline, launchedAt: launchedAt) else { return }
        Self.log.info("lock requested from a Control")
        lockAll()
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
            // The account of a store is bound to its slot once known (M4, M5).
            accounts.bindIfNeeded(accounts.activeSlot)
            consumePendingRoute()
            // "Me prévenir": a report after each unlock, so new findings are notified even when the
            // Watchtower page stays closed. Off: Watchtower runs only when its page is shown.
            if watchtower.notify { watchtower.refreshIfNeeded(session) }
            // Every item's site icon, in the background: lists never show a placeholder first.
            let urls = session.summaries.compactMap(\.primaryUrl)
            Task(priority: .utility) { [iconLoader] in await iconLoader.prefetch(urls) }
            resumeMailboxSetup()
            resumeMigration()
        } else {
            resetNavigation()
        }
        companion.sessionChanged()
    }

    /// The primary account's state changed (root view): the services bound to it (ruling P7) follow,
    /// whichever account is shown.
    func primaryStateChanged(_ state: VaultSession.State) {
        companion.sessionChanged()
        #if os(iOS)
        // The phone reads its agent requests only while the vault is open.
        if let phoneAgents { Task { await phoneAgents.sessionChanged() } }
        #endif
        #if os(macOS)
        if approvalPanel == nil { approvalPanel = ApprovalPanelController(hosts: developer) }
        if state == .unlocked {
            let primary = primarySession
            Task {
                await developer.sessionUnlocked(primary)
                // The panel races the iPhone again (the approver goes on every lock).
                await phoneApprovals.sessionUnlocked()
            }
        } else {
            developer.sessionLocked()
        }
        #endif
    }

    // MARK: - Routes from outside the app

    #if os(macOS)
    /// Bumped to show the main window (reopened if it was closed): the menu bar label observes it,
    /// being the one view that lives while no window is open.
    var mainWindowRequest = 0

    /// "Déverrouiller dans OnePass" (`onepass://unlock` or the bridge's request): the main window
    /// comes forward on the lock screen, which then asks for biometrics once. The activation alone
    /// is not enough since macOS 14 while the browser is in front; the link, opened through
    /// LaunchServices by the extension's process, is what brings the app forward.
    func showForUnlock() {
        if session.state != .unlocked { autoBiometricsPending = true }
        mainWindowRequest &+= 1
        NSApplication.shared.activate()
    }
    #endif

    /// A deep link (`onepass://`), from a widget, a Control or the system.
    func open(_ link: OnePassLink) {
        // Widgets and Controls show the primary account's items (ruling P7).
        if case .item = link, accounts.activeSlot != AccountDirectoryStore.primarySlot {
            switchAccount(to: AccountDirectoryStore.primarySlot)
        }
        handle(.link(link))
    }

    /// Runs the route now when unlocked, else keeps it for after the unlock (the newest wins).
    func handle(_ route: AppRoute) {
        guard session.state == .unlocked, !onboardingInProgress else {
            pendingRoute = route
            pendingRouteFresh = IntentAuthentication.isFreshUnlockRequest(
                state: session.state, onboarding: onboardingInProgress)
            pendingRouteAt = .now
            pendingRouteExpiry?.cancel()
            pendingRouteExpiry = nil
            if case .otpLink = route {
                pendingRouteExpiry = Task { [weak self] in
                    try? await Task.sleep(for: .seconds(PendingRequest.lifetime + 1))
                    guard !Task.isCancelled else { return }
                    self?.dropPendingOtpLink()
                }
            }
            return
        }
        run(route, freshUnlock: false)
    }

    /// A verification code link waiting for the unlock holds its secret: dropped when the app
    /// locks or leaves the screen, and once expired.
    func dropPendingOtpLink() {
        guard case .otpLink = pendingRoute else { return }
        pendingRoute = nil
        pendingRouteExpiry?.cancel()
        pendingRouteExpiry = nil
    }

    /// After an unlock: the waiting route, if any.
    func consumePendingRoute() {
        guard session.state == .unlocked, !onboardingInProgress, let route = pendingRoute else { return }
        pendingRoute = nil
        pendingRouteExpiry?.cancel()
        pendingRouteExpiry = nil
        // A copy request or code link left waiting more than 2 minutes was abandoned.
        if PendingRequest.isExpired(queuedAt: pendingRouteAt, now: .now) {
            switch route {
            case .copyTotp:
                showToast(String(localized: "Demande de copie expirée"), kind: .error)
                return
            case .otpLink:
                showToast(String(localized: "Lien de code de vérification expiré. Ouvre-le de nouveau."), kind: .error)
                return
            case .link:
                break
            }
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
                showToast(String(localized: "Élément introuvable"), kind: .error)
                return
            }
            perform(.reveal(ref))
        case .link(.generator):
            showSettings = false
            showGenerator = true
        case .link(.search):
            showSettings = false
            page = .items
            browseReveal = .search
            searchFocusRequest &+= 1
        case .copyTotp(let ref):
            Task { await copyTotp(ref, freshUnlock: freshUnlock) }
        case .otpLink(let link):
            Task { await presentOtpLink(link, source: .link) }
        }
    }

    /// The "Ajouter un code" sheet for a verification code link, or a message when the link is not
    /// one the core reads (HOTP, malformed). The sheets the model owns close first, the master
    /// password prompt of a code copy included; a new item being written keeps the link out (a
    /// message says so).
    func presentOtpLink(_ link: String, source: OtpLinkRequest.Source) async {
        let accounts: [OtpLinkAccount]
        do {
            accounts = try OtpLink.accounts(in: link)
        } catch {
            showToast(String(localized: "Ce lien de code de vérification n'est pas pris en charge."), kind: .error)
            return
        }
        guard newItemDraft == nil, !editing else {
            showToast(String(localized: "Termine l'élément en cours pour ajouter le code."), kind: .error)
            return
        }
        let covered = showSettings || showGenerator || showNewItemPicker || showImport || showOtpScanner
            || otpLinkRequest != nil || totpPasswordRequest != nil
        totpPasswordRequest = nil
        showOtpScanner = false
        showSettings = false
        showGenerator = false
        showNewItemPicker = false
        showImport = false
        otpLinkRequest = nil
        if covered {
            try? await Task.sleep(for: .milliseconds(700))
        } else {
            await Task.yield()
        }
        guard session.state == .unlocked else { return }
        otpLinkRequest = OtpLinkRequest(accounts: accounts, source: source)
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
            showToast(String(localized: "Ouvre OnePass pour copier le code"), kind: .error)
        }
    }

    /// Copies the item's current one-time code with the OnePass clipboard (90 s, local only).
    func copyTotpCode(_ ref: ItemRef) async {
        guard session.state == .unlocked else { return }
        let noCode = String(localized: "Cet élément n'a pas de code à usage unique")
        guard !session.hiddenVaultIDs.contains(ref.vaultID) else {
            showToast(noCode, kind: .error)
            return
        }
        let item: FfiItem
        do {
            item = try await session.loadItem(vaultID: ref.vaultID, itemID: ref.itemID)
        } catch {
            Self.log.error("one-time code: item not loaded")
            showToast(noCode, kind: .error)
            return
        }
        guard item.trashedAt == nil, let secret = firstOtpValue(of: item) else {
            showToast(noCode, kind: .error)
            return
        }
        // Travel Mode: an item behind extra protection is read in its detail only, after the
        // password and Face ID (spec 2026-11-02).
        guard !(item.travelGuard && session.isTravelling) else {
            showToast(String(localized: "Protégé en voyage : ouvre l'élément pour le lire."), kind: .error)
            return
        }
        let totp: FfiTotpCode
        do {
            totp = try totpNow(secretOrUri: secret, unixSeconds: UInt64(Date.now.timeIntervalSince1970))
        } catch {
            Self.log.error("one-time code: secret refused by the core")
            showToast(noCode, kind: .error)
            return
        }
        session.copy(totp.code, concealed: true)
        showToast(String(localized: "Code copié"))
    }

    /// Drops every item-bearing navigation state (the new item's draft holds typed values).
    /// Also run when the session leaves `unlocked` on its own (auto-lock, background, failure).
    func resetNavigation() {
        selectedItem = nil
        watchtowerFilter = nil
        watchtower.clear()
        cryptoWatch.clear()
        editing = false
        newItemDraft = nil
        editorDirty = false
        pendingDiscard = nil
        showNewItemPicker = false
        showImport = false
        showDeviceSetup = false
        showRestore = false
        showHostDevice = false
        // The offer holds the typed password: never kept past a lock.
        biometricOffer = nil
        showSettings = false
        showGenerator = false
        browseReveal = nil
        totpPasswordRequest = nil
        // The accounts hold their secrets: never kept past a lock (a link still waiting for the
        // unlock is dropped by `dropPendingOtpLink`).
        otpLinkRequest = nil
        showOtpScanner = false
    }

    /// Changes a local setting and restarts the auto-lock clock (a new delay applies from now).
    func updateSettings(_ change: (VaultSettings) -> Void) {
        change(settings)
        settingsChanged()
    }

    /// Changes the account profile on every device (`VaultSession.setProfile`), shown here at once.
    func setProfile(name: String, photo: Data?) {
        session.setProfile(name: name, photo: photo)
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
        // The system prompt does not always show (already asked within 10 s, or macOS keeps the
        // choice in System Settings): when the provider is still off, open that page instead of
        // leaving the button without effect.
        let enabled = await AutoFillStatus.requestActivation()
        if !enabled, !(await AutoFillStatus.isEnabled()) {
            await AutoFillStatus.openProviderSettings()
        }
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
        /// Every account of the device (multi-account spec M3).
        case lockAll
        /// Shows another account of the device.
        case switchAccount(String)
        /// A result of the "All accounts" search: its account, then the item.
        case revealInAccount(String, ItemRef)
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
        case .lockAll:
            lockAll()
        case .switchAccount(let slot):
            switchAccount(to: slot)
        case .revealInAccount(let slot, let ref):
            switchAccount(to: slot)
            if session.state == .unlocked { apply(.reveal(ref)) } else { pendingRoute = .link(.item(vaultID: ref.vaultID, itemID: ref.itemID)) }
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
            page = .items
            watchtowerFilter = nil
            browseReveal = .item(ref)
            selectedItem = ref
        }
    }

    /// The items of a sidebar filter, list and detail on screen (sidebar rows, Développeur's
    /// "Voir mes clés SSH").
    func showItems(_ filter: ItemFilter) {
        selection = filter
        watchtowerFilter = nil
        page = .items
    }

    /// "Voir les éléments" of a Watchtower card: every item of the visible vaults that the check
    /// flagged, in the full list.
    func showWatchtowerItems(title: String, itemIDs: Set<String>) {
        selection = .all
        watchtowerFilter = WatchtowerListFilter(title: title, itemIDs: itemIDs)
        page = .items
        if let ref = selectedItem, !itemIDs.contains(ref.itemID) { perform(.select(nil)) }
    }

    /// The list's rows, narrowed to the Watchtower items when a card asked for them.
    func applyWatchtowerFilter(_ items: [FfiItemSummary]) -> [FfiItemSummary] {
        guard let filter = watchtowerFilter else { return items }
        return items.filter { filter.itemIDs.contains($0.id) }
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
        page = .items
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
                showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    /// Archive (swipe on an iPhone list): out of the lists and the suggestions, kept in Archive. A
    /// toast says it happened; the Archive list brings it back.
    func archive(_ ref: ItemRef) {
        setArchived(true, ref)
    }

    func unarchive(_ ref: ItemRef) {
        setArchived(false, ref)
    }

    private func setArchived(_ archived: Bool, _ ref: ItemRef) {
        let title = session.summaries.first { $0.id == ref.itemID }?.title ?? ""
        Task {
            do {
                if archived {
                    try await session.archive(itemID: ref.itemID, vaultID: ref.vaultID)
                    showToast(String(localized: "« \(title) » archivé"))
                } else {
                    try await session.unarchive(itemID: ref.itemID, vaultID: ref.vaultID)
                    showToast(String(localized: "« \(title) » désarchivé"))
                }
            } catch {
                showToast(VaultError(error).localizedMessage, kind: .error)
            }
        }
    }

    /// Short notification at the bottom of the window: green check for a success, red for a
    /// failure (shown longer, it has to be read), neutral for information.
    func showToast(_ text: String, kind: ToastKind = .success) {
        let shown = Toast(text: text, kind: kind)
        toast = shown
        Task {
            try? await Task.sleep(for: .seconds(kind == .error ? 4 : 2))
            if toast == shown { toast = nil }
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

    @ObservationIgnored private var photoCache: (data: Data, image: Image)?

    /// The account photo, decoded once per change of the stored JPEG.
    var profileImage: Image? {
        _ = settingsRevision
        guard let data = settings.profilePhoto else { return nil }
        if let photoCache, photoCache.data == data { return photoCache.image }
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
            let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil)
        else { return nil }
        let image = Image(decorative: cgImage, scale: 1)
        photoCache = (data, image)
        return image
    }

    /// Initials for the account badge ("Camille Durand" gives "CD"), empty without a name.
    var initials: String {
        let words = settings.displayName.split(whereSeparator: { $0.isWhitespace || $0 == "-" })
        return words.prefix(2).compactMap { $0.first.map { String($0).uppercased() } }.joined()
    }
}

#if DEBUG
/// `-OnePassTestIsolation YES` (UI tests, screenshot runs and the Debug item helpers, Debug builds only): the app uses a store
/// in `OnePassUITest` (in the App Group container when there is one, so the AutoFill extension can
/// follow, else in `<tmp>`), the `me.somalabs.onepass.uitest` defaults suite and the
/// `me.somalabs.onepass.uitest` keychain service, never the user's store, settings or Secret Keys.
/// No sync, no widget or watch data, nothing in the system identity store (`UITestIsolation`).
enum TestIsolation {
    static let keychainService = UITestIsolation.keychainService
    static let suiteName = UITestIsolation.suiteName

    /// Also forced by the Debug helpers that create or unlock a fictional account
    /// (`-OnePassDebugItem`, `-OnePassDebugNewItem`, `-OnePassDebugImport`, `-OnePassDebugSeedAccount`): they never touch
    /// the user's store.
    static var isActive: Bool {
        let defaults = UserDefaults.standard
        return defaults.bool(forKey: "OnePassTestIsolation") || defaults.bool(forKey: "OnePassDebugSeedAccount")
            || defaults.string(forKey: "OnePassDebugItem") != nil
            || defaults.string(forKey: "OnePassDebugNewItem") != nil
            || defaults.string(forKey: "OnePassDebugImport") != nil
    }

    static var folder: URL { UITestIsolation.folder(container: .resolve()) }

    static var databaseURL: URL { UITestIsolation.databaseURL(container: .resolve()) }

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

/// The first-unlock biometric offer, with the password just typed (needed to wrap the key), in a
/// wipeable buffer (`AppModel.biometricOffer` wipes it when the offer goes away).
struct BiometricOffer: Identifiable {
    let id = UUID()
    let password: SecretBytes
}

/// The full pages of the main window besides the items (sidebar rows above the vaults).
enum BrowsePage: Hashable {
    case items, watchtower, crypto, developer
}

/// The items a Watchtower card shows in the list, under the card's title.
struct WatchtowerListFilter: Equatable {
    var title: String
    var itemIDs: Set<String>
}

extension AppModel {
    /// Opens the account's encrypted watch file and reads the wallets' public data from the core.
    /// No network: a refresh is the Crypto screen's to ask for.
    func prepareCryptoWatch() async {
        guard session.state == .unlocked, let store = session.cryptoWatchStore else { return }
        cryptoWatch.open(store: store)
        #if DEBUG
        DemoCrypto.installIfRequested(cryptoWatch)
        #endif
        await cryptoWatch.loadTargets(from: session)
    }
}

/// Why the Travel Mode sheet opens from the suggestion card.
enum TravelSheetRequest: String, Identifiable {
    /// "Oui": straight to the confirmation.
    case enter
    /// "De retour ?": the page, with "Désactiver".
    case exit
    var id: String { rawValue }
}
