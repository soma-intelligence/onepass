package me.somalabs.onepass.vault

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.util.concurrent.Executors
import me.somalabs.onepass.core.FfiDeviceKind
import me.somalabs.onepass.core.FfiDeviceMode
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.MailboxSync
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.mailboxServerCheck
import me.somalabs.onepass.core.openSyncStore
import me.somalabs.onepass.core.restoreFromKit
import me.somalabs.onepass.vaultkit.sync.MailboxCredentialStore
import me.somalabs.onepass.vaultkit.sync.MailboxEndpoints
import me.somalabs.onepass.vaultkit.sync.MailboxHome
import me.somalabs.onepass.vaultkit.sync.MailboxRestore
import me.somalabs.onepass.vaultkit.sync.MailboxSetup
import me.somalabs.onepass.vaultkit.sync.MailboxSetupOutcome
import me.somalabs.onepass.vaultkit.sync.MailboxSyncCoordinator
import me.somalabs.onepass.vaultkit.sync.RestoreSource
import me.somalabs.onepass.vaultkit.sync.SyncBackendState
import me.somalabs.onepass.vaultkit.sync.SyncChoice
import me.somalabs.onepass.vaultkit.sync.SyncStatus
import me.somalabs.onepass.core.FfiZoneSeedStore
import me.somalabs.onepass.core.ZoneSyncHandle
import me.somalabs.onepass.vaultkit.sharing.FfiZoneSync
import me.somalabs.onepass.vaultkit.sharing.ZoneRounds

/**
 * The sync of this device's account, for the whole process (the app, the
 * AutoFill service and the periodic job share it): where the account syncs
 * (store meta `sync.backend`), the mailbox coordinator when it syncs, the
 * setup of a new mailbox, the restore from the Emergency Kit. Listeners are
 * called on the main thread.
 *
 * Nothing secret is logged: only that a step failed.
 */
class SyncManager private constructor(context: Context) {
    private val app = context.applicationContext
    val vault = DeviceVault.get(app)
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "onepass-sync-manager").apply { isDaemon = true } }

    /** Mailbox credential seeds, each sealed by the device's Keystore key (`mailbox-<id>.bin`). */
    val credentials = object : MailboxCredentialStore {
        override fun seed(mailboxId: String) = vault.unsealFile(fileOf(mailboxId))
        override fun store(seed: ByteArray, mailboxId: String) = vault.sealFile(fileOf(mailboxId), seed)
        override fun delete(mailboxId: String) = vault.deleteFile(fileOf(mailboxId))
        private fun fileOf(id: String) = "mailbox-" + id.filter { it.isLetterOrDigit() } + ".bin"
    }

    /** Zone credential seeds (shared vaults, contacts, family), each sealed like the mailbox seeds (`zone-<id>.bin`). */
    private val zoneSeeds = object : FfiZoneSeedStore {
        override fun get(mailboxId: ByteArray): ByteArray? = runCatching { vault.unsealFile(fileOf(mailboxId)) }.getOrNull()
        override fun put(mailboxId: ByteArray, seed: ByteArray) {
            runCatching { vault.sealFile(fileOf(mailboxId), seed) }.onFailure { Log.e(TAG, "zone seed not kept") }
        }
        override fun delete(mailboxId: ByteArray) = vault.deleteFile(fileOf(mailboxId))
        private fun fileOf(id: ByteArray) = "zone-" + id.joinToString("") { "%02x".format(it) } + ".bin"
    }

    /**
     * The zone rounds of the account (iOS `ZoneRoundScheduler`): after each
     * private round of a mailbox account, on their own for an account kept on
     * this device. Made by [start].
     */
    @Volatile var zones: ZoneRounds? = null
        private set
    @Volatile var zoneHandle: ZoneSyncHandle? = null
        private set
    private val zoneListeners = mutableListOf<() -> Unit>()

    /** A zone round changed the store (invitations, shared vault items, family). Main thread. */
    fun onZoneChange(l: () -> Unit) = synchronized(this) { zoneListeners += l }

    @Volatile var backend: SyncBackendState = SyncBackendState.Local
        private set
    @Volatile var coordinator: MailboxSyncCoordinator? = null
        private set
    @Volatile var status: SyncStatus = SyncStatus.Disabled
        private set
    /** The last setup that could not finish (offline, refused), for the settings line. */
    @Volatile var setupError: MailboxSetupOutcome? = null
        private set

    private val statusListeners = mutableListOf<(SyncStatus) -> Unit>()
    private val changeListeners = mutableListOf<() -> Unit>()
    private var foreground = false
    private var started = false

    fun onStatus(l: (SyncStatus) -> Unit) = synchronized(this) { statusListeners += l }
    fun removeStatus(l: (SyncStatus) -> Unit) = synchronized(this) { statusListeners -= l }
    /** Remote changes arrived: the lists reload. */
    fun onRemoteChange(l: () -> Unit) = synchronized(this) { changeListeners += l }

    /** Reads the backend once and opens the coordinator of a mailbox account. Idempotent. */
    fun start() {
        synchronized(this) {
            if (started) return
            started = true
        }
        vault.onSession { s -> if (s != null) unlocked(s) else { coordinator?.sessionLocked(); zones?.sessionLocked() } }
        worker.execute {
            startZones()
            load()
            vault.session?.let { unlocked(it) }
        }
    }

    @Synchronized
    private fun startZones() {
        if (zones != null) return
        val store = runCatching { openSyncStore(vault.dbPath) }.getOrElse {
            Log.e(TAG, "zone store not opened")
            return
        }
        val handle = ZoneSyncHandle(zoneSeeds, MailboxEndpoints.HOSTED, null)
        val z = ZoneRounds(FfiZoneSync(handle, store))
        z.onRemoteChange { main.post { synchronized(this) { zoneListeners.toList() }.forEach { it() } } }
        zoneHandle = handle
        zones = z
        if (foreground) z.enterForeground()
    }

    /** New zones are made under the account's own mailbox, with this device's credential. */
    private fun zonesUnder(home: MailboxHome) {
        val handle = zoneHandle ?: return
        val seed = runCatching { credentials.seed(home.mailboxId) }.getOrNull() ?: return
        try {
            handle.setAccountMailbox(home.endpoint, home.mailboxId, seed)
        } catch (_: Exception) {
            Log.w(TAG, "zones not put under the account mailbox")
        } finally {
            seed.fill(0)
        }
    }

    private fun load() {
        val state = runCatching { openSyncStore(vault.dbPath).use { SyncBackendState.read(it) } }.getOrDefault(SyncBackendState.Local)
        backend = state
        if (state is SyncBackendState.Mailbox && coordinator == null) open(state.home, null)
        if (state !is SyncBackendState.Mailbox) setStatus(SyncStatus.Disabled)
    }

    /** The coordinator of `home`, with this device's credential; without its seed nothing syncs. */
    private fun open(home: MailboxHome, client: MailboxSync?) {
        val sync = client ?: run {
            val seed = runCatching { credentials.seed(home.mailboxId) }.getOrNull()
            if (seed == null) {
                Log.e(TAG, "mailbox credential missing, sync disabled")
                return
            }
            try {
                MailboxSync.open(vault.dbPath, home.endpoint, home.mailboxId, seed)
            } catch (_: Exception) {
                Log.e(TAG, "mailbox client not opened, sync disabled")
                return
            } finally {
                seed.fill(0)
            }
        }
        zonesUnder(home)
        val c = MailboxSyncCoordinator(sync, home, serverName(home.baseUrl), zones = zones)
        c.onStatus { s -> setStatus(s) }
        c.onRemoteChange { main.post { synchronized(this) { changeListeners.toList() }.forEach { it() } } }
        coordinator?.close()
        coordinator = c
        setStatus(c.status)
        vault.session?.let { c.sessionUnlocked(it) }
        if (foreground) c.enterForeground() else c.kick()
    }

    private fun unlocked(s: Session) {
        zones?.sessionUnlocked(s)
        coordinator?.sessionUnlocked(s)
        // An account kept on this device has no private round: its zones run on their own.
        if (coordinator == null) zones?.kick()
        // A setup cut off (offline, app closed) resumes at the next unlock.
        val b = backend
        if (b is SyncBackendState.PendingSetup) worker.execute { runSetup(s, b.choice) }
    }

    // ---- triggers --------------------------------------------------------------------

    fun localChange() {
        coordinator?.localChangesWritten() ?: zones?.kickSoon()
    }

    fun enterForeground() {
        foreground = true
        coordinator?.enterForeground()
        zones?.enterForeground()
    }

    fun enterBackground() {
        foreground = false
        coordinator?.enterBackground()
        zones?.enterBackground()
    }

    /** "Synchroniser maintenant": a round, then `done` on the main thread. */
    fun syncNow(done: () -> Unit) {
        worker.execute {
            coordinator?.syncNow() ?: zones?.syncNow()
            main.post(done)
        }
    }

    /** Blocking, for the periodic job: one round with whatever session is open (none: locked round). */
    fun roundForJob() {
        if (!started) start()
        val until = System.currentTimeMillis() + 10_000
        while (backend is SyncBackendState.Local && coordinator == null && System.currentTimeMillis() < until) {
            if (runCatching { openSyncStore(vault.dbPath).use { SyncBackendState.read(it) } }.getOrNull() !is SyncBackendState.Mailbox) break
            Thread.sleep(100)
        }
        coordinator?.syncNow(60_000) ?: run { startZones(); zones?.syncNow(60_000) }
    }

    // ---- setup -----------------------------------------------------------------------

    /**
     * "Activer la synchronisation" for an account on this device, or the
     * choice made when it was created: puts it on the mailbox of `choice`.
     * `done` on the main thread with the outcome.
     */
    fun enable(choice: SyncChoice, done: (MailboxSetupOutcome) -> Unit) {
        val s = vault.session ?: return done(MailboxSetupOutcome.Failed(IllegalStateException("locked")))
        worker.execute {
            val outcome = runSetup(s, choice)
            main.post { done(outcome) }
        }
    }

    private fun runSetup(s: Session, choice: SyncChoice): MailboxSetupOutcome {
        // Two triggers (an unlock and "Réessayer") never make two mailboxes: a finished setup stays.
        val current = runCatching { openSyncStore(vault.dbPath).use { SyncBackendState.read(it) } }.getOrNull()
        if (current is SyncBackendState.Mailbox) {
            backend = current
            if (coordinator == null) open(current.home, null)
            return MailboxSetupOutcome.Ready(current.home)
        }
        val outcome = try {
            val key = vault.secretKey()
            openSyncStore(vault.dbPath).use { store -> MailboxSetup(vault.dbPath, credentials, store).run(s, choice, key) }
        } catch (e: Exception) {
            MailboxSetupOutcome.Failed(e)
        }
        when (outcome) {
            is MailboxSetupOutcome.Ready -> {
                setupError = null
                backend = SyncBackendState.Mailbox(outcome.home)
                open(outcome.home, null)
            }
            MailboxSetupOutcome.Local -> {
                setupError = null
                backend = SyncBackendState.Local
            }
            else -> {
                Log.w(TAG, "mailbox setup did not finish")
                setupError = outcome
                backend = runCatching { openSyncStore(vault.dbPath).use { SyncBackendState.read(it) } }.getOrDefault(backend)
            }
        }
        setStatus(coordinator?.status ?: SyncStatus.Disabled)
        return outcome
    }

    /** A pending setup the server never saw is dropped ("Annuler"); false when its mailbox exists. */
    fun cancelPendingSetup(done: (Boolean) -> Unit) {
        worker.execute {
            val ok = runCatching {
                openSyncStore(vault.dbPath).use { store ->
                    val setup = MailboxSetup(vault.dbPath, credentials, store)
                    if (setup.mailboxCreated()) false else {
                        setup.forget()
                        SyncBackendState.write(SyncBackendState.Local, store)
                        true
                    }
                }
            }.getOrDefault(false)
            if (ok) {
                backend = SyncBackendState.Local
                setupError = null
            }
            main.post { done(ok) }
        }
    }

    /** The choice a new account is created with (onboarding), before its mailbox exists. */
    fun prepareNewAccount(choice: SyncChoice) {
        runCatching {
            openSyncStore(vault.dbPath).use {
                SyncBackendState.write(if (choice == SyncChoice.Local) SyncBackendState.Local else SyncBackendState.PendingSetup(choice), it)
            }
        }
        backend = if (choice == SyncChoice.Local) SyncBackendState.Local else SyncBackendState.PendingSetup(choice)
    }

    // ---- restore and pairing -----------------------------------------------------------

    /** Where the account of `secretKey` lives: the kit's server, then the OnePass server. Blocking. */
    fun locate(secretKey: String, kitServer: FfiMailboxEndpoint?): RestoreSource =
        MailboxRestore(vault.dbPath, credentials).locate(secretKey, kitServer)

    /**
     * Restore with the Emergency Kit (spec D.4, 7.5): the mailbox is fetched,
     * then `restore_from_kit` with the master password and new device keys,
     * then this device gets its credential and the coordinator starts.
     * Blocking. A failure empties the store again.
     */
    fun restore(home: MailboxHome, secretKey: String, password: String) {
        val device = vault.newDevice()
        try {
            val (session, client) = MailboxRestore(vault.dbPath, credentials).restore(home, secretKey) {
                restoreFromKit(vault.dbPath, password, secretKey, device.classical, device.keys.pq, deviceName(), FfiDeviceKind.ANDROID, FfiDeviceMode.PERSONAL)
            }
            backend = SyncBackendState.Mailbox(home)
            open(home, client)
            vault.adopt(session, secretKey, device)
        } catch (e: Exception) {
            credentials.delete(home.mailboxId)
            vault.discardUnfinished()
            throw e
        } finally {
            device.wipe()
        }
    }

    /** After a pairing: this device joined `home` with its credential `seed`. */
    fun joined(home: MailboxHome, seed: ByteArray) {
        credentials.store(seed, home.mailboxId)
        openSyncStore(vault.dbPath).use { SyncBackendState.write(SyncBackendState.Mailbox(home), it) }
        backend = SyncBackendState.Mailbox(home)
        open(home, null)
    }

    /** "Tester": the server answers `GET /v1/config`. Blocking. */
    fun check(endpoint: FfiMailboxEndpoint): Result<Boolean> = runCatching { mailboxServerCheck(endpoint).openSignup }

    // ---- helpers ------------------------------------------------------------------------

    fun serverName(url: String) = MailboxEndpoints.displayName(url, hostedName())

    fun hostedName(): String = if (french()) "Serveur OnePass" else "OnePass Server"

    private fun french() = app.resources.configuration.locales[0].language == "fr"

    private fun setStatus(s: SyncStatus) {
        status = s
        main.post { synchronized(this) { statusListeners.toList() }.forEach { it(s) } }
    }

    companion object {
        private const val TAG = "OnePassSync"

        fun deviceName(): String = (Build.MODEL ?: "Android").take(64)

        @Volatile
        private var instance: SyncManager? = null

        fun get(context: Context): SyncManager =
            instance ?: synchronized(this) {
                instance ?: SyncManager(context.applicationContext).also { instance = it }
            }
    }
}
