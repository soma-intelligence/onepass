package me.somalabs.onepass.vaultkit.sync

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import me.somalabs.onepass.core.FfiRoundReport
import me.somalabs.onepass.core.FfiRoundStatus
import me.somalabs.onepass.core.FfiWakeObserver
import me.somalabs.onepass.core.MailboxSync
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.WakeListenerHandle
import me.somalabs.onepass.core.startWakeListener

/** What the settings screen shows about sync (iOS `SyncStatus`, mailbox cases). */
sealed class SyncStatus {
    /** No mailbox: the account stays on this device. */
    object Disabled : SyncStatus()

    /** `lastSync`: Unix millis of the last round that ended idle, null before the first one. */
    data class Idle(val lastSync: Long?) : SyncStatus()
    object Syncing : SyncStatus()
    object Offline : SyncStatus()

    /** "La synchronisation reprendra dans un instant". */
    object Retrying : SyncStatus()

    /** "Vérifie l'heure de l'appareil". */
    object ClockSkew : SyncStatus()

    /** "Un enregistrement du serveur est illisible". */
    object Unreadable : SyncStatus()

    /** The core refused remote data (`Integrity { kind }`). */
    data class Refused(val kind: String) : SyncStatus()

    /** The server serves an older state, or a safe exit waits for it. */
    object WaitingForMailbox : SyncStatus()

    /** The account's signed home names another server: this device sends nothing more. */
    data class HomeMoved(val server: String) : SyncStatus()
}

/**
 * Schedules the sync rounds of an account on a mailbox (cross-platform spec
 * 4.10, 4.14; iOS `MailboxSyncCoordinator`). The round itself is the core's
 * (`MailboxSync.run_round`: fetch, rebase, send, home check); this class only
 * decides when one runs and what the status says.
 *
 * One round at a time: triggers that come during a round give one more round
 * after it. A round that asks for another (`rerun`) gets it at once; a server
 * delay (`retry_after_seconds`) is used as is, otherwise failures back off
 * along [retryDelaysMs] (30 s, 2 min, 10 min). Local writes are debounced
 * ([debounceMs]). While the app is in the foreground the mailbox's wake
 * channel kicks a round on each change made elsewhere, and a round runs every
 * [periodicMs] in case the wake channel is down. Once the account's signed
 * home names another place (`HomeMoved`), no round runs again.
 *
 * Listeners are called on the round thread.
 */
class MailboxSyncCoordinator(
    val client: MailboxSync,
    val home: MailboxHome,
    val serverName: String,
    private val debounceMs: Long = 2_000,
    private val retryDelaysMs: List<Long> = RETRY_DELAYS_MS,
    private val periodicMs: Long = 60_000,
    private val wakeStarter: (onWake: () -> Unit) -> (() -> Unit) = { onWake -> realWake(client, onWake) },
) {
    private val lock = Object()
    private val rounds = Executors.newSingleThreadExecutor { r -> Thread(r, "onepass-sync").apply { isDaemon = true } }
    private val timers: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "onepass-sync-timer").apply { isDaemon = true } }

    @Volatile var status: SyncStatus = SyncStatus.Idle(null)
        private set

    @Volatile private var session: Session? = null
    private var running = false
    private var rerun = false
    private var moved = false
    private var closed = false
    private var foreground = false
    private var retryAttempt = 0
    private var debounce: ScheduledFuture<*>? = null
    private var retry: ScheduledFuture<*>? = null
    private var periodic: ScheduledFuture<*>? = null
    private var stopWake: (() -> Unit)? = null

    private val statusListeners = mutableListOf<(SyncStatus) -> Unit>()
    private val changeListeners = mutableListOf<() -> Unit>()

    /** Tests: rounds run, and the most that ran at once. */
    @Volatile var roundsRun = 0
        private set
    @Volatile var maxConcurrentRounds = 0
        private set
    private var concurrent = 0

    val homeMoved: Boolean get() = synchronized(lock) { moved }

    fun onStatus(l: (SyncStatus) -> Unit) = synchronized(lock) { statusListeners += l }

    /** Called after each round that changed the store (fetched changes or a rebase). */
    fun onRemoteChange(l: () -> Unit) = synchronized(lock) { changeListeners += l }

    fun removeListeners() = synchronized(lock) {
        statusListeners.clear()
        changeListeners.clear()
    }

    // ---- triggers ------------------------------------------------------------------------

    /** Runs a round now (or joins the one in progress, plus one more) and returns when it is done. */
    fun syncNow(timeoutMs: Long = 120_000) {
        kick()
        val until = System.currentTimeMillis() + timeoutMs
        synchronized(lock) {
            while (running) {
                val left = until - System.currentTimeMillis()
                if (left <= 0) return
                lock.wait(left)
            }
        }
    }

    /** A round soon, without waiting for it. */
    fun kick() {
        synchronized(lock) {
            if (moved || closed) return
            if (running) {
                rerun = true
                return
            }
            running = true
        }
        rounds.execute { runRounds() }
    }

    /** Debounced: one round [debounceMs] after the last write. */
    fun localChangesWritten() = synchronized(lock) {
        if (closed) return
        debounce?.cancel(false)
        debounce = timers.schedule({ kick() }, debounceMs, TimeUnit.MILLISECONDS)
    }

    fun sessionUnlocked(s: Session) {
        session = s
        kick()
    }

    fun sessionLocked() {
        session = null
    }

    /** The app came to the foreground: listen to the wake channel, a round now and periodically. */
    fun enterForeground() {
        synchronized(lock) {
            if (closed) return
            foreground = true
            periodic?.cancel(false)
            periodic = timers.scheduleWithFixedDelay({ kick() }, periodicMs, periodicMs, TimeUnit.MILLISECONDS)
        }
        kick()
        timers.execute { startWake() }
    }

    /** The app left the foreground: stop listening (the periodic job takes over). */
    fun enterBackground() {
        val stop = synchronized(lock) {
            foreground = false
            periodic?.cancel(false)
            periodic = null
            stopWake.also { stopWake = null }
        }
        stop?.let { runCatching(it) }
    }

    /** Stops everything; the client is closed once the round in progress ended. */
    fun close() {
        enterBackground()
        synchronized(lock) {
            closed = true
            debounce?.cancel(false)
            retry?.cancel(false)
            statusListeners.clear()
            changeListeners.clear()
        }
        timers.shutdownNow()
        rounds.execute { runCatching { client.close() } }
        rounds.shutdown()
    }

    // ---- rounds --------------------------------------------------------------------------

    private fun runRounds() {
        try {
            while (true) {
                synchronized(lock) { rerun = false }
                round()
                synchronized(lock) {
                    if (!rerun || moved || closed) {
                        running = false
                        lock.notifyAll()
                        return
                    }
                }
            }
        } catch (t: Throwable) {
            synchronized(lock) {
                running = false
                lock.notifyAll()
            }
            throw t
        }
    }

    private fun round() {
        if (synchronized(lock) { moved || closed }) return
        synchronized(lock) {
            concurrent++
            maxConcurrentRounds = maxOf(maxConcurrentRounds, concurrent)
        }
        roundsRun++
        setStatus(SyncStatus.Syncing)
        val report = try {
            client.runRound(session, System.currentTimeMillis() / 1000)
        } catch (_: Exception) {
            FfiRoundReport(FfiRoundStatus.Retrying, false, emptyList(), null, false)
        } finally {
            synchronized(lock) { concurrent-- }
        }
        if (report.changed || report.rebased.isNotEmpty()) emitRemoteChange()
        apply(report)
    }

    private fun apply(report: FfiRoundReport) {
        when (val s = report.status) {
            FfiRoundStatus.Idle -> {
                synchronized(lock) {
                    retryAttempt = 0
                    retry?.cancel(false)
                    retry = null
                }
                setStatus(SyncStatus.Idle(System.currentTimeMillis()))
            }
            FfiRoundStatus.Offline -> { setStatus(SyncStatus.Offline); scheduleRetry(report) }
            FfiRoundStatus.Retrying -> { setStatus(SyncStatus.Retrying); scheduleRetry(report) }
            FfiRoundStatus.ClockSkew -> { setStatus(SyncStatus.ClockSkew); scheduleRetry(report) }
            FfiRoundStatus.WaitingForServer -> { setStatus(SyncStatus.WaitingForMailbox); scheduleRetry(report) }
            is FfiRoundStatus.Refused -> setStatus(SyncStatus.Refused(s.kind))
            FfiRoundStatus.Unsettled -> { setStatus(SyncStatus.Syncing); scheduleRetry(report) }
            FfiRoundStatus.Unreadable -> { setStatus(SyncStatus.Unreadable); scheduleRetry(report) }
            is FfiRoundStatus.HomeMoved -> {
                val stop = synchronized(lock) {
                    moved = true
                    rerun = false
                    retry?.cancel(false)
                    debounce?.cancel(false)
                    periodic?.cancel(false)
                    stopWake.also { stopWake = null }
                }
                stop?.let { runCatching(it) }
                val host = s.baseUrl?.let { runCatching { java.net.URI(it).host }.getOrNull() } ?: "iCloud"
                setStatus(SyncStatus.HomeMoved(host))
                return
            }
        }
        if (report.rerun) synchronized(lock) { rerun = true }
    }

    /** The server's delay when it gave one, otherwise the next step of the backoff. */
    private fun scheduleRetry(report: FfiRoundReport) = synchronized(lock) {
        if (closed) return
        retry?.cancel(false)
        val delay = report.retryAfterSeconds?.let { it.toLong() * 1000 }
            ?: retryDelaysMs[minOf(retryAttempt, retryDelaysMs.lastIndex)].also { retryAttempt++ }
        retry = timers.schedule({ kick() }, delay, TimeUnit.MILLISECONDS)
    }

    /** Tests: the delay of the retry scheduled, if any. */
    internal fun retryDelayMs(): Long? = synchronized(lock) { retry?.getDelay(TimeUnit.MILLISECONDS) }

    // ---- wake ----------------------------------------------------------------------------

    private fun startWake() {
        if (synchronized(lock) { stopWake != null || moved || closed || !foreground }) return
        val stop = try {
            wakeStarter { if (synchronized(lock) { foreground }) kick() }
        } catch (_: Exception) {
            // No wake channel: rounds still run on opening, on writes and periodically.
            return
        }
        val keep = synchronized(lock) {
            if (foreground && !moved && !closed && stopWake == null) {
                stopWake = stop
                true
            } else false
        }
        if (!keep) runCatching(stop)
    }

    // ---- listeners -----------------------------------------------------------------------

    private fun setStatus(s: SyncStatus) {
        status = s
        synchronized(lock) { statusListeners.toList() }.forEach { runCatching { it(s) } }
    }

    private fun emitRemoteChange() {
        synchronized(lock) { changeListeners.toList() }.forEach { runCatching { it() } }
    }

    companion object {
        val RETRY_DELAYS_MS = listOf(30_000L, 120_000L, 600_000L)

        private fun realWake(client: MailboxSync, onWake: () -> Unit): () -> Unit {
            val info = client.wakeInfo()
            val handle: WakeListenerHandle = startWakeListener(info, object : FfiWakeObserver {
                override fun wake() = onWake()
            })
            return { handle.stop(); handle.close() }
        }
    }
}
