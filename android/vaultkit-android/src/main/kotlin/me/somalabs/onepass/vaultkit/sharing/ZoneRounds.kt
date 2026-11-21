package me.somalabs.onepass.vaultkit.sharing

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import me.somalabs.onepass.core.FfiWakeInfo
import me.somalabs.onepass.core.FfiWakeObserver
import me.somalabs.onepass.core.FfiZone
import me.somalabs.onepass.core.FfiZoneRoundReport
import me.somalabs.onepass.core.FfiZoneSeedStore
import me.somalabs.onepass.core.FfiZoneWake
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.SyncStoreHandle
import me.somalabs.onepass.core.ZoneSyncHandle
import me.somalabs.onepass.core.startWakeListener

/**
 * The zone round of an account (sharing spec 13.3, iOS `ZoneSyncing`):
 * contact, family and shared vault mailboxes. The app talks to the core's
 * `ZoneSyncHandle`; tests may script a fake.
 */
interface ZoneSyncing {
    /** One zone round: with an unlocked `session` the share actions run too. `now`: Unix seconds. */
    fun runRound(session: Session?, now: Long): FfiZoneRoundReport

    /** The wake channel of every zone the last round synced. */
    fun wakeTopics(): List<FfiZoneWake>

    /** Listens to one zone's wake channel; returns what stops it. */
    fun startWake(info: FfiWakeInfo, onWake: () -> Unit): () -> Unit
}

/** [ZoneSyncing] over the core's `ZoneSyncHandle` and the account's sync store. */
class FfiZoneSync(val handle: ZoneSyncHandle, val store: SyncStoreHandle) : ZoneSyncing {
    override fun runRound(session: Session?, now: Long): FfiZoneRoundReport =
        try {
            handle.runRound(session, store, now)
        } catch (_: Exception) {
            EMPTY
        }

    override fun wakeTopics(): List<FfiZoneWake> = runCatching { handle.wakeTopics() }.getOrDefault(emptyList())

    override fun startWake(info: FfiWakeInfo, onWake: () -> Unit): () -> Unit {
        val h = startWakeListener(info, object : FfiWakeObserver {
            override fun wake() = onWake()
        })
        return { h.stop(); h.close() }
    }

    companion object {
        val EMPTY = FfiZoneRoundReport(emptyList(), 0u, emptyList(), emptyList(), false, null, false)
    }
}

/** Zone credential seeds in memory (tests; the app seals them on disk). */
class InMemoryZoneSeeds : FfiZoneSeedStore {
    private val seeds = HashMap<String, ByteArray>()
    private fun key(id: ByteArray) = id.joinToString("") { "%02x".format(it) }
    override fun get(mailboxId: ByteArray): ByteArray? = synchronized(seeds) { seeds[key(mailboxId)]?.copyOf() }
    override fun put(mailboxId: ByteArray, seed: ByteArray) = synchronized(seeds) { seeds[key(mailboxId)] = seed.copyOf() }
    override fun delete(mailboxId: ByteArray) { synchronized(seeds) { seeds.remove(key(mailboxId))?.fill(0) } }
}

/** A zone the server refuses (spec 13.8): erased after a signed removal, otherwise kept read-only here. */
data class ZoneRefusal(val zone: FfiZone, val removed: Boolean)

/**
 * Schedules the zone rounds (spec 13.6, 13.7; iOS `ZoneRoundScheduler`):
 * one at a time, right after each private round ([afterPrivateRound]), at
 * unlock, every [foregroundMs] in the foreground, and on each wake of a
 * zone's channel while in the foreground. An account that does not sync
 * through a mailbox has no private round: the app kicks the zones itself
 * ([kick]).
 *
 * Listeners are called on the zone thread.
 */
class ZoneRounds(
    val zones: ZoneSyncing,
    private val foregroundMs: Long = 15 * 60_000L,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private val lock = Object()
    private val rounds = Executors.newSingleThreadExecutor { r -> Thread(r, "onepass-zones").apply { isDaemon = true } }
    private val timers: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "onepass-zones-timer").apply { isDaemon = true } }

    @Volatile private var session: Session? = null
    private var running = false
    private var rerun = false
    private var closed = false
    private var foreground = false
    private var tick: ScheduledFuture<*>? = null
    private var retry: ScheduledFuture<*>? = null
    private var debounce: ScheduledFuture<*>? = null
    private val wakes = HashMap<String, () -> Unit>()

    private val changeListeners = mutableListOf<() -> Unit>()
    private val reportListeners = mutableListOf<(FfiZoneRoundReport) -> Unit>()

    /** The refusals of the last round, for the screens. */
    @Volatile var refusals: List<ZoneRefusal> = emptyList()
        private set
    /** The zones whose mailbox was full in the last round. */
    @Volatile var quotaFull: List<FfiZone> = emptyList()
        private set
    @Volatile var lastReport: FfiZoneRoundReport? = null
        private set

    /** Tests: rounds run, and the most that ran at once. */
    @Volatile var roundsRun = 0
        private set
    @Volatile var maxConcurrentRounds = 0
        private set
    private var concurrent = 0

    /** One call per round that changed the store. */
    fun onRemoteChange(l: () -> Unit) = synchronized(lock) { changeListeners += l }

    /** Every round's report. */
    fun onReport(l: (FfiZoneRoundReport) -> Unit) = synchronized(lock) { reportListeners += l }

    fun sessionUnlocked(s: Session) {
        session = s
    }

    fun sessionLocked() {
        session = null
    }

    /** A private round ended: a zone round now (or one more after the one in progress), and wait for it. */
    fun afterPrivateRound(timeoutMs: Long = 120_000) = syncNow(timeoutMs)

    /** Runs a zone round now and returns when it is done. */
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
            if (closed) return
            if (running) {
                rerun = true
                return
            }
            running = true
        }
        rounds.execute { runRounds() }
    }

    /** A local write (an account without a private round): one zone round [ms] after the last one. */
    fun kickSoon(ms: Long = 2_000) = synchronized(lock) {
        if (closed) return
        debounce?.cancel(false)
        debounce = timers.schedule({ kick() }, ms, TimeUnit.MILLISECONDS)
    }

    fun enterForeground() {
        synchronized(lock) {
            if (closed) return
            foreground = true
            if (tick == null) tick = timers.scheduleWithFixedDelay({ if (synchronized(lock) { foreground }) kick() }, foregroundMs, foregroundMs, TimeUnit.MILLISECONDS)
        }
        timers.execute { refreshWakes() }
    }

    fun enterBackground() {
        val stops = synchronized(lock) {
            foreground = false
            tick?.cancel(false)
            tick = null
            wakes.values.toList().also { wakes.clear() }
        }
        stops.forEach { runCatching(it) }
    }

    fun close() {
        enterBackground()
        synchronized(lock) {
            closed = true
            retry?.cancel(false)
            debounce?.cancel(false)
            changeListeners.clear()
            reportListeners.clear()
        }
        timers.shutdownNow()
        rounds.shutdown()
    }

    // ---- rounds ------------------------------------------------------------------------

    private fun runRounds() {
        try {
            var done = false
            while (!done) {
                synchronized(lock) { rerun = false }
                round()
                synchronized(lock) {
                    if (!rerun || closed) {
                        running = false
                        lock.notifyAll()
                        done = true
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
        if (synchronized(lock) { foreground && !closed }) timers.execute { refreshWakes() }
    }

    private fun round() {
        synchronized(lock) {
            concurrent++
            maxConcurrentRounds = maxOf(maxConcurrentRounds, concurrent)
        }
        roundsRun++
        val report = try {
            zones.runRound(session, clock())
        } finally {
            synchronized(lock) { concurrent-- }
        }
        lastReport = report
        quotaFull = report.quotaFull
        refusals = report.refusals.map { ZoneRefusal(it.zone, it.removed) }
        val (changes, reports) = synchronized(lock) { changeListeners.toList() to reportListeners.toList() }
        reports.forEach { runCatching { it(report) } }
        if (report.changed) changes.forEach { runCatching { it() } }
        if (report.rerun) synchronized(lock) { rerun = true }
        report.retryAfterSeconds?.let { after ->
            synchronized(lock) {
                if (!closed) {
                    retry?.cancel(false)
                    retry = timers.schedule({ kick() }, after.toLong() * 1000, TimeUnit.MILLISECONDS)
                }
            }
        }
    }

    // ---- wake ----------------------------------------------------------------------------

    /** One listener per zone topic the last round synced; listeners of zones gone are stopped. */
    private fun refreshWakes() {
        if (synchronized(lock) { !foreground || closed }) return
        val topics = zones.wakeTopics()
        val wanted = topics.map { it.mailboxId }.toSet()
        val gone = synchronized(lock) {
            wakes.keys.filter { it !in wanted }.map { wakes.remove(it)!! }
        }
        gone.forEach { runCatching(it) }
        for (t in topics) {
            if (synchronized(lock) { !foreground || closed || wakes.containsKey(t.mailboxId) }) continue
            val stop = try {
                zones.startWake(t.wake) { if (synchronized(lock) { foreground }) kick() }
            } catch (_: Exception) {
                // No wake channel: the zone still syncs after each private round and every 15 min.
                continue
            }
            val keep = synchronized(lock) {
                if (foreground && !closed && !wakes.containsKey(t.mailboxId)) {
                    wakes[t.mailboxId] = stop
                    true
                } else false
            }
            if (!keep) runCatching(stop)
        }
    }

    /** Tests: zone listeners running. */
    internal val wakeCount: Int get() = synchronized(lock) { wakes.size }
}
