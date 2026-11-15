package me.somalabs.onepass.vaultkit.pairing

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import me.somalabs.onepass.core.FfiDeviceKind
import me.somalabs.onepass.core.FfiDeviceMode
import me.somalabs.onepass.core.FfiHostCode
import me.somalabs.onepass.core.FfiMailboxEnrollment
import me.somalabs.onepass.core.FfiPairingMessage
import me.somalabs.onepass.core.FfiPeerDevice
import me.somalabs.onepass.core.FfiPqDeviceHalf
import me.somalabs.onepass.core.FfiUnlocked
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.PairingApprover
import me.somalabs.onepass.core.PairingHost
import me.somalabs.onepass.core.PairingNewcomer

/** Why a pairing stopped (iOS `PairingFailure`). */
enum class PairingFailure {
    /** "Ce code n'est pas valide. Vérifie-le : 8 caractères, par exemple K7QM-4XPR." */
    BAD_CODE,
    /** "Rapproche les deux appareils et vérifie qu'ils sont sur le même Wi-Fi." */
    HOST_NOT_FOUND,
    /** "La connexion avec l'autre appareil a été coupée." */
    CONNECTION_LOST,
    /** "L'autre appareil a annulé l'appairage." */
    CANCELLED_BY_PEER,
    /** "Appairage annulé. Rien n'a été envoyé." */
    CODE_REJECTED,
    /** "L'appairage a été refusé. Recommence depuis le début." */
    REFUSED,
    /** "Le nouvel appareil n'a pas confirmé à temps. Recommence l'appairage." */
    PEER_TIMEOUT,
    /** "Le délai est dépassé. Le compte reçu a été effacé de cet appareil : recommence l'appairage." */
    GRANT_EXPIRED,
    /** "Trop d'essais. Le compte reçu a été effacé de cet appareil : recommence l'appairage." */
    TOO_MANY_ATTEMPTS,
    OTHER,
}

/** This device's keys for a pairing (`confirm_with_key`, `seal_key_ack`, `introduce`). */
class DeviceKeys(val classical: ByteArray, val pq: FfiPqDeviceHalf) {
    fun wipe() = classical.fill(0)
}

private fun nowUnix() = System.currentTimeMillis() / 1000

/**
 * The unlocked device's side of a pairing, rendezvous direction (iOS
 * `PairingApproverFlow.startHosting`, on the Mac "Configurer un appareil"):
 * shows a code (QR text and `XXXX-XXXX`) renewed every 30 s, each published
 * as its own service; the first connection whose Hello proves a live code
 * goes to the 6-digit comparison. Then [approve] seals the grant (the app
 * passes the session, the Secret Key and its mailbox client), the newcomer
 * acknowledges and [introduce] pins its device key.
 *
 * Everything runs on the flow's thread; [onState] is called there.
 */
class PairingHostFlow(
    private val listener: PairingListener,
    private val onState: (State) -> Unit,
    private val renewMs: Long = 30_000,
    private val handshakeTimeoutMs: Long = 10_000,
    /** How long the new device may take to acknowledge the grant (it asks the master password first). */
    private val ackTimeoutMs: Long = 330_000,
) {
    sealed class State {
        object Connecting : State()
        data class Hosting(val code: FfiHostCode) : State()
        data class Comparing(val sas: String, val peer: FfiPeerDevice, val mode: FfiDeviceMode) : State()
        object WaitingForPeer : State()
        object Granting : State()
        /** The grant is out: waiting for the new device's acknowledgment. */
        object WaitingForAck : State()
        data class Done(val peer: FfiPeerDevice) : State()
        data class Failed(val failure: PairingFailure, val error: Throwable? = null) : State()
    }

    private val worker = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "onepass-pair-host").apply { isDaemon = true } }
    private val lock = Object()
    @Volatile var state: State = State.Connecting
        private set
    private var host: PairingHost? = null
    private val services = mutableListOf<Pair<Long, AutoCloseable>>()
    private var transport: PairingTransport? = null
    var approver: PairingApprover? = null
        private set
    private var peerConfirmed = false
    private var acked = false
    private var pending = 0
    private var finished = false

    fun start() {
        worker.execute {
            try {
                host = PairingHost()
                issue()
                worker.scheduleWithFixedDelay({ if (state is State.Hosting) runCatching { issue() } }, renewMs, renewMs, TimeUnit.MILLISECONDS)
            } catch (e: Exception) {
                fail(PairingFailure.OTHER, e)
            }
        }
    }

    private fun issue() {
        val h = host ?: return
        val now = nowUnix()
        val code = h.issue(now)
        synchronized(lock) {
            services.removeAll { (expires, s) -> (expires < now).also { if (it) runCatching { s.close() } } }
        }
        val published = listener.open(code.serviceName) { t -> connection(t) }
        synchronized(lock) { services += code.expiresAt to published }
        set(State.Hosting(code))
    }

    private fun connection(t: PairingTransport) {
        val admitted = synchronized(lock) {
            if (finished || approver != null || pending >= 4) false else { pending++; true }
        }
        if (!admitted) { t.close(); return }
        Thread({
            val hello = try {
                t.receive(PairingFrame.MAX_HANDSHAKE_BYTES, handshakeTimeoutMs)
            } catch (_: Exception) {
                synchronized(lock) { pending-- }
                t.close()
                return@Thread
            }
            post { hello(t, hello) }
        }, "onepass-pair-hello").apply { isDaemon = true; start() }
    }

    private fun hello(t: PairingTransport, hello: ByteArray) {
        synchronized(lock) { pending-- }
        val h = host ?: return t.close()
        if (approver != null || finished) return t.close()
        val ap = try {
            h.accept(hello, nowUnix())
        } catch (_: Exception) {
            // A wrong code or a malformed Hello: that connection is dropped. Too many close the host.
            t.close()
            if (!h.isOpen()) fail(PairingFailure.REFUSED)
            return
        }
        approver = ap
        transport = t
        withdraw()
        try {
            t.send(ap.keyExchange())
        } catch (e: Exception) {
            return fail(PairingFailure.CONNECTION_LOST, e)
        }
        set(State.Comparing(ap.sas(), ap.peer(), ap.requestedMode()))
        Thread({ receive(ap, t) }, "onepass-pair-host-rx").apply { isDaemon = true; start() }
    }

    private fun receive(ap: PairingApprover, t: PairingTransport) {
        while (true) {
            val frame = try {
                t.receive()
            } catch (e: Exception) {
                if (!(state is State.Done || state is State.Failed)) {
                    post { if (!acked) fail(PairingFailure.CONNECTION_LOST, e) }
                }
                return
            }
            val message = try {
                ap.onFrame(frame)
            } catch (e: Exception) {
                post { fail(PairingFailure.REFUSED, e) }
                return
            }
            when (message) {
                FfiPairingMessage.Confirmed -> synchronized(lock) { peerConfirmed = true; lock.notifyAll() }
                FfiPairingMessage.Ack -> synchronized(lock) { acked = true; lock.notifyAll() }
                FfiPairingMessage.End -> { post { fail(PairingFailure.CANCELLED_BY_PEER) }; return }
                else -> Unit
            }
        }
    }

    /**
     * "Les codes sont identiques": once the new device confirmed (within
     * 60 s), `seal` builds the grant frame (`seal_full_grant`), it is sent,
     * then `introduce` runs after the acknowledgment and the state is Done.
     * Blocking: call it off the main thread.
     */
    fun approve(seal: (PairingApprover) -> ByteArray, introduce: (PairingApprover) -> Unit) {
        val ap = approver ?: return
        val t = transport ?: return
        if (state !is State.Comparing) return
        set(State.WaitingForPeer)
        val confirmed = synchronized(lock) {
            val until = System.currentTimeMillis() + 60_000
            while (!peerConfirmed && !finished && System.currentTimeMillis() < until) lock.wait(500)
            peerConfirmed
        }
        if (!confirmed) return fail(PairingFailure.PEER_TIMEOUT)
        set(State.Granting)
        try {
            t.send(seal(ap))
        } catch (e: OnePassException) {
            return fail(PairingFailure.OTHER, e)
        } catch (e: Exception) {
            return fail(PairingFailure.CONNECTION_LOST, e)
        }
        set(State.WaitingForAck)
        val gotAck = synchronized(lock) {
            val until = System.currentTimeMillis() + ackTimeoutMs
            while (!acked && !finished && System.currentTimeMillis() < until) lock.wait(500)
            acked
        }
        if (!gotAck) return fail(PairingFailure.PEER_TIMEOUT)
        try {
            introduce(ap)
        } catch (e: Exception) {
            return fail(PairingFailure.OTHER, e)
        }
        val peer = ap.peer()
        finish()
        set(State.Done(peer))
    }

    /** "Ils sont différents", or leaving the screen: nothing more is granted. */
    fun cancel() {
        if (state is State.Done || state is State.Failed || state is State.Granting) return
        val ap = approver
        val t = transport
        if (ap != null && t != null) runCatching { t.send(ap.sealEnd()) }
        fail(PairingFailure.CODE_REJECTED)
    }

    private fun post(r: () -> Unit) {
        try {
            worker.execute(r)
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            // The flow ended.
        }
    }

    private fun withdraw() {
        val all = synchronized(lock) { services.map { it.second }.also { services.clear() } }
        all.forEach { runCatching { it.close() } }
    }

    private fun finish() {
        synchronized(lock) {
            finished = true
            lock.notifyAll()
        }
        withdraw()
        runCatching { host?.close() }
        transport?.close()
        worker.shutdown()
    }

    private fun fail(f: PairingFailure, e: Throwable? = null) {
        if (state is State.Done || state is State.Failed) return
        finish()
        set(State.Failed(f, e))
    }

    private fun set(s: State) {
        if (state is State.Done || state is State.Failed) {
            if (s !is State.Done && s !is State.Failed) return
        }
        state = s
        runCatching { onState(s) }
    }
}

/**
 * The new device's side, rendezvous direction (iOS `PairingNewcomerFlow.join`):
 * the code typed (or scanned) names the service, this device connects, proves
 * the code in its Hello, compares the 6-digit code, confirms with its device
 * key and its mailbox credential, receives the grant and acknowledges it.
 * Then [importAndUnlock] (the master password) opens the account here.
 */
class PairingJoinFlow(
    private val connectors: List<PairingConnector>,
    private val name: String,
    private val kind: FfiDeviceKind,
    private val keys: DeviceKeys,
    /** This device's mailbox credential key (32 bytes): the approver grants an enroll ticket for it. */
    private val mailboxCredentialPub: ByteArray?,
    private val onState: (State) -> Unit,
    private val connectTimeoutMs: Long = 20_000,
    private val handshakeTimeoutMs: Long = 10_000,
    private val grantLifetimeMs: Long = 300_000,
) {
    sealed class State {
        object Joining : State()
        data class Comparing(val sas: String) : State()
        object WaitingForApproval : State()
        /** The account arrived: ask the master password. `enrollment`: the mailbox to join, if any. */
        data class ReceivedFull(val enrollment: FfiMailboxEnrollment?) : State()
        object Importing : State()
        object Done : State()
        data class Failed(val failure: PairingFailure, val error: Throwable? = null) : State()
    }

    private val worker = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "onepass-pair-join").apply { isDaemon = true } }
    @Volatile var state: State = State.Joining
        private set
    private var newcomer: PairingNewcomer? = null
    private var transport: PairingTransport? = null
    private var failedImports = 0
    private var grantTimer: java.util.concurrent.ScheduledFuture<*>? = null

    fun join(code: String) {
        worker.execute {
            val n = try {
                PairingNewcomer.joinCode(name, kind, FfiDeviceMode.PERSONAL, code, nowUnix(), mailboxCredentialPub)
            } catch (e: Exception) {
                return@execute fail(PairingFailure.BAD_CODE, e)
            }
            newcomer = n
            set(State.Joining)
            // Every transport at once (the local network, the server's rendezvous): the first key
            // exchange wins, the others are closed.
            val (t, exchange) = race(n) ?: return@execute fail(PairingFailure.HOST_NOT_FOUND)
            transport = t
            val sas = try {
                n.onKeyExchange(exchange, nowUnix())
            } catch (e: OnePassException) {
                return@execute fail(PairingFailure.REFUSED, e)
            } catch (e: Exception) {
                return@execute fail(PairingFailure.CONNECTION_LOST, e)
            }
            set(State.Comparing(sas))
        }
    }

    private fun race(n: PairingNewcomer): Pair<PairingTransport, ByteArray>? {
        val won = java.util.concurrent.atomic.AtomicReference<Pair<PairingTransport, ByteArray>?>()
        val left = java.util.concurrent.CountDownLatch(connectors.size)
        val hello = n.hello()
        val service = n.serviceName()
        for (c in connectors) {
            Thread({
                var t: PairingTransport? = null
                try {
                    t = c.connect(service, connectTimeoutMs)
                    t.send(hello)
                    val kx = t.receive(PairingFrame.MAX_HANDSHAKE_BYTES, connectTimeoutMs + handshakeTimeoutMs)
                    if (!won.compareAndSet(null, t to kx)) t.close()
                    else repeat(connectors.size) { left.countDown() }
                } catch (_: Exception) {
                    t?.close()
                } finally {
                    left.countDown()
                }
            }, "onepass-pair-connect").apply { isDaemon = true; start() }
        }
        left.await(2 * (connectTimeoutMs + handshakeTimeoutMs), java.util.concurrent.TimeUnit.MILLISECONDS)
        return won.get()
    }

    /** The user saw the same code on both screens: confirm with this device's key, then wait for the grant. */
    fun confirmCode() = worker.execute {
        val n = newcomer ?: return@execute
        val t = transport ?: return@execute
        if (state !is State.Comparing) return@execute
        try {
            t.send(n.confirmWithKey(keys.classical, keys.pq))
        } catch (e: OnePassException) {
            return@execute fail(PairingFailure.REFUSED, e)
        } catch (e: Exception) {
            return@execute fail(PairingFailure.CONNECTION_LOST, e)
        }
        set(State.WaitingForApproval)
        receiveGrant(n, t)
    }

    private fun receiveGrant(n: PairingNewcomer, t: PairingTransport) {
        while (true) {
            val message = try {
                n.open(t.receive())
            } catch (e: OnePassException) {
                return fail(PairingFailure.REFUSED, e)
            } catch (e: Exception) {
                return fail(PairingFailure.CONNECTION_LOST, e)
            }
            when (message) {
                is FfiPairingMessage.FullGrant -> {
                    if (message.mode != FfiDeviceMode.PERSONAL) return fail(PairingFailure.REFUSED)
                    // Acknowledged at once with the device key: the approver pins it.
                    runCatching { t.send(n.sealKeyAck(keys.classical, keys.pq)) }
                    val enrollment = try {
                        n.mailboxEnrollment()
                    } catch (e: Exception) {
                        return fail(PairingFailure.REFUSED, e)
                    }
                    // The account is in the grant: the connection is no longer needed.
                    worker.schedule({ t.close() }, 2, TimeUnit.SECONDS)
                    transport = null
                    set(State.ReceivedFull(enrollment))
                    startGrantTimer()
                    return
                }
                FfiPairingMessage.End -> return fail(PairingFailure.CANCELLED_BY_PEER)
                is FfiPairingMessage.PublicGrant -> return fail(PairingFailure.REFUSED)
                else -> continue
            }
        }
    }

    /**
     * Full grant: imports the snapshot into the empty store with the master
     * password and returns the unlocked session and the received Secret Key.
     * A wrong password keeps the grant for another try (up to 5). Blocking.
     */
    fun importAndUnlock(dbPath: String, password: String): Pair<FfiUnlocked, String> {
        val n = newcomer ?: throw IllegalStateException("no grant")
        if (state !is State.ReceivedFull) throw IllegalStateException("no grant")
        grantTimer?.cancel(false)
        val received = state
        set(State.Importing)
        try {
            val unlocked = n.importSnapshotV2(dbPath, password, keys.classical, keys.pq)
            val key = n.takeSecretKey() ?: run {
                unlocked.session.lock()
                throw IllegalStateException("secret key")
            }
            finish()
            set(State.Done)
            return unlocked to key
        } catch (e: OnePassException.WrongPassword) {
            failedImports++
            if (failedImports >= 5) {
                fail(PairingFailure.TOO_MANY_ATTEMPTS)
            } else {
                set(received)
                startGrantTimer()
            }
            throw e
        } catch (e: Exception) {
            set(received)
            startGrantTimer()
            throw e
        }
    }

    /** The codes differ, or the user leaves: the approver is told when the code exchange is done. */
    fun cancel() {
        if (state is State.Done || state is State.Failed) return
        val n = newcomer
        val t = transport
        if (n != null && t != null) runCatching { t.send(n.sealEnd()) }
        fail(PairingFailure.CODE_REJECTED)
    }

    private fun startGrantTimer() {
        grantTimer?.cancel(false)
        grantTimer = worker.schedule({ if (state is State.ReceivedFull) fail(PairingFailure.GRANT_EXPIRED) }, grantLifetimeMs, TimeUnit.MILLISECONDS)
    }

    private fun finish() {
        grantTimer?.cancel(false)
        transport?.close()
        transport = null
        worker.shutdown()
    }

    private fun fail(f: PairingFailure, e: Throwable? = null) {
        if (state is State.Done || state is State.Failed) return
        // A received account not imported leaves memory (M3).
        runCatching { newcomer?.discardGrant() }
        finish()
        set(State.Failed(f, e))
    }

    private fun set(s: State) {
        if ((state is State.Done || state is State.Failed) && s !is State.Failed && s !is State.Done) return
        state = s
        runCatching { onState(s) }
    }
}
