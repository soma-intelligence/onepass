package me.somalabs.onepass.vaultkit.pairing

import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.FfiRdvRole
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.RendezvousTransport

/**
 * Pairing through the rendezvous of a mailbox server (T-RDV, spec 5.3), as
 * the Windows app does it: opaque sealed frames relayed by the server under
 * the code's session id, so two devices on different networks pair too. The
 * core seals every frame end to end; the server sees ciphertext only.
 */
class RendezvousPairingTransport(private val rdv: RendezvousTransport) : PairingTransport {
    @Volatile private var closed = false

    override fun send(frame: ByteArray) {
        if (closed) throw PairingClosed()
        try {
            rdv.send(frame)
        } catch (e: OnePassException) {
            throw PairingClosed(e.javaClass.simpleName)
        }
    }

    /** One read waits at most [SLICE_MS], then looks whether the flow closed. */
    override fun receive(maxBytes: Int, timeoutMs: Long): ByteArray {
        val until = if (timeoutMs > 0) System.currentTimeMillis() + timeoutMs else Long.MAX_VALUE
        while (true) {
            if (closed) throw PairingClosed()
            val left = until - System.currentTimeMillis()
            if (left <= 0) throw PairingClosed("timeout")
            try {
                return rdv.receive(maxBytes.toULong(), minOf(left, SLICE_MS).toULong())
            } catch (_: OnePassException.MailboxUnavailable) {
                // Nothing came in this slice (or the server is away): wait on.
            } catch (e: OnePassException) {
                throw PairingClosed(e.javaClass.simpleName)
            }
        }
    }

    override fun close() {
        closed = true
        runCatching { rdv.close() }
    }

    companion object {
        const val SLICE_MS = 10_000L

        fun open(endpoint: FfiMailboxEndpoint, session: String, role: FfiRdvRole) =
            RendezvousPairingTransport(RendezvousTransport(endpoint.baseUrl, session, role, endpoint.extraCaPem))
    }
}

/** A transport whose first frame was already read (the Hello a listener waited for). */
private class Prefetched(private var first: ByteArray?, private val inner: PairingTransport) : PairingTransport {
    override fun send(frame: ByteArray) = inner.send(frame)

    override fun receive(maxBytes: Int, timeoutMs: Long): ByteArray {
        first?.let {
            first = null
            if (it.size > maxBytes) { inner.close(); throw PairingClosed("frame too large") }
            return it
        }
        return inner.receive(maxBytes, timeoutMs)
    }

    override fun close() = inner.close()
}

/**
 * The host side over the rendezvous: for each code, waits on its session
 * until a Hello comes (the code lives 120 s), then hands the connection over
 * with that Hello. `endpoint`: the account's mailbox server.
 */
class RendezvousPairingListener(private val endpoint: FfiMailboxEndpoint, private val lifetimeMs: Long = 125_000) : PairingListener {
    override fun open(serviceName: String, onConnection: (PairingTransport) -> Unit): AutoCloseable {
        val t = try {
            RendezvousPairingTransport.open(endpoint, serviceName, FfiRdvRole.APPROVER)
        } catch (_: Exception) {
            return AutoCloseable { }
        }
        val handedOver = java.util.concurrent.atomic.AtomicBoolean(false)
        Thread({
            val hello = try {
                t.receive(PairingFrame.MAX_HANDSHAKE_BYTES, lifetimeMs)
            } catch (_: Exception) {
                t.close()
                return@Thread
            }
            handedOver.set(true)
            onConnection(Prefetched(hello, t))
        }, "onepass-pair-rdv").apply { isDaemon = true; start() }
        return AutoCloseable { if (!handedOver.get()) t.close() }
    }
}

/** The new device's side over the rendezvous of `endpoint`: the session is the code's. */
class RendezvousPairingConnector(private val endpoint: FfiMailboxEndpoint) : PairingConnector {
    override fun connect(serviceName: String, timeoutMs: Long): PairingTransport = try {
        RendezvousPairingTransport.open(endpoint, serviceName, FfiRdvRole.NEWCOMER)
    } catch (e: Exception) {
        throw PairingNotFound()
    }
}

/** Several listeners at once (the local network and the rendezvous): the first Hello wins. */
class CompositeListener(private val listeners: List<PairingListener>) : PairingListener {
    override fun open(serviceName: String, onConnection: (PairingTransport) -> Unit): AutoCloseable {
        val opened = listeners.mapNotNull { runCatching { it.open(serviceName, onConnection) }.getOrNull() }
        return AutoCloseable { opened.forEach { runCatching { it.close() } } }
    }
}
