package me.somalabs.onepass.vaultkit.sharing

import java.net.URI
import me.somalabs.onepass.core.FfiContact
import me.somalabs.onepass.core.FfiInvitePart
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.FfiPendingInvite
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.ZoneSyncHandle
import me.somalabs.onepass.core.inviteDelete
import me.somalabs.onepass.core.inviteGet
import me.somalabs.onepass.core.invitePut
import me.somalabs.onepass.core.pendingInviteFromBytes

/**
 * The drops of a remote contact invitation (sharing spec 13.9, iOS
 * `InviteDrops`): the invitee's reply and the inviter's answer, each on a
 * drop of its own on the server the link names. A drop id is never logged.
 */
interface InviteDrops {
    fun put(rdv: ByteArray, part: FfiInvitePart, bytes: ByteArray, server: FfiMailboxEndpoint)

    /** `null` until the half is all there. */
    fun get(rdv: ByteArray, part: FfiInvitePart, server: FfiMailboxEndpoint): ByteArray?
    fun delete(rdv: ByteArray, part: FfiInvitePart, server: FfiMailboxEndpoint)
}

/** [InviteDrops] over the core's `invite_put`, `invite_get` and `invite_delete`. */
object CoreInviteDrops : InviteDrops {
    override fun put(rdv: ByteArray, part: FfiInvitePart, bytes: ByteArray, server: FfiMailboxEndpoint) =
        invitePut(server.baseUrl, rdv, part, bytes, server.extraCaPem)

    override fun get(rdv: ByteArray, part: FfiInvitePart, server: FfiMailboxEndpoint): ByteArray? =
        inviteGet(server.baseUrl, rdv, part, server.extraCaPem)

    override fun delete(rdv: ByteArray, part: FfiInvitePart, server: FfiMailboxEndpoint) =
        inviteDelete(server.baseUrl, rdv, part, server.extraCaPem)
}

/**
 * Where the drops of an invitation live (iOS `InviteServer`): the server the
 * link names (`onepass://contact/<host>#...`), else the hosted instance.
 */
object InviteServer {
    const val LINK_PREFIX = "onepass://contact"
    private const val MAILBOX_PATH = "/functions/v1/mailbox"

    /**
     * The server of `link`; `known`: the servers this device already trusts
     * (the account's mailbox with its CA), reused when the link names one.
     */
    fun endpoint(link: String, hosted: String, known: List<FfiMailboxEndpoint> = emptyList()): FfiMailboxEndpoint {
        val text = link.trim()
        val host = text.removePrefix(LINK_PREFIX).takeIf { it != text && it.startsWith("/") }
            ?.drop(1)?.substringBefore('#', "")?.takeIf { it.isNotEmpty() && it.length <= 253 && hostOk(it) }
            ?: return known.firstOrNull { it.baseUrl == hosted } ?: FfiMailboxEndpoint(hosted, null)
        val url = "https://$host$MAILBOX_PATH"
        return known.firstOrNull { sameServer(it.baseUrl, url) } ?: FfiMailboxEndpoint(url, null)
    }

    /** The host to put in a new link: none for the hosted instance, `name[:port]` otherwise. */
    fun linkHost(server: String, hosted: String): String? {
        if (server == hosted) return null
        val uri = runCatching { URI(server) }.getOrNull() ?: return null
        val host = uri.host?.lowercase() ?: return null
        return if (uri.port > 0 && uri.port != 443) "$host:${uri.port}" else host
    }

    private fun hostOk(h: String): Boolean {
        val name = h.substringBefore(':')
        val port = h.substringAfter(':', "")
        return name.isNotEmpty() && name.all { it.isLowerCase() && it in 'a'..'z' || it.isDigit() || it == '.' || it == '-' } &&
            (port.isEmpty() && !h.contains(':') || port.length in 1..5 && port.all { it.isDigit() })
    }

    private fun sameServer(a: String, b: String): Boolean {
        val ua = runCatching { URI(a) }.getOrNull() ?: return false
        val ub = runCatching { URI(b) }.getOrNull() ?: return false
        fun port(u: URI) = if (u.port > 0) u.port else 443
        return ua.host.equals(ub.host, ignoreCase = true) && port(ua) == port(ub) && ua.path.trimEnd('/') == ub.path.trimEnd('/')
    }
}

/** Where the invitee keeps its pending reply (the ephemeral secret) until the answer lands. */
interface PendingInviteStore {
    fun put(rdvHex: String, server: FfiMailboxEndpoint, bytes: ByteArray)
    fun all(): List<Triple<String, FfiMailboxEndpoint, ByteArray>>
    fun delete(rdvHex: String)
}

class InMemoryPendingInvites : PendingInviteStore {
    private val map = LinkedHashMap<String, Pair<FfiMailboxEndpoint, ByteArray>>()
    override fun put(rdvHex: String, server: FfiMailboxEndpoint, bytes: ByteArray) = synchronized(map) { map[rdvHex] = server to bytes.copyOf() }
    override fun all() = synchronized(map) { map.map { (k, v) -> Triple(k, v.first, v.second.copyOf()) } }
    override fun delete(rdvHex: String) { synchronized(map) { map.remove(rdvHex)?.second?.fill(0) } }
}

/** The contact pair's mailbox needs the network: a failure pins nothing (spec 13.5). */
class ContactZoneOffline : Exception("offline")

class ContactInviteExpired : Exception("expired")

/** Makes the pair's mailbox and returns the signed offer (decision 16). */
fun interface ContactZoneCreating {
    fun offer(peerCard: ByteArray, session: Session): ByteArray
}

/** [ContactZoneCreating] over `ZoneSyncHandle.contact_zone_create`. */
class ContactZoneCreator(private val handle: ZoneSyncHandle, private val clock: () -> Long = { System.currentTimeMillis() / 1000 }) : ContactZoneCreating {
    override fun offer(peerCard: ByteArray, session: Session): ByteArray = try {
        handle.contactZoneCreate(session, peerCard, clock())
    } catch (_: OnePassException.MailboxUnavailable) {
        throw ContactZoneOffline()
    } catch (_: OnePassException.Forbidden) {
        throw ContactZoneOffline()
    } catch (_: OnePassException.ClockSkew) {
        throw ContactZoneOffline()
    }
}

/**
 * The remote contact invitation (sharing spec 5.3.2, 13.9; iOS
 * `ContactInviteFlow`): asynchronous through the drops of the server the
 * link names. The inviter makes a link and shares it; the invitee opens it,
 * writes its sealed reply and waits; the inviter makes the pair's mailbox
 * (decision 16) and writes its answer; both end with a contact at `Link`
 * (Read only, decision 1), verified later by comparing the safety number.
 *
 * Each flow runs on a thread of its own; [onState] is called on it.
 */
class ContactInviteFlow(
    private val session: Session,
    private val myName: String,
    private val drops: InviteDrops,
    private val creator: ContactZoneCreating,
    private val pending: PendingInviteStore,
    private val pollMs: Long = 5_000,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    sealed class State {
        object Idle : State()
        /** Share `link` (expires at `expiresAt`, Unix seconds); the reply is awaited. */
        data class Sharing(val link: String, val expiresAt: Long) : State()
        /** Reply written, the inviter's answer is awaited. */
        object WaitingForAnswer : State()
        data class Done(val contact: FfiContact) : State()
        data class Failed(val error: Throwable) : State()
    }

    @Volatile var state: State = State.Idle
        private set
    @Volatile private var cancelled = false
    private var thread: Thread? = null
    private val listeners = mutableListOf<(State) -> Unit>()

    fun onState(l: (State) -> Unit) = synchronized(listeners) { listeners += l }

    private fun set(s: State) {
        state = s
        synchronized(listeners) { listeners.toList() }.forEach { runCatching { it(s) } }
    }

    private fun start(work: () -> Unit) {
        cancelled = false
        thread = Thread({
            try {
                work()
            } catch (_: InterruptedException) {
            } catch (e: Exception) {
                if (!cancelled) set(State.Failed(e))
            }
        }, "onepass-contact-invite").apply { isDaemon = true; start() }
    }

    /** Inviter: a new invitation whose drops live on `server`; waits for the reply. */
    fun createInvite(server: FfiMailboxEndpoint, linkHost: String?) = start {
        val invite = session.createContactInvite(linkHost, clock())
        set(State.Sharing(invite.link, invite.expiresAt))
        val reply = poll(invite.rdvId, FfiInvitePart.REPLY, server, invite.expiresAt)
        val now = clock()
        val card = session.inviteReplyCard(invite.inviteId, reply, now)
        val offer = creator.offer(card, session)
        val answer = session.acceptInviteReply(invite.inviteId, reply, myName, offer, now)
        drops.put(invite.rdvId, FfiInvitePart.ANSWER, answer.answer, server)
        runCatching { drops.delete(invite.rdvId, FfiInvitePart.REPLY, server) }
        set(State.Done(answer.contact))
    }

    /** Invitee: a link was opened; the reply is written and the answer awaited. */
    fun open(link: String, server: FfiMailboxEndpoint) = start {
        val reply = session.contactInviteReply(link.trim(), myName, clock())
        val rdvHex = hex(reply.rdvId)
        pending.put(rdvHex, server, reply.pending.toBytes())
        drops.put(reply.rdvId, FfiInvitePart.REPLY, reply.bytes, server)
        set(State.WaitingForAnswer)
        awaitAnswer(reply.pending, server)
    }

    /** After a restart: a pending reply kept by [pending], awaited again. */
    fun resume(rdvHex: String, server: FfiMailboxEndpoint, bytes: ByteArray) = start {
        val p = try {
            pendingInviteFromBytes(bytes)
        } finally {
            bytes.fill(0)
        }
        set(State.WaitingForAnswer)
        awaitAnswer(p, server)
    }

    private fun awaitAnswer(p: FfiPendingInvite, server: FfiMailboxEndpoint) {
        val rdv = p.rdvId()
        val answer = try {
            poll(rdv, FfiInvitePart.ANSWER, server, clock() + 72 * 3600)
        } catch (e: ContactInviteExpired) {
            pending.delete(hex(rdv))
            throw e
        }
        val contact = session.finishInvite(p, answer, clock())
        pending.delete(hex(rdv))
        runCatching { drops.delete(rdv, FfiInvitePart.ANSWER, server) }
        set(State.Done(contact))
    }

    private fun poll(rdv: ByteArray, part: FfiInvitePart, server: FfiMailboxEndpoint, until: Long): ByteArray {
        while (true) {
            if (cancelled) throw InterruptedException()
            runCatching { drops.get(rdv, part, server) }.getOrNull()?.let { return it }
            if (clock() >= until) throw ContactInviteExpired()
            Thread.sleep(pollMs)
        }
    }

    fun cancel() {
        cancelled = true
        thread?.interrupt()
        thread = null
        set(State.Idle)
    }

    /** Tests: waits for the flow's thread. */
    fun join(ms: Long) = thread?.join(ms)

    companion object {
        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }
}
