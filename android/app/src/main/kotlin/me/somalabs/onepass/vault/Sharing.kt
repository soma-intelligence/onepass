package me.somalabs.onepass.vault

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.util.concurrent.Executors
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.FfiRecoveryAlert
import me.somalabs.onepass.core.FfiRekeyNotice
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.vaultkit.sharing.ContactInviteFlow
import me.somalabs.onepass.vaultkit.sharing.ContactZoneCreator
import me.somalabs.onepass.vaultkit.sharing.CoreInviteDrops
import me.somalabs.onepass.vaultkit.sharing.InviteServer
import me.somalabs.onepass.vaultkit.sharing.PendingInviteStore
import me.somalabs.onepass.vaultkit.sharing.SharingSnapshot
import me.somalabs.onepass.vaultkit.sync.MailboxEndpoints
import me.somalabs.onepass.vaultkit.sync.SyncBackendState

/**
 * The sharing state of this device's account for the whole process (iOS
 * `VaultSession+Sharing`): the snapshot the screens draw from, the contact
 * invitations in progress (they outlive the screen that started them), the
 * recovery requests read without unlocking. Listeners run on the main thread.
 *
 * Nothing secret is logged; a pending invitation's secret is sealed by the
 * device's Keystore key (`invite-<rdv>.bin`) until its answer lands.
 */
class Sharing private constructor(context: Context) {
    private val app = context.applicationContext
    val vault = DeviceVault.get(app)
    val sync = SyncManager.get(app)
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "onepass-sharing").apply { isDaemon = true } }

    @Volatile var snapshot = SharingSnapshot()
        private set
    @Volatile var alerts: List<FfiRecoveryAlert> = emptyList()
        private set

    /** The invitation this device made and waits on, and the links it opened. */
    @Volatile var inviter: ContactInviteFlow? = null
        private set
    val invitees = java.util.concurrent.CopyOnWriteArrayList<ContactInviteFlow>()

    /** A link opened while locked: answered at the next unlock. */
    @Volatile var pendingLink: String? = null

    private val listeners = mutableListOf<() -> Unit>()

    fun onChange(l: () -> Unit) = synchronized(listeners) { listeners += l }
    fun removeChange(l: () -> Unit) = synchronized(listeners) { listeners -= l }

    private fun changed() = main.post { synchronized(listeners) { listeners.toList() }.forEach { it() } }

    /** Blocking: reads the snapshot and the recovery requests again. */
    fun readNow(s: Session?) {
        snapshot = if (s != null) SharingSnapshot.read(s) else SharingSnapshot()
        alerts = runCatching { me.somalabs.onepass.core.recoveryAlerts(vault.dbPath) }.getOrDefault(emptyList())
    }

    /**
     * After a sync round brought changes: a manager's device answers the
     * members' key requests (leave, rotation) with a new key, then the state
     * is read again. Blocking; returns the keys renewed.
     */
    fun afterRound(s: Session): List<FfiRekeyNotice> {
        val notices = runCatching { s.processRekeyRequests(now()) }.getOrDefault(emptyList())
        if (notices.isNotEmpty()) {
            Log.i(TAG, "vault keys renewed: ${notices.size}")
            sync.localChange()
        }
        readNow(s)
        changed()
        return notices
    }

    fun clear() {
        snapshot = SharingSnapshot()
        inviter?.cancel()
        inviter = null
        invitees.forEach { it.cancel() }
        invitees.clear()
    }

    // ---- servers -------------------------------------------------------------------------

    /** The servers this device trusts already: the account's mailbox (with its CA). */
    fun knownServers(): List<FfiMailboxEndpoint> = when (val b = sync.backend) {
        is SyncBackendState.Mailbox -> listOf(b.home.endpoint)
        else -> emptyList()
    }

    /** Where this account's invitations live: its own mailbox server, else the hosted instance. */
    fun inviteServer(): FfiMailboxEndpoint = knownServers().firstOrNull() ?: FfiMailboxEndpoint(MailboxEndpoints.HOSTED, null)

    // ---- invitations ---------------------------------------------------------------------

    private val pending = object : PendingInviteStore {
        override fun put(rdvHex: String, server: FfiMailboxEndpoint, bytes: ByteArray) {
            val plain = ByteArrayOutputStream().use { b ->
                DataOutputStream(b).use { out ->
                    out.writeByte(1)
                    out.writeUTF(server.baseUrl)
                    out.writeUTF(server.extraCaPem ?: "")
                    out.writeInt(bytes.size)
                    out.write(bytes)
                }
                b.toByteArray()
            }
            try {
                vault.sealFile(name(rdvHex), plain)
            } finally {
                plain.fill(0)
            }
        }

        override fun all(): List<Triple<String, FfiMailboxEndpoint, ByteArray>> =
            (app.noBackupFilesDir.listFiles { f: File -> f.name.startsWith("invite-") && f.name.endsWith(".bin") } ?: emptyArray()).mapNotNull { f ->
                val rdv = f.name.removePrefix("invite-").removeSuffix(".bin")
                val plain = runCatching { vault.unsealFile(f.name) }.getOrNull() ?: return@mapNotNull null
                try {
                    DataInputStream(plain.inputStream()).use { input ->
                        if (input.readByte().toInt() != 1) return@mapNotNull null
                        val url = input.readUTF()
                        val ca = input.readUTF().ifEmpty { null }
                        val bytes = ByteArray(input.readInt()).also { input.readFully(it) }
                        Triple(rdv, FfiMailboxEndpoint(url, ca), bytes)
                    }
                } finally {
                    plain.fill(0)
                }
            }

        override fun delete(rdvHex: String) = vault.deleteFile(name(rdvHex))

        private fun name(rdv: String) = "invite-" + rdv.filter { it.isLetterOrDigit() } + ".bin"
    }

    private fun flow(s: Session, myName: String): ContactInviteFlow? {
        val handle = sync.zoneHandle ?: return null
        return ContactInviteFlow(s, myName, CoreInviteDrops, ContactZoneCreator(handle), pending).also { f ->
            f.onState { st ->
                if (st is ContactInviteFlow.State.Done) {
                    sync.localChange()
                    readNow(vault.session)
                }
                changed()
            }
        }
    }

    /** "Créer un lien": a new invitation on this account's server; the reply is awaited. */
    fun createInvite(myName: String): ContactInviteFlow? {
        val s = vault.session ?: return null
        val f = flow(s, myName) ?: return null
        inviter?.cancel()
        inviter = f
        val server = inviteServer()
        f.createInvite(server, InviteServer.linkHost(server.baseUrl, MailboxEndpoints.HOSTED))
        return f
    }

    /** A link was opened or pasted: the reply is written, the answer awaited. Locked: kept for the unlock. */
    fun openLink(link: String, myName: String): ContactInviteFlow? {
        val s = vault.session ?: run {
            pendingLink = link
            return null
        }
        val f = flow(s, myName) ?: return null
        invitees += f
        f.open(link, InviteServer.endpoint(link, MailboxEndpoints.HOSTED, knownServers()))
        return f
    }

    /** At unlock: the replies written before a restart are awaited again. */
    fun resumePending(myName: String) {
        val s = vault.session ?: return
        worker.execute {
            for ((rdv, server, bytes) in pending.all()) {
                if (invitees.any { it.state is ContactInviteFlow.State.WaitingForAnswer }) break
                val f = flow(s, myName) ?: return@execute
                invitees += f
                f.resume(rdv, server, bytes)
            }
        }
    }

    // ---- recovery --------------------------------------------------------------------------

    /** "Annuler la récupération" on this device: signed by its keys, no password. Blocking. */
    fun cancelRecovery(enrollmentId: String) {
        val keys = vault.deviceKeys()
        try {
            me.somalabs.onepass.core.cancelRecovery(vault.dbPath, enrollmentId, keys.classical, keys.pq, now())
        } finally {
            keys.classical.fill(0)
        }
        sync.localChange()
        readNow(vault.session)
        changed()
    }

    companion object {
        private const val TAG = "OnePassSharing"

        fun now() = System.currentTimeMillis() / 1000

        @Volatile
        private var instance: Sharing? = null

        fun get(context: Context): Sharing =
            instance ?: synchronized(this) {
                instance ?: Sharing(context.applicationContext).also { instance = it }
            }
    }
}
