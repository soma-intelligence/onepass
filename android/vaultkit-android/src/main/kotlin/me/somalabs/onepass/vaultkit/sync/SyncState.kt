package me.somalabs.onepass.vaultkit.sync

import java.net.URI
import java.util.Base64
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.FfiSyncBackend
import me.somalabs.onepass.core.SyncStoreHandle

/**
 * The Cleon server URLs the app accepts (iOS `MailboxEndpoints`).
 *
 * The hosted instance is the default of a new account, as on iPhone. A
 * self-hosted server is any `https://` base URL, with the PEM of a CA trusted
 * on top of the web roots when its certificate is not a public one. Debug and
 * release builds follow the same rule: a test mailbox reached through
 * `adb reverse` is `https://localhost:PORT/functions/v1/mailbox` with the
 * test CA, which passes it.
 */
object MailboxEndpoints {
    const val HOSTED = "https://mailbox.somalabs.me/functions/v1/mailbox"

    /**
     * `https`, a host, no user info, query or fragment, at most 256 bytes and
     * printable ASCII (the core's rule for a signed home).
     */
    fun validate(text: String): Boolean {
        if (text.length > 256 || text.contains('\\') || text.any { it.code !in 0x21..0x7e }) return false
        val uri = runCatching { URI(text) }.getOrNull() ?: return false
        return uri.scheme == "https" && !uri.host.isNullOrEmpty() && uri.rawUserInfo == null &&
            uri.rawQuery == null && uri.rawFragment == null
    }

    /** "Serveur Cleon" for the hosted instance, the host of a self-host. */
    fun displayName(url: String, hostedName: String): String =
        if (url == HOSTED) hostedName else runCatching { URI(url).host }.getOrNull() ?: url

    /** Trims a pasted CA: null when empty. */
    fun pem(text: String?): String? = text?.trim()?.takeIf { it.isNotEmpty() }
}

/**
 * A mailbox an account syncs with: the base URL as the signed home names it,
 * the mailbox id (32 hex characters) and, for a self-host, the PEM of a CA.
 */
data class MailboxHome(val baseUrl: String, val mailboxId: String, val extraCaPem: String? = null) {
    val endpoint: FfiMailboxEndpoint get() = FfiMailboxEndpoint(baseUrl, extraCaPem)
    val backend: FfiSyncBackend get() = FfiSyncBackend.Mailbox(baseUrl, mailboxId)
}

/** Where a new account keeps its encrypted vault (iOS `SyncChoice`, without iCloud). */
sealed class SyncChoice {
    /** The Cleon server hosted by Soma Labs (default). */
    object Hosted : SyncChoice()

    /** The user's own server. */
    data class SelfHost(val url: String, val extraCaPem: String?) : SyncChoice()

    /** Android has no iCloud: an account may also stay on this device only. */
    object Local : SyncChoice()

    val endpoint: FfiMailboxEndpoint?
        get() = when (this) {
            Hosted -> FfiMailboxEndpoint(MailboxEndpoints.HOSTED, null)
            is SelfHost -> FfiMailboxEndpoint(url, extraCaPem)
            Local -> null
        }

    companion object {
        val DEFAULT: SyncChoice = Hosted
    }
}

/**
 * Where this store's account syncs, as the app last decided it (store meta
 * `sync.backend`, iOS `SyncBackendState`). A store without it stays on this
 * device.
 */
sealed class SyncBackendState {
    object Local : SyncBackendState()
    data class Mailbox(val home: MailboxHome) : SyncBackendState()

    /** A setup that has not finished: it resumes at the next unlock. */
    data class PendingSetup(val choice: SyncChoice) : SyncBackendState()

    fun displayName(hostedName: String, localName: String): String = when (this) {
        Local -> localName
        is Mailbox -> MailboxEndpoints.displayName(home.baseUrl, hostedName)
        is PendingSetup -> when (val c = choice) {
            SyncChoice.Hosted -> hostedName
            is SyncChoice.SelfHost -> MailboxEndpoints.displayName(c.url, hostedName)
            SyncChoice.Local -> localName
        }
    }

    companion object {
        /** Store meta key (the handle namespaces it under `sync.`). */
        const val META_KEY = "backend"

        fun read(store: SyncStoreHandle): SyncBackendState = decode(store.meta(META_KEY))

        fun write(state: SyncBackendState, store: SyncStoreHandle) = store.setMeta(META_KEY, encode(state))

        fun encode(state: SyncBackendState): ByteArray {
            val fields = linkedMapOf<String, String>()
            when (state) {
                Local -> fields["kind"] = "local"
                is Mailbox -> {
                    fields["kind"] = "mailbox"
                    fields["url"] = state.home.baseUrl
                    fields["mailbox"] = state.home.mailboxId
                    state.home.extraCaPem?.let { fields["ca"] = it }
                }
                is PendingSetup -> {
                    fields["kind"] = "pending"
                    putChoice(fields, state.choice)
                }
            }
            return Fields.encode(fields)
        }

        fun decode(bytes: ByteArray?): SyncBackendState {
            if (bytes == null || bytes.isEmpty()) return Local
            val f = Fields.decode(bytes)
            return when (f["kind"]) {
                "mailbox" -> Mailbox(MailboxHome(f.getValue("url"), f.getValue("mailbox"), f["ca"]))
                "pending" -> PendingSetup(choiceOf(f))
                else -> Local
            }
        }

        internal fun putChoice(fields: MutableMap<String, String>, choice: SyncChoice) {
            when (choice) {
                SyncChoice.Hosted -> fields["choice"] = "hosted"
                SyncChoice.Local -> fields["choice"] = "local"
                is SyncChoice.SelfHost -> {
                    fields["choice"] = "self"
                    fields["url"] = choice.url
                    choice.extraCaPem?.let { fields["ca"] = it }
                }
            }
        }

        internal fun choiceOf(f: Map<String, String>): SyncChoice = when (f["choice"]) {
            "self" -> SyncChoice.SelfHost(f.getValue("url"), f["ca"])
            "local" -> SyncChoice.Local
            else -> SyncChoice.Hosted
        }
    }
}

/**
 * A small key/value format for the store meta values: one `key=base64(value)`
 * line each (no JSON library on the JVM side of the tests).
 */
internal object Fields {
    fun encode(fields: Map<String, String>): ByteArray =
        fields.entries.joinToString("\n") { (k, v) -> k + "=" + Base64.getEncoder().encodeToString(v.toByteArray(Charsets.UTF_8)) }
            .toByteArray(Charsets.UTF_8)

    fun decode(bytes: ByteArray): Map<String, String> =
        String(bytes, Charsets.UTF_8).lineSequence().filter { '=' in it }.associate { line ->
            val k = line.substringBefore('=')
            k to String(Base64.getDecoder().decode(line.substringAfter('=')), Charsets.UTF_8)
        }
}

/**
 * Where this device keeps its mailbox credential seeds (iOS
 * `MailboxCredentialStore`): sealed by a hardware key in the app, in memory
 * in the tests. Never logged.
 */
interface MailboxCredentialStore {
    fun seed(mailboxId: String): ByteArray?
    fun store(seed: ByteArray, mailboxId: String)
    fun delete(mailboxId: String)
}

/** Tests only. */
class InMemoryCredentialStore : MailboxCredentialStore {
    private val seeds = mutableMapOf<String, ByteArray>()

    @Synchronized override fun seed(mailboxId: String) = seeds[mailboxId]?.copyOf()

    @Synchronized override fun store(seed: ByteArray, mailboxId: String) {
        seeds[mailboxId] = seed.copyOf()
    }

    @Synchronized override fun delete(mailboxId: String) {
        seeds.remove(mailboxId)?.fill(0)
    }
}
