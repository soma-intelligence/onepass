package me.somalabs.onepass.wifi

import android.content.Context
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Automatic Wi-Fi on Android: the app's one entry point.
 *
 * The app calls [vaultChanged] with every router item after each unlock and
 * each change of the vault, and sets [routerSource] while a vault is open so
 * turning the switch back on installs at once. Nothing else: no button, no
 * screen to visit. Android shows its "allow suggested networks" prompt once,
 * by itself, the first time a suggested network is in range.
 */
class WifiAutomation private constructor(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val engine = WifiAutoSync(AndroidSuggestionPort(context), PrefsLedger(prefs), KeystoreFingerprinter())
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "onepass-wifi").apply { isDaemon = true } }
    private val main = Handler(Looper.getMainLooper())

    /** The router items of the open vault, or null while it is locked. */
    @Volatile
    var routerSource: (() -> List<RouterRecord>)? = null

    /** Called on the main thread after each sync. */
    @Volatile
    var onReport: ((SyncReport) -> Unit)? = null

    @Volatile
    var lastReport: SyncReport? = null
        private set

    /** "Wi-Fi automatique", on by default. */
    var enabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, true)
        set(value) {
            prefs.edit().putBoolean(KEY_ENABLED, value).apply()
            if (value) routerSource?.let { source -> submit { engine.sync(source(), true) } } else submit { engine.disable() }
        }

    /** The vault changed (unlock, save, trash, restore, archive, remote commit). */
    fun vaultChanged(records: List<RouterRecord>) {
        val on = enabled
        submit { engine.sync(records, on) }
    }

    /** Signing out of the account on this device: its networks leave too. */
    fun accountRemoved() {
        submit { engine.disable() }
    }

    private fun submit(block: () -> SyncReport) {
        worker.execute {
            val report = block()
            lastReport = report
            main.post { onReport?.invoke(report) }
        }
    }

    companion object {
        private const val PREFS = "onepass.wifi"
        private const val KEY_ENABLED = "auto"

        @Volatile
        private var instance: WifiAutomation? = null

        fun get(context: Context): WifiAutomation =
            instance ?: synchronized(this) {
                instance ?: WifiAutomation(context).also { instance = it }
            }
    }
}

/** The ledger in app preferences: base64 key, a colon, the fingerprint. */
internal class PrefsLedger(private val prefs: SharedPreferences) : SyncLedger {
    override fun read(): Map<NetworkKey, String> =
        prefs.getStringSet(KEY_LEDGER, emptySet()).orEmpty().mapNotNull { entry ->
            val colon = entry.lastIndexOf(':')
            if (colon <= 0) return@mapNotNull null
            val raw = try {
                String(Base64.decode(entry.substring(0, colon), Base64.NO_WRAP), Charsets.UTF_8)
            } catch (e: IllegalArgumentException) {
                return@mapNotNull null
            }
            NetworkKey.decode(raw)?.let { it to entry.substring(colon + 1) }
        }.toMap()

    override fun write(entries: Map<NetworkKey, String>) {
        val set = entries.map { (key, fp) ->
            Base64.encodeToString(key.encode().toByteArray(Charsets.UTF_8), Base64.NO_WRAP) + ":" + fp
        }.toSet()
        prefs.edit().putStringSet(KEY_LEDGER, set).commit()
    }

    override var approvalNoticeShown: Boolean
        get() = prefs.getBoolean(KEY_NOTICE, false)
        set(value) {
            prefs.edit().putBoolean(KEY_NOTICE, value).apply()
        }

    private companion object {
        const val KEY_LEDGER = "ledger"
        const val KEY_NOTICE = "approval_notice_shown"
    }
}

/** HMAC-SHA256 under a non-exportable Android Keystore key, first 16 bytes in hex. */
internal class KeystoreFingerprinter : Fingerprinter {
    override fun fingerprint(network: WifiNetwork): String {
        val mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256)
        mac.init(key())
        val input = listOf(network.security.name, network.ssid, network.hidden.toString(), network.passphrase)
            .joinToString("\u0000")
        val digest = mac.doFinal(input.toByteArray(Charsets.UTF_8))
        return digest.copyOf(16).joinToString("") { "%02x".format(it) }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE)
        generator.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN).build())
        return generator.generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "onepass.wifi.fingerprint"
    }
}
