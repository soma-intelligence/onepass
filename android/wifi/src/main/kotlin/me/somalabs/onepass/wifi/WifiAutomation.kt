package me.somalabs.onepass.wifi

import android.content.Context
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.util.Base64
import java.util.concurrent.Executors

/**
 * Automatic Wi-Fi on Android: the app's one entry point.
 *
 * The app calls [vaultChanged] with the vault's networks after each unlock and
 * each change of the vault, and sets [networkSource] while a vault is open so
 * turning the switch back on installs at once. Nothing else: no button, no
 * screen to visit. Android shows its "allow suggested networks" prompt once,
 * by itself, the first time a suggested network is in range.
 */
class WifiAutomation private constructor(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val engine = WifiAutoSync(AndroidSuggestionPort(context), PrefsLedger(prefs))
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "onepass-wifi").apply { isDaemon = true } }
    private val main = Handler(Looper.getMainLooper())

    /** The Wi-Fi networks of the open vault, or null while it is locked. */
    @Volatile
    var networkSource: (() -> List<WifiNetwork>)? = null

    /** Called on the main thread after each sync. */
    @Volatile
    var onReport: ((SyncReport) -> Unit)? = null

    @Volatile
    var lastReport: SyncReport? = null
        private set

    /** "Wi-Fi automatique", off by default. */
    var enabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, false)
        set(value) {
            prefs.edit().putBoolean(KEY_ENABLED, value).apply()
            if (value) networkSource?.let { source -> submit { engine.sync(source(), true) } } else submit { engine.disable() }
        }

    /** The vault changed (unlock, save, trash, restore, archive, remote commit). */
    fun vaultChanged(networks: List<WifiNetwork>) {
        val on = enabled
        submit { engine.sync(networks, on) }
    }

    /** Same, reading the networks through [networkSource] on the Wi-Fi thread. No-op while locked. */
    fun refresh() {
        val source = networkSource ?: return
        val on = enabled
        submit { engine.sync(source(), on) }
    }

    /** Signing out of the account on this device: its networks leave too. */
    fun accountRemoved() {
        submit { engine.disable() }
    }

    private fun submit(block: () -> SyncReport) {
        worker.execute {
            // A vault that locks meanwhile (or any core error) must not take the app down:
            // the next change of the vault syncs again.
            val report = try {
                block()
            } catch (e: Exception) {
                return@execute
            }
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

/** The ledger in app preferences: one entry per SSID. No secret. */
internal class PrefsLedger(private val prefs: SharedPreferences) : SyncLedger {
    override fun read(): Map<String, Applied> =
        prefs.getStringSet(KEY_LEDGER, emptySet()).orEmpty().mapNotNull { entry ->
            // base64(ssid) ":" security ":" fingerprint
            val parts = entry.split(':')
            if (parts.size != 3) return@mapNotNull null
            val ssid = try {
                String(Base64.decode(parts[0], Base64.NO_WRAP), Charsets.UTF_8)
            } catch (e: IllegalArgumentException) {
                return@mapNotNull null
            }
            val security = WifiSecurity.entries.firstOrNull { it.name == parts[1] } ?: return@mapNotNull null
            if (ssid.isEmpty()) null else ssid to Applied(security, parts[2])
        }.toMap()

    override fun write(entries: Map<String, Applied>) {
        val set = entries.map { (ssid, applied) ->
            Base64.encodeToString(ssid.toByteArray(Charsets.UTF_8), Base64.NO_WRAP) +
                ":" + applied.security.name + ":" + applied.fingerprint
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
