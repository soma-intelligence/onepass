package me.somalabs.onepass

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import java.io.File
import java.util.concurrent.Executors
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItem
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.createAccount
import me.somalabs.onepass.vaultkit.core.CoreLoader
import me.somalabs.onepass.wifi.VaultWifi
import me.somalabs.onepass.wifi.WifiAutomation

/**
 * Debug only. A throwaway vault in the app's no-backup files with test
 * routers, synced through the real path (core session, VaultWifi,
 * WifiAutomation), then back to the settings screen.
 *
 * - `seed`: Maison-Test (WPA2), Studio-Test (WPA3), Atelier-Test (WPA2,
 *   hidden), Cafe-Test (open), Bureau-Test (enterprise), Vieux-Test (WEP):
 *   3 suggestions.
 * - `edit`: Maison-Test gets a new password, Studio-Test goes to the trash,
 *   Chalet-Test (WPA3) arrives.
 * - `clear`: every router leaves the vault.
 */
class WifiDemoActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val step = intent.getStringExtra("step") ?: "seed"
        val wifi = WifiAutomation.get(this)
        val dir = noBackupFilesDir
        worker.execute {
            CoreLoader.ensureLoaded()
            val session = DemoVault.session(dir)
            when (step) {
                "seed" -> DemoVault.seed(session)
                "edit" -> DemoVault.edit(session)
                "clear" -> DemoVault.clear(session)
            }
            VaultWifi.opened(wifi, session)
            runOnUiThread {
                startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP))
                finish()
            }
        }
    }

    private companion object {
        val worker = Executors.newSingleThreadExecutor()
    }
}

private object DemoVault {
    // Test value for this throwaway debug vault only.
    private const val PASSWORD = "wifi-demo-master-1"
    private var session: Session? = null

    fun session(dir: File): Session = session ?: run {
        val db = File(dir, "wifi-demo.db")
        db.delete()
        createAccount(db.path, PASSWORD).session.also { session = it }
    }

    fun seed(s: Session) {
        clear(s)
        add(s, "Maison-Test", "maison-test-pass-1", "WPA2")
        add(s, "Studio-Test", "studio-test-pass-1", "WPA3")
        add(s, "Atelier-Test", "atelier-test-pass-1", "WPA2", hidden = true)
        add(s, "Cafe-Test", "", "Ouvert")
        add(s, "Bureau-Test", "bureau-test-pass-1", "WPA2-Enterprise")
        add(s, "Vieux-Test", "vieux-test-pass-1", "WEP")
    }

    fun edit(s: Session) {
        for (item in routers(s)) {
            when (item.title) {
                "Maison-Test" -> s.saveItem(set(item, mapOf("wifi_password" to "maison-test-pass-2")))
                "Studio-Test" -> s.trashItem(item.vaultId, item.id)
            }
        }
        add(s, "Chalet-Test", "chalet-test-pass-1", "WPA3")
    }

    fun clear(s: Session) {
        for (item in routers(s)) s.deleteItem(item.vaultId, item.id)
    }

    private fun routers(s: Session): List<FfiItem> =
        s.itemSummaries().filter { it.itemType == FfiItemType.ROUTER && it.trashedAt == null }
            .map { s.item(it.vaultId, it.id) }

    private fun add(s: Session, ssid: String, password: String, security: String, hidden: Boolean = false) {
        val vault = s.vaults().first()
        val values = buildMap {
            put("ssid", ssid)
            put("wifi_password", password)
            put("security", security)
            put("hidden", if (hidden) "oui" else "non")
        }
        s.saveItem(set(s.newItem(vault.id, FfiItemType.ROUTER, ssid), values))
    }

    private fun set(item: FfiItem, values: Map<String, String>): FfiItem =
        item.copy(
            sections = item.sections.map { section ->
                section.copy(
                    fields = section.fields.map { field ->
                        val v = values[field.id] ?: return@map field
                        field.copy(
                            value = when (field.id) {
                                "wifi_password" -> FfiFieldValue.Password(v)
                                "security", "hidden" -> FfiFieldValue.Menu(v)
                                else -> FfiFieldValue.Text(v)
                            },
                        )
                    },
                )
            },
        )
}
