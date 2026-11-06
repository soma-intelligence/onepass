package me.somalabs.onepass.vaultkit.core

import java.nio.file.Path
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItem
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.FfiKdfParams
import me.somalabs.onepass.core.FfiWifiSecurity
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.createAccountWithKdfBytes
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

/**
 * Automatic Wi-Fi's selection, through the Kotlin bindings: which Router
 * items Android gets (`Session.wifiNetworks`, shared model of the core).
 */
class WifiNetworksTest {
    companion object {
        private val FAST_KDF = FfiKdfParams(mKib = 8192u, t = 1u, p = 1u)

        @JvmStatic
        @BeforeAll
        fun loadCore() {
            CoreLoader.ensureLoaded()
        }
    }

    @TempDir
    lateinit var dir: Path

    private lateinit var session: Session

    @BeforeEach
    fun open() {
        val created = createAccountWithKdfBytes(
            dir.resolve("vault.db").toString(),
            "correct horse battery staple".toByteArray(Charsets.UTF_8),
            FAST_KDF,
        )
        session = created.session
    }

    @AfterEach
    fun close() {
        session.close()
    }

    private fun router(ssid: String, password: String, security: String, hidden: String = "non"): FfiItem {
        val vault = session.vaults().first()
        val values = mapOf("ssid" to ssid, "wifi_password" to password, "security" to security, "hidden" to hidden)
        val item = session.newItem(vault.id, FfiItemType.ROUTER, ssid)
        return session.saveItem(
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
            ),
        )
    }

    @Test
    fun keepsPersonalNetworksAndLeavesOutOpenWepAndEnterprise() {
        router("Home-Test", "home-test-pass-1", "WPA2")
        router("Studio-Test", "studio-test-pass-1", "WPA3", hidden = "oui")
        router("Cafe-Test", "", "Ouvert")
        router("Old-Test", "old-test-pass-1", "WEP")
        router("Corp-Test", "corp-test-pass-1", "WPA2-Enterprise")
        router("Short-Test", "short", "WPA2")

        val selection = session.wifiNetworks(emptyList())
        assertEquals(listOf("Home-Test", "Studio-Test"), selection.networks.map { it.ssid })
        val studio = selection.networks.last()
        assertEquals(FfiWifiSecurity.WPA3_PERSONAL, studio.security)
        assertTrue(studio.hidden)
        assertEquals("studio-test-pass-1", studio.psk)
        assertEquals(1u, selection.skipped["open"])
        assertEquals(1u, selection.skipped["wep"])
        assertEquals(1u, selection.skipped["enterprise"])
        assertEquals(1u, selection.skipped["bad_password"])
    }

    @Test
    fun theFingerprintMovesWithAnEditAndNeverHoldsThePassword() {
        val saved = router("Home-Test", "home-test-pass-1", "WPA2")
        val before = session.wifiNetworks(emptyList()).networks.single()
        assertFalse(before.fingerprint.contains("home-test-pass-1"))

        // Unchanged vault, same fingerprint.
        assertEquals(before.fingerprint, session.wifiNetworks(emptyList()).networks.single().fingerprint)

        Thread.sleep(5)
        session.saveItem(
            saved.copy(
                sections = saved.sections.map { s ->
                    s.copy(fields = s.fields.map { f -> if (f.id == "wifi_password") f.copy(value = FfiFieldValue.Password("home-test-pass-2")) else f })
                },
            ),
        )
        val after = session.wifiNetworks(emptyList()).networks.single()
        assertEquals("home-test-pass-2", after.psk)
        assertNotEquals(before.fingerprint, after.fingerprint)
    }

    @Test
    fun trashedItemsAndHiddenVaultsLeave() {
        val home = router("Home-Test", "home-test-pass-1", "WPA2")
        assertEquals(1, session.wifiNetworks(emptyList()).networks.size)
        assertTrue(session.wifiNetworks(listOf(home.vaultId)).networks.isEmpty())

        session.trashItem(home.vaultId, home.id)
        assertTrue(session.wifiNetworks(emptyList()).networks.isEmpty())
    }
}
