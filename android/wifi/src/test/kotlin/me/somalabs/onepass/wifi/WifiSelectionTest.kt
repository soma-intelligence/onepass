package me.somalabs.onepass.wifi

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WifiSelectionTest {
    private fun router(
        ssid: String,
        password: String = "test-pass-123",
        security: String = "WPA2",
        hidden: String = "non",
        id: String = ssid,
        updatedAt: Long = 0,
        usable: Boolean = true,
        guestSsid: String = "",
        guestPassword: String = "",
    ) = RouterRecord(id, ssid, password, security, hidden, guestSsid, guestPassword, updatedAt, usable)

    @Test
    fun keepsWpa2AndWpa3PersonalNetworks() {
        val selected = WifiSelection.select(listOf(router("Home-Test"), router("Studio-Test", security = "WPA3")))
        assertEquals(
            listOf(NetworkKey("Home-Test", WifiSecurity.WPA2), NetworkKey("Studio-Test", WifiSecurity.WPA3)),
            selected.map { it.key },
        )
    }

    @Test
    fun leavesOutOpenWepAndEnterpriseNetworks() {
        val records = listOf(
            router("Cafe-Test", password = "", security = "Ouvert"),
            router("Open-Test", security = "open"),
            router("Old-Test", security = "WEP"),
            router("Corp-Test", security = "WPA2-Enterprise"),
            router("Corp2-Test", security = "WPA2 Entreprise"),
            router("Eap-Test", security = "EAP-TLS"),
            router("Dot1x-Test", security = "802.1X"),
            router("Weird-Test", security = "Kerberos"),
        )
        assertTrue(WifiSelection.select(records).isEmpty())
    }

    @Test
    fun mapsSecurityTexts() {
        assertEquals(WifiSecurity.WPA2, WifiSelection.securityOf("WPA", "x"))
        assertEquals(WifiSecurity.WPA2, WifiSelection.securityOf("wpa2-psk", "x"))
        assertEquals(WifiSecurity.WPA2, WifiSelection.securityOf("WPA2/WPA3", "x"))
        assertEquals(WifiSecurity.WPA3, WifiSelection.securityOf("WPA3", "x"))
        assertEquals(WifiSecurity.WPA3, WifiSelection.securityOf("SAE", "x"))
        assertEquals(WifiSecurity.WPA2, WifiSelection.securityOf("", "a password"))
        assertNull(WifiSelection.securityOf("", ""))
        assertNull(WifiSelection.securityOf("Aucune", "x"))
    }

    @Test
    fun needsAnSsidAndAPassphraseAndroidAccepts() {
        val records = listOf(
            router(""),
            router("   "),
            router("Short-Test", password = "1234567"),
            router("Long-Test", password = "z".repeat(64)),
            router("Accent-Test", password = "motdepassé1"),
            router("TooLongSsid-Test-0123456789-abcdef"),
        )
        assertTrue(WifiSelection.select(records).isEmpty())
        // 64 hex digits are a raw PSK.
        assertEquals(1, WifiSelection.select(listOf(router("Hex-Test", password = "0123456789abcdef".repeat(4)))).size)
        // WPA3 takes up to 128 characters.
        assertEquals(1, WifiSelection.select(listOf(router("Sae-Test", password = "b".repeat(100), security = "WPA3"))).size)
    }

    @Test
    fun readsTheHiddenFlag() {
        val selected = WifiSelection.select(listOf(router("Hidden-Test", hidden = "oui"), router("Shown-Test", hidden = "non")))
        assertTrue(selected.first { it.ssid == "Hidden-Test" }.hidden)
        assertFalse(selected.first { it.ssid == "Shown-Test" }.hidden)
    }

    @Test
    fun addsTheGuestNetworkOfTheSameRouter() {
        val selected = WifiSelection.select(
            listOf(router("Home-Test", guestSsid = "Home-Guest-Test", guestPassword = "guest-pass-1", hidden = "oui")),
        )
        assertEquals(listOf("Home-Guest-Test", "Home-Test"), selected.map { it.ssid })
        assertFalse(selected.first { it.ssid == "Home-Guest-Test" }.hidden)
    }

    @Test
    fun skipsItemsNoLongerUsable() {
        assertTrue(WifiSelection.select(listOf(router("Trashed-Test", usable = false))).isEmpty())
    }

    @Test
    fun theMostRecentlyEditedItemWinsADuplicateNetwork() {
        val selected = WifiSelection.select(
            listOf(
                router("Home-Test", password = "older-pass-1", id = "a", updatedAt = 10),
                router("Home-Test", password = "newer-pass-1", id = "b", updatedAt = 20),
                router("Home-Test", password = "oldest-pass-1", id = "c", updatedAt = 5),
            ),
        )
        assertEquals(1, selected.size)
        assertEquals("b", selected.single().itemId)
        assertEquals("newer-pass-1", selected.single().passphrase)
    }

    @Test
    fun neverPrintsThePassphrase() {
        val network = WifiSelection.select(listOf(router("Home-Test", password = "secret-pass-1"))).single()
        assertFalse(network.toString().contains("secret-pass-1"))
        assertFalse(router("Home-Test", password = "secret-pass-1").toString().contains("secret-pass-1"))
    }

    @Test
    fun networkKeysRoundTrip() {
        val key = NetworkKey("Café \t: Test", WifiSecurity.WPA3)
        assertEquals(key, NetworkKey.decode(key.encode()))
        assertNull(NetworkKey.decode("WPA9\tx"))
        assertNull(NetworkKey.decode("WPA2\t"))
    }
}
