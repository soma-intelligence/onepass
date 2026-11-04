package me.somalabs.onepass.wifi

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** A WifiManager in memory: what Android would hold for this app. */
private class FakePort(
    override val replacesInPlace: Boolean = true,
    var listable: Boolean = true,
) : SuggestionPort {
    val held = LinkedHashMap<NetworkKey, WifiNetwork>()
    val calls = mutableListOf<String>()
    var refuseSsids = setOf<String>()
    var approvalState = SuggestionApproval.PENDING

    override fun installedSsids(): Set<String>? = if (listable) held.keys.map { it.ssid }.toSet() else null

    override fun add(networks: List<WifiNetwork>): PortResult {
        calls += "add " + networks.joinToString(",") { it.ssid }
        if (networks.any { it.ssid in refuseSsids }) return PortResult.Refused("invalid network")
        if (!replacesInPlace && networks.any { it.key in held }) return PortResult.Refused("duplicate")
        networks.forEach { held[it.key] = it }
        return PortResult.Ok
    }

    override fun remove(keys: List<NetworkKey>): PortResult {
        calls += "remove " + keys.joinToString(",") { it.ssid }
        keys.forEach { held.remove(it) }
        return PortResult.Ok
    }

    override fun removeAll(): PortResult {
        calls += "removeAll"
        held.clear()
        return PortResult.Ok
    }

    override fun approval(): SuggestionApproval = approvalState
}

private class MemoryLedger : SyncLedger {
    var entries: Map<NetworkKey, String> = emptyMap()
    override fun read(): Map<NetworkKey, String> = entries
    override fun write(entries: Map<NetworkKey, String>) {
        this.entries = entries.toMap()
    }
    override var approvalNoticeShown: Boolean = false
}

/** Stands in for the keyed HMAC: deterministic, and changes with the passphrase. */
private val fakeFingerprint = Fingerprinter { "${it.security}|${it.ssid}|${it.hidden}|${it.passphrase.hashCode()}" }

class WifiAutoSyncTest {
    private fun router(ssid: String, password: String = "test-pass-123", security: String = "WPA2", id: String = ssid) =
        RouterRecord(id, ssid, password, security, "non")

    private val home = router("Home-Test")
    private val studio = router("Studio-Test", security = "WPA3")
    private val cafe = router("Cafe-Test", password = "", security = "Ouvert")

    @Test
    fun installsTheVaultNetworksOnce() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger(), fakeFingerprint)

        val first = sync.sync(listOf(home, studio, cafe), enabled = true)
        assertEquals(2, first.installed)
        assertEquals(2, first.added)
        assertEquals(setOf("Home-Test", "Studio-Test"), port.held.keys.map { it.ssid }.toSet())

        port.calls.clear()
        val second = sync.sync(listOf(home, studio, cafe), enabled = true)
        assertTrue(port.calls.isEmpty(), "a second sync with the same vault touches nothing: ${port.calls}")
        assertEquals(0, second.added + second.updated + second.removed)
        assertEquals(2, second.installed)
    }

    @Test
    fun addsNewRemovesDeletedUpdatesChanged() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger(), fakeFingerprint)
        sync.sync(listOf(home, studio), enabled = true)

        port.calls.clear()
        val office = router("Office-Test")
        val homeNewPass = router("Home-Test", password = "changed-pass-9")
        val report = sync.sync(listOf(homeNewPass, office), enabled = true)

        assertEquals(1, report.added)
        assertEquals(1, report.updated)
        assertEquals(1, report.removed)
        assertEquals(setOf("Home-Test", "Office-Test"), port.held.keys.map { it.ssid }.toSet())
        assertEquals("changed-pass-9", port.held[NetworkKey("Home-Test", WifiSecurity.WPA2)]!!.passphrase)
        // Android 11+: the changed network is re-added in place, never removed first.
        assertEquals(listOf("remove Studio-Test", "add Home-Test", "add Office-Test"), port.calls)
    }

    @Test
    fun onAndroid10AChangedNetworkIsRemovedThenAdded() {
        val port = FakePort(replacesInPlace = false, listable = false)
        val sync = WifiAutoSync(port, MemoryLedger(), fakeFingerprint)
        sync.sync(listOf(home), enabled = true)

        port.calls.clear()
        val report = sync.sync(listOf(router("Home-Test", password = "changed-pass-9")), enabled = true)
        assertEquals(listOf("remove Home-Test", "add Home-Test"), port.calls)
        assertEquals(1, report.updated)
        assertEquals("changed-pass-9", port.held.values.single().passphrase)
    }

    @Test
    fun aSecurityChangeIsANewKey() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger(), fakeFingerprint)
        sync.sync(listOf(home), enabled = true)
        sync.sync(listOf(router("Home-Test", security = "WPA3")), enabled = true)
        assertEquals(listOf(NetworkKey("Home-Test", WifiSecurity.WPA3)), port.held.keys.toList())
    }

    @Test
    fun turningTheSwitchOffRemovesEverythingAndOnBringsItBack() {
        val port = FakePort()
        val ledger = MemoryLedger()
        val sync = WifiAutoSync(port, ledger, fakeFingerprint)
        sync.sync(listOf(home, studio), enabled = true)

        val off = sync.sync(listOf(home, studio), enabled = false)
        assertFalse(off.enabled)
        assertEquals(0, off.installed)
        assertEquals(2, off.removed)
        assertTrue(port.held.isEmpty())
        assertTrue(ledger.entries.isEmpty())

        // Off twice: nothing to remove, no call.
        port.calls.clear()
        sync.disable()
        assertTrue(port.calls.isEmpty())

        assertEquals(2, sync.sync(listOf(home, studio), enabled = true).installed)
    }

    @Test
    fun anEmptyVaultLeavesNoSuggestion() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger(), fakeFingerprint)
        sync.sync(listOf(home, studio), enabled = true)
        val report = sync.sync(emptyList(), enabled = true)
        assertEquals(2, report.removed)
        assertTrue(port.held.isEmpty())
    }

    @Test
    fun suggestionsLostByTheSystemAreInstalledAgain() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger(), fakeFingerprint)
        sync.sync(listOf(home, studio), enabled = true)

        port.held.clear() // e.g. Android dropped them
        port.calls.clear()
        val report = sync.sync(listOf(home, studio), enabled = true)
        assertEquals(listOf("removeAll", "add Home-Test,Studio-Test"), port.calls)
        assertEquals(2, report.installed)
        assertEquals(2, report.added)
    }

    @Test
    fun oneRefusedNetworkDoesNotKeepTheOthersOff() {
        val port = FakePort().apply { refuseSsids = setOf("Studio-Test") }
        val ledger = MemoryLedger()
        val sync = WifiAutoSync(port, ledger, fakeFingerprint)
        val report = sync.sync(listOf(home, studio), enabled = true)

        assertEquals(1, report.installed)
        assertEquals("invalid network", report.failure)
        assertEquals(setOf("Home-Test"), ledger.entries.keys.map { it.ssid }.toSet())

        // Once Android accepts it, the next sync installs only the missing one.
        port.refuseSsids = emptySet()
        port.calls.clear()
        val again = sync.sync(listOf(home, studio), enabled = true)
        assertEquals(listOf("add Studio-Test"), port.calls)
        assertNull(again.failure)
        assertEquals(2, again.installed)
    }

    @Test
    fun theApprovalNoticeShowsExactlyOnce() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger(), fakeFingerprint)

        // Nothing to suggest yet: no notice.
        assertFalse(sync.sync(listOf(cafe), enabled = true).showApprovalNotice)
        assertTrue(sync.sync(listOf(home), enabled = true).showApprovalNotice)
        assertFalse(sync.sync(listOf(home, studio), enabled = true).showApprovalNotice)
    }

    @Test
    fun noApprovalNoticeOnceAndroidApproved() {
        val port = FakePort().apply { approvalState = SuggestionApproval.APPROVED }
        val sync = WifiAutoSync(port, MemoryLedger(), fakeFingerprint)
        val report = sync.sync(listOf(home), enabled = true)
        assertFalse(report.showApprovalNotice)
        assertEquals(SuggestionApproval.APPROVED, report.approval)
    }

    @Test
    fun planOfIsPureAndOrdered() {
        val desired = WifiSelection.select(listOf(home, studio))
        val ledger = mapOf(
            NetworkKey("Zeta-Test", WifiSecurity.WPA2) to "x",
            NetworkKey("Alpha-Test", WifiSecurity.WPA2) to "y",
        )
        val plan = SyncPlan.of(desired, ledger, installedSsids = null, fingerprinter = fakeFingerprint)
        assertEquals(listOf("Home-Test", "Studio-Test"), plan.add.map { it.ssid })
        assertEquals(listOf("Alpha-Test", "Zeta-Test"), plan.remove.map { it.ssid })
        assertTrue(plan.update.isEmpty())
        assertFalse(plan.rebuild)
        assertTrue(SyncPlan.of(emptyList(), emptyMap(), emptySet(), fakeFingerprint).isEmpty)
    }
}
