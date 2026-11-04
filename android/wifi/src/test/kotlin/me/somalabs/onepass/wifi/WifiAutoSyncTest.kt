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
    var refuseAll = false
    var approvalState = SuggestionApproval.PENDING

    override fun installedSsids(): Set<String>? = if (listable) held.keys.map { it.ssid }.toSet() else null

    override fun add(networks: List<WifiNetwork>): PortResult {
        calls += "add " + networks.joinToString(",") { it.ssid }
        if (refuseAll) return PortResult.Refused("app disallowed")
        if (networks.any { it.ssid in refuseSsids }) return PortResult.Refused("invalid network")
        if (!replacesInPlace && networks.any { it.key in held }) return PortResult.Refused("duplicate")
        networks.forEach { held[it.key] = it }
        return PortResult.Ok
    }

    override fun remove(keys: List<NetworkKey>): PortResult {
        calls += "remove " + keys.joinToString(",") { "${it.ssid}/${it.security}" }
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
    var entries: Map<String, Applied> = emptyMap()
    override fun read(): Map<String, Applied> = entries
    override fun write(entries: Map<String, Applied>) {
        this.entries = entries.toMap()
    }
    override var approvalNoticeShown: Boolean = false
}

class WifiAutoSyncTest {
    /** As the core hands them over; the fingerprint moves with each edit of the item. */
    private fun net(ssid: String, version: Int = 1, security: WifiSecurity = WifiSecurity.WPA2, pass: String = "test-pass-$version") =
        WifiNetwork(ssid, pass, security, hidden = false, itemId = "item-$ssid", fingerprint = "$ssid-v$version")

    private val home = net("Home-Test")
    private val studio = net("Studio-Test", security = WifiSecurity.WPA3)

    @Test
    fun installsTheVaultNetworksOnce() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger())

        val first = sync.sync(listOf(home, studio), enabled = true)
        assertEquals(2, first.installed)
        assertEquals(2, first.added)
        assertEquals(setOf(home.key, studio.key), port.held.keys)

        port.calls.clear()
        val second = sync.sync(listOf(home, studio), enabled = true)
        assertTrue(port.calls.isEmpty(), "a second sync with the same vault touches nothing: ${port.calls}")
        assertEquals(0, second.added + second.updated + second.removed)
        assertEquals(2, second.installed)
    }

    @Test
    fun addsNewRemovesDeletedUpdatesChanged() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger())
        sync.sync(listOf(home, studio), enabled = true)

        port.calls.clear()
        val office = net("Office-Test")
        val homeEdited = net("Home-Test", version = 2)
        val report = sync.sync(listOf(homeEdited, office), enabled = true)

        assertEquals(1, report.added)
        assertEquals(1, report.updated)
        assertEquals(1, report.removed)
        assertEquals(setOf(home.key, office.key), port.held.keys)
        assertEquals("test-pass-2", port.held.getValue(home.key).passphrase)
        // Android 11+: the changed network is re-added in place, never removed first.
        assertEquals(listOf("remove Studio-Test/WPA3", "add Home-Test,Office-Test"), port.calls)
    }

    @Test
    fun onAndroid10AChangedNetworkIsRemovedThenAdded() {
        val port = FakePort(replacesInPlace = false, listable = false)
        val sync = WifiAutoSync(port, MemoryLedger())
        sync.sync(listOf(home), enabled = true)

        port.calls.clear()
        val report = sync.sync(listOf(net("Home-Test", version = 2)), enabled = true)
        assertEquals(listOf("remove Home-Test/WPA2", "add Home-Test"), port.calls)
        assertEquals(1, report.updated)
        assertEquals("test-pass-2", port.held.values.single().passphrase)
    }

    @Test
    fun aSecurityChangeReplacesTheOldAndroidKey() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger())
        sync.sync(listOf(home), enabled = true)

        port.calls.clear()
        sync.sync(listOf(net("Home-Test", version = 2, security = WifiSecurity.WPA3)), enabled = true)
        assertEquals(listOf("remove Home-Test/WPA2", "add Home-Test"), port.calls)
        assertEquals(listOf(NetworkKey("Home-Test", WifiSecurity.WPA3)), port.held.keys.toList())
    }

    @Test
    fun turningTheSwitchOffRemovesEverythingAndOnBringsItBack() {
        val port = FakePort()
        val ledger = MemoryLedger()
        val sync = WifiAutoSync(port, ledger)
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
        val sync = WifiAutoSync(port, MemoryLedger())
        sync.sync(listOf(home, studio), enabled = true)
        val report = sync.sync(emptyList(), enabled = true)
        assertEquals(2, report.removed)
        assertEquals(0, report.installed)
        assertTrue(port.held.isEmpty())
    }

    @Test
    fun suggestionsLostByTheSystemAreInstalledAgain() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger())
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
        val sync = WifiAutoSync(port, ledger)
        val report = sync.sync(listOf(home, studio), enabled = true)

        assertEquals(1, report.installed)
        assertEquals(1, report.added)
        assertEquals("invalid network", report.failure)
        assertEquals(setOf("Home-Test"), ledger.entries.keys)

        // Once Android accepts it, the next sync installs only the missing one.
        port.refuseSsids = emptySet()
        port.calls.clear()
        val again = sync.sync(listOf(home, studio), enabled = true)
        assertEquals(listOf("add Studio-Test"), port.calls)
        assertNull(again.failure)
        assertEquals(2, again.installed)
    }

    @Test
    fun aRefusedUpdateIsRetriedAtTheNextSync() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger())
        sync.sync(listOf(home), enabled = true)

        port.refuseAll = true
        val refused = sync.sync(listOf(net("Home-Test", version = 2)), enabled = true)
        assertEquals("app disallowed", refused.failure)
        assertEquals(0, refused.updated)

        port.refuseAll = false
        port.calls.clear()
        val retried = sync.sync(listOf(net("Home-Test", version = 2)), enabled = true)
        assertEquals(listOf("add Home-Test"), port.calls)
        assertEquals(1, retried.updated)
    }

    @Test
    fun theApprovalNoticeShowsExactlyOnce() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger())

        // Nothing to suggest yet: no notice.
        assertFalse(sync.sync(emptyList(), enabled = true).showApprovalNotice)
        assertTrue(sync.sync(listOf(home), enabled = true).showApprovalNotice)
        assertFalse(sync.sync(listOf(home, studio), enabled = true).showApprovalNotice)
    }

    @Test
    fun noApprovalNoticeOnceAndroidApproved() {
        val port = FakePort().apply { approvalState = SuggestionApproval.APPROVED }
        val report = WifiAutoSync(port, MemoryLedger()).sync(listOf(home), enabled = true)
        assertFalse(report.showApprovalNotice)
        assertEquals(SuggestionApproval.APPROVED, report.approval)
    }

    @Test
    fun planOfIsPureAndOrdered() {
        val ledger = mapOf(
            "Zeta-Test" to Applied(WifiSecurity.WPA2, "x"),
            "Alpha-Test" to Applied(WifiSecurity.WPA3, "y"),
            "Home-Test" to Applied(WifiSecurity.WPA2, "Home-Test-v0"),
        )
        val plan = SyncPlan.of(listOf(home, studio), ledger, installedSsids = null)
        assertEquals(listOf("Studio-Test"), plan.add.map { it.ssid })
        assertEquals(listOf("Home-Test"), plan.update.map { it.first.ssid })
        assertEquals(
            listOf(NetworkKey("Alpha-Test", WifiSecurity.WPA3), NetworkKey("Zeta-Test", WifiSecurity.WPA2)),
            plan.remove,
        )
        assertFalse(plan.rebuild)
        assertTrue(SyncPlan.of(emptyList(), emptyMap(), emptySet()).isEmpty)
    }

    @Test
    fun aRawHexKeyStaysOffAndroidWithoutFailing() {
        val port = FakePort()
        val sync = WifiAutoSync(port, MemoryLedger())
        val raw = net("Raw-Test", pass = "ab".repeat(32))
        val report = sync.sync(listOf(home, raw), enabled = true)
        assertEquals(setOf(home.key), port.held.keys)
        assertEquals(1, report.unsupported)
        assertNull(report.failure)
        // 63 or 65 characters are passphrases (or invalid), not raw keys.
        assertFalse(net("A", pass = "a".repeat(63)).hasRawKey)
        assertFalse(net("B", pass = "g".repeat(64)).hasRawKey)
        assertTrue(raw.hasRawKey)
    }

    @Test
    fun neverPrintsThePassphrase() {
        assertFalse(net("Home-Test", pass = "secret-pass-1").toString().contains("secret-pass-1"))
    }
}
