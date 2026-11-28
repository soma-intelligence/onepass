package me.somalabs.onepass.vaultkit.sync

import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference
import me.somalabs.onepass.core.FfiDeviceKind
import me.somalabs.onepass.core.FfiDeviceMode
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.FfiKdfParams
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.FfiRoundStatus
import me.somalabs.onepass.core.MailboxSync
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.createAccountV2
import me.somalabs.onepass.core.generateClassicalDeviceKeys
import me.somalabs.onepass.core.generateSoftwarePqHalf
import me.somalabs.onepass.core.mailboxEnroll
import me.somalabs.onepass.core.mailboxGenerateCredential
import me.somalabs.onepass.core.mailboxServerCheck
import me.somalabs.onepass.core.openSoftwarePqHalf
import me.somalabs.onepass.core.openSyncStore
import me.somalabs.onepass.core.restoreFromKit
import me.somalabs.onepass.vaultkit.core.CoreLoader
import me.somalabs.onepass.vaultkit.pairing.DeviceKeys
import me.somalabs.onepass.vaultkit.pairing.LoopbackDirectory
import me.somalabs.onepass.vaultkit.pairing.PairingHostFlow
import me.somalabs.onepass.vaultkit.pairing.PairingJoinFlow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.CleanupMode
import org.junit.jupiter.api.io.TempDir

/**
 * The Android sync engine against the core's fake mailbox (loopback TLS):
 * an account put on a mailbox, a second device restored from the Emergency
 * Kit, edits both ways through the coordinator, and a third device paired
 * over the local-network transport with the mailbox handed over. Synthetic
 * data only.
 */
class MailboxSyncTest {
    companion object {
        private val FAST_KDF = FfiKdfParams(mKib = 8192u, t = 1u, p = 1u)
        private const val PASSWORD = "correct horse battery staple"
        private lateinit var ep: FfiMailboxEndpoint

        @JvmStatic
        @BeforeAll
        fun start() {
            CoreLoader.ensureLoaded()
            ep = testMailboxStart()
        }
    }

    // Never deleted: Windows keeps the SQLite files of the sessions open until the process ends.
    @TempDir(cleanup = CleanupMode.NEVER)
    lateinit var dir: Path

    private class Device(val db: String, val session: Session, val secretKey: String, val keys: DeviceKeys)

    private fun keys() = DeviceKeys(generateClassicalDeviceKeys(), openSoftwarePqHalf(generateSoftwarePqHalf()))

    private fun newAccount(name: String): Device {
        val db = dir.resolve("$name.db").toString()
        val k = keys()
        val created = createAccountV2(db, PASSWORD, FAST_KDF, k.classical, k.pq, name, FfiDeviceKind.ANDROID, FfiDeviceMode.PERSONAL)
        return Device(db, created.session, created.secretKey, k)
    }

    private fun Session.addLogin(title: String) {
        val vault = vaults()[0].id
        val item = newItem(vault, FfiItemType.LOGIN, title)
        item.sections.flatMap { it.fields }.firstOrNull { it.id == "username" }?.value = FfiFieldValue.Text("camille@exemple.fr")
        saveItem(item)
    }

    private fun Session.titles() = itemSummaries().map { it.title }.sorted()

    private fun choice() = SyncChoice.SelfHost(ep.baseUrl, ep.extraCaPem)

    private fun setUp(d: Device, creds: MailboxCredentialStore): MailboxHome {
        val outcome = openSyncStore(d.db).use { MailboxSetup(d.db, creds, it).run(d.session, choice(), d.secretKey) }
        assertTrue(outcome is MailboxSetupOutcome.Ready, "setup: $outcome")
        return (outcome as MailboxSetupOutcome.Ready).home
    }

    private fun coordinator(d: Device, home: MailboxHome, creds: MailboxCredentialStore): MailboxSyncCoordinator {
        val seed = creds.seed(home.mailboxId)!!
        val sync = MailboxSync.open(d.db, home.endpoint, home.mailboxId, seed)
        return MailboxSyncCoordinator(sync, home, "test", debounceMs = 50, wakeStarter = { error("no wake channel") })
            .also { it.sessionUnlocked(d.session); it.syncNow() }
    }

    @Test
    fun theTestServerAnswersItsConfig() {
        assertTrue(mailboxServerCheck(ep).openSignup)
        // The hosted server is not up yet: a clear MailboxUnavailable, not a crash.
        assertThrows<OnePassException.MailboxUnavailable> {
            mailboxServerCheck(FfiMailboxEndpoint("https://localhost:1/functions/v1/mailbox", null))
        }
    }

    @Test
    fun setupResumesAfterACutWithoutASecondMailbox() {
        val a = newAccount("a")
        val creds = InMemoryCredentialStore()
        openSyncStore(a.db).use { store ->
            val setup = MailboxSetup(a.db, creds, store)
            setup.interruptAfter = MailboxSetup.Step.RECOVERY_GRANTED
            assertTrue(setup.run(a.session, choice(), a.secretKey) is MailboxSetupOutcome.Failed)
            val pending = SyncBackendState.read(store)
            assertTrue(pending is SyncBackendState.PendingSetup)
            assertTrue(setup.mailboxCreated())
            setup.interruptAfter = null
            val done = setup.run(a.session, choice(), a.secretKey) as MailboxSetupOutcome.Ready
            assertEquals(SyncBackendState.Mailbox(done.home), SyncBackendState.read(store))
            assertFalse(setup.inProgress())
            assertEquals(done.home.backend, a.session.syncHome()!!.backend)
        }
    }

    @Test
    fun anUnreachableServerLeavesTheAccountHereAndPending() {
        val a = newAccount("a")
        openSyncStore(a.db).use { store ->
            val setup = MailboxSetup(a.db, InMemoryCredentialStore(), store)
            val outcome = setup.run(a.session, SyncChoice.SelfHost("https://localhost:1/functions/v1/mailbox", null), a.secretKey)
            assertTrue(outcome is MailboxSetupOutcome.Offline, "outcome: $outcome")
            assertTrue(SyncBackendState.read(store) is SyncBackendState.PendingSetup)
            assertFalse(setup.mailboxCreated())
            setup.forget()
            assertFalse(setup.inProgress())
        }
        assertEquals(null, a.session.syncHome())
    }

    @Test
    fun restoreFromTheKitThenEditsBothWays() {
        // A: an account with an item, put on the mailbox.
        val a = newAccount("a")
        a.session.addLogin("Messagerie")
        val credsA = InMemoryCredentialStore()
        val home = setUp(a, credsA)
        val syncA = coordinator(a, home, credsA)
        assertEquals(SyncStatus.Idle::class, syncA.status::class)

        // B: a new device with nothing but the kit (Secret Key, master password, server).
        val dbB = dir.resolve("b.db").toString()
        val credsB = InMemoryCredentialStore()
        val restore = MailboxRestore(dbB, credsB, hosted = null)
        val found = restore.locate(a.secretKey, ep) as RestoreSource.Found
        assertEquals(home.mailboxId, found.home.mailboxId)
        // A wrong password: nothing granted, nothing stored.
        assertThrows<OnePassException.WrongPassword> {
            restore.restore(found.home, a.secretKey) {
                val k = keys()
                restoreFromKit(dbB, "wrong password here", a.secretKey, k.classical, k.pq, "B", FfiDeviceKind.ANDROID, FfiDeviceMode.PERSONAL)
            }
        }
        assertEquals(null, credsB.seed(home.mailboxId))
        val kb = keys()
        val (sessionB, clientB) = restore.restore(found.home, a.secretKey) {
            restoreFromKit(dbB, PASSWORD, a.secretKey, kb.classical, kb.pq, "Pixel B", FfiDeviceKind.ANDROID, FfiDeviceMode.PERSONAL)
        }
        assertEquals(listOf("Messagerie"), sessionB.titles())
        assertEquals(SyncBackendState.Mailbox(found.home), openSyncStore(dbB).use { SyncBackendState.read(it) })
        val syncB = MailboxSyncCoordinator(clientB, found.home, "test", debounceMs = 50, wakeStarter = { error("none") })
        syncB.sessionUnlocked(sessionB)
        syncB.syncNow()

        // A trusts the kit-restored device when it asks.
        syncA.syncNow()
        a.session.kitRestoredDevices().forEach { a.session.acceptKitRestored(it.id, a.keys.classical, a.keys.pq) }
        syncA.syncNow()
        syncB.syncNow()

        // An edit on A reaches B, and one on B reaches A; B's coordinator says something changed.
        val changedOnB = AtomicReference(false)
        syncB.onRemoteChange { changedOnB.set(true) }
        a.session.addLogin("Banque")
        syncA.localChangesWritten()
        Thread.sleep(300)
        syncA.syncNow()
        syncB.syncNow()
        assertTrue(changedOnB.get())
        assertEquals(listOf("Banque", "Messagerie"), sessionB.titles())
        sessionB.addLogin("Train")
        syncB.syncNow()
        syncA.syncNow()
        assertEquals(listOf("Banque", "Messagerie", "Train"), a.session.titles())
        assertEquals(SyncStatus.Idle::class, syncA.status::class)
        assertEquals(SyncStatus.Idle::class, syncB.status::class)
        assertEquals(1, syncA.maxConcurrentRounds)
        syncA.close()
        syncB.close()
    }

    @Test
    fun aKitNobodyKnowsIsNotFound() {
        val a = newAccount("a")
        val restore = MailboxRestore(dir.resolve("x.db").toString(), InMemoryCredentialStore(), hosted = null)
        assertEquals(RestoreSource.NotFound, restore.locate(a.secretKey, ep))
        val offline = MailboxRestore(dir.resolve("y.db").toString(), InMemoryCredentialStore(), hosted = null)
            .locate(a.secretKey, FfiMailboxEndpoint("https://localhost:1/functions/v1/mailbox", null))
        assertTrue(offline is RestoreSource.Offline)
    }

    @Test
    fun anOfflineRoundBacksOff() {
        val a = newAccount("a")
        val credsA = InMemoryCredentialStore()
        val home = setUp(a, credsA)
        val dead = MailboxHome("https://localhost:1/functions/v1/mailbox", home.mailboxId, null)
        val sync = MailboxSync.open(a.db, dead.endpoint, dead.mailboxId, credsA.seed(home.mailboxId)!!)
        val c = MailboxSyncCoordinator(sync, dead, "test", wakeStarter = { error("none") })
        c.sessionUnlocked(a.session)
        c.syncNow()
        val s = c.status
        assertTrue(s is SyncStatus.Offline || s is SyncStatus.Retrying || s is SyncStatus.HomeMoved, "status: $s")
        if (s !is SyncStatus.HomeMoved) {
            val delay = c.retryDelayMs()!!
            assertTrue(delay in 1..30_000, "first retry after 30 s: $delay")
        }
        c.close()
    }

    @Test
    fun pairingHandsOverTheAccountAndTheMailbox() {
        val a = newAccount("a")
        a.session.addLogin("Messagerie")
        val credsA = InMemoryCredentialStore()
        val home = setUp(a, credsA)
        val syncA = coordinator(a, home, credsA)

        val hostState = AtomicReference<PairingHostFlow.State>()
        val joinState = AtomicReference<PairingJoinFlow.State>()
        val host = PairingHostFlow(LoopbackDirectory.listener, { hostState.set(it) })
        host.start()
        val code = waitFor(hostState) { it is PairingHostFlow.State.Hosting } as PairingHostFlow.State.Hosting

        val dbC = dir.resolve("c.db").toString()
        val credC = mailboxGenerateCredential()
        val kc = keys()
        val join = PairingJoinFlow(listOf(LoopbackDirectory.connector), "Pixel C", FfiDeviceKind.ANDROID, kc, credC.publicKey, { joinState.set(it) })
        join.join(code.code.shortText)
        val sasC = (waitFor(joinState) { it is PairingJoinFlow.State.Comparing } as PairingJoinFlow.State.Comparing).sas
        val compare = waitFor(hostState) { it is PairingHostFlow.State.Comparing } as PairingHostFlow.State.Comparing
        assertEquals(compare.sas, sasC)
        assertEquals("Pixel C", compare.peer.name)

        join.confirmCode()
        val approving = Thread {
            host.approve(
                seal = { ap -> syncA.syncNow(); ap.sealFullGrant(a.session, a.secretKey, FfiDeviceMode.PERSONAL, false, syncA.client) },
                introduce = { ap -> ap.introduce(a.session, a.keys.classical, a.keys.pq) },
            )
        }.apply { start() }
        val received = waitFor(joinState) { it is PairingJoinFlow.State.ReceivedFull } as PairingJoinFlow.State.ReceivedFull
        val enrollment = received.enrollment!!
        assertEquals(home.backend, enrollment.home.backend)
        // The fake answers only credentials it already holds: an enroll ticket is refused there
        // (UnknownCredential), so A grants the credential C sent instead. The real server enrolls.
        val homeC = try {
            mailboxEnroll(credC.seed, enrollment.ticket, ep.extraCaPem)
        } catch (e: OnePassException.MailboxUnavailable) {
            assertTrue(e.reason.contains("UnknownCredential"), e.reason)
            syncA.client.grant(credC.publicKey, me.somalabs.onepass.core.FfiCredentialRole.WRITE, ByteArray(0))
            me.somalabs.onepass.core.FfiMailboxHome(home.baseUrl, home.mailboxId, 0u)
        }
        assertEquals(home.mailboxId, homeC.mailboxId)
        assertThrows<OnePassException.WrongPassword> { join.importAndUnlock(dbC, "wrong password here") }
        val (unlocked, secretKey) = join.importAndUnlock(dbC, PASSWORD)
        assertEquals(a.secretKey, secretKey)
        approving.join(30_000)
        assertTrue(hostState.get() is PairingHostFlow.State.Done, "host: ${hostState.get()}")
        val sessionC = unlocked.session
        assertTrue(a.session.devices().any { it.name == "Pixel C" })

        val syncC = MailboxSyncCoordinator(MailboxSync.open(dbC, ep, homeC.mailboxId, credC.seed), MailboxHome(homeC.baseUrl, homeC.mailboxId, ep.extraCaPem), "test", wakeStarter = { error("none") })
        syncC.sessionUnlocked(sessionC)
        syncA.syncNow()
        syncC.syncNow()
        assertEquals(listOf("Messagerie"), sessionC.titles())
        sessionC.addLogin("Train")
        syncC.syncNow()
        syncA.syncNow()
        assertEquals(listOf("Messagerie", "Train"), a.session.titles())
        assertTrue(syncC.status is SyncStatus.Idle, "C: ${syncC.status}")
        syncA.close()
        syncC.close()
    }

    @Test
    fun aWrongCodeFindsNobody() {
        val st = AtomicReference<PairingJoinFlow.State>()
        val join = PairingJoinFlow(listOf(LoopbackDirectory.connector), "X", FfiDeviceKind.ANDROID, keys(), null, { st.set(it) }, connectTimeoutMs = 500)
        join.join("12")
        val failed = waitFor(st) { it is PairingJoinFlow.State.Failed } as PairingJoinFlow.State.Failed
        assertEquals(me.somalabs.onepass.vaultkit.pairing.PairingFailure.BAD_CODE, failed.failure)
    }

    @Test
    fun backendStateRoundTrips() {
        val states = listOf(
            SyncBackendState.Local,
            SyncBackendState.Mailbox(MailboxHome("https://h/x", "ab".repeat(16), "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----")),
            SyncBackendState.PendingSetup(SyncChoice.Hosted),
            SyncBackendState.PendingSetup(SyncChoice.SelfHost("https://localhost:8443/functions/v1/mailbox", null)),
        )
        for (s in states) assertEquals(s, SyncBackendState.decode(SyncBackendState.encode(s)))
        assertEquals(SyncBackendState.Local, SyncBackendState.decode(null))
        assertTrue(MailboxEndpoints.validate("https://localhost:8443/functions/v1/mailbox"))
        assertTrue(MailboxEndpoints.validate(MailboxEndpoints.HOSTED))
        assertFalse(MailboxEndpoints.validate("http://localhost:8443/functions/v1/mailbox"))
        assertFalse(MailboxEndpoints.validate("https://user@host/x"))
        assertFalse(MailboxEndpoints.validate("https://host/x?q=1"))
        assertFalse(MailboxEndpoints.validate("https:///x"))
    }

    private fun <T> waitFor(ref: AtomicReference<T>, timeoutMs: Long = 30_000, ok: (T) -> Boolean): T {
        val until = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < until) {
            ref.get()?.let { v ->
                if (ok(v)) return v
                if (v is PairingHostFlow.State.Failed) error("host failed: ${v.failure} ${v.error}")
                if (v is PairingJoinFlow.State.Failed && !ok(v)) error("join failed: ${v.failure} ${v.error}")
            }
            Thread.sleep(20)
        }
        error("timeout, last state ${ref.get()}")
    }

    @Suppress("unused")
    private val roundStatusIdle = FfiRoundStatus.Idle
}
