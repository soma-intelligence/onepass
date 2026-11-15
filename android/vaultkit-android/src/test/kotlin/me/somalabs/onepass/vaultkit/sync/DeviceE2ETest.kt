package me.somalabs.onepass.vaultkit.sync

import java.io.File
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicReference
import me.somalabs.onepass.core.FfiDeviceKind
import me.somalabs.onepass.core.FfiDeviceMode
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.MailboxSync
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.generateClassicalDeviceKeys
import me.somalabs.onepass.core.generateSoftwarePqHalf
import me.somalabs.onepass.core.mailboxEnroll
import me.somalabs.onepass.core.mailboxGenerateCredential
import me.somalabs.onepass.core.normalizeSecretKey
import me.somalabs.onepass.core.openSoftwarePqHalf
import me.somalabs.onepass.core.restoreFromKit
import me.somalabs.onepass.vaultkit.core.CoreLoader
import me.somalabs.onepass.vaultkit.pairing.DeviceKeys
import me.somalabs.onepass.vaultkit.pairing.PairingJoinFlow
import me.somalabs.onepass.vaultkit.pairing.RendezvousPairingConnector
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable

/**
 * Manual end-to-end runs against a phone or an emulator syncing with the
 * PC's test mailbox (desktop `test-mailbox`, `adb reverse`): this JVM plays
 * the second device. Off unless ONEPASS_E2E is set; synthetic test accounts
 * only. Parameters come from a file named by ONEPASS_E2E (key=value lines:
 * mode, url, ca, sk, pw, code, out), never from the command line.
 */
@EnabledIfEnvironmentVariable(named = "ONEPASS_E2E", matches = ".+")
class DeviceE2ETest {
    private val conf: Map<String, String> = File(System.getenv("ONEPASS_E2E")!!).readLines()
        .filter { '=' in it }.associate { it.substringBefore('=') to it.substringAfter('=') }
    private val out = File(conf.getValue("out")).also { it.parentFile?.mkdirs() }
    private fun log(s: String) = out.appendText(s + "\n")
    private val endpoint get() = FfiMailboxEndpoint(conf.getValue("url"), File(conf.getValue("ca")).readText())

    private fun Session.titles() = itemSummaries().map { it.title }.sorted()

    private fun Session.addLogin(title: String) {
        val item = newItem(vaults()[0].id, FfiItemType.LOGIN, title)
        item.sections.flatMap { it.fields }.firstOrNull { it.id == "username" }?.value = FfiFieldValue.Text("pc@exemple.fr")
        saveItem(item)
    }

    /** Restore the phone's account from its kit, show what came, add an item, then follow for a while. */
    @Test
    fun restoreFromThePhonesKit() {
        if (conf["mode"] != "restore") return
        CoreLoader.ensureLoaded()
        val db = Files.createTempDirectory("e2e").resolve("pc.db").toString()
        val sk = normalizeSecretKey(conf.getValue("sk"))
        val restore = MailboxRestore(db, InMemoryCredentialStore(), hosted = null)
        val found = restore.locate(sk, endpoint) as RestoreSource.Found
        log("found mailbox")
        val k = DeviceKeys(generateClassicalDeviceKeys(), openSoftwarePqHalf(generateSoftwarePqHalf()))
        val (session, client) = restore.restore(found.home, sk) {
            restoreFromKit(db, conf.getValue("pw"), sk, k.classical, k.pq, "PC de test", FfiDeviceKind.WINDOWS, FfiDeviceMode.PERSONAL)
        }
        log("restored: " + session.titles())
        val sync = MailboxSyncCoordinator(client, found.home, "test", wakeStarter = { error("none") })
        sync.sessionUnlocked(session)
        sync.syncNow()
        log("status ${sync.status} awaitingPin=${runCatching { session.awaitingPin() }.getOrNull()}")
        var added = false
        val until = System.currentTimeMillis() + (conf["seconds"]?.toLong() ?: 240) * 1000
        while (System.currentTimeMillis() < until) {
            if (!added) {
                try {
                    session.addLogin("Depuis le PC")
                    added = true
                    log("added 'Depuis le PC'")
                } catch (e: OnePassException) {
                    log("add refused for now: ${e.javaClass.simpleName}")
                }
            }
            sync.syncNow()
            log("titles " + session.titles() + " status " + sync.status::class.simpleName)
            Thread.sleep(10_000)
        }
        sync.close()
    }

    /** Join the phone showing a code (Réglages > Appareils > Ajouter un appareil) over the rendezvous. */
    @Test
    fun joinThePhoneShowingACode() {
        if (conf["mode"] != "pair") return
        CoreLoader.ensureLoaded()
        val db = Files.createTempDirectory("e2e").resolve("pc.db").toString()
        val cred = mailboxGenerateCredential()
        val k = DeviceKeys(generateClassicalDeviceKeys(), openSoftwarePqHalf(generateSoftwarePqHalf()))
        val state = AtomicReference<PairingJoinFlow.State>()
        val flow = PairingJoinFlow(listOf(RendezvousPairingConnector(endpoint)), "PC de test", FfiDeviceKind.WINDOWS, k, cred.publicKey,
            { s -> state.set(s); log("state ${s::class.simpleName}" + ((s as? PairingJoinFlow.State.Comparing)?.let { " sas=" + it.sas } ?: "")) })
        flow.join(conf["codefile"]?.let { File(it).readText().trim() } ?: conf.getValue("code"))
        val until = System.currentTimeMillis() + 180_000
        while (state.get() !is PairingJoinFlow.State.Comparing && state.get() !is PairingJoinFlow.State.Failed && System.currentTimeMillis() < until) Thread.sleep(200)
        assertTrue(state.get() is PairingJoinFlow.State.Comparing, "state ${state.get()}")
        flow.confirmCode()
        while (state.get() !is PairingJoinFlow.State.ReceivedFull && state.get() !is PairingJoinFlow.State.Failed && System.currentTimeMillis() < until) Thread.sleep(200)
        val received = state.get() as PairingJoinFlow.State.ReceivedFull
        val enrollment = received.enrollment!!
        log("grant names the mailbox ${enrollment.home.backend}")
        val enrolled = runCatching { mailboxEnroll(cred.seed, enrollment.ticket, endpoint.extraCaPem) }
        log("enroll: " + (enrolled.exceptionOrNull()?.let { "refused (${(it as? OnePassException.MailboxUnavailable)?.reason ?: it.javaClass.simpleName})" } ?: "ok"))
        val (unlocked, _) = flow.importAndUnlock(db, conf.getValue("pw"))
        log("imported: " + unlocked.session.titles())
        enrolled.getOrNull()?.let { home ->
            val sync = MailboxSyncCoordinator(MailboxSync.open(db, endpoint, home.mailboxId, cred.seed), MailboxHome(home.baseUrl, home.mailboxId, endpoint.extraCaPem), "test", wakeStarter = { error("none") })
            sync.sessionUnlocked(unlocked.session)
            sync.syncNow()
            log("synced: " + unlocked.session.titles() + " " + sync.status)
            sync.close()
        }
    }
}
