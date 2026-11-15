package me.somalabs.onepass.vaultkit.sharing

import java.io.File
import java.nio.file.Files
import me.somalabs.onepass.core.FfiDeviceKind
import me.somalabs.onepass.core.FfiDeviceMode
import me.somalabs.onepass.core.FfiFieldValue
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.FfiKdfParams
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.FfiRole
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.ZoneSyncHandle
import me.somalabs.onepass.core.createAccountV2
import me.somalabs.onepass.core.generateClassicalDeviceKeys
import me.somalabs.onepass.core.generateSoftwarePqHalf
import me.somalabs.onepass.core.openSoftwarePqHalf
import me.somalabs.onepass.core.openSyncStore
import me.somalabs.onepass.vaultkit.core.CoreLoader
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable

/**
 * Manual end-to-end run against a phone or an emulator whose account syncs
 * with the PC's test mailbox (desktop `test-mailbox`, `adb reverse`): this
 * JVM plays a contact, "Camille". It makes an invitation link (written to
 * `out`), answers the phone's reply, then follows for `minutes`: joins every
 * vault and family the phone invites it to, adds an item to a shared vault
 * it can write, and sends the phone one item. Off unless ONEPASS_SHARE_E2E
 * names a file of key=value lines (url, ca, out, minutes). Synthetic
 * account and data only.
 */
@EnabledIfEnvironmentVariable(named = "ONEPASS_SHARE_E2E", matches = ".+")
class SharingDeviceE2ETest {
    private val conf: Map<String, String> = File(System.getenv("ONEPASS_SHARE_E2E")!!).readLines()
        .filter { '=' in it }.associate { it.substringBefore('=') to it.substringAfter('=') }
    private val out = File(conf.getValue("out")).also { it.parentFile?.mkdirs(); it.writeText("") }
    private fun log(s: String) = out.appendText(s + "\n")
    private fun now() = System.currentTimeMillis() / 1000

    @Test
    fun playAContactOfThePhone() {
        CoreLoader.ensureLoaded()
        val ep = FfiMailboxEndpoint(conf.getValue("url"), File(conf.getValue("ca")).readText())
        val db = Files.createTempDirectory("share-e2e").resolve("camille.db").toString()
        val classical = generateClassicalDeviceKeys()
        val pq = openSoftwarePqHalf(generateSoftwarePqHalf())
        val created = createAccountV2(db, "camille test password", FfiKdfParams(8192u, 1u, 1u), classical, pq, "PC de Camille", FfiDeviceKind.ANDROID, FfiDeviceMode.PERSONAL)
        val s: Session = created.session
        val handle = ZoneSyncHandle(InMemoryZoneSeeds(), ep.baseUrl, ep.extraCaPem)
        val rounds = ZoneRounds(FfiZoneSync(handle, openSyncStore(db))).also { it.sessionUnlocked(s) }
        val flow = ContactInviteFlow(s, "Camille", CoreInviteDrops, ContactZoneCreator(handle), InMemoryPendingInvites(), pollMs = 1_000)
        flow.onState { st ->
            when (st) {
                is ContactInviteFlow.State.Sharing -> log("link=${st.link}")
                is ContactInviteFlow.State.Done -> log("contact=${st.contact.nameLocal} level=${st.contact.level}")
                is ContactInviteFlow.State.Failed -> log("invite failed: ${st.error.javaClass.simpleName}")
                else -> Unit
            }
        }
        flow.createInvite(ep, InviteServer.linkHost(ep.baseUrl, "https://hosted.invalid/functions/v1/mailbox"))

        val until = System.currentTimeMillis() + (conf["minutes"]?.toLong() ?: 20) * 60_000
        var verified = false
        var sent = false
        val added = HashSet<String>()
        var lastState = ""
        while (System.currentTimeMillis() < until) {
            rounds.syncNow()
            val snap = SharingSnapshot.read(s)
            val phone = snap.contacts.firstOrNull()
            if (phone != null && !verified && flow.state is ContactInviteFlow.State.Done) {
                log("safety=${phone.safetyNumber}")
                s.confirmSafetyNumber(phone.accountId, phone.safetyNumber, now())
                verified = true
                log("verified ${phone.nameLocal}")
            }
            snap.shareInvites.forEach { inv ->
                log("share invite from=${inv.fromNameLocal} role=${inv.role} hint=${inv.vaultNameHint}")
                runCatching { s.acceptShareInvite(inv.id, now()) }.onSuccess { log("joined ${it.name}") }.onFailure { log("join failed: ${it.javaClass.simpleName}") }
            }
            snap.familyInvites.forEach { inv ->
                log("family invite from=${inv.fromNameLocal} role=${inv.role}")
                runCatching { s.acceptFamilyInvite(inv.id, now()) }.onSuccess { log("family joined, members=${it.members.size}") }.onFailure { log("family join failed: ${it.javaClass.simpleName}") }
            }
            snap.receivedItems.forEach { r ->
                log("received ${r.title} from ${r.fromNameLocal}")
                runCatching { s.acceptReceivedItem(r.sendId, s.vaults().first { v -> snap.role(v.id) == null }.id, now()) }
            }
            for (v in snap.sharedVaults) {
                if (v.role != FfiRole.READ && v.vaultId !in added) {
                    runCatching {
                        val item = s.newItem(v.vaultId, FfiItemType.LOGIN, "Ajouté par Camille")
                        item.sections.flatMap { it.fields }.firstOrNull { it.id == "username" }?.value = FfiFieldValue.Text("camille@exemple.fr")
                        s.saveItem(item)
                    }.onSuccess { added += v.vaultId; log("added an item to ${v.name}") }.onFailure { log("add failed in ${v.name}: ${it.javaClass.simpleName}") }
                }
            }
            if (phone != null && !sent) {
                runCatching {
                    val mine = s.vaults().first { v -> snap.role(v.id) == null }.id
                    val item = s.newItem(mine, FfiItemType.LOGIN, "Code du portail")
                    item.sections.flatMap { it.fields }.firstOrNull { it.id == "username" }?.value = FfiFieldValue.Text("portail")
                    val saved = s.saveItem(item)
                    s.sendItem(mine, saved.id, phone.accountId, now() + 7 * 86_400, now())
                }.onSuccess { sent = true; log("sent Code du portail") }.onFailure { log("send failed: ${it.javaClass.simpleName}") }
            }
            val state = snap.sharedVaults.joinToString("; ") { v ->
                "${v.name} role=${v.role} members=${v.members.size} items=" + s.itemSummaries().filter { it.vaultId == v.vaultId && it.trashedAt == null }.map { it.title }.sorted()
            } + " | family=" + (snap.family?.members?.size ?: 0)
            if (state != lastState) {
                log("state: $state")
                lastState = state
            }
            Thread.sleep(2_000)
        }
        rounds.close()
        s.lock()
        log("end")
    }
}
