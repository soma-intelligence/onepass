package me.somalabs.onepass.vaultkit.sharing

import java.io.File
import java.nio.file.Path
import me.somalabs.onepass.core.FfiContactLevel
import me.somalabs.onepass.core.FfiDeviceKind
import me.somalabs.onepass.core.FfiDeviceMode
import me.somalabs.onepass.core.FfiFamilyRole
import me.somalabs.onepass.core.FfiItemType
import me.somalabs.onepass.core.FfiKdfParams
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.FfiRecoveryStatus
import me.somalabs.onepass.core.FfiRoundStatus
import me.somalabs.onepass.core.FfiRole
import me.somalabs.onepass.core.FfiVaultMeta
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.ZoneSyncHandle
import me.somalabs.onepass.core.contactInitiatorBegin
import me.somalabs.onepass.core.createAccountV2
import me.somalabs.onepass.core.generateClassicalDeviceKeys
import me.somalabs.onepass.core.generateSoftwarePqHalf
import me.somalabs.onepass.core.openSoftwarePqHalf
import me.somalabs.onepass.core.openSyncStore
import me.somalabs.onepass.core.recoveryAlerts
import me.somalabs.onepass.core.recoveryResponderStart
import me.somalabs.onepass.vaultkit.core.CoreLoader
import me.somalabs.onepass.vaultkit.pairing.DeviceKeys
import me.somalabs.onepass.vaultkit.sync.testMailboxStart
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.CleanupMode
import org.junit.jupiter.api.io.TempDir

/**
 * Sharing between two accounts against the core's test mailbox (loopback
 * TLS), as the Android app drives it: a contact added by link both ways
 * (drops), the safety numbers compared, a vault shared, joined, edited on
 * both sides, a member removed, an item sent, a family made and joined, and
 * an organizer-assisted recovery up to the new device. Synthetic data only.
 */
class SharingFlowTest {
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

    @TempDir(cleanup = CleanupMode.NEVER)
    lateinit var dir: Path

    private fun now() = System.currentTimeMillis() / 1000

    inner class Person(val name: String) {
        val db: String = dir.resolve("$name.db").toString()
        val keys = DeviceKeys(generateClassicalDeviceKeys(), openSoftwarePqHalf(generateSoftwarePqHalf()))
        val session: Session
        val secretKey: String
        val accountId: String
        val handle: ZoneSyncHandle
        val rounds: ZoneRounds

        init {
            val created = createAccountV2(db, PASSWORD, FAST_KDF, keys.classical, keys.pq, "Android de $name", FfiDeviceKind.ANDROID, FfiDeviceMode.PERSONAL)
            session = created.session
            secretKey = created.secretKey
            accountId = session.accountId()
            handle = ZoneSyncHandle(InMemoryZoneSeeds(), ep.baseUrl, ep.extraCaPem)
            rounds = ZoneRounds(FfiZoneSync(handle, openSyncStore(db))).also { it.sessionUnlocked(session) }
        }

        fun snapshot() = SharingSnapshot.read(session)

        fun flow() = ContactInviteFlow(session, name, CoreInviteDrops, ContactZoneCreator(handle), InMemoryPendingInvites(), pollMs = 100)
    }

    /** Rounds for everyone until two quiet passes in a row (the Rust tests' `settle_zones`). */
    private fun settle(vararg people: Person) {
        var quiet = 0
        repeat(16) {
            var allQuiet = true
            for (p in people) {
                p.rounds.syncNow()
                val r = p.rounds.lastReport!!
                if (r.actionsDone != 0u || r.rerun || r.changed || r.zones.any { it.status != FfiRoundStatus.Idle }) allQuiet = false
            }
            quiet = if (allQuiet) quiet + 1 else 0
            if (quiet == 2) return
        }
        error("zones never settled")
    }

    private fun waitFor(what: String, ms: Long = 60_000, cond: () -> Boolean) {
        val until = System.currentTimeMillis() + ms
        while (!cond()) {
            check(System.currentTimeMillis() < until) { "timed out: $what" }
            Thread.sleep(50)
        }
    }

    /** Alice invites Bob by link; Bob opens it; both compare the safety number. */
    private fun contacts(): Pair<Person, Person> {
        val alice = Person("Alice")
        val bob = Person("Bob")
        val inviter = alice.flow()
        inviter.createInvite(ep, InviteServer.linkHost(ep.baseUrl, "https://hosted.invalid/functions/v1/mailbox"))
        waitFor("link") { inviter.state is ContactInviteFlow.State.Sharing }
        val link = (inviter.state as ContactInviteFlow.State.Sharing).link
        assertTrue(link.startsWith("onepass://contact/localhost:"), "link names the test server")
        // The invitee finds the server in the link (the test CA is the one it knows for it).
        val server = InviteServer.endpoint(link, "https://hosted.invalid/functions/v1/mailbox", listOf(ep))
        assertEquals(ep.baseUrl, server.baseUrl)
        val invitee = bob.flow()
        invitee.open(link, server)
        waitFor("both done") {
            (inviter.state is ContactInviteFlow.State.Done || inviter.state is ContactInviteFlow.State.Failed) &&
                (invitee.state is ContactInviteFlow.State.Done || invitee.state is ContactInviteFlow.State.Failed)
        }
        val a = inviter.state as? ContactInviteFlow.State.Done ?: error("inviter: ${inviter.state}")
        val b = invitee.state as? ContactInviteFlow.State.Done ?: error("invitee: ${invitee.state}")
        assertEquals(bob.accountId, a.contact.accountId)
        assertEquals(alice.accountId, b.contact.accountId)
        assertEquals("Bob", a.contact.nameLocal)
        assertEquals(FfiContactLevel.LINK, a.contact.level)
        settle(alice, bob)

        // The same safety number on both phones; a match makes the contact Verified.
        val na = alice.snapshot().contact(bob.accountId)!!.safetyNumber
        val nb = bob.snapshot().contact(alice.accountId)!!.safetyNumber
        assertEquals(nb, na)
        assertEquals(12, na.trim().split(Regex("\\s+")).size)
        assertEquals(FfiContactLevel.VERIFIED, alice.session.confirmSafetyNumber(bob.accountId, na, now()).level)
        assertEquals(FfiContactLevel.VERIFIED, bob.session.confirmSafetyNumber(alice.accountId, nb, now()).level)
        return alice to bob
    }

    private fun Session.addLogin(vaultId: String, title: String): String {
        val item = newItem(vaultId, FfiItemType.LOGIN, title)
        item.sections.flatMap { it.fields }.firstOrNull { it.id == "username" }?.value = me.somalabs.onepass.core.FfiFieldValue.Text("camille@exemple.fr")
        return saveItem(item).id
    }

    private fun Session.titlesIn(vaultId: String) = itemSummaries().filter { it.vaultId == vaultId && it.trashedAt == null }.map { it.title }.sorted()

    @Test
    fun contactsShareEditRemoveSendFamilyAndRecovery() {
        val (alice, bob) = contacts()

        // Rename and the local name stays local.
        alice.session.renameContact(bob.accountId, "Bob (travail)")
        assertEquals("Bob (travail)", alice.snapshot().contact(bob.accountId)!!.nameLocal)

        // ---- a shared vault ----
        val atlas = alice.session.createVault(FfiVaultMeta("Projet Atlas", "folder", "purple", false, false)).id
        alice.session.addLogin(atlas, "Banque")
        val shared = alice.session.shareVault(atlas, now())
        assertTrue(shared.owner)
        // A member is added once the zone round made the vault's mailbox.
        assertThrows<OnePassException> { alice.session.addMember(atlas, bob.accountId, FfiRole.WRITE, now()) }
        settle(alice)
        alice.session.addMember(atlas, bob.accountId, FfiRole.WRITE, now())
        assertEquals(2, alice.snapshot().shared(atlas)!!.members.size)
        settle(alice, bob)
        val invite = bob.snapshot().shareInvites.single()
        assertEquals("Alice", invite.fromNameLocal)
        assertEquals(FfiRole.WRITE, invite.role)
        bob.session.acceptShareInvite(invite.id, now())
        settle(alice, bob)
        assertEquals(listOf(atlas), bob.snapshot().sharedVaults.map { it.vaultId })
        assertTrue(bob.snapshot().shareInvites.isEmpty())
        assertEquals(listOf("Banque"), bob.session.titlesIn(atlas))

        // Edits go both ways.
        alice.session.addLogin(atlas, "Messagerie")
        settle(alice, bob)
        assertEquals(listOf("Banque", "Messagerie"), bob.session.titlesIn(atlas))
        val bank = bob.session.itemSummaries().first { it.vaultId == atlas && it.title == "Banque" }
        val item = bob.session.item(atlas, bank.id)
        bob.session.saveItem(item.copy(title = "Banque en ligne"))
        settle(alice, bob)
        assertEquals(listOf("Banque en ligne", "Messagerie"), alice.session.titlesIn(atlas))

        // Roles: down to Read, Bob's writes are refused.
        alice.session.setRole(atlas, bob.accountId, FfiRole.READ, now())
        settle(alice, bob)
        assertEquals(FfiRole.READ, bob.snapshot().role(atlas))
        assertThrows<OnePassException> { bob.session.addLogin(atlas, "Refusé") }

        // ---- send an item ----
        val mine = bob.session.vaults().first { it.id != atlas }.id
        val sendId = alice.session.sendItem(atlas, bank.id, bob.accountId, now() + 7 * 86400, now())
        assertTrue(sendId.isNotEmpty())
        settle(alice, bob)
        val received = bob.snapshot().receivedItems.single()
        assertEquals("Alice", received.fromNameLocal)
        assertEquals("Banque en ligne", received.title)
        bob.session.acceptReceivedItem(received.sendId, mine, now())
        assertTrue(bob.snapshot().receivedItems.isEmpty())
        assertTrue("Banque en ligne" in bob.session.titlesIn(mine))

        // ---- remove the member ----
        val removal = alice.session.removeMember(atlas, bob.accountId, now())
        assertEquals(2u, removal.seenItems)
        assertEquals(listOf(alice.accountId), alice.snapshot().shared(atlas)!!.members.map { it.accountId })
        assertEquals(2, alice.snapshot().seenByFormerMembers.size)
        settle(alice, bob)
        assertTrue(bob.snapshot().sharedVaults.isEmpty())
        assertTrue(bob.session.titlesIn(atlas).isEmpty())
        // Alone, the owner makes it personal again.
        alice.session.stopSharing(atlas, now())
        assertTrue(alice.snapshot().sharedVaults.isEmpty())

        // ---- the family ----
        val family = alice.session.createFamily("Famille", now())
        assertTrue(family.iAmOrganizer)
        assertTrue(family.needsSecondOrganizer)
        settle(alice)
        alice.session.inviteToFamily(bob.accountId, FfiFamilyRole.MEMBER, now())
        settle(alice, bob)
        val fi = bob.snapshot().familyInvites.single()
        assertEquals("Alice", fi.fromNameLocal)
        val joined = bob.session.acceptFamilyInvite(fi.id, now())
        assertFalse(joined.iAmOrganizer)
        settle(alice, bob)
        assertEquals(2, alice.snapshot().family!!.members.size)
        val familyVault = alice.snapshot().family!!.vaults.single()
        assertTrue(bob.snapshot().sharedVaults.any { it.vaultId == familyVault })
        alice.session.addLogin(familyVault, "Wi-Fi maison")
        settle(alice, bob)
        assertEquals(listOf("Wi-Fi maison"), bob.session.titlesIn(familyVault))

        // ---- recovery with the organizer's help ----
        // Bob's account syncs through a mailbox: a new device fetches its private base with the kit.
        val bobCreds = me.somalabs.onepass.vaultkit.sync.InMemoryCredentialStore()
        val setup = openSyncStore(bob.db).use {
            me.somalabs.onepass.vaultkit.sync.MailboxSetup(bob.db, bobCreds, it).run(bob.session, me.somalabs.onepass.vaultkit.sync.SyncChoice.SelfHost(ep.baseUrl, ep.extraCaPem), bob.secretKey)
        }
        val bobHome = (setup as me.somalabs.onepass.vaultkit.sync.MailboxSetupOutcome.Ready).home
        val enrollment = bob.session.enrollRecovery(alice.accountId, 86_400u, PASSWORD, bob.secretKey, now())
        assertTrue(enrollment.valid)
        settle(alice, bob)
        val helper = alice.snapshot().helpers.single()
        assertEquals(bob.accountId, helper.member)
        val t0 = now()
        val status = alice.session.requestRecovery(bob.accountId, PASSWORD, alice.secretKey, t0)
        val after = (status as FfiRecoveryStatus.Waiting).releaseAfter
        assertTrue(after >= t0 + 86_400)
        settle(alice, bob)
        // Bob's devices see the request, locked or not.
        val alert = recoveryAlerts(bob.db).single()
        assertEquals(enrollment.enrollmentId, alert.enrollmentId)
        // Too early: nothing is released.
        assertTrue(alice.session.recoveryStatus(bob.accountId, t0 + 10) is FfiRecoveryStatus.Waiting)
        val later = after + 5
        assertEquals(FfiRecoveryStatus.Ready, alice.session.recoveryStatus(bob.accountId, later))

        // Face to face: Bob's new device shows the QR, Alice's reads the same SAS and releases.
        val start = recoveryResponderStart(later)
        val begin = contactInitiatorBegin(start.qr, start.hello, later)
        val sas = start.responder.onKeyExchange(begin.keyExchange, later)
        assertEquals(begin.sas, sas)
        begin.initiator.confirmSasForRecovery()
        val frame = alice.session.releaseRecoveryShare(bob.accountId, begin.initiator, later)
        assertTrue(frame.isNotEmpty())

        // Bob's private round sends his enrollment to his mailbox.
        me.somalabs.onepass.core.MailboxSync.open(bob.db, bobHome.endpoint, bobHome.mailboxId, bobCreds.seed(bobHome.mailboxId)!!).use {
            me.somalabs.onepass.vaultkit.sync.MailboxRestore.settle(it, bob.session)
        }
        // The new device fetches Bob's private base with the Emergency Kit's Secret Key, then recovers.
        bob.rounds.close()
        val newDb = dir.resolve("Bob-new.db").toString()
        val keys = DeviceKeys(generateClassicalDeviceKeys(), openSoftwarePqHalf(generateSoftwarePqHalf()))
        val newPassword = "a brand new master password"
        val newSecretKey = me.somalabs.onepass.core.generateSecretKey()
        val (recovered, client) = me.somalabs.onepass.vaultkit.sync.MailboxRestore(newDb, me.somalabs.onepass.vaultkit.sync.InMemoryCredentialStore(), hosted = null)
            .restore(bobHome, bob.secretKey) {
                start.responder.recover(newDb, frame, bob.secretKey, newPassword, newSecretKey, keys.classical, keys.pq,
                    "Nouvel Android de Bob", FfiDeviceKind.ANDROID, FfiDeviceMode.PERSONAL, later)
            }
        client.close()
        bob.session.lock()
        assertEquals(bob.accountId, recovered.accountId())
        assertTrue("Banque en ligne" in recovered.itemSummaries().map { it.title })
        recovered.lock()
        // The new password and Secret Key open it.
        val unlocked = me.somalabs.onepass.core.unlockWithPassword(newDb, newPassword, newSecretKey)
        assertEquals(bob.accountId, unlocked.session.accountId())
        unlocked.session.lock()
        alice.rounds.close()
    }

    @Test
    fun aRemovedContactAndAnExpiredInvitation() {
        val (alice, bob) = contacts()
        alice.session.removeContact(bob.accountId, now())
        val c = alice.snapshot().contacts.single { it.accountId == bob.accountId }
        assertTrue(c.state is me.somalabs.onepass.core.FfiContactState.Removed)
        // Sharing with a removed contact is refused.
        val v = alice.session.createVault(FfiVaultMeta("Projet", "folder", "blue", false, false)).id
        alice.session.shareVault(v, now())
        settle(alice)
        assertThrows<OnePassException> { alice.session.addMember(v, bob.accountId, FfiRole.READ, now()) }

        // A link nobody answers expires (72 hours).
        var t = now()
        val inviter = ContactInviteFlow(alice.session, "Alice", CoreInviteDrops, ContactZoneCreator(alice.handle), InMemoryPendingInvites(), pollMs = 20) { t }
        inviter.createInvite(ep, null)
        waitFor("link") { inviter.state is ContactInviteFlow.State.Sharing }
        t += 73 * 3600
        waitFor("expired") { inviter.state is ContactInviteFlow.State.Failed }
        assertTrue((inviter.state as ContactInviteFlow.State.Failed).error is ContactInviteExpired)
        alice.rounds.close()
        bob.rounds.close()
    }

    @Test
    fun theSchedulerRunsOneRoundAtATime() {
        val p = Person("Solo")
        repeat(5) { p.rounds.kick() }
        p.rounds.syncNow()
        assertTrue(p.rounds.maxConcurrentRounds == 1)
        assertNotNull(p.rounds.lastReport)
        p.rounds.close()
    }
}
