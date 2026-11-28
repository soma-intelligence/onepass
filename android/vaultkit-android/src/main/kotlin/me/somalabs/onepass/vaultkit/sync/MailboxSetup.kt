package me.somalabs.onepass.vaultkit.sync

import me.somalabs.onepass.core.FfiCredentialRole
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.MailboxSync
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.SyncStoreHandle
import me.somalabs.onepass.core.mailboxCreate
import me.somalabs.onepass.core.mailboxGenerateCredential
import me.somalabs.onepass.core.mailboxLocator
import me.somalabs.onepass.core.mailboxRecoveryCredential

/** How a mailbox setup ended (iOS `MailboxSetupOutcome`). */
sealed class MailboxSetupOutcome {
    data class Ready(val home: MailboxHome) : MailboxSetupOutcome()

    /** The account stays on this device by choice. */
    object Local : MailboxSetupOutcome()

    /** The server could not be reached: the account stays here, the setup resumes later. */
    data class Offline(val reason: String?) : MailboxSetupOutcome()

    /** A refusal the user must act on (bad URL, server refusing). */
    data class Failed(val error: Throwable) : MailboxSetupOutcome()
}

/**
 * Puts an account on a mailbox (cross-platform spec D.2, D.4; iOS
 * `MailboxSetup`): device credential, mailbox, recovery credential granted,
 * locator registered, signed home adopted, backend state written. Each step
 * is recorded in the store meta (`sync.mailbox.setup`) before the next one
 * starts, so a cut at any point resumes where it stopped and never creates a
 * second mailbox. The recovery credential's seed is derived from the Secret
 * Key and never stored.
 *
 * Blocking (network): call it off the main thread.
 */
class MailboxSetup(
    private val dbPath: String,
    private val credentials: MailboxCredentialStore,
    private val store: SyncStoreHandle,
) {
    internal enum class Step { STARTED, CREDENTIAL, CREATED, RECOVERY_GRANTED, LOCATOR_SET, HOME_ADOPTED, DONE }

    internal data class Progress(val step: Step, val baseUrl: String, val extraCaPem: String?, val mailboxId: String?)

    /** Tests: stop (as a crash would) right after this step is recorded. */
    internal var interruptAfter: Step? = null

    private class Interrupted : RuntimeException()

    /** Whether a setup is under way (a step is recorded). */
    fun inProgress(): Boolean = readProgress() != null

    /** Whether the server already holds the mailbox of the setup in progress. */
    fun mailboxCreated(): Boolean = (readProgress()?.step ?: Step.STARTED) >= Step.CREATED

    /** Run (or resume) the setup for `choice` on the unlocked `session`. */
    fun run(session: Session, choice: SyncChoice, secretKey: String): MailboxSetupOutcome = try {
        steps(session, choice, secretKey)
    } catch (_: Interrupted) {
        MailboxSetupOutcome.Failed(IllegalStateException("interrupted"))
    } catch (e: OnePassException.MailboxUnavailable) {
        MailboxSetupOutcome.Offline(e.reason)
    } catch (e: Exception) {
        MailboxSetupOutcome.Failed(e)
    }

    /** Drop the progress of a setup that never created its mailbox (the user turned it off). */
    fun forget() {
        readProgress()?.takeIf { it.step < Step.CREATED }?.let { credentials.delete(PENDING_ID) }
        store.setMeta(META_KEY, ByteArray(0))
    }

    private fun steps(session: Session, choice: SyncChoice, secretKey: String): MailboxSetupOutcome {
        var p: Progress = readProgress() ?: run {
            val endpoint = when (choice) {
                SyncChoice.Local -> {
                    SyncBackendState.write(SyncBackendState.Local, store)
                    return MailboxSetupOutcome.Local
                }
                else -> choice.endpoint!!
            }
            if (!MailboxEndpoints.validate(endpoint.baseUrl)) {
                return MailboxSetupOutcome.Failed(IllegalArgumentException(BAD_URL))
            }
            SyncBackendState.write(SyncBackendState.PendingSetup(choice), store)
            Progress(Step.STARTED, endpoint.baseUrl, endpoint.extraCaPem, null).also { save(it) }
        }
        val endpoint = FfiMailboxEndpoint(p.baseUrl, p.extraCaPem)

        // 1. This device's credential, kept before the server knows it.
        if (p.step < Step.CREDENTIAL) {
            val credential = mailboxGenerateCredential()
            credentials.store(credential.seed, PENDING_ID)
            credential.seed.fill(0)
            p = advance(p, Step.CREDENTIAL)
        }
        // 2. The mailbox, managed by that credential.
        if (p.step < Step.CREATED) {
            val seed = credentials.seed(PENDING_ID) ?: throw OnePassException.InvalidInput("mailbox credential")
            try {
                val created = mailboxCreate(endpoint, seed, null)
                credentials.store(seed, created.mailboxId)
                credentials.delete(PENDING_ID)
                p = advance(p.copy(mailboxId = created.mailboxId), Step.CREATED)
            } finally {
                seed.fill(0)
            }
        }
        val mailboxId = p.mailboxId ?: throw OnePassException.InvalidInput("mailbox credential")
        val seed = credentials.seed(mailboxId) ?: throw OnePassException.InvalidInput("mailbox credential")
        val home = MailboxHome(p.baseUrl, mailboxId, p.extraCaPem)
        val sync = try {
            MailboxSync.open(dbPath, home.endpoint, mailboxId, seed)
        } finally {
            seed.fill(0)
        }
        sync.use {
            // 3. The recovery credential, derived from the Secret Key, granted, then forgotten.
            if (p.step < Step.RECOVERY_GRANTED) {
                val recovery = mailboxRecoveryCredential(secretKey, mailboxId)
                recovery.seed.fill(0)
                try {
                    sync.grant(recovery.publicKey, FfiCredentialRole.MANAGE, RECOVERY_LABEL)
                } catch (_: OnePassException.Conflict) {
                    // Granted before a cut: the server already holds it.
                }
                p = advance(p, Step.RECOVERY_GRANTED)
            }
            // 4. The locator a restore looks the mailbox up by.
            if (p.step < Step.LOCATOR_SET) {
                sync.setLocator(mailboxLocator(secretKey))
                p = advance(p, Step.LOCATOR_SET)
            }
        }
        // 5. The account's signed home names the mailbox.
        if (p.step < Step.HOME_ADOPTED) {
            val backend = home.backend
            if (session.syncHome()?.backend != backend) {
                session.adoptSyncHome(session.signSyncHome(backend))
            }
            p = advance(p, Step.HOME_ADOPTED)
        }
        // 6. The app syncs with it from now on.
        SyncBackendState.write(SyncBackendState.Mailbox(home), store)
        advance(p, Step.DONE)
        store.setMeta(META_KEY, ByteArray(0))
        return MailboxSetupOutcome.Ready(home)
    }

    private fun advance(p: Progress, step: Step): Progress {
        val next = p.copy(step = step)
        save(next)
        if (interruptAfter == step) throw Interrupted()
        return next
    }

    private fun readProgress(): Progress? {
        val bytes = store.meta(META_KEY)?.takeIf { it.isNotEmpty() } ?: return null
        val f = Fields.decode(bytes)
        return Progress(Step.valueOf(f.getValue("step")), f.getValue("url"), f["ca"], f["mailbox"])
    }

    private fun save(p: Progress) {
        val fields = linkedMapOf("step" to p.step.name, "url" to p.baseUrl)
        p.extraCaPem?.let { fields["ca"] = it }
        p.mailboxId?.let { fields["mailbox"] = it }
        store.setMeta(META_KEY, Fields.encode(fields))
    }

    companion object {
        const val META_KEY = "mailbox.setup"
        /** The credential slot of the device seed before the mailbox id is known. */
        const val PENDING_ID = "pending"
        /** The grant label of the recovery credential: the server sees it, it names a role only. */
        val RECOVERY_LABEL = "recovery".toByteArray()
        /** The message key of a URL the core would refuse. */
        const val BAD_URL = "sync.setup.badURL"
    }
}
