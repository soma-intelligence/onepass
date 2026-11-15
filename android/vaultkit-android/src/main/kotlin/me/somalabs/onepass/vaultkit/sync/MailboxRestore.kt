package me.somalabs.onepass.vaultkit.sync

import me.somalabs.onepass.core.FfiCredentialRole
import me.somalabs.onepass.core.FfiMailboxEndpoint
import me.somalabs.onepass.core.FfiRoundStatus
import me.somalabs.onepass.core.MailboxSync
import me.somalabs.onepass.core.OnePassException
import me.somalabs.onepass.core.Session
import me.somalabs.onepass.core.SyncStoreHandle
import me.somalabs.onepass.core.mailboxGenerateCredential
import me.somalabs.onepass.core.mailboxLocate
import me.somalabs.onepass.core.mailboxLocator
import me.somalabs.onepass.core.mailboxRecoveryCredential

/** Where a restore from the Emergency Kit finds the account (iOS `RestoreSource`, without iCloud). */
sealed class RestoreSource {
    data class Found(val home: MailboxHome) : RestoreSource()
    object NotFound : RestoreSource()

    /** No server answered: nothing can be said yet. */
    data class Offline(val reason: String?) : RestoreSource()
}

/**
 * Restores an account kept on a mailbox from the Secret Key alone (spec D.4,
 * iOS `MailboxRestore`). The kit's server (self-host) is asked first, then
 * the OnePass server, by the account's locator. The recovery credential,
 * derived from the Secret Key and never stored, fetches the whole mailbox
 * into the store; this device gets its own credential only after the master
 * password unlocked the account, so a wrong password leaves nothing granted
 * and nothing stored.
 *
 * Blocking (network): call it off the main thread.
 */
class MailboxRestore(
    private val dbPath: String,
    private val credentials: MailboxCredentialStore,
    private val hosted: String? = MailboxEndpoints.HOSTED,
) {
    /** Find the account of `secretKey`. `kitServer`: the server of a self-host kit, with its CA. */
    fun locate(secretKey: String, kitServer: FfiMailboxEndpoint?): RestoreSource {
        val locator = try {
            mailboxLocator(secretKey)
        } catch (_: OnePassException) {
            return RestoreSource.NotFound
        }
        var offline: String? = null
        var unreachable = false
        val endpoints = listOfNotNull(kitServer, hosted?.let { FfiMailboxEndpoint(it, null) })
            .distinctBy { it.baseUrl }
        for (endpoint in endpoints) {
            try {
                // Oldest first: the account's first mailbox is the one its home names.
                mailboxLocate(endpoint, locator).firstOrNull()?.let {
                    return RestoreSource.Found(MailboxHome(endpoint.baseUrl, it, endpoint.extraCaPem))
                }
            } catch (e: OnePassException) {
                unreachable = true
                if (offline == null) offline = (e as? OnePassException.MailboxUnavailable)?.reason
            }
        }
        return if (unreachable) RestoreSource.Offline(offline) else RestoreSource.NotFound
    }

    /**
     * Fetch the mailbox of `home` into the store with the recovery
     * credential, then `unlock` (the master password, `restore_from_kit`).
     * Once unlocked: this device's credential is generated, granted by the
     * recovery credential and kept; the backend state names the mailbox.
     * Returns the unlocked session and this device's client. `unlock`
     * throwing ends the restore with nothing granted or stored.
     */
    fun restore(home: MailboxHome, secretKey: String, unlock: () -> Session): Pair<Session, MailboxSync> {
        val recovery = mailboxRecoveryCredential(secretKey, home.mailboxId)
        val recoveryClient = try {
            MailboxSync.open(dbPath, home.endpoint, home.mailboxId, recovery.seed)
        } finally {
            recovery.seed.fill(0)
        }
        recoveryClient.use {
            val fetched = settle(recoveryClient, null)
            when (fetched.status) {
                FfiRoundStatus.Idle, FfiRoundStatus.WaitingForServer, FfiRoundStatus.Unsettled -> Unit
                else -> throw OnePassException.MailboxUnavailable("restore fetch")
            }
            val session = unlock()
            val device = mailboxGenerateCredential()
            try {
                recoveryClient.grant(device.publicKey, FfiCredentialRole.MANAGE, ByteArray(0))
                credentials.store(device.seed, home.mailboxId)
                openSyncStore(dbPath).use { SyncBackendState.write(SyncBackendState.Mailbox(home), it) }
                val client = MailboxSync.open(dbPath, home.endpoint, home.mailboxId, device.seed)
                // The rebase of what the recovery fetch staged, signed by this device from now on.
                client.runRound(session, now())
                return session to client
            } finally {
                device.seed.fill(0)
            }
        }
    }

    private fun openSyncStore(path: String): SyncStoreHandle = me.somalabs.onepass.core.openSyncStore(path)

    companion object {
        fun now(): Long = System.currentTimeMillis() / 1000

        /** Rounds until one ends with nothing left to run at once (at most 12). */
        fun settle(sync: MailboxSync, session: Session?): me.somalabs.onepass.core.FfiRoundReport {
            var last = sync.runRound(session, now())
            var changed = last.changed
            var n = 1
            while (last.rerun && n < 12) {
                last = sync.runRound(session, now())
                changed = changed || last.changed
                n++
            }
            return last.copy(changed = changed)
        }
    }
}
