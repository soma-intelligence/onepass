package me.somalabs.onepass.vaultkit.sharing

import me.somalabs.onepass.core.FfiContact
import me.somalabs.onepass.core.FfiFamily
import me.somalabs.onepass.core.FfiFamilyInvite
import me.somalabs.onepass.core.FfiHelper
import me.somalabs.onepass.core.FfiIdentityChange
import me.somalabs.onepass.core.FfiReceivedItem
import me.somalabs.onepass.core.FfiRecoveryEnrollment
import me.somalabs.onepass.core.FfiRole
import me.somalabs.onepass.core.FfiShareInvite
import me.somalabs.onepass.core.FfiSharedVault
import me.somalabs.onepass.core.Session

/**
 * What the sharing screens show (iOS `SharingSnapshot`), read again after
 * each change and each sync round. Every name is the contact book's
 * `name_local` (core), never one read from a mailbox; every role and right
 * comes from the core, never recomputed here.
 */
data class SharingSnapshot(
    val contacts: List<FfiContact> = emptyList(),
    val sharedVaults: List<FfiSharedVault> = emptyList(),
    val shareInvites: List<FfiShareInvite> = emptyList(),
    val identityChanges: List<FfiIdentityChange> = emptyList(),
    val family: FfiFamily? = null,
    val familyInvites: List<FfiFamilyInvite> = emptyList(),
    val recoveryEnrollment: FfiRecoveryEnrollment? = null,
    /** The members who chose this account as their organizer (spec 11.4). */
    val helpers: List<FfiHelper> = emptyList(),
    val receivedItems: List<FfiReceivedItem> = emptyList(),
    /** Ids of the items a removed member could read (Watchtower "Vus par un ancien membre"). */
    val seenByFormerMembers: Set<String> = emptySet(),
) {
    /** This account's role in a shared vault, null for a personal vault. */
    fun role(vaultId: String): FfiRole? = sharedVaults.firstOrNull { it.vaultId == vaultId }?.role

    fun shared(vaultId: String): FfiSharedVault? = sharedVaults.firstOrNull { it.vaultId == vaultId }

    fun contact(accountId: String): FfiContact? = contacts.firstOrNull { it.accountId == accountId }

    /** Invitations, key changes and received items waiting for an answer. */
    val notices: Int get() = shareInvites.size + identityChanges.size + receivedItems.size

    companion object {
        /**
         * Reads everything again (iOS `refreshSharing`). A part that cannot be
         * read is left empty: display only.
         */
        fun read(s: Session, now: Long = System.currentTimeMillis() / 1000): SharingSnapshot = SharingSnapshot(
            contacts = runCatching { s.contacts() }.getOrDefault(emptyList()),
            sharedVaults = runCatching { s.sharedVaults() }.getOrDefault(emptyList()),
            shareInvites = runCatching { s.shareInvites() }.getOrDefault(emptyList()),
            identityChanges = runCatching { s.refreshMemberIdentities(now) }.getOrDefault(emptyList()),
            family = runCatching { s.family() }.getOrNull(),
            familyInvites = runCatching { s.familyInvites() }.getOrDefault(emptyList()),
            recoveryEnrollment = runCatching { s.recoveryEnrollment() }.getOrNull(),
            helpers = runCatching { s.recoveryEnrollmentsForMe() }.getOrDefault(emptyList()),
            receivedItems = runCatching { s.receivedItems(now) }.getOrDefault(emptyList()),
            seenByFormerMembers = runCatching { s.seenByFormerMembers().map { it.itemId }.toSet() }.getOrDefault(emptySet()),
        )
    }
}
