//! Shared vaults for the apps (sharing plan 4, Task 3): share, members,
//! invitations, roles, leave, removal with a new key, transfer, and the
//! identity changes of members (spec 7 to 10, 12).
//!
//! The network side (zone mailboxes, grants, revocations) runs in the zone
//! round (`ZoneSyncHandle::run_round`); these calls only write the core's
//! records and queue its share actions.

use onepass_core::Id;
use onepass_core::repo::members::{AdoptionProof, IdentityChange};
use onepass_core::share::{
    MemberView, RekeyNotice, RekeyReason, Role, ShareInviteView, SharedVaultInfo,
};

use crate::contacts::FfiContactLevel;
use crate::convert::{id_hex, parse_id, vault_to_ffi};
use crate::error::{OnePassError, invalid};
use crate::session::{Session, find_vault};
use crate::types::FfiVault;

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FfiRole {
    Read,
    Write,
    Manage,
}

impl From<Role> for FfiRole {
    fn from(r: Role) -> FfiRole {
        match r {
            Role::Read => FfiRole::Read,
            Role::Write => FfiRole::Write,
            Role::Manage => FfiRole::Manage,
        }
    }
}

impl From<FfiRole> for Role {
    fn from(r: FfiRole) -> Role {
        match r {
            FfiRole::Read => Role::Read,
            FfiRole::Write => Role::Write,
            FfiRole::Manage => Role::Manage,
        }
    }
}

/// One member as the screens show it. `name_local` is empty for this
/// account and for an account not in the book.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiMember {
    pub account_id: String,
    pub name_local: String,
    pub role: FfiRole,
    pub owner: bool,
    pub level: FfiContactLevel,
    /// The pinned contact's keys differ from the ones in the member list.
    pub keys_changed: bool,
    pub key_pending: bool,
}

impl From<&MemberView> for FfiMember {
    fn from(m: &MemberView) -> FfiMember {
        FfiMember {
            account_id: id_hex(m.account_id),
            name_local: m.name_local.clone(),
            role: m.role.into(),
            owner: m.owner,
            level: m.level.into(),
            keys_changed: m.keys_changed,
            key_pending: m.key_pending,
        }
    }
}

/// A shared vault: this account's role, the key generation, the members.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiSharedVault {
    pub vault_id: String,
    pub name: String,
    pub role: FfiRole,
    pub owner: bool,
    pub generation: u32,
    pub members: Vec<FfiMember>,
    /// This account's new identity waits for a manager (writes refused).
    pub identity_pending: bool,
    pub mcp_hidden: bool,
}

pub(crate) fn shared_to_ffi(s: &SharedVaultInfo) -> FfiSharedVault {
    FfiSharedVault {
        vault_id: id_hex(s.vault_id),
        name: s.name.clone(),
        role: s.role.into(),
        owner: s.owner,
        generation: s.generation,
        members: s.members.iter().map(FfiMember::from).collect(),
        identity_pending: s.identity_pending,
        mcp_hidden: s.mcp_hidden,
    }
}

/// An invitation to a shared vault, received in a contact pair's zone. No
/// vault name before joining (it is sealed under the vault key), only the
/// inviter's hint.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiShareInvite {
    pub id: String,
    pub vault_name_hint: Option<String>,
    pub from_name_local: String,
    pub role: FfiRole,
    pub server_host: String,
}

impl From<&ShareInviteView> for FfiShareInvite {
    fn from(v: &ShareInviteView) -> FfiShareInvite {
        FfiShareInvite {
            id: id_hex(v.id),
            vault_name_hint: v.vault_name_hint.clone(),
            from_name_local: v.from_name_local.clone(),
            role: v.role.into(),
            server_host: v.server_host.clone(),
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiRekeyReason {
    /// The member left the vault.
    Leave,
    /// The member's account rotated its keys.
    MemberRotation,
}

/// A key change this manager's device made on a member's request.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiRekeyNotice {
    pub vault_id: String,
    pub reason: FfiRekeyReason,
    pub account_id: String,
    pub generation: u32,
}

impl From<&RekeyNotice> for FfiRekeyNotice {
    fn from(n: &RekeyNotice) -> FfiRekeyNotice {
        FfiRekeyNotice {
            vault_id: id_hex(n.vault_id),
            reason: match n.reason {
                RekeyReason::Leave => FfiRekeyReason::Leave,
                RekeyReason::MemberRotation => FfiRekeyReason::MemberRotation,
            },
            account_id: id_hex(n.account_id),
            generation: n.generation,
        }
    }
}

/// A contact's key rotation seen in the zones shared with it (spec 12.3):
/// `child` (64 hex characters) is the new head to confirm with
/// `adopt_member_identity`.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiIdentityChange {
    pub account_id: String,
    pub name_local: String,
    pub child: String,
    /// From the contact's own roster, never from a card.
    pub rotator_name: Option<String>,
    pub revoked_names: Vec<String>,
    pub issued_at: i64,
    pub vaults: Vec<String>,
    pub forked: bool,
}

fn hash_hex(h: &[u8; 32]) -> String {
    crate::convert::bytes_hex(h)
}

fn parse_hash(s: &str) -> Result<[u8; 32], OnePassError> {
    crate::convert::hex_bytes(s)
        .filter(|_| s.len() == 64)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("lineage hash"))
}

impl From<&IdentityChange> for FfiIdentityChange {
    fn from(c: &IdentityChange) -> FfiIdentityChange {
        FfiIdentityChange {
            account_id: id_hex(c.account_id),
            name_local: c.name_local.clone(),
            child: hash_hex(&c.child),
            rotator_name: c.rotator_name.clone(),
            revoked_names: c.revoked_names.clone(),
            issued_at: c.issued_at,
            vaults: c.vaults.iter().copied().map(id_hex).collect(),
            forked: c.forked,
        }
    }
}

/// How a manager checked a member's new identity: the 6-digit rotation
/// code is enough for a reader; a writer or manager needs a face-to-face
/// session (its transcript hash).
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FfiAdoptionProof {
    Code { code: u32 },
    InPerson { transcript_hash: Vec<u8> },
}

impl TryFrom<FfiAdoptionProof> for AdoptionProof {
    type Error = OnePassError;

    fn try_from(p: FfiAdoptionProof) -> Result<AdoptionProof, OnePassError> {
        Ok(match p {
            FfiAdoptionProof::Code { code } => AdoptionProof::Code(code),
            FfiAdoptionProof::InPerson { transcript_hash } => AdoptionProof::InPerson {
                transcript_hash: transcript_hash
                    .try_into()
                    .map_err(|_| invalid("transcript hash"))?,
            },
        })
    }
}

/// A member removed with a new key: every item the vault listed was
/// readable by them (`seen_items`, live, archived and trashed).
#[derive(uniffi::Record, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfiRemoval {
    pub generation: u32,
    pub seen_items: u32,
}

/// An item a removed member could read (spec 9.3): its password should
/// change.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiSeenItem {
    pub vault_id: String,
    pub item_id: String,
}

fn ids(v: &[Id]) -> Vec<String> {
    v.iter().copied().map(id_hex).collect()
}

#[uniffi::export]
impl Session {
    /// Share a personal vault: it moves to a zone of its own, this account
    /// its owner and only manager. Its mailbox is made by the next zone
    /// round.
    pub fn share_vault(&self, vault_id: String, now: i64) -> Result<FfiSharedVault, OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| {
            let vault = find_vault(repo, id)?;
            Ok(shared_to_ffi(&repo.share_vault(&vault, now)?))
        })
    }

    /// The shared vaults this account is a member of.
    pub fn shared_vaults(&self) -> Result<Vec<FfiSharedVault>, OnePassError> {
        self.with(|repo| Ok(repo.shared_vaults()?.iter().map(shared_to_ffi).collect()))
    }

    /// Invite contact `contact` with `role` (manager only). A role above
    /// Read needs a verified contact (`ContactNotVerified`).
    pub fn add_member(
        &self,
        vault_id: String,
        contact: String,
        role: FfiRole,
        now: i64,
    ) -> Result<FfiSharedVault, OnePassError> {
        let (vault_id, contact) = (parse_id(&vault_id)?, parse_id(&contact)?);
        self.with(|repo| {
            Ok(shared_to_ffi(&repo.add_member(
                vault_id,
                contact,
                role.into(),
                now,
            )?))
        })
    }

    /// The invitations waiting in the contact zones.
    pub fn share_invites(&self) -> Result<Vec<FfiShareInvite>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .share_invites()?
                .iter()
                .map(FfiShareInvite::from)
                .collect())
        })
    }

    pub fn accept_share_invite(
        &self,
        invite_id: String,
        now: i64,
    ) -> Result<FfiSharedVault, OnePassError> {
        let id = parse_id(&invite_id)?;
        self.with(|repo| Ok(shared_to_ffi(&repo.accept_share_invite(id, now)?)))
    }

    pub fn decline_share_invite(&self, invite_id: String) -> Result<(), OnePassError> {
        let id = parse_id(&invite_id)?;
        self.with(|repo| Ok(repo.decline_share_invite(id)?))
    }

    /// Change a member's role (manager only).
    pub fn set_role(
        &self,
        vault_id: String,
        account_id: String,
        role: FfiRole,
        now: i64,
    ) -> Result<FfiSharedVault, OnePassError> {
        let (vault_id, account_id) = (parse_id(&vault_id)?, parse_id(&account_id)?);
        self.with(|repo| {
            Ok(shared_to_ffi(&repo.set_role(
                vault_id,
                account_id,
                role.into(),
                now,
            )?))
        })
    }

    /// Leave a shared vault: a manager changes the key on the next round.
    pub fn leave_shared_vault(&self, vault_id: String, now: i64) -> Result<(), OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| Ok(repo.leave_shared_vault(id, now)?))
    }

    /// A manager's device answers the members' requests (leave, rotation)
    /// with a new key; what it did.
    pub fn process_rekey_requests(&self, now: i64) -> Result<Vec<FfiRekeyNotice>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .process_rekey_requests(now)?
                .iter()
                .map(FfiRekeyNotice::from)
                .collect())
        })
    }

    /// Remove a member with a new key.
    pub fn remove_member(
        &self,
        vault_id: String,
        account_id: String,
        now: i64,
    ) -> Result<FfiRemoval, OnePassError> {
        let (vault_id, account_id) = (parse_id(&vault_id)?, parse_id(&account_id)?);
        self.with(|repo| {
            let o = repo.remove_member(vault_id, account_id, now)?;
            Ok(FfiRemoval {
                generation: o.generation,
                seen_items: o.seen_items,
            })
        })
    }

    /// A manager takes over a vault whose owner is gone: a copy under a new
    /// id, this account its owner.
    pub fn transfer_by_copy(
        &self,
        vault_id: String,
        now: i64,
    ) -> Result<FfiSharedVault, OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| Ok(shared_to_ffi(&repo.transfer_by_copy(id, now)?)))
    }

    /// The owner, alone in the vault, makes it personal again.
    pub fn stop_sharing(&self, vault_id: String, now: i64) -> Result<FfiVault, OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| {
            let v = repo.stop_sharing(id, now)?;
            let live = repo
                .items(&v)?
                .iter()
                .filter(|i| i.trashed_at.is_none())
                .count();
            Ok(vault_to_ffi(
                &v,
                u32::try_from(live).unwrap_or(u32::MAX),
                None,
            ))
        })
    }

    /// Hide a shared vault from the MCP server on this device.
    pub fn set_shared_vault_mcp_hidden(
        &self,
        vault_id: String,
        hidden: bool,
    ) -> Result<(), OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| Ok(repo.set_shared_vault_mcp_hidden(id, hidden)?))
    }

    /// The items a removed member could read, to change.
    pub fn seen_by_former_members(&self) -> Result<Vec<FfiSeenItem>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .seen_by_former_members()?
                .into_iter()
                .map(|(v, i)| FfiSeenItem {
                    vault_id: id_hex(v),
                    item_id: id_hex(i),
                })
                .collect())
        })
    }

    /// The members' key rotations seen in the shared zones.
    pub fn refresh_member_identities(
        &self,
        now: i64,
    ) -> Result<Vec<FfiIdentityChange>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .refresh_member_identities(now)?
                .iter()
                .map(FfiIdentityChange::from)
                .collect())
        })
    }

    /// Confirm a member's new identity `child` (64 hex characters) in every
    /// vault this account manages with them. A code for a writer or a
    /// manager is `ContactNotVerified`.
    pub fn adopt_member_identity(
        &self,
        account_id: String,
        child: String,
        proof: FfiAdoptionProof,
        now: i64,
    ) -> Result<Vec<FfiSharedVault>, OnePassError> {
        let account_id = parse_id(&account_id)?;
        let child = parse_hash(&child)?;
        let proof = AdoptionProof::try_from(proof)?;
        self.with(|repo| {
            Ok(repo
                .adopt_member_identity(account_id, child, proof, now)?
                .iter()
                .map(shared_to_ffi)
                .collect())
        })
    }

    /// The members that have not confirmed this account's new identity yet.
    pub fn members_not_confirmed(&self, vault_id: String) -> Result<Vec<String>, OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| Ok(ids(&repo.members_not_confirmed(id)?)))
    }
}
