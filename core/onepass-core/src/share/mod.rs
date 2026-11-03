//! Shared vaults (sharing spec 6 to 10, plan 2): vault key generations
//! wrapped per member, the signed membership chain, shared manifests and
//! the local pinned state of each shared vault.

use aws_lc_rs::digest::{self, SHA256};
use serde::{Deserialize, Serialize};

use crate::Id;

mod access;
mod action;
mod invite;
mod key;
pub(crate) mod manifest;
mod membership;
mod rekey;
mod state;

pub use access::{
    AccessTarget, CONTACT_ZONE_DOMAIN, ContactZoneOffer, MAILBOX_CREDENTIAL_ID_PREFIX,
    MAX_CREDENTIAL_ENVELOPE, MAX_ZONE_CA_PEM_BYTES, MAX_ZONE_URL_BYTES, SignedContactZoneOffer,
    SignedZoneAccess, ZONE_ACCESS_DOMAIN, ZONE_ACCESS_ID_PREFIX, ZONE_ACCESS_KIND,
    ZONE_ACCESS_SEED_LABEL, ZONE_CREDENTIAL_LABEL, ZoneAccess, ZoneHome, ZoneRole, ZoneSeed,
    credential_id_of, open_zone_credential, server_role, verify_contact_zone_offer,
    wrap_zone_credential,
};
pub use membership::{
    MEMBERSHIP_FORMAT, MEMBERSHIP_HISTORY, Member, MembershipBody, MembershipReason,
    MembershipSeen, MovedTo, Removed, SignedMembership, accept_first, accept_next,
    identity_pub_hash, merge_concurrent, merge_removed, sign_membership,
};

pub use manifest::{
    MembershipView, SharedSignedManifest, sign_shared_manifest, verify_shared_manifest,
};

pub use state::{
    FormerMemberExposure, PendingIdentity, SHARE_STATE_VERSION, SharePush, ShareState,
};

pub use action::{MemberView, ShareAction, SharedVaultInfo, ZoneMailboxKind};

pub use rekey::{RekeyNotice, RekeyReason, RekeyRequest};

pub use invite::{CredentialRenewal, InviteRecord, ShareInvite, ShareInviteView};

pub use key::{
    MAX_MEMBER_KEY_ENVELOPE, MemberKey, key_commit, key_context, member_key_id, open_member_key,
    wrap_member_key,
};

/// `wrap_key_labeled` label of a vault key generation for a member (spec
/// 19.1).
pub const VAULT_KEY_LABEL: &[u8] = b"onepass/share/vault-key/v1";
/// Hash prefix of a `MemberKey` record id (spec 19.1).
pub const MEMBER_KEY_ID_PREFIX: &[u8] = b"onepass/member-key-id/v1";
/// HMAC message prefix of a generation's key commitment (spec 19.1).
pub const KEY_COMMIT_INFO: &[u8] = b"onepass/vault-key-commit/v1";
/// Signature domain of a membership body (spec 19.1).
pub const MEMBERSHIP_DOMAIN: &[u8] = b"onepass/membership/v1";
/// Signature domain of a shared manifest blob (spec 19.1).
pub const SHARED_MANIFEST_DOMAIN: &[u8] = b"onepass/shared-manifest/v1";
/// Signature domain of a share invite (plan 2 ruling A-9).
pub const SHARE_INVITE_DOMAIN: &[u8] = b"onepass/share-invite/v1";
/// Signature domain of a rekey request (plan 2 ruling A-9).
pub const REKEY_REQUEST_DOMAIN: &[u8] = b"onepass/rekey-request/v1";
/// Most members of one shared vault (decision 12).
pub const MAX_MEMBERS: usize = 64;

/// A member's rights in a shared vault, ordered `Read < Write < Manage`
/// (spec 10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Role {
    Read,
    Write,
    Manage,
}

/// One identity of one account: what a membership names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MemberRef {
    pub account_id: Id,
    pub identity_id: Id,
}

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&SHA256);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

pub(crate) fn id16(h: &[u8; 32]) -> Id {
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    Id(id)
}
