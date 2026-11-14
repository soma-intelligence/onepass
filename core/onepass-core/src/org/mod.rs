//! Organizations (OnePass Business): the constants and the id shared by the
//! org lineage, roster, keyset and join modules.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::crypto::random_array;

mod identity;
mod join;
mod keyset;
mod lineage;
mod pin;
mod rebase;
mod roster;
mod rules;

pub use identity::{OrgIdentityPublic, OrgSecrets, fingerprint_words, org_fingerprint};
pub use join::{
    Invitation, JoinRequestBody, MAX_JOIN_GENESIS_BYTES, SignedJoinRequest, VerifiedJoin,
    activate_member, invite_member, join_code, join_code_of, sign_join_request,
    verify_join_request,
};
pub use keyset::{OrgKeyset, SealedOrgKeyset, open_org_keyset, seal_org_keyset};
pub use lineage::{
    MemberRef, OrgChangeBody, OrgChangeKind, OrgGenesisBody, OrgHeadInfo, OrgLineage,
    OrgRecordBody, RosterCheckpoint, SignedOrgRecord, add_owner_signature, quorum, sign_org_change,
    sign_org_genesis, verify_org_chain, verify_org_genesis,
};
pub use pin::{
    OrgPin, PinSource, dns_fingerprint, dns_txt_value, fingerprint_base32, parse_dns_txt, pin_org,
};
pub use rebase::{merge_members, rebase_roster};
pub use roster::{
    MemberState, OrgMember, Role, RoleSet, RosterBody, SignedRoster, invite_commit,
    member_kem_hash, scim_id_hash, sign_roster,
};
pub use rules::{
    accept_first_roster, accept_next_roster, accept_roster_chain, check_transition, founding_roster,
};

/// The id of an organization: 16 random bytes fixed at its genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OrgId(pub [u8; 16]);

impl OrgId {
    /// A fresh random org id.
    pub fn generate() -> Result<OrgId> {
        Ok(OrgId(random_array::<16>()?))
    }
}

pub const ORG_FORMAT: u8 = 1;
/// X16: the fingerprint commits to the whole genesis.
pub const ORG_FINGERPRINT_PREFIX: &[u8] = b"onepass/org-fingerprint/v1";
pub const ORG_GENESIS_DOMAIN: &[u8] = b"onepass/org-genesis/v1";
pub const ORG_CHANGE_DOMAIN: &[u8] = b"onepass/org-change/v1";
pub const ORG_ROSTER_DOMAIN: &[u8] = b"onepass/org-roster/v1";
pub const ORG_KEYSET_LABEL: &[u8] = b"onepass/org-keyset/v1";
pub const ORG_JOIN_DOMAIN: &[u8] = b"onepass/org-join/v1";
pub const SCIM_ID_PREFIX: &[u8] = b"onepass/scim-id/v1";
pub const ORG_WORDS_PREFIX: &[u8] = b"onepass/org-words/v1";
pub const ORG_INVITE_PREFIX: &[u8] = b"onepass/org-invite/v1";
pub const ORG_MEMBER_KEM_PREFIX: &[u8] = b"onepass/org-member-kem/v1";
pub const ORG_JOIN_CODE_PREFIX: &[u8] = b"onepass/org-join-code/v1";
pub const ORG_PIN_VERSION: u8 = 1;
pub const MAX_DISPLAY_NAME_BYTES: usize = 64;
pub const MAX_ORG_OWNERS: usize = 8;
pub const MAX_MEMBER_DEVICES: usize = 8;
pub const MAX_ROSTER_MEMBERS: usize = 2000;
pub const MAX_ORG_NAME_CHARS: usize = 128;
/// The org mailbox's per-record cap.
pub const MAX_ORG_RECORD_BYTES: usize = 900 * 1024;

/// `DevicePublic::fingerprint()`.
pub type DeviceFpr = [u8; 32];

/// SHA-256 over the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_id_generate_differs() {
        assert_ne!(OrgId::generate().unwrap(), OrgId::generate().unwrap());
    }

    #[test]
    fn labels_are_exact() {
        assert_eq!(ORG_FINGERPRINT_PREFIX, b"onepass/org-fingerprint/v1");
        assert_eq!(ORG_GENESIS_DOMAIN, b"onepass/org-genesis/v1");
        assert_eq!(ORG_CHANGE_DOMAIN, b"onepass/org-change/v1");
        assert_eq!(ORG_ROSTER_DOMAIN, b"onepass/org-roster/v1");
        assert_eq!(ORG_KEYSET_LABEL, b"onepass/org-keyset/v1");
        assert_eq!(ORG_JOIN_DOMAIN, b"onepass/org-join/v1");
        assert_eq!(SCIM_ID_PREFIX, b"onepass/scim-id/v1");
        assert_eq!(ORG_WORDS_PREFIX, b"onepass/org-words/v1");
        assert_eq!(ORG_INVITE_PREFIX, b"onepass/org-invite/v1");
        assert_eq!(ORG_MEMBER_KEM_PREFIX, b"onepass/org-member-kem/v1");
        assert_eq!(ORG_JOIN_CODE_PREFIX, b"onepass/org-join-code/v1");
    }

    #[test]
    fn sha256_concatenates_parts() {
        assert_eq!(sha256(&[b"ab", b"c"]), sha256(&[b"abc"]));
        assert_ne!(sha256(&[b"abc"]), sha256(&[b"abd"]));
    }
}
