//! Organization (OnePass Business) types of the FFI: roles, members, the
//! pinned state the apps show, the fingerprint words and the join link.
//! Swift gets display values only: never org record bytes, org secrets or
//! the owner keyset.

mod invite;

use onepass_core::generator::Wordlist;
use onepass_core::org::{fingerprint_words, parse_dns_txt};

use crate::error::{OnePassError, invalid};

pub use invite::{org_invite_encode, org_invite_parse};

/// A role of an organization member (a member holds a set of them).
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FfiOrgRole {
    Owner,
    Admin,
    UserManager,
    PolicyManager,
    Auditor,
    RecoveryOfficer,
    Provisioner,
}

/// Where a member stands in the roster.
#[derive(uniffi::Enum, Debug, Clone, PartialEq, Eq)]
pub enum FfiMemberState {
    Invited,
    Active,
    Suspended,
    /// `at`: Unix seconds. `by`: the account id (32 hex) that removed it.
    Removed {
        at: i64,
        by: String,
    },
}

/// How this device pinned the organization.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiPinSource {
    Mdm,
    Dns,
    Tofu { verified: bool },
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgDevice {
    /// 64 hex.
    pub fingerprint: String,
    pub name: Option<String>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgMember {
    /// 32 lowercase hex.
    pub account_id: String,
    pub display_name: Option<String>,
    pub roles: Vec<FfiOrgRole>,
    pub state: FfiMemberState,
    pub devices: Vec<FfiOrgDevice>,
    /// In an earlier owner set of the lineage, not in the head.
    pub former_owner: bool,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgState {
    pub org_id: String,
    pub name: String,
    pub fingerprint: Vec<u8>,
    /// 4 groups of 5 words.
    pub fingerprint_words: Vec<Vec<String>>,
    /// `v=op1; org=...`, the DNS TXT value.
    pub dns_value: String,
    pub source: FfiPinSource,
    pub lineage_generation: u64,
    /// 0 when no roster is pinned yet.
    pub roster_seq: u64,
    /// 32 lowercase hex account ids.
    pub owners: Vec<String>,
    pub members: Vec<FfiOrgMember>,
}

/// The content of a join link (see `invite`).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiOrgInvite {
    pub server_url: String,
    /// 32 hex.
    pub mailbox_id: String,
    /// 32 hex.
    pub org_id: String,
    /// 32 hex: the Invited member's account id the inviter chose.
    pub account_id: String,
    pub fingerprint: Vec<u8>,
    /// 32 bytes.
    pub nonce: Vec<u8>,
    /// 32 bytes: the seed of the invite credential.
    pub credential_seed: Vec<u8>,
    /// 32 bytes: the one-use `managed` mailbox token.
    pub member_token: Vec<u8>,
    pub domain: Option<String>,
}

fn fpr_array(fingerprint: &[u8]) -> Result<[u8; 32], OnePassError> {
    fingerprint
        .try_into()
        .map_err(|_| invalid("organisation fingerprint"))
}

/// The 4 x 5 words of a fingerprint, always the EFF English list (the
/// words are read aloud and compared across devices, whatever their locale).
#[uniffi::export]
pub fn org_fingerprint_words(fingerprint: Vec<u8>) -> Result<Vec<Vec<String>>, OnePassError> {
    let fpr = fpr_array(&fingerprint)?;
    Ok(fingerprint_words(&fpr, Wordlist::EffEnglish)
        .into_iter()
        .map(|g| g.into_iter().collect())
        .collect())
}

/// The fingerprint of a DNS TXT value (`v=op1; org=<base32>`).
#[uniffi::export]
pub fn org_parse_dns_txt(text: String) -> Result<Vec<u8>, OnePassError> {
    Ok(parse_dns_txt(&text)?.to_vec())
}

/// The fingerprint of its bare base32 text (52 characters, any case): the
/// MDM `org_fpr` value.
#[uniffi::export]
pub fn org_parse_fingerprint(text: String) -> Result<Vec<u8>, OnePassError> {
    Ok(parse_fingerprint(&text)?.to_vec())
}

pub(crate) fn parse_fingerprint(text: &str) -> Result<[u8; 32], OnePassError> {
    let text = text.trim_ascii();
    if text.len() != 52 {
        return Err(invalid("organisation fingerprint"));
    }
    data_encoding::BASE32_NOPAD
        .decode(text.to_ascii_uppercase().as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("organisation fingerprint"))
}
