//! Invitations carried in a contact pair's zone (sharing spec 7.3, 13.5):
//! a manager's signed invite to a shared vault, the body that removed the
//! recipient (Task 9) and a renewed credential (Task 14).

use serde::{Deserialize, Serialize};

use super::{MemberRef, SHARE_INVITE_DOMAIN, SignedMembership, ZoneHome, id16, sha256};
use crate::crypto::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::lineage::decode_strict_with;
use crate::{Error, Id, Result};

use super::MAX_CREDENTIAL_ENVELOPE;

const BAD: Error = Error::InvalidFormat("share invite");

/// A manager's invitation of a member to a shared vault: the body that
/// adds the member, where the zone lives and the member's credential seed
/// wrapped for its pinned KEM key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareInvite {
    pub vault_id: Id,
    pub membership: SignedMembership,
    pub home: ZoneHome,
    pub credential: Vec<u8>,
    pub signer: MemberRef,
    pub sig: HybridSignature,
}

/// A new credential for a member's own account (Task 14): same domain as
/// the invite, another tag in the signed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRenewal {
    pub vault_id: Id,
    pub home: ZoneHome,
    pub credential: Vec<u8>,
    pub signer: MemberRef,
    pub sig: HybridSignature,
}

/// What a `ShareInvite` record of a contact zone holds. Decoded once per
/// record and never kept in bulk, so the variants stay unboxed.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InviteRecord {
    Vault(ShareInvite),
    /// The signed body that removed the recipient (Task 9).
    Removed(SignedMembership),
    Credential(CredentialRenewal),
}

fn invite_message(
    vault_id: Id,
    membership: &SignedMembership,
    home: &ZoneHome,
    credential: &[u8],
    signer: &MemberRef,
) -> Vec<u8> {
    postcard::to_allocvec(&(0u8, vault_id, membership, home, credential, signer))
        .expect("invite encodes")
}

fn renewal_message(
    vault_id: Id,
    home: &ZoneHome,
    credential: &[u8],
    signer: &MemberRef,
) -> Vec<u8> {
    postcard::to_allocvec(&(1u8, vault_id, home, credential, signer)).expect("renewal encodes")
}

fn check_credential(c: &[u8]) -> Result<()> {
    if c.is_empty() || c.len() > MAX_CREDENTIAL_ENVELOPE {
        return Err(BAD);
    }
    Ok(())
}

impl ShareInvite {
    pub fn sign(
        vault_id: Id,
        membership: SignedMembership,
        home: ZoneHome,
        credential: Vec<u8>,
        signer: MemberRef,
        key: &HybridSigningKey,
    ) -> Result<ShareInvite> {
        home.check()?;
        check_credential(&credential)?;
        let sig = key.sign(
            SHARE_INVITE_DOMAIN,
            &invite_message(vault_id, &membership, &home, &credential, &signer),
        )?;
        Ok(ShareInvite {
            vault_id,
            membership,
            home,
            credential,
            signer,
            sig,
        })
    }

    pub fn verify(&self, signer_key: &HybridVerifyingKey) -> Result<()> {
        signer_key.verify(
            SHARE_INVITE_DOMAIN,
            &invite_message(
                self.vault_id,
                &self.membership,
                &self.home,
                &self.credential,
                &self.signer,
            ),
            &self.sig,
        )
    }
}

impl CredentialRenewal {
    pub fn sign(
        vault_id: Id,
        home: ZoneHome,
        credential: Vec<u8>,
        signer: MemberRef,
        key: &HybridSigningKey,
    ) -> Result<CredentialRenewal> {
        home.check()?;
        check_credential(&credential)?;
        let sig = key.sign(
            SHARE_INVITE_DOMAIN,
            &renewal_message(vault_id, &home, &credential, &signer),
        )?;
        Ok(CredentialRenewal {
            vault_id,
            home,
            credential,
            signer,
            sig,
        })
    }

    pub fn verify(&self, signer_key: &HybridVerifyingKey) -> Result<()> {
        signer_key.verify(
            SHARE_INVITE_DOMAIN,
            &renewal_message(self.vault_id, &self.home, &self.credential, &self.signer),
            &self.sig,
        )
    }
}

impl InviteRecord {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("invite record encodes")
    }

    /// Strict decoding and shape rules (bodies, home, envelope sizes);
    /// signatures are checked by the caller against its contact book.
    pub fn decode(b: &[u8]) -> Result<InviteRecord> {
        let r: InviteRecord = decode_strict_with(b, BAD)?;
        match &r {
            InviteRecord::Vault(i) => {
                i.membership.body.check()?;
                i.home.check()?;
                check_credential(&i.credential)?;
                if i.membership.body.vault_id != i.vault_id {
                    return Err(BAD);
                }
            }
            InviteRecord::Removed(m) => m.body.check()?,
            InviteRecord::Credential(c) => {
                c.home.check()?;
                check_credential(&c.credential)?;
            }
        }
        Ok(r)
    }

    /// Record id: `SHA-256(data)[..16]`.
    pub fn id(&self) -> Id {
        id16(&sha256(&[&self.encode()]))
    }
}

/// An invitation as the screens show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareInviteView {
    pub id: Id,
    /// The vault meta is sealed under the vault key: no name before joining.
    pub vault_name_hint: Option<String>,
    pub from_name_local: String,
    pub role: super::Role,
    pub server_host: String,
}

/// A member's lineage record copied into the zones it shares with others
/// (sharing spec 12.2, Task 13): its rotation, or an intro, so that the
/// other members can follow its identity. `RecordKind::MemberLineage`,
/// immutable, id `MemberLineageRecord::id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberLineageRecord {
    Lineage(crate::lineage::LineageRecord),
    Intro(crate::lineage::SignedIntro),
}

impl MemberLineageRecord {
    /// The lineage record's own id, or the intro's.
    pub fn id(&self) -> Id {
        match self {
            MemberLineageRecord::Lineage(r) => r.record_id(),
            MemberLineageRecord::Intro(i) => crate::lineage::intro_id(&i.body),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("member lineage encodes")
    }

    /// Strict decoding; signatures are checked against the member's
    /// pinned lineage by the reader.
    pub fn decode(b: &[u8]) -> Result<MemberLineageRecord> {
        decode_strict_with(b, Error::InvalidFormat("member lineage"))
    }
}
