//! A member's request that a manager rotate a shared vault's key (sharing
//! spec 9.4, 12.2, S12): written by a member who leaves, or by a member
//! whose account rotated away from a revoked device. Any manager who reads
//! it rotates the key; rotating grants nothing to anyone.

use serde::{Deserialize, Serialize};

use super::{MemberRef, REKEY_REQUEST_DOMAIN, id16, sha256};
use crate::crypto::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::lineage::decode_strict_with;
use crate::{Error, Id, Result};

const BAD: Error = Error::InvalidFormat("rekey request");
const ID_PREFIX: &[u8] = b"onepass/rekey-request-id/v1";

/// Why a member asks for a new key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RekeyReason {
    /// The signer left the vault (spec 9.4).
    Leave,
    /// The signer's account rotated its keys (spec 12.2).
    MemberRotation,
}

/// The signed request, kept as a `RecordKind::RekeyRequest` record of the
/// vault's zone, id `RekeyRequest::id_for`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyRequest {
    pub vault_id: Id,
    pub account_id: Id,
    pub lineage_hash: Option<[u8; 32]>,
    pub reason: RekeyReason,
    /// The generation the request is about: a rotation past it satisfies
    /// it.
    pub at_generation: u32,
    pub signer: MemberRef,
    pub sig: HybridSignature,
}

/// What a manager's client did with a request (`process_rekey_requests`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyNotice {
    pub vault_id: Id,
    pub reason: RekeyReason,
    pub account_id: Id,
    /// The generation after the rotation.
    pub generation: u32,
}

fn message(
    vault_id: Id,
    account_id: Id,
    lineage_hash: &Option<[u8; 32]>,
    reason: RekeyReason,
    at_generation: u32,
    signer: &MemberRef,
) -> Vec<u8> {
    postcard::to_allocvec(&(
        vault_id,
        account_id,
        lineage_hash,
        reason,
        at_generation,
        signer,
    ))
    .expect("rekey request encodes")
}

impl RekeyRequest {
    pub fn sign(
        vault_id: Id,
        lineage_hash: Option<[u8; 32]>,
        reason: RekeyReason,
        at_generation: u32,
        signer: MemberRef,
        key: &HybridSigningKey,
    ) -> Result<RekeyRequest> {
        let account_id = signer.account_id;
        let sig = key.sign(
            REKEY_REQUEST_DOMAIN,
            &message(
                vault_id,
                account_id,
                &lineage_hash,
                reason,
                at_generation,
                &signer,
            ),
        )?;
        Ok(RekeyRequest {
            vault_id,
            account_id,
            lineage_hash,
            reason,
            at_generation,
            signer,
            sig,
        })
    }

    pub fn verify(&self, signer_key: &HybridVerifyingKey) -> Result<()> {
        signer_key.verify(
            REKEY_REQUEST_DOMAIN,
            &message(
                self.vault_id,
                self.account_id,
                &self.lineage_hash,
                self.reason,
                self.at_generation,
                &self.signer,
            ),
            &self.sig,
        )
    }

    /// One request per member, vault and generation.
    pub fn id_for(vault_id: Id, account_id: Id, at_generation: u32) -> Id {
        id16(&sha256(&[
            ID_PREFIX,
            &vault_id.0,
            &account_id.0,
            &at_generation.to_be_bytes(),
        ]))
    }

    pub fn id(&self) -> Id {
        Self::id_for(self.vault_id, self.account_id, self.at_generation)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("rekey request encodes")
    }

    /// Strict decoding: the signer is the account the request is about,
    /// and the generation is not zero.
    pub fn decode(b: &[u8]) -> Result<RekeyRequest> {
        let r: RekeyRequest = decode_strict_with(b, BAD)?;
        if r.signer.account_id != r.account_id || r.at_generation == 0 {
            return Err(BAD);
        }
        Ok(r)
    }
}
