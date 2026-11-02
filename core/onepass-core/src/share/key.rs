//! Vault key generations and their `MemberKey` envelopes (spec 6.1 choice
//! A, 6.2): one envelope per member and generation, under the member's
//! pinned KEM key, bound to the vault, the generation and the member's
//! identity, and checked against the generation's key commitment before
//! any use (A15, A16).

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac::{self, HMAC_SHA256};
use serde::{Deserialize, Serialize};

use super::{KEY_COMMIT_INFO, MEMBER_KEY_ID_PREFIX, MemberRef, VAULT_KEY_LABEL, id16, sha256};
use crate::account::Keyset;
use crate::crypto::kem::{unwrap_key_labeled, wrap_key_labeled};
use crate::crypto::{HybridKemPublic, SymmetricKey};
use crate::lineage::decode_strict_with;
use crate::{Error, Id, IntegrityError, Result};

/// Largest envelope a `MemberKey` carries (a hybrid KEM envelope is about
/// 1.7 KiB).
pub const MAX_MEMBER_KEY_ENVELOPE: usize = 4096;

/// The vault key of generation `generation`, wrapped for one member
/// (record `RecordKind::MemberKey`, id `member_key_id`, immutable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberKey {
    pub vault_id: Id,
    pub generation: u32,
    pub account_id: Id,
    pub identity_id: Id,
    pub envelope: Vec<u8>,
}

impl MemberKey {
    pub fn member(&self) -> MemberRef {
        MemberRef {
            account_id: self.account_id,
            identity_id: self.identity_id,
        }
    }

    /// The record id of this envelope.
    pub fn id(&self) -> Id {
        member_key_id(self.vault_id, self.generation, &self.member())
    }

    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("member key encodes")
    }

    /// Strict: the whole buffer, canonical, generation from 1, an envelope
    /// of at most `MAX_MEMBER_KEY_ENVELOPE` bytes.
    pub fn decode(b: &[u8]) -> Result<MemberKey> {
        let mk: MemberKey = decode_strict_with(b, Error::InvalidFormat("member key"))?;
        if mk.generation == 0
            || mk.envelope.is_empty()
            || mk.envelope.len() > MAX_MEMBER_KEY_ENVELOPE
        {
            return Err(Error::InvalidFormat("member key"));
        }
        Ok(mk)
    }
}

/// `SHA-256("onepass/member-key-id/v1" || vault || g || account ||
/// identity)[..16]`, `g` big endian on 4 bytes.
pub fn member_key_id(vault: Id, g: u32, member: &MemberRef) -> Id {
    id16(&sha256(&[
        MEMBER_KEY_ID_PREFIX,
        &vault.0,
        &g.to_be_bytes(),
        &member.account_id.0,
        &member.identity_id.0,
    ]))
}

/// The KEM context of an envelope: `postcard((vault_id, generation,
/// account_id, identity_id))`.
pub fn key_context(vault: Id, g: u32, member: &MemberRef) -> Vec<u8> {
    postcard::to_allocvec(&(vault, g, member.account_id, member.identity_id))
        .expect("key context encodes")
}

/// HMAC-SHA256 under the vault key of `"onepass/vault-key-commit/v1" ||
/// vault_id || g` (`g` big endian on 4 bytes): commits a membership body
/// to the key of its generation.
pub fn key_commit(key: &SymmetricKey, vault: Id, g: u32) -> [u8; 32] {
    let k = hmac::Key::new(HMAC_SHA256, key.expose());
    let mut ctx = hmac::Context::with_key(&k);
    ctx.update(KEY_COMMIT_INFO);
    ctx.update(&vault.0);
    ctx.update(&g.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.sign().as_ref());
    out
}

/// Wrap `key` (generation `g` of `vault`) for `member` under `kem_pub`,
/// the member's KEM key as pinned in the contact book.
pub fn wrap_member_key(
    kem_pub: &HybridKemPublic,
    key: &SymmetricKey,
    vault: Id,
    g: u32,
    member: &MemberRef,
) -> Result<MemberKey> {
    if g == 0 {
        return Err(Error::InvalidFormat("member key"));
    }
    let envelope = wrap_key_labeled(
        kem_pub,
        key,
        VAULT_KEY_LABEL,
        &key_context(vault, g, member),
    )?;
    Ok(MemberKey {
        vault_id: vault,
        generation: g,
        account_id: member.account_id,
        identity_id: member.identity_id,
        envelope,
    })
}

/// Open `mk` with this account's keyset: the current KEM key, then each
/// retired one (an envelope made before a rotation). The opened key must
/// match `expected_commit` (the generation's commitment from the pinned
/// membership body), checked before any use: `Integrity(Commitment)`
/// otherwise (A15). An envelope for another vault, generation, account or
/// identity does not open (A16).
pub fn open_member_key(
    keyset: &Keyset,
    mk: &MemberKey,
    expected_commit: &[u8; 32],
) -> Result<SymmetricKey> {
    let context = key_context(mk.vault_id, mk.generation, &mk.member());
    let mut last = Error::Crypto;
    for kem in std::iter::once(&keyset.kem).chain(keyset.retired_kem.iter()) {
        match unwrap_key_labeled(kem, &mk.envelope, VAULT_KEY_LABEL, &context) {
            Ok(key) => {
                let commit = key_commit(&key, mk.vault_id, mk.generation);
                if verify_slices_are_equal(&commit, expected_commit).is_err() {
                    return Err(IntegrityError::Commitment.into());
                }
                return Ok(key);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}
