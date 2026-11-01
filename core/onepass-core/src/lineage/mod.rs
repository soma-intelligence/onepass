//! Lineage records of key rotation v2 (spec sections 6.1 to 6.5 and 15):
//! genesis, rotation, intro and legacy intro, with strict codecs.
//!
//! Every body is `postcard`, decoded strictly (whole buffer, canonical
//! re-encoding, sorted and unique lists, no unchecked body in memory).
//! Signatures use the framing of `crypto/sign.rs` over `postcard(body)`.

use std::collections::BTreeMap;

use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use serde::{Deserialize, Serialize};

use crate::crypto::{HybridKemPublic, HybridVerifyingKey, IdentitySignature};
use crate::crypto::{HybridSignature, HybridSigningKey, IdentityKey, IdentityVerifyingKey};
use crate::device_keys::DeviceKeys;
use crate::devices::{DeviceKind, DeviceMode};
use crate::manifest::SeenManifest;
use crate::{Error, Id, Result};

mod codec;
mod legacy;
pub mod resolve;
pub mod verify;

pub(crate) use codec::{check_entry, decode_strict_with};
pub use codec::{check_genesis, check_intro, check_legacy_intro, check_rotation};
pub use legacy::{LegacyAnchor, LegacyIntros, accept_legacy_intros, legacy_intro_id};
pub use verify::{
    verify_genesis, verify_intro, verify_intro_identity, verify_legacy_intro, verify_rotation,
};

/// Format byte of every body.
pub const LINEAGE_FORMAT: u8 = 1;
/// Most devices in a roster.
pub const MAX_ROSTER: usize = 64;

/// Signature domain of a genesis, by the creator's device key.
pub const GENESIS_DOMAIN: &[u8] = b"onepass/genesis/v1";
/// Signature domain of a genesis, by the identity key.
pub const GENESIS_IDENTITY_DOMAIN: &[u8] = b"onepass/genesis/identity/v1";
/// Signature domain of a rotation, by the rotator's device key.
pub const ROTATION_DOMAIN: &[u8] = b"onepass/rotation/v1";
/// Signature domain of a rotation, by the new identity key.
pub const ROTATION_IDENTITY_DOMAIN: &[u8] = b"onepass/rotation/identity/v1";
/// Signature domain of an intro, by the introducer's device key (and, for
/// a kit self-intro, by the identity key).
pub const INTRO_DOMAIN: &[u8] = b"onepass/device-intro/v1";
/// Signature domain of a legacy intro, by the account signing key.
pub const LEGACY_DEVICE_DOMAIN: &[u8] = b"onepass/legacy-device/v1";

const LINEAGE_PREFIX: &[u8] = b"onepass/lineage/v1";
const GENESIS_TAG: u8 = 0x00;
const ROTATION_TAG: u8 = 0x01;
const IDENTITY_ID_PREFIX: &[u8] = b"onepass/identity-id/v1";
const DELIVERY_ID_PREFIX: &[u8] = b"onepass/delivery-id/v1";
const INTRO_ID_PREFIX: &[u8] = b"onepass/intro-id/v1";
const RECREATED_VAULT_ID_PREFIX: &[u8] = b"onepass/recreated-vault-id/v1";
const RECREATED_VAULT_KEY_INFO: &[u8] = b"onepass/recreated-vault-key/v1";
const ROTATION_CODE_INFO: &[u8] = b"onepass/rotation/code/v1";

/// One trusted device of a roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    pub device_id: Id,
    pub sign_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
    /// At most 64 characters.
    pub name: String,
    pub kind: DeviceKind,
    pub mode: DeviceMode,
    pub introduced_by: Option<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisBody {
    pub format: u8,
    pub account_id: Id,
    pub identity_pub: IdentityVerifyingKey,
    pub creator: RosterEntry,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationReason {
    Revoke,
    Rotate,
    RotateWithPassword,
    Reapply,
    Finish,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationBody {
    pub format: u8,
    pub account_id: Id,
    /// Parent generation + 1.
    pub generation: u64,
    /// Lineage hash of the parent (genesis or rotation).
    pub parent: [u8; 32],
    pub rotator: Id,
    pub reason: RotationReason,
    /// Sorted, unique, never the rotator.
    pub revoked: Vec<Id>,
    /// Sorted by device id, the rotator included, no revoked id, at most 64.
    pub roster: Vec<RosterEntry>,
    /// The new identity.
    pub identity_pub: IdentityVerifyingKey,
    pub params_hash: [u8; 32],
    pub keyset_hash: [u8; 32],
    /// Recipient (roster minus rotator) and SHA-256 of the envelope.
    pub deliveries: Vec<(Id, [u8; 32])>,
    /// Per live vault, the old-identity manifest the content was rotated from.
    pub from_heads: BTreeMap<Id, SeenManifest>,
    /// Informative, shown to the user.
    pub issued_at: i64,
}

/// A body with the device signature and the identity signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<B> {
    pub body: B,
    pub device_sig: HybridSignature,
    pub identity_sig: IdentitySignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineageRecord {
    Genesis(Signed<GenesisBody>),
    Rotation(Signed<RotationBody>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntroBody {
    pub format: u8,
    pub account_id: Id,
    pub head: [u8; 32],
    pub entry: RosterEntry,
    pub introducer: Id,
    /// The new device's proof of possession, context = account id.
    pub pop: HybridSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIntro {
    pub body: IntroBody,
    pub sig: HybridSignature,
    /// Only for a kit self-intro (spec 7.5 step 5).
    pub identity_sig: Option<IdentitySignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyIntroBody {
    pub account_id: Id,
    pub genesis_hash: [u8; 32],
    pub entry: RosterEntry,
    /// The device's proof of possession, context = account id.
    pub pop: HybridSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLegacyIntro {
    pub body: LegacyIntroBody,
    pub account_sig: HybridSignature,
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&SHA256);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Lineage hash of a rotation body (the signatures are not hashed).
pub(crate) fn rotation_hash(body: &RotationBody) -> [u8; 32] {
    sha256(&[LINEAGE_PREFIX, &[ROTATION_TAG], &body_bytes(body)])
}

pub(crate) fn body_bytes<T: Serialize>(body: &T) -> Vec<u8> {
    postcard::to_allocvec(body).expect("lineage body encodes")
}

/// The record id of the lineage record whose hash is `hash`: `hash[..16]`.
pub fn record_id_of(hash: &[u8; 32]) -> Id {
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);
    Id(id)
}

impl LineageRecord {
    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("lineage record encodes")
    }

    /// Strict: the whole buffer, structural checks of the body, valid key
    /// and signature lengths and a canonical re-encoding equal to the input.
    pub fn decode(b: &[u8]) -> Result<LineageRecord> {
        codec::decode_record(b)
    }

    /// `SHA-256("onepass/lineage/v1" || tag || postcard(body))`, tag 0x00
    /// for a genesis and 0x01 for a rotation.
    pub fn hash(&self) -> [u8; 32] {
        match self {
            LineageRecord::Genesis(s) => {
                sha256(&[LINEAGE_PREFIX, &[GENESIS_TAG], &body_bytes(&s.body)])
            }
            LineageRecord::Rotation(s) => rotation_hash(&s.body),
        }
    }

    /// `hash()[..16]`.
    pub fn record_id(&self) -> Id {
        record_id_of(&self.hash())
    }

    /// 0 for a genesis.
    pub fn generation(&self) -> u64 {
        match self {
            LineageRecord::Genesis(_) => 0,
            LineageRecord::Rotation(s) => s.body.generation,
        }
    }

    /// `None` for a genesis.
    pub fn parent(&self) -> Option<[u8; 32]> {
        match self {
            LineageRecord::Genesis(_) => None,
            LineageRecord::Rotation(s) => Some(s.body.parent),
        }
    }

    pub fn account_id(&self) -> Id {
        match self {
            LineageRecord::Genesis(s) => s.body.account_id,
            LineageRecord::Rotation(s) => s.body.account_id,
        }
    }

    /// The identity this record introduces.
    pub fn identity_pub(&self) -> &IdentityVerifyingKey {
        match self {
            LineageRecord::Genesis(s) => &s.body.identity_pub,
            LineageRecord::Rotation(s) => &s.body.identity_pub,
        }
    }
}

impl SignedIntro {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("intro encodes")
    }

    /// Strict, like [`LineageRecord::decode`].
    pub fn decode(b: &[u8]) -> Result<SignedIntro> {
        codec::decode_intro(b)
    }
}

impl SignedLegacyIntro {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("legacy intro encodes")
    }

    /// Strict, like [`LineageRecord::decode`].
    pub fn decode(b: &[u8]) -> Result<SignedLegacyIntro> {
        codec::decode_legacy_intro(b)
    }
}

struct Len8;

impl KeyType for Len8 {
    fn len(&self) -> usize {
        8
    }
}

/// The 6-digit rotation code: `HKDF-SHA256(ikm = h, info =
/// "onepass/rotation/code/v1")`, 8 bytes big endian, modulo 10^6.
pub fn rotation_code(h: &[u8; 32]) -> u32 {
    let prk = Salt::new(HKDF_SHA256, &[]).extract(h);
    let okm = prk
        .expand(&[ROTATION_CODE_INFO], Len8)
        .expect("8 bytes is a valid HKDF length");
    let mut out = [0u8; 8];
    okm.fill(&mut out).expect("8 bytes fill");
    (u64::from_be_bytes(out) % 1_000_000) as u32
}

fn id16(h: [u8; 32]) -> Id {
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    Id(id)
}

/// `SHA-256("onepass/intro-id/v1" || postcard(body))[..16]`.
pub fn intro_id(body: &IntroBody) -> Id {
    id16(sha256(&[INTRO_ID_PREFIX, &body_bytes(body)]))
}

/// `SHA-256("onepass/delivery-id/v1" || h || recipient_id)[..16]`.
pub fn delivery_id(h: &[u8; 32], recipient: Id) -> Id {
    id16(sha256(&[DELIVERY_ID_PREFIX, h, &recipient.0]))
}

/// `SHA-256("onepass/identity-id/v1" || identity_pub)[..16]`.
pub fn identity_id(pubkey: &IdentityVerifyingKey) -> Id {
    id16(sha256(&[IDENTITY_ID_PREFIX, pubkey.as_bytes()]))
}

/// The id of a vault of a left identity re-created under `identity_pub`
/// (spec 10.4): `SHA-256("onepass/recreated-vault-id/v1" || identity_pub
/// || old vault id)[..16]`. Every device that replays its own writes of
/// that vault under that identity re-creates the same vault (Task 19
/// carried item 2), never one each.
pub fn recreated_vault_id(identity_pub: &IdentityVerifyingKey, old: Id) -> Id {
    id16(sha256(&[
        RECREATED_VAULT_ID_PREFIX,
        identity_pub.as_bytes(),
        &old.0,
    ]))
}

/// The vault key of a vault re-created under an identity (spec 10.4,
/// review I3 of Task 19): `HKDF-SHA256(ikm = the identity's KEM secret,
/// info = "onepass/recreated-vault-key/v1" || old vault id)`. Every
/// device of that identity derives the same key, so two re-creations of
/// one vault before either synced are concurrent edits of one vault, and a
/// vault planted at the derived id under any other key is told apart. Only
/// holders of the identity's KEM secret derive it, as only they open its
/// envelope.
pub(crate) fn recreated_vault_key(
    kem_secret: &[u8],
    old: Id,
) -> Result<crate::crypto::SymmetricKey> {
    crate::crypto::key::hkdf32(&[], kem_secret, &[RECREATED_VAULT_KEY_INFO, &old.0])
}

/// Sign a genesis with the creator's device key and the identity key.
pub fn sign_genesis(
    body: GenesisBody,
    device: &DeviceKeys,
    identity: &IdentityKey,
) -> Result<Signed<GenesisBody>> {
    let msg = body_bytes(&body);
    Ok(Signed {
        device_sig: device.sign(GENESIS_DOMAIN, &msg)?,
        identity_sig: identity.sign(GENESIS_IDENTITY_DOMAIN, &msg)?,
        body,
    })
}

/// Sign a rotation with the rotator's device key and the new identity key.
pub fn sign_rotation(
    body: RotationBody,
    device: &DeviceKeys,
    identity: &IdentityKey,
) -> Result<Signed<RotationBody>> {
    let msg = body_bytes(&body);
    Ok(Signed {
        device_sig: device.sign(ROTATION_DOMAIN, &msg)?,
        identity_sig: identity.sign(ROTATION_IDENTITY_DOMAIN, &msg)?,
        body,
    })
}

/// Sign an intro with the introducer's device key; `identity` only for a
/// kit self-intro.
pub fn sign_intro(
    body: IntroBody,
    introducer: &DeviceKeys,
    identity: Option<&IdentityKey>,
) -> Result<SignedIntro> {
    let msg = body_bytes(&body);
    Ok(SignedIntro {
        sig: introducer.sign(INTRO_DOMAIN, &msg)?,
        identity_sig: identity.map(|k| k.sign(INTRO_DOMAIN, &msg)).transpose()?,
        body,
    })
}

/// Sign a legacy intro with the account signing key.
pub fn sign_legacy_intro(
    body: LegacyIntroBody,
    account: &HybridSigningKey,
) -> Result<SignedLegacyIntro> {
    let account_sig = account.sign(LEGACY_DEVICE_DOMAIN, &body_bytes(&body))?;
    Ok(SignedLegacyIntro { body, account_sig })
}

/// A shorthand for the error every failed signature check returns.
pub(crate) fn bad_signature() -> Error {
    Error::Integrity(crate::IntegrityError::Signature)
}
