//! Manifests of a shared vault (sharing spec 8): the personal manifest
//! format with an `EXT_V2` extension naming the membership body and key
//! generation, signed by one member under its own domain.

use serde::{Deserialize, Serialize};

use super::{MemberRef, MembershipBody, Role, SHARED_MANIFEST_DOMAIN};
use crate::crypto::{BlobKind, HybridSignature, HybridSigningKey, HybridVerifyingKey, open, seal};
use crate::lineage::decode_strict_with;
use crate::manifest::{
    Manifest, SeenManifest, aad, check_history, check_shape, decode_manifest, encode_manifest,
};
use crate::vault::Vault;
use crate::{Error, IntegrityError, Result, ValidationError};

const BAD: Error = Error::InvalidFormat("shared manifest");

/// A sealed shared manifest, the member who signed it, and the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSignedManifest {
    pub blob: Vec<u8>,
    pub signer: MemberRef,
    pub sig: HybridSignature,
}

impl SharedSignedManifest {
    /// Strict decoding of a record a hostile zone may serve. Nothing is
    /// verified here; see `verify_shared_manifest`.
    pub fn decode(b: &[u8]) -> Result<SharedSignedManifest> {
        decode_strict_with(b, BAD)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("shared manifest encodes")
    }
}

/// The signed message: the signer is bound with the blob, so a signature
/// cannot be moved to another member's name.
fn signed_message(signer: &MemberRef, blob: &[u8]) -> Vec<u8> {
    postcard::to_allocvec(&(signer, blob)).expect("signed message encodes")
}

/// The pinned membership chain a manifest is checked against: the head and
/// its known ancestors, newest first.
#[derive(Debug, Clone, Copy)]
pub struct MembershipView<'a> {
    pub head: &'a MembershipBody,
    pub ancestors: &'a [MembershipBody],
}

impl MembershipView<'_> {
    /// Head first, then the ancestors, newest first.
    fn bodies(&self) -> impl Iterator<Item = &MembershipBody> {
        std::iter::once(self.head).chain(self.ancestors.iter())
    }

    fn signing_key(&self, signer: &MemberRef) -> Option<&HybridVerifyingKey> {
        self.bodies()
            .flat_map(|b| b.members.iter())
            .find(|m| m.member_ref() == *signer)
            .map(|m| &m.sign_pub)
    }
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// Seal the manifest with the vault key of its generation and sign it as
/// `signer`. Refuses what `verify_shared_manifest` would refuse on its
/// shape, and a manifest without `ext.membership` and `ext.generation`.
pub fn sign_shared_manifest(
    vault: &Vault,
    key: &HybridSigningKey,
    signer: MemberRef,
    m: &Manifest,
) -> Result<SharedSignedManifest> {
    check_shape(vault, m)?;
    if !m.ext.as_ref().is_some_and(|e| e.membership.is_some()) {
        return Err(BAD);
    }
    let blob = seal(
        vault.key(),
        BlobKind::Manifest,
        &aad(vault.id),
        &encode_manifest(m),
    )?;
    let sig = key.sign(SHARED_MANIFEST_DOMAIN, &signed_message(&signer, &blob))?;
    Ok(SharedSignedManifest { blob, signer, sig })
}

/// Open a shared manifest this device wrote itself and still holds as a
/// pending row, without the checks of `verify_shared_manifest`: a rebase
/// reads where its lost write started from (the meta it was bound to may
/// no longer open).
pub(crate) fn open_own_shared_manifest(
    vault: &Vault,
    sm: &SharedSignedManifest,
) -> Result<Manifest> {
    let plain = open(vault.key(), BlobKind::Manifest, &aad(vault.id), &sm.blob)?;
    decode_manifest(&plain)
}

/// Verify a shared manifest (spec 8.2), in order: the signature under the
/// signer's key from the pinned chain (`Integrity(Signature)`); the opening
/// and decoding; the shape (as `verify_manifest`); the membership body it
/// names, unknown (`NotFound`, the caller sets it aside) or a known seq
/// with another hash (`Integrity(MembershipFork)`); the signer in that body
/// with `Write` or `Manage` and the same key (`Validation`); no body between
/// it and the head that changes the signer's role, drops the signer or
/// changes the generation (`Validation`); `ext.generation` equal to that
/// body's (`Integrity(WrongContext)`); a `meta_hash` change against
/// `prev_meta_hash` only by a `Manage` signer (`Validation`); then the
/// history against `last_seen` (`Integrity(ManifestRollback)`).
pub fn verify_shared_manifest(
    vault: &Vault,
    view: &MembershipView,
    sm: &SharedSignedManifest,
    last_seen: Option<&SeenManifest>,
    prev_meta_hash: Option<[u8; 32]>,
) -> Result<Manifest> {
    let key = view
        .signing_key(&sm.signer)
        .ok_or_else(|| refused("signer", "not a member of this vault"))?;
    key.verify(
        SHARED_MANIFEST_DOMAIN,
        &signed_message(&sm.signer, &sm.blob),
        &sm.sig,
    )?;
    let plain = open(vault.key(), BlobKind::Manifest, &aad(vault.id), &sm.blob)?;
    let m = decode_manifest(&plain)?;
    check_shape(vault, &m)?;
    let ext = m.ext.as_ref().ok_or(BAD)?;
    let (Some(seen), Some(generation)) = (ext.membership, ext.generation) else {
        return Err(BAD);
    };

    let pointed = match view.bodies().find(|b| b.seq == seen.seq) {
        Some(b) if b.hash() == seen.hash => b,
        Some(_) => return Err(IntegrityError::MembershipFork.into()),
        None => return Err(Error::NotFound),
    };
    let member = pointed
        .members
        .iter()
        .find(|x| x.member_ref() == sm.signer)
        .ok_or_else(|| refused("signer", "not a member of the named body"))?;
    if member.sign_pub != *key {
        return Err(IntegrityError::Signature.into());
    }
    if member.role < Role::Write {
        return Err(refused("signer", "reader cannot write"));
    }
    for later in view.bodies().filter(|b| b.seq > pointed.seq) {
        match later.members.iter().find(|x| x.member_ref() == sm.signer) {
            Some(x) if x.role == member.role => {}
            Some(_) => return Err(refused("signer", "role changed since the named body")),
            None => return Err(refused("signer", "no longer a member")),
        }
        if later.generation != pointed.generation {
            return Err(refused("generation", "key generation changed since"));
        }
    }
    if generation != pointed.generation {
        return Err(IntegrityError::WrongContext.into());
    }
    if let Some(prev) = prev_meta_hash
        && ext.meta_hash != Some(prev)
        && member.role < Role::Manage
    {
        return Err(refused("meta", "only a manager changes the vault meta"));
    }
    check_history(&m, last_seen)?;
    Ok(m)
}
