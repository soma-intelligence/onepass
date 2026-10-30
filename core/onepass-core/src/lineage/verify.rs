//! Signature checks of lineage records. Keys come from the caller (the
//! local trust state), never from the record being checked. Every failure
//! is `Error::Integrity(IntegrityError::Signature)`.

use super::{
    GENESIS_DOMAIN, GENESIS_IDENTITY_DOMAIN, GenesisBody, INTRO_DOMAIN, LEGACY_DEVICE_DOMAIN,
    ROTATION_DOMAIN, ROTATION_IDENTITY_DOMAIN, RotationBody, Signed, SignedIntro,
    SignedLegacyIntro, bad_signature, body_bytes,
};
use crate::Result;
use crate::crypto::{HybridVerifyingKey, IdentityVerifyingKey};
use crate::device_keys::{DevicePublic, verify_pop};

/// Both signatures of a rotation: the rotator's device key, and the new
/// identity named in the body.
pub fn verify_rotation(r: &Signed<RotationBody>, rotator: &HybridVerifyingKey) -> Result<()> {
    let msg = body_bytes(&r.body);
    rotator.verify(ROTATION_DOMAIN, &msg, &r.device_sig)?;
    r.body
        .identity_pub
        .verify(ROTATION_IDENTITY_DOMAIN, &msg, &r.identity_sig)
}

/// Both signatures of a genesis: the creator's key named in the body, and
/// the identity named in the body.
pub fn verify_genesis(g: &Signed<GenesisBody>) -> Result<()> {
    let msg = body_bytes(&g.body);
    g.body
        .creator
        .sign_pub
        .verify(GENESIS_DOMAIN, &msg, &g.device_sig)?;
    g.body
        .identity_pub
        .verify(GENESIS_IDENTITY_DOMAIN, &msg, &g.identity_sig)
}

fn entry_public(e: &super::RosterEntry) -> DevicePublic {
    DevicePublic {
        device_id: e.device_id,
        sign_pub: e.sign_pub.clone(),
        kem_pub: e.kem_pub.clone(),
    }
}

/// The introducer's signature and the new device's proof of possession.
/// `introducer` comes from the local roster (for a self-intro, it is the
/// entry's own key).
pub fn verify_intro(i: &SignedIntro, introducer: &HybridVerifyingKey) -> Result<()> {
    introducer.verify(INTRO_DOMAIN, &body_bytes(&i.body), &i.sig)?;
    verify_pop(
        &i.body.account_id.0,
        &entry_public(&i.body.entry),
        &i.body.pop,
    )
}

/// The identity signature of a kit self-intro. A missing signature fails.
pub fn verify_intro_identity(i: &SignedIntro, identity: &IdentityVerifyingKey) -> Result<()> {
    match &i.identity_sig {
        Some(s) => identity.verify(INTRO_DOMAIN, &body_bytes(&i.body), s),
        None => Err(bad_signature()),
    }
}

/// The account signing key's signature and the device's proof of
/// possession.
pub fn verify_legacy_intro(i: &SignedLegacyIntro, account_sign: &HybridVerifyingKey) -> Result<()> {
    account_sign.verify(LEGACY_DEVICE_DOMAIN, &body_bytes(&i.body), &i.account_sig)?;
    verify_pop(
        &i.body.account_id.0,
        &entry_public(&i.body.entry),
        &i.body.pop,
    )
}
