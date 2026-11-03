//! Strict decoding and structural checks of lineage records.

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{
    GenesisBody, IntroBody, LINEAGE_FORMAT, LegacyIntroBody, LineageRecord, MAX_ROSTER,
    RosterEntry, RotationBody, RotationReason, Signed, SignedIntro, SignedLegacyIntro,
};
use crate::crypto::sign::{MLDSA_PUBLIC_LEN, MLDSA_SIG_LEN, SLH_PUBLIC_LEN, SLH_SIG_LEN};
use crate::crypto::{HybridKemPublic, HybridSignature, IdentitySignature, IdentityVerifyingKey};
use crate::devices::MAX_DEVICE_NAME_CHARS;
use crate::{Error, Result};

const BAD: Error = Error::InvalidFormat("lineage record");

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

/// Whole buffer, then canonical re-encoding.
fn decode_strict<T: Serialize + DeserializeOwned>(b: &[u8]) -> Result<T> {
    decode_strict_with(b, BAD)
}

/// `decode_strict` with the caller's error for every refusal.
pub(crate) fn decode_strict_with<T: Serialize + DeserializeOwned>(
    b: &[u8],
    err: Error,
) -> Result<T> {
    let (value, rest) = postcard::take_from_bytes::<T>(b).map_err(|_| err.clone())?;
    if !rest.is_empty() {
        return Err(err);
    }
    if postcard::to_allocvec(&value).map_err(|_| err.clone())? != b {
        return Err(err);
    }
    Ok(value)
}

pub(crate) fn check_hybrid_sig(s: &HybridSignature) -> Result<()> {
    if s.mldsa.len() != MLDSA_SIG_LEN {
        return Err(bad("signature length"));
    }
    Ok(())
}

fn check_identity_pub(k: &IdentityVerifyingKey) -> Result<()> {
    if k.as_bytes().len() != SLH_PUBLIC_LEN {
        return Err(bad("identity public key length"));
    }
    Ok(())
}

fn check_identity_sig(s: &IdentitySignature) -> Result<()> {
    if s.as_bytes().len() != SLH_SIG_LEN {
        return Err(bad("identity signature length"));
    }
    Ok(())
}

/// Key lengths, a parsable ML-KEM key and a bounded name.
pub(crate) fn check_entry(e: &RosterEntry) -> Result<()> {
    if e.sign_pub.mldsa.len() != MLDSA_PUBLIC_LEN {
        return Err(bad("roster entry signing key"));
    }
    HybridKemPublic::from_bytes(&e.kem_pub.to_bytes()).map_err(|_| bad("roster entry kem key"))?;
    if e.name.chars().count() > MAX_DEVICE_NAME_CHARS {
        return Err(bad("roster entry name"));
    }
    Ok(())
}

pub fn check_genesis(b: &GenesisBody) -> Result<()> {
    if b.format != LINEAGE_FORMAT {
        return Err(bad("genesis format"));
    }
    check_identity_pub(&b.identity_pub)?;
    check_entry(&b.creator)
}

/// Structural rules of a rotation body (spec 6.3).
pub fn check_rotation(b: &RotationBody) -> Result<()> {
    if b.format != LINEAGE_FORMAT {
        return Err(bad("rotation format"));
    }
    if b.generation == 0 {
        return Err(bad("rotation generation"));
    }
    check_identity_pub(&b.identity_pub)?;
    if !b.revoked.windows(2).all(|w| w[0] < w[1]) {
        return Err(bad("rotation revoked list"));
    }
    if b.revoked.contains(&b.rotator) {
        return Err(bad("rotator is revoked"));
    }
    if b.roster.len() > MAX_ROSTER {
        return Err(bad("roster too long"));
    }
    if !b.roster.windows(2).all(|w| w[0].device_id < w[1].device_id) {
        return Err(bad("roster order"));
    }
    for e in &b.roster {
        check_entry(e)?;
        if b.revoked.contains(&e.device_id) {
            return Err(bad("revoked device in roster"));
        }
    }
    if !b.roster.iter().any(|e| e.device_id == b.rotator) {
        return Err(bad("rotator missing from roster"));
    }
    // A recovery keeps the rotator alone (plan 3 ruling B-3).
    if b.reason == RotationReason::Recover && b.roster.len() != 1 {
        return Err(bad("recover roster"));
    }
    // Deliveries: exactly the roster minus the rotator, in roster order.
    let expected = b.roster.iter().filter(|e| e.device_id != b.rotator);
    if b.deliveries.len() != expected.clone().count()
        || !b
            .deliveries
            .iter()
            .zip(expected)
            .all(|(d, e)| d.0 == e.device_id)
    {
        return Err(bad("rotation deliveries"));
    }
    Ok(())
}

pub fn check_intro(b: &IntroBody) -> Result<()> {
    if b.format != LINEAGE_FORMAT {
        return Err(bad("intro format"));
    }
    check_entry(&b.entry)?;
    check_hybrid_sig(&b.pop)
}

pub fn check_legacy_intro(b: &LegacyIntroBody) -> Result<()> {
    check_entry(&b.entry)?;
    check_hybrid_sig(&b.pop)
}

fn check_signed<B>(s: &Signed<B>) -> Result<()> {
    check_hybrid_sig(&s.device_sig)?;
    check_identity_sig(&s.identity_sig)
}

pub(super) fn decode_record(b: &[u8]) -> Result<LineageRecord> {
    let record = decode_strict::<LineageRecord>(b)?;
    match &record {
        LineageRecord::Genesis(s) => {
            check_genesis(&s.body)?;
            check_signed(s)?;
        }
        LineageRecord::Rotation(s) => {
            check_rotation(&s.body)?;
            check_signed(s)?;
        }
    }
    Ok(record)
}

pub(super) fn decode_intro(b: &[u8]) -> Result<SignedIntro> {
    let intro = decode_strict::<SignedIntro>(b)?;
    check_intro(&intro.body)?;
    check_hybrid_sig(&intro.sig)?;
    if let Some(s) = &intro.identity_sig {
        check_identity_sig(s)?;
    }
    Ok(intro)
}

pub(super) fn decode_legacy_intro(b: &[u8]) -> Result<SignedLegacyIntro> {
    let intro = decode_strict::<SignedLegacyIntro>(b)?;
    check_legacy_intro(&intro.body)?;
    check_hybrid_sig(&intro.account_sig)?;
    Ok(intro)
}
