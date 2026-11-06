//! Stolen-device wipe orders (founder decision 2026-11-03, recover-wipe):
//! "Marquer comme volé" on a device of the account tells a device already
//! removed by a lineage record to erase itself at once, with no 7-day
//! clock.
//!
//! An order is signed by the identity of a lineage head (`head`), the one
//! the issuing device is on: only the devices of that head (and the
//! recovering device after a `Recover`) hold that key, never a device the
//! lineage removed. It names the account, the target's device id and the
//! hash of its public device keys, the lineage record that removed it
//! (`removed_by`) and the issuing device, which must be in `head`'s roster.
//!
//! The target applies an order only while it is `Quarantined { by, .. }`
//! with `by == removed_by`, and only when `head` is `by` itself or a
//! descendant of `by` through rotations each signed by a device of its
//! parent's roster (no `Recover` after `by`). So a forged order (another
//! identity, a device outside the roster) or a replayed one (another
//! device, another removal, a removal the user answered "Ce n'était pas
//! moi" to, a device paired again under new keys) erases nothing.
//!
//! Orders are stored as `RecordKind::Lineage` rows (immutable, never
//! deleted by a client, remote deletions refused): no new record kind, and
//! every reader of lineage rows already skips rows that do not decode as a
//! `LineageRecord`. The encoding starts with `WIPE_MAGIC`, which
//! `LineageRecord::decode` refuses (its first byte is no variant), and a
//! lineage record never decodes as an order.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::codec::{self, check_identity_sig};
use super::verify::verify_rotation;
use super::{
    LINEAGE_FORMAT, LineageRecord, RotationBody, RotationReason, Signed, body_bytes, id16, sha256,
};
use crate::crypto::{IdentityKey, IdentitySignature, IdentityVerifyingKey};
use crate::device_keys::DevicePublic;
use crate::store::{Record, RecordKind, RecordStore};
use crate::trust::{DeviceLineageState, TrustState};
use crate::{Error, Id, Result};

/// Signature domain of a wipe order, by the identity key of `head`.
pub const WIPE_DOMAIN: &[u8] = b"onepass/wipe-order/v1";
/// First bytes of an encoded order.
pub const WIPE_MAGIC: &[u8; 8] = b"OPWIPE01";
const WIPE_ID_PREFIX: &[u8] = b"onepass/wipe-id/v1";
const WIPE_TARGET_PREFIX: &[u8] = b"onepass/wipe-target/v1";
/// Most rotations walked from `removed_by` to `head`.
pub const MAX_WIPE_CHAIN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WipeBody {
    pub format: u8,
    pub account_id: Id,
    /// The device to erase.
    pub target: Id,
    /// `target_key` of the target's public device keys.
    pub target_key: [u8; 32],
    /// The lineage hash of the rotation that removed the target.
    pub removed_by: [u8; 32],
    /// The lineage hash of the head whose identity signs.
    pub head: [u8; 32],
    /// The issuing device, in `head`'s roster.
    pub issuer: Id,
    /// Unix seconds, informative.
    pub issued_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWipe {
    pub body: WipeBody,
    /// The identity of `head`, `onepass/wipe-order/v1`.
    pub identity_sig: IdentitySignature,
}

const BAD: Error = Error::InvalidFormat("wipe order");

impl SignedWipe {
    /// `WIPE_MAGIC || postcard(self)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = WIPE_MAGIC.to_vec();
        out.extend(postcard::to_allocvec(self).expect("wipe order encodes"));
        out
    }

    /// Strict: the magic, then the whole buffer, a canonical re-encoding,
    /// the lineage format and the signature length.
    pub fn decode(b: &[u8]) -> Result<SignedWipe> {
        let rest = b.strip_prefix(WIPE_MAGIC.as_slice()).ok_or(BAD)?;
        let w = codec::decode_strict_with::<SignedWipe>(rest, BAD)?;
        if w.body.format != LINEAGE_FORMAT {
            return Err(BAD);
        }
        check_identity_sig(&w.identity_sig).map_err(|_| BAD)?;
        Ok(w)
    }

    /// `SHA-256("onepass/wipe-id/v1" || encoding)[..16]`: a record id that
    /// never meets a lineage record's (`hash[..16]` of another domain).
    pub fn record_id(&self) -> Id {
        id16(sha256(&[WIPE_ID_PREFIX, &self.encode()]))
    }
}

/// `SHA-256("onepass/wipe-target/v1" || postcard(device public))`.
pub fn target_key(p: &DevicePublic) -> [u8; 32] {
    sha256(&[WIPE_TARGET_PREFIX, &p.encode()])
}

/// Sign an order with the identity key of `body.head`.
pub fn sign_wipe(body: WipeBody, identity: &IdentityKey) -> Result<SignedWipe> {
    let identity_sig = identity.sign(WIPE_DOMAIN, &body_bytes(&body))?;
    Ok(SignedWipe { body, identity_sig })
}

/// The identity signature, under the key of the head (from a verified
/// record, never from the order).
pub fn verify_wipe(w: &SignedWipe, identity: &IdentityVerifyingKey) -> Result<()> {
    identity.verify(WIPE_DOMAIN, &body_bytes(&w.body), &w.identity_sig)
}

/// The order as a lineage row: id = `record_id`, version = the head's
/// generation, written once.
pub(crate) fn wipe_record(w: &SignedWipe, generation: u64) -> Record {
    Record {
        id: w.record_id(),
        kind: RecordKind::Lineage,
        version: generation,
        data: w.encode(),
    }
}

/// Every lineage row that decodes as an order.
pub(crate) fn stored_wipes<S: RecordStore + ?Sized>(store: &S) -> Result<Vec<SignedWipe>> {
    Ok(store
        .list(RecordKind::Lineage)?
        .iter()
        .filter_map(|r| SignedWipe::decode(&r.data).ok())
        .collect())
}

/// Signed rotations by lineage hash.
pub(crate) fn signed_rotations(
    records: &[LineageRecord],
) -> BTreeMap<[u8; 32], &Signed<RotationBody>> {
    records
        .iter()
        .filter_map(|r| match r {
            LineageRecord::Rotation(s) => Some((r.hash(), s)),
            LineageRecord::Genesis(_) => None,
        })
        .collect()
}

/// The record of `head` when it is `from` or a descendant of `from` along
/// rotations each signed by a device of its parent's roster (both
/// signatures checked, generations consecutive, no `Recover`), at most
/// `MAX_WIPE_CHAIN` steps. `None` otherwise.
pub(crate) fn chain_head<'a>(
    rotations: &BTreeMap<[u8; 32], &'a Signed<RotationBody>>,
    from: [u8; 32],
    head: [u8; 32],
) -> Option<&'a Signed<RotationBody>> {
    let mut path = Vec::new();
    let mut at = head;
    while at != from {
        let r = rotations.get(&at)?;
        path.push(*r);
        if path.len() > MAX_WIPE_CHAIN {
            return None;
        }
        at = r.body.parent;
    }
    let mut prev = *rotations.get(&from)?;
    for r in path.into_iter().rev() {
        let b = &r.body;
        if b.reason == RotationReason::Recover
            || b.account_id != prev.body.account_id
            || b.generation != prev.body.generation.checked_add(1)?
        {
            return None;
        }
        let entry = prev.body.roster.iter().find(|e| e.device_id == b.rotator)?;
        verify_rotation(r, &entry.sign_pub).ok()?;
        prev = r;
    }
    Some(prev)
}

/// Whether `w` orders this device (`trust`) to erase now: see the module
/// doc. Any failure is `false`.
pub(crate) fn orders_me(
    w: &SignedWipe,
    trust: &TrustState,
    rotations: &BTreeMap<[u8; 32], &Signed<RotationBody>>,
) -> bool {
    let DeviceLineageState::Quarantined { by, .. } = &trust.state else {
        return false;
    };
    let b = &w.body;
    if b.account_id != trust.account_id
        || b.target != trust.me.device_id
        || b.target_key != target_key(&trust.me)
        || b.removed_by != *by
        || !rotations
            .get(by)
            .is_some_and(|r| r.body.revoked.contains(&trust.me.device_id))
    {
        return false;
    }
    let Some(head) = chain_head(rotations, *by, b.head) else {
        return false;
    };
    head.body.roster.iter().any(|e| e.device_id == b.issuer)
        && b.issuer != trust.me.device_id
        && verify_wipe(w, &head.body.identity_pub).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lineage_record_never_decodes_as_an_order_and_back() {
        // The magic's first byte is no `LineageRecord` variant.
        assert!(LineageRecord::decode(WIPE_MAGIC).is_err());
        let mut b = WIPE_MAGIC.to_vec();
        b.extend([0u8; 64]);
        assert!(LineageRecord::decode(&b).is_err());
        assert_eq!(SignedWipe::decode(&[]), Err(BAD));
        assert_eq!(SignedWipe::decode(&[0, 1, 2]), Err(BAD));
        assert_eq!(SignedWipe::decode(WIPE_MAGIC), Err(BAD));
    }

    #[test]
    fn round_trip_and_strict() {
        let identity = IdentityKey::generate().unwrap();
        let body = WipeBody {
            format: LINEAGE_FORMAT,
            account_id: Id([1; 16]),
            target: Id([2; 16]),
            target_key: [3; 32],
            removed_by: [4; 32],
            head: [5; 32],
            issuer: Id([6; 16]),
            issued_at: 7,
        };
        let w = sign_wipe(body, &identity).unwrap();
        let bytes = w.encode();
        assert_eq!(SignedWipe::decode(&bytes).unwrap(), w);
        verify_wipe(&w, &identity.verifying_key()).unwrap();
        let other = IdentityKey::generate().unwrap();
        assert!(verify_wipe(&w, &other.verifying_key()).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(SignedWipe::decode(&trailing), Err(BAD));
        let mut format = w.clone();
        format.body.format = 2;
        assert_eq!(SignedWipe::decode(&format.encode()), Err(BAD));
        assert!(LineageRecord::decode(&bytes).is_err());
        let mut changed = w.clone();
        changed.body.target = Id([9; 16]);
        assert!(verify_wipe(&changed, &identity.verifying_key()).is_err());
    }
}
