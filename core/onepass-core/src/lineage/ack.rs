//! Signed follow acknowledgments of key rotation v2 (spec 6.8, owner ruling
//! O6): a device that pins a head writes, in the same local transaction, a
//! record saying so, signed by its own device key. The rotator (and every
//! other device) then shows each roster entry as "à jour" or "en attente".
//!
//! Display only: no trust decision ever reads an acknowledgment. A forged
//! one fails verification under the entry's pinned key, a withheld one only
//! shows "en attente", and one for another head is ignored.

use serde::{Deserialize, Serialize};

use super::{LINEAGE_FORMAT, body_bytes, codec, id16, sha256};
use crate::crypto::{HybridSignature, HybridVerifyingKey};
use crate::device_keys::DeviceKeys;
use crate::store::{Record, RecordKind, RecordStore};
use crate::trust::TrustState;
use crate::{Error, Id, Result};

/// Signature domain of an acknowledgment, by the acknowledging device's key.
pub const ACK_DOMAIN: &[u8] = b"onepass/device-ack/v1";
const ACK_ID_PREFIX: &[u8] = b"onepass/ack-id/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckBody {
    pub format: u8,
    pub account_id: Id,
    /// The lineage hash the device pinned.
    pub head: [u8; 32],
    pub device_id: Id,
    /// Unix seconds, informative.
    pub acked_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAck {
    pub body: AckBody,
    /// The acknowledging device's key, `onepass/device-ack/v1`.
    pub sig: HybridSignature,
}

impl SignedAck {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("ack encodes")
    }

    /// Strict, like [`super::LineageRecord::decode`].
    pub fn decode(b: &[u8]) -> Result<SignedAck> {
        let ack = codec::decode_strict_with::<SignedAck>(b, Error::InvalidFormat("device ack"))?;
        if ack.body.format != LINEAGE_FORMAT {
            return Err(Error::InvalidFormat("device ack format"));
        }
        codec::check_hybrid_sig(&ack.sig)?;
        Ok(ack)
    }
}

/// `SHA-256("onepass/ack-id/v1" || head || device_id)[..16]`.
pub fn ack_id(head: &[u8; 32], device_id: Id) -> Id {
    id16(sha256(&[ACK_ID_PREFIX, head, &device_id.0]))
}

/// Sign an acknowledgment with the acknowledging device's key.
pub fn sign_ack(body: AckBody, device: &DeviceKeys) -> Result<SignedAck> {
    let sig = device.sign(ACK_DOMAIN, &body_bytes(&body))?;
    Ok(SignedAck { body, sig })
}

/// The device's signature. `device` comes from the local roster, never from
/// the record.
pub fn verify_ack(a: &SignedAck, device: &HybridVerifyingKey) -> Result<()> {
    device.verify(ACK_DOMAIN, &body_bytes(&a.body), &a.sig)
}

/// The acknowledgment record of `trust`'s head by this device (`trust.me`),
/// signed by `device`: id = `ack_id`, version = the head's generation,
/// written once (expected version `None`). The caller puts it in the
/// transaction that pins that head.
pub(crate) fn ack_record(trust: &TrustState, device: &DeviceKeys, at: i64) -> Result<Record> {
    let body = AckBody {
        format: LINEAGE_FORMAT,
        account_id: trust.account_id,
        head: trust.head.hash,
        device_id: trust.me.device_id,
        acked_at: at,
    };
    let signed = sign_ack(body, device)?;
    Ok(Record {
        id: ack_id(&trust.head.hash, trust.me.device_id),
        kind: RecordKind::DeviceAck,
        version: trust.head.generation,
        data: signed.encode(),
    })
}

/// `ack_record` as a write for a pinning transaction, or none when this
/// store already holds the very same acknowledgment id (a device that
/// pins a head again, after a crash or a re-pair at the same head: the
/// record is immutable and the first one stands).
pub(crate) fn ack_write<S: RecordStore + ?Sized>(
    store: &S,
    trust: &TrustState,
    device: &DeviceKeys,
    at: i64,
) -> Result<Option<(Record, Option<u64>)>> {
    let rec = ack_record(trust, device, at)?;
    if store.get(RecordKind::DeviceAck, rec.id)?.is_some() {
        return Ok(None);
    }
    Ok(Some((rec, None)))
}

/// One roster entry as an acknowledgment shows it (spec 6.8, 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckStatus {
    pub device_id: Id,
    /// "à jour": an acknowledgment of the current head verifies under the
    /// entry's pinned key; else "en attente".
    pub acknowledged: bool,
    /// The verified acknowledgment's date (informative), `None` while
    /// waiting.
    pub acked_at: Option<i64>,
}

/// The verified acknowledgment of `head` by `entry`'s device, if any.
fn verified_ack<S: RecordStore + ?Sized>(
    store: &S,
    account_id: Id,
    head: &[u8; 32],
    device_id: Id,
    key: &HybridVerifyingKey,
) -> Option<i64> {
    let rec = store
        .get(RecordKind::DeviceAck, ack_id(head, device_id))
        .ok()??;
    let ack = SignedAck::decode(&rec.data).ok()?;
    let b = &ack.body;
    if b.head != *head || b.device_id != device_id || b.account_id != account_id {
        return None;
    }
    verify_ack(&ack, key).ok()?;
    Some(b.acked_at)
}

/// Each roster entry of `trust`, in roster order, "à jour" or "en attente"
/// for the current head. `None` at generation 0: no rotation yet, nothing to
/// acknowledge, nothing shown (ruling of 2026-11-02, spec 6.8). Any record
/// that does not decode, names another head, device or account, or does
/// not verify under the pinned key counts as missing.
pub fn ack_statuses<S: RecordStore + ?Sized>(
    store: &S,
    trust: &TrustState,
) -> Option<Vec<AckStatus>> {
    if trust.head.generation == 0 {
        return None;
    }
    Some(
        trust
            .roster
            .iter()
            .map(|e| {
                let at = verified_ack(
                    store,
                    trust.account_id,
                    &trust.head.hash,
                    e.device_id,
                    &e.sign_pub,
                );
                AckStatus {
                    device_id: e.device_id,
                    acknowledged: at.is_some(),
                    acked_at: at,
                }
            })
            .collect(),
    )
}
