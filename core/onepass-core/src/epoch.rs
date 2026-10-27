//! Signed restore epoch: the owner's mark that the account was deliberately
//! set back (a restore, or a choice after an integrity alert), so that the
//! other devices accept the new manifest heads instead of reporting a
//! rollback, while a store replaying, hiding or forging epochs is refused.
//!
//! One record per account (`RecordKind::RestoreEpoch`, id = account id,
//! version = epoch number), data = `postcard(SignedRestoreEpoch)`, in clear
//! and signed with the account's hybrid signing key (the key of the
//! manifests) under the domain `"onepass/restore-epoch/v1"`, over
//! `postcard(RestoreEpoch)`. Only the holder of the master password and the
//! Secret Key can issue one. How a device applies it: `Repository`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::manifest::SeenManifest;
use crate::{Error, Id, IntegrityError, Result};

/// Signature domain of restore epochs.
pub const EPOCH_DOMAIN: &[u8] = b"onepass/restore-epoch/v1";

const BAD: Error = Error::InvalidFormat("restore epoch");

/// Why an epoch was issued. Informative: every reason is applied the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpochReason {
    /// A backup was restored.
    Restore,
    /// After an alert, the owner kept this device's copy.
    KeepThisDevice,
    /// After an alert, the owner took the server's copy.
    TakeServer,
}

/// The signed content of an epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreEpoch {
    pub account_id: Id,
    /// Strictly increasing, 1 for the first.
    pub epoch: u64,
    /// Unix seconds, informative only.
    pub issued_at: i64,
    /// The manifest heads after the restore, per vault.
    pub heads: BTreeMap<Id, SeenManifest>,
    pub reason: EpochReason,
}

/// An epoch and the account's signature over `postcard(epoch)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRestoreEpoch {
    pub epoch: RestoreEpoch,
    pub signature: HybridSignature,
}

fn message(epoch: &RestoreEpoch) -> Result<Vec<u8>> {
    postcard::to_allocvec(epoch).map_err(|_| BAD)
}

impl SignedRestoreEpoch {
    /// Sign `epoch` with the account signing key.
    pub fn sign(epoch: RestoreEpoch, key: &HybridSigningKey) -> Result<SignedRestoreEpoch> {
        let signature = key.sign(EPOCH_DOMAIN, &message(&epoch)?)?;
        Ok(SignedRestoreEpoch { epoch, signature })
    }

    /// The record data, `postcard(self)`.
    pub fn encode(&self) -> Vec<u8> {
        // Plain data (ids, integers, byte arrays): encoding cannot fail.
        postcard::to_allocvec(self).expect("restore epoch encodes")
    }

    /// Decode record data from an untrusted store: the whole buffer
    /// (trailing bytes refused), and only the canonical encoding (decoding
    /// then encoding again gives the same bytes, so unsorted or duplicate
    /// heads are refused). Otherwise `InvalidFormat("restore epoch")`.
    /// Nothing is verified here; see `verify`.
    pub fn decode(bytes: &[u8]) -> Result<SignedRestoreEpoch> {
        let signed: SignedRestoreEpoch = match postcard::take_from_bytes(bytes) {
            Ok((s, [])) => s,
            _ => return Err(BAD),
        };
        if signed.encode() != bytes {
            return Err(BAD);
        }
        Ok(signed)
    }

    /// Check the epoch belongs to `account_id` (else `EpochRollback`), is
    /// at least 1 (else `InvalidFormat("restore epoch")`), and carries a
    /// valid signature under `key`, the pinned account's key, never one
    /// taken from the record (else `Signature`).
    pub fn verify(&self, account_id: Id, key: &HybridVerifyingKey) -> Result<&RestoreEpoch> {
        if self.epoch.account_id != account_id {
            return Err(IntegrityError::EpochRollback.into());
        }
        if self.epoch.epoch == 0 {
            return Err(BAD);
        }
        key.verify(EPOCH_DOMAIN, &message(&self.epoch)?, &self.signature)?;
        Ok(&self.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(account_id: Id) -> RestoreEpoch {
        let mut heads = BTreeMap::new();
        heads.insert(
            Id([1; 16]),
            SeenManifest {
                seq: 4,
                hash: [7; 32],
            },
        );
        heads.insert(
            Id([2; 16]),
            SeenManifest {
                seq: 9,
                hash: [8; 32],
            },
        );
        RestoreEpoch {
            account_id,
            epoch: 3,
            issued_at: 1_793_000_000,
            heads,
            reason: EpochReason::KeepThisDevice,
        }
    }

    #[test]
    fn sign_encode_decode_verify() {
        let key = HybridSigningKey::generate().unwrap();
        let public = key.verifying_key().unwrap();
        let account = Id::new();
        let signed = SignedRestoreEpoch::sign(epoch(account), &key).unwrap();
        let bytes = signed.encode();
        let back = SignedRestoreEpoch::decode(&bytes).unwrap();
        assert_eq!(back, signed);
        assert_eq!(back.verify(account, &public).unwrap(), &epoch(account));

        // Another account, another key, a changed field, trailing bytes.
        assert_eq!(
            back.verify(Id::new(), &public),
            Err(IntegrityError::EpochRollback.into())
        );
        let other = HybridSigningKey::generate().unwrap();
        assert_eq!(
            back.verify(account, &other.verifying_key().unwrap()),
            Err(IntegrityError::Signature.into())
        );
        let mut changed = back.clone();
        changed.epoch.issued_at += 1;
        assert_eq!(
            changed.verify(account, &public),
            Err(IntegrityError::Signature.into())
        );
        let mut zero = SignedRestoreEpoch::sign(
            RestoreEpoch {
                epoch: 0,
                ..epoch(account)
            },
            &key,
        )
        .unwrap();
        assert_eq!(zero.verify(account, &public), Err(BAD));
        zero.epoch.epoch = 1;
        assert_eq!(
            zero.verify(account, &public),
            Err(IntegrityError::Signature.into())
        );
        let mut padded = bytes.clone();
        padded.push(0);
        assert_eq!(SignedRestoreEpoch::decode(&padded), Err(BAD));
        assert_eq!(
            SignedRestoreEpoch::decode(&bytes[..bytes.len() - 1]),
            Err(BAD)
        );
    }

    #[test]
    fn non_canonical_heads_refused() {
        let key = HybridSigningKey::generate().unwrap();
        let signed = SignedRestoreEpoch::sign(epoch(Id::new()), &key).unwrap();
        let bytes = signed.encode();
        // Swap the two heads (each: 16-byte id, varint seq, 32-byte hash)
        // after the account id (16), epoch (1), issued_at (zigzag varint)
        // and the map length (1): the map decodes, but not canonically.
        let issued = postcard::to_allocvec(&signed.epoch.issued_at).unwrap();
        let start = 16 + 1 + issued.len() + 1;
        let entry = 16 + 1 + 32;
        let mut swapped = bytes.clone();
        swapped[start..start + entry].copy_from_slice(&bytes[start + entry..start + 2 * entry]);
        swapped[start + entry..start + 2 * entry].copy_from_slice(&bytes[start..start + entry]);
        let parsed: SignedRestoreEpoch = postcard::from_bytes(&swapped).unwrap();
        assert_eq!(parsed, signed, "the map itself is the same");
        assert_eq!(SignedRestoreEpoch::decode(&swapped), Err(BAD));
    }
}
