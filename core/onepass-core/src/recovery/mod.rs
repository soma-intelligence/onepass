//! Organizer-assisted recovery (sharing spec 11.3 choice C, 11.4 to 11.7,
//! S17 to S21, decisions 1, 3 and 4, plan 3 arbitrages B-1, B-2, B-7).
//!
//! The recovery key RK is derived, never drawn (B-1): `RK =
//! HKDF-SHA256(ikm = S_org || S_store, info = "onepass/recovery/rk/v1" ||
//! postcard((account_id, identity_id, enrollment_id)))`, from two random
//! 32-byte halves. `S_org` goes to the organizer, wrapped for its KEM key
//! as pinned `Verified` in the member's book; `S_store` stays in the
//! member's private zone (`RecoveryHalf`), sealed under a key derived from
//! the Secret Key for an account on the mailbox (11.7). The keyset is
//! sealed under RK itself (B-2, `RecoverySlot`). The signed messages of
//! the enrollment, the request and the cancellation travel in the
//! member-organizer contact zone (`RecordKind::RecoveryMessage`).

use crate::crypto::SymmetricKey;
use crate::crypto::key::hkdf32;
use crate::share::MemberRef;
use crate::{Error, Id, Result};
use serde::{Deserialize, Serialize};

pub mod messages;

pub use messages::RecoveryMessage;

/// HKDF info prefix of RK.
pub const RK_INFO: &[u8] = b"onepass/recovery/rk/v1";
/// KEM label of the organizer's half.
pub const SHARE_LABEL: &[u8] = b"onepass/recovery/share/v1";
/// Signature domain of an enrollment, by the member's account key.
pub const ENROLL_DOMAIN: &[u8] = b"onepass/recovery/enroll/v1";
/// Signature domain of a request, by the organizer's account key.
pub const REQUEST_DOMAIN: &[u8] = b"onepass/recovery/request/v1";
/// Signature domain of a cancellation, by a member device key.
pub const CANCEL_DOMAIN: &[u8] = b"onepass/recovery/cancel/v1";
/// Domain of the organizer's note that it handed its half over.
pub const RELEASE_DOMAIN: &[u8] = b"onepass/recovery/release/v1";
/// HKDF info prefix of `K_store`, the key that seals `S_store` for an
/// account on the mailbox (spec 11.7).
pub const STORE_SEAL_INFO: &[u8] = b"onepass/recovery/store-seal/v1";

/// The delay a member gets unless it picks another (decision 3).
pub const RECOVERY_DELAY_DEFAULT_SECS: u32 = 72 * 3600;
/// Shortest delay a member may pick.
pub const RECOVERY_DELAY_MIN_SECS: u32 = 24 * 3600;
/// Longest delay a member may pick.
pub const RECOVERY_DELAY_MAX_SECS: u32 = 7 * 86_400;

/// `HKDF-SHA256(ikm = s_org || s_store, info = RK_INFO ||
/// postcard((account_id, identity_id, enrollment_id)))`.
pub fn derive_rk(
    s_org: &[u8; 32],
    s_store: &[u8; 32],
    account_id: Id,
    identity_id: Id,
    enrollment_id: Id,
) -> Result<SymmetricKey> {
    let mut ikm = zeroize::Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(s_org);
    ikm[32..].copy_from_slice(s_store);
    let bound = postcard::to_allocvec(&(account_id, identity_id, enrollment_id))
        .map_err(|_| Error::InvalidFormat("recovery"))?;
    hkdf32(&[], &ikm[..], &[RK_INFO, &bound])
}

/// `K_store = HKDF-SHA256(ikm = Secret Key, info = STORE_SEAL_INFO ||
/// enrollment_id)` (spec 11.7).
pub fn store_seal_key(secret_key: &[u8; 32], enrollment_id: Id) -> Result<SymmetricKey> {
    hkdf32(&[], secret_key, &[STORE_SEAL_INFO, &enrollment_id.0])
}

/// The KEM context of the organizer's half: `postcard((member account,
/// member identity, organizer account, organizer identity,
/// enrollment_id))`.
pub fn share_context(member: &MemberRef, organizer: &MemberRef, enrollment_id: Id) -> Vec<u8> {
    postcard::to_allocvec(&(
        member.account_id,
        member.identity_id,
        organizer.account_id,
        organizer.identity_id,
        enrollment_id,
    ))
    .expect("share context encodes")
}

/// What a member signs when it enrolls: who helps, from when, after which
/// delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryEnrollment {
    pub member: MemberRef,
    pub organizer: MemberRef,
    pub enrollment_id: Id,
    pub delay_secs: u32,
    pub created_at: i64,
}

impl RecoveryEnrollment {
    /// The delay within its bounds, member and organizer two accounts.
    pub fn check(&self) -> Result<()> {
        if !(RECOVERY_DELAY_MIN_SECS..=RECOVERY_DELAY_MAX_SECS).contains(&self.delay_secs)
            || self.member.account_id == self.organizer.account_id
        {
            return Err(Error::InvalidFormat("recovery enrollment"));
        }
        Ok(())
    }
}

/// What a `RecoveryHalf` record holds (plan 3 Task 4): `S_store` in clear
/// for an account on iCloud, sealed under `K_store` for an account on the
/// mailbox (spec 11.7), with the enrollment it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryHalf {
    Clear {
        enrollment_id: Id,
        s_store: [u8; 32],
    },
    Sealed {
        enrollment_id: Id,
        sealed: Vec<u8>,
    },
}

impl RecoveryHalf {
    pub fn encode(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(postcard::to_allocvec(self).expect("recovery half encodes"))
    }

    pub fn decode(b: &[u8]) -> Result<RecoveryHalf> {
        let h: RecoveryHalf =
            crate::lineage::decode_strict_with(b, Error::InvalidFormat("recovery half"))?;
        if let RecoveryHalf::Sealed { sealed, .. } = &h
            && (sealed.is_empty() || sealed.len() > 1024)
        {
            return Err(Error::InvalidFormat("recovery half"));
        }
        Ok(h)
    }

    pub fn enrollment_id(&self) -> Id {
        match self {
            RecoveryHalf::Clear { enrollment_id, .. }
            | RecoveryHalf::Sealed { enrollment_id, .. } => *enrollment_id,
        }
    }
}

impl Drop for RecoveryHalf {
    fn drop(&mut self) {
        if let RecoveryHalf::Clear { s_store, .. } = self {
            zeroize::Zeroize::zeroize(s_store);
        }
    }
}

/// The AAD of a recovery slot: its record id, the member's identity id.
pub fn slot_aad(identity_id: Id) -> crate::crypto::Aad {
    crate::crypto::Aad {
        blob_id: identity_id,
        vault_id: None,
        schema: 1,
    }
}

/// The AAD of a sealed `S_store`: the enrollment and the identity, schema
/// 2 (the slot's blob kind, another key and another context).
pub fn half_aad(identity_id: Id, enrollment_id: Id) -> crate::crypto::Aad {
    crate::crypto::Aad {
        blob_id: enrollment_id,
        vault_id: Some(identity_id),
        schema: 2,
    }
}
