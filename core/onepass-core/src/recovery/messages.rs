//! The signed recovery messages of the member-organizer contact zone
//! (sharing plan 3 Task 4): `RecordKind::RecoveryMessage`, decoded
//! strictly. An enrollment is signed by the member's account key, a
//! request by the organizer's, a cancellation by one of the member's
//! device keys (a locked device can cancel).

use serde::{Deserialize, Serialize};

use super::{CANCEL_DOMAIN, ENROLL_DOMAIN, RELEASE_DOMAIN, REQUEST_DOMAIN, RecoveryEnrollment};
use crate::crypto::{HybridSignature, HybridVerifyingKey};
use crate::lineage::decode_strict_with;
use crate::share::{MemberRef, sha256};
use crate::{Error, Id, Result};

/// Largest envelope of the organizer's half.
pub const MAX_SHARE_ENVELOPE: usize = 4096;

const BAD: Error = Error::InvalidFormat("recovery message");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMessage {
    /// The member chose the organizer: `envelope` wraps `S_org` for the
    /// organizer's pinned KEM key.
    Enroll {
        enrollment: RecoveryEnrollment,
        envelope: Vec<u8>,
        sig: HybridSignature,
    },
    /// The organizer started a recovery; it may be released from
    /// `release_after`, on the organizer's clock (B-7).
    Request {
        enrollment_id: Id,
        requested_at: i64,
        release_after: i64,
        organizer: MemberRef,
        sig: HybridSignature,
    },
    /// A device of the member said "Ce n'était pas moi".
    Cancel {
        enrollment_id: Id,
        device: Id,
        at: i64,
        sig: HybridSignature,
    },
    /// The organizer handed its half over face to face, at `at` on its
    /// clock: one release per enrollment.
    Released {
        enrollment_id: Id,
        at: i64,
        organizer: MemberRef,
        sig: HybridSignature,
    },
}

/// Placeholder signature, replaced by the signer.
pub fn unsigned() -> HybridSignature {
    HybridSignature {
        mldsa: Vec::new(),
        ed25519: [0; 64],
    }
}

impl RecoveryMessage {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("recovery message encodes")
    }

    /// Strict: whole buffer, canonical, structural checks.
    pub fn decode(b: &[u8]) -> Result<RecoveryMessage> {
        let m: RecoveryMessage = decode_strict_with(b, BAD)?;
        m.check()?;
        Ok(m)
    }

    fn check(&self) -> Result<()> {
        match self {
            RecoveryMessage::Enroll {
                enrollment,
                envelope,
                ..
            } => {
                enrollment.check()?;
                if envelope.is_empty() || envelope.len() > MAX_SHARE_ENVELOPE {
                    return Err(BAD);
                }
            }
            RecoveryMessage::Request {
                requested_at,
                release_after,
                ..
            } => {
                if release_after < requested_at {
                    return Err(BAD);
                }
            }
            RecoveryMessage::Cancel { .. } | RecoveryMessage::Released { .. } => {}
        }
        Ok(())
    }

    /// The enrollment this message is about.
    pub fn enrollment_id(&self) -> Id {
        match self {
            RecoveryMessage::Enroll { enrollment, .. } => enrollment.enrollment_id,
            RecoveryMessage::Request { enrollment_id, .. }
            | RecoveryMessage::Cancel { enrollment_id, .. }
            | RecoveryMessage::Released { enrollment_id, .. } => *enrollment_id,
        }
    }

    /// The record id: the enrollment id for an enrollment, a hash of the
    /// enrollment (and device) for the others, so one record per request
    /// and per cancelling device.
    pub fn record_id(&self) -> Id {
        let h = match self {
            RecoveryMessage::Enroll { enrollment, .. } => return enrollment.enrollment_id,
            RecoveryMessage::Request { enrollment_id, .. } => {
                sha256(&[REQUEST_DOMAIN, &enrollment_id.0])
            }
            RecoveryMessage::Cancel {
                enrollment_id,
                device,
                ..
            } => sha256(&[CANCEL_DOMAIN, &enrollment_id.0, &device.0]),
            RecoveryMessage::Released { enrollment_id, .. } => {
                sha256(&[RELEASE_DOMAIN, &enrollment_id.0])
            }
        };
        let mut id = [0u8; 16];
        id.copy_from_slice(&h[..16]);
        Id(id)
    }

    /// The domain and the signed bytes (every field but the signature).
    fn signed(&self) -> (&'static [u8], Vec<u8>) {
        let bytes = match self {
            RecoveryMessage::Enroll {
                enrollment,
                envelope,
                ..
            } => postcard::to_allocvec(&(enrollment, envelope)),
            RecoveryMessage::Request {
                enrollment_id,
                requested_at,
                release_after,
                organizer,
                ..
            } => postcard::to_allocvec(&(enrollment_id, requested_at, release_after, organizer)),
            RecoveryMessage::Cancel {
                enrollment_id,
                device,
                at,
                ..
            } => postcard::to_allocvec(&(enrollment_id, device, at)),
            RecoveryMessage::Released {
                enrollment_id,
                at,
                organizer,
                ..
            } => postcard::to_allocvec(&(enrollment_id, at, organizer)),
        }
        .expect("recovery message encodes");
        let domain = match self {
            RecoveryMessage::Enroll { .. } => ENROLL_DOMAIN,
            RecoveryMessage::Request { .. } => REQUEST_DOMAIN,
            RecoveryMessage::Cancel { .. } => CANCEL_DOMAIN,
            RecoveryMessage::Released { .. } => RELEASE_DOMAIN,
        };
        (domain, bytes)
    }

    fn sig_mut(&mut self) -> &mut HybridSignature {
        match self {
            RecoveryMessage::Enroll { sig, .. }
            | RecoveryMessage::Request { sig, .. }
            | RecoveryMessage::Cancel { sig, .. }
            | RecoveryMessage::Released { sig, .. } => sig,
        }
    }

    fn sig(&self) -> &HybridSignature {
        match self {
            RecoveryMessage::Enroll { sig, .. }
            | RecoveryMessage::Request { sig, .. }
            | RecoveryMessage::Cancel { sig, .. }
            | RecoveryMessage::Released { sig, .. } => sig,
        }
    }

    /// Sign with `sign`, a hybrid signer (account key or device key).
    pub fn sign_with(
        mut self,
        sign: impl FnOnce(&[u8], &[u8]) -> Result<HybridSignature>,
    ) -> Result<RecoveryMessage> {
        self.check()?;
        let (domain, bytes) = self.signed();
        *self.sig_mut() = sign(domain, &bytes)?;
        Ok(self)
    }

    /// The signature under `key` (the caller picks the key: the member's
    /// account key from its book for an enrollment, the organizer's for a
    /// request, a member device key from its roster for a cancellation).
    pub fn verify(&self, key: &HybridVerifyingKey) -> Result<()> {
        let (domain, bytes) = self.signed();
        key.verify(domain, &bytes, self.sig())
    }
}
