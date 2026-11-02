//! A follower's request for a mailbox credential (spec D.5, followers).
//!
//! When an Apple device migrates the account from iCloud to a mailbox, the
//! other Apple devices of the account have no credential on it. Each one
//! writes, in the frozen iCloud zone, a request signed by its own device
//! key: "grant this credential key on this mailbox". A migrated device
//! verifies it against its verified roster and grants the key.
//!
//! The request is a side record (`store::SIDE_KIND_MAILBOX_ENROLL_REQUEST`),
//! never a `RecordKind`: the apps keep it out of the store. The server
//! holding it (iCloud) can drop or replay it, never forge one: the
//! signature is the device's hybrid key under `ENROLL_REQUEST_DOMAIN`, over
//! the account, the mailbox, the credential key and the issue time. A
//! replay within the 7 days grants the same key again, to the same device.

use serde::{Deserialize, Serialize};

use crate::crypto::HybridSignature;
use crate::device_keys::DeviceKeys;
use crate::error::ValidationError;
use crate::repo::Repository;
use crate::store::RecordStore;
use crate::{Error, Id, IntegrityError, Result};

/// Signature domain of an enroll request.
pub const ENROLL_REQUEST_DOMAIN: &[u8] = b"onepass/mailbox-enroll-request/v1";
/// How long a request stays valid.
pub const ENROLL_REQUEST_TTL_SECS: i64 = 7 * 24 * 3600;
/// How far ahead of the verifier's clock a request may be dated.
pub const ENROLL_REQUEST_SKEW_SECS: i64 = 300;

/// The signed content of a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequestBody {
    pub account_id: Id,
    pub device_id: Id,
    /// The Ed25519 public key of the credential to grant.
    pub credential_pub: [u8; 32],
    pub mailbox_id: [u8; 16],
    /// Unix seconds, the requesting device's clock.
    pub issued_at: i64,
}

impl EnrollRequestBody {
    /// `postcard(self)`: the signed bytes.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("enroll request body encodes")
    }
}

/// A body and the requesting device's signature over its encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnrollRequest {
    pub body: EnrollRequestBody,
    pub sig: HybridSignature,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
    sig: HybridSignature,
}

fn refused(reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: "enroll_request".into(),
        reason,
    })
}

impl SignedEnrollRequest {
    /// `postcard(Wire{postcard(body), sig})`.
    pub fn encode(&self) -> Vec<u8> {
        let wire = Wire {
            body: self.body.encode(),
            sig: self.sig.clone(),
        };
        postcard::to_allocvec(&wire).expect("enroll request encodes")
    }

    /// Strict decode, no signature check: the whole buffer and a canonical
    /// body; `Validation("enroll_request", "malformed")` otherwise.
    pub fn decode(bytes: &[u8]) -> Result<SignedEnrollRequest> {
        let wire: Wire = match postcard::take_from_bytes(bytes) {
            Ok((w, [])) => w,
            _ => return Err(refused("malformed")),
        };
        let body: EnrollRequestBody = match postcard::take_from_bytes(&wire.body) {
            Ok((b, [])) => b,
            _ => return Err(refused("malformed")),
        };
        let signed = SignedEnrollRequest {
            body,
            sig: wire.sig,
        };
        if signed.body.encode() != wire.body || signed.encode() != bytes {
            return Err(refused("malformed"));
        }
        Ok(signed)
    }
}

impl<S: RecordStore> Repository<S> {
    /// A request, signed by this device's `keys`, for `credential_pub` on
    /// `mailbox_id`. Refused when this device has no trust state, or when
    /// `keys` are not the keys the trust state pins for it.
    pub fn sign_enroll_request(
        &self,
        keys: &DeviceKeys,
        credential_pub: [u8; 32],
        mailbox_id: [u8; 16],
        now: i64,
    ) -> Result<Vec<u8>> {
        let trust = self
            .store()
            .trust_state()?
            .ok_or_else(|| refused("no trust state"))?;
        if trust.account_id != self.account().params.account_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let me = trust.me.device_id;
        if keys.public(me)? != trust.me {
            return Err(refused("not this device's keys"));
        }
        let body = EnrollRequestBody {
            account_id: trust.account_id,
            device_id: me,
            credential_pub,
            mailbox_id,
            issued_at: now,
        };
        let sig = keys.sign(ENROLL_REQUEST_DOMAIN, &body.encode())?;
        Ok(SignedEnrollRequest { body, sig }.encode())
    }

    /// Verify a request for `mailbox_id` read from the frozen zone: strict
    /// decode, this account, this mailbox, issued within
    /// `[now - TTL, now + 300]`, a device of the verified roster neither
    /// revoked nor excluded, and its signature under the domain. Any fault
    /// is `Validation("enroll_request", reason)`.
    pub fn verify_enroll_request(
        &self,
        bytes: &[u8],
        mailbox_id: [u8; 16],
        now: i64,
    ) -> Result<EnrollRequestBody> {
        let signed = SignedEnrollRequest::decode(bytes)?;
        let body = &signed.body;
        let trust = self
            .store()
            .trust_state()?
            .ok_or_else(|| refused("no trust state"))?;
        let account_id = self.account().params.account_id;
        if body.account_id != account_id || trust.account_id != account_id {
            return Err(refused("other account"));
        }
        if body.mailbox_id != mailbox_id {
            return Err(refused("other mailbox"));
        }
        if body.issued_at < now.saturating_sub(ENROLL_REQUEST_TTL_SECS) {
            return Err(refused("expired"));
        }
        if body.issued_at > now.saturating_add(ENROLL_REQUEST_SKEW_SECS) {
            return Err(refused("from the future"));
        }
        if trust.revoked.contains(&body.device_id) || trust.excluded.contains(&body.device_id) {
            return Err(refused("device revoked"));
        }
        let entry = trust
            .roster
            .iter()
            .find(|e| e.device_id == body.device_id)
            .ok_or_else(|| refused("unknown device"))?;
        entry
            .sign_pub
            .verify(ENROLL_REQUEST_DOMAIN, &body.encode(), &signed.sig)
            .map_err(|_| refused("signature"))?;
        Ok(signed.body)
    }
}
