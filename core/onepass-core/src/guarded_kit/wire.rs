//! Realm wire format (Guarded Kit spec, section 7): postcard requests and
//! signed responses.
//!
//! Request: `"OPGRQ01" || postcard(Request)`. Response: `"OPGRS01" ||
//! postcard(SignedResponse)`, where the realm's Ed25519 response key signs
//! `RESPONSE_DOMAIN || SHA-256(request bytes) || postcard(body)`. A client
//! accepts a response only under the response key pinned for that realm,
//! and only for the request it sent.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use super::GuardError;

pub const REQUEST_MAGIC: &[u8; 7] = b"OPGRQ01";
pub const RESPONSE_MAGIC: &[u8; 7] = b"OPGRS01";
pub const RESPONSE_DOMAIN: &[u8] = b"onepass/guard/realm-response/v1";
/// Domain of the owner signatures (status, delete).
pub const OWNER_DOMAIN: &[u8] = b"onepass/guard/owner/v1";

/// A guard's id at one realm.
pub type GuardId = [u8; 16];

/// What a client asks a realm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Registration: a new guard owned by `owner` (Ed25519 public key),
    /// with this realm's share of the OPRF key, its tag and its sealed
    /// share of `G`. One round; the realm draws the guard id.
    Register {
        owner: [u8; 32],
        version: u32,
        key_share: [u8; 32],
        tag: [u8; 32],
        #[serde(with = "serde_bytes")]
        share_ct: Vec<u8>,
    },
    /// Restore, phase 1: one counted attempt.
    Evaluate { guard_id: GuardId, blinded: [u8; 32] },
    /// Restore, phase 2: the tag check that releases the share.
    Unlock { guard_id: GuardId, tag: [u8; 32] },
    /// Owner poll: attempts and failures since the last success. `nonce`
    /// makes each signed poll distinct.
    Status {
        guard_id: GuardId,
        nonce: [u8; 16],
        #[serde(with = "serde_bytes")]
        sig: Vec<u8>,
    },
    /// Owner delete.
    Delete {
        guard_id: GuardId,
        #[serde(with = "serde_bytes")]
        sig: Vec<u8>,
    },
}

/// What a realm answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseBody {
    Registered { guard_id: GuardId },
    Evaluated { evaluation: [u8; 32], remaining: u8 },
    Unlocked {
        #[serde(with = "serde_bytes")]
        share_ct: Vec<u8>,
    },
    WrongTag { remaining: u8 },
    /// Unknown guard, or erased after its last attempt.
    Gone,
    Status {
        version: u32,
        attempts: u8,
        limit: u8,
        /// Unix seconds of each failed unlock since the last success.
        failures: Vec<u64>,
    },
    Deleted,
    Refused(RefusalCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalCode {
    Malformed,
    BadSignature,
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedResponse {
    pub request_hash: [u8; 32],
    pub body: ResponseBody,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

pub fn encode_request(r: &Request) -> Result<Vec<u8>, GuardError> {
    let mut out = REQUEST_MAGIC.to_vec();
    out.extend(postcard::to_allocvec(r).map_err(|_| GuardError::Malformed("request"))?);
    Ok(out)
}

pub fn decode_request(b: &[u8]) -> Result<Request, GuardError> {
    let rest = b
        .strip_prefix(REQUEST_MAGIC.as_slice())
        .ok_or(GuardError::Malformed("request magic"))?;
    postcard::from_bytes(rest).map_err(|_| GuardError::Malformed("request"))
}

pub fn request_hash(request: &[u8]) -> [u8; 32] {
    let d = digest(&SHA256, request);
    let mut h = [0u8; 32];
    h.copy_from_slice(d.as_ref());
    h
}

/// Bytes the realm signs for `body` answering `request_hash`.
pub fn response_message(request_hash: &[u8; 32], body: &ResponseBody) -> Result<Vec<u8>, GuardError> {
    let mut m = RESPONSE_DOMAIN.to_vec();
    m.extend_from_slice(request_hash);
    m.extend(postcard::to_allocvec(body).map_err(|_| GuardError::Malformed("response"))?);
    Ok(m)
}

pub fn encode_response(r: &SignedResponse) -> Result<Vec<u8>, GuardError> {
    let mut out = RESPONSE_MAGIC.to_vec();
    out.extend(postcard::to_allocvec(r).map_err(|_| GuardError::Malformed("response"))?);
    Ok(out)
}

/// Decode and check a response to `request` under the pinned `response_key`.
pub fn open_response(
    response: &[u8],
    request: &[u8],
    response_key: &[u8; 32],
) -> Result<ResponseBody, GuardError> {
    let rest = response
        .strip_prefix(RESPONSE_MAGIC.as_slice())
        .ok_or(GuardError::Malformed("response magic"))?;
    let r: SignedResponse =
        postcard::from_bytes(rest).map_err(|_| GuardError::Malformed("response"))?;
    let expected = request_hash(request);
    if r.request_hash != expected {
        return Err(GuardError::RealmSignature);
    }
    let m = response_message(&r.request_hash, &r.body)?;
    UnparsedPublicKey::new(&ED25519, response_key)
        .verify(&m, &r.sig)
        .map_err(|_| GuardError::RealmSignature)?;
    Ok(r.body)
}

/// Owner-signed message of a status poll.
pub fn status_message(guard_id: &GuardId, nonce: &[u8; 16]) -> Vec<u8> {
    let mut m = OWNER_DOMAIN.to_vec();
    m.extend_from_slice(b"status");
    m.extend_from_slice(guard_id);
    m.extend_from_slice(nonce);
    m
}

/// Owner-signed message of a delete.
pub fn delete_message(guard_id: &GuardId) -> Vec<u8> {
    let mut m = OWNER_DOMAIN.to_vec();
    m.extend_from_slice(b"delete");
    m.extend_from_slice(guard_id);
    m
}
