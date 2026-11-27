//! Realm logic (Guarded Kit spec, sections 5 and 6), independent of
//! transport and storage. A realm server wraps [`Realm::handle`] in HTTP
//! and backs [`RealmStore`] with its rollback-resistant state (R1).
//!
//! A realm holds one share `k_i` of the guard's OPRF key, never the key:
//! alone it can neither evaluate the OPRF nor test a password against its
//! tag (spec 4).
//!
//! Counting: every `Evaluate` raises `attempts` before evaluating. A
//! correct `Unlock` resets it. When `attempts` has reached the limit, a
//! wrong `Unlock` or any further `Evaluate` erases the OPRF key, the tag
//! and the share for good (decision Q4).

use std::collections::HashMap;

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use zeroize::{Zeroize, Zeroizing};

use super::GuardError;
use super::oprf;
use super::wire::{
    GuardId, RefusalCode, Request, ResponseBody, SignedResponse, decode_request, delete_message,
    encode_response, request_hash, response_message, status_message,
};
use crate::crypto::random_array;
use crate::crypto::sign::{ed25519_public_of, ed25519_sign};

/// Attempts per realm before erasure (decision Q3).
pub const DEFAULT_LIMIT: u8 = 10;
/// Largest sealed share a realm stores.
pub const MAX_SHARE_CT: usize = 1024;
/// Failures kept per guard.
const MAX_FAILURES: usize = 64;

/// One guard at one realm.
#[derive(Clone)]
pub struct GuardRecord {
    pub owner: [u8; 32],
    pub version: u32,
    /// This realm's share `k_i` of the OPRF key.
    pub key_share: Zeroizing<[u8; oprf::KEY_LEN]>,
    pub tag: [u8; 32],
    pub share_ct: Vec<u8>,
    pub attempts: u8,
    pub failures: Vec<u64>,
}

impl Drop for GuardRecord {
    fn drop(&mut self) {
        self.tag.zeroize();
        self.share_ct.zeroize();
    }
}

/// Storage of a realm. A production realm must not let its state roll
/// back (spec R1); the memory store is for tests and the local realm.
pub trait RealmStore {
    fn get(&self, id: &GuardId) -> Option<GuardRecord>;
    fn put(&mut self, id: GuardId, record: GuardRecord);
    fn erase(&mut self, id: &GuardId);
}

#[derive(Default)]
pub struct MemoryRealmStore {
    records: HashMap<GuardId, GuardRecord>,
}

impl MemoryRealmStore {
    /// Records held.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Forget every record (a realm that lost its state, in tests).
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

impl RealmStore for MemoryRealmStore {
    fn get(&self, id: &GuardId) -> Option<GuardRecord> {
        self.records.get(id).cloned()
    }
    fn put(&mut self, id: GuardId, record: GuardRecord) {
        self.records.insert(id, record);
    }
    fn erase(&mut self, id: &GuardId) {
        self.records.remove(id);
    }
}

/// A realm: its response signing key, its limit and its store.
pub struct Realm<S: RealmStore> {
    response_seed: Zeroizing<[u8; 32]>,
    limit: u8,
    store: S,
}

fn owner_ok(owner: &[u8; 32], message: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, owner)
        .verify(message, sig)
        .is_ok()
}

impl<S: RealmStore> Realm<S> {
    pub fn new(response_seed: [u8; 32], limit: u8, store: S) -> Realm<S> {
        Realm {
            response_seed: Zeroizing::new(response_seed),
            limit,
            store,
        }
    }

    /// The Ed25519 key clients pin for this realm.
    pub fn response_key(&self) -> Result<[u8; 32], GuardError> {
        ed25519_public_of(&self.response_seed).map_err(|_| GuardError::Crypto)
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Answer one request at Unix time `now`. Always returns a signed
    /// response, refusals included.
    pub fn handle(&mut self, request: &[u8], now: u64) -> Result<Vec<u8>, GuardError> {
        let body = match decode_request(request) {
            Ok(r) => self.dispatch(r, now)?,
            Err(_) => ResponseBody::Refused(RefusalCode::Malformed),
        };
        let request_hash = request_hash(request);
        let sig = ed25519_sign(
            &self.response_seed,
            &response_message(&request_hash, &body)?,
        )
        .map_err(|_| GuardError::Crypto)?;
        encode_response(&SignedResponse {
            request_hash,
            body,
            sig: sig.to_vec(),
        })
    }

    fn dispatch(&mut self, r: Request, now: u64) -> Result<ResponseBody, GuardError> {
        Ok(match r {
            Request::Register {
                owner,
                version,
                key_share,
                tag,
                share_ct,
            } => {
                if share_ct.len() > MAX_SHARE_CT {
                    return Ok(ResponseBody::Refused(RefusalCode::TooLarge));
                }
                // The share must be a valid nonzero scalar: the OPRF refuses
                // anything else at evaluation time, so refuse it now.
                if oprf::evaluate(&key_share, &oprf::blind(b"probe")?.message).is_err() {
                    return Ok(ResponseBody::Refused(RefusalCode::Malformed));
                }
                let guard_id = random_array::<16>().map_err(|_| GuardError::Crypto)?;
                self.store.put(
                    guard_id,
                    GuardRecord {
                        owner,
                        version,
                        key_share: Zeroizing::new(key_share),
                        tag,
                        share_ct,
                        attempts: 0,
                        failures: Vec::new(),
                    },
                );
                ResponseBody::Registered { guard_id }
            }
            Request::Evaluate { guard_id, blinded } => {
                let Some(mut rec) = self.store.get(&guard_id) else {
                    return Ok(ResponseBody::Gone);
                };
                if rec.attempts >= self.limit {
                    self.store.erase(&guard_id);
                    return Ok(ResponseBody::Gone);
                }
                // Count first, then evaluate: a crash in between costs the
                // user an attempt, never gives the attacker a free one.
                rec.attempts += 1;
                let remaining = self.limit - rec.attempts;
                let key = rec.key_share.clone();
                self.store.put(guard_id, rec);
                match oprf::evaluate(&key, &blinded) {
                    Ok(evaluation) => ResponseBody::Evaluated {
                        evaluation,
                        remaining,
                    },
                    Err(_) => ResponseBody::Refused(RefusalCode::Malformed),
                }
            }
            Request::Unlock { guard_id, tag } => {
                let Some(mut rec) = self.store.get(&guard_id) else {
                    return Ok(ResponseBody::Gone);
                };
                if verify_slices_are_equal(&rec.tag, &tag).is_ok() {
                    let share_ct = rec.share_ct.clone();
                    rec.attempts = 0;
                    rec.failures.clear();
                    self.store.put(guard_id, rec);
                    ResponseBody::Unlocked { share_ct }
                } else if rec.attempts >= self.limit {
                    self.store.erase(&guard_id);
                    ResponseBody::Gone
                } else {
                    if rec.failures.len() < MAX_FAILURES {
                        rec.failures.push(now);
                    }
                    let remaining = self.limit - rec.attempts;
                    self.store.put(guard_id, rec);
                    ResponseBody::WrongTag { remaining }
                }
            }
            Request::Status {
                guard_id,
                nonce,
                sig,
            } => {
                let Some(rec) = self.store.get(&guard_id) else {
                    return Ok(ResponseBody::Gone);
                };
                if !owner_ok(&rec.owner, &status_message(&guard_id, &nonce), &sig) {
                    return Ok(ResponseBody::Refused(RefusalCode::BadSignature));
                }
                ResponseBody::Status {
                    version: rec.version,
                    attempts: rec.attempts,
                    limit: self.limit,
                    failures: rec.failures.clone(),
                }
            }
            Request::Delete { guard_id, sig } => {
                let Some(rec) = self.store.get(&guard_id) else {
                    return Ok(ResponseBody::Gone);
                };
                if !owner_ok(&rec.owner, &delete_message(&guard_id), &sig) {
                    return Ok(ResponseBody::Refused(RefusalCode::BadSignature));
                }
                self.store.erase(&guard_id);
                ResponseBody::Deleted
            }
        })
    }
}
