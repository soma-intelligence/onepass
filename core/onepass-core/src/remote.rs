//! Remote approval messages (agent-ready spec 5.1): the Mac asks an enrolled
//! iPhone to approve or unlock, the iPhone answers. The transport (CloudKit)
//! is hostile, so every message is signed by its sender's hybrid signing key
//! (ML-DSA-87 + Ed25519) and its sensitive part is sealed to the recipient's
//! hybrid KEM key. This module is the pure message layer: no I/O, no clock;
//! the caller passes `now` (Unix seconds).
//!
//! Wire form of a message: `postcard { message, signature }`, where
//! `message = version (1) || type (1 request, 2 response) || postcard(body)`
//! and the signature covers `message` under `onepass/remote/message/v1`.
//! The sealed body of a request is `KEM envelope || blob`: the envelope wraps
//! a random key under the label `onepass/remote/request/v1`, the context
//! `request_id || from || to`; the blob seals the postcard `RequestBody`
//! under that key (`BlobKind::Remote`, blob id = request id).
//!
//! A sender is looked up in the approver list by `device_id` and role; a
//! device can hold two active entries after concurrent registrations, so a
//! message is accepted when any of them verifies it.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::approvers::{ApproverEntry, ApproverRole};
use crate::crypto::kem::{self, HybridKemPublic, HybridKemSecret};
use crate::crypto::{
    Aad, BlobKind, HybridSignature, HybridSigningKey, SymmetricKey, open, random_array, seal,
};
use crate::{Error, Id, IntegrityError, Result};

/// A request lives this long (`expires_at = created_at + 60`).
pub const REQUEST_TTL_SECS: i64 = 60;
/// How far the phone's clock may be off the Mac's, either way.
pub const PHONE_CLOCK_SKEW_SECS: i64 = 120;
/// How long the phone remembers the ids of the requests it has seen.
pub const REPLAY_WINDOW_SECS: i64 = 86_400;

/// Messages larger than this are refused before they are parsed.
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Most entries a replay guard keeps (a flood evicts the oldest).
const MAX_REPLAY_ENTRIES: usize = 8192;
/// At most this many detail lines or targets in a request body.
const MAX_BODY_LIST: usize = 64;

const VERSION: u8 = 1;
const TYPE_REQUEST: u8 = 1;
const TYPE_RESPONSE: u8 = 2;
const SIGN_DOMAIN: &[u8] = b"onepass/remote/message/v1";
const REQUEST_LABEL: &[u8] = b"onepass/remote/request/v1";
const UNLOCK_LABEL: &[u8] = b"onepass/remote/unlock/v1";
const SCHEMA: u16 = 1;

/// What a request asks for. Postcard encodes variants by index: new variants
/// must only ever be appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteKind {
    Approve,
    Unlock,
    ApproveAndUnlock,
    Pair,
    Lock,
    ForgetUnlock,
}

impl RemoteKind {
    /// Who sends this kind: `Lock` and `ForgetUnlock` are notices from the
    /// phone to the Mac (spec 6.3, 6.4); every other kind goes from the Mac
    /// to the phone.
    pub fn sender_role(self) -> ApproverRole {
        match self {
            RemoteKind::Lock | RemoteKind::ForgetUnlock => ApproverRole::Phone,
            _ => ApproverRole::Mac,
        }
    }

    /// Who receives this kind (the other role).
    pub fn recipient_role(self) -> ApproverRole {
        match self.sender_role() {
            ApproverRole::Mac => ApproverRole::Phone,
            ApproverRole::Phone => ApproverRole::Mac,
        }
    }

    fn needs_unlock_key(self) -> bool {
        matches!(self, RemoteKind::Unlock | RemoteKind::ApproveAndUnlock)
    }
}

/// The sealed part of a request: what the phone shows and what it needs to
/// answer. `transfer_key` carries `K_r` for `Pair`.
#[derive(Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub client: String,
    pub client_verified: bool,
    pub action: String,
    pub details: Vec<(String, String)>,
    pub targets: Vec<String>,
    pub remember_allowed: bool,
    pub strong_required: bool,
    pub confirm_code: String,
    pub unlock_eph_pub: Option<HybridKemPublic>,
    pub transfer_key: Option<Zeroizing<[u8; 32]>>,
    pub window_minutes: Option<u32>,
}

impl fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestBody")
            .field("client", &self.client)
            .field("client_verified", &self.client_verified)
            .field("action", &self.action)
            .field("details", &self.details)
            .field("targets", &self.targets)
            .field("remember_allowed", &self.remember_allowed)
            .field("strong_required", &self.strong_required)
            .field("confirm_code", &self.confirm_code)
            .field("unlock_eph_pub", &self.unlock_eph_pub)
            .field("transfer_key", &self.transfer_key.as_ref().map(|_| "**"))
            .field("window_minutes", &self.window_minutes)
            .finish()
    }
}

/// Everything of a request except its sealed body, which `seal_request`
/// fills itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub request_id: [u8; 16],
    pub from: Id,
    pub to: Id,
    pub created_at: i64,
    pub expires_at: i64,
    pub registry_seq: u64,
    pub approver_list_seq: u64,
    pub kind: RemoteKind,
}

/// A request as signed on the wire (sender to recipient).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRequest {
    pub request_id: [u8; 16],
    pub from: Id,
    pub to: Id,
    pub created_at: i64,
    pub expires_at: i64,
    pub registry_seq: u64,
    pub approver_list_seq: u64,
    pub kind: RemoteKind,
    #[serde(with = "serde_bytes")]
    pub sealed_body: Vec<u8>,
}

/// The phone's answer. Postcard index order: append only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteDecision {
    Denied,
    Once,
    Grant5m,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteResponse {
    pub request_id: [u8; 16],
    pub from: Id,
    pub to: Id,
    pub created_at: i64,
    pub decision: RemoteDecision,
    /// `K_r` wrapped to the request's `unlock_eph_pub`.
    pub sealed_unlock: Option<Vec<u8>>,
}

/// This device's own approval keys: what it signs with and opens with.
pub struct ApproverIdentity {
    pub device_id: Id,
    pub signing: HybridSigningKey,
    pub kem: HybridKemSecret,
}

impl fmt::Debug for ApproverIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApproverIdentity")
            .field("device_id", &self.device_id)
            .field("signing", &"**")
            .field("kem", &"**")
            .finish()
    }
}

/// The ids of the requests a device has accepted in the last 24 hours, so a
/// request replayed from the transport is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayGuard {
    /// `(request_id, accepted_at)`, oldest first.
    seen: Vec<([u8; 16], i64)>,
}

impl ReplayGuard {
    pub fn new() -> ReplayGuard {
        ReplayGuard::default()
    }

    pub fn contains(&self, request_id: &[u8; 16]) -> bool {
        self.seen.iter().any(|(id, _)| id == request_id)
    }

    #[cfg(test)]
    fn is_empty_for_tests(&self) -> bool {
        self.seen.is_empty()
    }

    /// Remember `request_id` as accepted at `now`, forgetting what is older
    /// than the replay window.
    pub fn record(&mut self, request_id: [u8; 16], now: i64) {
        let floor = now.saturating_sub(REPLAY_WINDOW_SECS);
        self.seen.retain(|(_, at)| *at > floor);
        if self.seen.len() >= MAX_REPLAY_ENTRIES {
            let drop = self.seen.len() + 1 - MAX_REPLAY_ENTRIES;
            self.seen.drain(..drop);
        }
        self.seen.push((request_id, now));
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::InvalidFormat("replay guard"))
    }

    pub fn from_bytes(b: &[u8]) -> Result<ReplayGuard> {
        let guard: ReplayGuard = decode(b, "replay guard")?;
        if guard.seen.len() > MAX_REPLAY_ENTRIES {
            return Err(Error::InvalidFormat("replay guard"));
        }
        Ok(guard)
    }
}

/// The requests a Mac has sent and still waits on: `request_id` to the
/// phone it went to and its `expires_at`.
#[derive(Debug, Clone, Default)]
pub struct PendingRequests {
    pending: Vec<([u8; 16], Id, i64)>,
}

impl PendingRequests {
    pub fn new() -> PendingRequests {
        PendingRequests::default()
    }

    pub fn insert(&mut self, request_id: [u8; 16], to: Id, expires_at: i64) {
        self.pending.push((request_id, to, expires_at));
    }

    /// Track a request just sealed.
    pub fn insert_header(&mut self, header: &RequestHeader) {
        self.insert(header.request_id, header.to, header.expires_at);
    }

    /// Stop waiting on a request (answered elsewhere, or expired).
    pub fn forget(&mut self, request_id: &[u8; 16]) {
        self.pending.retain(|(id, _, _)| id != request_id);
    }

    pub fn contains(&self, request_id: &[u8; 16]) -> bool {
        self.pending.iter().any(|(id, _, _)| id == request_id)
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    fn take(&mut self, request_id: &[u8; 16]) -> Option<(Id, i64)> {
        let at = self
            .pending
            .iter()
            .position(|(id, _, _)| id == request_id)?;
        let (_, to, expires_at) = self.pending.swap_remove(at);
        Some((to, expires_at))
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    #[serde(with = "serde_bytes")]
    message: Vec<u8>,
    signature: HybridSignature,
}

fn integrity(e: IntegrityError) -> Error {
    Error::Integrity(e)
}

fn kem_context(request_id: &[u8; 16], from: Id, to: Id) -> [u8; 48] {
    let mut c = [0u8; 48];
    c[..16].copy_from_slice(request_id);
    c[16..32].copy_from_slice(&from.0);
    c[32..].copy_from_slice(&to.0);
    c
}

fn body_aad(request_id: &[u8; 16]) -> Aad {
    Aad {
        blob_id: Id(*request_id),
        vault_id: None,
        schema: SCHEMA,
    }
}

/// One signed message has exactly one encoding: trailing bytes are refused.
fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8], what: &'static str) -> Result<T> {
    match postcard::take_from_bytes::<T>(bytes) {
        Ok((value, [])) => Ok(value),
        _ => Err(Error::InvalidFormat(what)),
    }
}

fn encode_message<T: Serialize>(kind: u8, body: &T) -> Result<Vec<u8>> {
    let mut m = vec![VERSION, kind];
    let bytes = postcard::to_allocvec(body).map_err(|_| Error::InvalidFormat("remote message"))?;
    m.extend_from_slice(&bytes);
    Ok(m)
}

fn sign_message(signer: &HybridSigningKey, message: Vec<u8>) -> Result<Vec<u8>> {
    let signature = signer.sign(SIGN_DOMAIN, &message)?;
    postcard::to_allocvec(&Envelope { message, signature })
        .map_err(|_| Error::InvalidFormat("remote message"))
}

/// Parse the envelope and return the message payload (type checked) with
/// the signature, not yet verified.
fn parse_envelope(bytes: &[u8], kind: u8) -> Result<(Envelope, usize)> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::InvalidFormat("remote message size"));
    }
    let env: Envelope = decode(bytes, "remote message")?;
    if env.message.len() < 2 || env.message[0] != VERSION || env.message[1] != kind {
        return Err(Error::InvalidFormat("remote message"));
    }
    Ok((env, 2))
}

/// Verify `env` against any active entry of `from` with the given role.
fn verify_sender(
    env: &Envelope,
    from: Id,
    role: ApproverRole,
    approvers: &[ApproverEntry],
) -> Result<()> {
    let mut known = false;
    for entry in approvers
        .iter()
        .filter(|e| e.device_id == from && e.role == role && e.retired_at.is_none())
    {
        known = true;
        if entry
            .sign_pub
            .verify(SIGN_DOMAIN, &env.message, &env.signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(integrity(if known {
        IntegrityError::RemoteSignature
    } else {
        IntegrityError::RemoteUnknownDevice
    }))
}

fn check_body_shape(kind: RemoteKind, body: &RequestBody) -> Result<()> {
    let bad = Error::InvalidFormat("remote request body");
    if body.details.len() > MAX_BODY_LIST || body.targets.len() > MAX_BODY_LIST {
        return Err(bad);
    }
    if kind.needs_unlock_key() != body.unlock_eph_pub.is_some() {
        return Err(bad);
    }
    if (kind == RemoteKind::Pair) != body.transfer_key.is_some() {
        return Err(bad);
    }
    Ok(())
}

fn check_header_times(h: &RequestHeader) -> Result<()> {
    match h.expires_at.checked_sub(h.created_at) {
        Some(ttl) if ttl > 0 && ttl <= REQUEST_TTL_SECS => Ok(()),
        _ => Err(Error::InvalidFormat("remote request lifetime")),
    }
}

/// Seal `body` to `to` (the phone, or the Mac for a phone notice) and sign
/// the whole request as `signer`. `to` must hold the recipient role of the
/// kind.
pub fn seal_request(
    signer: &HybridSigningKey,
    to: &ApproverEntry,
    header: RequestHeader,
    body: &RequestBody,
) -> Result<Vec<u8>> {
    if header.to != to.device_id || to.role != header.kind.recipient_role() {
        return Err(integrity(IntegrityError::RemoteWrongRecipient));
    }
    check_header_times(&header)?;
    check_body_shape(header.kind, body)?;

    let key = SymmetricKey::generate()?;
    let envelope = kem::wrap_key_labeled(
        &to.kem_pub,
        &key,
        REQUEST_LABEL,
        &kem_context(&header.request_id, header.from, header.to),
    )?;
    // Exact size first, then one write into a wiped buffer: no growing plain
    // Vec leaves copies of the transfer key behind.
    let bad = |_| Error::InvalidFormat("remote request body");
    let size = postcard::experimental::serialized_size(body).map_err(bad)?;
    let mut plain = Zeroizing::new(vec![0u8; size]);
    let used = postcard::to_slice(body, &mut plain).map_err(bad)?.len();
    plain.truncate(used);
    let blob = seal(
        &key,
        BlobKind::Remote,
        &body_aad(&header.request_id),
        &plain,
    )?;
    let mut sealed_body = envelope;
    sealed_body.extend_from_slice(&blob);

    let request = RemoteRequest {
        request_id: header.request_id,
        from: header.from,
        to: header.to,
        created_at: header.created_at,
        expires_at: header.expires_at,
        registry_seq: header.registry_seq,
        approver_list_seq: header.approver_list_seq,
        kind: header.kind,
        sealed_body,
    };
    sign_message(signer, encode_message(TYPE_REQUEST, &request)?)
}

/// The receiving side: check recipient, sender (a Mac, or a phone for the
/// notices `Lock` and `ForgetUnlock`), signature, expiry (with the phone's
/// clock tolerance) and replay, then open the body.
pub fn open_request(
    bytes: &[u8],
    me: &ApproverIdentity,
    approvers: &[ApproverEntry],
    now: i64,
    seen: &mut ReplayGuard,
) -> Result<(RemoteRequest, RequestBody)> {
    let (env, skip) = parse_envelope(bytes, TYPE_REQUEST)?;
    let request: RemoteRequest = decode(&env.message[skip..], "remote request")?;
    if request.to != me.device_id {
        return Err(integrity(IntegrityError::RemoteWrongRecipient));
    }
    verify_sender(&env, request.from, request.kind.sender_role(), approvers)?;
    // The receiver must hold the kind's recipient role: a phone never takes
    // a notice meant for a Mac, nor a Mac a request meant for a phone.
    let role = request.kind.recipient_role();
    if !approvers
        .iter()
        .any(|e| e.device_id == me.device_id && e.role == role && e.retired_at.is_none())
    {
        return Err(integrity(IntegrityError::RemoteWrongRecipient));
    }

    if now.saturating_add(PHONE_CLOCK_SKEW_SECS) < request.created_at
        || now > request.expires_at.saturating_add(PHONE_CLOCK_SKEW_SECS)
    {
        return Err(integrity(IntegrityError::RemoteExpired));
    }
    if seen.contains(&request.request_id) {
        return Err(integrity(IntegrityError::RemoteReplay));
    }
    check_header_times(&RequestHeader {
        request_id: request.request_id,
        from: request.from,
        to: request.to,
        created_at: request.created_at,
        expires_at: request.expires_at,
        registry_seq: request.registry_seq,
        approver_list_seq: request.approver_list_seq,
        kind: request.kind,
    })?;

    let env_len = kem::envelope_len();
    if request.sealed_body.len() < env_len {
        return Err(Error::InvalidFormat("remote request body"));
    }
    let (envelope, blob) = request.sealed_body.split_at(env_len);
    let key = kem::unwrap_key_labeled(
        &me.kem,
        envelope,
        REQUEST_LABEL,
        &kem_context(&request.request_id, request.from, request.to),
    )?;
    let plain = open(&key, BlobKind::Remote, &body_aad(&request.request_id), blob)?;
    let body: RequestBody = decode(&plain, "remote request body")?;
    check_body_shape(request.kind, &body)?;

    seen.record(request.request_id, now);
    Ok((request, body))
}

/// The phone's answer to `request`, addressed to the Mac `to` that sent it.
/// `unlock_key` (`K_r`) and `eph` (the request's `unlock_eph_pub`) go
/// together, and only with a decision other than `Denied`. `now` stamps
/// `created_at`.
pub fn seal_response(
    signer: &HybridSigningKey,
    to: &ApproverEntry,
    request: &RemoteRequest,
    decision: RemoteDecision,
    unlock_key: Option<&SymmetricKey>,
    eph: Option<&HybridKemPublic>,
    now: i64,
) -> Result<Vec<u8>> {
    if to.device_id != request.from {
        return Err(integrity(IntegrityError::RemoteWrongRecipient));
    }
    let response_ctx = kem_context(&request.request_id, request.to, request.from);
    let sealed_unlock = match (unlock_key, eph) {
        (Some(k), Some(e)) if decision != RemoteDecision::Denied => {
            Some(kem::wrap_key_labeled(e, k, UNLOCK_LABEL, &response_ctx)?)
        }
        (None, None) => None,
        _ => return Err(Error::InvalidFormat("remote unlock key")),
    };
    let response = RemoteResponse {
        request_id: request.request_id,
        from: request.to,
        to: request.from,
        created_at: now,
        decision,
        sealed_unlock,
    };
    sign_message(signer, encode_message(TYPE_RESPONSE, &response)?)
}

/// The Mac side: accept one answer per request it sent, from a phone of the
/// list, addressed to it, before the request's `expires_at` on its own
/// clock. Nothing is consumed unless every check passes.
pub fn open_response(
    bytes: &[u8],
    me: &ApproverIdentity,
    approvers: &[ApproverEntry],
    pending: &mut PendingRequests,
    now: i64,
) -> Result<RemoteResponse> {
    let (env, skip) = parse_envelope(bytes, TYPE_RESPONSE)?;
    let response: RemoteResponse = decode(&env.message[skip..], "remote response")?;
    if response.to != me.device_id {
        return Err(integrity(IntegrityError::RemoteWrongRecipient));
    }
    verify_sender(&env, response.from, ApproverRole::Phone, approvers)?;

    let unknown = || integrity(IntegrityError::RemoteUnknownRequest);
    let Some((phone, expires_at)) = pending
        .pending
        .iter()
        .find(|(id, _, _)| *id == response.request_id)
        .map(|(_, to, exp)| (*to, *exp))
    else {
        return Err(unknown());
    };
    if phone != response.from {
        return Err(unknown());
    }
    if now > expires_at {
        return Err(integrity(IntegrityError::RemoteExpired));
    }
    pending.take(&response.request_id);
    Ok(response)
}

/// Open the `K_r` of an accepted response with the private half of the
/// request's `unlock_eph_pub`.
pub fn open_unlock(
    response: &RemoteResponse,
    eph_secret: &HybridKemSecret,
) -> Result<SymmetricKey> {
    let sealed = response
        .sealed_unlock
        .as_deref()
        .ok_or(Error::InvalidFormat("remote unlock key"))?;
    kem::unwrap_key_labeled(
        eph_secret,
        sealed,
        UNLOCK_LABEL,
        &kem_context(&response.request_id, response.from, response.to),
    )
}

/// A fresh random request id.
pub fn new_request_id() -> Result<[u8; 16]> {
    random_array::<16>()
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_800_000_000;

    struct Party {
        id: ApproverIdentity,
        entry: ApproverEntry,
    }

    fn party(n: u8, role: ApproverRole) -> Party {
        let signing = HybridSigningKey::generate().unwrap();
        let kem = HybridKemSecret::generate().unwrap();
        let device_id = Id([n; 16]);
        let entry = ApproverEntry {
            device_id,
            sign_pub: signing.verifying_key().unwrap(),
            kem_pub: kem.public().unwrap(),
            role,
            added_at: 0,
            retired_at: None,
        };
        Party {
            id: ApproverIdentity {
                device_id,
                signing,
                kem,
            },
            entry,
        }
    }

    fn header(mac: &Party, phone: &Party, kind: RemoteKind) -> RequestHeader {
        RequestHeader {
            request_id: [9; 16],
            from: mac.id.device_id,
            to: phone.id.device_id,
            created_at: T,
            expires_at: T + REQUEST_TTL_SECS,
            registry_seq: 3,
            approver_list_seq: 4,
            kind,
        }
    }

    fn body() -> RequestBody {
        RequestBody {
            client: "Claude Code".into(),
            client_verified: true,
            action: "read_secret".into(),
            details: vec![("field".into(), "password".into())],
            targets: vec!["Work/GitHub".into()],
            remember_allowed: true,
            strong_required: false,
            confirm_code: "kq".into(),
            unlock_eph_pub: None,
            transfer_key: None,
            window_minutes: None,
        }
    }

    fn list(mac: &Party, phone: &Party) -> Vec<ApproverEntry> {
        vec![mac.entry.clone(), phone.entry.clone()]
    }

    fn sealed(mac: &Party, phone: &Party) -> Vec<u8> {
        seal_request(
            &mac.id.signing,
            &phone.entry,
            header(mac, phone, RemoteKind::Approve),
            &body(),
        )
        .unwrap()
    }

    fn err(e: IntegrityError) -> Error {
        Error::Integrity(e)
    }

    /// What opening a body sealed to another key gives.
    const WRONG_KEY: Error = Error::Integrity(IntegrityError::Commitment);

    #[test]
    fn notices_go_from_the_phone_to_the_mac() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let list = list(&mac, &phone);
        for kind in [RemoteKind::Lock, RemoteKind::ForgetUnlock] {
            let mut b = body();
            b.client = "OnePass".into();
            let notice = seal_request(
                &phone.id.signing,
                &mac.entry,
                header(&phone, &mac, kind),
                &b,
            )
            .unwrap();
            let mut seen = ReplayGuard::new();
            let (req, _) = open_request(&notice, &mac.id, &list, T + 1, &mut seen).unwrap();
            assert_eq!(req.kind, kind);
            assert_eq!(req.from, phone.id.device_id);
            // Sealed the wrong way round: refused at sealing.
            assert_eq!(
                seal_request(
                    &mac.id.signing,
                    &phone.entry,
                    header(&mac, &phone, kind),
                    &b
                )
                .unwrap_err(),
                err(IntegrityError::RemoteWrongRecipient)
            );
        }
        // A notice addressed to a phone is refused by that phone.
        let to_phone = ApproverEntry {
            role: ApproverRole::Mac,
            ..phone.entry.clone()
        };
        let mut h = header(&phone, &phone, RemoteKind::Lock);
        h.to = phone.id.device_id;
        let misdirected = seal_request(&phone.id.signing, &to_phone, h, &body()).unwrap();
        let mut seen = ReplayGuard::new();
        assert_eq!(
            open_request(&misdirected, &phone.id, &list, T + 1, &mut seen).unwrap_err(),
            err(IntegrityError::RemoteWrongRecipient)
        );
        assert!(seen.is_empty_for_tests());
        // A notice signed by a Mac is refused: only a phone sends one.
        let mut h = header(&phone, &mac, RemoteKind::Lock);
        h.from = mac.id.device_id;
        let forged = seal_request(&mac.id.signing, &mac.entry, h, &body()).unwrap();
        assert_eq!(
            open_request(&forged, &mac.id, &list, T + 1, &mut ReplayGuard::new()).unwrap_err(),
            err(IntegrityError::RemoteUnknownDevice)
        );
        // An Approve request cannot be addressed to a Mac either.
        assert_eq!(
            seal_request(
                &phone.id.signing,
                &mac.entry,
                header(&phone, &mac, RemoteKind::Approve),
                &body()
            )
            .unwrap_err(),
            err(IntegrityError::RemoteWrongRecipient)
        );
    }

    #[test]
    fn request_round_trip() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        let mut seen = ReplayGuard::new();
        let (req, b) =
            open_request(&bytes, &phone.id, &list(&mac, &phone), T + 5, &mut seen).unwrap();
        assert_eq!(req.request_id, [9; 16]);
        assert_eq!(req.from, mac.id.device_id);
        assert_eq!(req.registry_seq, 3);
        assert_eq!(req.approver_list_seq, 4);
        assert_eq!(req.kind, RemoteKind::Approve);
        assert_eq!(b.client, "Claude Code");
        assert_eq!(b.confirm_code, "kq");
        assert_eq!(b.targets, vec!["Work/GitHub".to_string()]);
        assert!(seen.contains(&[9; 16]));
    }

    #[test]
    fn pair_request_carries_transfer_key() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let mut b = body();
        b.transfer_key = Some(Zeroizing::new([0x5a; 32]));
        let bytes = seal_request(
            &mac.id.signing,
            &phone.entry,
            header(&mac, &phone, RemoteKind::Pair),
            &b,
        )
        .unwrap();
        let (_, got) = open_request(
            &bytes,
            &phone.id,
            &list(&mac, &phone),
            T,
            &mut ReplayGuard::new(),
        )
        .unwrap();
        assert_eq!(*got.transfer_key.unwrap(), [0x5a; 32]);
    }

    #[test]
    fn response_round_trip_with_unlock_key() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let eph_secret = HybridKemSecret::generate().unwrap();
        let mut b = body();
        b.unlock_eph_pub = Some(eph_secret.public().unwrap());
        let bytes = seal_request(
            &mac.id.signing,
            &phone.entry,
            header(&mac, &phone, RemoteKind::ApproveAndUnlock),
            &b,
        )
        .unwrap();
        let approvers = list(&mac, &phone);
        let (req, opened) =
            open_request(&bytes, &phone.id, &approvers, T, &mut ReplayGuard::new()).unwrap();

        let k_r = SymmetricKey::generate().unwrap();
        let resp = seal_response(
            &phone.id.signing,
            &mac.entry,
            &req,
            RemoteDecision::Grant5m,
            Some(&k_r),
            opened.unlock_eph_pub.as_ref(),
            T + 10,
        )
        .unwrap();

        let mut pending = PendingRequests::new();
        pending.insert_header(&header(&mac, &phone, RemoteKind::ApproveAndUnlock));
        let got = open_response(&resp, &mac.id, &approvers, &mut pending, T + 11).unwrap();
        assert_eq!(got.decision, RemoteDecision::Grant5m);
        assert_eq!(got.from, phone.id.device_id);
        assert_eq!(got.to, mac.id.device_id);
        assert!(pending.is_empty());
        let k = open_unlock(&got, &eph_secret).unwrap();
        assert_eq!(k.expose(), k_r.expose());
    }

    #[test]
    fn request_rejected_when_expired_beyond_skew() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        let r = open_request(
            &bytes,
            &phone.id,
            &list(&mac, &phone),
            T + 60 + 121,
            &mut ReplayGuard::new(),
        );
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteExpired));
        let early = open_request(
            &bytes,
            &phone.id,
            &list(&mac, &phone),
            T - 121,
            &mut ReplayGuard::new(),
        );
        assert_eq!(early.unwrap_err(), err(IntegrityError::RemoteExpired));
    }

    #[test]
    fn request_accepted_within_skew() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        for now in [T - 120, T - 119, T + 60 + 119, T + 60 + 120] {
            open_request(
                &bytes,
                &phone.id,
                &list(&mac, &phone),
                now,
                &mut ReplayGuard::new(),
            )
            .unwrap();
        }
    }

    #[test]
    fn request_replay_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        let approvers = list(&mac, &phone);
        let mut seen = ReplayGuard::new();
        open_request(&bytes, &phone.id, &approvers, T, &mut seen).unwrap();
        let again = open_request(&bytes, &phone.id, &approvers, T + 1, &mut seen);
        assert_eq!(again.unwrap_err(), err(IntegrityError::RemoteReplay));
        // The guard survives a relaunch of the phone app.
        let mut restored = ReplayGuard::from_bytes(&seen.to_bytes().unwrap()).unwrap();
        let after = open_request(&bytes, &phone.id, &approvers, T + 2, &mut restored);
        assert_eq!(after.unwrap_err(), err(IntegrityError::RemoteReplay));
    }

    #[test]
    fn replay_guard_forgets_after_the_window() {
        let mut g = ReplayGuard::new();
        g.record([1; 16], 100);
        g.record([2; 16], 100 + REPLAY_WINDOW_SECS + 1);
        assert!(!g.contains(&[1; 16]));
        assert!(g.contains(&[2; 16]));
        assert!(ReplayGuard::from_bytes(&[0xff; 9]).is_err());
    }

    #[test]
    fn request_from_revoked_device_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        // A revoked Mac is no longer in `approvers()`.
        let r = open_request(
            &bytes,
            &phone.id,
            std::slice::from_ref(&phone.entry),
            T,
            &mut ReplayGuard::new(),
        );
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteUnknownDevice));
        // Same device id, other key: the signature does not verify.
        let impostor = Party {
            entry: ApproverEntry {
                sign_pub: party(1, ApproverRole::Mac).entry.sign_pub,
                ..mac.entry.clone()
            },
            ..party(1, ApproverRole::Mac)
        };
        let r = open_request(
            &bytes,
            &phone.id,
            &[impostor.entry, phone.entry.clone()],
            T,
            &mut ReplayGuard::new(),
        );
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteSignature));
    }

    #[test]
    fn request_accepted_when_second_entry_of_device_verifies() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        let other = party(1, ApproverRole::Mac);
        let approvers = vec![other.entry, mac.entry.clone(), phone.entry.clone()];
        open_request(&bytes, &phone.id, &approvers, T, &mut ReplayGuard::new()).unwrap();
    }

    #[test]
    fn request_for_other_device_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let other = party(3, ApproverRole::Phone);
        let bytes = sealed(&mac, &phone);
        let mut approvers = list(&mac, &phone);
        approvers.push(other.entry.clone());
        let r = open_request(&bytes, &other.id, &approvers, T, &mut ReplayGuard::new());
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteWrongRecipient));
    }

    #[test]
    fn response_for_unknown_request_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let approvers = list(&mac, &phone);
        let (req, _) = open_request(
            &sealed(&mac, &phone),
            &phone.id,
            &approvers,
            T,
            &mut ReplayGuard::new(),
        )
        .unwrap();
        let resp = seal_response(
            &phone.id.signing,
            &mac.entry,
            &req,
            RemoteDecision::Once,
            None,
            None,
            T,
        )
        .unwrap();
        let r = open_response(&resp, &mac.id, &approvers, &mut PendingRequests::new(), T);
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteUnknownRequest));
        // Pending for another phone: the answer does not count.
        let mut pending = PendingRequests::new();
        pending.insert([9; 16], Id([7; 16]), T + 60);
        let r = open_response(&resp, &mac.id, &approvers, &mut pending, T);
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteUnknownRequest));
        assert_eq!(pending.len(), 1);
    }

    fn answered(mac: &Party, phone: &Party) -> (Vec<u8>, Vec<ApproverEntry>, PendingRequests) {
        let approvers = list(mac, phone);
        let (req, _) = open_request(
            &sealed(mac, phone),
            &phone.id,
            &approvers,
            T,
            &mut ReplayGuard::new(),
        )
        .unwrap();
        let resp = seal_response(
            &phone.id.signing,
            &mac.entry,
            &req,
            RemoteDecision::Once,
            None,
            None,
            T,
        )
        .unwrap();
        let mut pending = PendingRequests::new();
        pending.insert_header(&header(mac, phone, RemoteKind::Approve));
        (resp, approvers, pending)
    }

    #[test]
    fn response_after_expiry_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let (resp, approvers, mut pending) = answered(&mac, &phone);
        let r = open_response(&resp, &mac.id, &approvers, &mut pending, T + 60 + 1);
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteExpired));
        // Exactly at expires_at it still counts.
        open_response(&resp, &mac.id, &approvers, &mut pending, T + 60).unwrap();
    }

    #[test]
    fn response_second_time_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let (resp, approvers, mut pending) = answered(&mac, &phone);
        open_response(&resp, &mac.id, &approvers, &mut pending, T + 1).unwrap();
        let again = open_response(&resp, &mac.id, &approvers, &mut pending, T + 2);
        assert_eq!(
            again.unwrap_err(),
            err(IntegrityError::RemoteUnknownRequest)
        );
    }

    #[test]
    fn response_signed_by_a_mac_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let (_, approvers, mut pending) = answered(&mac, &phone);
        // A response cannot be passed off as a request, nor the reverse.
        let req_bytes = sealed(&mac, &phone);
        let r = open_response(&req_bytes, &mac.id, &approvers, &mut pending, T);
        assert!(matches!(r, Err(Error::InvalidFormat(_))));
        let (resp, _, _) = answered(&mac, &phone);
        let r = open_request(&resp, &phone.id, &approvers, T, &mut ReplayGuard::new());
        assert!(matches!(r, Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn tampered_header_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        let env: Envelope = postcard::from_bytes(&bytes).unwrap();
        let mut req: RemoteRequest = postcard::from_bytes(&env.message[2..]).unwrap();
        req.expires_at += 30;
        let forged = postcard::to_allocvec(&Envelope {
            message: encode_message(TYPE_REQUEST, &req).unwrap(),
            signature: env.signature,
        })
        .unwrap();
        let r = open_request(
            &forged,
            &phone.id,
            &list(&mac, &phone),
            T,
            &mut ReplayGuard::new(),
        );
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteSignature));
    }

    #[test]
    fn body_sealed_to_other_phone_unreadable() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let other = party(3, ApproverRole::Phone);
        let bytes = sealed(&mac, &phone);
        // Re-address the signed request to `other` with a valid signature,
        // keeping the body sealed to `phone`.
        let env: Envelope = postcard::from_bytes(&bytes).unwrap();
        let mut req: RemoteRequest = postcard::from_bytes(&env.message[2..]).unwrap();
        req.to = other.id.device_id;
        let resigned =
            sign_message(&mac.id.signing, encode_message(TYPE_REQUEST, &req).unwrap()).unwrap();
        let approvers = vec![mac.entry.clone(), phone.entry.clone(), other.entry.clone()];
        let mut seen = ReplayGuard::new();
        let r = open_request(&resigned, &other.id, &approvers, T, &mut seen);
        assert_eq!(r.unwrap_err(), WRONG_KEY);
        assert!(!seen.contains(&[9; 16]));
        // The unmodified request opened with the wrong secret fails too.
        let wrong = ApproverIdentity {
            device_id: phone.id.device_id,
            signing: HybridSigningKey::generate().unwrap(),
            kem: other.id.kem,
        };
        let r = open_request(&bytes, &wrong, &approvers, T, &mut ReplayGuard::new());
        assert_eq!(r.unwrap_err(), WRONG_KEY);
    }

    #[test]
    fn unlock_key_needs_a_decision_and_an_ephemeral_key() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let (req, _) = open_request(
            &sealed(&mac, &phone),
            &phone.id,
            &list(&mac, &phone),
            T,
            &mut ReplayGuard::new(),
        )
        .unwrap();
        let k = SymmetricKey::generate().unwrap();
        let eph = HybridKemSecret::generate().unwrap().public().unwrap();
        for (d, key, e) in [
            (RemoteDecision::Denied, Some(&k), Some(&eph)),
            (RemoteDecision::Once, Some(&k), None),
            (RemoteDecision::Once, None, Some(&eph)),
        ] {
            let r = seal_response(&phone.id.signing, &mac.entry, &req, d, key, e, T);
            assert_eq!(r.unwrap_err(), Error::InvalidFormat("remote unlock key"));
        }
    }

    #[test]
    fn seal_request_checks_shape() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let mut h = header(&mac, &phone, RemoteKind::Approve);
        h.expires_at = h.created_at + REQUEST_TTL_SECS + 1;
        let r = seal_request(&mac.id.signing, &phone.entry, h, &body());
        assert_eq!(
            r.unwrap_err(),
            Error::InvalidFormat("remote request lifetime")
        );
        // Unlock without an ephemeral key, Pair without a transfer key.
        for kind in [RemoteKind::Unlock, RemoteKind::Pair] {
            let h = header(&mac, &phone, kind);
            let r = seal_request(&mac.id.signing, &phone.entry, h, &body());
            assert_eq!(r.unwrap_err(), Error::InvalidFormat("remote request body"));
        }
        let other = party(3, ApproverRole::Phone);
        let h = header(&mac, &phone, RemoteKind::Approve);
        let r = seal_request(&mac.id.signing, &other.entry, h, &body());
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteWrongRecipient));
    }

    #[test]
    fn request_signed_by_a_phone_entry_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        // The sender's device id is listed, with a valid key, but as a Phone.
        let wrong_role = ApproverEntry {
            role: ApproverRole::Phone,
            ..mac.entry.clone()
        };
        let r = open_request(
            &bytes,
            &phone.id,
            &[wrong_role, phone.entry.clone()],
            T,
            &mut ReplayGuard::new(),
        );
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteUnknownDevice));
    }

    #[test]
    fn request_from_retired_mac_entry_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let bytes = sealed(&mac, &phone);
        let retired = ApproverEntry {
            retired_at: Some(T - 1),
            ..mac.entry.clone()
        };
        let r = open_request(
            &bytes,
            &phone.id,
            &[retired, phone.entry.clone()],
            T,
            &mut ReplayGuard::new(),
        );
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteUnknownDevice));
    }

    #[test]
    fn response_signed_by_a_mac_entry_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let (resp, _, mut pending) = answered(&mac, &phone);
        let wrong_role = ApproverEntry {
            role: ApproverRole::Mac,
            ..phone.entry.clone()
        };
        let r = open_response(
            &resp,
            &mac.id,
            &[mac.entry.clone(), wrong_role],
            &mut pending,
            T + 1,
        );
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteUnknownDevice));
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn response_from_retired_phone_entry_rejected() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let (resp, _, mut pending) = answered(&mac, &phone);
        let retired = ApproverEntry {
            retired_at: Some(T - 1),
            ..phone.entry.clone()
        };
        let r = open_response(
            &resp,
            &mac.id,
            &[mac.entry.clone(), retired],
            &mut pending,
            T + 1,
        );
        assert_eq!(r.unwrap_err(), err(IntegrityError::RemoteUnknownDevice));
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn trailing_bytes_refused() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let approvers = list(&mac, &phone);
        let invalid = |r: Result<_>| matches!(r.map(|_: ()| ()), Err(Error::InvalidFormat(_)));

        let mut req = sealed(&mac, &phone);
        req.push(0);
        let r = open_request(&req, &phone.id, &approvers, T, &mut ReplayGuard::new());
        assert!(invalid(r.map(|_| ())));

        // Trailing byte inside the signed message (re-signed, so the
        // signature is valid): still not the one encoding.
        let env: Envelope = postcard::from_bytes(&sealed(&mac, &phone)).unwrap();
        let mut message = env.message.clone();
        message.push(0);
        let inner = sign_message(&mac.id.signing, message).unwrap();
        let r = open_request(&inner, &phone.id, &approvers, T, &mut ReplayGuard::new());
        assert!(invalid(r.map(|_| ())));

        let (mut resp, _, mut pending) = answered(&mac, &phone);
        resp.push(0);
        let r = open_response(&resp, &mac.id, &approvers, &mut pending, T + 1);
        assert!(invalid(r.map(|_| ())));
        assert_eq!(pending.len(), 1);

        let mut guard = ReplayGuard::new().to_bytes().unwrap();
        guard.push(0);
        assert!(invalid(ReplayGuard::from_bytes(&guard).map(|_| ())));
    }

    #[test]
    fn extreme_lifetime_is_an_error_not_a_panic() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let mut h = header(&mac, &phone, RemoteKind::Approve);
        h.created_at = i64::MIN;
        h.expires_at = i64::MAX;
        let r = seal_request(&mac.id.signing, &phone.entry, h, &body());
        assert_eq!(
            r.unwrap_err(),
            Error::InvalidFormat("remote request lifetime")
        );

        // The same header as a hostile Mac signs it: the phone refuses it too.
        let env: Envelope = postcard::from_bytes(&sealed(&mac, &phone)).unwrap();
        let mut req: RemoteRequest = postcard::from_bytes(&env.message[2..]).unwrap();
        req.created_at = i64::MIN;
        req.expires_at = i64::MAX;
        let forged =
            sign_message(&mac.id.signing, encode_message(TYPE_REQUEST, &req).unwrap()).unwrap();
        let r = open_request(
            &forged,
            &phone.id,
            &list(&mac, &phone),
            T,
            &mut ReplayGuard::new(),
        );
        assert_eq!(
            r.unwrap_err(),
            Error::InvalidFormat("remote request lifetime")
        );
    }

    #[test]
    fn oversized_message_refused() {
        let (mac, phone) = (party(1, ApproverRole::Mac), party(2, ApproverRole::Phone));
        let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let r = open_request(
            &big,
            &phone.id,
            &list(&mac, &phone),
            T,
            &mut ReplayGuard::new(),
        );
        assert!(matches!(r, Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn debug_never_prints_transfer_key() {
        let mut b = body();
        b.transfer_key = Some(Zeroizing::new([0xab; 32]));
        let s = format!("{b:?}");
        assert!(s.contains("**"));
        assert!(!s.contains("171"));
        assert!(!s.contains("ab, ab"));
        let id = party(1, ApproverRole::Mac).id;
        assert!(!format!("{id:?}").contains("mlkem"));
    }
}
