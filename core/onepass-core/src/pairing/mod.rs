//! QR pairing protocol (milestone 2b, spec 5): a new device (N, the
//! newcomer) gets the Secret Key and a store snapshot, or a read-only public
//! session, from an unlocked device (A, the approver). Independent of the
//! OS and of the transport; every format below is enough to implement it
//! elsewhere. postcard is the serde wire format (varints, enum variants by
//! index, `[u8; N]` raw, `Vec<u8>`/`String` length-prefixed). Times are
//! Unix seconds.
//!
//! 1. N draws an ephemeral hybrid KEM pair (ML-KEM-1024 + X25519, `kem`), a
//!    random 16-byte `session_id`, and shows the QR text
//!    `"OPPAIR1:" || BASE32(postcard(PairingQr))` (RFC 4648, upper case, no
//!    padding), `PairingQr = {version: u8 = 1, session_id: [u8; 16],
//!    key_hash: [u8; 32], expires_at: i64}`, where `key_hash =
//!    SHA-256(mlkem public (1568) || x25519 public (32))` and `expires_at =
//!    issue + 120`. No URL, no full key.
//! 2. N -> A, Hello: `"OPH1" || postcard(Hello)`, `Hello = {session_id,
//!    ephemeral_public: {mlkem: bytes, x25519: [u8; 32]}, device:
//!    {device_id: [u8; 16], name: String, kind: DeviceKind}, requested_mode:
//!    DeviceMode}`.
//! 3. A refuses unless: the QR parses canonically, `now <= expires_at`,
//!    `now >= expires_at - 120 - CLOCK_SKEW_SECS`, the Hello `session_id`
//!    is the QR's, and `SHA-256(ephemeral_public) == key_hash`. A draws a
//!    32-byte session key K and wraps it:
//!    `kem::wrap_key_labeled(ephemeral_public, K, "onepass/pairing/v1",
//!    transcript)`, `transcript = SHA-256(QR text bytes || Hello bytes)`.
//! 4. A -> N, KeyExchange: `"OPK1" || envelope`. N refuses it after its own
//!    `expires_at`, then forgets the ephemeral secret.
//! 5. Both show the SAS: the first 8 bytes of `HKDF-SHA256(salt = empty,
//!    ikm = K, info = "onepass/pairing/sas/v1" || transcript)` as a
//!    big-endian u64, modulo 10^6, as 6 zero-padded digits.
//! 6. From here every message is a channel frame (`channel`): N -> A
//!    `Confirmed` once its user confirmed the SAS; A -> N `Grant` once the
//!    peer's `Confirmed` arrived and its own user confirmed; N -> A `Ack`;
//!    in a public session, N -> A `Audit` events; `End` from either side
//!    closes both.
//!
//! Frames: `aead::seal(subkey, BlobKind::Pairing = 12, Aad {blob_id,
//! vault_id: None, schema: 1}, postcard(Message))`, with the subkey
//! `HKDF-SHA256(salt = empty, ikm = K, info = "a2n")` from A to N and
//! `"n2a"` from N to A, and `blob_id = session_id` with its last 8 bytes
//! XOR the frame counter (u64 big-endian). Each direction counts from 0
//! and the receiver accepts only the next counter: a replayed, reordered,
//! reflected or foreign frame fails, and any failed frame closes the
//! channel. No frame passes after `End`, nor after a public grant's
//! `expires_at`. `Message = Confirmed | Grant(Full | Public) | Ack |
//! Audit | End` (variant indexes 0 to 4).
//!
//! The grant matches the requested mode: a public request gets only a
//! `PublicGrant` (read only, this session's id, not yet expired), a
//! personal or shared request only a `FullGrant` of that same mode, whose
//! snapshot (the `base` rows of the store, `SnapshotRecord {kind: record
//! kind code, id, version, data}`) is at most `MAX_SNAPSHOT_BYTES`
//! serialized. The newcomer imports it later as a remote fetch.

pub mod approver;
pub mod channel;
pub mod messages;
pub mod newcomer;
pub mod qr;
pub mod snapshot;

use aws_lc_rs::digest::{Context, SHA256};
use time::OffsetDateTime;

use crate::crypto::SymmetricKey;
use crate::crypto::key::hkdf32;
use crate::{Error, Result, ValidationError};

pub use approver::Approver;
pub use channel::Channel;
pub use messages::{
    AuditAction, AuditEvent, DeviceInfo, FullGrant, Grant, Hello, KeyExchange, Message,
    PublicGrant, SnapshotRecord,
};
pub use newcomer::Newcomer;
pub use qr::PairingQr;
pub use snapshot::{MAX_SNAPSHOT_BYTES, check_snapshot_size, snapshot_from_store};

/// A QR is valid this long after it is shown (spec 5.1, ruling B16).
pub const QR_LIFETIME_SECS: i64 = 120;

/// How far the approver's clock may lag behind the newcomer's: a QR issued
/// more than this in the approver's future is refused. Five minutes covers
/// the drift of two network-synced clocks with a wide margin while still
/// refusing a QR dated far ahead to outlive its two minutes.
pub const CLOCK_SKEW_SECS: i64 = 300;

/// Largest channel frame (spec 5.5: transport frames are at most 64 MiB).
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// Label of the KEM envelope that carries the session key.
const KEM_LABEL: &[u8] = b"onepass/pairing/v1";
const SAS_INFO: &[u8] = b"onepass/pairing/sas/v1";

/// The short authentication code both screens show: 6 decimal digits,
/// zero padded, from the session key and the transcript.
pub fn sas(k: &SymmetricKey, transcript: &[u8; 32]) -> Result<String> {
    let okm = hkdf32(&[], k.expose(), &[SAS_INFO, transcript])?;
    let mut first = [0u8; 8];
    first.copy_from_slice(&okm.expose()[..8]);
    Ok(format!("{:06}", u64::from_be_bytes(first) % 1_000_000))
}

/// `SHA-256(qr_text || hello)`.
fn transcript(qr_text: &str, hello: &[u8]) -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(qr_text.as_bytes());
    ctx.update(hello);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(aws_lc_rs::digest::digest(&SHA256, bytes).as_ref());
    out
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// A protocol step refused (wrong state, expired, wrong grant).
fn refused(reason: &'static str) -> Error {
    ValidationError {
        field: "pairing".into(),
        reason,
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_is_six_digits_and_zero_padded() {
        // Find a key whose code starts with 0 to see the padding.
        let mut seen_padded = false;
        for i in 0..200u8 {
            let s = sas(&SymmetricKey::from_bytes([i; 32]), &[i; 32]).unwrap();
            assert_eq!(s.len(), 6);
            assert!(s.bytes().all(|c| c.is_ascii_digit()));
            seen_padded |= s.starts_with('0');
        }
        assert!(seen_padded);
    }

    #[test]
    fn sas_matches_the_spec_formula() {
        let k = SymmetricKey::from_bytes([3; 32]);
        let t = [5u8; 32];
        let okm = hkdf32(&[], k.expose(), &[b"onepass/pairing/sas/v1", &t]).unwrap();
        let v = u64::from_be_bytes(okm.expose()[..8].try_into().unwrap()) % 1_000_000;
        assert_eq!(sas(&k, &t).unwrap(), format!("{v:06}"));
    }
}
