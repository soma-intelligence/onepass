//! The QR the newcomer shows: a commitment to its ephemeral key, never the
//! key itself, and no URL (spec 5.1, ruling B11). And the invite QR the
//! approver shows in the other direction (`invite`): the same layout under
//! another prefix, a one-time secret in place of the key hash.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Error, Result};

/// Prefix of every pairing QR text.
pub const QR_PREFIX: &str = "OPPAIR1:";
/// Prefix of every invite QR text.
pub const INVITE_PREFIX: &str = "OPJOIN1:";
/// The only QR version.
pub const QR_VERSION: u8 = 1;
/// Longest QR text accepted (a real one is about 95 characters).
const MAX_QR_TEXT: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingQr {
    pub version: u8,
    pub session_id: [u8; 16],
    /// SHA-256 of the ephemeral public key (`HybridKemPublic::to_bytes`).
    pub key_hash: [u8; 32],
    pub expires_at: i64,
}

impl PairingQr {
    /// `"OPPAIR1:" || BASE32(postcard(self))`, upper case, no padding.
    pub fn to_text(&self) -> String {
        to_text(
            QR_PREFIX,
            &encode(
                self.version,
                &self.session_id,
                &self.key_hash,
                self.expires_at,
            ),
        )
    }

    #[cfg(test)]
    fn encode(&self) -> Vec<u8> {
        encode(
            self.version,
            &self.session_id,
            &self.key_hash,
            self.expires_at,
        )
    }

    /// Parse a scanned QR text. Only the exact canonical text of a version 1
    /// QR is accepted: no case change, padding, whitespace or trailing data,
    /// so both sides hash the same bytes into the transcript.
    pub fn parse(text: &str) -> Result<PairingQr> {
        let qr: PairingQr = parse(QR_PREFIX, text, Error::InvalidFormat("pairing qr"))?;
        if qr.version != QR_VERSION || qr.to_text() != text {
            return Err(Error::InvalidFormat("pairing qr"));
        }
        Ok(qr)
    }
}

/// The QR the approver shows when the new device scans (`invite`):
/// `"OPJOIN1:" || BASE32(postcard(self))`, the layout of `PairingQr` with a
/// fresh 32-byte secret where the key hash was. Only someone who read the
/// screen knows the secret: it signs the Hello and enters the transcript.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteQr {
    pub version: u8,
    pub session_id: [u8; 16],
    pub secret: [u8; 32],
    pub expires_at: i64,
}

impl InviteQr {
    pub fn to_text(&self) -> String {
        let mut body = encode(
            self.version,
            &self.session_id,
            &self.secret,
            self.expires_at,
        );
        let text = to_text(INVITE_PREFIX, &body);
        body.zeroize();
        text
    }

    /// Parse a scanned invite: the canonical text of a version 1 invite only.
    pub fn parse(text: &str) -> Result<InviteQr> {
        let qr: InviteQr = parse(INVITE_PREFIX, text, Error::InvalidFormat("invite qr"))?;
        if qr.version != QR_VERSION || qr.to_text() != text {
            return Err(Error::InvalidFormat("invite qr"));
        }
        Ok(qr)
    }
}

impl Drop for InviteQr {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for InviteQr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteQr")
            .field("version", &self.version)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

fn to_text(prefix: &str, body: &[u8]) -> String {
    let mut out = String::with_capacity(prefix.len() + BASE32_NOPAD.encode_len(body.len()));
    out.push_str(prefix);
    BASE32_NOPAD.encode_append(body, &mut out);
    out
}

/// The postcard encoding, written by hand so `to_text` cannot fail:
/// version, the two arrays raw, then `expires_at` as a zigzag varint.
fn encode(version: u8, session_id: &[u8; 16], field: &[u8; 32], expires_at: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 32 + 10);
    out.push(version);
    out.extend_from_slice(session_id);
    out.extend_from_slice(field);
    let mut z = ((expires_at << 1) ^ (expires_at >> 63)) as u64;
    loop {
        let byte = (z & 0x7f) as u8;
        z >>= 7;
        if z == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out
}

fn parse<T: for<'de> Deserialize<'de>>(prefix: &str, text: &str, bad: Error) -> Result<T> {
    if text.len() > MAX_QR_TEXT {
        return Err(bad);
    }
    let Some(body) = text.strip_prefix(prefix) else {
        return Err(bad);
    };
    let Ok(mut bytes) = BASE32_NOPAD.decode(body.as_bytes()) else {
        return Err(bad);
    };
    let parsed = postcard::take_from_bytes::<T>(&bytes).map(|(v, rest)| (v, rest.is_empty()));
    bytes.zeroize();
    match parsed {
        Ok((v, true)) => Ok(v),
        _ => Err(bad),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hand_encoding_is_postcard() {
        for expires_at in [0, 1, -1, 127, 128, 1_790_000_000, i64::MAX, i64::MIN] {
            let qr = PairingQr {
                version: 1,
                session_id: [9; 16],
                key_hash: [8; 32],
                expires_at,
            };
            assert_eq!(qr.encode(), postcard::to_allocvec(&qr).unwrap());
            assert_eq!(PairingQr::parse(&qr.to_text()).unwrap(), qr);
        }
    }

    #[test]
    fn real_size_is_small() {
        let qr = PairingQr {
            version: 1,
            session_id: [0xff; 16],
            key_hash: [0xff; 32],
            expires_at: i64::MAX,
        };
        assert!(qr.to_text().len() <= 110, "{}", qr.to_text().len());
    }

    #[test]
    fn invite_round_trips_and_keeps_its_secret_out_of_debug() {
        let invite = InviteQr {
            version: 1,
            session_id: [7; 16],
            secret: [0xab; 32],
            expires_at: 1_790_000_120,
        };
        let text = invite.to_text();
        assert!(text.starts_with(INVITE_PREFIX));
        assert_eq!(InviteQr::parse(&text).unwrap(), invite);
        assert!(!format!("{invite:?}").contains("171"), "secret in Debug");
        assert!(text.len() <= 110);
    }

    #[test]
    fn the_two_qr_kinds_never_parse_as_each_other() {
        let pairing = PairingQr {
            version: 1,
            session_id: [1; 16],
            key_hash: [2; 32],
            expires_at: 5,
        };
        let invite = InviteQr {
            version: 1,
            session_id: [1; 16],
            secret: [2; 32],
            expires_at: 5,
        };
        assert!(InviteQr::parse(&pairing.to_text()).is_err());
        assert!(PairingQr::parse(&invite.to_text()).is_err());
    }

    #[test]
    fn a_non_canonical_invite_is_refused() {
        let invite = InviteQr {
            version: 1,
            session_id: [3; 16],
            secret: [4; 32],
            expires_at: 9,
        };
        let text = invite.to_text();
        assert!(InviteQr::parse(&text.to_lowercase()).is_err());
        assert!(InviteQr::parse(&format!("{text} ")).is_err());
        assert!(InviteQr::parse(&format!("{text}AA")).is_err());
        let v2 = InviteQr {
            version: 2,
            session_id: [3; 16],
            secret: [4; 32],
            expires_at: 9,
        };
        assert!(InviteQr::parse(&v2.to_text()).is_err());
    }
}
