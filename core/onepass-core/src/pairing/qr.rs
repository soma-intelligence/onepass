//! The QR the newcomer shows: a commitment to its ephemeral key, never the
//! key itself, and no URL (spec 5.1, ruling B11).

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Prefix of every pairing QR text.
pub const QR_PREFIX: &str = "OPPAIR1:";
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
        let body = self.encode();
        let mut out = String::with_capacity(QR_PREFIX.len() + BASE32_NOPAD.encode_len(body.len()));
        out.push_str(QR_PREFIX);
        BASE32_NOPAD.encode_append(&body, &mut out);
        out
    }

    /// The postcard encoding, written by hand so `to_text` cannot fail:
    /// version, the two arrays raw, then `expires_at` as a zigzag varint.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 16 + 32 + 10);
        out.push(self.version);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.key_hash);
        let mut z = ((self.expires_at << 1) ^ (self.expires_at >> 63)) as u64;
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

    /// Parse a scanned QR text. Only the exact canonical text of a version 1
    /// QR is accepted: no case change, padding, whitespace or trailing data,
    /// so both sides hash the same bytes into the transcript.
    pub fn parse(text: &str) -> Result<PairingQr> {
        const BAD: Error = Error::InvalidFormat("pairing qr");
        if text.len() > MAX_QR_TEXT {
            return Err(BAD);
        }
        let body = text.strip_prefix(QR_PREFIX).ok_or(BAD)?;
        let bytes = BASE32_NOPAD.decode(body.as_bytes()).map_err(|_| BAD)?;
        let (qr, rest): (PairingQr, _) = postcard::take_from_bytes(&bytes).map_err(|_| BAD)?;
        if !rest.is_empty() || qr.version != QR_VERSION || qr.to_text() != text {
            return Err(BAD);
        }
        Ok(qr)
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
}
