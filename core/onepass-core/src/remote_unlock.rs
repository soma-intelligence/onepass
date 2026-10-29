//! Remote unlock envelope and throttle (agent-ready spec 6). The Mac keeps
//! `C`, the AUK sealed under a random key `K_r`; the iPhone keeps `K_r`
//! behind Face ID. Neither half opens the vault alone. This module is the
//! pure crypto and the rate limiter: no I/O, no clock (the caller passes
//! `now`, Unix seconds).
//!
//! `C = seal(K_r, BlobKind::RemoteUnlock, aad, AUK)` with
//! `aad = { blob_id, vault_id: None, schema: 1 }`. The blob id is derived
//! from the two devices, `SHA-256("onepass/remote-unlock/blob-id/v1" || mac
//! || phone)` truncated to 16 bytes, so `open` needs only the two ids and a
//! `C` made for one (Mac, phone) pair opens for no other.

use aws_lc_rs::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account::Auk;
use crate::crypto::{Aad, BlobKind, SymmetricKey, open as aead_open, seal};
use crate::{Error, Id, Result};

/// Window of an agents-only session when nothing else is chosen.
pub const DEFAULT_WINDOW_MINUTES: u32 = 60;
/// Shortest and longest window a user can pick.
pub const MIN_WINDOW_MINUTES: u32 = 15;
pub const MAX_WINDOW_MINUTES: u32 = 480;

/// One unlock request per this many seconds.
pub const REQUEST_INTERVAL_SECS: i64 = 600;
/// Refusals in a row before the phone is left alone.
pub const REFUSALS_BEFORE_BLOCK: u8 = 3;
/// How long the block lasts.
pub const BLOCK_SECS: i64 = 3600;

const SCHEMA: u16 = 1;
const BLOB_ID_DOMAIN: &[u8] = b"onepass/remote-unlock/blob-id/v1";

fn context(mac: Id, phone: Id) -> Aad {
    let mut input = Vec::with_capacity(BLOB_ID_DOMAIN.len() + 32);
    input.extend_from_slice(BLOB_ID_DOMAIN);
    input.extend_from_slice(&mac.0);
    input.extend_from_slice(&phone.0);
    let hash = digest(&SHA256, &input);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash.as_ref()[..16]);
    Aad {
        blob_id: Id(id),
        vault_id: None,
        schema: SCHEMA,
    }
}

/// Seal `auk` under a fresh `K_r` for the pair (`mac`, `phone`). Returns
/// `C` (kept by the Mac) and `K_r` (sent to the phone, then wiped).
pub fn enroll(auk: &Auk, mac: Id, phone: Id) -> Result<(Vec<u8>, SymmetricKey)> {
    let k_r = SymmetricKey::generate()?;
    let c = seal(
        &k_r,
        BlobKind::RemoteUnlock,
        &context(mac, phone),
        auk.as_bytes(),
    )?;
    Ok((c, k_r))
}

/// Open `c` with `k_r`. Fails for any other key, Mac or phone id.
pub fn open(c: &[u8], k_r: &SymmetricKey, mac: Id, phone: Id) -> Result<Auk> {
    let plain = aead_open(k_r, BlobKind::RemoteUnlock, &context(mac, phone), c)?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    if plain.len() != bytes.len() {
        return Err(Error::InvalidFormat("remote unlock envelope"));
    }
    bytes.copy_from_slice(&plain);
    Ok(Auk::from_bytes(*bytes))
}

/// Clamp a requested window to 15 minutes through 8 hours.
pub fn clamp_window_minutes(m: u32) -> u32 {
    m.clamp(MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES)
}

/// Rate limit of unlock requests to one phone: one per 10 minutes, and an
/// hour of silence after three refusals in a row. Persisted by the caller;
/// persisted values are untrusted, so a timestamp from the future (a block
/// further out than an hour, a request later than now) is ignored and never
/// locks anyone out for longer than the rule itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockThrottle {
    last_request: Option<i64>,
    refusals: u8,
    blocked_until: Option<i64>,
}

impl UnlockThrottle {
    pub fn new() -> UnlockThrottle {
        UnlockThrottle::default()
    }

    pub fn may_request(&self, now: i64) -> bool {
        if let Some(until) = self.blocked_until {
            // A genuine block ends at most BLOCK_SECS from now; a stored value
            // further out is corrupt (or the clock went back) and is ignored.
            let left = until.saturating_sub(now);
            if left > 0 && left <= BLOCK_SECS {
                return false;
            }
        }
        if let Some(last) = self.last_request {
            let elapsed = now.saturating_sub(last);
            if (0..REQUEST_INTERVAL_SECS).contains(&elapsed) {
                return false;
            }
        }
        true
    }

    /// A request went out at `now`.
    pub fn requested(&mut self, now: i64) {
        self.last_request = Some(now);
    }

    /// The phone refused (or the request timed out unanswered).
    pub fn refused(&mut self, now: i64) {
        self.refusals = self.refusals.saturating_add(1);
        if self.refusals >= REFUSALS_BEFORE_BLOCK {
            self.refusals = 0;
            self.blocked_until = Some(now.saturating_add(BLOCK_SECS));
        }
    }

    /// The phone approved: the run of refusals is over.
    pub fn approved(&mut self) {
        self.refusals = 0;
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::InvalidFormat("unlock throttle"))
    }

    /// Strict: one encoding, no trailing bytes, no impossible counter.
    pub fn from_bytes(b: &[u8]) -> Result<UnlockThrottle> {
        match postcard::take_from_bytes::<UnlockThrottle>(b) {
            Ok((t, [])) if t.refusals < REFUSALS_BEFORE_BLOCK => Ok(t),
            _ => Err(Error::InvalidFormat("unlock throttle")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auk() -> Auk {
        Auk::from_bytes([0x5a; 32])
    }
    fn ids() -> (Id, Id) {
        (Id([1; 16]), Id([2; 16]))
    }

    #[test]
    fn enroll_open_gives_same_auk() {
        let (m, p) = ids();
        let (c, k) = enroll(&auk(), m, p).unwrap();
        assert_eq!(open(&c, &k, m, p).unwrap().as_bytes(), &[0x5a; 32]);
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let (m, p) = ids();
        let (c, _) = enroll(&auk(), m, p).unwrap();
        let other = SymmetricKey::generate().unwrap();
        assert!(open(&c, &other, m, p).is_err());
    }

    #[test]
    fn open_with_swapped_devices_fails() {
        let (m, p) = ids();
        let (c, k) = enroll(&auk(), m, p).unwrap();
        assert!(open(&c, &k, p, m).is_err());
        assert!(open(&c, &k, m, Id([3; 16])).is_err());
    }

    #[test]
    fn c_alone_reveals_nothing() {
        let (m, p) = ids();
        let (c, k) = enroll(&auk(), m, p).unwrap();
        assert!(!c.windows(32).any(|w| w == [0x5a; 32]));
        assert!(!c.windows(32).any(|w| w == k.expose()));
        assert!(!format!("{:?}", open(&c, &k, m, p).unwrap()).contains("5a"));
    }

    #[test]
    fn truncated_or_wrong_size_plaintext_is_refused() {
        let (m, p) = ids();
        let (c, k) = enroll(&auk(), m, p).unwrap();
        assert!(open(&c[..c.len() - 1], &k, m, p).is_err());
        let short = seal(&k, BlobKind::RemoteUnlock, &context(m, p), &[1; 31]).unwrap();
        assert!(matches!(
            open(&short, &k, m, p),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn throttle_one_per_ten_minutes() {
        let mut t = UnlockThrottle::new();
        assert!(t.may_request(1000));
        t.requested(1000);
        assert!(!t.may_request(1000));
        assert!(!t.may_request(1599));
        assert!(t.may_request(1600));
    }

    #[test]
    fn throttle_blocks_one_hour_after_three_refusals() {
        let mut t = UnlockThrottle::new();
        for i in 0..3 {
            t.requested(1000 + i * 600);
            t.refused(1000 + i * 600);
        }
        let end = 1000 + 2 * 600;
        assert!(!t.may_request(end + 600));
        assert!(!t.may_request(end + 3599));
        assert!(t.may_request(end + 3600));
    }

    #[test]
    fn throttle_approval_resets_refusals() {
        let mut t = UnlockThrottle::new();
        t.refused(0);
        t.refused(1);
        t.approved();
        t.refused(2);
        t.refused(3);
        assert!(t.may_request(10_000));
        t.refused(4);
        assert!(!t.may_request(100));
        assert!(t.may_request(4000));
    }

    #[test]
    fn throttle_roundtrip_and_strict_decoding() {
        let mut t = UnlockThrottle::new();
        t.requested(50);
        t.refused(50);
        let b = t.to_bytes().unwrap();
        assert_eq!(UnlockThrottle::from_bytes(&b).unwrap(), t);
        let mut long = b.clone();
        long.push(0);
        assert!(UnlockThrottle::from_bytes(&long).is_err());
        assert!(UnlockThrottle::from_bytes(&[]).is_err());
        let bad = UnlockThrottle {
            refusals: 3,
            ..UnlockThrottle::new()
        };
        assert!(UnlockThrottle::from_bytes(&bad.to_bytes().unwrap()).is_err());
    }

    #[test]
    fn hostile_values_never_panic_or_lock_forever() {
        let hostile = UnlockThrottle {
            last_request: Some(i64::MAX),
            refusals: 2,
            blocked_until: Some(i64::MAX),
        };
        for now in [i64::MIN, 0, 1_000, i64::MAX] {
            let _ = hostile.may_request(now);
        }
        let mut t = hostile;
        t.requested(i64::MAX);
        t.refused(i64::MAX);
        t.refused(i64::MIN);
        assert!(t.may_request(0));
        let past = UnlockThrottle {
            last_request: Some(i64::MIN),
            refusals: 0,
            blocked_until: Some(i64::MIN),
        };
        assert!(past.may_request(0));
    }

    #[test]
    fn window_clamped() {
        assert_eq!(clamp_window_minutes(0), 15);
        assert_eq!(clamp_window_minutes(14), 15);
        assert_eq!(clamp_window_minutes(60), 60);
        assert_eq!(clamp_window_minutes(480), 480);
        assert_eq!(clamp_window_minutes(u32::MAX), 480);
        assert_eq!(DEFAULT_WINDOW_MINUTES, 60);
    }
}
