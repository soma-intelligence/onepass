//! Pairing with committed numeric comparison (spec 6.4).
//!
//! E commits to its ephemeral public key and nonce before seeing the host's,
//! both sides derive a six digit code from the transcript, the user compares
//! the two screens, then each side proves knowledge of the confirmation key.
//! Any failure or a deadline of 120 s since the start wipes the state; the
//! host only yields a `PairingRecord` after a valid extension MAC.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest;
use zeroize::Zeroizing;

use crate::kdf::{hmac, sas, try_expand, verify_hmac};
use crate::kem::{self, CT_LEN, KemPublic, KemSecret};
use crate::transcript::{TRANSCRIPT_LABEL, Transcript};
use crate::wire::{B64, PairConfirm, PairDone, PairHello, PairOffer, PairReveal};
use crate::{BridgeError, Result};

/// Pairing deadline, counted from the host's `start` (or the extension's).
pub const PAIRING_TIMEOUT_SECS: u64 = 120;
/// Longest accepted `ext_name` or `browser`, in bytes.
pub const MAX_NAME_LEN: usize = 128;

const COMMIT_LABEL: &[u8] = b"onepass/bridge/commit/v1";
const SAS_LABEL: &str = "onepass/bridge/sas/v1";
const PAIRING_KEY_LABEL: &str = "onepass/bridge/pairing-key/v1";
const CONFIRM_LABEL: &str = "onepass/bridge/pair-confirm/v1";
const ROLE_HOST: &[u8] = b"host";
const ROLE_EXT: &[u8] = b"ext";

/// Six digit comparison code, formatted `"123 456"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sas(pub String);

/// A completed pairing, stored by both sides.
#[derive(Clone)]
pub struct PairingRecord {
    pub pairing_id: [u8; 16],
    pub key: Zeroizing<[u8; 32]>,
    pub ext_name: String,
    pub browser: String,
    pub created_at: u64,
}

impl std::fmt::Debug for PairingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingRecord")
            .field("pairing_id", &self.pairing_id)
            .field("key", &"**")
            .field("ext_name", &self.ext_name)
            .field("browser", &self.browser)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Keys derived once the transcript is complete.
struct Keys {
    t: [u8; 32],
    pairing_key: Zeroizing<[u8; 32]>,
    confirm: Zeroizing<[u8; 32]>,
}

/// Intermediate values of a pairing, for cross-language test vectors only.
#[cfg(any(test, feature = "vectors"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorKeys {
    pub transcript_hash: [u8; 32],
    pub pairing_key: [u8; 32],
    pub confirm_key: [u8; 32],
}

#[cfg(any(test, feature = "vectors"))]
impl Keys {
    fn vector_keys(&self) -> VectorKeys {
        VectorKeys {
            transcript_hash: self.t,
            pairing_key: *self.pairing_key,
            confirm_key: *self.confirm,
        }
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| BridgeError::Crypto)?;
    Ok(b)
}

/// `SHA-256("onepass/bridge/commit/v1" || pk_E || n_E)`.
fn commitment(pk_e: &[u8], n_e: &[u8; 32]) -> [u8; 32] {
    let mut h = digest::Context::new(&digest::SHA256);
    h.update(COMMIT_LABEL);
    h.update(pk_e);
    h.update(n_e);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finish().as_ref());
    out
}

fn check_name(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > MAX_NAME_LEN || s.chars().any(char::is_control) {
        return Err(BridgeError::BadFrame("pairing name"));
    }
    Ok(())
}

/// Transcript of spec 6.4 step 4, in that exact order.
struct TranscriptInput<'a> {
    ext_name: &'a str,
    browser: &'a str,
    commit: &'a [u8; 32],
    pairing_id: &'a [u8; 16],
    pk_h: &'a [u8],
    n_h: &'a [u8; 32],
    pk_e: &'a [u8],
    n_e: &'a [u8; 32],
    ct_e: &'a [u8; CT_LEN],
}

fn derive(input: &TranscriptInput<'_>, ss: &[u8; 32]) -> Result<(Sas, Keys)> {
    let mut tr = Transcript::new(TRANSCRIPT_LABEL);
    tr.push(input.ext_name.as_bytes());
    tr.push(input.browser.as_bytes());
    tr.push(input.commit);
    tr.push(input.pairing_id);
    tr.push(input.pk_h);
    tr.push(input.n_h);
    tr.push(input.pk_e);
    tr.push(input.n_e);
    tr.push(input.ct_e);
    let t = tr.hash();
    let code = sas(&*try_expand(&t, ss, SAS_LABEL)?);
    let keys = Keys {
        t,
        pairing_key: try_expand(&t, ss, PAIRING_KEY_LABEL)?,
        confirm: try_expand(&t, ss, CONFIRM_LABEL)?,
    };
    Ok((Sas(code), keys))
}

fn expired(started: u64, now: u64) -> bool {
    now.saturating_sub(started) > PAIRING_TIMEOUT_SECS
}

enum HostState {
    AwaitReveal {
        sk: Box<KemSecret>,
        n_h: [u8; 32],
    },
    AwaitApproval(Keys),
    AwaitConfirm(Keys),
    /// Wiped after an error, a timeout or completion.
    Closed,
}

/// Host (app) side of a pairing.
pub struct HostPairing {
    started: u64,
    pairing_id: [u8; 16],
    ext_name: String,
    browser: String,
    commit: [u8; 32],
    state: HostState,
}

impl HostPairing {
    /// Handle `pair_hello`: draw an ephemeral key pair, a nonce and a
    /// pairing id, answer `pair_offer`.
    pub fn start(hello: PairHello, now: u64) -> Result<(HostPairing, PairOffer)> {
        Self::start_with(hello, now, random()?, KemSecret::generate()?, random()?)
    }

    /// `start` with fixed randomness, for test vectors only.
    #[cfg(any(test, feature = "vectors"))]
    pub fn start_deterministic(
        hello: PairHello,
        now: u64,
        pairing_id: [u8; 16],
        sk: KemSecret,
        n_h: [u8; 32],
    ) -> Result<(HostPairing, PairOffer)> {
        Self::start_with(hello, now, pairing_id, sk, n_h)
    }

    fn start_with(
        hello: PairHello,
        now: u64,
        pairing_id: [u8; 16],
        sk: KemSecret,
        n_h: [u8; 32],
    ) -> Result<(HostPairing, PairOffer)> {
        check_name(&hello.ext_name)?;
        check_name(&hello.browser)?;
        let offer = PairOffer {
            pairing_id: B64(pairing_id),
            pk: B64(sk.public().to_bytes()),
            n: B64(n_h),
        };
        let host = HostPairing {
            started: now,
            pairing_id,
            ext_name: hello.ext_name,
            browser: hello.browser,
            commit: hello.commit.0,
            state: HostState::AwaitReveal {
                sk: Box::new(sk),
                n_h,
            },
        };
        Ok((host, offer))
    }

    /// Derived values once the code is known, for test vectors only.
    #[cfg(any(test, feature = "vectors"))]
    pub fn vector_keys(&self) -> Option<VectorKeys> {
        match &self.state {
            HostState::AwaitApproval(k) | HostState::AwaitConfirm(k) => Some(k.vector_keys()),
            _ => None,
        }
    }

    /// Take the state, leaving `Closed`: any early return wipes it.
    fn take(&mut self, now: u64) -> Result<HostState> {
        let state = std::mem::replace(&mut self.state, HostState::Closed);
        if expired(self.started, now) {
            return Err(BridgeError::Expired);
        }
        Ok(state)
    }

    /// Handle `pair_reveal`: check the commitment, decapsulate, derive the
    /// code to show. The caller then sends `pair_sas`.
    pub fn on_reveal(&mut self, reveal: PairReveal, now: u64) -> Result<Sas> {
        let HostState::AwaitReveal { sk, n_h } = self.take(now)? else {
            return Err(BridgeError::BadFrame("unexpected pair_reveal"));
        };
        let want = commitment(&reveal.pk.0, &reveal.n.0);
        if verify_slices_are_equal(&want, &self.commit).is_err() {
            return Err(BridgeError::BadMac);
        }
        KemPublic::from_bytes(&reveal.pk.0)?;
        let ss = sk.decapsulate(&reveal.ct.0)?;
        let (code, keys) = derive(
            &TranscriptInput {
                ext_name: &self.ext_name,
                browser: &self.browser,
                commit: &self.commit,
                pairing_id: &self.pairing_id,
                pk_h: &sk.public().to_bytes(),
                n_h: &n_h,
                pk_e: &reveal.pk.0,
                n_e: &reveal.n.0,
                ct_e: &reveal.ct.0,
            },
            &ss,
        )?;
        self.state = HostState::AwaitApproval(keys);
        Ok(code)
    }

    /// The user approved in the app: answer `pair_done`.
    pub fn approve(&mut self, now: u64) -> Result<PairDone> {
        let HostState::AwaitApproval(keys) = self.take(now)? else {
            return Err(BridgeError::BadFrame("nothing to approve"));
        };
        let mac = hmac(&keys.confirm, ROLE_HOST, &keys.t);
        self.state = HostState::AwaitConfirm(keys);
        Ok(PairDone { mac: B64(mac) })
    }

    /// Handle `pair_confirm`: the record to store, then send `pair_ok`.
    pub fn on_confirm(mut self, confirm: PairConfirm, now: u64) -> Result<PairingRecord> {
        let HostState::AwaitConfirm(keys) = self.take(now)? else {
            return Err(BridgeError::BadFrame("unexpected pair_confirm"));
        };
        if !verify_hmac(&keys.confirm, ROLE_EXT, &keys.t, &confirm.mac.0) {
            return Err(BridgeError::BadMac);
        }
        Ok(PairingRecord {
            pairing_id: self.pairing_id,
            key: keys.pairing_key,
            ext_name: std::mem::take(&mut self.ext_name),
            browser: std::mem::take(&mut self.browser),
            created_at: now,
        })
    }
}

enum ExtState {
    AwaitOffer { sk: Box<KemSecret>, n_e: [u8; 32] },
    AwaitDone { pairing_id: [u8; 16], keys: Keys },
    Verified { pairing_id: [u8; 16], keys: Keys },
    Closed,
}

/// Extension side of a pairing (used by tests, vectors and the TypeScript
/// client as reference).
pub struct ExtPairing {
    started: u64,
    ext_name: String,
    browser: String,
    commit: [u8; 32],
    state: ExtState,
}

impl ExtPairing {
    /// Draw an ephemeral key pair and nonce, commit to them: `pair_hello`.
    pub fn start(ext_name: &str, browser: &str, now: u64) -> Result<(ExtPairing, PairHello)> {
        Self::start_with(ext_name, browser, now, KemSecret::generate()?, random()?)
    }

    /// `start` with fixed randomness, for test vectors only.
    #[cfg(any(test, feature = "vectors"))]
    pub fn start_deterministic(
        ext_name: &str,
        browser: &str,
        now: u64,
        sk: KemSecret,
        n_e: [u8; 32],
    ) -> Result<(ExtPairing, PairHello)> {
        Self::start_with(ext_name, browser, now, sk, n_e)
    }

    fn start_with(
        ext_name: &str,
        browser: &str,
        now: u64,
        sk: KemSecret,
        n_e: [u8; 32],
    ) -> Result<(ExtPairing, PairHello)> {
        check_name(ext_name)?;
        check_name(browser)?;
        let commit = commitment(&sk.public().to_bytes(), &n_e);
        let hello = PairHello {
            commit: B64(commit),
            ext_name: ext_name.to_owned(),
            browser: browser.to_owned(),
        };
        let ext = ExtPairing {
            started: now,
            ext_name: ext_name.to_owned(),
            browser: browser.to_owned(),
            commit,
            state: ExtState::AwaitOffer {
                sk: Box::new(sk),
                n_e,
            },
        };
        Ok((ext, hello))
    }

    /// Derived values once the code is known, for test vectors only.
    #[cfg(any(test, feature = "vectors"))]
    pub fn vector_keys(&self) -> Option<VectorKeys> {
        match &self.state {
            ExtState::AwaitDone { keys, .. } | ExtState::Verified { keys, .. } => {
                Some(keys.vector_keys())
            }
            _ => None,
        }
    }

    fn take(&mut self, now: u64) -> Result<ExtState> {
        let state = std::mem::replace(&mut self.state, ExtState::Closed);
        if expired(self.started, now) {
            return Err(BridgeError::Expired);
        }
        Ok(state)
    }

    /// Handle `pair_offer`: encapsulate to the host key, reveal, and the
    /// code to show.
    pub fn on_offer(&mut self, offer: PairOffer) -> Result<(PairReveal, Sas)> {
        self.offer_with(offer, kem::encapsulate)
    }

    /// `on_offer` with fixed encapsulation randomness, for test vectors only.
    #[cfg(any(test, feature = "vectors"))]
    pub fn on_offer_deterministic(
        &mut self,
        offer: PairOffer,
        mlkem_seed: &[u8; 32],
        x25519_eph: &[u8; 32],
    ) -> Result<(PairReveal, Sas)> {
        self.offer_with(offer, |pk| {
            kem::encapsulate_deterministic(pk, mlkem_seed, x25519_eph)
        })
    }

    fn offer_with(
        &mut self,
        offer: PairOffer,
        encaps: impl FnOnce(&KemPublic) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>)>,
    ) -> Result<(PairReveal, Sas)> {
        let ExtState::AwaitOffer { sk, n_e } = std::mem::replace(&mut self.state, ExtState::Closed)
        else {
            return Err(BridgeError::BadFrame("unexpected pair_offer"));
        };
        let pk_h = KemPublic::from_bytes(&offer.pk.0)?;
        let (ct, ss) = encaps(&pk_h)?;
        let pk_e = sk.public().to_bytes();
        let (code, keys) = derive(
            &TranscriptInput {
                ext_name: &self.ext_name,
                browser: &self.browser,
                commit: &self.commit,
                pairing_id: &offer.pairing_id.0,
                pk_h: &offer.pk.0,
                n_h: &offer.n.0,
                pk_e: &pk_e,
                n_e: &n_e,
                ct_e: &ct,
            },
            &ss,
        )?;
        self.state = ExtState::AwaitDone {
            pairing_id: offer.pairing_id.0,
            keys,
        };
        let reveal = PairReveal {
            pk: B64(pk_e),
            n: B64(n_e),
            ct: B64(ct),
        };
        Ok((reveal, Sas(code.0)))
    }

    /// Handle `pair_done`: check the host MAC.
    pub fn on_done(&mut self, done: PairDone, now: u64) -> Result<()> {
        let ExtState::AwaitDone { pairing_id, keys } = self.take(now)? else {
            return Err(BridgeError::BadFrame("unexpected pair_done"));
        };
        if !verify_hmac(&keys.confirm, ROLE_HOST, &keys.t, &done.mac.0) {
            return Err(BridgeError::BadMac);
        }
        self.state = ExtState::Verified { pairing_id, keys };
        Ok(())
    }

    /// The user confirmed the codes match: `pair_confirm` and the record.
    pub fn confirm(mut self, now: u64) -> Result<(PairConfirm, PairingRecord)> {
        let ExtState::Verified { pairing_id, keys } = self.take(now)? else {
            return Err(BridgeError::BadFrame("pairing not verified"));
        };
        let mac = hmac(&keys.confirm, ROLE_EXT, &keys.t);
        let record = PairingRecord {
            pairing_id,
            key: keys.pairing_key,
            ext_name: std::mem::take(&mut self.ext_name),
            browser: std::mem::take(&mut self.browser),
            created_at: now,
        };
        Ok((PairConfirm { mac: B64(mac) }, record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_pairing_is_reproducible() {
        let run = || {
            let sk_e = KemSecret::from_seeds(&[1u8; 64], &[2u8; 32]).unwrap();
            let sk_h = KemSecret::from_seeds(&[3u8; 64], &[4u8; 32]).unwrap();
            let (mut e, hello) =
                ExtPairing::start_deterministic("OnePass", "Chromium", 0, sk_e, [5u8; 32]).unwrap();
            let (mut h, offer) =
                HostPairing::start_deterministic(hello, 0, [6u8; 16], sk_h, [7u8; 32]).unwrap();
            let (reveal, sas_e) = e
                .on_offer_deterministic(offer, &[8u8; 32], &[9u8; 32])
                .unwrap();
            let sas_h = h.on_reveal(reveal, 0).unwrap();
            assert_eq!(sas_e, sas_h);
            let done = h.approve(0).unwrap();
            e.on_done(done.clone(), 0).unwrap();
            let (confirm, rec) = e.confirm(0).unwrap();
            h.on_confirm(confirm.clone(), 0).unwrap();
            (sas_e, done, confirm, rec.key)
        };
        let a = run();
        let b = run();
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
        assert_eq!(a.2, b.2);
        assert_eq!(*a.3, *b.3);
    }

    #[test]
    fn commitment_is_raw_concatenation() {
        let pk = [0xABu8; 1600];
        let n = [0xCDu8; 32];
        let mut raw = COMMIT_LABEL.to_vec();
        raw.extend_from_slice(&pk);
        raw.extend_from_slice(&n);
        let want = digest::digest(&digest::SHA256, &raw);
        assert_eq!(commitment(&pk, &n).as_slice(), want.as_ref());
    }
}
