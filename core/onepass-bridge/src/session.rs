//! Session handshake (spec 6.5): mutual authentication through the pairing
//! key, forward secrecy through an ephemeral hybrid KEM.
//!
//! `T = H(pairing_id, pk_e, n_e, ct, n_h, session_id)`; keys are
//! `HKDF(salt = T, ikm = ss_e || PK)` expanded with the e2h, h2e and
//! confirm labels. The host proves itself in `welcome`, the extension in
//! `finish`; the host builds its channel only after a valid `finish`.

use zeroize::Zeroizing;

use crate::channel::{Channel, Role};
use crate::kdf::{hmac, try_expand, verify_hmac};
use crate::kem::{self, CT_LEN, KemPublic, KemSecret};
use crate::pairing::PairingRecord;
use crate::transcript::{TRANSCRIPT_LABEL, Transcript};
use crate::wire::{B64, Finish, Hello, Welcome};
use crate::{BridgeError, Result};

const E2H_LABEL: &str = "onepass/bridge/session/e2h/v1";
const H2E_LABEL: &str = "onepass/bridge/session/h2e/v1";
const CONFIRM_LABEL: &str = "onepass/bridge/session/confirm/v1";
const ROLE_HOST: &[u8] = b"host";
const ROLE_EXT: &[u8] = b"ext";

struct SessionKeys {
    t: [u8; 32],
    e2h: Zeroizing<[u8; 32]>,
    h2e: Zeroizing<[u8; 32]>,
    confirm: Zeroizing<[u8; 32]>,
}

struct TranscriptInput<'a> {
    pairing_id: &'a [u8; 16],
    pk_e: &'a [u8],
    n_e: &'a [u8; 32],
    ct: &'a [u8; CT_LEN],
    n_h: &'a [u8; 32],
    session_id: &'a [u8; 16],
}

fn derive(
    input: &TranscriptInput<'_>,
    ss_e: &[u8; 32],
    pairing_key: &[u8; 32],
) -> Result<SessionKeys> {
    let mut tr = Transcript::new(TRANSCRIPT_LABEL);
    tr.push(input.pairing_id);
    tr.push(input.pk_e);
    tr.push(input.n_e);
    tr.push(input.ct);
    tr.push(input.n_h);
    tr.push(input.session_id);
    let t = tr.hash();
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_e);
    ikm[32..].copy_from_slice(pairing_key);
    Ok(SessionKeys {
        t,
        e2h: try_expand(&t, &*ikm, E2H_LABEL)?,
        h2e: try_expand(&t, &*ikm, H2E_LABEL)?,
        confirm: try_expand(&t, &*ikm, CONFIRM_LABEL)?,
    })
}

/// Intermediate values of a session handshake, for test vectors only.
#[cfg(any(test, feature = "vectors"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorKeys {
    pub transcript_hash: [u8; 32],
    pub key_e2h: [u8; 32],
    pub key_h2e: [u8; 32],
    pub key_confirm: [u8; 32],
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| BridgeError::Crypto)?;
    Ok(b)
}

/// Salt of the username hashes of one bridge session (spec 9): a hash
/// made in one session says nothing in the next. Wiped on drop.
pub struct UsernameSalt(Zeroizing<[u8; 32]>);

impl UsernameSalt {
    /// 32 fresh random bytes.
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(random()?)))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex, as `fill_salt` gives it.
    pub fn hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&*self.0)
    }
}

/// Host side after `welcome`, waiting for `finish`.
pub struct PendingSession {
    session_id: [u8; 16],
    keys: SessionKeys,
}

/// Handle `hello`: look the pairing up (`UnknownPairing` if absent),
/// encapsulate to the extension's ephemeral key, answer `welcome`.
pub fn host_accept(
    hello: Hello,
    lookup: impl Fn(&[u8; 16]) -> Option<Zeroizing<[u8; 32]>>,
) -> Result<(PendingSession, Welcome)> {
    accept_with(hello, lookup, kem::encapsulate, random()?, random()?)
}

/// `host_accept` with fixed randomness, for test vectors only.
#[cfg(any(test, feature = "vectors"))]
pub fn host_accept_deterministic(
    hello: Hello,
    lookup: impl Fn(&[u8; 16]) -> Option<Zeroizing<[u8; 32]>>,
    mlkem_seed: &[u8; 32],
    x25519_eph: &[u8; 32],
    n_h: [u8; 32],
    session_id: [u8; 16],
) -> Result<(PendingSession, Welcome)> {
    accept_with(
        hello,
        lookup,
        |pk| kem::encapsulate_deterministic(pk, mlkem_seed, x25519_eph),
        n_h,
        session_id,
    )
}

fn accept_with(
    hello: Hello,
    lookup: impl Fn(&[u8; 16]) -> Option<Zeroizing<[u8; 32]>>,
    encaps: impl FnOnce(&KemPublic) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>)>,
    n_h: [u8; 32],
    session_id: [u8; 16],
) -> Result<(PendingSession, Welcome)> {
    let pairing_key = lookup(&hello.pairing_id.0).ok_or(BridgeError::UnknownPairing)?;
    let pk_e = KemPublic::from_bytes(&hello.pk.0)?;
    let (ct, ss_e) = encaps(&pk_e)?;
    let keys = derive(
        &TranscriptInput {
            pairing_id: &hello.pairing_id.0,
            pk_e: &hello.pk.0,
            n_e: &hello.n.0,
            ct: &ct,
            n_h: &n_h,
            session_id: &session_id,
        },
        &ss_e,
        &pairing_key,
    )?;
    let mac = hmac(&keys.confirm, ROLE_HOST, &keys.t);
    let welcome = Welcome {
        ct: B64(ct),
        n: B64(n_h),
        session_id: B64(session_id),
        mac: B64(mac),
    };
    Ok((PendingSession { session_id, keys }, welcome))
}

impl PendingSession {
    /// Derived values, for test vectors only.
    #[cfg(any(test, feature = "vectors"))]
    pub fn vector_keys(&self) -> VectorKeys {
        VectorKeys {
            transcript_hash: self.keys.t,
            key_e2h: *self.keys.e2h,
            key_h2e: *self.keys.h2e,
            key_confirm: *self.keys.confirm,
        }
    }

    /// Handle `finish`: verify the extension MAC, open the channel. `now`
    /// starts the idle timer.
    pub fn on_finish(self, finish: Finish, now: u64) -> Result<Channel> {
        if !verify_hmac(&self.keys.confirm, ROLE_EXT, &self.keys.t, &finish.mac.0) {
            return Err(BridgeError::BadMac);
        }
        Channel::new(
            Role::Host,
            self.session_id,
            &self.keys.e2h,
            &self.keys.h2e,
            now,
        )
    }
}

/// Extension side after `hello`, waiting for `welcome`.
pub struct ExtPending {
    pairing_id: [u8; 16],
    pairing_key: Zeroizing<[u8; 32]>,
    sk: Box<KemSecret>,
    n_e: [u8; 32],
}

/// Open a session for a stored pairing: `hello`.
pub fn ext_hello(pairing: &PairingRecord) -> Result<(ExtPending, Hello)> {
    hello_with(pairing, KemSecret::generate()?, random()?)
}

/// `ext_hello` with fixed randomness, for test vectors only.
#[cfg(any(test, feature = "vectors"))]
pub fn ext_hello_deterministic(
    pairing: &PairingRecord,
    sk: KemSecret,
    n_e: [u8; 32],
) -> Result<(ExtPending, Hello)> {
    hello_with(pairing, sk, n_e)
}

fn hello_with(
    pairing: &PairingRecord,
    sk: KemSecret,
    n_e: [u8; 32],
) -> Result<(ExtPending, Hello)> {
    let hello = Hello {
        pairing_id: B64(pairing.pairing_id),
        pk: B64(sk.public().to_bytes()),
        n: B64(n_e),
    };
    let pending = ExtPending {
        pairing_id: pairing.pairing_id,
        pairing_key: pairing.key.clone(),
        sk: Box::new(sk),
        n_e,
    };
    Ok((pending, hello))
}

impl ExtPending {
    /// Handle `welcome`: decapsulate, derive, verify the host MAC in
    /// constant time, answer `finish` with the open channel.
    pub fn on_welcome(self, welcome: Welcome, now: u64) -> Result<(Channel, Finish)> {
        let ss_e = self.sk.decapsulate(&welcome.ct.0)?;
        let keys = derive(
            &TranscriptInput {
                pairing_id: &self.pairing_id,
                pk_e: &self.sk.public().to_bytes(),
                n_e: &self.n_e,
                ct: &welcome.ct.0,
                n_h: &welcome.n.0,
                session_id: &welcome.session_id.0,
            },
            &ss_e,
            &self.pairing_key,
        )?;
        if !verify_hmac(&keys.confirm, ROLE_HOST, &keys.t, &welcome.mac.0) {
            return Err(BridgeError::BadMac);
        }
        let mac = hmac(&keys.confirm, ROLE_EXT, &keys.t);
        let channel = Channel::new(Role::Ext, welcome.session_id.0, &keys.e2h, &keys.h2e, now)?;
        Ok((channel, Finish { mac: B64(mac) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Envelope;

    fn record() -> PairingRecord {
        PairingRecord {
            pairing_id: [1u8; 16],
            key: Zeroizing::new([2u8; 32]),
            ext_name: "OnePass".into(),
            browser: "Chromium".into(),
            created_at: 0,
        }
    }

    #[test]
    fn deterministic_session_is_reproducible() {
        let run = || {
            let sk = KemSecret::from_seeds(&[3u8; 64], &[4u8; 32]).unwrap();
            let (ext, hello) = ext_hello_deterministic(&record(), sk, [5u8; 32]).unwrap();
            let (pending, welcome) = host_accept_deterministic(
                hello,
                |_| Some(Zeroizing::new([2u8; 32])),
                &[6u8; 32],
                &[7u8; 32],
                [8u8; 32],
                [9u8; 16],
            )
            .unwrap();
            let (mut ext_ch, finish) = ext.on_welcome(welcome.clone(), 0).unwrap();
            let _host = pending.on_finish(finish.clone(), 0).unwrap();
            let frame = ext_ch.seal(b"{\"id\":1,\"op\":\"status\"}").unwrap();
            (welcome, finish, frame)
        };
        let a = run();
        let b = run();
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
        assert_eq!(a.2, b.2);
        assert!(matches!(a.2, Envelope::Msg(_)));
    }

    #[test]
    fn keys_are_label_separated() {
        let input = TranscriptInput {
            pairing_id: &[1u8; 16],
            pk_e: &[2u8; 1600],
            n_e: &[3u8; 32],
            ct: &[4u8; CT_LEN],
            n_h: &[5u8; 32],
            session_id: &[6u8; 16],
        };
        let k = derive(&input, &[7u8; 32], &[8u8; 32]).unwrap();
        assert_ne!(*k.e2h, *k.h2e);
        assert_ne!(*k.e2h, *k.confirm);
        // The pairing key is part of the input keying material.
        let k2 = derive(&input, &[7u8; 32], &[9u8; 32]).unwrap();
        assert_eq!(k.t, k2.t);
        assert_ne!(*k.e2h, *k2.e2h);
    }
}
