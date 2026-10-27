#![no_main]

//! `HybridVerifyingKey::verify` and `IdentityVerifyingKey::verify` on
//! arbitrary keys and signatures: as a hostile store serves them (postcard),
//! and at the exact lengths (input bytes repeated), so the ML-DSA, Ed25519
//! and SLH-DSA verifiers themselves get arbitrary input.

use libfuzzer_sys::fuzz_target;
use onepass_core::crypto::{
    HybridSignature, HybridVerifyingKey, IdentitySignature, IdentityVerifyingKey,
};

const MLDSA_PUBLIC: usize = 2592;
const MLDSA_SIG: usize = 4627;
const SLH_PUBLIC: usize = 64;
const SLH_SIG: usize = 29792;

/// `n` bytes taken from `src` repeated, starting at `skip`.
fn fill(src: &[u8], skip: usize, n: usize) -> Vec<u8> {
    if src.is_empty() {
        return vec![0; n];
    }
    src.iter()
        .cycle()
        .skip(skip % src.len())
        .take(n)
        .copied()
        .collect()
}

/// Postcard bytes of a byte string, the encoding of the identity types.
fn bytes_record(b: &[u8]) -> Vec<u8> {
    postcard::to_allocvec(&serde_bytes::Bytes::new(b)).unwrap()
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    // Stored form.
    if let Ok((k, s, m)) =
        postcard::from_bytes::<(HybridVerifyingKey, HybridSignature, Vec<u8>)>(rest)
    {
        let _ = k.verify(b"manifest", &m, &s);
    }
    if let Ok((k, s, m)) =
        postcard::from_bytes::<(IdentityVerifyingKey, IdentitySignature, Vec<u8>)>(rest)
    {
        let _ = k.verify(b"account-params", &m, &s);
    }
    // Exact lengths, or one byte short when the selector says so.
    let short = |bit: u8, n: usize| if sel & bit != 0 { n - 1 } else { n };
    let msg = &rest[..rest.len().min(64)];
    let mut ed_key = [0u8; 32];
    ed_key.copy_from_slice(&fill(rest, 7, 32));
    let mut ed_sig = [0u8; 64];
    ed_sig.copy_from_slice(&fill(rest, 11, 64));
    let key = HybridVerifyingKey {
        mldsa: fill(rest, 0, short(1, MLDSA_PUBLIC)),
        ed25519: ed_key,
    };
    let sig = HybridSignature {
        mldsa: fill(rest, 3, short(2, MLDSA_SIG)),
        ed25519: ed_sig,
    };
    let _ = key.verify(b"manifest", msg, &sig);
    let id_key: IdentityVerifyingKey =
        postcard::from_bytes(&bytes_record(&fill(rest, 5, short(4, SLH_PUBLIC)))).unwrap();
    let id_sig: IdentitySignature =
        postcard::from_bytes(&bytes_record(&fill(rest, 13, short(8, SLH_SIG)))).unwrap();
    let _ = id_key.verify(b"account-params", msg, &id_sig);
});
