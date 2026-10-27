//! Differential test between `slh-dsa` 0.1.0 (the identity key's
//! implementation) and the 0.2.0-rc.5 release candidate it will move to once
//! 0.2 is stable (Ruling 13). Same seeds must give the same keys, the same
//! randomizer must give byte-identical signatures, and a signature made by
//! one version must verify with the other (pure SLH-DSA, empty context).
//!
//! SLH-DSA-SHA2-256s is slow without optimizations: about 4 s with
//! `--release`, about a minute in a debug build (`make test`).

use onepass_core::crypto::{IdentityKey, IdentitySignature, IdentityVerifyingKey};
use serde_bytes::{ByteBuf, Bytes};

use slh_dsa::{
    Sha2_256s as Old256s, Signature as OldSignature, SigningKey as OldSigningKey,
    VerifyingKey as OldVerifyingKey,
};
use slh_dsa_next::{
    Sha2_256s as New256s, Signature as NewSignature, SigningKey as NewSigningKey,
    VerifyingKey as NewVerifyingKey,
};

const N: usize = 32;

/// Deterministic, distinct seed triples `sk_seed || sk_prf || pk_seed`.
fn seeds(i: u8) -> [u8; 3 * N] {
    let mut s = [0u8; 3 * N];
    for (j, b) in s.iter_mut().enumerate() {
        *b = (j as u8).wrapping_mul(31).wrapping_add(i.wrapping_mul(97)) ^ 0x5a;
    }
    s
}

fn old_key(s: &[u8; 3 * N]) -> OldSigningKey<Old256s> {
    OldSigningKey::slh_keygen_internal(&s[..N], &s[N..2 * N], &s[2 * N..])
}

fn new_key(s: &[u8; 3 * N]) -> NewSigningKey<New256s> {
    NewSigningKey::slh_keygen_internal(&s[..N], &s[N..2 * N], &s[2 * N..])
}

fn old_vk(sk: &OldSigningKey<Old256s>) -> OldVerifyingKey<Old256s> {
    AsRef::<OldVerifyingKey<Old256s>>::as_ref(sk).clone()
}

fn new_vk(sk: &NewSigningKey<New256s>) -> NewVerifyingKey<New256s> {
    AsRef::<NewVerifyingKey<New256s>>::as_ref(sk).clone()
}

fn messages() -> Vec<Vec<u8>> {
    vec![Vec::new(), (0..1024u32).map(|i| (i % 251) as u8).collect()]
}

/// The framing of `crypto::sign`: `"onepass/sig/v1" || u16_be(len(domain))
/// || domain || msg`.
fn framed(domain: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut out = b"onepass/sig/v1".to_vec();
    out.extend_from_slice(&u16::try_from(domain.len()).unwrap().to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(msg);
    out
}

fn identity_sig_bytes(sig: &IdentitySignature) -> Vec<u8> {
    let enc = postcard::to_allocvec(sig).unwrap();
    postcard::from_bytes::<ByteBuf>(&enc).unwrap().into_vec()
}

fn identity_sig(bytes: &[u8]) -> IdentitySignature {
    postcard::from_bytes(&postcard::to_allocvec(Bytes::new(bytes)).unwrap()).unwrap()
}

fn identity_vk(bytes: &[u8]) -> IdentityVerifyingKey {
    postcard::from_bytes(&postcard::to_allocvec(Bytes::new(bytes)).unwrap()).unwrap()
}

#[test]
fn same_seeds_give_the_same_keys() {
    for i in 0..3 {
        let s = seeds(i);
        let old = old_key(&s);
        let new = new_key(&s);
        assert_eq!(
            old_vk(&old).to_bytes().as_slice(),
            new_vk(&new).to_bytes().as_slice(),
            "public key, seed {i}"
        );
        assert_eq!(
            old.to_bytes().as_slice(),
            new.to_bytes().as_slice(),
            "secret key encoding, seed {i}"
        );
        // The FIPS 205 encodings parse back in the other version.
        let old_from_new = OldSigningKey::<Old256s>::try_from(new.to_bytes().as_slice()).unwrap();
        assert_eq!(
            old_from_new.to_bytes().as_slice(),
            old.to_bytes().as_slice()
        );
        let new_from_old = NewSigningKey::<New256s>::try_from(old.to_bytes().as_slice()).unwrap();
        assert_eq!(
            new_from_old.to_bytes().as_slice(),
            new.to_bytes().as_slice()
        );
    }
}

#[test]
fn signatures_match_and_cross_verify() {
    let s = seeds(7);
    let old = old_key(&s);
    let new = new_key(&s);
    let (ovk, nvk) = (old_vk(&old), new_vk(&new));
    let rand = [0x42u8; N];
    for (k, msg) in messages().iter().enumerate() {
        // Hedged, as OnePass signs: the same randomizer gives the same bytes.
        let so = old.try_sign_with_context(msg, &[], Some(&rand)).unwrap();
        let sn = new.try_sign_with_context(msg, &[], Some(&rand)).unwrap();
        assert_eq!(so.to_vec(), sn.to_vec(), "hedged signature, message {k}");

        let sn_as_old = OldSignature::<Old256s>::try_from(sn.to_vec().as_slice()).unwrap();
        let so_as_new = NewSignature::<New256s>::try_from(so.to_vec().as_slice()).unwrap();
        ovk.try_verify_with_context(msg, &[], &sn_as_old)
            .unwrap_or_else(|_| panic!("0.1 rejects a 0.2 signature, message {k}"));
        nvk.try_verify_with_context(msg, &[], &so_as_new)
            .unwrap_or_else(|_| panic!("0.2 rejects a 0.1 signature, message {k}"));

        // Both reject the other's signature over a different message.
        let mut other = msg.clone();
        other.push(0);
        assert!(
            ovk.try_verify_with_context(&other, &[], &sn_as_old)
                .is_err()
        );
        assert!(
            nvk.try_verify_with_context(&other, &[], &so_as_new)
                .is_err()
        );
    }

    // Deterministic variant (no randomizer): also byte-identical.
    let msg = b"deterministic";
    let so = old.try_sign_with_context(msg, &[], None).unwrap();
    let sn = new.try_sign_with_context(msg, &[], None).unwrap();
    assert_eq!(so.to_vec(), sn.to_vec(), "deterministic signature");
}

#[test]
fn onepass_identity_key_interoperates_with_the_candidate() {
    let s = seeds(3);
    let new = new_key(&s);

    // A key made by 0.2 from the same seeds imports as an IdentityKey: the
    // import recomputes pk_root with 0.1 and requires a match.
    let identity = IdentityKey::from_bytes(new.to_bytes().as_slice()).unwrap();
    let vk_bytes = new_vk(&new).to_vec();
    assert_eq!(identity.verifying_key(), identity_vk(&vk_bytes));

    let domain = b"account-params";
    let msg = b"differential";
    let nvk = new_vk(&new);

    // OnePass (0.1, hedged) signs; 0.2 verifies the framed message.
    let sig = identity.sign(domain, msg).unwrap();
    let sig_new = NewSignature::<New256s>::try_from(identity_sig_bytes(&sig).as_slice()).unwrap();
    nvk.try_verify_with_context(&framed(domain, msg), &[], &sig_new)
        .expect("0.2 rejects an IdentityKey signature");
    assert!(
        nvk.try_verify_with_context(&framed(b"manifest", msg), &[], &sig_new)
            .is_err()
    );

    // 0.2 signs the framed message; IdentityVerifyingKey (0.1) accepts it,
    // and only under the right domain.
    let rand = [0x17u8; N];
    let by_new = new
        .try_sign_with_context(&framed(domain, msg), &[], Some(&rand))
        .unwrap();
    let as_identity = identity_sig(&by_new.to_vec());
    identity
        .verifying_key()
        .verify(domain, msg, &as_identity)
        .expect("IdentityVerifyingKey rejects a 0.2 signature");
    assert!(
        identity
            .verifying_key()
            .verify(b"manifest", msg, &as_identity)
            .is_err()
    );
}
