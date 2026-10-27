#![no_main]

//! A manifest record as a hostile store serves it: decoded, then its
//! signature checked with a fixed account key, as `verify_manifest` does
//! before anything else. Random bytes never pass the signature, so the
//! authenticated part (opening, `Manifest` decoding) is out of reach here.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use onepass_core::crypto::{HybridSigningKey, HybridVerifyingKey};
use onepass_core::manifest::SignedManifest;

fn verifier() -> &'static HybridVerifyingKey {
    static K: OnceLock<HybridVerifyingKey> = OnceLock::new();
    K.get_or_init(|| {
        HybridSigningKey::generate()
            .unwrap()
            .verifying_key()
            .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(sm) = SignedManifest::decode(data) {
        let _ = verifier().verify(b"manifest", &sm.blob, &sm.sig);
    }
});
