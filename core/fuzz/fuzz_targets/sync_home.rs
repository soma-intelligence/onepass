#![no_main]

//! A `SyncHome` record as a hostile store or mailbox serves it
//! (cross-platform spec 4.13): verified with a fixed account key, as
//! `Repository::sync_home` reads it. The input is tried twice: as the whole
//! record (random bytes never pass the signature), and as the signed body
//! of a record signed here, which reaches the strict decoding of the body
//! and its URL rule. Nothing may panic; a body that verifies re-encodes to
//! the input, is well formed, and chains to itself.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use onepass_core::Id;
use onepass_core::crypto::{HybridSigningKey, HybridVerifyingKey};
use onepass_core::synchome::{SYNC_HOME_DOMAIN, SignedSyncHome, verify_sync_home};

fn keys() -> &'static (HybridSigningKey, HybridVerifyingKey) {
    static K: OnceLock<(HybridSigningKey, HybridVerifyingKey)> = OnceLock::new();
    K.get_or_init(|| {
        let sk = HybridSigningKey::generate().unwrap();
        let vk = sk.verifying_key().unwrap();
        (sk, vk)
    })
}

fuzz_target!(|data: &[u8]| {
    let (sk, vk) = keys();
    let _ = SignedSyncHome::decode(data);
    let _ = verify_sync_home(data, vk, Id([0; 16]), None);
    let Ok(sig) = sk.sign(SYNC_HOME_DOMAIN, data) else {
        return;
    };
    let record = postcard::to_allocvec(&(serde_bytes::Bytes::new(data), &sig)).unwrap();
    let Ok(signed) = SignedSyncHome::decode(&record) else {
        return;
    };
    assert_eq!(signed.body.encode(), data);
    assert!(signed.body.backend.well_formed());
    let account = signed.body.account_id;
    let body = verify_sync_home(&record, vk, account, None).unwrap();
    assert_eq!(body, signed.body);
    assert_eq!(
        verify_sync_home(&record, vk, account, Some(&body.seen())).unwrap(),
        body
    );
});
