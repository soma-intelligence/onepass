#![no_main]

//! An account params record as a hostile store serves it, through the real
//! unlock path: decoding, identity signature over the decoded fields, then
//! the floor and ceiling checks. Random bytes never pass the signature, so
//! Argon2 is never reached.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use onepass_core::account::{Account, AccountParams};
use onepass_core::crypto::SecretKey;

fn secret_key() -> &'static SecretKey {
    static K: OnceLock<SecretKey> = OnceLock::new();
    K.get_or_init(|| SecretKey::generate().unwrap())
}

fuzz_target!(|data: &[u8]| {
    let _ = AccountParams::decode(data);
    let _ = Account::unlock("password", secret_key(), data, &[], None);
});
