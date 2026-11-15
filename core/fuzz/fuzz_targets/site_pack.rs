#![no_main]

//! A site pack as a hostile download serves it: whatever the bytes, `parse` must not panic, and
//! every recipe it keeps has at most 12 steps, ends with its own `expect_*` step and carries
//! timeouts from 1 to 60 seconds.

use libfuzzer_sys::fuzz_target;
use onepass_core::site_pack::{Step, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(pack) = parse(data) else {
        return;
    };
    for site in pack.sites.values() {
        for (setup, last) in [
            (&site.setup_totp, Step::ExpectQr),
            (&site.setup_passkey, Step::ExpectPasskeyPrompt),
        ] {
            let Some(recipe) = setup.as_ref().and_then(|s| s.recipe.as_ref()) else {
                continue;
            };
            assert!(!recipe.is_empty() && recipe.len() <= 12);
            assert_eq!(recipe.last().unwrap().step, last);
            assert!(recipe.iter().all(|s| (1..=60).contains(&s.timeout_s)));
        }
    }
});
