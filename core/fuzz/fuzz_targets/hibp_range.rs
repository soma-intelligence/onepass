#![no_main]

//! A Have I Been Pwned range response as a hostile server sends it.

use libfuzzer_sys::fuzz_target;
use onepass_core::watchtower::parse_range;

fuzz_target!(|data: &[u8]| {
    let _ = parse_range(data);
});
