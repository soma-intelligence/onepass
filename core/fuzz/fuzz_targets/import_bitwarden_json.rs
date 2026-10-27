#![no_main]

//! a Bitwarden JSON export, on hostile bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::import::{Format, detect, parse};

fuzz_target!(|data: &[u8]| {
    let _ = parse(Format::BitwardenJson, data);
    let _ = detect("export", data);
});
