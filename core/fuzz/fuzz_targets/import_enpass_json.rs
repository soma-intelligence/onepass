#![no_main]

//! An Enpass JSON export, on hostile bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::import::{Format, detect, parse};

fuzz_target!(|data: &[u8]| {
    let _ = parse(Format::EnpassJson, data);
    let _ = detect("export", data);
});
