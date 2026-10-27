#![no_main]

//! a 1Password 1pux archive (zip with export.data), on hostile bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::import::{Format, detect, parse};

fuzz_target!(|data: &[u8]| {
    let _ = parse(Format::OnePasswordPux, data);
    let _ = detect("export", data);
});
