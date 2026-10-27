#![no_main]

//! a KeePass 2 XML export, on hostile bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::import::{Format, detect, parse};

fuzz_target!(|data: &[u8]| {
    let _ = parse(Format::KeePassXml, data);
    let _ = detect("export", data);
});
