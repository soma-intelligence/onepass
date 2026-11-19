#![no_main]

//! Org DNS TXT values as a hostile resolver serves them: parsing must not
//! panic, and a parsed fingerprint written back as a TXT value parses to the
//! same fingerprint.

use libfuzzer_sys::fuzz_target;
use onepass_core::org::{dns_txt_value, parse_dns_txt};

fuzz_target!(|data: &[u8]| {
    let Ok(txt) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(f) = parse_dns_txt(txt) {
        assert_eq!(parse_dns_txt(&dns_txt_value(&f)).ok(), Some(f));
    }
});
