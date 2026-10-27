#![no_main]

//! Text based inputs: otpauth URI lists, Wi-Fi QR strings and the macOS
//! `networksetup` outputs. The first byte picks the parser.

use libfuzzer_sys::fuzz_target;
use onepass_core::import::text::{parse_hardware_ports, parse_preferred_networks, parse_wifi_qr};
use onepass_core::import::{Format, parse};

fuzz_target!(|data: &[u8]| {
    let Some((first, rest)) = data.split_first() else {
        return;
    };
    match first % 4 {
        0 => {
            let _ = parse(Format::OtpAuthUris, rest);
        }
        1 => {
            let _ = parse(Format::WifiQr, rest);
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = parse_wifi_qr(s);
            }
        }
        2 => {
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = parse_hardware_ports(s);
            }
        }
        _ => {
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = parse_preferred_networks(s);
            }
        }
    }
});
