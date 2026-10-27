#![no_main]

//! Every CSV based import format (and the two LastPass and Dashlane variants),
//! on hostile bytes. The first byte picks the format.

use libfuzzer_sys::fuzz_target;
use onepass_core::import::{Format, parse};

const FORMATS: [Format; 13] = [
    Format::OnePasswordCsv,
    Format::BitwardenCsv,
    Format::ChromeCsv,
    Format::SafariCsv,
    Format::FirefoxCsv,
    Format::LastPassCsv,
    Format::DashlaneCsv,
    Format::ProtonPassCsv,
    Format::DashlaneZip,
    Format::OnePassCsv,
    Format::NordPassCsv,
    Format::KeeperCsv,
    Format::RoboFormCsv,
];

fuzz_target!(|data: &[u8]| {
    let Some((first, rest)) = data.split_first() else {
        return;
    };
    let format = FORMATS[usize::from(*first) % FORMATS.len()];
    let _ = parse(format, rest);
});
