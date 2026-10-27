#![no_main]

//! The catalogs the caller supplies: 2fa.directory, the passkeys directory
//! and the HIBP breaches list. The first byte picks the document type.

use libfuzzer_sys::fuzz_target;
use onepass_core::watchtower::{BreachCatalog, SiteDirectory};

fuzz_target!(|data: &[u8]| {
    let Some((first, rest)) = data.split_first() else {
        return;
    };
    match first % 3 {
        0 => {
            if let Ok(d) = SiteDirectory::from_2fa_directory(rest) {
                let _ = d.lookup("example.com");
            }
        }
        1 => {
            let mut d = SiteDirectory::default();
            let _ = d.add_passkeys_directory(rest);
            let _ = d.lookup("example.com");
        }
        _ => {
            if let Ok(c) = BreachCatalog::from_hibp(rest) {
                let _ = c.lookup("example.com");
            }
        }
    }
});
