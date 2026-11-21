//! ICAO 9303 part 11 chip access: BAC, PACE and secure messaging, then
//! passive authentication against a CSCA master list.
//!
//! Nothing here logs or prints key material or APDU bytes.

pub mod bac;
pub mod card_access;
pub mod dg;
pub mod master_list;
pub mod pace;
pub mod passive_auth;
pub mod session;
pub mod sm;

use std::fmt;

pub use bac::{BacExchange, BacKeys, derive_bac_keys};
pub use card_access::{PaceInfo, parse_card_access};
pub use master_list::{MasterList, load_master_list};
pub use pace::{PaceCurve, PaceExchange, PaceRandom};
pub use passive_auth::{ChipStatus, verify_sod};
pub use session::{AccessKey, ChipRead, IcaoSession, Step};
pub use sm::{Cipher, SecureChannel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcaoError {
    /// The chip refused the access keys (wrong MRZ data).
    AccessDenied,
    /// A secure messaging MAC did not verify.
    BadMac,
    /// The chip answered in a way the protocol does not allow.
    Protocol(&'static str),
    /// The chip answered with an error status word.
    Chip(u16),
    /// No chip in the field.
    NoChip,
    /// A cryptographic primitive refused its input (bad key length).
    Crypto,
}

impl fmt::Display for IcaoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcaoError::AccessDenied => f.write_str("the chip refused the access keys"),
            IcaoError::BadMac => f.write_str("secure messaging MAC mismatch"),
            IcaoError::Protocol(m) => write!(f, "chip protocol error: {m}"),
            IcaoError::Chip(sw) => write!(f, "chip status {sw:04X}"),
            IcaoError::NoChip => f.write_str("no chip found"),
            IcaoError::Crypto => f.write_str("invalid key material"),
        }
    }
}

impl std::error::Error for IcaoError {}

#[cfg(test)]
pub(crate) mod testutil {
    const FIXTURE: &str = include_str!("../../../tests/fixtures/icao/appendix_d.txt");

    pub fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect()
    }

    pub fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    pub fn text(name: &str) -> &'static str {
        FIXTURE
            .lines()
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == name).then(|| v.trim())
            })
            .unwrap_or_else(|| panic!("missing fixture {name}"))
    }

    pub fn fx(name: &str) -> Vec<u8> {
        unhex(text(name))
    }
}
