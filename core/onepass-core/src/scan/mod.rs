//! Reading an eMRTD (ePassport) chip: MRZ parsing, then the chip protocols
//! built on it (BAC, PACE, data groups, passive authentication).
//!
//! Nothing here logs or prints APDU bytes or MRZ content.

pub mod apdu;
pub mod icao;
pub mod mrz;
pub mod tlv;
pub mod to_item;
