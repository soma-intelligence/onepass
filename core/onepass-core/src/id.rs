use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Error;

/// A 16 byte UUIDv7 identifier (blob, item, vault, account, device).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Id(pub [u8; 16]);

impl Id {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Id {
        Id(*Uuid::now_v7().as_bytes())
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Uuid::from_bytes(self.0).hyphenated(), f)
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(s: &str) -> Result<Id, Error> {
        Uuid::parse_str(s)
            .map(|u| Id(*u.as_bytes()))
            .map_err(|_| Error::InvalidFormat("id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_ordered_and_roundtrip() {
        let a = Id::new();
        let b = Id::new();
        assert_ne!(a, b);
        assert!(a < b, "UUIDv7 must sort by creation time");
        assert_eq!(a, a.to_string().parse::<Id>().unwrap());
        assert_eq!(a.0[6] >> 4, 7, "version nibble must be 7");
    }
}
