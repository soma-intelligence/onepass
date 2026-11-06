//! Record zones (sharing spec 13.2, 13.3): the account's private zone and
//! one zone per shared vault, contact pair and family. Every zone lives in
//! the same local database, so one local transaction can touch the private
//! zone and shared zones at once (plan 2, ruling A-8).

use crate::{Error, Id, Result};

/// Where a record lives.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Zone {
    /// The account's own records (every record before sharing).
    Private,
    /// A shared vault, by vault id.
    Vault(Id),
    /// A contact pair, by `contact::pair_id`.
    Contact(Id),
    /// A family, by family id.
    Family(Id),
}

const TAG_VAULT: u8 = 1;
const TAG_CONTACT: u8 = 2;
const TAG_FAMILY: u8 = 3;

impl Zone {
    /// The stored key: empty for `Private`, else a tag byte (1 vault, 2
    /// contact, 3 family) then the 16 bytes of the id.
    pub fn key(&self) -> Vec<u8> {
        let (tag, id) = match self {
            Zone::Private => return Vec::new(),
            Zone::Vault(id) => (TAG_VAULT, id),
            Zone::Contact(id) => (TAG_CONTACT, id),
            Zone::Family(id) => (TAG_FAMILY, id),
        };
        let mut out = Vec::with_capacity(17);
        out.push(tag);
        out.extend_from_slice(&id.0);
        out
    }

    /// Decode `key`, strictly: empty, or exactly a known tag and 16 bytes.
    pub fn from_key(b: &[u8]) -> Result<Zone> {
        if b.is_empty() {
            return Ok(Zone::Private);
        }
        if b.len() != 17 {
            return Err(Error::InvalidFormat("zone key"));
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[1..]);
        let id = Id(id);
        match b[0] {
            TAG_VAULT => Ok(Zone::Vault(id)),
            TAG_CONTACT => Ok(Zone::Contact(id)),
            TAG_FAMILY => Ok(Zone::Family(id)),
            _ => Err(Error::InvalidFormat("zone key")),
        }
    }

    /// Whether this is a shared zone (anything but `Private`).
    pub fn is_shared(&self) -> bool {
        !matches!(self, Zone::Private)
    }
}
