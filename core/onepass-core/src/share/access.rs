//! Zone mailboxes (sharing spec 13.3 to 13.5): where a zone lives, the
//! signed per-account access to it, member credential seeds and the
//! contact zone offer.

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Longest `ZoneHome::url`, in bytes.
pub const MAX_ZONE_URL_BYTES: usize = 256;
/// Longest `ZoneHome::extra_ca_pem`, in bytes.
pub const MAX_ZONE_CA_PEM_BYTES: usize = 8 * 1024;

/// Where a zone's mailbox lives: the server and the mailbox id on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneHome {
    pub url: String,
    pub mailbox_id: [u8; 16],
    pub extra_ca_pem: Option<String>,
}

impl ZoneHome {
    /// Shape rules: an `https://` URL of at most 256 bytes, a PEM of at
    /// most 8 KiB. `InvalidFormat` otherwise.
    pub fn check(&self) -> Result<()> {
        let bad = Error::InvalidFormat("zone home");
        if self.url.len() > MAX_ZONE_URL_BYTES
            || !self.url.starts_with("https://")
            || self.url.len() == "https://".len()
            || self.url.chars().any(char::is_control)
        {
            return Err(bad);
        }
        if self
            .extra_ca_pem
            .as_ref()
            .is_some_and(|p| p.len() > MAX_ZONE_CA_PEM_BYTES || p.is_empty())
        {
            return Err(bad);
        }
        Ok(())
    }

    /// The host of `url`, for the screens.
    pub fn host(&self) -> &str {
        let rest = &self.url["https://".len()..];
        rest.split(['/', '?', '#']).next().unwrap_or(rest)
    }
}
