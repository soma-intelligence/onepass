//! Automatic Wi-Fi over the UniFFI surface: the Router items a device may
//! join on its own, chosen by the shared model (`onepass_core::wifi`), so
//! every platform installs the same networks.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::HashMap;
use std::fmt;

use onepass_core::wifi::{self, Security};

use crate::convert::{id_hex, parse_id};
use crate::error::OnePassError;
use crate::session::Session;

/// Security of a network that qualifies (WPA2 or WPA3 personal only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiWifiSecurity {
    Wpa2Personal,
    Wpa3Personal,
}

/// A network the device may join. `fingerprint` is secret free (item id,
/// SSID, security, hidden flag, item update time): a changed password moves
/// it, a ledger of fingerprints never holds anything about the password.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWifiNetwork {
    pub item_id: String,
    pub ssid: String,
    pub psk: String,
    pub security: FfiWifiSecurity,
    pub hidden: bool,
    pub fingerprint: String,
}

impl fmt::Debug for FfiWifiNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiWifiNetwork")
            .field("item_id", &self.item_id)
            .field("ssid", &self.ssid)
            .field("psk", &"[redacted]")
            .field("security", &self.security)
            .field("hidden", &self.hidden)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// The networks, one per SSID, sorted by SSID, and how many Router items
/// were left out for each reason (`open`, `wep`, `enterprise`...).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiWifiSelection {
    pub networks: Vec<FfiWifiNetwork>,
    pub skipped: HashMap<String, u32>,
}

#[uniffi::export]
impl Session {
    /// The Wi-Fi networks of every vault of this account, the vaults
    /// `excluded_vault_ids` (hidden on this device) left out.
    pub fn wifi_networks(
        &self,
        excluded_vault_ids: Vec<String>,
    ) -> Result<FfiWifiSelection, OnePassError> {
        let excluded = excluded_vault_ids
            .iter()
            .map(|s| parse_id(s))
            .collect::<Result<Vec<_>, _>>()?;
        self.with(|repo| {
            let mut items = Vec::new();
            for v in repo.vaults()? {
                if !excluded.contains(&v.id) {
                    items.extend(repo.items(&v)?);
                }
            }
            let selection = wifi::select(&items);
            Ok(FfiWifiSelection {
                networks: selection
                    .networks
                    .iter()
                    .map(|n| FfiWifiNetwork {
                        item_id: id_hex(n.item_id),
                        ssid: n.ssid.clone(),
                        psk: n.psk.to_string(),
                        security: match n.security {
                            Security::Wpa2Personal => FfiWifiSecurity::Wpa2Personal,
                            Security::Wpa3Personal => FfiWifiSecurity::Wpa3Personal,
                        },
                        hidden: n.hidden,
                        fingerprint: n.fingerprint(),
                    })
                    .collect(),
                skipped: selection
                    .skipped_codes()
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect(),
            })
        })
    }
}
