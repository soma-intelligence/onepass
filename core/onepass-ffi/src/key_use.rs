//! Key-use log of an item for the detail screen: which channel used a
//! secret of it, how, from which device and client, and how often (see
//! `onepass_core::model::key_use`). Never a value: a client is a short
//! application name and a field a label, both sanitized by the core.

use onepass_core::model::key_use::{KeyUse, KeyUseAction, KeyUseChannel};
use time::OffsetDateTime;

use crate::convert::{parse_id, ts};
use crate::error::OnePassError;
use crate::session::{Session, find_item, find_vault};

/// Where a use came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiKeyUseChannel {
    App,
    AutoFill,
    Cli,
    Mcp,
    SshAgent,
    DesktopFill,
}

/// What was done with the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiKeyUseAction {
    Revealed,
    Copied,
    Injected,
    Totp,
    Signed,
    Filled,
}

/// One coalesced entry of an item's key-use log.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiKeyUse {
    pub channel: FfiKeyUseChannel,
    pub action: FfiKeyUseAction,
    /// Name of the device in the account's device list, empty when unknown.
    pub device_name: String,
    /// Application name as the client gave it (untrusted: show as text),
    /// may be empty.
    pub client: String,
    /// Label of the field touched, empty when the action covers the item.
    pub field: String,
    /// Unix seconds.
    pub first_at: i64,
    /// Unix seconds.
    pub last_at: i64,
    pub count: u32,
}

impl From<KeyUseChannel> for FfiKeyUseChannel {
    fn from(c: KeyUseChannel) -> Self {
        match c {
            KeyUseChannel::App => Self::App,
            KeyUseChannel::AutoFill => Self::AutoFill,
            KeyUseChannel::Cli => Self::Cli,
            KeyUseChannel::Mcp => Self::Mcp,
            KeyUseChannel::SshAgent => Self::SshAgent,
            KeyUseChannel::DesktopFill => Self::DesktopFill,
        }
    }
}

impl From<KeyUseAction> for FfiKeyUseAction {
    fn from(a: KeyUseAction) -> Self {
        match a {
            KeyUseAction::Revealed => Self::Revealed,
            KeyUseAction::Copied => Self::Copied,
            KeyUseAction::Injected => Self::Injected,
            KeyUseAction::Totp => Self::Totp,
            KeyUseAction::Signed => Self::Signed,
            KeyUseAction::Filled => Self::Filled,
        }
    }
}

impl From<FfiKeyUseAction> for KeyUseAction {
    fn from(a: FfiKeyUseAction) -> Self {
        match a {
            FfiKeyUseAction::Revealed => Self::Revealed,
            FfiKeyUseAction::Copied => Self::Copied,
            FfiKeyUseAction::Injected => Self::Injected,
            FfiKeyUseAction::Totp => Self::Totp,
            FfiKeyUseAction::Signed => Self::Signed,
            FfiKeyUseAction::Filled => Self::Filled,
        }
    }
}

fn row(e: KeyUse) -> FfiKeyUse {
    FfiKeyUse {
        channel: e.channel.into(),
        action: e.action.into(),
        device_name: e.device_name,
        client: e.client,
        field: e.field,
        first_at: ts(e.first_at),
        last_at: ts(e.last_at),
        count: e.count,
    }
}

#[uniffi::export]
impl Session {
    /// The item's key-use log, most recent use first. Uses this device
    /// still holds in its queue (within the hour, or from a read-only
    /// session) show once flushed.
    pub fn item_key_uses(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<Vec<FfiKeyUse>, OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let item = find_item(repo, &vault, item_id)?;
            let mut entries = item.key_use_trailer().entries;
            entries.sort_by_key(|a| std::cmp::Reverse(a.last_at));
            Ok(entries.into_iter().map(row).collect())
        })
    }

    /// Empty the item's key-use log ("Clear log"), on every device once
    /// synced: older entries another device holds do not come back. The
    /// item's `updated_at` is unchanged.
    pub fn clear_key_uses(&self, vault_id: String, item_id: String) -> Result<(), OnePassError> {
        let (vault_id, item_id) = (parse_id(&vault_id)?, parse_id(&item_id)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            Ok(repo.clear_key_uses(&vault, item_id, OffsetDateTime::now_utc())?)
        })
    }

    /// Fold this device's queued key uses an hour old or more into their
    /// items. Run at unlock and at each app foreground; the caller ignores
    /// the error (best effort, the rows stay queued). How many uses were
    /// applied.
    pub fn flush_key_use_queue(&self) -> Result<u32, OnePassError> {
        self.with(|repo| {
            let n = repo.flush_key_use_queue(OffsetDateTime::now_utc())?;
            Ok(u32::try_from(n).unwrap_or(u32::MAX))
        })
    }
}
