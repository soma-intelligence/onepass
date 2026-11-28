//! The shared zones of the account (sharing spec 13.3 to 13.7), as the
//! Apple apps' `ZoneRoundScheduler` runs them: shared vaults, contact pairs
//! and the family, one zone round right after each private round of the
//! sync thread (sync.rs), on a zone's wake channel and on its retry delay.
//!
//! Zone credential seeds live in `mailbox.bin` next to the account's own
//! (key `zone.<mailbox id hex>`), sealed like it, never logged or returned:
//! the Keychain's job on Apple (`ZoneSeedKeychain`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use onepass_ffi::{
    FfiZoneKind, FfiZoneRoundReport, FfiZoneSeedStore, SyncStoreHandle, WakeListenerHandle,
    ZoneSyncHandle,
};
use serde::Serialize;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::state::AppState;
use crate::sync::{self, Home};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The seed store the core caches zone seeds in.
pub struct SeedFile(pub AppHandle);

impl SeedFile {
    fn key(mailbox_id: &[u8]) -> String {
        format!("zone.{}", hex(mailbox_id))
    }
}

impl FfiZoneSeedStore for SeedFile {
    fn get(&self, mailbox_id: Vec<u8>) -> Option<Vec<u8>> {
        let state = self.0.state::<AppState>();
        sync::seed(&state, &Self::key(&mailbox_id))
            .ok()
            .flatten()
            .map(|s| s.to_vec())
    }

    fn put(&self, mailbox_id: Vec<u8>, seed: Vec<u8>) {
        let seed = Zeroizing::new(seed);
        let state = self.0.state::<AppState>();
        let _ = sync::store_seed(&state, &Self::key(&mailbox_id), &seed);
    }

    fn delete(&self, mailbox_id: Vec<u8>) {
        let state = self.0.state::<AppState>();
        let _ = sync::delete_seed(&state, &Self::key(&mailbox_id));
    }
}

/// The zone side of an account on a mailbox: the core's driver and the
/// store it rounds on.
#[derive(Clone)]
pub struct ZoneClient {
    pub handle: Arc<ZoneSyncHandle>,
    pub store: Arc<SyncStoreHandle>,
}

impl ZoneClient {
    /// The zones of the account whose home is `home`, made under its
    /// mailbox with this device's credential `seed`.
    pub fn open(app: &AppHandle, home: &Home, seed: &[u8]) -> Option<ZoneClient> {
        let state = app.state::<AppState>();
        let hosted = sync::hosted();
        let handle = ZoneSyncHandle::new(
            Arc::new(SeedFile(app.clone())),
            hosted.base_url.clone(),
            hosted.ca_pem.clone(),
        );
        handle
            .set_account_mailbox(home.endpoint(), home.mailbox_id.clone(), seed.to_vec())
            .ok()?;
        let store = onepass_ffi::open_sync_store(state.db_path()).ok()?;
        Some(ZoneClient { handle, store })
    }
}

/// What the screens show of the last zone round (spec 13.8): the vaults the
/// server refuses (kept read-only here), those whose mailbox is full.
#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ZoneView {
    pub refused_vaults: Vec<String>,
    pub full_vaults: Vec<String>,
    pub last_round: Option<i64>,
}

impl ZoneView {
    pub fn from_report(r: &FfiZoneRoundReport, at: i64) -> ZoneView {
        let vault = |kind: FfiZoneKind, id: &Option<String>| {
            (kind == FfiZoneKind::Vault).then(|| id.clone()).flatten()
        };
        ZoneView {
            refused_vaults: r
                .refusals
                .iter()
                .filter(|x| !x.removed)
                .filter_map(|x| vault(x.zone.kind, &x.zone.id))
                .collect(),
            full_vaults: r
                .quota_full
                .iter()
                .filter_map(|z| vault(z.kind, &z.id))
                .collect(),
            last_round: Some(at),
        }
    }
}

/// The wake listeners of the zones the last round synced, by mailbox id.
#[derive(Default)]
pub struct ZoneWakes(HashMap<String, Arc<WakeListenerHandle>>);

impl ZoneWakes {
    /// One listener per topic of `client`; the ones of zones gone stop.
    pub fn refresh(
        &mut self,
        client: &ZoneClient,
        observer: impl Fn() -> Arc<dyn onepass_ffi::FfiWakeObserver>,
    ) {
        let topics = client.handle.wake_topics();
        self.0.retain(|id, w| {
            let keep = topics.iter().any(|t| &t.mailbox_id == id);
            if !keep {
                w.stop();
            }
            keep
        });
        for t in topics {
            if self.0.contains_key(&t.mailbox_id) {
                continue;
            }
            // No wake channel: the zone still syncs after each private round.
            if let Ok(h) = onepass_ffi::start_wake_listener(t.wake.clone(), observer()) {
                self.0.insert(t.mailbox_id.clone(), h);
            }
        }
    }

    pub fn stop(&mut self) {
        for (_, w) in self.0.drain() {
            w.stop();
        }
    }
}

/// The shared zone state the sync thread and the commands both see.
#[derive(Default)]
pub struct Zones {
    pub client: Mutex<Option<ZoneClient>>,
    pub view: Mutex<ZoneView>,
}

impl Zones {
    pub fn client(&self) -> Option<ZoneClient> {
        lock(&self.client).clone()
    }

    pub fn view(&self) -> ZoneView {
        lock(&self.view).clone()
    }
}

/// The server whose drops carry a contact invitation (`InviteServer.url`):
/// the one the link names (`onepass://contact/<host>#...`), else the
/// Cleon server.
pub fn server_for_link(link: &str) -> sync::Server {
    let text = link.trim();
    if let Some(rest) = text.strip_prefix("onepass://contact/")
        && let Some((host, _)) = rest.split_once('#')
        && !host.is_empty()
    {
        let url = format!("https://{host}/functions/v1/mailbox");
        if sync::valid_url(&url) {
            let ca_pem = sync::ca_for(&url, None);
            return sync::Server {
                base_url: url,
                ca_pem,
            };
        }
    }
    sync::hosted()
}

/// The host a new link names: none for the Cleon server.
pub fn link_host(server: &sync::Server) -> Option<String> {
    if server.base_url == sync::hosted().base_url {
        return None;
    }
    url::Url::parse(&server.base_url).ok().and_then(|u| {
        u.host_str().map(|h| match u.port() {
            Some(p) => format!("{h}:{p}"),
            None => h.to_owned(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_servers() {
        let hosted = sync::hosted().base_url;
        assert_eq!(server_for_link("onepass://contact#ABC").base_url, hosted);
        assert_eq!(
            server_for_link(" onepass://contact/sync.example.org#ABC ").base_url,
            "https://sync.example.org/functions/v1/mailbox"
        );
        assert_eq!(
            server_for_link("onepass://contact/bad host#ABC").base_url,
            hosted
        );
        assert_eq!(link_host(&sync::hosted()), None);
        assert_eq!(
            link_host(&sync::Server {
                base_url: "https://sync.example.org:8443/functions/v1/mailbox".into(),
                ca_pem: None
            })
            .as_deref(),
            Some("sync.example.org:8443")
        );
    }
}
