//! Zone sync for the sharing tests: one fake server per shared zone, the
//! devices push and pull each zone they know (rows held, or a zone access
//! of their account). Used next to `common`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::common::*;
use onepass_core::repo::share::list_zone_accesses;
use onepass_core::share::AccessTarget;
use onepass_core::store::Zone;
use onepass_core::sync::PhaseOutcome;

#[derive(Default)]
pub struct Zones {
    pub servers: BTreeMap<Zone, Server>,
    pub cursors: BTreeMap<(PathBuf, Zone), u64>,
}

impl Zones {
    pub fn server(&mut self, zone: Zone) -> &mut Server {
        self.servers.entry(zone).or_default()
    }
}

/// The shared zones `dev` knows.
pub fn zones_of(dev: &Device) -> Vec<Zone> {
    let st = dev.store();
    let mut out = st.zones().unwrap();
    for a in list_zone_accesses(&st).unwrap() {
        if let AccessTarget::Zone(z) = a.target
            && !out.contains(&z)
        {
            out.push(z);
        }
    }
    out
}

/// Push `zone`'s pending rows, then move a resealing being pushed to its
/// next phase and push again, until nothing moves.
pub fn zpush(zs: &mut Zones, dev: &Device, zone: Zone) -> std::result::Result<(), Conflict> {
    loop {
        zpush_once(zs, dev, zone)?;
        if dev.store().push_share_phase(zone).unwrap() == PhaseOutcome::Retry {
            return Ok(());
        }
    }
}

/// One batch of `zone`'s pending rows, no phase move.
pub fn zpush_once(zs: &mut Zones, dev: &Device, zone: Zone) -> std::result::Result<(), Conflict> {
    let mut store = dev.store();
    let batch: Vec<(Change, Option<u64>)> = store
        .pending_changes_in(zone)
        .unwrap()
        .into_iter()
        .map(|c| {
            let tag = tag_of(store.server_meta_in(zone, c.kind, c.id).unwrap());
            (c, tag)
        })
        .collect();
    let tags = zs.server(zone).push(&batch)?;
    for ((c, _), tag) in batch.iter().zip(tags) {
        let meta = c.data.as_ref().map(|_| tag_bytes(tag));
        store
            .mark_pushed_in(zone, c.kind, c.id, c.version, meta)
            .unwrap();
    }
    Ok(())
}

pub fn zpull(zs: &mut Zones, dev: &Device, zone: Zone) {
    let key = (dev.path.clone(), zone);
    let cursor = zs.cursors.get(&key).copied().unwrap_or(0);
    let (changes, next) = zs.server(zone).changes_since(cursor);
    let mut store = dev.store();
    for c in changes {
        store.stage_remote_in(zone, c).unwrap();
    }
    store.commit_remote_in(zone).unwrap();
    zs.cursors.insert(key, next);
}

/// The private zone as `common::sync`, then every zone `dev` knows: push,
/// then pull.
pub fn zsync(server: &mut Server, zs: &mut Zones, dev: &mut Device) {
    sync(server, dev).unwrap();
    for z in zones_of(dev) {
        zsync_zone(zs, dev, z);
    }
}

/// Push and pull one zone; a refused push pulls, rebases and tries again.
pub fn zsync_zone(zs: &mut Zones, dev: &mut Device, z: Zone) {
    for _ in 0..3 {
        match zpush(zs, dev, z) {
            Ok(()) => {
                zpull(zs, dev, z);
                return;
            }
            Err(_) => {
                zpull(zs, dev, z);
                dev.repo().rebase().unwrap();
                // A rebase that found my removal erased the zone.
                if !zones_of(dev).contains(&z) {
                    return;
                }
            }
        }
    }
    panic!("no agreement on {z:?} after three rounds");
}

/// `zsync` for each device, twice, so every write reaches every device.
pub fn zsettle(server: &mut Server, zs: &mut Zones, devs: &mut [&mut Device]) {
    for _ in 0..2 {
        for d in devs.iter_mut() {
            zsync(server, zs, d);
        }
    }
}
