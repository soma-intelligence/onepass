//! Sync health per vault: a server behind the device's copy is a sync
//! state, not an integrity error, until it lasts.
//!
//! When the server serves an older state than the copy this device verified
//! (a lagging replica, a zone wiped and refilled by a device that was
//! behind, a fetch cut short, a batch seen between its two halves), the
//! device keeps serving its own copy (`Repository::served`), sends it again
//! when the server went back (`SyncStore`), and reports the vault
//! `ServerBehind`. Each sync round (`note_sync_round`) counts one more
//! round; once the vault was behind for `STALE_ALERT_ROUNDS` rounds and
//! `STALE_ALERT_SECONDS` seconds, it is an `Alert`. A fork the rebase
//! cannot merge, or no verified copy at all, is an `Alert` at once.
//!
//! A round is clean for a vault when a fetch served a state at least as new
//! as the copy and it loads cleanly (or the rebase merged onto it). The
//! confirmation of this device's own push does not count: a server that
//! takes the copy and serves the old state again stays behind. The vault is
//! `Ok` again only after `STALE_CLEAR_ROUNDS` clean rounds in a row: a
//! store that alternates the good state and an old one never gets there,
//! its rounds keep counting (`since` is never reset) and it is reported at
//! the threshold, never hidden for longer.
//!
//! Clock: `since` moves back to an earlier `now` (a clock set forward once
//! cannot push the alert back), and past `STALE_ALERT_MAX_ROUNDS` rounds the
//! alert does not wait for the seconds (a clock that stands still cannot
//! hold it back).
//!
//! The health lives in the store's local meta, never in a server record.

use std::collections::BTreeMap;

use crate::repo::{Repository, Use, seen};
use crate::store::{RecordKind, RecordStore};
use crate::sync::{SyncStore, VaultSyncHealth};
use crate::{Error, Id, Result};

impl Repository<SyncStore> {
    /// The sync health of every vault of the store: `Ok` unless a round,
    /// a read or a rebase found the server behind or an alert.
    pub fn sync_health(&self) -> Result<BTreeMap<Id, VaultSyncHealth>> {
        let mut out: BTreeMap<Id, VaultSyncHealth> = self
            .store
            .list(RecordKind::VaultKey)?
            .into_iter()
            .map(|r| (r.id, VaultSyncHealth::Ok))
            .collect();
        for (v, e) in self.store.health()? {
            let health = if e.alert {
                VaultSyncHealth::Alert(e.cause)
            } else {
                VaultSyncHealth::ServerBehind {
                    since: e.since.unwrap_or(0),
                    rounds: e.rounds,
                }
            };
            out.insert(v, health);
        }
        Ok(out)
    }

    /// The end of a sync round (after fetch, rebase and push) at `now`,
    /// Unix seconds: every vault is checked as a read would (`served`: a
    /// server gone back to an older state gets the device's copy queued
    /// again for the next push), then every vault still behind counts one
    /// more round and becomes an alert past the thresholds. The device
    /// state is saved.
    ///
    /// Errors: those of the restore epoch and the vault list (`vaults`),
    /// after the round was counted, and store errors. A vault's integrity
    /// error is not returned: it is its `Alert` health.
    pub fn note_sync_round(&mut self, now: i64) -> Result<()> {
        let checked = self.check_vaults();
        self.store.count_round(now)?;
        self.persist_device_state()?;
        checked
    }

    /// Whether the safe exit "keep this device"
    /// (`issue_restore_epoch_from_local`) has anything to push over the
    /// server's: a fork, a vault in alert, or one the server went back on.
    /// False while the only trouble is another device's newer write not
    /// fully served yet (the rebase settles it; an epoch issued then would
    /// be withdrawn), so the app offers or re-issues the exit only when it
    /// is useful.
    pub fn keep_needed(&self) -> Result<bool> {
        self.store.keep_needed()
    }

    /// Forget the sync health of every vault, after the owner chose to:
    /// each reads `Ok` until the next rounds find it behind again or in
    /// alert (a fork shows again on the next read). Discards no data: the
    /// way out of an unreadable health map (`sync_health` failing with
    /// `Error::Store`) other than taking the server's state. The memory of
    /// cleared vaults goes too.
    pub fn reset_sync_health(&mut self) -> Result<()> {
        self.store.reset_health()
    }

    fn check_vaults(&mut self) -> Result<()> {
        self.sync_epoch()?;
        for vault in self.vaults()? {
            match self.served(&vault, Use::Read) {
                Ok(loaded) => {
                    self.device
                        .last_seen
                        .insert(vault.id, seen(&loaded.manifest));
                }
                Err(Error::Integrity(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
