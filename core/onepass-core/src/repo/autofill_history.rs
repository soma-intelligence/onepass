//! The device's autofill history (`crate::autofill_history`): record an
//! event, read a site's events, the learned bonuses of a site, the switch,
//! clear. Every call is a no-op on a store that keeps no history, so a
//! fill never fails for want of one.

use std::collections::BTreeMap;

use time::OffsetDateTime;

use super::Repository;
use crate::Result;
use crate::autofill_history::{
    AutofillEvent, ClientContext, HistoryKeys, MAX_PER_SITE, MAX_TOTAL, expired,
};
use crate::fill_plan::learned;
use crate::id::Id;
use crate::store::RecordStore;

/// Local meta key of the switch: absent or `[1]` on, `[0]` off.
const SWITCH_KEY: &str = "autofill.history";
/// A full sweep of expired rows every this many appends (by `seq`).
const SWEEP_EVERY: i64 = 128;

impl<S: RecordStore> Repository<S> {
    fn history_keys(&self) -> Result<HistoryKeys> {
        let ikm = self.account.keyset().kem.to_bytes();
        HistoryKeys::derive(&ikm, self.account_id())
    }

    /// Whether the autofill history is on for this device (on by default:
    /// it never leaves the device).
    pub fn autofill_history_enabled(&self) -> Result<bool> {
        if !self.store.keeps_autofill_history() {
            return Ok(false);
        }
        Ok(self.store.local_meta(SWITCH_KEY)?.as_deref() != Some(&[0]))
    }

    /// Turn the history on or off. Off erases it at once.
    pub fn set_autofill_history_enabled(&mut self, on: bool) -> Result<()> {
        if !self.store.keeps_autofill_history() {
            return Ok(());
        }
        if !on {
            self.store.autofill_clear()?;
        }
        self.store.set_local_meta(SWITCH_KEY, Some(&[u8::from(on)]))
    }

    /// Record one event (validated, sealed, filed under its site tag,
    /// trimmed to the caps). Nothing is written while the history is off,
    /// during Travel Mode, or on a store without history: `false`.
    pub fn record_autofill_event(&mut self, ev: AutofillEvent) -> Result<bool> {
        if self.travelling || !self.autofill_history_enabled()? {
            return Ok(false);
        }
        let mut ev = ev.validated()?;
        if ev.device_id.is_none() {
            ev.device_id = self.chain.device_id;
        }
        let keys = self.history_keys()?;
        let tag = keys.site_tag(&ev.site);
        let blob = keys.seal_event(&tag, &ev)?;
        self.store
            .autofill_append(&tag, &blob, MAX_PER_SITE, MAX_TOTAL)?;
        let rows = self.store.autofill_rows(Some(&tag))?;
        if rows
            .last()
            .is_some_and(|(seq, _, _)| seq % SWEEP_EVERY == 0)
        {
            self.prune_autofill_history(ev.at)?;
        }
        Ok(true)
    }

    /// The events of `site` (a registrable domain), oldest first. Rows past
    /// the retention, or that no longer open (another keyset after a
    /// rotation, a damaged row), are deleted on the way.
    pub fn autofill_events_for_site(
        &mut self,
        site: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<AutofillEvent>> {
        if !self.autofill_history_enabled()? {
            return Ok(Vec::new());
        }
        let keys = self.history_keys()?;
        let site = site.trim().to_ascii_lowercase();
        let tag = keys.site_tag(&site);
        let mut out = Vec::new();
        let mut dead = Vec::new();
        for (seq, t, data) in self.store.autofill_rows(Some(&tag))? {
            match keys.open_event(&t, &data) {
                Ok(ev) if ev.site == site && !expired(&ev, now) => out.push(ev),
                _ => dead.push(seq),
            }
        }
        if !dead.is_empty() {
            self.store.autofill_delete(&dead)?;
        }
        Ok(out)
    }

    /// The learned bonus of each item on `site` for a plan made in
    /// `client` (`fill_plan::learned::affinity`); empty while the history
    /// is off. Travel Mode: empty too.
    pub fn autofill_affinity(
        &mut self,
        site: &str,
        client: &ClientContext,
        now: OffsetDateTime,
    ) -> Result<BTreeMap<Id, i64>> {
        if self.travelling {
            return Ok(BTreeMap::new());
        }
        let events = self.autofill_events_for_site(site, now)?;
        Ok(learned::affinity(&events, client, now))
    }

    /// Delete every row past the retention or that no longer opens: how
    /// many went.
    pub fn prune_autofill_history(&mut self, now: OffsetDateTime) -> Result<usize> {
        if !self.store.keeps_autofill_history() {
            return Ok(0);
        }
        let keys = self.history_keys()?;
        let dead: Vec<i64> = self
            .store
            .autofill_rows(None)?
            .into_iter()
            .filter(|(_, t, data)| !keys.open_event(t, data).is_ok_and(|e| !expired(&e, now)))
            .map(|(seq, _, _)| seq)
            .collect();
        if !dead.is_empty() {
            self.store.autofill_delete(&dead)?;
        }
        Ok(dead.len())
    }

    /// Erase the whole history of this device: how many events went.
    pub fn clear_autofill_history(&mut self) -> Result<usize> {
        if !self.store.keeps_autofill_history() {
            return Ok(0);
        }
        self.store.autofill_clear()
    }

    /// Erase the events of one site (with "forget this site").
    pub fn forget_autofill_site(&mut self, site: &str) -> Result<usize> {
        if !self.store.keeps_autofill_history() {
            return Ok(0);
        }
        let tag = self
            .history_keys()?
            .site_tag(&site.trim().to_ascii_lowercase());
        let seqs: Vec<i64> = self
            .store
            .autofill_rows(Some(&tag))?
            .into_iter()
            .map(|(seq, _, _)| seq)
            .collect();
        self.store.autofill_delete(&seqs)?;
        Ok(seqs.len())
    }

    /// How many events the device keeps (for the settings screen).
    pub fn autofill_history_count(&self) -> Result<usize> {
        if !self.store.keeps_autofill_history() {
            return Ok(0);
        }
        Ok(self.store.autofill_rows(None)?.len())
    }
}
