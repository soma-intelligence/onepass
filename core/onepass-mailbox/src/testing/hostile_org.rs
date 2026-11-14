//! `HostileOrgStore`: a wrapper over any `OrgStoreApi` that lies on reads.
//!
//! It stands for a malicious or broken org mailbox server: it withholds the
//! newest roster, replays an older one, forks a roster or a lineage record,
//! truncates the lineage, hides join requests. Writes always pass through
//! unchanged (a server that refuses writes is `FaultHandle::fail_next`).
//! Lies stay armed until `honest()`.
//!
//! This serves plan C's VaultKit-level tests; plan B never needs it.
//!
//! Precedence when lies conflict, for `latest_roster`: a `fork_roster` at a
//! seq at or above the honest newest wins (the highest such seq), then
//! `replay_roster`, then `withhold_newest_roster`, then the honest answer.
//! `replay_roster` serves the inner store's honest bytes when the fork seq
//! is below the honest newest; at or above the newest the fork wins.
//! `roster(seq)` answers a forked seq's bytes first, otherwise the inner
//! store's. `lineage_from` applies `withhold_lineage_from` first (so a fork
//! at or past the withheld generation is never served), then
//! `fork_lineage` on the generations still returned; a fork on a generation
//! that `lineage_from` does not return is ignored. Each `fork_*` and
//! `drop_join_request` call with the same key replaces the earlier one.

use std::collections::{BTreeMap, BTreeSet};

use crate::org::{JoinFeedDelta, JoinRequest, OrgStoreApi, OrgStoreError};
use crate::{ChangeFeed, MailboxApi};

/// An org store that lies on reads. See the module doc.
pub struct HostileOrgStore<S: OrgStoreApi> {
    inner: S,
    withhold_newest: bool,
    replay: Option<u64>,
    forked_rosters: BTreeMap<u64, Vec<u8>>,
    forked_lineage: BTreeMap<u64, Vec<u8>>,
    lineage_cut: Option<u64>,
    dropped_joins: BTreeSet<[u8; 16]>,
    drop_all_joins: bool,
}

impl<S: OrgStoreApi> HostileOrgStore<S> {
    /// Honest until a lie is armed.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            withhold_newest: false,
            replay: None,
            forked_rosters: BTreeMap::new(),
            forked_lineage: BTreeMap::new(),
            lineage_cut: None,
            dropped_joins: BTreeSet::new(),
            drop_all_joins: false,
        }
    }

    /// The honest store underneath, for seeding and for checking writes.
    pub fn inner(&mut self) -> &mut S {
        &mut self.inner
    }

    /// latest_roster answers the roster before the newest (None when there is one).
    pub fn withhold_newest_roster(&mut self) {
        self.withhold_newest = true;
    }

    /// latest_roster answers (seq, roster(seq)) of this older seq.
    pub fn replay_roster(&mut self, seq: u64) {
        self.replay = Some(seq);
    }

    /// roster(seq) answers `bytes`; latest_roster answers (seq, bytes) when seq >= the honest newest.
    pub fn fork_roster(&mut self, seq: u64, bytes: Vec<u8>) {
        self.forked_rosters.insert(seq, bytes);
    }

    /// lineage_from serves `bytes` at `generation` in place of the stored record.
    pub fn fork_lineage(&mut self, generation: u64, bytes: Vec<u8>) {
        self.forked_lineage.insert(generation, bytes);
    }

    /// lineage_from stops before `generation` (withholds it and every later one).
    pub fn withhold_lineage_from(&mut self, generation: u64) {
        self.lineage_cut = Some(generation);
    }

    /// join_requests leaves out this account's request.
    pub fn drop_join_request(&mut self, account_id: [u8; 16]) {
        self.dropped_joins.insert(account_id);
    }

    /// join_requests (and the `upserts` of join_requests_since) answer empty.
    pub fn drop_all_join_requests(&mut self) {
        self.drop_all_joins = true;
    }

    /// Disarms every lie.
    pub fn honest(&mut self) {
        self.withhold_newest = false;
        self.replay = None;
        self.forked_rosters.clear();
        self.forked_lineage.clear();
        self.lineage_cut = None;
        self.dropped_joins.clear();
        self.drop_all_joins = false;
    }
}

impl<S: OrgStoreApi> OrgStoreApi for HostileOrgStore<S> {
    fn put_lineage(&mut self, generation: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError> {
        self.inner.put_lineage(generation, bytes)
    }

    fn lineage_from(&mut self, generation: u64) -> Result<Vec<(u64, Vec<u8>)>, OrgStoreError> {
        let mut out = self.inner.lineage_from(generation)?;
        if let Some(cut) = self.lineage_cut {
            out.retain(|(g, _)| *g < cut);
        }
        for (g, bytes) in &mut out {
            if let Some(fork) = self.forked_lineage.get(g) {
                bytes.clone_from(fork);
            }
        }
        Ok(out)
    }

    fn put_roster(&mut self, seq: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError> {
        self.inner.put_roster(seq, bytes)
    }

    fn roster(&mut self, seq: u64) -> Result<Option<Vec<u8>>, OrgStoreError> {
        if let Some(fork) = self.forked_rosters.get(&seq) {
            return Ok(Some(fork.clone()));
        }
        self.inner.roster(seq)
    }

    fn latest_roster(&mut self) -> Result<Option<(u64, Vec<u8>)>, OrgStoreError> {
        let honest = self.inner.latest_roster()?;
        let newest = honest.as_ref().map_or(0, |(seq, _)| *seq);
        if let Some((seq, bytes)) = self.forked_rosters.iter().next_back()
            && *seq >= newest
        {
            return Ok(Some((*seq, bytes.clone())));
        }
        if let Some(seq) = self.replay {
            return Ok(self.inner.roster(seq)?.map(|b| (seq, b)));
        }
        if self.withhold_newest {
            let Some((seq, _)) = honest else {
                return Ok(None);
            };
            return match seq.checked_sub(1) {
                Some(prev) => Ok(self.inner.roster(prev)?.map(|b| (prev, b))),
                _ => Ok(None),
            };
        }
        Ok(honest)
    }

    fn put_owner_keyset(
        &mut self,
        account_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<(), OrgStoreError> {
        self.inner.put_owner_keyset(account_id, bytes)
    }

    fn owner_keyset(&mut self, account_id: [u8; 16]) -> Result<Option<Vec<u8>>, OrgStoreError> {
        self.inner.owner_keyset(account_id)
    }

    fn put_join_request(
        &mut self,
        account_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<(), OrgStoreError> {
        self.inner.put_join_request(account_id, bytes)
    }

    fn join_requests(&mut self) -> Result<Vec<JoinRequest>, OrgStoreError> {
        if self.drop_all_joins {
            return Ok(Vec::new());
        }
        let mut out = self.inner.join_requests()?;
        out.retain(|(account, _)| !self.dropped_joins.contains(account));
        Ok(out)
    }

    /// The inner feed with the drop rules applied to `upserts`. A dropped
    /// request is left out of `upserts` and not added to `removed`; the
    /// cursor still moves past it, as for a server that hides it.
    fn join_requests_since(
        &mut self,
        feed: &mut ChangeFeed,
    ) -> Result<JoinFeedDelta, OrgStoreError> {
        let mut delta = self.inner.join_requests_since(feed)?;
        if self.drop_all_joins {
            delta.upserts.clear();
        } else {
            delta
                .upserts
                .retain(|(account, _)| !self.dropped_joins.contains(account));
        }
        Ok(delta)
    }

    fn delete_join_request(&mut self, account_id: [u8; 16]) -> Result<(), OrgStoreError> {
        self.inner.delete_join_request(account_id)
    }

    fn mailbox(&self) -> &dyn MailboxApi {
        self.inner.mailbox()
    }

    fn create_member_invite(&mut self, ttl_hours: u16) -> Result<Vec<u8>, OrgStoreError> {
        self.inner.create_member_invite(ttl_hours)
    }
}
