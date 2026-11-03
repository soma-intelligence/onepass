//! The sync round in Rust (cross-platform spec 4.14): `round()`,
//! `fetchAll`, `rebaseIfUnlocked`, `sendPending`, `ordered` and `split` of
//! `SyncCoordinator.swift`, in the same order and with the same rules, over
//! any `Transport`.
//!
//! A round: bind (a server state other than the one the store holds resets
//! the local zone), then up to `MAX_TURNS` turns of: every page from the
//! stored cursor (each page staged, then its cursor saved), one
//! `commit_remote` and `finish_full_fetch` after the last page; the rebase
//! when unlocked; the `SyncHome` check; then every pending change as one
//! atomic batch (split only past the transport's limits, items before their
//! manifest), `mark_pushed` for each saved change. A conflict stages the
//! server's row and starts another turn. A device in the middle of its own
//! key rotation pushes its phases in order (`push_rotation_phase`).
//!
//! `SyncDriver::for_zone` runs the same round on one shared zone (sharing
//! plan 4, Task 1): the `_in` methods of the store, the meta keys
//! `zone.<zone key hex>.cursor` and `.incarnation`, no `SyncHome` check
//! and no sync health (the private round counts those), the share push
//! phases (`push_share_phase`) in place of the rotation phases, and the
//! pending order of `pending_changes_in` kept as the store gives it (the
//! shared push order is the core's).
//!
//! The driver runs one round at a time on the calling thread; scheduling
//! (debounce, wake, retry timers) belongs to the app, which reads
//! `RoundReport::retry_after` and `rerun`.

use std::collections::BTreeSet;
use std::time::Duration;

use onepass_core::repo::Repository;
use onepass_core::store::{RecordKind, RecordStore, Zone};
use onepass_core::sync::{Change, RebaseReport, SyncStore, VaultSyncHealth};
use onepass_core::synchome::{SyncBackend, SyncHomeBody};
use onepass_core::trust::DeviceLineageState;
use onepass_core::{Error, Id, IntegrityError};

use crate::policy::{
    CURSOR_KEY, INCARNATION_KEY, MAX_PHASES_PER_ROUND, MAX_QUICK_CONFLICT_ROUNDS, MAX_RESETS,
    MAX_TURNS, UNREADABLE_ROUNDS_BEFORE_REPORT, ordered, retry_delay, split,
};
use crate::transport::{Outgoing, SendResult, Transport, TransportError};

/// What an unlocked session lends the round.
pub trait RoundHooks {
    fn rebase(&mut self) -> onepass_core::Result<RebaseReport>;
    /// Counts the round for the sync health, then reads it.
    fn note_round(&mut self, now: i64) -> onepass_core::Result<Vec<(Id, VaultSyncHealth)>>;
    /// The sync health, without counting a round.
    fn health(&mut self) -> onepass_core::Result<Vec<(Id, VaultSyncHealth)>>;
    /// The safe exit "keep this device": the epoch number.
    fn keep_this_device(&mut self) -> onepass_core::Result<u64>;
    /// Where the account syncs, verified and pinned.
    fn sync_home(&mut self) -> onepass_core::Result<Option<SyncHomeBody>>;
}

impl RoundHooks for Repository<SyncStore> {
    fn rebase(&mut self) -> onepass_core::Result<RebaseReport> {
        self.rebase_report()
    }

    fn note_round(&mut self, now: i64) -> onepass_core::Result<Vec<(Id, VaultSyncHealth)>> {
        self.note_sync_round(now)?;
        Ok(self.sync_health()?.into_iter().collect())
    }

    fn health(&mut self) -> onepass_core::Result<Vec<(Id, VaultSyncHealth)>> {
        Ok(self.sync_health()?.into_iter().collect())
    }

    fn keep_this_device(&mut self) -> onepass_core::Result<u64> {
        Ok(self
            .issue_restore_epoch_from_local(onepass_core::epoch::EpochReason::KeepThisDevice)?
            .epoch)
    }

    fn sync_home(&mut self) -> onepass_core::Result<Option<SyncHomeBody>> {
        Repository::sync_home(self)
    }
}

/// How a round ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundStatus {
    /// Everything sent and fetched, every vault `Ok`.
    Idle,
    /// The server could not be reached.
    Offline,
    /// The server was busy, or a record stayed unreadable: retried later.
    Retrying,
    /// The server refused the request as stale: this device's clock is off.
    ClockSkew,
    /// A vault the server is behind on, or a safe exit not settled yet.
    WaitingForServer,
    /// Integrity refused the server's data (`kind` as the FFI names it).
    Refused { kind: String },
    /// Conflicts were left after every turn.
    Unsettled,
    /// A record stayed unreadable for `UNREADABLE_ROUNDS_BEFORE_REPORT`
    /// rounds in a row.
    Unreadable,
    /// The account's signed `SyncHome` names another place: nothing was
    /// sent, the app asks the user before it follows.
    HomeMoved(SyncBackend),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundReport {
    pub status: RoundStatus,
    /// Remote changes were applied, or a rebase changed vaults: reload.
    pub changed: bool,
    pub rebased: Vec<Id>,
    /// Run the next round after this delay.
    pub retry_after: Option<Duration>,
    /// Run the next round at once.
    pub rerun: bool,
}

/// Why the turns of a round stopped early.
enum Stop {
    Transport(TransportError),
    Unsettled,
    Integrity(String),
    HomeMoved(SyncBackend),
    Core,
}

impl From<TransportError> for Stop {
    fn from(e: TransportError) -> Self {
        Stop::Transport(e)
    }
}

impl From<Error> for Stop {
    fn from(e: Error) -> Self {
        match e {
            Error::Integrity(i) => Stop::Integrity(integrity_kind(i)),
            _ => Stop::Core,
        }
    }
}

/// The FFI's name of an integrity error: its variant in snake case
/// (`ManifestRollback`: `manifest_rollback`).
pub fn integrity_kind(e: IntegrityError) -> String {
    let mut out = String::new();
    for (i, c) in format!("{e:?}").chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// What one round gathered on the way.
#[derive(Default)]
struct Round {
    changed: bool,
    rebased: Vec<Id>,
    epoch_withdrawn: bool,
}

/// See the module doc.
pub struct SyncDriver<T: Transport> {
    transport: T,
    zone: Zone,
    /// The account's sync home (private zone only): a signed `SyncHome`
    /// naming anything else stops the round.
    home: Option<SyncBackend>,
    cursor_key: String,
    incarnation_key: String,
    /// The transport error that ended the last round, if one did.
    last_error: Option<TransportError>,
    retry_attempt: u32,
    unreadable_rounds: u32,
    conflict_rounds: u32,
    /// Kind of the last integrity refusal of a rebase, until one succeeds.
    refusal: Option<String>,
    /// The last sync health read (unlocked rounds only).
    health: Vec<(Id, VaultSyncHealth)>,
    /// The last `SyncHome` an unlocked round read, for the locked ones.
    last_home: Option<SyncHomeBody>,
    /// A safe exit was issued and is followed until every vault is `Ok`.
    safe_exit: bool,
    /// The safe exit was "keep this device".
    safe_exit_keep: bool,
    /// `keep_this_device` was withdrawn: issue it again after a clean
    /// rebase.
    keep_reissue: bool,
}

impl<T: Transport> SyncDriver<T> {
    /// A driver for an account whose sync home is `home`: a signed
    /// `SyncHome` naming anything else stops the round.
    pub fn new(transport: T, home: SyncBackend) -> Self {
        let mut d = SyncDriver::for_zone(transport, Zone::Private);
        d.home = Some(home);
        d
    }

    /// A driver for `zone` (a shared zone, or the private zone without a
    /// home check).
    pub fn for_zone(transport: T, zone: Zone) -> Self {
        let (cursor_key, incarnation_key) = if zone.is_shared() {
            let hex: String = zone.key().iter().map(|b| format!("{b:02x}")).collect();
            (
                format!("zone.{hex}.cursor"),
                format!("zone.{hex}.incarnation"),
            )
        } else {
            (CURSOR_KEY.to_string(), INCARNATION_KEY.to_string())
        };
        SyncDriver {
            transport,
            zone,
            home: None,
            cursor_key,
            incarnation_key,
            last_error: None,
            retry_attempt: 0,
            unreadable_rounds: 0,
            conflict_rounds: 0,
            refusal: None,
            health: Vec::new(),
            last_home: None,
            safe_exit: false,
            safe_exit_keep: false,
            keep_reissue: false,
        }
    }

    pub fn zone(&self) -> Zone {
        self.zone
    }

    /// The store meta key of this driver's change cursor.
    pub fn cursor_key(&self) -> &str {
        &self.cursor_key
    }

    /// The transport error that ended the last round (`None`: the last
    /// round reached the server, or ended for another reason).
    pub fn last_error(&self) -> Option<&TransportError> {
        self.last_error.as_ref()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// The last sync health an unlocked round read.
    pub fn health(&self) -> &[(Id, VaultSyncHealth)] {
        &self.health
    }

    /// The session issued a safe exit's epoch: the rounds follow it until
    /// every vault is `Ok` (`WaitingForServer` meanwhile).
    pub fn safe_exit_issued(&mut self, keep_this_device: bool) {
        self.safe_exit = true;
        self.safe_exit_keep = keep_this_device;
        self.keep_reissue = false;
        self.conflict_rounds = 0;
        self.refusal = None;
    }

    /// One round. `hooks`: the unlocked session, `None` while locked (the
    /// fetch and the send still run, held vaults send nothing). `now`: Unix
    /// seconds, for the sync health.
    pub fn run_round(
        &mut self,
        store: &mut SyncStore,
        mut hooks: Option<&mut dyn RoundHooks>,
        now: i64,
    ) -> RoundReport {
        let mut round = Round::default();
        let result = self.turns(store, &mut hooks, &mut round);
        self.last_error = match &result {
            Err(Stop::Transport(e)) => Some(e.clone()),
            _ => None,
        };
        let mut retry_after = None;
        let mut rerun = false;
        let status = match result {
            Ok(()) => {
                self.retry_attempt = 0;
                self.unreadable_rounds = 0;
                self.note_round(&mut hooks, now);
                let status = self.status_after_round(round.epoch_withdrawn);
                if round.epoch_withdrawn {
                    self.conflict_rounds += 1;
                    if self.conflict_rounds <= MAX_QUICK_CONFLICT_ROUNDS {
                        rerun = true;
                    } else {
                        retry_after = Some(self.next_delay());
                    }
                } else {
                    self.conflict_rounds = 0;
                }
                status
            }
            Err(Stop::Transport(TransportError::Offline)) => {
                retry_after = Some(self.next_delay());
                RoundStatus::Offline
            }
            Err(Stop::Transport(TransportError::Retryable { after })) => {
                retry_after = Some(after.unwrap_or_else(|| self.next_delay()));
                RoundStatus::Retrying
            }
            Err(Stop::Transport(TransportError::Stale)) => {
                retry_after = Some(self.next_delay());
                RoundStatus::ClockSkew
            }
            Err(Stop::Transport(TransportError::RecordUnreadable)) => {
                self.unreadable_rounds += 1;
                retry_after = Some(self.next_delay());
                if self.unreadable_rounds >= UNREADABLE_ROUNDS_BEFORE_REPORT {
                    RoundStatus::Unreadable
                } else {
                    RoundStatus::Retrying
                }
            }
            Err(Stop::Transport(
                TransportError::ZoneReset
                | TransportError::Other(_)
                | TransportError::Quota
                | TransportError::Revoked,
            ))
            | Err(Stop::Core) => {
                retry_after = Some(self.next_delay());
                RoundStatus::Retrying
            }
            Err(Stop::Unsettled) => {
                retry_after = Some(self.next_delay());
                RoundStatus::Unsettled
            }
            Err(Stop::Integrity(kind)) => {
                self.refusal = Some(kind.clone());
                RoundStatus::Refused { kind }
            }
            Err(Stop::HomeMoved(backend)) => RoundStatus::HomeMoved(backend),
        };
        RoundReport {
            status,
            changed: round.changed,
            rebased: round.rebased,
            retry_after,
            rerun,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let d = retry_delay(self.retry_attempt);
        self.retry_attempt = self.retry_attempt.saturating_add(1);
        d
    }

    fn turns(
        &mut self,
        store: &mut SyncStore,
        hooks: &mut Option<&mut dyn RoundHooks>,
        round: &mut Round,
    ) -> Result<(), Stop> {
        self.bind(store, false)?;
        let mut turn = 0;
        let mut resets = 0;
        loop {
            match self.turn(store, hooks, round) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    turn += 1;
                    if turn >= MAX_TURNS {
                        return Err(Stop::Unsettled);
                    }
                }
                Err(Stop::Transport(TransportError::ZoneReset)) => {
                    // The server lost its data: forget its tags and the
                    // cursor, then fetch from scratch; what it lacks is
                    // queued after that fetch. Each reset restarts the
                    // turn count; the third ends the round unsettled.
                    resets += 1;
                    if resets > MAX_RESETS {
                        return Err(Stop::Unsettled);
                    }
                    self.bind(store, true)?;
                    turn = 0;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Binds the store to the server state: the first round with a store
    /// that holds an account queues what the server lacks (a zone reset);
    /// another incarnation than the stored one resets the zone. `reset`:
    /// the server just said it lost its data.
    fn bind(&mut self, store: &mut SyncStore, reset: bool) -> Result<(), Stop> {
        let incarnation = self.transport.binding()?;
        let stored = store
            .meta(&self.incarnation_key)?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes);
        let shared = self.zone.is_shared();
        let reset = match stored {
            Some(s) => reset || s != incarnation,
            None => reset || (!shared && store.has_account()?),
        };
        if reset {
            if shared {
                // Ruling (plan 4 Task 1): a zone whose mailbox lost its
                // data is fetched from scratch; the core has no zoned
                // requeue, so rows only this device held are not sent
                // again (pending writes still are).
                store.set_meta(&self.cursor_key, &[])?;
                store.begin_full_fetch_in(self.zone)?;
            } else {
                store.begin_zone_reset(CURSOR_KEY)?;
            }
        }
        if reset || stored != Some(incarnation) {
            store.set_meta(&self.incarnation_key, &incarnation.to_be_bytes())?;
        }
        Ok(())
    }

    /// Fetch, rebase, home check, send. `Ok(true)`: nothing left to retry.
    fn turn(
        &mut self,
        store: &mut SyncStore,
        hooks: &mut Option<&mut dyn RoundHooks>,
        round: &mut Round,
    ) -> Result<bool, Stop> {
        self.fetch_all(store, round)?;
        self.rebase(hooks, round)?;
        self.check_home(hooks)?;
        self.send_all(store)
    }

    /// Every page from the stored cursor (see `SyncCoordinator.fetchAll`):
    /// each page staged, then its cursor saved; one `commit_remote` and
    /// `finish_full_fetch` after the last page. A change whose server meta
    /// is the one stored (this device's own push coming back) is not
    /// staged, except a manifest, which then is no remote change.
    fn fetch_all(&mut self, store: &mut SyncStore, round: &mut Round) -> Result<(), Stop> {
        let zone = self.zone;
        let mut cursor = store.meta(&self.cursor_key)?.filter(|c| !c.is_empty());
        if cursor.is_none() {
            store.begin_full_fetch_in(zone)?;
        }
        let mut changed = 0usize;
        let mut echoed: BTreeSet<Id> = BTreeSet::new();
        loop {
            let page = self.transport.fetch(cursor.as_deref())?;
            if page.restarted_from_scratch {
                store.begin_full_fetch_in(zone)?;
            }
            for change in page.changes {
                let known = store.server_meta_in(zone, change.kind, change.id)?;
                if change.data.is_some() {
                    if change.server_meta.is_some() && known == change.server_meta {
                        if change.kind != RecordKind::Manifest {
                            continue;
                        }
                        echoed.insert(change.id);
                        store.stage_remote_in(zone, change)?;
                        continue;
                    }
                    changed += 1;
                } else if known.is_some() {
                    changed += 1;
                }
                store.stage_remote_in(zone, change)?;
            }
            if let Some(next) = page.cursor {
                store.set_meta(&self.cursor_key, &next)?;
                cursor = Some(next);
            }
            if !page.more {
                break;
            }
            if cursor.is_none() {
                // More pages without a cursor would fetch the same page
                // forever.
                return Err(TransportError::Retryable { after: None }.into());
            }
        }
        let vaults = store.commit_remote_in(zone)?;
        // A shared zone settles a fetch from scratch in `commit_remote_in`.
        let dropped = if zone.is_shared() {
            false
        } else {
            store.finish_full_fetch()?
        };
        if changed > 0 || vaults.iter().any(|v| !echoed.contains(v)) || dropped {
            round.changed = true;
        }
        Ok(())
    }

    /// Unlocked only (see `SyncCoordinator.rebaseIfUnlocked`): the vaults
    /// rebased count even when an error follows; an integrity error sets
    /// the refusal and the round goes on; a withdrawn epoch is followed.
    fn rebase(
        &mut self,
        hooks: &mut Option<&mut dyn RoundHooks>,
        round: &mut Round,
    ) -> Result<(), Stop> {
        let Some(h) = hooks.as_deref_mut() else {
            return Ok(());
        };
        let report = h.rebase()?;
        if !report.rebased.is_empty() {
            round.changed = true;
            round.rebased.extend(report.rebased);
        }
        match report.error {
            None => {
                self.refusal = None;
                if self.keep_reissue {
                    self.keep_reissue = false;
                    // Every vault `Ok`: the server converged without it.
                    let troubled = h.health()?.iter().any(|(_, s)| *s != VaultSyncHealth::Ok);
                    if troubled {
                        h.keep_this_device()?;
                    }
                }
            }
            Some(Error::Conflict) => {
                round.epoch_withdrawn = true;
                if self.safe_exit_keep {
                    self.keep_reissue = true;
                }
            }
            Some(Error::Integrity(i)) => self.refusal = Some(integrity_kind(i)),
            Some(e) => return Err(e.into()),
        }
        Ok(())
    }

    /// The account's signed `SyncHome` (unlocked; the last one read while
    /// locked) must name this driver's home.
    fn check_home(&mut self, hooks: &mut Option<&mut dyn RoundHooks>) -> Result<(), Stop> {
        if self.home.is_none() {
            return Ok(());
        }
        if let Some(h) = hooks.as_deref_mut() {
            self.last_home = h.sync_home()?;
        }
        let Some(mine) = &self.home else {
            return Ok(());
        };
        match &self.last_home {
            Some(home) if home.backend != *mine => Err(Stop::HomeMoved(home.backend.clone())),
            _ => Ok(()),
        }
    }

    /// Pending changes, then the phases of this device's own rotation in
    /// order: each phase's writes are sent, then settled
    /// (`push_rotation_phase`), at most `MAX_PHASES_PER_ROUND` a round.
    fn send_all(&mut self, store: &mut SyncStore) -> Result<bool, Stop> {
        if !self.resend_lost(store)? {
            return Ok(false);
        }
        let mut phases = 0;
        loop {
            if !self.send_pending(store)? {
                return Ok(false);
            }
            if self.zone.is_shared() {
                // A resealing pushed in this zone moves to its next phase
                // once the writes of the current one are confirmed.
                if phases >= MAX_PHASES_PER_ROUND {
                    return Ok(true);
                }
                phases += 1;
                if store.push_share_phase(self.zone)? == onepass_core::sync::PhaseOutcome::Retry {
                    return Ok(true);
                }
                continue;
            }
            let phase = match store.trust_state()?.map(|t| t.state) {
                Some(DeviceLineageState::Rotating { phase }) => phase,
                _ => return Ok(true),
            };
            if phases >= MAX_PHASES_PER_ROUND {
                return Ok(true);
            }
            phases += 1;
            if store.push_rotation_phase(phase)? == onepass_core::sync::PhaseOutcome::Retry {
                return Ok(false);
            }
        }
    }

    /// The local copy of the writes the server answered as saved and never
    /// served (`Transport::unconfirmed`), sent again as new writes: the
    /// server holds nothing under the key (a conflict means it does; its
    /// row is staged as for any conflict). A key with a pending change goes
    /// with the pending ones.
    fn resend_lost(&mut self, store: &mut SyncStore) -> Result<bool, Stop> {
        let lost = self.transport.unconfirmed();
        if lost.is_empty() {
            return Ok(true);
        }
        let zone = self.zone;
        let pending: BTreeSet<(RecordKind, Id)> = store
            .pending_changes_in(zone)?
            .into_iter()
            .map(|c| (c.kind, c.id))
            .collect();
        let mut outgoing = Vec::new();
        for (kind, id) in lost {
            if pending.contains(&(kind, id)) {
                continue;
            }
            let rec = if zone.is_shared() {
                store.get_in(zone, kind, id)?
            } else {
                RecordStore::get(store, kind, id)?
            };
            if let Some(rec) = rec {
                outgoing.push(Outgoing {
                    change: Change {
                        kind,
                        id,
                        version: rec.version,
                        data: Some(rec.data),
                    },
                    server_meta: None,
                });
            }
        }
        let limits = self.transport.limits();
        let mut settled = true;
        for batch in split(self.order(outgoing), limits.max_records, limits.max_bytes) {
            settled &= self.send(store, &batch)?;
        }
        Ok(settled)
    }

    /// The private zone's batch order (`ordered`); a shared zone keeps the
    /// store's push order (`pending_changes_in`).
    fn order(&self, outgoing: Vec<Outgoing>) -> Vec<Outgoing> {
        if self.zone.is_shared() {
            outgoing
        } else {
            ordered(outgoing)
        }
    }

    /// Every pending change, as one batch unless the limits force a split.
    /// `false` at the first batch not fully saved.
    fn send_pending(&mut self, store: &mut SyncStore) -> Result<bool, Stop> {
        let zone = self.zone;
        let mut outgoing = Vec::new();
        for change in store.pending_changes_in(zone)? {
            let server_meta = store.server_meta_in(zone, change.kind, change.id)?;
            outgoing.push(Outgoing {
                change,
                server_meta,
            });
        }
        if outgoing.is_empty() {
            return Ok(true);
        }
        let limits = self.transport.limits();
        for batch in split(self.order(outgoing), limits.max_records, limits.max_bytes) {
            if !self.send(store, &batch)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// One batch: `mark_pushed` for each saved change, the server's rows of
    /// the conflicts staged (committed by the next fetch). A write saved
    /// without server meta counts as not saved.
    fn send(&mut self, store: &mut SyncStore, batch: &[Outgoing]) -> Result<bool, Stop> {
        let results = self.transport.send(batch)?;
        let mut settled = results.len() >= batch.len();
        for result in results {
            match result {
                SendResult::Saved {
                    kind,
                    id,
                    server_meta,
                } => {
                    let Some(o) = batch
                        .iter()
                        .find(|o| o.change.kind == kind && o.change.id == id)
                    else {
                        continue;
                    };
                    if o.change.data.is_some() && server_meta.is_none() {
                        settled = false;
                    } else {
                        store.mark_pushed_in(self.zone, kind, id, o.change.version, server_meta)?;
                    }
                }
                SendResult::Conflict(server) => {
                    store.stage_remote(server)?;
                    settled = false;
                }
                SendResult::Failed { .. } => settled = false,
            }
        }
        Ok(settled)
    }

    /// The end of a complete round (unlocked): count it, read the health.
    /// An integrity error is a refusal; other errors keep the last health.
    fn note_round(&mut self, hooks: &mut Option<&mut dyn RoundHooks>, now: i64) {
        if self.zone.is_shared() {
            return;
        }
        let Some(h) = hooks.as_deref_mut() else {
            return;
        };
        match h.note_round(now) {
            Ok(health) => self.health = health,
            Err(Error::Integrity(i)) => self.refusal = Some(integrity_kind(i)),
            Err(_) => {}
        }
    }

    /// See `SyncCoordinator.statusAfterRound`.
    fn status_after_round(&mut self, epoch_withdrawn: bool) -> RoundStatus {
        if let Some(kind) = &self.refusal {
            return RoundStatus::Refused { kind: kind.clone() };
        }
        let alert = self.health.iter().find_map(|(_, s)| match s {
            VaultSyncHealth::Alert(e) => Some(*e),
            _ => None,
        });
        if let Some(e) = alert {
            return if self.keep_reissue || epoch_withdrawn {
                RoundStatus::WaitingForServer
            } else {
                RoundStatus::Refused {
                    kind: integrity_kind(e),
                }
            };
        }
        let all_ok = self.health.iter().all(|(_, s)| *s == VaultSyncHealth::Ok);
        if all_ok && !self.keep_reissue && !epoch_withdrawn {
            self.safe_exit = false;
            self.safe_exit_keep = false;
        }
        if !all_ok || self.safe_exit {
            return RoundStatus::WaitingForServer;
        }
        RoundStatus::Idle
    }
}
