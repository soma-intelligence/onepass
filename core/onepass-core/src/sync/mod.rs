//! Offline-first sync support: a layered local store that sits between the
//! `Repository` and a remote (CloudKit). The `Repository` stays synchronous
//! and unaware of the network; see `store` for the layers.

mod health;
mod rebase;
mod store;

pub use rebase::RebaseReport;
pub use store::{
    AccountState, DroppedVaultWrites, IgnoredDeletion, MAX_IGNORED_DELETIONS, SyncStore,
};

use crate::store::RecordKind;
use crate::{Id, IntegrityError};

/// Sync rounds a vault may stay `ServerBehind` before it is an alert (with
/// `STALE_ALERT_SECONDS`; both must be reached).
pub const STALE_ALERT_ROUNDS: u32 = 5;

/// Seconds a vault may stay `ServerBehind` before it is an alert (with
/// `STALE_ALERT_ROUNDS`; both must be reached).
pub const STALE_ALERT_SECONDS: i64 = 600;

/// Rounds after which a vault still behind is an alert whatever the clock
/// says (with `STALE_ALERT_ROUNDS`): a wrong clock cannot delay the alert
/// past this many rounds.
pub const STALE_ALERT_MAX_ROUNDS: u32 = 50;

/// Clean rounds in a row (the server serves a state at least as new as the
/// device's copy, nothing left to confirm) before a vault behind is `Ok`
/// again. A store that alternates the good state and an old one never gets
/// there, and the alert count keeps running.
pub const STALE_CLEAR_ROUNDS: u32 = 3;

/// Rounds a vault cleared after `STALE_CLEAR_ROUNDS` clean rounds keeps the
/// count of its last stretch behind (`since`, rounds): found behind again
/// within them, it resumes that count instead of starting over, so a store
/// that rolls back once every `STALE_CLEAR_ROUNDS + 1` rounds still reaches
/// the alert. An alert is remembered too: found behind again within the
/// window, the vault is an alert at once.
///
/// Evasion bound: a store that serves an old state for one round, then
/// the good one for `STALE_CLEAR_ROUNDS + STALE_MEMORY_ROUNDS` rounds (one
/// behind round every `STALE_CLEAR_ROUNDS + STALE_MEMORY_ROUNDS + 1` = 24
/// rounds), or for up to `STALE_ALERT_ROUNDS - 1` rounds in a row with the
/// same gap (4 rounds in 27, about 15% of the time), never reaches the
/// alert. Meanwhile the device serves its verified copy and pushes it
/// back, so no data is lost or replaced; only the warning is missed.
pub const STALE_MEMORY_ROUNDS: u32 = 20;

const _: () = assert!(STALE_MEMORY_ROUNDS <= 255, "stored in one byte");

/// The sync state of one vault (`Repository::sync_health`). Not an
/// integrity error by itself: only `Alert` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultSyncHealth {
    /// The server serves a state at least as new as the device's copy.
    Ok,
    /// The server serves an older or incomplete state: the device serves
    /// its own verified copy and sends it again. `since`: Unix seconds of
    /// the first sync round that counted it (0 until one did); `rounds`:
    /// rounds counted since (`Repository::note_sync_round`).
    ServerBehind { since: i64, rounds: u32 },
    /// The server stayed behind for `STALE_ALERT_ROUNDS` rounds and
    /// `STALE_ALERT_SECONDS`, or serves a fork the rebase cannot merge, or
    /// the device has no verified copy to serve.
    Alert(IntegrityError),
}

/// Largest record `data` the store accepts, kept under the CloudKit record
/// size limit.
pub const MAX_RECORD_BYTES: usize = 900 * 1024;

/// A local write waiting to be pushed. `data: None` is a deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: RecordKind,
    pub id: Id,
    pub version: u64,
    pub data: Option<Vec<u8>>,
}

/// A change received from the server. `data: None` is a deletion.
/// `server_meta` is opaque to the core (encoded system fields of the remote
/// record, kept for the next push).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteChange {
    pub kind: RecordKind,
    pub id: Id,
    pub version: u64,
    pub data: Option<Vec<u8>>,
    pub server_meta: Option<Vec<u8>>,
}
