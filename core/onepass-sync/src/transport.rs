//! What the sync driver needs of a remote: a binding (which server state the
//! local store is bound to), pages of changes from a cursor, atomic batches
//! of writes, and the batch limits. `MailboxTransport` is the mailbox one;
//! the CloudKit one stays in Swift.

use std::time::Duration;

use onepass_core::Id;
use onepass_core::store::RecordKind;
use onepass_core::sync::{Change, RemoteChange};

/// One page of changes. `cursor`: where the next fetch starts, saved once
/// the page is staged (`None`: nothing to save for this page).
/// `restarted_from_scratch`: the remote could not serve the cursor (it
/// expired) and this page starts a fetch from scratch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub changes: Vec<RemoteChange>,
    pub cursor: Option<Vec<u8>>,
    pub more: bool,
    pub restarted_from_scratch: bool,
}

/// A pending change and the server meta the store holds for it (the
/// version the write expects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub change: Change,
    pub server_meta: Option<Vec<u8>>,
}

impl Outgoing {
    /// What the change weighs in a batch: its data plus a fixed overhead.
    pub fn batch_bytes(&self) -> usize {
        self.change.data.as_ref().map_or(0, Vec::len) + 64
    }
}

/// The outcome of one change of a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendResult {
    /// Written; `server_meta` is what the store keeps for the next write
    /// (`None` for a deletion that changed nothing).
    Saved {
        kind: RecordKind,
        id: Id,
        server_meta: Option<Vec<u8>>,
    },
    /// The server holds another version: this is its row.
    Conflict(RemoteChange),
    /// Not written (the batch did not go through for another change).
    Failed { kind: RecordKind, id: Id },
}

/// The largest batch the remote takes in one atomic write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchLimits {
    pub max_records: usize,
    pub max_bytes: usize,
}

/// Why a transport call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// No network, or the server is unreachable.
    Offline,
    /// Busy: try again, after `after` when the server said so.
    Retryable { after: Option<Duration> },
    /// The server refused the request as stale: this device's clock is off.
    Stale,
    /// The server lost its data (another incarnation): reset the local zone.
    ZoneReset,
    /// A record the server serves cannot be read (a blob that does not
    /// match its hash, a body that does not decode).
    RecordUnreadable,
    /// Anything else, for the logs.
    Other(String),
}

pub trait Transport {
    /// The incarnation of the server state (a mailbox's `incarnation`): a
    /// change means the server lost its data and the local zone resets.
    fn binding(&mut self) -> Result<u64, TransportError>;

    /// One page of changes after `cursor` (`None`: from scratch).
    fn fetch(&mut self, cursor: Option<&[u8]>) -> Result<Page, TransportError>;

    /// One atomic batch: one result per change, in order.
    fn send(&mut self, batch: &[Outgoing]) -> Result<Vec<SendResult>, TransportError>;

    fn limits(&self) -> BatchLimits;

    /// Own writes the server answered as saved and never served (a batch
    /// applied in part, spec 11), found by the fetches since the last call:
    /// the driver sends their local copy again. Default: none (a remote
    /// that cannot tell).
    fn unconfirmed(&mut self) -> Vec<(RecordKind, Id)> {
        Vec::new()
    }
}
