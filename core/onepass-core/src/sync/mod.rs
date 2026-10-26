//! Offline-first sync support: a layered local store that sits between the
//! `Repository` and a remote (CloudKit). The `Repository` stays synchronous
//! and unaware of the network; see `store` for the layers.

mod store;

pub use store::SyncStore;

use crate::Id;
use crate::store::RecordKind;

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
