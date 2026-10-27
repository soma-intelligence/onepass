//! `SyncStore`: a layered SQLite store.
//!
//! - `base`: last known server state (with opaque `server_meta`).
//! - `pending`: local writes not yet confirmed by the server (`data NULL` is
//!   a deletion). Reads see `pending` over `base`.
//! - `staging`: changes received during a fetch, applied to `base` in one
//!   transaction by `commit_remote`.
//! - `ancestor`: for a manifest, a restore epoch or a signed list with a
//!   pending local write, the `base` row that write was built on, kept when
//!   the server replaces `base`.
//! - `kept`: the `base` rows of manifests and items the server replaced or
//!   removed since their vault last loaded cleanly (the first such row per
//!   key), so the device still holds its own verified copy when the server
//!   goes back to an older state or serves an incomplete one. See
//!   `RecordStore::kept_rows` and `crate::sync::VaultSyncHealth`.
//! - `meta`: device state, change token, sync health and other small
//!   values.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::ops::Deref;

use rusqlite::{
    Connection, OptionalExtension, Savepoint, Transaction, TransactionBehavior, params,
};

use std::collections::BTreeMap;

use super::{
    Change, MAX_RECORD_BYTES, RemoteChange, STALE_ALERT_MAX_ROUNDS, STALE_ALERT_ROUNDS,
    STALE_ALERT_SECONDS, STALE_CLEAR_ROUNDS, STALE_MEMORY_ROUNDS,
};
use crate::account::{AccountParams, signed_params};
use crate::chain::{ChainState, Seen};
use crate::format::STORE_USER_VERSION;
use crate::lists::{VAULT_LIST_DOMAIN, verify};
use crate::repo::{DeviceState, split_item_record};
use crate::store::{Record, RecordKind, RecordStore, VaultEvent};
use crate::vaultlist::VaultListEntry;
use crate::{Error, Id, IntegrityError, Result};

const DEVICE_STATE_KEY: &str = "device_state";
/// The restore epoch mark (`RecordStore::restore_epoch_mark`): epoch
/// (8 bytes, big endian) then the SHA-256 of its record data.
const EPOCH_MARK_KEY: &str = "epoch_hash";
/// The pinned chain state (`ChainState`), beside the device state.
const CHAIN_STATE_KEY: &str = "chain";
/// Raised when a fetch dropped a local password change the server had
/// overtaken (`SyncStore::take_password_change_superseded`).
const SUPERSEDED_KEY: &str = "password_change_superseded";
/// The capped log of remote deletions the store refused (outside the `sync.`
/// namespace of the FFI handle, so only the core writes it).
const IGNORED_DELETIONS_KEY: &str = "ignored_deletions";
const IGNORED_LOG_VERSION: u8 = 1;
const IGNORED_ENTRY_BYTES: usize = 1 + 16 + 8;
/// Most entries kept in the log of ignored deletions (and in the log of
/// dropped vault writes); the oldest go first.
pub const MAX_IGNORED_DELETIONS: usize = 100;
/// The sync health of the vaults not `Ok` (see `HealthEntry`), outside the
/// `sync.` namespace of the FFI handle: only the core writes it.
const HEALTH_KEY: &str = "sync_health";
const HEALTH_VERSION: u8 = 1;
/// `vault (16) | seq (8) | cause (1) | flags (1) | since (8) | rounds (4)
/// | clean rounds (1)`.
const HEALTH_ENTRY_BYTES: usize = 16 + 8 + 1 + 1 + 8 + 4 + 1;
/// The count of the vaults cleared lately (see `HealthMemory`), next to
/// the health map.
const HEALTH_MEMORY_KEY: &str = "sync_health_memory";
const HEALTH_MEMORY_VERSION: u8 = 1;
/// `vault (16) | flags (1) | since (8) | rounds (4) | rounds left (1)`.
const HEALTH_MEMORY_ENTRY_BYTES: usize = 16 + 1 + 8 + 4 + 1;
/// The capped log of vaults whose pending local writes a rebase dropped
/// because the signed vault list marks them deleted (same encoding as the
/// ignored deletions, kind `Manifest`, id the vault).
const DROPPED_WRITES_KEY: &str = "dropped_vault_writes";
const FETCH_MODE_KEY: &str = "zone.full_fetch";
const FETCH_PLAIN: u8 = 1;
const FETCH_RESET: u8 = 2;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS base (
    kind INTEGER NOT NULL,
    id BLOB NOT NULL,
    version INTEGER NOT NULL,
    data BLOB NOT NULL,
    server_meta BLOB,
    PRIMARY KEY (kind, id)
);
CREATE TABLE IF NOT EXISTS pending (
    kind INTEGER NOT NULL,
    id BLOB NOT NULL,
    version INTEGER NOT NULL,
    data BLOB,
    vault BLOB,
    PRIMARY KEY (kind, id)
);
CREATE TABLE IF NOT EXISTS staging (
    kind INTEGER NOT NULL,
    id BLOB NOT NULL,
    version INTEGER NOT NULL,
    data BLOB,
    server_meta BLOB,
    PRIMARY KEY (kind, id)
);
CREATE TABLE IF NOT EXISTS ancestor (
    kind INTEGER NOT NULL,
    id BLOB NOT NULL,
    version INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (kind, id)
);
CREATE TABLE IF NOT EXISTS kept (
    kind INTEGER NOT NULL,
    id BLOB NOT NULL,
    version INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (kind, id)
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT NOT NULL PRIMARY KEY,
    value BLOB NOT NULL
);
";

/// Check `PRAGMA user_version`, then create what is missing and stamp the
/// current version. 0 (a new file, or one from before the check) and the
/// current version open; nothing is dropped or rewritten. A newer version is
/// `InvalidFormat("store from a newer version")`, the file left untouched.
fn init_schema(conn: &Connection) -> Result<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(store_err)?;
    if version > STORE_USER_VERSION {
        return Err(Error::InvalidFormat("store from a newer version"));
    }
    conn.execute_batch(SCHEMA).map_err(store_err)?;
    conn.execute_batch(&format!("PRAGMA user_version = {STORE_USER_VERSION};"))
        .map_err(store_err)?;
    Ok(())
}

/// A `staging` row: `(kind, id, version, data, server_meta)`.
type StagedRow = (i64, Vec<u8>, i64, Option<Vec<u8>>, Option<Vec<u8>>);

pub struct SyncStore {
    conn: Connection,
}

/// Only the SQLite error code goes into the error: never paths or data.
fn store_err(e: rusqlite::Error) -> Error {
    match e.sqlite_error_code() {
        Some(code) => Error::Store(format!("sqlite: {code:?}")),
        None => Error::Store("sqlite".into()),
    }
}

fn to_i64(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::InvalidFormat("record version"))
}

/// Rows come from a file that may have been edited: check every column.
fn decode_row(kind: i64, id: Vec<u8>, version: i64, data: Vec<u8>) -> Result<Record> {
    Ok(Record {
        kind: decode_kind(kind)?,
        id: decode_id(id)?,
        version: u64::try_from(version).map_err(|_| Error::InvalidFormat("record version"))?,
        data,
    })
}

fn decode_kind(kind: i64) -> Result<RecordKind> {
    u8::try_from(kind)
        .map_err(|_| Error::InvalidFormat("record kind"))
        .and_then(RecordKind::from_code)
}

fn decode_id(id: Vec<u8>) -> Result<Id> {
    Ok(Id(id
        .try_into()
        .map_err(|_| Error::InvalidFormat("record id"))?))
}

fn check_size(data: &[u8]) -> Result<()> {
    if data.len() > MAX_RECORD_BYTES {
        Err(Error::InvalidFormat("record too large"))
    } else {
        Ok(())
    }
}

/// Version of the effective record (pending over base), if any.
fn effective_version(conn: &Connection, kind: RecordKind, id: Id) -> Result<Option<u64>> {
    Ok(effective_get(conn, kind, id)?.map(|r| r.version))
}

/// The effective record of one key: a pending row hides the `base` row, and a
/// pending deletion hides it entirely.
fn effective_get(conn: &Connection, kind: RecordKind, id: Id) -> Result<Option<Record>> {
    let pending: Option<(i64, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT version, data FROM pending WHERE kind = ?1 AND id = ?2",
            params![kind.code(), &id.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(store_err)?;
    if let Some((version, data)) = pending {
        return data
            .map(|d| decode_row(i64::from(kind.code()), id.0.to_vec(), version, d))
            .transpose();
    }
    conn.query_row(
        "SELECT version, data FROM base WHERE kind = ?1 AND id = ?2",
        params![kind.code(), &id.0[..]],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )
    .optional()
    .map_err(store_err)?
    .map(|(version, data)| decode_row(i64::from(kind.code()), id.0.to_vec(), version, data))
    .transpose()
}

/// The persisted mode of a begun fetch from scratch (`FETCH_PLAIN` or `FETCH_RESET`).
fn fetch_mode(conn: &Connection) -> Result<Option<u8>> {
    let value: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![FETCH_MODE_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(store_err)?;
    Ok(value.and_then(|v| v.first().copied()))
}

/// The kinds whose pending row keeps the `base` row it was built on as its
/// `ancestor`, to tell when the server moved on: manifests, the restore
/// epoch and the two signed lists.
fn keeps_ancestor(kind: RecordKind) -> bool {
    matches!(
        kind,
        RecordKind::Manifest
            | RecordKind::RestoreEpoch
            | RecordKind::DeviceList
            | RecordKind::VaultList
    )
}

/// Write a pending data row. A manifest, restore epoch or list write over a
/// `base` row with no `ancestor` yet first keeps that `base` row as its
/// ancestor.
fn write_pending(tx: &Connection, r: &Record) -> Result<()> {
    let version = to_i64(r.version)?;
    if keeps_ancestor(r.kind) {
        tx.execute(
            "INSERT OR IGNORE INTO ancestor (kind, id, version, data)
             SELECT kind, id, version, data FROM base WHERE kind = ?1 AND id = ?2",
            params![r.kind.code(), &r.id.0[..]],
        )
        .map_err(store_err)?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO pending (kind, id, version, data) VALUES (?1, ?2, ?3, ?4)",
        params![r.kind.code(), &r.id.0[..], version, r.data],
    )
    .map_err(store_err)?;
    Ok(())
}

/// Vaults whose pending manifest was not built on the current `base`
/// manifest: the ancestor it captured (the `base` row it was built on) is
/// gone, older than `base`, or another manifest with the same seq, so the
/// server moved on and the local manifest must be rebased before any push.
/// A `base` older than the ancestor is a server that went back: the local
/// manifest is not held, its push restores the server's copy.
fn held_vaults(conn: &Connection) -> Result<BTreeSet<Id>> {
    let mut stmt = conn
        .prepare(
            "SELECT p.id FROM pending p
             JOIN base b ON b.kind = p.kind AND b.id = p.id
             LEFT JOIN ancestor a ON a.kind = p.kind AND a.id = p.id
             WHERE p.kind = ?1 AND p.data IS NOT NULL
               AND (a.id IS NULL OR b.version > a.version
                    OR (b.version = a.version AND b.data != a.data))",
        )
        .map_err(store_err)?;
    let rows = stmt
        .query_map(params![RecordKind::Manifest.code()], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(store_err)?;
    rows.map(|id| decode_id(id.map_err(store_err)?)).collect()
}

/// Whether the pending restore epoch was not built on the current `base`
/// one: the server took another device's epoch meanwhile. Such an epoch is
/// never pushed; the rebase drops it (`Error::Conflict`).
fn held_epoch(conn: &Connection) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pending p
             JOIN base b ON b.kind = p.kind AND b.id = p.id
             LEFT JOIN ancestor a ON a.kind = p.kind AND a.id = p.id
             WHERE p.kind = ?1 AND p.data IS NOT NULL
               AND (a.id IS NULL OR a.version != b.version OR a.data != b.data))",
        params![RecordKind::RestoreEpoch.code()],
        |r| r.get(0),
    )
    .map_err(store_err)
}

/// The signed lists (device list, vault list) whose pending row was not
/// built on the current `base` row, as for `held_vaults`: the server list
/// moved on, and the local one must be rebuilt over it (`Repository::rebase`)
/// before any push.
fn held_lists(conn: &Connection) -> Result<BTreeSet<(RecordKind, Id)>> {
    let mut stmt = conn
        .prepare(
            "SELECT p.kind, p.id FROM pending p
             JOIN base b ON b.kind = p.kind AND b.id = p.id
             LEFT JOIN ancestor a ON a.kind = p.kind AND a.id = p.id
             WHERE p.kind IN (?1, ?2) AND p.data IS NOT NULL
               AND (a.id IS NULL OR a.version != b.version)",
        )
        .map_err(store_err)?;
    let rows = stmt
        .query_map(
            params![RecordKind::DeviceList.code(), RecordKind::VaultList.code()],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .map_err(store_err)?;
    rows.map(|row| {
        let (kind, id) = row.map_err(store_err)?;
        Ok((decode_kind(kind)?, decode_id(id)?))
    })
    .collect()
}

/// The epoch of an account params record, `None` if it does not decode.
fn params_epoch(data: &[u8]) -> Option<u64> {
    AccountParams::decode(data).ok().map(|p| p.epoch)
}

/// The data of one row of `table` (`pending` or `base`), `None` if there is
/// no row or it is a deletion.
fn row_data(conn: &Connection, table: &str, kind: RecordKind, id: Id) -> Result<Option<Vec<u8>>> {
    Ok(conn
        .query_row(
            &format!("SELECT data FROM {table} WHERE kind = ?1 AND id = ?2"),
            params![kind.code(), &id.0[..]],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()
        .map_err(store_err)?
        .flatten())
}

/// The `base` account params of account `id` as the server holds them: a
/// row with server metadata. A row without (a zone reset forgot the server
/// state and requeued it) is not the server's.
fn server_params(conn: &Connection, id: Id) -> Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT data FROM base WHERE kind = ?1 AND id = ?2 AND server_meta IS NOT NULL",
        params![RecordKind::AccountParams.code(), &id.0[..]],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(store_err)
}

/// Whether the pending account params and keyset of account `id` may be
/// pushed: both rows are pending with data (they go out together or not at
/// all), and the pending params decode at an epoch above the server's (a
/// change the server already has, or one it has overtaken, never goes out;
/// see `server_params`).
fn account_pair_pushable(conn: &Connection, id: Id) -> Result<bool> {
    let params = row_data(conn, "pending", RecordKind::AccountParams, id)?;
    let keyset = row_data(conn, "pending", RecordKind::Keyset, id)?;
    let (Some(params), Some(_)) = (params, keyset) else {
        return Ok(false);
    };
    let Some(epoch) = params_epoch(&params) else {
        return Ok(false);
    };
    let base = server_params(conn, id)?;
    Ok(match base.as_deref().map(params_epoch) {
        Some(Some(base_epoch)) => epoch > base_epoch,
        // No server params (a new account, or a zone reset that requeued
        // the pair), or ones that do not even decode: the pair goes out.
        _ => true,
    })
}

/// After a fetch: a local password change (pending account params and
/// keyset) that the server params caught up with (epoch at least the
/// pending one) is dropped, both rows together, so it can never be pushed
/// over the server's pair. If the server pair is not this very change (a
/// push confirmed before `mark_pushed`), the change lost a race: the
/// `password_change_superseded` flag is raised for the app. A pending keyset
/// left without its pending params is dropped as well.
fn settle_account_changes(tx: &Connection) -> Result<()> {
    let ids: Vec<Vec<u8>> = {
        let mut stmt = tx
            .prepare("SELECT id FROM pending WHERE kind = ?1 AND data IS NOT NULL")
            .map_err(store_err)?;
        let rows = stmt
            .query_map(params![RecordKind::AccountParams.code()], |r| r.get(0))
            .map_err(store_err)?;
        rows.collect::<rusqlite::Result<_>>().map_err(store_err)?
    };
    for id in ids {
        let id = decode_id(id)?;
        let (Some(pending), Some(base)) = (
            row_data(tx, "pending", RecordKind::AccountParams, id)?,
            server_params(tx, id)?,
        ) else {
            continue;
        };
        let (Some(local), Some(remote)) = (params_epoch(&pending), params_epoch(&base)) else {
            continue;
        };
        if remote < local {
            continue;
        }
        for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
            tx.execute(
                "DELETE FROM pending WHERE kind = ?1 AND id = ?2",
                params![kind.code(), &id.0[..]],
            )
            .map_err(store_err)?;
        }
        if pending != base {
            tx.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![SUPERSEDED_KEY, &[1u8][..]],
            )
            .map_err(store_err)?;
        }
    }
    // A pending keyset without its pending params can never go out (the
    // pair goes together, `account_pair_pushable`): it is the leftover of a
    // change whose params were confirmed or dropped, and goes too.
    tx.execute(
        "DELETE FROM pending WHERE kind = ?1 AND data IS NOT NULL AND NOT EXISTS
             (SELECT 1 FROM pending p WHERE p.kind = ?2 AND p.id = pending.id
                  AND p.data IS NOT NULL)",
        params![RecordKind::Keyset.code(), RecordKind::AccountParams.code()],
    )
    .map_err(store_err)?;
    Ok(())
}

/// `SyncStore::pending_changes` on a consistent view.
fn pending_changes_in(tx: &Connection) -> Result<Vec<Change>> {
    let held = held_vaults(tx)?;
    let held_lists = held_lists(tx)?;
    let deleted = deleted_vaults(tx, &[]);
    // The epoch ships only with or after the manifests its heads name: never
    // while a vault is held (its head would be rebased away).
    let epoch_held = held_epoch(tx)? || !held.is_empty();
    let mut stmt = tx
        .prepare("SELECT kind, id, version, data, vault FROM pending ORDER BY kind, id")
        .map_err(store_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
                r.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })
        .map_err(store_err)?;
    let mut writes = Vec::new();
    let mut deletions = Vec::new();
    for row in rows {
        let (kind, id, version, data, tomb_vault) = row.map_err(store_err)?;
        let kind = decode_kind(kind)?;
        let id = decode_id(id)?;
        let version = u64::try_from(version).map_err(|_| Error::InvalidFormat("record version"))?;
        let vault = match kind {
            RecordKind::Manifest => Some(id),
            RecordKind::Item => match data.as_deref() {
                Some(d) => Some(split_item_record(d)?.0),
                None => tomb_vault.map(decode_id).transpose()?,
            },
            _ => None,
        };
        if vault.is_some_and(|v| held.contains(&v))
            || (kind == RecordKind::RestoreEpoch && epoch_held)
            || held_lists.contains(&(kind, id))
        {
            continue;
        }
        // A write into a vault the verified vault list marks deleted (by
        // another device): never pushed, it would bring back part of the
        // vault. The rebase drops it (`drop_pending_vault_writes`).
        let owner = match kind {
            RecordKind::VaultKey | RecordKind::VaultMeta => Some(id),
            _ => vault,
        };
        if data.is_some() && owner.is_some_and(|v| deleted.contains(&v)) {
            continue;
        }
        if data.is_some()
            && matches!(kind, RecordKind::AccountParams | RecordKind::Keyset)
            && !account_pair_pushable(tx, id)?
        {
            continue;
        }
        let change = Change {
            kind,
            id,
            version,
            data,
        };
        if change.data.is_some() {
            writes.push(change);
        } else {
            deletions.push(change);
        }
    }
    // Deletions go last, highest kind first: a fetching device never
    // sees a manifest without its key.
    deletions.sort_by(|a, b| b.kind.cmp(&a.kind).then(a.id.cmp(&b.id)));
    writes.extend(deletions);
    Ok(writes)
}

impl SyncStore {
    /// Open or create the store at `path`: WAL, `synchronous = FULL` and a
    /// 5 s busy timeout, so a session and a sync manager can each hold a
    /// connection on the same file.
    pub fn open(path: &Path) -> Result<SyncStore> {
        let conn = Connection::open(path).map_err(store_err)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(store_err)?;
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .map_err(store_err)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(Error::Store("sqlite: WAL unavailable".into()));
        }
        conn.execute_batch("PRAGMA synchronous = FULL;")
            .map_err(store_err)?;
        init_schema(&conn)?;
        Ok(SyncStore { conn })
    }

    pub fn open_in_memory() -> Result<SyncStore> {
        let conn = Connection::open_in_memory().map_err(store_err)?;
        init_schema(&conn)?;
        Ok(SyncStore { conn })
    }

    /// A write transaction: an `IMMEDIATE` one, or a savepoint inside an
    /// open batch (`begin_batch`), so a batch nests the per-call writes and
    /// commits or rolls them back together.
    fn write_tx(&mut self) -> Result<WriteTx<'_>> {
        if self.conn.is_autocommit() {
            self.conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map(WriteTx::Top)
                .map_err(store_err)
        } else {
            self.conn
                .savepoint()
                .map(WriteTx::Nested)
                .map_err(store_err)
        }
    }

    /// Run `f` on a consistent view: a read transaction, or the open batch.
    fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        if self.conn.is_autocommit() {
            let tx = self.conn.unchecked_transaction().map_err(store_err)?;
            f(&tx)
        } else {
            f(&self.conn)
        }
    }

    /// Open a batch: every write until `commit_batch` or `rollback_batch`
    /// lands in one `IMMEDIATE` transaction, so a crash leaves all of it or
    /// none. Batches do not nest.
    pub(crate) fn begin_batch(&mut self) -> Result<()> {
        if !self.conn.is_autocommit() {
            return Err(Error::Store("batch already open".into()));
        }
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(store_err)
    }

    pub(crate) fn commit_batch(&mut self) -> Result<()> {
        self.conn.execute_batch("COMMIT").map_err(store_err)
    }

    pub(crate) fn rollback_batch(&mut self) -> Result<()> {
        self.conn.execute_batch("ROLLBACK").map_err(store_err)
    }

    /// Local writes to push, minus the held vaults, minus the writes (not
    /// the deletions) into a vault the verified vault list in `base` marks
    /// deleted (`deleted_vaults`, spec 4.5), and minus the account params
    /// and keyset unless both are pending and the params epoch is above the
    /// server's (`account_pair_pushable`). Order: account params, keysets,
    /// vault keys, vault metas, items, manifests, then deletions, so a
    /// manifest never reaches the server before its items.
    pub fn pending_changes(&self) -> Result<Vec<Change>> {
        self.read(pending_changes_in)
    }

    /// Every `base` row, ordered by kind then id: the store as the server
    /// sees it, never a `pending` write. The pairing snapshot (spec 5.1).
    pub fn export_records(&self) -> Result<Vec<Record>> {
        self.read(|conn| {
            let mut stmt = conn
                .prepare("SELECT kind, id, version, data FROM base ORDER BY kind, id")
                .map_err(store_err)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .map_err(store_err)?;
            rows.map(|row| {
                let (k, id, v, d) = row.map_err(store_err)?;
                decode_row(k, id, v, d)
            })
            .collect()
        })
    }

    /// The server confirmed `(kind, id, version)`. If the pending row has
    /// exactly that version it moves to `base` with `server_meta` (a pending
    /// deletion removes the `base` row); any other version changes nothing.
    pub fn mark_pushed(
        &mut self,
        kind: RecordKind,
        id: Id,
        version: u64,
        server_meta: Option<Vec<u8>>,
    ) -> Result<()> {
        let v = to_i64(version)?;
        let tx = self.write_tx()?;
        let pending: Option<Option<Vec<u8>>> = tx
            .query_row(
                "SELECT data FROM pending WHERE kind = ?1 AND id = ?2 AND version = ?3",
                params![kind.code(), &id.0[..], v],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?;
        let Some(data) = pending else {
            return Ok(());
        };
        match data {
            Some(data) => tx.execute(
                "INSERT OR REPLACE INTO base (kind, id, version, data, server_meta)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![kind.code(), &id.0[..], v, data, server_meta],
            ),
            None => tx.execute(
                "DELETE FROM base WHERE kind = ?1 AND id = ?2",
                params![kind.code(), &id.0[..]],
            ),
        }
        .map_err(store_err)?;
        tx.execute(
            "DELETE FROM pending WHERE kind = ?1 AND id = ?2",
            params![kind.code(), &id.0[..]],
        )
        .map_err(store_err)?;
        if keeps_ancestor(kind) {
            tx.execute(
                "DELETE FROM ancestor WHERE kind = ?1 AND id = ?2",
                params![kind.code(), &id.0[..]],
            )
            .map_err(store_err)?;
        }
        if kind == RecordKind::Manifest {
            // The server took this device's copy back: only a fetch that
            // serves it (or newer) shows that it kept it.
            update_health_lenient(&tx, |map| {
                map.get_mut(&id)
                    .map(|e| {
                        e.awaiting = true;
                        e.dirty();
                    })
                    .is_some()
            })?;
        }
        tx.commit()
    }

    /// Marks the start of a fetch from scratch (no change token, or the token
    /// expired): the server returns live records only, never the deletions of
    /// the past, so every `server_meta` is forgotten and the staged pages are
    /// dropped. Records the fetch returns get their tag back in `commit_remote`;
    /// `finish_full_fetch` then settles the rows it did not return. The mode is
    /// persisted (plain full fetch), so the settlement also happens after a
    /// restart. A reset already marked stays a reset. One transaction.
    pub fn begin_full_fetch(&mut self) -> Result<()> {
        self.begin_fetch_mode(FETCH_PLAIN, None)
    }

    /// A server data loss (its zone was deleted and recreated): like
    /// `begin_full_fetch`, plus the change token stored under `token_key` is
    /// deleted and the mode is "reset". Nothing becomes pending yet: a stale
    /// local row must not overwrite a newer version another device uploads
    /// meanwhile. See `finish_full_fetch`.
    pub fn begin_zone_reset(&mut self, token_key: &str) -> Result<()> {
        self.begin_fetch_mode(FETCH_RESET, Some(token_key))
    }

    fn begin_fetch_mode(&mut self, mode: u8, token_key: Option<&str>) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute("UPDATE base SET server_meta = NULL", [])
            .map_err(store_err)?;
        tx.execute("DELETE FROM staging", []).map_err(store_err)?;
        if let Some(key) = token_key {
            tx.execute("DELETE FROM meta WHERE key = ?1", params![key])
                .map_err(store_err)?;
        }
        let current = fetch_mode(&tx)?.unwrap_or(0);
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![FETCH_MODE_KEY, &[current.max(mode)][..]],
        )
        .map_err(store_err)?;
        tx.commit()
    }

    /// Whether a fetch from scratch was begun and not yet finished.
    pub fn full_fetch_pending(&self) -> Result<bool> {
        self.read(|c| Ok(fetch_mode(c)?.is_some()))
    }

    /// After the `commit_remote` of the complete fetch from scratch. Settles
    /// every `base` row still without `server_meta` (the server did not return
    /// it) and without a pending row, then clears the mode. One transaction; a
    /// no-op without a begun fetch. Returns whether `base` rows were deleted.
    ///
    /// - Plain full fetch: only an item row whose vault manifest the server
    ///   returned is deleted (the server is authoritative for the items of a
    ///   vault it serves; the fetch carries no tombstones). Every other row
    ///   stays in `base` untouched: the stable id kinds (account params,
    ///   keyset, vault keys, vault metas), the manifests and the items of a
    ///   vault the server did not return. The store is not trusted: an empty
    ///   or partial answer must never erase the local copy, and a vault this
    ///   device has seen and the server hides is reported by the repository
    ///   (`VaultMissing` or a manifest rollback), not silently forgotten.
    /// - Reset: an item row whose vault manifest the server returned is
    ///   deleted (the server is authoritative for that vault, and a stale item
    ///   blob next to its manifest would be refused as unexpected). Any other
    ///   such row (the stable id kinds, items of a vault the server lacks)
    ///   becomes a pending row with the same version and data, a manifest
    ///   or the restore epoch keeping its `base` row as ancestor (not held).
    ///
    /// Both modes: every row of a vault the account's signed vault list in
    /// `base` marks deleted (`deleted_vaults`), its key, meta, manifest and
    /// item records, that the server did not return is deleted, and the
    /// vault leaves the persisted `last_seen` (spec 4.5).
    ///
    /// A pending tombstone or edit is never touched. After a plain full fetch,
    /// the kept rows the server has no right to remove (see `commit_remote`)
    /// are appended to the log of `ignored_deletions`.
    pub fn finish_full_fetch(&mut self) -> Result<bool> {
        let tx = self.write_tx()?;
        let Some(mode) = fetch_mode(&tx)? else {
            return Ok(false);
        };
        let missing = "b.server_meta IS NULL AND NOT EXISTS
             (SELECT 1 FROM pending p WHERE p.kind = b.kind AND p.id = b.id)";
        let deleted = deleted_vaults(&tx, &[]);
        if mode == FETCH_PLAIN {
            // The server stopped serving rows it has no right to remove: they
            // stay (see above) and the refusal is logged.
            let seen: BTreeSet<Id> = device_state_in(&tx)?.last_seen.into_keys().collect();
            let rows: Vec<(i64, Vec<u8>)> = {
                let mut stmt = tx
                    .prepare(&format!(
                        "SELECT b.kind, b.id FROM base b WHERE b.kind != ?1 AND {missing}
                         ORDER BY b.kind, b.id"
                    ))
                    .map_err(store_err)?;
                let rows = stmt
                    .query_map(params![RecordKind::Item.code()], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .map_err(store_err)?;
                rows.collect::<rusqlite::Result<_>>().map_err(store_err)?
            };
            let mut ignored = Vec::new();
            for (kind, id) in rows {
                let kind = decode_kind(kind)?;
                if protected_from_remote_deletion(kind, &id, &seen, &deleted)
                    && let Ok(id) = decode_id(id)
                {
                    ignored.push((kind, id));
                }
            }
            append_ignored(&tx, &ignored)?;
        }
        // Both modes: the rows of a vault the signed list marks deleted.
        let mut removed = 0;
        for v in &deleted {
            removed += tx
                .execute(
                    &format!(
                        "DELETE FROM base AS b WHERE {missing} AND (
                             (b.kind IN (?1, ?2, ?3) AND b.id = ?5)
                             OR (b.kind = ?4 AND substr(b.data, 1, 16) = ?5))"
                    ),
                    params![
                        RecordKind::VaultKey.code(),
                        RecordKind::VaultMeta.code(),
                        RecordKind::Manifest.code(),
                        RecordKind::Item.code(),
                        &v.0[..]
                    ],
                )
                .map_err(store_err)?;
        }
        forget_seen(&tx, &deleted)?;
        // Both modes: an item the server did not return, in a vault whose
        // manifest it did return, is gone from that vault. Kept first: it
        // may belong to this device's copy of a vault the server is behind on.
        tx.execute(
            &format!(
                "INSERT OR IGNORE INTO kept (kind, id, version, data)
                 SELECT b.kind, b.id, b.version, b.data FROM base AS b
                 WHERE b.kind = ?1 AND {missing}
                 AND EXISTS (SELECT 1 FROM base m WHERE m.kind = ?2
                     AND m.id = substr(b.data, 1, 16) AND m.server_meta IS NOT NULL)"
            ),
            params![RecordKind::Item.code(), RecordKind::Manifest.code()],
        )
        .map_err(store_err)?;
        removed += tx
            .execute(
                &format!(
                    "DELETE FROM base AS b WHERE b.kind = ?1 AND {missing}
                     AND EXISTS (SELECT 1 FROM base m WHERE m.kind = ?2
                         AND m.id = substr(b.data, 1, 16) AND m.server_meta IS NOT NULL)"
                ),
                params![RecordKind::Item.code(), RecordKind::Manifest.code()],
            )
            .map_err(store_err)?;
        if mode == FETCH_RESET {
            tx.execute(
                &format!(
                    "INSERT OR IGNORE INTO ancestor (kind, id, version, data)
                     SELECT b.kind, b.id, b.version, b.data FROM base b
                     WHERE b.kind IN (?1, ?2, ?3, ?4) AND {missing}"
                ),
                params![
                    RecordKind::Manifest.code(),
                    RecordKind::RestoreEpoch.code(),
                    RecordKind::DeviceList.code(),
                    RecordKind::VaultList.code()
                ],
            )
            .map_err(store_err)?;
            tx.execute(
                &format!(
                    "INSERT INTO pending (kind, id, version, data)
                     SELECT b.kind, b.id, b.version, b.data FROM base b WHERE {missing}"
                ),
                [],
            )
            .map_err(store_err)?;
        }
        tx.execute("DELETE FROM meta WHERE key = ?1", params![FETCH_MODE_KEY])
            .map_err(store_err)?;
        tx.commit()?;
        Ok(removed > 0)
    }

    /// Park a change received from the server. Nothing is visible until
    /// `commit_remote`. A later change for the same key replaces it.
    pub fn stage_remote(&mut self, c: RemoteChange) -> Result<()> {
        let v = to_i64(c.version)?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO staging (kind, id, version, data, server_meta)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![c.kind.code(), &c.id.0[..], v, c.data, c.server_meta],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Apply all staged changes to `base` in one transaction and empty
    /// `staging`. `pending` is not touched, except for a local password
    /// change the server params have caught up with: its pending account
    /// params and keyset are dropped together, and
    /// `take_password_change_superseded` reports it when the server pair is
    /// another change. Returns the ids of the vaults whose manifest was
    /// applied.
    ///
    /// Remote deletions the store has no right to make are ignored (they
    /// come from a hostile or broken server): account params, keysets, the
    /// restore epoch and the signed lists, and the vault key, vault meta and
    /// manifest of a vault in the device's `last_seen`, unless the account's
    /// signed vault list marks that vault deleted (spec 4.5,
    /// `deleted_vaults`: the list in `base` or the one staged in this batch,
    /// verified). The local rows stay and the vault stays readable from
    /// them: nothing the server sends can make this device forget its
    /// account or a vault it has read (the
    /// repository reports `VaultMissing` if those rows ever disappear). Each
    /// ignored deletion is appended to the capped log of `ignored_deletions`.
    /// A vault the verified list marks deleted also leaves the persisted
    /// `last_seen`.
    pub fn commit_remote(&mut self) -> Result<Vec<Id>> {
        let tx = self.write_tx()?;
        let seen: BTreeSet<Id> = device_state_in(&tx)?.last_seen.into_keys().collect();
        let staged: Vec<StagedRow> = {
            let mut stmt = tx
                .prepare(
                    "SELECT kind, id, version, data, server_meta FROM staging ORDER BY kind, id",
                )
                .map_err(store_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .map_err(store_err)?;
            rows.collect::<rusqlite::Result<_>>().map_err(store_err)?
        };
        let deleted = deleted_vaults(&tx, &staged);
        let mut vaults = BTreeSet::new();
        let mut ignored = Vec::new();
        let mut manifests = Vec::new();
        for (kind, id, version, data, server_meta) in staged {
            let kind_code = kind;
            let kind = decode_kind(kind)?;
            if data.is_none() && protected_from_remote_deletion(kind, &id, &seen, &deleted) {
                if let Ok(id) = decode_id(id) {
                    ignored.push((kind, id));
                }
                continue;
            }
            if matches!(kind, RecordKind::Manifest | RecordKind::Item) {
                // The first row replaced or removed since the vault last
                // loaded cleanly stays as part of the device's copy.
                tx.execute(
                    "INSERT OR IGNORE INTO kept (kind, id, version, data)
                     SELECT kind, id, version, data FROM base
                     WHERE kind = ?1 AND id = ?2 AND (?3 IS NULL OR data != ?3)",
                    params![kind_code, &id, &data],
                )
                .map_err(store_err)?;
            }
            if kind == RecordKind::Manifest {
                let v = decode_id(id.clone())?;
                vaults.insert(v);
                if data.is_some() {
                    manifests.push((v, version));
                }
            }
            match data {
                Some(data) => tx.execute(
                    "INSERT OR REPLACE INTO base (kind, id, version, data, server_meta)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![kind_code, id, version, data, server_meta],
                ),
                None => tx.execute(
                    "DELETE FROM base WHERE kind = ?1 AND id = ?2",
                    params![kind_code, id],
                ),
            }
            .map_err(store_err)?;
        }
        tx.execute("DELETE FROM staging", []).map_err(store_err)?;
        append_ignored(&tx, &ignored)?;
        // A vault the server was behind on: served again at least as new as
        // the device's copy, or still older.
        update_health_lenient(&tx, |map| {
            let mut changed = false;
            for (v, version) in &manifests {
                if let Some(e) = map.get_mut(v) {
                    e.awaiting = u64::try_from(*version).map_or(true, |n| n < e.seq);
                    if e.awaiting {
                        e.dirty();
                    }
                    changed = true;
                }
            }
            changed
        })?;
        forget_seen(&tx, &deleted)?;
        settle_account_changes(&tx)?;
        tx.commit()?;
        Ok(vaults.into_iter().collect())
    }

    /// The opaque server metadata kept with the `base` row.
    pub fn server_meta(&self, kind: RecordKind, id: Id) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT server_meta FROM base WHERE kind = ?1 AND id = ?2",
                params![kind.code(), &id.0[..]],
                |r| r.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(store_err)?
            .flatten())
    }

    pub fn meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()
            .map_err(store_err)
    }

    pub fn set_meta(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// The persisted device state, or the default one if none was saved.
    pub fn device_state(&self) -> Result<DeviceState> {
        device_state_in(&self.conn)
    }

    pub fn set_device_state(&mut self, s: &DeviceState) -> Result<()> {
        self.set_meta(DEVICE_STATE_KEY, &s.encode())
    }

    /// Merge `mem` and `mem_chain` with the stored device state and chain
    /// state, in one transaction (a savepoint inside an open batch), and
    /// store and return the result.
    /// Two processes (the app and an extension) each keep their own state
    /// over one file: per vault the entry with the larger `seq` wins, so
    /// neither process rewinds `last_seen`; the same `seq` with another hash
    /// is a fork, refused (`ManifestRollback`) before anything is written,
    /// like `Repository::adopt_device_state`. The pin is the memory one, or
    /// the stored one if memory has none; when both pin the same account,
    /// the KDF floor is the componentwise maximum of the two (it only goes
    /// up; the memory salt is kept unless the stored floor raised it).
    ///
    /// Invariant: on this file a higher stored `seq` is always a descendant
    /// of a lower one (manifests are committed conditionally), except after
    /// a rebase, which renumbers a vault and may end below the `seq` of the
    /// local manifests it abandoned. Those were persisted earlier, so the
    /// vaults in `force` take the memory entry as is (or none), whatever is
    /// stored. The restore epoch only goes up too, unless `keep_epoch` (the
    /// caller dropped a pending epoch it had not shipped): then the memory
    /// one stands.
    ///
    /// The chain state merges by `merge_chain` (its rules never rewind a
    /// pin either); `force_lists` is the list rebase's own renumbering.
    pub(crate) fn merge_device_state(
        &mut self,
        mem: &DeviceState,
        mem_chain: &ChainState,
        force: &[Id],
        keep_epoch: bool,
        force_lists: bool,
    ) -> Result<(DeviceState, ChainState)> {
        let tx = self.write_tx()?;
        let stored = device_state_in(&tx)?;
        let chain = merge_chain(mem_chain, &chain_state_in(&tx)?, force_lists)?;
        let pinned = match (mem.pinned.clone(), stored.pinned) {
            (Some(mut mine), Some(theirs))
                if mine.account_id == theirs.account_id
                    && mine.identity_pub == theirs.identity_pub =>
            {
                let salt = mine.kdf_floor.salt;
                let before = (mine.kdf_floor.m_kib, mine.kdf_floor.t, mine.kdf_floor.p);
                mine.raise_floor(&theirs.kdf_floor);
                let after = (mine.kdf_floor.m_kib, mine.kdf_floor.t, mine.kdf_floor.p);
                if before == after {
                    mine.kdf_floor.salt = salt;
                }
                Some(mine)
            }
            (mine, theirs) => mine.or(theirs),
        };
        let epoch = if keep_epoch {
            mem.epoch
        } else {
            mem.epoch.max(stored.epoch)
        };
        let mut merged = DeviceState {
            pinned,
            last_seen: mem.last_seen.clone(),
            epoch,
        };
        for (v, theirs) in stored.last_seen {
            if force.contains(&v) {
                continue;
            }
            match merged.last_seen.get(&v) {
                Some(ours) if ours.seq == theirs.seq && ours.hash != theirs.hash => {
                    return Err(Error::Integrity(IntegrityError::ManifestRollback));
                }
                Some(ours) if ours.seq >= theirs.seq => {}
                _ => {
                    merged.last_seen.insert(v, theirs);
                }
            }
        }
        for (key, value) in [
            (DEVICE_STATE_KEY, merged.encode()),
            (CHAIN_STATE_KEY, chain.encode()),
        ] {
            tx.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(store_err)?;
        }
        tx.commit()?;
        Ok((merged, chain))
    }

    /// The persisted chain state, or the default one if none was saved.
    pub fn chain_state(&self) -> Result<ChainState> {
        match self.meta(CHAIN_STATE_KEY)? {
            Some(bytes) => ChainState::decode(&bytes),
            None => Ok(ChainState::default()),
        }
    }

    /// Save the chain state alone. A session saves it with the device state
    /// through `Repository::persist_device_state` (one transaction, inside
    /// the open batch if any); this is for tools and tests.
    pub fn set_chain_state(&self, s: &ChainState) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![CHAIN_STATE_KEY, s.encode()],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Whether a fetch dropped a local password change that another device's
    /// change overtook (see `commit_remote`) since the last call; the flag
    /// is cleared by reading it. The app then closes the session and asks
    /// for the password now in force.
    pub fn take_password_change_superseded(&mut self) -> Result<bool> {
        let tx = self.write_tx()?;
        let raised = tx
            .execute("DELETE FROM meta WHERE key = ?1", params![SUPERSEDED_KEY])
            .map_err(store_err)?
            > 0;
        tx.commit()?;
        Ok(raised)
    }

    /// Whether an account params record is visible (pending or base).
    pub fn has_account(&self) -> Result<bool> {
        Ok(!self.list(RecordKind::AccountParams)?.is_empty())
    }

    /// What the store holds, as the apps need it before any unlock. A device
    /// state with a pinned account and no params record means the account
    /// this device knew has disappeared from the store: an integrity fault,
    /// never an empty store a new account could be created in.
    pub fn account_state(&self) -> Result<AccountState> {
        let has_account = self.has_account()?;
        let pinned = self.device_state()?.pinned.is_some();
        Ok(match (has_account, pinned) {
            (true, _) => AccountState::Present,
            (false, true) => AccountState::PinnedButMissing,
            (false, false) => AccountState::Empty,
        })
    }

    /// Empty every table in one transaction (records, sync state, device
    /// state). For a store whose account creation was abandoned: the file
    /// stays in place, so other open connections keep working on it.
    pub fn reset(&mut self) -> Result<()> {
        let tx = self.write_tx()?;
        for table in ["base", "pending", "staging", "ancestor", "kept", "meta"] {
            tx.execute(&format!("DELETE FROM {table}"), [])
                .map_err(store_err)?;
        }
        tx.commit()
    }

    /// For a device whose account disappeared from the store (account
    /// missing): empties every table like `reset`, device state included (the
    /// pin and the last seen manifests), in one transaction, so a restore or a
    /// new account can start from scratch. Refused while an account params
    /// record is visible: a readable account is never wiped by this path.
    pub fn reset_for_recovery(&mut self) -> Result<()> {
        let tx = self.write_tx()?;
        let visible: bool = tx
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM pending WHERE kind = ?1 AND data IS NOT NULL)
                     OR EXISTS (SELECT 1 FROM base b WHERE kind = ?1 AND NOT EXISTS
                         (SELECT 1 FROM pending p WHERE p.kind = b.kind AND p.id = b.id))",
                params![RecordKind::AccountParams.code()],
                |r| r.get(0),
            )
            .map_err(store_err)?;
        if visible {
            return Err(Error::InvalidFormat("store holds an account"));
        }
        for table in ["base", "pending", "staging", "ancestor", "kept", "meta"] {
            tx.execute(&format!("DELETE FROM {table}"), [])
                .map_err(store_err)?;
        }
        tx.commit()
    }

    /// Remote deletions (or removals by a full fetch) the store refused,
    /// oldest first, at most `MAX_IGNORED_DELETIONS`.
    pub fn ignored_deletions(&self) -> Result<Vec<IgnoredDeletion>> {
        self.read(ignored_in)
    }

    /// Empty the log of ignored deletions.
    pub fn clear_ignored_deletions(&mut self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM meta WHERE key = ?1",
                params![IGNORED_DELETIONS_KEY],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Vaults whose pending local writes a rebase dropped because the
    /// signed vault list marks them deleted (`Repository::rebase`), oldest
    /// first, at most `MAX_IGNORED_DELETIONS`.
    pub fn dropped_vault_writes(&self) -> Result<Vec<DroppedVaultWrites>> {
        Ok(self
            .read(|c| log_in(c, DROPPED_WRITES_KEY))?
            .into_iter()
            .map(|e| DroppedVaultWrites {
                vault_id: e.id,
                at: e.at,
            })
            .collect())
    }

    /// Empty the log of dropped vault writes.
    pub fn clear_dropped_vault_writes(&mut self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM meta WHERE key = ?1",
                params![DROPPED_WRITES_KEY],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// Drop every pending write (not the tombstones) into `vault`: its key,
    /// meta and manifest rows with data and its item records, with the
    /// manifest's ancestor unless a pending tombstone of the manifest still
    /// needs it. If anything was dropped, the vault is appended to the log
    /// of `dropped_vault_writes`. Returns whether anything was dropped. For
    /// a vault the verified vault list marks deleted (`Repository::rebase`).
    pub(crate) fn drop_pending_vault_writes(&mut self, vault: Id) -> Result<bool> {
        let tx = self.write_tx()?;
        let dropped = tx
            .execute(
                "DELETE FROM pending WHERE data IS NOT NULL AND (
                     (kind IN (?1, ?2, ?3) AND id = ?5)
                     OR (kind = ?4 AND substr(data, 1, 16) = ?5))",
                params![
                    RecordKind::VaultKey.code(),
                    RecordKind::VaultMeta.code(),
                    RecordKind::Manifest.code(),
                    RecordKind::Item.code(),
                    &vault.0[..]
                ],
            )
            .map_err(store_err)?;
        tx.execute(
            "DELETE FROM ancestor WHERE kind = ?1 AND id = ?2
                 AND NOT EXISTS (SELECT 1 FROM pending p WHERE p.kind = ?1 AND p.id = ?2)",
            params![RecordKind::Manifest.code(), &vault.0[..]],
        )
        .map_err(store_err)?;
        if dropped > 0 {
            append_log(&tx, DROPPED_WRITES_KEY, &[(RecordKind::Manifest, vault)])?;
        }
        tx.commit()?;
        Ok(dropped > 0)
    }

    /// Vaults held back because the server manifest caught up with, or
    /// passed, the local pending one. Sorted by id.
    pub fn vaults_needing_rebase(&self) -> Result<Vec<Id>> {
        Ok(held_vaults(&self.conn)?.into_iter().collect())
    }

    /// The `base` manifest a pending manifest of `vault` was built on.
    pub(crate) fn ancestor_manifest(&self, vault: Id) -> Result<Option<Record>> {
        self.conn
            .query_row(
                "SELECT version, data FROM ancestor WHERE kind = ?1 AND id = ?2",
                params![RecordKind::Manifest.code(), &vault.0[..]],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(store_err)?
            .map(|(version, data)| {
                decode_row(
                    i64::from(RecordKind::Manifest.code()),
                    vault.0.to_vec(),
                    version,
                    data,
                )
            })
            .transpose()
    }

    /// Remove every pending row of `vault` (its manifest and its items,
    /// deletions included) and the manifest's ancestor, so the next local
    /// write starts again from the current `base`. Read
    /// `ancestor_manifest` first.
    pub(crate) fn drop_pending_vault(&mut self, vault: Id) -> Result<()> {
        let tx = self.write_tx()?;
        delete_vault_rows(&tx, vault)?;
        tx.commit()
    }

    /// Whether the pending restore epoch lost the race to another device's
    /// (see `held_epoch`).
    pub(crate) fn epoch_held(&self) -> Result<bool> {
        self.read(held_epoch)
    }

    /// The version (epoch number) of the restore epoch written here and not
    /// yet pushed, if any.
    pub(crate) fn pending_epoch(&self) -> Result<Option<u64>> {
        self.read(|c| {
            c.query_row(
                "SELECT version FROM pending WHERE kind = ?1 AND data IS NOT NULL",
                params![RecordKind::RestoreEpoch.code()],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(store_err)?
            .map(|v| u64::try_from(v).map_err(|_| Error::InvalidFormat("record version")))
            .transpose()
        })
    }

    /// Make the pending manifests of `vaults` built on the current `base`
    /// row: its ancestor becomes that row, so it is no longer held and its
    /// push overwrites what the server holds now. For an owner's explicit
    /// choice of the local copy (`issue_restore_epoch_from_local`), on the
    /// vaults the server is behind on or forked from only.
    pub(crate) fn rebuild_ancestors_on_base(&mut self, vaults: &[Id]) -> Result<()> {
        let tx = self.write_tx()?;
        let code = RecordKind::Manifest.code();
        for v in vaults {
            tx.execute(
                "DELETE FROM ancestor WHERE kind = ?1 AND id = ?2",
                params![code, &v.0[..]],
            )
            .map_err(store_err)?;
            tx.execute(
                "INSERT INTO ancestor (kind, id, version, data)
                 SELECT b.kind, b.id, b.version, b.data FROM base b
                 WHERE b.kind = ?1 AND b.id = ?2 AND EXISTS (SELECT 1 FROM pending p
                     WHERE p.kind = b.kind AND p.id = b.id AND p.data IS NOT NULL)",
                params![code, &v.0[..]],
            )
            .map_err(store_err)?;
        }
        tx.commit()
    }

    /// The signed lists held back because the server list caught up with,
    /// or passed, the local pending one (`held_lists`): `(kind, account id)`,
    /// sorted.
    pub fn lists_needing_rebase(&self) -> Result<Vec<(RecordKind, Id)>> {
        Ok(held_lists(&self.conn)?.into_iter().collect())
    }

    /// The `table` row (`base` or `ancestor`) of `(kind, id)`, if any.
    fn table_record(&self, table: &str, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        self.conn
            .query_row(
                &format!("SELECT version, data FROM {table} WHERE kind = ?1 AND id = ?2"),
                params![kind.code(), &id.0[..]],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(store_err)?
            .map(|(version, data)| decode_row(i64::from(kind.code()), id.0.to_vec(), version, data))
            .transpose()
    }

    /// The `base` row of `(kind, id)`: the last server state, under any
    /// pending row.
    pub(crate) fn base_record(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        self.table_record("base", kind, id)
    }

    /// The `base` row a pending row of `(kind, id)` was built on.
    pub(crate) fn ancestor_record(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        self.table_record("ancestor", kind, id)
    }

    /// Remove the pending row of `(kind, id)` and its ancestor, so the next
    /// local write starts again from the current `base`. Read
    /// `ancestor_record` first.
    pub(crate) fn drop_pending_record(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        let tx = self.write_tx()?;
        for table in ["pending", "ancestor"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE kind = ?1 AND id = ?2"),
                params![kind.code(), &id.0[..]],
            )
            .map_err(store_err)?;
        }
        tx.commit()
    }

    /// Drop every local write of vault rows (keys, metas, manifests, items),
    /// of the restore epoch and of the signed lists, their ancestors, the
    /// kept rows and the sync health: reads see the server's state only.
    /// For an owner's explicit choice of the server's copy
    /// (`issue_restore_epoch_take_server`), after the local one was
    /// exported. The lists go too: a pending vault list naming a vault
    /// created here, whose rows are dropped, would report it missing
    /// forever. Account params and keysets stay. One transaction.
    pub(crate) fn discard_local_changes(&mut self) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute(
            "DELETE FROM pending WHERE kind IN (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                RecordKind::VaultKey.code(),
                RecordKind::VaultMeta.code(),
                RecordKind::Item.code(),
                RecordKind::Manifest.code(),
                RecordKind::RestoreEpoch.code(),
                RecordKind::DeviceList.code(),
                RecordKind::VaultList.code()
            ],
        )
        .map_err(store_err)?;
        for table in ["ancestor", "kept"] {
            tx.execute(&format!("DELETE FROM {table}"), [])
                .map_err(store_err)?;
        }
        for key in [HEALTH_KEY, HEALTH_MEMORY_KEY] {
            tx.execute("DELETE FROM meta WHERE key = ?1", params![key])
                .map_err(store_err)?;
        }
        tx.commit()
    }

    /// The vaults whose sync health is not `Ok`, with their entry.
    pub(crate) fn health(&self) -> Result<BTreeMap<Id, HealthEntry>> {
        self.read(health_in)
    }

    /// The vaults whose copy "keep this device" pushes over the server's.
    ///
    /// A vault held for a rebase (`vaults_needing_rebase`: the server's
    /// manifest moved past the one the local copy was built on) is one only
    /// when it is a fork (`HealthEntry::fork`): otherwise another device's
    /// newer write is there, maybe incomplete, and the vault stays held on
    /// its copy until the rebase merges onto it. Any other vault is one when
    /// it is in alert or when the server went back on it: its `base`
    /// manifest is gone or older than the copy this device serves (its
    /// pending manifest, else its kept one). The health entry's `seq` is
    /// not used: after a first keep it is the epoch head, above any honest
    /// server state.
    pub(crate) fn keep_targets(&self) -> Result<Vec<Id>> {
        self.read(|c| {
            let held = held_vaults(c)?;
            let mut out = Vec::new();
            for (v, e) in health_in(c)? {
                if held.contains(&v) {
                    if e.fork {
                        out.push(v);
                    }
                    continue;
                }
                let older = match copy_manifest_version(c, v)? {
                    Some(copy) => base_manifest(c, v)?.is_none_or(|(version, _)| version < copy),
                    None => false,
                };
                if e.alert || older {
                    out.push(v);
                }
            }
            Ok(out)
        })
    }

    /// Whether "keep this device" has anything to do: a vault it would push
    /// over the server's (`keep_targets`: every fork, every other vault in
    /// alert or that the server went back on). False while the only
    /// trouble is a newer server state still incomplete: the rebase settles
    /// it, and an epoch issued then would be withdrawn.
    pub(crate) fn keep_needed(&self) -> Result<bool> {
        Ok(!self.keep_targets()?.is_empty())
    }

    /// Replace the entries of `vaults` by fresh ones for the copy at
    /// `seq`: behind, not counted yet, no alert. After the owner chose this
    /// device's copy.
    pub(crate) fn restart_health(&mut self, vaults: &BTreeMap<Id, u64>) -> Result<()> {
        let tx = self.write_tx()?;
        update_health(&tx, |map| {
            for (v, seq) in vaults {
                let cause = map
                    .get(v)
                    .map_or(IntegrityError::ManifestRollback, |e| e.cause);
                map.insert(*v, HealthEntry::new(*seq, cause));
            }
            !vaults.is_empty()
        })?;
        tx.commit()
    }

    /// Forget the sync health and the memory of cleared vaults, after the
    /// owner chose to (`Repository::reset_sync_health`): every vault reads
    /// `Ok` until the next rounds find it behind again. The way out of an
    /// unreadable health map that discards nothing.
    pub(crate) fn reset_health(&mut self) -> Result<()> {
        let tx = self.write_tx()?;
        for key in [HEALTH_KEY, HEALTH_MEMORY_KEY] {
            tx.execute("DELETE FROM meta WHERE key = ?1", params![key])
                .map_err(store_err)?;
        }
        tx.commit()
    }

    /// The end of a sync round at `now` (Unix seconds).
    ///
    /// A vault that loaded cleanly in this round (`VaultEvent::Clean` with
    /// nothing left to confirm) counts one clean round; after
    /// `STALE_CLEAR_ROUNDS` clean rounds in a row its entry is removed
    /// (`Ok`). A single clean round is not enough: a store that serves the
    /// good state one round and the old one the next keeps the vault behind
    /// and its count running.
    ///
    /// Every other vault still behind counts one more round, from `now` if
    /// it was not counted yet, and becomes an alert once it reached
    /// `STALE_ALERT_ROUNDS` rounds and `STALE_ALERT_SECONDS` seconds, or
    /// `STALE_ALERT_MAX_ROUNDS` rounds whatever the clock says. A clock
    /// earlier than `since` moves `since` back: a clock set forward once
    /// cannot push the alert back.
    ///
    /// The clean mark is spent by the round that counts it: the next round
    /// is clean only if a fresh clean load marks it again, so a round that
    /// stopped before loading the vault (an epoch or vault list error)
    /// counts as behind, not clean. A cleared vault's count is remembered
    /// for `STALE_MEMORY_ROUNDS` rounds (`HealthMemory`), alert included.
    ///
    /// An alert from a fork or from no verified copy (`VaultEvent::Alert`)
    /// is never cleared here: only a safe exit (keep this device, take the
    /// server, `reset_health`) ends it. An alert reached by staying behind
    /// clears like the rest, after `STALE_CLEAR_ROUNDS` clean rounds.
    ///
    /// Fails closed: an unreadable health map is an error.
    pub(crate) fn count_round(&mut self, now: i64) -> Result<()> {
        let tx = self.write_tx()?;
        let mut memory = memory_in(&tx)?;
        let memory_before = memory.clone();
        memory.retain(|_, m| {
            m.left = m.left.saturating_sub(1);
            m.left > 0
        });
        update_health(&tx, |map| {
            let mut cleared = Vec::new();
            for (v, e) in map.iter_mut() {
                if e.clean {
                    e.clean = false;
                    if e.fork {
                        // A fork (or no verified copy) is settled by a safe
                        // exit only, never by clean rounds.
                        e.clean_rounds = 0;
                        continue;
                    }
                    e.clean_rounds = e.clean_rounds.saturating_add(1);
                    if u32::from(e.clean_rounds) >= STALE_CLEAR_ROUNDS {
                        cleared.push(*v);
                    }
                    continue;
                }
                e.clean_rounds = 0;
                if e.alert {
                    continue;
                }
                let since = e.since.map_or(now, |s| s.min(now));
                e.since = Some(since);
                e.rounds = e.rounds.saturating_add(1);
                if e.rounds >= STALE_ALERT_ROUNDS
                    && (now.saturating_sub(since) >= STALE_ALERT_SECONDS
                        || e.rounds >= STALE_ALERT_MAX_ROUNDS)
                {
                    e.alert = true;
                }
            }
            for v in cleared {
                if let Some(e) = map.remove(&v) {
                    memory.insert(
                        v,
                        HealthMemory {
                            since: e.since,
                            rounds: e.rounds,
                            alert: e.alert,
                            left: u8::try_from(STALE_MEMORY_ROUNDS).unwrap_or(u8::MAX),
                        },
                    );
                }
            }
            true
        })?;
        if memory != memory_before {
            save_memory(&tx, &memory)?;
        }
        tx.commit()
    }

    /// Remove the pending restore epoch and its ancestor: reads see the
    /// server's epoch again.
    pub(crate) fn drop_pending_epoch(&mut self) -> Result<()> {
        let tx = self.write_tx()?;
        let code = RecordKind::RestoreEpoch.code();
        tx.execute("DELETE FROM pending WHERE kind = ?1", params![code])
            .map_err(store_err)?;
        tx.execute("DELETE FROM ancestor WHERE kind = ?1", params![code])
            .map_err(store_err)?;
        tx.commit()
    }
}

/// What `SyncStore::account_state` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    /// No account params and no pinned account: a new account may be created.
    Empty,
    /// An account params record is visible.
    Present,
    /// This device pinned an account whose params record is gone.
    PinnedButMissing,
}

/// A remote deletion (or a removal by a full fetch from scratch) the store
/// refused: which record, and when (Unix seconds, device clock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgnoredDeletion {
    pub kind: RecordKind,
    pub id: Id,
    pub at: i64,
}

/// A vault whose pending local writes a rebase dropped because the signed
/// vault list marks it deleted (spec 4.5): which vault, and when (Unix
/// seconds, device clock).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DroppedVaultWrites {
    pub vault_id: Id,
    pub at: i64,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// Version byte, then `kind (1) | id (16) | at (8, big endian)` per entry.
fn encode_ignored(entries: &[IgnoredDeletion]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + entries.len() * IGNORED_ENTRY_BYTES);
    out.push(IGNORED_LOG_VERSION);
    for e in entries {
        out.push(e.kind.code());
        out.extend_from_slice(&e.id.0);
        out.extend_from_slice(&e.at.to_be_bytes());
    }
    out
}

fn decode_ignored(bytes: &[u8]) -> Result<Vec<IgnoredDeletion>> {
    let bad = || Error::InvalidFormat("ignored deletions");
    let (&version, rest) = bytes.split_first().ok_or_else(bad)?;
    if version != IGNORED_LOG_VERSION || rest.len() % IGNORED_ENTRY_BYTES != 0 {
        return Err(bad());
    }
    let (entries, tail) = rest.as_chunks::<IGNORED_ENTRY_BYTES>();
    if !tail.is_empty() {
        return Err(bad());
    }
    entries
        .iter()
        .map(|c| {
            let id: [u8; 16] = c[1..17].try_into().map_err(|_| bad())?;
            let at: [u8; 8] = c[17..25].try_into().map_err(|_| bad())?;
            Ok(IgnoredDeletion {
                kind: RecordKind::from_code(c[0])?,
                id: Id(id),
                at: i64::from_be_bytes(at),
            })
        })
        .collect()
}

fn ignored_in(conn: &Connection) -> Result<Vec<IgnoredDeletion>> {
    log_in(conn, IGNORED_DELETIONS_KEY)
}

/// The capped log under `key` (ignored deletions, dropped vault writes).
fn log_in(conn: &Connection, key: &str) -> Result<Vec<IgnoredDeletion>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .optional()
        .map_err(store_err)?;
    bytes.map_or(Ok(Vec::new()), |b| decode_ignored(&b))
}

/// Append to the capped log, oldest entries dropped past the cap. One entry
/// per `(kind, id)`: a record refused again moves to the end with the latest
/// time. An unreadable log (edited file) starts again empty: logging never
/// blocks a commit.
fn append_ignored(conn: &Connection, new: &[(RecordKind, Id)]) -> Result<()> {
    append_log(conn, IGNORED_DELETIONS_KEY, new)
}

/// `append_ignored` for the capped log under `key`.
fn append_log(conn: &Connection, key: &str, new: &[(RecordKind, Id)]) -> Result<()> {
    if new.is_empty() {
        return Ok(());
    }
    let mut entries = log_in(conn, key).unwrap_or_default();
    let at = unix_now();
    entries.retain(|e| !new.contains(&(e.kind, e.id)));
    let mut fresh: Vec<(RecordKind, Id)> = Vec::with_capacity(new.len());
    for key in new {
        if !fresh.contains(key) {
            fresh.push(*key);
        }
    }
    let new = fresh;
    entries.extend(
        new.iter()
            .map(|&(kind, id)| IgnoredDeletion { kind, id, at }),
    );
    let excess = entries.len().saturating_sub(MAX_IGNORED_DELETIONS);
    entries.drain(..excess);
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        params![key, encode_ignored(&entries)],
    )
    .map_err(store_err)?;
    Ok(())
}

/// The device state persisted in `meta`, or the default one.
fn device_state_in(conn: &Connection) -> Result<DeviceState> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![DEVICE_STATE_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(store_err)?;
    match bytes {
        Some(bytes) => DeviceState::decode(&bytes),
        None => Ok(DeviceState::default()),
    }
}

/// The sync state of a vault that is not `Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HealthEntry {
    /// Seq of the device's copy the server is behind on.
    pub seq: u64,
    /// The check the server's state failed.
    pub cause: IntegrityError,
    /// Unix seconds of the first round that counted it.
    pub since: Option<i64>,
    pub rounds: u32,
    /// The server took this device's copy back (`mark_pushed`) and no fetch
    /// served it yet: until one does, the server is not trusted to have
    /// kept it.
    pub awaiting: bool,
    pub alert: bool,
    /// The vault loaded cleanly from a state the server served, with
    /// nothing left to confirm, since the last round that found it behind.
    pub clean: bool,
    /// Clean rounds in a row (`count_round`).
    pub clean_rounds: u8,
    /// The alert came from a fork or from no verified copy
    /// (`VaultEvent::Alert`), not from staying behind: clean rounds never
    /// clear it, only a safe exit.
    pub fork: bool,
}

impl HealthEntry {
    fn new(seq: u64, cause: IntegrityError) -> HealthEntry {
        HealthEntry {
            seq,
            cause,
            since: None,
            rounds: 0,
            awaiting: false,
            alert: false,
            clean: false,
            clean_rounds: 0,
            fork: false,
        }
    }

    /// Found behind (or alerting) again: the clean streak restarts.
    fn dirty(&mut self) {
        self.clean = false;
        self.clean_rounds = 0;
    }
}

/// The count of a vault cleared after `STALE_CLEAR_ROUNDS` clean rounds,
/// kept for `STALE_MEMORY_ROUNDS` rounds: found behind again meanwhile, the
/// vault resumes it (`resume`) instead of starting from zero, so a store
/// that rolls back once every few rounds cannot keep the alert away by
/// letting the vault clear in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HealthMemory {
    since: Option<i64>,
    rounds: u32,
    /// It was cleared in alert: found behind again, it is an alert at once.
    alert: bool,
    /// Rounds before it is forgotten.
    left: u8,
}

/// A vault found behind (or alerting) with no entry yet: its entry, which
/// resumes the count of `memory` if it was cleared lately.
fn resume(
    memory: &mut BTreeMap<Id, HealthMemory>,
    vault: Id,
    seq: u64,
    cause: IntegrityError,
) -> HealthEntry {
    let mut e = HealthEntry::new(seq, cause);
    if let Some(m) = memory.remove(&vault) {
        e.since = m.since;
        e.rounds = m.rounds;
        e.alert = m.alert;
    }
    e
}

/// The code of an `IntegrityError` persisted in the health map. Exhaustive:
/// a new variant does not compile until it gets its code.
fn cause_code(e: IntegrityError) -> u8 {
    match e {
        IntegrityError::Commitment => 0,
        IntegrityError::Aead => 1,
        IntegrityError::Signature => 2,
        IntegrityError::ManifestRollback => 3,
        IntegrityError::ManifestMissingItem => 4,
        IntegrityError::ManifestUnexpectedItem => 5,
        IntegrityError::ManifestItemMismatch => 6,
        IntegrityError::ParamsUnsigned => 7,
        IntegrityError::ParamsDowngrade => 8,
        IntegrityError::WrongKind => 9,
        IntegrityError::WrongContext => 10,
        IntegrityError::VaultMissing => 11,
        IntegrityError::EpochRollback => 12,
        IntegrityError::ParamsRollback => 13,
        IntegrityError::DeviceListRollback => 14,
        IntegrityError::VaultListRollback => 15,
    }
}

fn cause_of(code: u8) -> Option<IntegrityError> {
    Some(match code {
        0 => IntegrityError::Commitment,
        1 => IntegrityError::Aead,
        2 => IntegrityError::Signature,
        3 => IntegrityError::ManifestRollback,
        4 => IntegrityError::ManifestMissingItem,
        5 => IntegrityError::ManifestUnexpectedItem,
        6 => IntegrityError::ManifestItemMismatch,
        7 => IntegrityError::ParamsUnsigned,
        8 => IntegrityError::ParamsDowngrade,
        9 => IntegrityError::WrongKind,
        10 => IntegrityError::WrongContext,
        11 => IntegrityError::VaultMissing,
        12 => IntegrityError::EpochRollback,
        13 => IntegrityError::ParamsRollback,
        14 => IntegrityError::DeviceListRollback,
        15 => IntegrityError::VaultListRollback,
        _ => return None,
    })
}

const HEALTH_SINCE: u8 = 1;
const HEALTH_AWAITING: u8 = 2;
const HEALTH_ALERT: u8 = 4;
const HEALTH_CLEAN: u8 = 8;
const HEALTH_FORK: u8 = 16;

fn encode_health(map: &BTreeMap<Id, HealthEntry>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + map.len() * HEALTH_ENTRY_BYTES);
    out.push(HEALTH_VERSION);
    for (v, e) in map {
        let flags = if e.since.is_some() { HEALTH_SINCE } else { 0 }
            | if e.awaiting { HEALTH_AWAITING } else { 0 }
            | if e.alert { HEALTH_ALERT } else { 0 }
            | if e.clean { HEALTH_CLEAN } else { 0 }
            | if e.fork { HEALTH_FORK } else { 0 };
        out.extend_from_slice(&v.0);
        out.extend_from_slice(&e.seq.to_be_bytes());
        out.push(cause_code(e.cause));
        out.push(flags);
        out.extend_from_slice(&e.since.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&e.rounds.to_be_bytes());
        out.push(e.clean_rounds);
    }
    out
}

fn health_unreadable() -> Error {
    Error::Store("sync health unreadable".into())
}

/// Decodes the health map. Fails closed: a map of another version or
/// length is an error (never an empty map, which would hide every alert),
/// and an entry with an unknown cause code is kept as an alert.
fn decode_health(bytes: &[u8]) -> Result<BTreeMap<Id, HealthEntry>> {
    let (&version, rest) = bytes.split_first().ok_or_else(health_unreadable)?;
    if version != HEALTH_VERSION {
        return Err(health_unreadable());
    }
    let (entries, tail) = rest.as_chunks::<HEALTH_ENTRY_BYTES>();
    if !tail.is_empty() {
        return Err(health_unreadable());
    }
    let mut map = BTreeMap::new();
    for c in entries {
        let mut id = [0; 16];
        id.copy_from_slice(&c[0..16]);
        let mut seq = [0; 8];
        seq.copy_from_slice(&c[16..24]);
        let flags = c[25];
        let mut since = [0; 8];
        since.copy_from_slice(&c[26..34]);
        let mut rounds = [0; 4];
        rounds.copy_from_slice(&c[34..38]);
        let cause = cause_of(c[24]);
        map.insert(
            Id(id),
            HealthEntry {
                seq: u64::from_be_bytes(seq),
                cause: cause.unwrap_or(IntegrityError::ManifestRollback),
                since: (flags & HEALTH_SINCE != 0).then_some(i64::from_be_bytes(since)),
                rounds: u32::from_be_bytes(rounds),
                awaiting: flags & HEALTH_AWAITING != 0,
                alert: cause.is_none() || flags & HEALTH_ALERT != 0,
                clean: flags & HEALTH_CLEAN != 0,
                clean_rounds: c[38],
                fork: flags & HEALTH_FORK != 0,
            },
        );
    }
    Ok(map)
}

/// The value of `key` in `meta`, if any.
fn meta_in(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
        r.get::<_, Vec<u8>>(0)
    })
    .optional()
    .map_err(store_err)
}

/// The health map in `meta`; empty when there is none. An unreadable one
/// (edited file) is an error, not an empty map.
fn health_in(conn: &Connection) -> Result<BTreeMap<Id, HealthEntry>> {
    match meta_in(conn, HEALTH_KEY)? {
        Some(b) => decode_health(&b),
        None => Ok(BTreeMap::new()),
    }
}

fn encode_memory(map: &BTreeMap<Id, HealthMemory>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + map.len() * HEALTH_MEMORY_ENTRY_BYTES);
    out.push(HEALTH_MEMORY_VERSION);
    for (v, m) in map {
        out.extend_from_slice(&v.0);
        out.push(
            if m.since.is_some() { HEALTH_SINCE } else { 0 }
                | if m.alert { HEALTH_ALERT } else { 0 },
        );
        out.extend_from_slice(&m.since.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&m.rounds.to_be_bytes());
        out.push(m.left);
    }
    out
}

/// Decodes the memory of cleared vaults; fails closed like `decode_health`.
fn decode_memory(bytes: &[u8]) -> Result<BTreeMap<Id, HealthMemory>> {
    let (&version, rest) = bytes.split_first().ok_or_else(health_unreadable)?;
    if version != HEALTH_MEMORY_VERSION {
        return Err(health_unreadable());
    }
    let (entries, tail) = rest.as_chunks::<HEALTH_MEMORY_ENTRY_BYTES>();
    if !tail.is_empty() {
        return Err(health_unreadable());
    }
    let mut map = BTreeMap::new();
    for c in entries {
        let mut id = [0; 16];
        id.copy_from_slice(&c[0..16]);
        let mut since = [0; 8];
        since.copy_from_slice(&c[17..25]);
        let mut rounds = [0; 4];
        rounds.copy_from_slice(&c[25..29]);
        map.insert(
            Id(id),
            HealthMemory {
                since: (c[16] & HEALTH_SINCE != 0).then_some(i64::from_be_bytes(since)),
                rounds: u32::from_be_bytes(rounds),
                alert: c[16] & HEALTH_ALERT != 0,
                left: c[29],
            },
        );
    }
    Ok(map)
}

fn memory_in(conn: &Connection) -> Result<BTreeMap<Id, HealthMemory>> {
    match meta_in(conn, HEALTH_MEMORY_KEY)? {
        Some(b) => decode_memory(&b),
        None => Ok(BTreeMap::new()),
    }
}

fn save_memory(conn: &Connection, map: &BTreeMap<Id, HealthMemory>) -> Result<()> {
    if map.is_empty() {
        conn.execute(
            "DELETE FROM meta WHERE key = ?1",
            params![HEALTH_MEMORY_KEY],
        )
    } else {
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![HEALTH_MEMORY_KEY, encode_memory(map)],
        )
    }
    .map_err(store_err)?;
    Ok(())
}

/// `update_health` for the paths a read or a fetch takes: an unreadable
/// map is left as is (so `health` keeps failing and the app offers the
/// safe exits) and `f` is skipped, instead of blocking every read and the
/// export of the vaults.
fn update_health_lenient(
    conn: &Connection,
    f: impl FnOnce(&mut BTreeMap<Id, HealthEntry>) -> bool,
) -> Result<()> {
    match health_in(conn) {
        Ok(map) => save_health(conn, map, f),
        Err(_) => Ok(()),
    }
}

/// Apply `f` to the health map and save it if `f` says it changed. Fails
/// closed on an unreadable map.
fn update_health(
    conn: &Connection,
    f: impl FnOnce(&mut BTreeMap<Id, HealthEntry>) -> bool,
) -> Result<()> {
    save_health(conn, health_in(conn)?, f)
}

fn save_health(
    conn: &Connection,
    mut map: BTreeMap<Id, HealthEntry>,
    f: impl FnOnce(&mut BTreeMap<Id, HealthEntry>) -> bool,
) -> Result<()> {
    if !f(&mut map) {
        return Ok(());
    }
    if map.is_empty() {
        conn.execute("DELETE FROM meta WHERE key = ?1", params![HEALTH_KEY])
    } else {
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![HEALTH_KEY, encode_health(&map)],
        )
    }
    .map_err(store_err)?;
    Ok(())
}

/// The kept rows of one vault, `?3`: its manifest (kind `?1`) and its item
/// records by vault prefix (kind `?2`).
const KEPT_ROWS: &str = "(kind = ?1 AND id = ?3) OR (kind = ?2 AND substr(data, 1, 16) = ?3)";

fn delete_kept(tx: &Connection, vault: Id) -> Result<()> {
    tx.execute(
        &format!("DELETE FROM kept WHERE {KEPT_ROWS}"),
        params![
            RecordKind::Manifest.code(),
            RecordKind::Item.code(),
            &vault.0[..]
        ],
    )
    .map_err(store_err)?;
    Ok(())
}

/// The `base` manifest row of a vault: `(version, data)`.
fn base_manifest(conn: &Connection, vault: Id) -> Result<Option<(u64, Vec<u8>)>> {
    conn.query_row(
        "SELECT version, data FROM base WHERE kind = ?1 AND id = ?2",
        params![RecordKind::Manifest.code(), &vault.0[..]],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
    )
    .optional()
    .map_err(store_err)?
    .map(|(v, d)| {
        u64::try_from(v)
            .map(|v| (v, d))
            .map_err(|_| Error::InvalidFormat("record version"))
    })
    .transpose()
}

/// The version of the copy of `vault` this device serves over the
/// server's: its pending manifest, else its kept one.
fn copy_manifest_version(conn: &Connection, vault: Id) -> Result<Option<u64>> {
    let code = RecordKind::Manifest.code();
    let pending: Option<i64> = conn
        .query_row(
            "SELECT version FROM pending WHERE kind = ?1 AND id = ?2 AND data IS NOT NULL",
            params![code, &vault.0[..]],
            |r| r.get(0),
        )
        .optional()
        .map_err(store_err)?;
    let version = match pending {
        Some(v) => Some(v),
        None => conn
            .query_row(
                "SELECT version FROM kept WHERE kind = ?1 AND id = ?2",
                params![code, &vault.0[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?,
    };
    version
        .map(|v| u64::try_from(v).map_err(|_| Error::InvalidFormat("record version")))
        .transpose()
}

fn has_pending_manifest(conn: &Connection, vault: Id) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM pending WHERE kind = ?1 AND id = ?2 AND data IS NOT NULL)",
        params![RecordKind::Manifest.code(), &vault.0[..]],
        |r| r.get(0),
    )
    .map_err(store_err)
}

/// `RecordStore::delete` inside a transaction: a row known to the server
/// becomes a tombstone carrying its version, a local-only row vanishes. A
/// signed list record is never deleted (spec 4.2: the lists only grow):
/// `InvalidFormat("list record deletion")`.
fn delete_in(tx: &Connection, kind: RecordKind, id: Id) -> Result<()> {
    if matches!(kind, RecordKind::DeviceList | RecordKind::VaultList) {
        return Err(Error::InvalidFormat("list record deletion"));
    }
    let base_row: Option<(i64, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT version, substr(data, 1, 16) FROM base WHERE kind = ?1 AND id = ?2",
            params![kind.code(), &id.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(store_err)?;
    match base_row {
        // Known to the server: a tombstone carrying the deleted version.
        Some((version, prefix)) => {
            // An item tombstone keeps its vault, for holding and dropping.
            let vault = if kind == RecordKind::Item {
                prefix
            } else {
                None
            };
            if kind == RecordKind::Manifest {
                tx.execute(
                    "INSERT OR IGNORE INTO ancestor (kind, id, version, data)
                     SELECT kind, id, version, data FROM base WHERE kind = ?1 AND id = ?2",
                    params![kind.code(), &id.0[..]],
                )
                .map_err(store_err)?;
            }
            tx.execute(
                "INSERT OR REPLACE INTO pending (kind, id, version, data, vault)
                 VALUES (?1, ?2, ?3, NULL, ?4)",
                params![kind.code(), &id.0[..], version, vault],
            )
            .map_err(store_err)?;
        }
        // Local only: it vanishes.
        None => {
            tx.execute(
                "DELETE FROM pending WHERE kind = ?1 AND id = ?2",
                params![kind.code(), &id.0[..]],
            )
            .map_err(store_err)?;
        }
    }
    Ok(())
}

/// A remote deletion `commit_remote` ignores: account params, keysets, the
/// restore epoch and the signed device and vault lists (never deleted by a
/// client), and the vault key, meta or manifest of a vault the device has
/// seen, unless the verified vault list marks that vault deleted
/// (`deleted`, spec 4.5). A store that hides the epoch from a device with a
/// fresh copy is caught by the repository (`EpochRollback`).
fn protected_from_remote_deletion(
    kind: RecordKind,
    id: &[u8],
    seen: &BTreeSet<Id>,
    deleted: &BTreeSet<Id>,
) -> bool {
    match kind {
        RecordKind::AccountParams
        | RecordKind::Keyset
        | RecordKind::RestoreEpoch
        | RecordKind::DeviceList
        | RecordKind::VaultList => true,
        RecordKind::VaultKey | RecordKind::VaultMeta | RecordKind::Manifest => {
            decode_id(id.to_vec()).is_ok_and(|v| seen.contains(&v) && !deleted.contains(&v))
        }
        RecordKind::Item => false,
    }
}

/// The vaults the account's signed vault list marks deleted, as this store
/// can prove it without an unlock: the pinned account (device state) gives
/// the account id and identity; the `base` account params of that account,
/// signed by that identity (`account::signed_params`), give the signing
/// key; the vault list in `base`, and the one staged in `staged` (this
/// batch), each count if it verifies under that key against the pinned
/// chain state (`lists::verify`) and is the account's. Fail closed: no pin,
/// no params, a list that does not verify, or any read error proves
/// nothing (empty set, or that list skipped).
fn deleted_vaults(conn: &Connection, staged: &[StagedRow]) -> BTreeSet<Id> {
    proven_deleted(conn, staged).unwrap_or_default()
}

fn proven_deleted(conn: &Connection, staged: &[StagedRow]) -> Result<BTreeSet<Id>> {
    let mut out = BTreeSet::new();
    let Some(pin) = device_state_in(conn)?.pinned else {
        return Ok(out);
    };
    let account = pin.account_id;
    let Some(params) = row_data(conn, "base", RecordKind::AccountParams, account)? else {
        return Ok(out);
    };
    let signing = signed_params(&params, Some(&pin))?.signing_pub;
    let chain = chain_state_in(conn)?;
    let base = row_data(conn, "base", RecordKind::VaultList, account)?;
    let incoming = staged.iter().find_map(|(kind, id, _, data, _)| {
        (*kind == i64::from(RecordKind::VaultList.code()) && id[..] == account.0[..])
            .then_some(data.as_deref())
            .flatten()
    });
    for bytes in [base.as_deref(), incoming].into_iter().flatten() {
        let Ok(body) = verify::<VaultListEntry>(
            &signing,
            VAULT_LIST_DOMAIN,
            bytes,
            chain.vault_list.as_ref(),
        ) else {
            continue;
        };
        if body.account_id != account {
            continue;
        }
        out.extend(
            body.entries
                .iter()
                .filter(|e| e.deleted_at.is_some())
                .map(|e| e.vault_id),
        );
    }
    Ok(out)
}

/// The persisted chain state, or the default one.
fn chain_state_in(conn: &Connection) -> Result<ChainState> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![CHAIN_STATE_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(store_err)?;
    bytes.map_or(Ok(ChainState::default()), |b| ChainState::decode(&b))
}

/// Merge two chain states of one account (this process's, `mem`, and the
/// one stored by any process on the file), so that no pin goes back:
/// - `params_epoch`: the larger;
/// - each signed list seen: the larger `seq`; the same `seq` with another
///   hash is a fork (`DeviceListRollback`, `VaultListRollback`), unless
///   `force_lists` (a list rebase renumbered the lists in memory: the
///   memory ones stand, as for the vaults a manifest rebase forces);
/// - `device_id`: set once, never changed: two different ids for this
///   device is refused like a fork (`DeviceListRollback`).
pub(crate) fn merge_chain(
    mem: &ChainState,
    stored: &ChainState,
    force_lists: bool,
) -> Result<ChainState> {
    fn seen(
        mem: Option<Seen>,
        stored: Option<Seen>,
        force: bool,
        fork: IntegrityError,
    ) -> Result<Option<Seen>> {
        Ok(match (mem, stored) {
            (Some(m), _) if force => Some(m),
            (Some(m), Some(s)) if m.seq == s.seq && m.hash != s.hash => {
                return Err(fork.into());
            }
            (Some(m), Some(s)) => Some(if m.seq >= s.seq { m } else { s }),
            (m, s) => m.or(s),
        })
    }
    let device_id = match (mem.device_id, stored.device_id) {
        (Some(m), Some(s)) if m != s => {
            return Err(IntegrityError::DeviceListRollback.into());
        }
        (m, s) => m.or(s),
    };
    Ok(ChainState {
        params_epoch: mem.params_epoch.max(stored.params_epoch),
        device_list: seen(
            mem.device_list,
            stored.device_list,
            force_lists,
            IntegrityError::DeviceListRollback,
        )?,
        vault_list: seen(
            mem.vault_list,
            stored.vault_list,
            force_lists,
            IntegrityError::VaultListRollback,
        )?,
        device_id,
    })
}

/// Forget the `deleted` vaults (the signed vault list marks them deleted):
/// they leave the persisted `last_seen`, their kept rows go, and so does
/// their sync health, so that an alert about a vault the owner deleted
/// never outlives it (no safe exit could clear it: `vaults()` no longer
/// returns the vault). An unreadable health map is left as is.
fn forget_seen(conn: &Connection, deleted: &BTreeSet<Id>) -> Result<()> {
    for v in deleted {
        delete_kept(conn, *v)?;
    }
    update_health_lenient(conn, |map| {
        let before = map.len();
        map.retain(|id, _| !deleted.contains(id));
        map.len() != before
    })?;
    if let Ok(mut memory) = memory_in(conn) {
        let before = memory.len();
        memory.retain(|id, _| !deleted.contains(id));
        if memory.len() != before {
            save_memory(conn, &memory)?;
        }
    }
    let mut state = device_state_in(conn)?;
    let before = state.last_seen.len();
    state.last_seen.retain(|id, _| !deleted.contains(id));
    if state.last_seen.len() == before {
        return Ok(());
    }
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        params![DEVICE_STATE_KEY, state.encode()],
    )
    .map_err(store_err)?;
    Ok(())
}

/// The pending rows of one vault, `?3`: its manifest (kind `?1`), its item
/// records by vault prefix and its item tombstones by their vault (kind
/// `?2`).
const VAULT_ROWS: &str = "(kind = ?1 AND id = ?3)
    OR (kind = ?2 AND data IS NOT NULL AND substr(data, 1, 16) = ?3)
    OR (kind = ?2 AND data IS NULL AND vault = ?3)";

/// A write transaction of `SyncStore::write_tx`.
enum WriteTx<'a> {
    Top(Transaction<'a>),
    Nested(Savepoint<'a>),
}

impl Deref for WriteTx<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        match self {
            WriteTx::Top(t) => t,
            WriteTx::Nested(s) => s,
        }
    }
}

impl WriteTx<'_> {
    fn commit(self) -> Result<()> {
        match self {
            WriteTx::Top(t) => t.commit(),
            WriteTx::Nested(s) => s.commit(),
        }
        .map_err(store_err)
    }
}

fn delete_vault_rows(tx: &Connection, vault: Id) -> Result<()> {
    let codes = (RecordKind::Manifest.code(), RecordKind::Item.code());
    tx.execute(
        &format!("DELETE FROM pending WHERE {VAULT_ROWS}"),
        params![codes.0, codes.1, &vault.0[..]],
    )
    .map_err(store_err)?;
    tx.execute(
        "DELETE FROM ancestor WHERE kind = ?1 AND id = ?2",
        params![codes.0, &vault.0[..]],
    )
    .map_err(store_err)?;
    Ok(())
}

impl RecordStore for SyncStore {
    fn put(&mut self, r: Record) -> Result<()> {
        check_size(&r.data)?;
        let tx = self.write_tx()?;
        write_pending(&tx, &r)?;
        tx.commit()
    }

    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
        check_size(&r.data)?;
        let tx = self.write_tx()?;
        if effective_version(&tx, r.kind, r.id)? != expected {
            return Err(Error::Conflict);
        }
        write_pending(&tx, &r)?;
        tx.commit()
    }

    /// Every conditional write in one transaction (or one savepoint of the
    /// open batch): a conflict or a failure on any of them, or a crash,
    /// leaves none of them.
    fn put_all_if_version(&mut self, writes: Vec<(Record, Option<u64>)>) -> Result<()> {
        for (r, _) in &writes {
            check_size(&r.data)?;
        }
        let tx = self.write_tx()?;
        for (r, expected) in &writes {
            if effective_version(&tx, r.kind, r.id)? != *expected {
                return Err(Error::Conflict);
            }
            write_pending(&tx, r)?;
        }
        tx.commit()
    }

    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        self.read(|c| effective_get(c, kind, id))
    }

    fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT kind, id, version, data FROM pending
                     WHERE kind = ?1 AND data IS NOT NULL
                 UNION ALL
                 SELECT kind, id, version, data FROM base b WHERE kind = ?1
                     AND NOT EXISTS (SELECT 1 FROM pending p WHERE p.kind = b.kind AND p.id = b.id)",
            )
            .map_err(store_err)?;
        let rows = stmt
            .query_map(params![kind.code()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .map_err(store_err)?;
        rows.map(|row| {
            let (k, id, v, d) = row.map_err(store_err)?;
            decode_row(k, id, v, d)
        })
        .collect()
    }

    fn restore_epoch_mark(&self) -> Result<Option<(u64, [u8; 32])>> {
        let Some(v) = self.meta(EPOCH_MARK_KEY)? else {
            return Ok(None);
        };
        let (epoch, hash) = v
            .split_first_chunk::<8>()
            .filter(|(_, h)| h.len() == 32)
            .ok_or(Error::InvalidFormat("restore epoch mark"))?;
        let mut h = [0u8; 32];
        h.copy_from_slice(hash);
        Ok(Some((u64::from_be_bytes(*epoch), h)))
    }

    fn set_restore_epoch_mark(&mut self, epoch: u64, hash: [u8; 32]) -> Result<()> {
        let mut v = epoch.to_be_bytes().to_vec();
        v.extend_from_slice(&hash);
        self.set_meta(EPOCH_MARK_KEY, &v)
    }

    fn chain_state(&self) -> Result<ChainState> {
        SyncStore::chain_state(self)
    }

    fn persists_chain(&self) -> bool {
        true
    }

    /// The writes and the chain state in one transaction (or one savepoint
    /// of the open batch). The chain state is merged with the stored one
    /// (`merge_chain`): another process on the file may have pinned a newer
    /// list or params epoch, or this device's id, meanwhile.
    fn put_all_if_version_with_chain(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: &ChainState,
    ) -> Result<()> {
        for (r, _) in &writes {
            check_size(&r.data)?;
        }
        let tx = self.write_tx()?;
        for (r, expected) in &writes {
            if effective_version(&tx, r.kind, r.id)? != *expected {
                return Err(Error::Conflict);
            }
            write_pending(&tx, r)?;
        }
        let merged = merge_chain(chain, &chain_state_in(&tx)?, false)?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![CHAIN_STATE_KEY, merged.encode()],
        )
        .map_err(store_err)?;
        tx.commit()
    }

    /// The conditional writes and the deletions (as `delete`) in one
    /// transaction (or one savepoint of the open batch).
    fn put_all_if_version_and_delete(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
    ) -> Result<()> {
        for (r, _) in &writes {
            check_size(&r.data)?;
        }
        let tx = self.write_tx()?;
        for (r, expected) in &writes {
            if effective_version(&tx, r.kind, r.id)? != *expected {
                return Err(Error::Conflict);
            }
            write_pending(&tx, r)?;
        }
        for (kind, id) in deletes {
            delete_in(&tx, kind, id)?;
        }
        tx.commit()
    }

    /// A signed list record is never deleted (spec 4.2: the lists only
    /// grow): `InvalidFormat("list record deletion")`, nothing written.
    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        let tx = self.write_tx()?;
        delete_in(&tx, kind, id)?;
        tx.commit()
    }

    fn kept_rows(&self, vault: Id) -> Result<Option<Vec<Record>>> {
        self.read(|c| {
            let mut stmt = c
                .prepare(&format!(
                    "SELECT kind, id, version, data FROM kept WHERE {KEPT_ROWS}"
                ))
                .map_err(store_err)?;
            let rows = stmt
                .query_map(
                    params![
                        RecordKind::Manifest.code(),
                        RecordKind::Item.code(),
                        &vault.0[..]
                    ],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .map_err(store_err)?;
            rows.map(|row| {
                let (k, id, v, d) = row.map_err(store_err)?;
                decode_row(k, id, v, d)
            })
            .collect::<Result<Vec<_>>>()
            .map(Some)
        })
    }

    /// Materialize the device's copy (see the trait). The pending
    /// manifest's ancestor decides what the push does: a `base` older than
    /// the copy (the server went back) becomes the ancestor, so the push
    /// restores the server's copy; a newer `base` (the server moved on, its
    /// state incomplete) leaves the copy itself as the ancestor, so the
    /// vault is held until the rebase merges onto the server's state.
    fn keep_local_copy(
        &mut self,
        vault: Id,
        manifest: &Record,
        restore: &[Record],
        unlisted: &[Id],
        write: bool,
    ) -> Result<()> {
        let tx = self.write_tx()?;
        let base = base_manifest(&tx, vault)?;
        let behind = base.as_ref().is_none_or(|(v, _)| *v < manifest.version);
        if !(write || behind) {
            return Ok(());
        }
        if effective_get(&tx, RecordKind::Manifest, vault)?.as_ref() != Some(manifest) {
            let version = to_i64(manifest.version)?;
            let code = RecordKind::Manifest.code();
            tx.execute(
                "INSERT OR REPLACE INTO pending (kind, id, version, data) VALUES (?1, ?2, ?3, ?4)",
                params![code, &vault.0[..], version, manifest.data],
            )
            .map_err(store_err)?;
            tx.execute(
                "DELETE FROM ancestor WHERE kind = ?1 AND id = ?2",
                params![code, &vault.0[..]],
            )
            .map_err(store_err)?;
            if base.is_some() {
                let (v, data) = if behind {
                    base.ok_or(Error::NotFound)?
                } else {
                    (manifest.version, manifest.data.clone())
                };
                tx.execute(
                    "INSERT INTO ancestor (kind, id, version, data) VALUES (?1, ?2, ?3, ?4)",
                    params![code, &vault.0[..], to_i64(v)?, data],
                )
                .map_err(store_err)?;
            }
        }
        for r in restore {
            check_size(&r.data)?;
            tx.execute(
                "INSERT OR REPLACE INTO pending (kind, id, version, data) VALUES (?1, ?2, ?3, ?4)",
                params![r.kind.code(), &r.id.0[..], to_i64(r.version)?, r.data],
            )
            .map_err(store_err)?;
        }
        for id in unlisted {
            delete_in(&tx, RecordKind::Item, *id)?;
        }
        tx.commit()
    }

    fn vault_event(&mut self, vault: Id, event: VaultEvent) -> Result<()> {
        // A clean load with nothing to settle writes nothing.
        if event == VaultEvent::Clean {
            let idle = self.read(|c| {
                let kept: bool = c
                    .query_row(
                        &format!("SELECT EXISTS (SELECT 1 FROM kept WHERE {KEPT_ROWS})"),
                        params![
                            RecordKind::Manifest.code(),
                            RecordKind::Item.code(),
                            &vault.0[..]
                        ],
                        |r| r.get(0),
                    )
                    .map_err(store_err)?;
                // An unreadable map is no entry here: reads go on.
                let entry = health_in(c).is_ok_and(|m| m.contains_key(&vault));
                Ok(!kept && !entry)
            })?;
            if idle {
                return Ok(());
            }
        }
        let tx = self.write_tx()?;
        match event {
            VaultEvent::Clean => {
                delete_kept(&tx, vault)?;
                // Clean once the server serves the copy back by itself;
                // settled after `STALE_CLEAR_ROUNDS` such rounds
                // (`count_round`).
                let pending = has_pending_manifest(&tx, vault)?;
                update_health_lenient(&tx, |map| match map.get_mut(&vault) {
                    Some(e) if !e.awaiting && !pending && !e.clean => {
                        e.clean = true;
                        true
                    }
                    _ => false,
                })?;
            }
            VaultEvent::Behind { seq, cause } => {
                // An unreadable map (or memory) is left as is: the read
                // goes on, `health` and `count_round` report it.
                if let (Ok(health), Ok(mut memory)) = (health_in(&tx), memory_in(&tx)) {
                    let resumed = memory.contains_key(&vault);
                    save_health(&tx, health, |map| {
                        let e = map
                            .entry(vault)
                            .or_insert_with(|| resume(&mut memory, vault, seq, cause));
                        e.seq = e.seq.max(seq);
                        e.cause = cause;
                        e.dirty();
                        true
                    })?;
                    if resumed && !memory.contains_key(&vault) {
                        save_memory(&tx, &memory)?;
                    }
                }
            }
            VaultEvent::EpochAccepted => {
                update_health_lenient(&tx, |map| match map.get_mut(&vault) {
                    Some(e) if e.fork => {
                        e.fork = false;
                        true
                    }
                    _ => false,
                })?;
            }
            VaultEvent::CaughtUp => {
                // The rebase verified the server's newer state: a clean
                // round, settled like the others. The device's copy is now
                // built on that state, so it is what the server must keep
                // serving: an older copy's seq (or the head of an epoch
                // that was withdrawn) no longer applies.
                delete_kept(&tx, vault)?;
                let base = base_manifest(&tx, vault)?.map(|(version, _)| version);
                update_health_lenient(&tx, |map| match map.get_mut(&vault) {
                    Some(e) => {
                        if let Some(version) = base {
                            e.seq = version;
                        }
                        e.awaiting = false;
                        e.clean = true;
                        true
                    }
                    None => false,
                })?;
            }
            VaultEvent::Alert { seq, cause } => {
                // An unreadable map (or memory) is left as is: the read
                // goes on, `health` and `count_round` report it.
                if let (Ok(health), Ok(mut memory)) = (health_in(&tx), memory_in(&tx)) {
                    let resumed = memory.contains_key(&vault);
                    save_health(&tx, health, |map| {
                        let e = map
                            .entry(vault)
                            .or_insert_with(|| resume(&mut memory, vault, seq, cause));
                        e.seq = e.seq.max(seq);
                        e.cause = cause;
                        e.alert = true;
                        e.fork = true;
                        e.dirty();
                        true
                    })?;
                    if resumed && !memory.contains_key(&vault) {
                        save_memory(&tx, &memory)?;
                    }
                }
            }
        }
        tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: Id, kind: RecordKind, version: u64, data: &[u8]) -> Record {
        Record {
            id,
            kind,
            version,
            data: data.to_vec(),
        }
    }

    fn item_data(vault: Id, body: &[u8]) -> Vec<u8> {
        let mut d = vault.0.to_vec();
        d.extend_from_slice(body);
        d
    }

    fn remote(kind: RecordKind, id: Id, version: u64, data: Option<Vec<u8>>) -> RemoteChange {
        RemoteChange {
            kind,
            id,
            version,
            data,
            server_meta: Some(vec![9, version as u8]),
        }
    }

    /// Put a record straight into `base`, as a server fetch would.
    fn fast_kdf() -> crate::crypto::KdfParams {
        crate::crypto::KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: crate::crypto::random_array().unwrap(),
        }
    }

    fn account_kinds(s: &SyncStore) -> Vec<RecordKind> {
        s.pending_changes()
            .unwrap()
            .into_iter()
            .map(|c| c.kind)
            .filter(|k| matches!(k, RecordKind::AccountParams | RecordKind::Keyset))
            .collect()
    }

    #[test]
    fn account_pair_goes_out_together_and_only_above_the_server_epoch() {
        let n = crate::account::Account::create_with_params("pw", fast_kdf()).unwrap();
        let a = n.account.params.account_id;
        let mut s = SyncStore::open_in_memory().unwrap();
        s.put(rec(a, RecordKind::AccountParams, 1, &n.params_record))
            .unwrap();
        // The params alone do not go out.
        assert_eq!(account_kinds(&s), vec![]);
        s.put(rec(a, RecordKind::Keyset, 1, &n.keyset_record))
            .unwrap();
        assert_eq!(
            account_kinds(&s),
            vec![RecordKind::AccountParams, RecordKind::Keyset]
        );
        // The keyset alone does not go out either.
        let mut keyset_only = SyncStore::open_in_memory().unwrap();
        keyset_only
            .put(rec(a, RecordKind::Keyset, 1, &n.keyset_record))
            .unwrap();
        assert_eq!(account_kinds(&keyset_only), vec![]);
        // A base copy the server does not hold (no server metadata, as a
        // zone reset leaves it): the pair goes out.
        let base = |s: &SyncStore, meta: Option<Vec<u8>>| {
            s.conn
                .execute(
                    "INSERT OR REPLACE INTO base (kind, id, version, data, server_meta)
                     VALUES (?1, ?2, 1, ?3, ?4)",
                    params![
                        RecordKind::AccountParams.code(),
                        &a.0[..],
                        n.params_record.clone(),
                        meta
                    ],
                )
                .unwrap();
        };
        base(&s, None);
        assert_eq!(
            account_kinds(&s),
            vec![RecordKind::AccountParams, RecordKind::Keyset]
        );
        // Server params at the same epoch: the pending pair stays home.
        base(&s, Some(vec![1]));
        assert_eq!(account_kinds(&s), vec![]);
        // Undecodable pending params never go out.
        let mut junk = SyncStore::open_in_memory().unwrap();
        junk.put(rec(a, RecordKind::AccountParams, 1, b"ap"))
            .unwrap();
        junk.put(rec(a, RecordKind::Keyset, 1, b"ks")).unwrap();
        assert_eq!(account_kinds(&junk), vec![]);
    }

    #[test]
    fn fetched_params_drop_an_overtaken_password_change() {
        let n = crate::account::Account::create_with_params("pw", fast_kdf()).unwrap();
        let a = n.account.params.account_id;
        let change = |pw: &str| {
            crate::account::Account::unlock(
                "pw",
                &n.secret_key,
                &n.params_record,
                &n.keyset_record,
                None,
            )
            .unwrap()
            .rekey(&n.secret_key, pw)
            .unwrap()
        };
        let (mine, theirs) = (change("mien"), change("le sien"));
        let fresh = || {
            let mut s = SyncStore::open_in_memory().unwrap();
            seed_base(
                &mut s,
                RecordKind::AccountParams,
                a,
                1,
                n.params_record.clone(),
            );
            seed_base(&mut s, RecordKind::Keyset, a, 1, n.keyset_record.clone());
            s.put(rec(a, RecordKind::Keyset, 2, &mine.keyset_record))
                .unwrap();
            s.put(rec(a, RecordKind::AccountParams, 2, &mine.params_record))
                .unwrap();
            s
        };
        let stage = |s: &mut SyncStore, kind, data: &[u8]| {
            s.stage_remote(remote(kind, a, 2, Some(data.to_vec())))
                .unwrap();
        };

        // Another change at the same epoch: both pending rows go, flagged once.
        let mut s = fresh();
        stage(&mut s, RecordKind::AccountParams, &theirs.params_record);
        stage(&mut s, RecordKind::Keyset, &theirs.keyset_record);
        s.commit_remote().unwrap();
        assert_eq!(count(&s, "pending"), 0);
        assert_eq!(
            s.get(RecordKind::AccountParams, a).unwrap().unwrap().data,
            theirs.params_record
        );
        assert!(s.take_password_change_superseded().unwrap());
        assert!(!s.take_password_change_superseded().unwrap());

        // The server echoes this very change (pushed, never marked): the
        // pending rows go, without a flag.
        let mut s = fresh();
        stage(&mut s, RecordKind::AccountParams, &mine.params_record);
        stage(&mut s, RecordKind::Keyset, &mine.keyset_record);
        s.commit_remote().unwrap();
        assert_eq!(count(&s, "pending"), 0);
        assert!(!s.take_password_change_superseded().unwrap());

        // Older server params: the local change stays and still goes out.
        let mut s = fresh();
        stage(&mut s, RecordKind::AccountParams, &n.params_record);
        s.commit_remote().unwrap();
        assert_eq!(count(&s, "pending"), 2);
        assert!(!s.take_password_change_superseded().unwrap());
        assert_eq!(
            account_kinds(&s),
            vec![RecordKind::AccountParams, RecordKind::Keyset]
        );
    }

    fn seed_base(s: &mut SyncStore, kind: RecordKind, id: Id, version: u64, data: Vec<u8>) {
        s.stage_remote(remote(kind, id, version, Some(data)))
            .unwrap();
        s.commit_remote().unwrap();
    }

    fn count(s: &SyncStore, table: &str) -> i64 {
        s.conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn list_held_when_the_server_moved_on() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let a = Id::new();
        let kinds = |s: &SyncStore| -> Vec<RecordKind> {
            s.pending_changes()
                .unwrap()
                .iter()
                .map(|c| c.kind)
                .collect()
        };
        seed_base(&mut s, RecordKind::DeviceList, a, 1, b"l1".to_vec());
        // A local list built on the server's seq 1: it goes out.
        s.put_if_version(rec(a, RecordKind::DeviceList, 2, b"l2"), Some(1))
            .unwrap();
        assert_eq!(kinds(&s), vec![RecordKind::DeviceList]);
        assert_eq!(s.lists_needing_rebase().unwrap(), vec![]);
        assert_eq!(
            s.ancestor_record(RecordKind::DeviceList, a)
                .unwrap()
                .unwrap()
                .data,
            b"l1"
        );
        // The server moves on: held, kept for the rebase.
        seed_base(&mut s, RecordKind::DeviceList, a, 2, b"other".to_vec());
        assert_eq!(kinds(&s), vec![]);
        assert_eq!(
            s.lists_needing_rebase().unwrap(),
            vec![(RecordKind::DeviceList, a)]
        );
        assert_eq!(
            s.base_record(RecordKind::DeviceList, a)
                .unwrap()
                .unwrap()
                .data,
            b"other"
        );
        assert_eq!(
            s.get(RecordKind::DeviceList, a).unwrap().unwrap().data,
            b"l2"
        );
        // Dropped: the server list shows again, nothing held.
        s.drop_pending_record(RecordKind::DeviceList, a).unwrap();
        assert_eq!(s.lists_needing_rebase().unwrap(), vec![]);
        assert_eq!(s.ancestor_record(RecordKind::DeviceList, a).unwrap(), None);
        assert_eq!(
            s.get(RecordKind::DeviceList, a).unwrap().unwrap().data,
            b"other"
        );
        // Confirmed pushes clear the ancestor.
        s.put_if_version(rec(a, RecordKind::VaultList, 1, b"v1"), None)
            .unwrap();
        s.mark_pushed(RecordKind::VaultList, a, 1, Some(vec![1]))
            .unwrap();
        assert_eq!(s.ancestor_record(RecordKind::VaultList, a).unwrap(), None);
        assert_eq!(count(&s, "pending"), 0);
    }

    #[test]
    fn fetch_drops_a_lone_pending_keyset() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let a = Id::new();
        seed_base(&mut s, RecordKind::Keyset, a, 1, b"k1".to_vec());
        s.put(rec(a, RecordKind::Keyset, 2, b"k2")).unwrap();
        assert_eq!(count(&s, "pending"), 1);
        s.commit_remote().unwrap();
        assert_eq!(count(&s, "pending"), 0);
        assert_eq!(s.get(RecordKind::Keyset, a).unwrap().unwrap().data, b"k1");
        assert!(!s.take_password_change_superseded().unwrap());
    }

    #[test]
    fn exercise_shared_store_contract() {
        let mut s = SyncStore::open_in_memory().unwrap();
        crate::store::exercise(&mut s);
    }

    #[test]
    fn pending_shadows_base() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let id = Id::new();
        seed_base(&mut s, RecordKind::Keyset, id, 1, b"old".to_vec());
        assert_eq!(
            s.get(RecordKind::Keyset, id).unwrap(),
            Some(rec(id, RecordKind::Keyset, 1, b"old"))
        );
        s.put(rec(id, RecordKind::Keyset, 2, b"new")).unwrap();
        assert_eq!(
            s.get(RecordKind::Keyset, id).unwrap(),
            Some(rec(id, RecordKind::Keyset, 2, b"new"))
        );
        assert_eq!(
            s.list(RecordKind::Keyset).unwrap(),
            vec![rec(id, RecordKind::Keyset, 2, b"new")]
        );
        // put_if_version compares to the effective version.
        assert_eq!(
            s.put_if_version(rec(id, RecordKind::Keyset, 3, b"x"), Some(1)),
            Err(Error::Conflict)
        );
        s.put_if_version(rec(id, RecordKind::Keyset, 3, b"x"), Some(2))
            .unwrap();
    }

    #[test]
    fn delete_of_base_row_is_a_tombstone() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let id = Id::new();
        seed_base(&mut s, RecordKind::Keyset, id, 4, b"k".to_vec());
        s.delete(RecordKind::Keyset, id).unwrap();
        assert_eq!(s.get(RecordKind::Keyset, id).unwrap(), None);
        assert_eq!(s.list(RecordKind::Keyset).unwrap(), vec![]);
        assert_eq!(
            s.pending_changes().unwrap(),
            vec![Change {
                kind: RecordKind::Keyset,
                id,
                version: 4,
                data: None
            }]
        );
        // Rewriting after a delete brings it back.
        s.put_if_version(rec(id, RecordKind::Keyset, 5, b"n"), None)
            .unwrap();
        assert!(s.get(RecordKind::Keyset, id).unwrap().is_some());
    }

    #[test]
    fn delete_of_pending_only_row_vanishes() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let id = Id::new();
        s.put(rec(id, RecordKind::Keyset, 1, b"k")).unwrap();
        s.delete(RecordKind::Keyset, id).unwrap();
        assert_eq!(s.get(RecordKind::Keyset, id).unwrap(), None);
        assert_eq!(s.pending_changes().unwrap(), vec![]);
        assert_eq!(count(&s, "pending"), 0);
    }

    #[test]
    fn pending_changes_order_items_before_manifest() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let (i1, i2, gone) = (Id::new(), Id::new(), Id::new());
        seed_base(&mut s, RecordKind::Item, gone, 1, item_data(vault, b"old"));
        s.put(rec(vault, RecordKind::Manifest, 1, b"m")).unwrap();
        s.put(rec(i1, RecordKind::Item, 1, &item_data(vault, b"1")))
            .unwrap();
        s.put(rec(vault, RecordKind::VaultMeta, 1, b"vm")).unwrap();
        s.put(rec(vault, RecordKind::VaultKey, 1, b"vk")).unwrap();
        s.put(rec(i2, RecordKind::Item, 1, &item_data(vault, b"2")))
            .unwrap();
        // A real account pair: the params and keyset go out only together
        // and only with a decodable epoch.
        let n = crate::account::Account::create_with_params("pw", fast_kdf()).unwrap();
        let a = n.account.params.account_id;
        s.put(rec(a, RecordKind::AccountParams, 1, &n.params_record))
            .unwrap();
        s.put(rec(a, RecordKind::Keyset, 1, &n.keyset_record))
            .unwrap();
        s.delete(RecordKind::Item, gone).unwrap();
        let gone_key = Id::new();
        seed_base(&mut s, RecordKind::Keyset, gone_key, 1, b"k".to_vec());
        s.delete(RecordKind::Keyset, gone_key).unwrap();
        let kinds: Vec<(RecordKind, bool)> = s
            .pending_changes()
            .unwrap()
            .iter()
            .map(|c| (c.kind, c.data.is_some()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (RecordKind::AccountParams, true),
                (RecordKind::Keyset, true),
                (RecordKind::VaultKey, true),
                (RecordKind::VaultMeta, true),
                (RecordKind::Item, true),
                (RecordKind::Item, true),
                (RecordKind::Manifest, true),
                (RecordKind::Item, false),
                (RecordKind::Keyset, false),
            ]
        );
    }

    #[test]
    fn dropping_vault_writes_keeps_tombstones_and_logs_once() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let item = Id::new();
        seed_base(&mut s, RecordKind::Manifest, vault, 1, b"m1".to_vec());
        s.put(rec(vault, RecordKind::Manifest, 2, b"m2")).unwrap();
        s.put(rec(item, RecordKind::Item, 1, &item_data(vault, b"1")))
            .unwrap();
        s.put(rec(vault, RecordKind::VaultMeta, 2, b"vm")).unwrap();
        let tomb = Id::new();
        seed_base(&mut s, RecordKind::Item, tomb, 1, item_data(vault, b"t"));
        s.delete(RecordKind::Item, tomb).unwrap();
        // Another vault's write stays.
        let other = Id::new();
        s.put(rec(other, RecordKind::Manifest, 1, b"o")).unwrap();

        // The writes go, the tombstone stays, logged once.
        assert!(s.drop_pending_vault_writes(vault).unwrap());
        assert!(!s.drop_pending_vault_writes(vault).unwrap());
        assert_eq!(count(&s, "pending"), 2);
        assert_eq!(count(&s, "ancestor"), 0);
        let log = s.dropped_vault_writes().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].vault_id, vault);
        s.clear_dropped_vault_writes().unwrap();
        assert!(s.dropped_vault_writes().unwrap().is_empty());
    }

    #[test]
    fn no_vault_deletion_proven_without_a_pin() {
        let s = SyncStore::open_in_memory().unwrap();
        assert!(deleted_vaults(&s.conn, &[]).is_empty());
    }

    #[test]
    fn mark_pushed_moves_row_to_base_with_meta() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let id = Id::new();
        s.put(rec(id, RecordKind::Keyset, 2, b"k")).unwrap();
        s.mark_pushed(RecordKind::Keyset, id, 2, Some(vec![7, 7]))
            .unwrap();
        assert_eq!(s.pending_changes().unwrap(), vec![]);
        assert_eq!(count(&s, "pending"), 0);
        assert_eq!(
            s.get(RecordKind::Keyset, id).unwrap(),
            Some(rec(id, RecordKind::Keyset, 2, b"k"))
        );
        assert_eq!(
            s.server_meta(RecordKind::Keyset, id).unwrap(),
            Some(vec![7, 7])
        );
        assert_eq!(s.server_meta(RecordKind::Item, id).unwrap(), None);
        // A pushed deletion removes the base row too.
        s.delete(RecordKind::Keyset, id).unwrap();
        s.mark_pushed(RecordKind::Keyset, id, 2, None).unwrap();
        assert_eq!(count(&s, "pending"), 0);
        assert_eq!(count(&s, "base"), 0);
        assert_eq!(s.get(RecordKind::Keyset, id).unwrap(), None);
    }

    #[test]
    fn zone_reset_requeues_only_rows_the_server_does_not_return() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (a, b, c, m, gone) = (Id::new(), Id::new(), Id::new(), Id::new(), Id::new());
        seed_base(&mut s, RecordKind::VaultMeta, a, 1, b"a-old".to_vec());
        seed_base(&mut s, RecordKind::Manifest, m, 4, b"m".to_vec());
        seed_base(&mut s, RecordKind::VaultMeta, b, 2, b"b".to_vec());
        seed_base(&mut s, RecordKind::VaultMeta, c, 2, b"c".to_vec());
        seed_base(&mut s, RecordKind::VaultMeta, gone, 1, b"gone".to_vec());
        s.mark_pushed(RecordKind::VaultMeta, a, 9, Some(vec![1]))
            .unwrap();
        s.set_meta("tok", &[7]).unwrap();
        s.stage_remote(remote(
            RecordKind::VaultMeta,
            c,
            1,
            Some(b"stale page".to_vec()),
        ))
        .unwrap();
        s.put(rec(b, RecordKind::VaultMeta, 3, b"b-newer")).unwrap();
        s.delete(RecordKind::VaultMeta, gone).unwrap();

        // Begin: tags, staging and token are gone, nothing is pending yet.
        let pending_before = s.pending_changes().unwrap().len();
        s.begin_zone_reset("tok").unwrap();
        assert!(s.full_fetch_pending().unwrap());
        assert_eq!(s.meta("tok").unwrap(), None);
        assert_eq!(count(&s, "staging"), 0);
        assert_eq!(s.pending_changes().unwrap().len(), pending_before);
        assert_eq!(s.server_meta(RecordKind::VaultMeta, c).unwrap(), None);

        // The new zone returns a newer `a` and the manifest.
        s.stage_remote(RemoteChange {
            kind: RecordKind::VaultMeta,
            id: a,
            version: 12,
            data: Some(b"a-newer".to_vec()),
            server_meta: Some(vec![9]),
        })
        .unwrap();
        s.stage_remote(RemoteChange {
            kind: RecordKind::Manifest,
            id: m,
            version: 5,
            data: Some(b"m-newer".to_vec()),
            server_meta: Some(vec![8]),
        })
        .unwrap();
        s.commit_remote().unwrap();

        // Only `c` (absent from the server, no pending row) is requeued.
        assert!(!s.finish_full_fetch().unwrap());
        assert!(!s.full_fetch_pending().unwrap());
        let pending = s.pending_changes().unwrap();
        let find = |id: Id| pending.iter().find(|p| p.id == id);
        assert_eq!(find(c).unwrap().data, Some(b"c".to_vec()));
        assert!(find(a).is_none() && find(m).is_none());
        // The local edit and the tombstone are kept as they were.
        assert_eq!(find(b).unwrap().data, Some(b"b-newer".to_vec()));
        assert_eq!(find(gone).unwrap().data, None);
        assert_eq!(pending.len(), 3);
        assert_eq!(
            s.get(RecordKind::VaultMeta, a).unwrap(),
            Some(rec(a, RecordKind::VaultMeta, 12, b"a-newer"))
        );
        // No begun fetch, no change.
        assert!(!s.finish_full_fetch().unwrap());
        assert_eq!(s.pending_changes().unwrap().len(), 3);
    }

    #[test]
    fn reset_drops_stale_items_of_a_vault_the_server_returned() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (vault, other_vault) = (Id::new(), Id::new());
        let (stale, kept, orphan, local) = (Id::new(), Id::new(), Id::new(), Id::new());
        seed_base(&mut s, RecordKind::Manifest, vault, 3, b"m".to_vec());
        seed_base(&mut s, RecordKind::Item, stale, 2, item_data(vault, b"x"));
        seed_base(&mut s, RecordKind::Item, kept, 2, item_data(vault, b"k"));
        seed_base(
            &mut s,
            RecordKind::Item,
            orphan,
            2,
            item_data(other_vault, b"o"),
        );
        seed_base(&mut s, RecordKind::Item, local, 2, item_data(vault, b"l"));
        s.put(rec(local, RecordKind::Item, 3, &item_data(vault, b"l3")))
            .unwrap();

        s.begin_zone_reset("tok").unwrap();
        // The server returns the vault manifest and one item, not the others.
        for (kind, id, data, tag) in [
            (RecordKind::Manifest, vault, b"m2".to_vec(), 1u8),
            (RecordKind::Item, kept, item_data(vault, b"k"), 2),
        ] {
            s.stage_remote(RemoteChange {
                kind,
                id,
                version: 4,
                data: Some(data),
                server_meta: Some(vec![tag]),
            })
            .unwrap();
        }
        s.commit_remote().unwrap();
        assert!(s.finish_full_fetch().unwrap());

        // The stale blob is gone (not requeued), the orphan (vault unknown to the server) is requeued.
        assert_eq!(s.get(RecordKind::Item, stale).unwrap(), None);
        let pending = s.pending_changes().unwrap();
        assert!(pending.iter().all(|p| p.id != stale && p.id != kept));
        assert!(pending.iter().any(|p| p.id == orphan));
        assert!(pending.iter().any(|p| p.id == local && p.version == 3));
        assert_eq!(count(&s, "base"), 4);
    }

    #[test]
    fn plain_full_fetch_deletes_only_items_of_returned_vaults() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (kept, absent, edited, m) = (Id::new(), Id::new(), Id::new(), Id::new());
        let (served, hidden) = (Id::new(), Id::new());
        let (gone_item, hidden_item) = (Id::new(), Id::new());
        seed_base(&mut s, RecordKind::VaultMeta, kept, 1, b"k".to_vec());
        seed_base(&mut s, RecordKind::VaultMeta, absent, 1, b"g".to_vec());
        seed_base(&mut s, RecordKind::VaultMeta, edited, 1, b"e".to_vec());
        seed_base(&mut s, RecordKind::Manifest, m, 2, b"m".to_vec());
        seed_base(&mut s, RecordKind::Manifest, served, 1, b"s".to_vec());
        seed_base(&mut s, RecordKind::Manifest, hidden, 1, b"h".to_vec());
        seed_base(
            &mut s,
            RecordKind::Item,
            gone_item,
            1,
            item_data(served, b"a"),
        );
        seed_base(
            &mut s,
            RecordKind::Item,
            hidden_item,
            1,
            item_data(hidden, b"b"),
        );
        s.put(rec(edited, RecordKind::VaultMeta, 2, b"e2")).unwrap();
        s.set_meta("tok", &[1]).unwrap();

        s.begin_full_fetch().unwrap();
        // The token is the caller's business in this mode.
        assert_eq!(s.meta("tok").unwrap(), Some(vec![1]));
        assert!(s.full_fetch_pending().unwrap());
        s.stage_remote(RemoteChange {
            kind: RecordKind::VaultMeta,
            id: kept,
            version: 1,
            data: Some(b"k".to_vec()),
            server_meta: Some(vec![3]),
        })
        .unwrap();
        s.stage_remote(remote(RecordKind::Manifest, served, 1, Some(b"s".to_vec())))
            .unwrap();
        s.commit_remote().unwrap();
        assert!(s.finish_full_fetch().unwrap());

        assert_eq!(
            s.server_meta(RecordKind::VaultMeta, kept).unwrap(),
            Some(vec![3])
        );
        // The item the server no longer lists in a vault it served is gone.
        assert_eq!(s.get(RecordKind::Item, gone_item).unwrap(), None);
        // Everything else the server did not return stays: stable kinds,
        // manifests, and the items of a vault it did not serve.
        assert!(s.get(RecordKind::VaultMeta, absent).unwrap().is_some());
        assert!(s.get(RecordKind::Manifest, m).unwrap().is_some());
        assert!(s.get(RecordKind::Manifest, hidden).unwrap().is_some());
        assert!(s.get(RecordKind::Item, hidden_item).unwrap().is_some());
        // A local edit stays (pending), nothing was requeued.
        let pending = s.pending_changes().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, edited);
        assert!(!s.full_fetch_pending().unwrap());
    }

    #[test]
    fn plain_full_fetch_of_an_empty_zone_keeps_every_row() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (acct, vault, item) = (Id::new(), Id::new(), Id::new());
        seed_base(&mut s, RecordKind::AccountParams, acct, 1, b"p".to_vec());
        seed_base(&mut s, RecordKind::Keyset, acct, 1, b"k".to_vec());
        seed_base(&mut s, RecordKind::VaultKey, vault, 1, b"vk".to_vec());
        seed_base(&mut s, RecordKind::VaultMeta, vault, 1, b"vm".to_vec());
        seed_base(&mut s, RecordKind::Manifest, vault, 1, b"m".to_vec());
        seed_base(&mut s, RecordKind::Item, item, 1, item_data(vault, b"i"));
        s.begin_full_fetch().unwrap();
        s.commit_remote().unwrap();
        assert!(!s.finish_full_fetch().unwrap());
        assert_eq!(count(&s, "base"), 6);
        assert_eq!(count(&s, "pending"), 0);
        assert!(s.has_account().unwrap());
    }

    #[test]
    fn commit_remote_ignores_deletion_of_account_records_and_seen_vaults() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (acct, seen, unseen, item) = (Id::new(), Id::new(), Id::new(), Id::new());
        for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
            seed_base(&mut s, kind, acct, 1, b"a".to_vec());
        }
        for v in [seen, unseen] {
            for kind in [
                RecordKind::VaultKey,
                RecordKind::VaultMeta,
                RecordKind::Manifest,
            ] {
                seed_base(&mut s, kind, v, 1, b"v".to_vec());
            }
        }
        seed_base(&mut s, RecordKind::Item, item, 1, item_data(seen, b"i"));
        let mut state = DeviceState::default();
        state.last_seen.insert(
            seen,
            crate::manifest::SeenManifest {
                seq: 1,
                hash: [7; 32],
            },
        );
        s.set_device_state(&state).unwrap();

        for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
            s.stage_remote(remote(kind, acct, 1, None)).unwrap();
        }
        for v in [seen, unseen] {
            for kind in [
                RecordKind::VaultKey,
                RecordKind::VaultMeta,
                RecordKind::Manifest,
            ] {
                s.stage_remote(remote(kind, v, 1, None)).unwrap();
            }
        }
        s.stage_remote(remote(RecordKind::Item, item, 1, None))
            .unwrap();
        // The ignored manifest deletion is not reported as an applied vault.
        assert_eq!(s.commit_remote().unwrap(), vec![unseen]);

        assert!(s.has_account().unwrap());
        assert!(s.get(RecordKind::Keyset, acct).unwrap().is_some());
        for kind in [
            RecordKind::VaultKey,
            RecordKind::VaultMeta,
            RecordKind::Manifest,
        ] {
            assert!(s.get(kind, seen).unwrap().is_some());
            assert_eq!(s.get(kind, unseen).unwrap(), None);
        }
        // Item deletions are ordinary remote changes.
        assert_eq!(s.get(RecordKind::Item, item).unwrap(), None);
        assert_eq!(count(&s, "staging"), 0);

        // Every refused deletion is logged (kind, id, time), nothing else.
        let log = s.ignored_deletions().unwrap();
        let logged: Vec<(RecordKind, Id)> = log.iter().map(|e| (e.kind, e.id)).collect();
        assert_eq!(
            logged,
            vec![
                (RecordKind::AccountParams, acct),
                (RecordKind::Keyset, acct),
                (RecordKind::VaultKey, seen),
                (RecordKind::VaultMeta, seen),
                (RecordKind::Manifest, seen),
            ]
        );
        assert!(log.iter().all(|e| e.at > 1_700_000_000));
        s.clear_ignored_deletions().unwrap();
        assert_eq!(s.ignored_deletions().unwrap(), vec![]);
    }

    #[test]
    fn ignored_deletion_log_keeps_the_newest_hundred() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let ids: Vec<Id> = (0..130).map(|_| Id::new()).collect();
        for id in &ids {
            seed_base(&mut s, RecordKind::Keyset, *id, 1, b"k".to_vec());
        }
        for chunk in ids.chunks(40) {
            for id in chunk {
                s.stage_remote(remote(RecordKind::Keyset, *id, 1, None))
                    .unwrap();
            }
            s.commit_remote().unwrap();
        }
        let log = s.ignored_deletions().unwrap();
        assert_eq!(log.len(), MAX_IGNORED_DELETIONS);
        // Oldest dropped: the first 30 ids are gone, order is kept.
        let mut expected = ids[30..].to_vec();
        expected.sort();
        let mut kept: Vec<Id> = log.iter().map(|e| e.id).collect();
        kept.sort();
        assert_eq!(kept, expected);
        assert!(s.has_account().is_ok());
    }

    #[test]
    fn plain_full_fetch_logs_rows_the_server_stopped_serving() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (acct, seen, unseen, item) = (Id::new(), Id::new(), Id::new(), Id::new());
        seed_base(&mut s, RecordKind::AccountParams, acct, 1, b"p".to_vec());
        seed_base(&mut s, RecordKind::Keyset, acct, 1, b"k".to_vec());
        seed_base(&mut s, RecordKind::Manifest, seen, 1, b"m".to_vec());
        seed_base(&mut s, RecordKind::Manifest, unseen, 1, b"u".to_vec());
        seed_base(&mut s, RecordKind::Item, item, 1, item_data(seen, b"i"));
        let mut state = DeviceState::default();
        state.last_seen.insert(
            seen,
            crate::manifest::SeenManifest {
                seq: 1,
                hash: [7; 32],
            },
        );
        s.set_device_state(&state).unwrap();
        // The server serves the keyset only.
        s.begin_full_fetch().unwrap();
        s.stage_remote(remote(RecordKind::Keyset, acct, 1, Some(b"k".to_vec())))
            .unwrap();
        s.commit_remote().unwrap();
        s.finish_full_fetch().unwrap();
        let logged: Vec<(RecordKind, Id)> = s
            .ignored_deletions()
            .unwrap()
            .iter()
            .map(|e| (e.kind, e.id))
            .collect();
        assert_eq!(
            logged,
            vec![
                (RecordKind::AccountParams, acct),
                (RecordKind::Manifest, seen)
            ]
        );
        // A reset requeues instead: nothing more is logged.
        s.begin_zone_reset("tok").unwrap();
        s.commit_remote().unwrap();
        s.finish_full_fetch().unwrap();
        assert_eq!(s.ignored_deletions().unwrap().len(), 2);
    }

    #[test]
    fn ignored_deletion_log_keeps_one_entry_per_record_with_the_latest_time() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (a, b) = (Id::new(), Id::new());
        seed_base(&mut s, RecordKind::Keyset, a, 1, b"a".to_vec());
        seed_base(&mut s, RecordKind::Keyset, b, 1, b"b".to_vec());
        for id in [a, b] {
            s.stage_remote(remote(RecordKind::Keyset, id, 1, None))
                .unwrap();
        }
        s.commit_remote().unwrap();
        // Backdate the log, then `a` is refused again: one entry, moved last, new time.
        let mut old = s.ignored_deletions().unwrap();
        for e in &mut old {
            e.at = 1_000;
        }
        s.set_meta(IGNORED_DELETIONS_KEY, &encode_ignored(&old))
            .unwrap();
        s.stage_remote(remote(RecordKind::Keyset, a, 1, None))
            .unwrap();
        s.commit_remote().unwrap();
        let log = s.ignored_deletions().unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!((log[0].id, log[0].at), (b, 1_000));
        assert_eq!(log[1].id, a);
        assert!(log[1].at > 1_000);
        // The same record under another kind is another entry.
        seed_base(&mut s, RecordKind::AccountParams, a, 1, b"p".to_vec());
        s.stage_remote(remote(RecordKind::AccountParams, a, 1, None))
            .unwrap();
        s.commit_remote().unwrap();
        assert_eq!(s.ignored_deletions().unwrap().len(), 3);
    }

    #[test]
    fn unreadable_ignored_log_starts_again() {
        let mut s = SyncStore::open_in_memory().unwrap();
        s.set_meta(IGNORED_DELETIONS_KEY, &[9, 9, 9]).unwrap();
        assert!(s.ignored_deletions().is_err());
        let id = Id::new();
        seed_base(&mut s, RecordKind::Keyset, id, 1, b"k".to_vec());
        s.stage_remote(remote(RecordKind::Keyset, id, 1, None))
            .unwrap();
        s.commit_remote().unwrap();
        assert_eq!(s.ignored_deletions().unwrap().len(), 1);
    }

    #[test]
    fn reset_for_recovery_clears_the_pin_and_refuses_a_visible_account() {
        let s = SyncStore::open_in_memory().unwrap();
        let kdf = crate::crypto::KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: crate::crypto::random_array().unwrap(),
        };
        let (mut repo, _sk) =
            crate::repo::Repository::create_account(s, "Projet Atlas", kdf).unwrap();
        repo.persist_device_state().unwrap();
        let mut s = repo.store;
        assert_eq!(
            s.reset_for_recovery(),
            Err(Error::InvalidFormat("store holds an account"))
        );
        assert_eq!(s.account_state().unwrap(), AccountState::Present);
        let id = s.list(RecordKind::AccountParams).unwrap()[0].id;
        s.delete(RecordKind::AccountParams, id).unwrap();
        assert_eq!(s.account_state().unwrap(), AccountState::PinnedButMissing);
        s.reset_for_recovery().unwrap();
        assert_eq!(s.account_state().unwrap(), AccountState::Empty);
        assert_eq!(s.device_state().unwrap(), DeviceState::default());
        for table in ["base", "pending", "staging", "ancestor", "kept", "meta"] {
            assert_eq!(count(&s, table), 0, "{table}");
        }
    }

    #[test]
    fn account_state_reports_a_pinned_account_that_disappeared() {
        let mut s = SyncStore::open_in_memory().unwrap();
        assert_eq!(s.account_state().unwrap(), AccountState::Empty);
        let kdf = crate::crypto::KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: crate::crypto::random_array().unwrap(),
        };
        let (mut repo, _sk) =
            crate::repo::Repository::create_account(s, "Projet Atlas", kdf).unwrap();
        repo.persist_device_state().unwrap();
        s = repo.store;
        assert_eq!(s.account_state().unwrap(), AccountState::Present);
        s.conn
            .execute(
                "DELETE FROM pending WHERE kind = ?1",
                params![RecordKind::AccountParams.code()],
            )
            .unwrap();
        assert!(!s.has_account().unwrap());
        assert_eq!(s.account_state().unwrap(), AccountState::PinnedButMissing);
    }

    #[test]
    fn reset_empties_every_table_and_keeps_the_connection_usable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sqlite");
        let mut s = SyncStore::open(&path).unwrap();
        let mut other = SyncStore::open(&path).unwrap();
        let (vault, m) = (Id::new(), Id::new());
        seed_base(&mut s, RecordKind::Manifest, m, 1, b"m".to_vec());
        s.put(rec(m, RecordKind::Manifest, 2, b"m2")).unwrap();
        s.put(rec(vault, RecordKind::Keyset, 1, b"k")).unwrap();
        s.stage_remote(remote(RecordKind::Keyset, vault, 3, None))
            .unwrap();
        s.set_meta("sync.tok", &[1]).unwrap();
        s.set_device_state(&DeviceState::default()).unwrap();
        other.reset().unwrap();
        for table in ["base", "pending", "staging", "ancestor", "kept", "meta"] {
            assert_eq!(count(&s, table), 0, "{table}");
        }
        // Both connections keep working on the same file.
        s.put(rec(vault, RecordKind::Keyset, 1, b"k")).unwrap();
        assert_eq!(other.list(RecordKind::Keyset).unwrap().len(), 1);
    }

    #[test]
    fn begun_fetch_survives_reopen_and_a_reset_is_not_downgraded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sqlite");
        let m = Id::new();
        {
            let mut s = SyncStore::open(&path).unwrap();
            seed_base(&mut s, RecordKind::Manifest, m, 4, b"m".to_vec());
            s.begin_zone_reset("tok").unwrap();
            s.begin_full_fetch().unwrap();
        }
        // A restart in the middle of the fetch: the mode is still "reset".
        let mut s = SyncStore::open(&path).unwrap();
        assert!(s.full_fetch_pending().unwrap());
        assert!(!s.finish_full_fetch().unwrap());
        let pending = s.pending_changes().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].data, Some(b"m".to_vec()));
    }

    #[test]
    fn mark_pushed_ignores_other_version() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let id = Id::new();
        s.put(rec(id, RecordKind::VaultMeta, 3, b"k")).unwrap();
        s.mark_pushed(RecordKind::VaultMeta, id, 2, Some(vec![1]))
            .unwrap();
        assert_eq!(count(&s, "base"), 0);
        assert_eq!(s.pending_changes().unwrap().len(), 1);
    }

    #[test]
    fn commit_remote_is_atomic_and_reports_vaults() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let item = Id::new();
        s.stage_remote(remote(
            RecordKind::Item,
            item,
            1,
            Some(item_data(vault, b"i")),
        ))
        .unwrap();
        s.stage_remote(remote(RecordKind::Manifest, vault, 1, Some(b"m".to_vec())))
            .unwrap();
        assert_eq!(s.get(RecordKind::Manifest, vault).unwrap(), None);
        assert_eq!(s.get(RecordKind::Item, item).unwrap(), None);
        assert_eq!(s.list(RecordKind::Item).unwrap(), vec![]);
        assert_eq!(s.commit_remote().unwrap(), vec![vault]);
        assert!(s.get(RecordKind::Manifest, vault).unwrap().is_some());
        assert!(s.get(RecordKind::Item, item).unwrap().is_some());
        assert_eq!(count(&s, "staging"), 0);
        assert_eq!(
            s.server_meta(RecordKind::Manifest, vault).unwrap(),
            Some(vec![9, 1])
        );
        // Remote deletion.
        s.stage_remote(remote(RecordKind::Item, item, 2, None))
            .unwrap();
        assert_eq!(s.commit_remote().unwrap(), vec![]);
        assert_eq!(s.get(RecordKind::Item, item).unwrap(), None);
    }

    #[test]
    fn commit_remote_keeps_pending() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let id = Id::new();
        seed_base(&mut s, RecordKind::VaultMeta, id, 1, b"base".to_vec());
        s.put(rec(id, RecordKind::VaultMeta, 2, b"local")).unwrap();
        s.stage_remote(remote(
            RecordKind::VaultMeta,
            id,
            3,
            Some(b"remote".to_vec()),
        ))
        .unwrap();
        s.commit_remote().unwrap();
        assert_eq!(
            s.get(RecordKind::VaultMeta, id).unwrap(),
            Some(rec(id, RecordKind::VaultMeta, 2, b"local"))
        );
        assert_eq!(s.pending_changes().unwrap().len(), 1);
        let base_version: i64 = s
            .conn
            .query_row("SELECT version FROM base", [], |r| r.get(0))
            .unwrap();
        assert_eq!(base_version, 3);
    }

    #[test]
    fn ancestor_kept_when_remote_overwrites_base_manifest() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        seed_base(&mut s, RecordKind::Manifest, vault, 1, b"m1".to_vec());
        assert_eq!(s.ancestor_manifest(vault).unwrap(), None);
        s.put(rec(vault, RecordKind::Manifest, 2, b"local"))
            .unwrap();
        s.put(rec(vault, RecordKind::Manifest, 3, b"local2"))
            .unwrap();
        let anc = rec(vault, RecordKind::Manifest, 1, b"m1");
        assert_eq!(s.ancestor_manifest(vault).unwrap(), Some(anc.clone()));
        seed_base(&mut s, RecordKind::Manifest, vault, 2, b"remote".to_vec());
        assert_eq!(s.ancestor_manifest(vault).unwrap(), Some(anc));
        // Pushing the manifest clears it.
        s.mark_pushed(RecordKind::Manifest, vault, 3, None).unwrap();
        assert_eq!(s.ancestor_manifest(vault).unwrap(), None);
    }

    #[test]
    fn held_vault_sends_nothing() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (held, free) = (Id::new(), Id::new());
        let (h_item, h_old, f_item) = (Id::new(), Id::new(), Id::new());
        seed_base(&mut s, RecordKind::Manifest, held, 2, b"m2".to_vec());
        seed_base(&mut s, RecordKind::Manifest, free, 1, b"f1".to_vec());
        seed_base(&mut s, RecordKind::Item, h_old, 1, item_data(held, b"old"));
        s.put(rec(held, RecordKind::Manifest, 3, b"local")).unwrap();
        s.put(rec(h_item, RecordKind::Item, 1, &item_data(held, b"n")))
            .unwrap();
        s.delete(RecordKind::Item, h_old).unwrap();
        s.put(rec(free, RecordKind::Manifest, 2, b"f2")).unwrap();
        s.put(rec(f_item, RecordKind::Item, 1, &item_data(free, b"n")))
            .unwrap();
        // Not held yet: base (2) is older than pending (3).
        assert_eq!(s.pending_changes().unwrap().len(), 5);
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![]);
        // The server catches up.
        seed_base(&mut s, RecordKind::Manifest, held, 3, b"remote".to_vec());
        let sent = s.pending_changes().unwrap();
        let ids: Vec<Id> = sent.iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![f_item, free]);
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![held]);
        // Dropping the vault's pending rows releases nothing local to send.
        s.drop_pending_vault(held).unwrap();
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![]);
        assert_eq!(s.pending_changes().unwrap().len(), 2);
        assert_eq!(s.ancestor_manifest(held).unwrap(), None);
        assert_eq!(
            s.get(RecordKind::Manifest, held).unwrap(),
            Some(rec(held, RecordKind::Manifest, 3, b"remote"))
        );
        assert!(s.get(RecordKind::Item, h_old).unwrap().is_some());
        assert_eq!(s.get(RecordKind::Item, h_item).unwrap(), None);
    }

    #[test]
    fn oversized_record_refused() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let id = Id::new();
        let big = vec![0u8; MAX_RECORD_BYTES + 1];
        assert_eq!(
            s.put(rec(id, RecordKind::Keyset, 1, &big)),
            Err(Error::InvalidFormat("record too large"))
        );
        assert_eq!(
            s.put_if_version(rec(id, RecordKind::Keyset, 1, &big), None),
            Err(Error::InvalidFormat("record too large"))
        );
        let ok = vec![0u8; MAX_RECORD_BYTES];
        s.put(rec(id, RecordKind::Keyset, 1, &ok)).unwrap();
    }

    #[test]
    fn store_user_version_newer_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.sqlite");
        // A database from before the version check (user_version 0) opens,
        // keeps its rows and is stamped with the current version.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value BLOB NOT NULL);
                 INSERT INTO meta VALUES ('change_token', x'746f6b');",
            )
            .unwrap();
        }
        {
            let s = SyncStore::open(&path).unwrap();
            assert_eq!(s.meta("change_token").unwrap(), Some(b"tok".to_vec()));
            let v: i64 = s
                .conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, crate::format::STORE_USER_VERSION);
        }
        // The current version opens again.
        drop(SyncStore::open(&path).unwrap());
        // A newer one is refused, and left as it is.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA user_version = 2;").unwrap();
        }
        assert!(matches!(
            SyncStore::open(&path),
            Err(Error::InvalidFormat("store from a newer version"))
        ));
        let conn = Connection::open(&path).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 2);
    }

    #[test]
    fn device_state_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.sqlite");
        let mut state = DeviceState::default();
        state.last_seen.clear();
        {
            let mut s = SyncStore::open(&path).unwrap();
            assert_eq!(s.device_state().unwrap(), DeviceState::default());
            assert!(!s.has_account().unwrap());
            s.set_device_state(&state).unwrap();
            s.set_meta("change_token", b"tok").unwrap();
            s.put(rec(Id::new(), RecordKind::AccountParams, 1, b"ap"))
                .unwrap();
        }
        let s = SyncStore::open(&path).unwrap();
        assert_eq!(s.device_state().unwrap(), state);
        assert_eq!(s.meta("change_token").unwrap(), Some(b"tok".to_vec()));
        assert_eq!(s.meta("absent").unwrap(), None);
        assert!(s.has_account().unwrap());
        let v: i64 = s
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn two_connections_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.sqlite");
        let mut a = SyncStore::open(&path).unwrap();
        let mut b = SyncStore::open(&path).unwrap();
        let id = Id::new();
        a.put(rec(id, RecordKind::Keyset, 1, b"k")).unwrap();
        assert!(b.get(RecordKind::Keyset, id).unwrap().is_some());
        b.mark_pushed(RecordKind::Keyset, id, 1, Some(vec![1]))
            .unwrap();
        assert_eq!(a.pending_changes().unwrap(), vec![]);
        b.set_meta("k", b"v").unwrap();
        assert_eq!(a.meta("k").unwrap(), Some(b"v".to_vec()));
        b.stage_remote(remote(RecordKind::Keyset, id, 2, Some(b"r".to_vec())))
            .unwrap();
        a.commit_remote().unwrap();
        assert_eq!(
            b.get(RecordKind::Keyset, id).unwrap(),
            Some(rec(id, RecordKind::Keyset, 2, b"r"))
        );
    }

    #[test]
    fn held_when_remote_advances_behind_local_lead() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let item = Id::new();
        seed_base(&mut s, RecordKind::Manifest, vault, 1, b"m1".to_vec());
        s.put(rec(vault, RecordKind::Manifest, 2, b"l2")).unwrap();
        s.put(rec(vault, RecordKind::Manifest, 3, b"l3")).unwrap();
        s.put(rec(item, RecordKind::Item, 1, &item_data(vault, b"i")))
            .unwrap();
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![]);
        assert_eq!(s.pending_changes().unwrap().len(), 2);
        // Remote v2 lands: 3 > 2, but the local v3 was built on v1.
        seed_base(&mut s, RecordKind::Manifest, vault, 2, b"r2".to_vec());
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![vault]);
        assert_eq!(s.pending_changes().unwrap(), vec![]);
    }

    #[test]
    fn held_vault_keeps_item_tombstones_after_remote_delete() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let item = Id::new();
        seed_base(&mut s, RecordKind::Manifest, vault, 1, b"m1".to_vec());
        seed_base(&mut s, RecordKind::Item, item, 1, item_data(vault, b"i"));
        s.put(rec(vault, RecordKind::Manifest, 2, b"l2")).unwrap();
        s.delete(RecordKind::Item, item).unwrap();
        assert_eq!(s.pending_changes().unwrap().len(), 2);
        // The server deletes the item and advances the manifest.
        s.stage_remote(remote(RecordKind::Item, item, 2, None))
            .unwrap();
        s.stage_remote(remote(RecordKind::Manifest, vault, 2, Some(b"r2".to_vec())))
            .unwrap();
        s.commit_remote().unwrap();
        assert_eq!(count(&s, "base"), 1);
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![vault]);
        assert_eq!(s.pending_changes().unwrap(), vec![]);
        s.drop_pending_vault(vault).unwrap();
        assert_eq!(count(&s, "pending"), 0);
    }

    #[test]
    fn server_going_back_leaves_the_vault_unheld_and_its_rows_kept() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (vault, item, other) = (Id::new(), Id::new(), Id::new());
        seed_base(&mut s, RecordKind::Manifest, vault, 3, b"m3".to_vec());
        seed_base(&mut s, RecordKind::Item, item, 1, item_data(vault, b"i"));
        seed_base(
            &mut s,
            RecordKind::Item,
            other,
            1,
            item_data(Id::new(), b"o"),
        );
        s.put(rec(vault, RecordKind::Manifest, 4, b"l4")).unwrap();
        // The server goes back to seq 2 and drops the item: older than the
        // ancestor, so not held; both rows it replaced are kept.
        s.stage_remote(remote(RecordKind::Manifest, vault, 2, Some(b"m2".to_vec())))
            .unwrap();
        s.stage_remote(remote(RecordKind::Item, item, 1, None))
            .unwrap();
        s.commit_remote().unwrap();
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![]);
        let mut kept = s.kept_rows(vault).unwrap().unwrap();
        kept.sort_by_key(|r| r.kind);
        assert_eq!(
            kept,
            vec![
                rec(item, RecordKind::Item, 1, &item_data(vault, b"i")),
                rec(vault, RecordKind::Manifest, 3, b"m3"),
            ]
        );
        // The same seq with other content is a fork: held.
        seed_base(&mut s, RecordKind::Manifest, vault, 3, b"fork".to_vec());
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![vault]);
        // A clean load drops the kept rows.
        s.vault_event(vault, VaultEvent::Clean).unwrap();
        assert_eq!(s.kept_rows(vault).unwrap(), Some(vec![]));
    }

    #[test]
    fn health_counts_rounds_and_settles_only_on_a_fetch() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let cause = IntegrityError::ManifestRollback;
        seed_base(&mut s, RecordKind::Manifest, vault, 2, b"m2".to_vec());
        s.vault_event(vault, VaultEvent::Behind { seq: 3, cause })
            .unwrap();
        for i in 1..=STALE_ALERT_ROUNDS {
            s.count_round(100 * i64::from(i)).unwrap();
        }
        let e = s.health().unwrap()[&vault];
        assert_eq!((e.since, e.rounds, e.alert), (Some(100), 5, false));
        // The copy pushed back: not settled until a fetch serves it.
        s.put(rec(vault, RecordKind::Manifest, 3, b"m3")).unwrap();
        s.mark_pushed(RecordKind::Manifest, vault, 3, None).unwrap();
        s.vault_event(vault, VaultEvent::Clean).unwrap();
        assert!(s.health().unwrap()[&vault].awaiting);
        // Served older again: still behind; time passes: an alert.
        seed_base(&mut s, RecordKind::Manifest, vault, 2, b"m2".to_vec());
        s.count_round(100 + STALE_ALERT_SECONDS).unwrap();
        let e = s.health().unwrap()[&vault];
        assert!(e.alert && e.awaiting);
        // Persisted as is.
        assert_eq!(
            decode_health(&encode_health(&s.health().unwrap())),
            Ok(s.health().unwrap())
        );
        // Served back, loaded cleanly: settled after `STALE_CLEAR_ROUNDS`
        // clean rounds in a row, not one.
        seed_base(&mut s, RecordKind::Manifest, vault, 3, b"m3".to_vec());
        for i in 1..STALE_CLEAR_ROUNDS {
            s.vault_event(vault, VaultEvent::Clean).unwrap();
            s.count_round(1000).unwrap();
            let e = s.health().unwrap()[&vault];
            assert_eq!(u32::from(e.clean_rounds), i);
        }
        s.vault_event(vault, VaultEvent::Clean).unwrap();
        s.count_round(1000).unwrap();
        assert!(s.health().unwrap().is_empty());
        // An unreadable map is an error, never an empty map that would hide
        // every alert.
        s.set_meta(HEALTH_KEY, &[HEALTH_VERSION, 1, 2]).unwrap();
        assert!(matches!(s.health(), Err(Error::Store(_))));
        s.set_meta(HEALTH_KEY, &[HEALTH_VERSION + 1]).unwrap();
        assert!(matches!(s.health(), Err(Error::Store(_))));
        assert!(matches!(s.count_round(2000), Err(Error::Store(_))));
    }

    #[test]
    fn periodic_rollback_still_alerts() {
        // The server rolls the vault back every `STALE_CLEAR_ROUNDS + 1`-th
        // round and serves it cleanly in between: just enough clean rounds
        // to clear the entry each time. The count resumes across the clears.
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let cause = IntegrityError::ManifestRollback;
        let period = STALE_CLEAR_ROUNDS + 1;
        let mut alerts = 0;
        for round in 0..60u32 {
            if round % period == 0 {
                s.vault_event(vault, VaultEvent::Behind { seq: 3, cause })
                    .unwrap();
            } else {
                s.vault_event(vault, VaultEvent::Clean).unwrap();
            }
            s.count_round(1_793_000_000 + 100 * i64::from(round))
                .unwrap();
            if s.health().unwrap().get(&vault).is_some_and(|e| e.alert) {
                alerts += 1;
            }
        }
        assert!(alerts > 0, "a periodic rollback never alerted");
        // Forgotten after `STALE_MEMORY_ROUNDS` rounds without a rollback.
        let mut s = SyncStore::open_in_memory().unwrap();
        s.vault_event(vault, VaultEvent::Behind { seq: 3, cause })
            .unwrap();
        s.count_round(0).unwrap();
        for _ in 0..STALE_CLEAR_ROUNDS {
            s.vault_event(vault, VaultEvent::Clean).unwrap();
            s.count_round(0).unwrap();
        }
        assert!(s.health().unwrap().is_empty());
        assert_eq!(memory_in(&s.conn).unwrap()[&vault].rounds, 1);
        for _ in 0..STALE_MEMORY_ROUNDS {
            s.count_round(0).unwrap();
        }
        assert!(memory_in(&s.conn).unwrap().is_empty());
        s.vault_event(vault, VaultEvent::Behind { seq: 3, cause })
            .unwrap();
        assert_eq!(s.health().unwrap()[&vault].rounds, 0);
    }

    #[test]
    fn clean_mark_is_spent_by_each_round() {
        // One clean load, then rounds that stop early (an epoch or vault
        // list error) and never load the vault: they are not clean rounds.
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let cause = IntegrityError::ManifestRollback;
        s.vault_event(vault, VaultEvent::Behind { seq: 3, cause })
            .unwrap();
        s.count_round(100).unwrap();
        s.vault_event(vault, VaultEvent::Clean).unwrap();
        s.count_round(200).unwrap();
        let e = s.health().unwrap()[&vault];
        assert_eq!((e.clean, e.clean_rounds), (false, 1));
        for i in 0..STALE_CLEAR_ROUNDS {
            s.count_round(300 + i64::from(i)).unwrap();
        }
        let e = s.health().unwrap()[&vault];
        assert_eq!((e.clean, e.clean_rounds), (false, 0));
        assert_eq!(e.rounds, 1 + STALE_CLEAR_ROUNDS);
    }

    /// Defines `ALL_CAUSES` and `exhaustive` from one list: `exhaustive`
    /// does not compile once a variant is added, until it is listed here,
    /// which also puts it in `ALL_CAUSES`.
    macro_rules! causes {
        ($($v:ident),* $(,)?) => {
            const ALL_CAUSES: &[IntegrityError] = &[$(IntegrityError::$v),*];
            fn exhaustive(e: IntegrityError) {
                match e {
                    $(IntegrityError::$v)|* => {}
                }
            }
        };
    }
    causes!(
        Commitment,
        Aead,
        Signature,
        ManifestRollback,
        ManifestMissingItem,
        ManifestUnexpectedItem,
        ManifestItemMismatch,
        ParamsUnsigned,
        ParamsDowngrade,
        WrongKind,
        WrongContext,
        VaultMissing,
        EpochRollback,
        ParamsRollback,
        DeviceListRollback,
        VaultListRollback,
    );

    #[test]
    fn alerts_stay_until_resolved() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (fork, behind) = (Id::new(), Id::new());
        let cause = IntegrityError::ManifestRollback;
        // A fork alert: clean rounds never clear it.
        s.vault_event(fork, VaultEvent::Alert { seq: 3, cause })
            .unwrap();
        for i in 0..2 * STALE_CLEAR_ROUNDS {
            s.vault_event(fork, VaultEvent::Clean).unwrap();
            s.count_round(i64::from(i)).unwrap();
            let e = s.health().unwrap()[&fork];
            assert!(e.alert && e.fork);
        }
        // Only a safe exit does.
        s.reset_health().unwrap();
        assert!(s.health().unwrap().is_empty());
        // An alert reached by staying behind clears after the clean rounds,
        // and comes back at once if the server goes back within the window.
        s.vault_event(behind, VaultEvent::Behind { seq: 3, cause })
            .unwrap();
        for _ in 0..STALE_ALERT_MAX_ROUNDS {
            s.count_round(0).unwrap();
        }
        assert!(s.health().unwrap()[&behind].alert);
        for _ in 0..STALE_CLEAR_ROUNDS {
            s.vault_event(behind, VaultEvent::Clean).unwrap();
            s.count_round(0).unwrap();
        }
        assert!(s.health().unwrap().is_empty());
        s.vault_event(behind, VaultEvent::Behind { seq: 3, cause })
            .unwrap();
        let e = s.health().unwrap()[&behind];
        assert!(e.alert && !e.fork);
        assert_eq!(e.rounds, STALE_ALERT_MAX_ROUNDS);
    }

    #[test]
    fn unreadable_health_never_blocks_reads() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let vault = Id::new();
        let cause = IntegrityError::ManifestRollback;
        s.set_meta(HEALTH_KEY, &[HEALTH_VERSION, 1]).unwrap();
        // The events of a read or a fetch go on and leave the map as is.
        s.vault_event(vault, VaultEvent::Clean).unwrap();
        s.vault_event(vault, VaultEvent::CaughtUp).unwrap();
        s.vault_event(vault, VaultEvent::Behind { seq: 3, cause })
            .unwrap();
        s.vault_event(vault, VaultEvent::Alert { seq: 3, cause })
            .unwrap();
        assert_eq!(s.meta(HEALTH_KEY).unwrap(), Some(vec![HEALTH_VERSION, 1]));
        // The health and the rounds fail closed.
        assert!(matches!(s.health(), Err(Error::Store(_))));
        assert!(matches!(s.count_round(0), Err(Error::Store(_))));
        assert!(matches!(s.keep_targets(), Err(Error::Store(_))));
        s.reset_health().unwrap();
        assert!(s.health().unwrap().is_empty());
        s.count_round(0).unwrap();
    }

    #[test]
    fn health_cause_codes_round_trip_and_fail_closed() {
        let mut codes = std::collections::BTreeSet::new();
        assert_eq!(ALL_CAUSES.len(), 16);
        for &cause in ALL_CAUSES {
            exhaustive(cause);
            let code = cause_code(cause);
            assert_eq!(cause_of(code), Some(cause));
            assert!(codes.insert(code), "duplicate code {code}");
            let mut map = BTreeMap::new();
            let mut e = HealthEntry::new(7, cause);
            e.since = Some(-5);
            e.rounds = 9;
            e.clean = true;
            e.clean_rounds = 2;
            e.fork = true;
            map.insert(Id([3; 16]), e);
            assert_eq!(decode_health(&encode_health(&map)), Ok(map));
        }
        for code in 0..=u8::MAX {
            if let Some(cause) = cause_of(code) {
                assert_eq!(cause_code(cause), code);
            } else {
                assert!(!codes.contains(&code));
            }
        }
        // An unknown cause code keeps the entry, as an alert.
        let mut map = BTreeMap::new();
        map.insert(Id([4; 16]), HealthEntry::new(7, IntegrityError::Aead));
        let mut bytes = encode_health(&map);
        bytes[1 + 24] = 200;
        let e = decode_health(&bytes).unwrap()[&Id([4; 16])];
        assert!(e.alert);
        assert_eq!(e.seq, 7);
        // Memory round trip.
        let mut memory = BTreeMap::new();
        memory.insert(
            Id([5; 16]),
            HealthMemory {
                since: Some(-1),
                rounds: 4,
                alert: true,
                left: 3,
            },
        );
        memory.insert(
            Id([6; 16]),
            HealthMemory {
                since: None,
                rounds: 0,
                alert: false,
                left: 1,
            },
        );
        assert_eq!(decode_memory(&encode_memory(&memory)), Ok(memory));
        assert!(decode_memory(&[HEALTH_MEMORY_VERSION, 0]).is_err());
    }

    #[test]
    fn alert_is_clock_proof() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (ahead, stuck) = (Id::new(), Id::new());
        let cause = IntegrityError::ManifestRollback;
        for v in [ahead, stuck] {
            s.vault_event(v, VaultEvent::Behind { seq: 3, cause })
                .unwrap();
        }
        // Clock a year ahead for one round, then right again: `since`
        // follows it back, the alert comes on time.
        let t0 = 1_793_000_000;
        s.count_round(t0 + 31_536_000).unwrap();
        for i in 0..STALE_ALERT_ROUNDS - 1 {
            s.count_round(t0 + 150 * i64::from(i + 1)).unwrap();
        }
        let e = s.health().unwrap()[&ahead];
        assert_eq!((e.since, e.rounds, e.alert), (Some(t0 + 150), 5, false));
        s.count_round(t0 + 150 + STALE_ALERT_SECONDS).unwrap();
        assert!(s.health().unwrap()[&ahead].alert);
        // A clock that stands still: the alert comes at the round cap.
        let mut s = SyncStore::open_in_memory().unwrap();
        s.vault_event(stuck, VaultEvent::Behind { seq: 3, cause })
            .unwrap();
        for _ in 1..STALE_ALERT_MAX_ROUNDS {
            s.count_round(t0).unwrap();
        }
        assert!(!s.health().unwrap()[&stuck].alert);
        s.count_round(t0).unwrap();
        assert!(s.health().unwrap()[&stuck].alert);
    }

    #[test]
    fn batch_rolls_back_or_commits_everything() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let (held, free) = (Id::new(), Id::new());
        let (item, old) = (Id::new(), Id::new());
        seed_base(&mut s, RecordKind::Manifest, held, 2, b"m2".to_vec());
        seed_base(&mut s, RecordKind::Item, old, 1, item_data(held, b"old"));
        s.put(rec(held, RecordKind::Manifest, 3, b"local")).unwrap();
        s.put(rec(item, RecordKind::Item, 2, &item_data(held, b"new")))
            .unwrap();
        s.delete(RecordKind::Item, old).unwrap();
        s.put(rec(free, RecordKind::Manifest, 1, b"f1")).unwrap();
        seed_base(&mut s, RecordKind::Manifest, held, 3, b"remote".to_vec());
        let state = |s: &SyncStore| {
            (
                s.pending_changes().unwrap(),
                s.vaults_needing_rebase().unwrap(),
                s.ancestor_manifest(held).unwrap(),
                s.get(RecordKind::Manifest, held).unwrap(),
                s.device_state().unwrap(),
            )
        };
        let before = state(&s);

        // A rebase that drops, writes again, then fails: nothing changed.
        s.begin_batch().unwrap();
        assert!(s.begin_batch().is_err(), "batches do not nest");
        s.drop_pending_vault(held).unwrap();
        s.put(rec(held, RecordKind::Manifest, 4, b"half")).unwrap();
        // A refused write inside the batch undoes only itself.
        assert_eq!(
            s.put_if_version(rec(free, RecordKind::Manifest, 9, b"x"), Some(7)),
            Err(Error::Conflict)
        );
        let mut dev = DeviceState::default();
        dev.last_seen.insert(
            held,
            crate::manifest::SeenManifest {
                seq: 4,
                hash: [1; 32],
            },
        );
        s.set_device_state(&dev).unwrap();
        assert_eq!(
            s.get(RecordKind::Manifest, held).unwrap(),
            Some(rec(held, RecordKind::Manifest, 4, b"half"))
        );
        s.rollback_batch().unwrap();
        assert_eq!(state(&s), before);

        // The same, committed: all of it stays.
        s.begin_batch().unwrap();
        s.drop_pending_vault(held).unwrap();
        s.put(rec(held, RecordKind::Manifest, 4, b"done")).unwrap();
        s.set_device_state(&dev).unwrap();
        s.commit_batch().unwrap();
        assert_eq!(s.vaults_needing_rebase().unwrap(), vec![]);
        assert_eq!(s.device_state().unwrap(), dev);
        assert_eq!(
            s.ancestor_manifest(held).unwrap(),
            Some(rec(held, RecordKind::Manifest, 3, b"remote"))
        );
        assert!(s.get(RecordKind::Item, old).unwrap().is_some());
    }

    fn seen_at(seq: u64, byte: u8) -> Option<Seen> {
        Some(Seen {
            seq,
            hash: [byte; 32],
        })
    }

    #[test]
    fn chain_merge_never_rewinds_a_pin() {
        let id = Id::new();
        let older = ChainState {
            params_epoch: 1,
            device_list: seen_at(2, 1),
            vault_list: seen_at(5, 1),
            device_id: None,
        };
        let newer = ChainState {
            params_epoch: 2,
            device_list: seen_at(3, 2),
            vault_list: seen_at(4, 2),
            device_id: Some(id),
        };
        let merged = ChainState {
            params_epoch: 2,
            device_list: seen_at(3, 2),
            vault_list: seen_at(5, 1),
            device_id: Some(id),
        };
        // Whichever process persists, nothing goes back.
        assert_eq!(merge_chain(&older, &newer, false).unwrap(), merged);
        assert_eq!(merge_chain(&newer, &older, false).unwrap(), merged);
        assert_eq!(
            merge_chain(&ChainState::default(), &newer, false).unwrap(),
            newer
        );
    }

    #[test]
    fn chain_merge_refuses_forks_unless_forced() {
        let stored = ChainState {
            device_list: seen_at(3, 1),
            vault_list: seen_at(3, 1),
            ..ChainState::default()
        };
        let vault_fork = ChainState {
            vault_list: seen_at(3, 2),
            ..stored.clone()
        };
        let device_fork = ChainState {
            device_list: seen_at(3, 2),
            ..stored.clone()
        };
        assert_eq!(
            merge_chain(&vault_fork, &stored, false),
            Err(IntegrityError::VaultListRollback.into())
        );
        assert_eq!(
            merge_chain(&device_fork, &stored, false),
            Err(IntegrityError::DeviceListRollback.into())
        );
        // A list rebase renumbered the lists: the memory ones stand, even
        // below the stored seq.
        let rebased = ChainState {
            vault_list: seen_at(2, 3),
            ..vault_fork.clone()
        };
        assert_eq!(merge_chain(&rebased, &stored, true).unwrap(), rebased);
        // A device id is set once: another one is refused, forced or not.
        let mine = ChainState {
            device_id: Some(Id::new()),
            ..stored.clone()
        };
        let other = ChainState {
            device_id: Some(Id::new()),
            ..stored.clone()
        };
        for force in [false, true] {
            assert_eq!(
                merge_chain(&mine, &other, force),
                Err(IntegrityError::DeviceListRollback.into())
            );
        }
    }

    #[test]
    fn merged_persist_keeps_the_stored_chain_pins() {
        let mut s = SyncStore::open_in_memory().unwrap();
        let id = Id::new();
        let stored = ChainState {
            params_epoch: 3,
            device_list: seen_at(4, 1),
            vault_list: seen_at(6, 1),
            device_id: Some(id),
        };
        s.set_chain_state(&stored).unwrap();
        // A process that unlocked before those pins persists its own.
        let stale = ChainState {
            params_epoch: 2,
            device_list: seen_at(3, 9),
            vault_list: seen_at(5, 9),
            device_id: None,
        };
        let (_, chain) = s
            .merge_device_state(&DeviceState::default(), &stale, &[], false, false)
            .unwrap();
        assert_eq!(chain, stored);
        assert_eq!(s.chain_state().unwrap(), stored);
        // The same through a list write that carries the chain state.
        s.put_all_if_version_with_chain(vec![], &stale).unwrap();
        assert_eq!(s.chain_state().unwrap(), stored);
    }
}
