//! `SyncStore`: a layered SQLite store.
//!
//! - `base`: last known server state (with opaque `server_meta`).
//! - `pending`: local writes not yet confirmed by the server (`data NULL` is
//!   a deletion). Reads see `pending` over `base`.
//! - `staging`: changes received during a fetch, applied to `base` in one
//!   transaction by `commit_remote`.
//! - `ancestor`: for a manifest with a pending local write, the `base` row
//!   that write was built on, kept when the server replaces `base`.
//! - `meta`: device state, change token and other small values.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::ops::Deref;

use rusqlite::{
    Connection, OptionalExtension, Savepoint, Transaction, TransactionBehavior, params,
};

use super::{Change, MAX_RECORD_BYTES, RemoteChange};
use crate::repo::{DeviceState, split_item_record};
use crate::store::{Record, RecordKind, RecordStore};
use crate::{Error, Id, Result};

const DEVICE_STATE_KEY: &str = "device_state";
/// The capped log of remote deletions the store refused (outside the `sync.`
/// namespace of the FFI handle, so only the core writes it).
const IGNORED_DELETIONS_KEY: &str = "ignored_deletions";
const IGNORED_LOG_VERSION: u8 = 1;
const IGNORED_ENTRY_BYTES: usize = 1 + 16 + 8;
/// Most entries kept in the log of ignored deletions; the oldest go first.
pub const MAX_IGNORED_DELETIONS: usize = 100;
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
CREATE TABLE IF NOT EXISTS meta (
    key TEXT NOT NULL PRIMARY KEY,
    value BLOB NOT NULL
);
PRAGMA user_version = 1;
";

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

/// Write a pending data row. A manifest write over a `base` manifest with no
/// `ancestor` yet first keeps that `base` row as its ancestor.
fn write_pending(tx: &Connection, r: &Record) -> Result<()> {
    let version = to_i64(r.version)?;
    if r.kind == RecordKind::Manifest {
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
/// gone or older than `base`, so the server moved on and the local manifest
/// must be rebased before any push.
fn held_vaults(conn: &Connection) -> Result<BTreeSet<Id>> {
    let mut stmt = conn
        .prepare(
            "SELECT p.id FROM pending p
             JOIN base b ON b.kind = p.kind AND b.id = p.id
             LEFT JOIN ancestor a ON a.kind = p.kind AND a.id = p.id
             WHERE p.kind = ?1 AND p.data IS NOT NULL
               AND (a.id IS NULL OR a.version != b.version)",
        )
        .map_err(store_err)?;
    let rows = stmt
        .query_map(params![RecordKind::Manifest.code()], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(store_err)?;
    rows.map(|id| decode_id(id.map_err(store_err)?)).collect()
}

/// `SyncStore::pending_changes` on a consistent view.
fn pending_changes_in(tx: &Connection) -> Result<Vec<Change>> {
    let held = held_vaults(tx)?;
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
        if vault.is_some_and(|v| held.contains(&v)) {
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
        conn.execute_batch(SCHEMA).map_err(store_err)?;
        Ok(SyncStore { conn })
    }

    pub fn open_in_memory() -> Result<SyncStore> {
        let conn = Connection::open_in_memory().map_err(store_err)?;
        conn.execute_batch(SCHEMA).map_err(store_err)?;
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

    /// Local writes to push, minus the held vaults. Order: account params,
    /// keysets, vault keys, vault metas, items, manifests, then deletions,
    /// so a manifest never reaches the server before its items.
    pub fn pending_changes(&self) -> Result<Vec<Change>> {
        self.read(pending_changes_in)
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
        if kind == RecordKind::Manifest {
            tx.execute(
                "DELETE FROM ancestor WHERE kind = ?1 AND id = ?2",
                params![kind.code(), &id.0[..]],
            )
            .map_err(store_err)?;
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
    ///   keeping its `base` row as ancestor (not held).
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
                if protected_from_remote_deletion(kind, &id, &seen)
                    && let Ok(id) = decode_id(id)
                {
                    ignored.push((kind, id));
                }
            }
            append_ignored(&tx, &ignored)?;
        }
        // Both modes: an item the server did not return, in a vault whose
        // manifest it did return, is gone from that vault.
        let deleted = tx
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
                     WHERE b.kind = ?1 AND {missing}"
                ),
                params![RecordKind::Manifest.code()],
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
        Ok(deleted > 0)
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
    /// `staging`. `pending` is never touched. Returns the ids of the vaults
    /// whose manifest was applied.
    ///
    /// Remote deletions the store has no right to make are ignored (no
    /// client deletes them in M2, so they come from a hostile or broken
    /// server): account params and keysets, and the vault key, vault meta and
    /// manifest of a vault in the device's `last_seen`. The local rows stay
    /// and the vault stays readable from them: nothing the server sends can
    /// make this device forget its account or a vault it has read (the
    /// repository reports `VaultMissing` if those rows ever disappear). Each
    /// ignored deletion is appended to the capped log of `ignored_deletions`.
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
        let mut vaults = BTreeSet::new();
        let mut ignored = Vec::new();
        for (kind, id, version, data, server_meta) in staged {
            let kind_code = kind;
            let kind = decode_kind(kind)?;
            if data.is_none() && protected_from_remote_deletion(kind, &id, &seen) {
                if let Ok(id) = decode_id(id) {
                    ignored.push((kind, id));
                }
                continue;
            }
            if kind == RecordKind::Manifest {
                vaults.insert(decode_id(id.clone())?);
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

    /// Merge `mem` with the stored device state, in one transaction (a
    /// savepoint inside an open batch), and store and return the result.
    /// Two processes (the app and an extension) each keep their own state
    /// over one file: per vault the entry with the larger `seq` wins (a tie
    /// keeps the memory one), so neither process rewinds `last_seen`. The
    /// pin is the memory one.
    pub(crate) fn merge_device_state(&mut self, mem: &DeviceState) -> Result<DeviceState> {
        let tx = self.write_tx()?;
        let stored = device_state_in(&tx)?;
        let mut merged = DeviceState {
            pinned: mem.pinned.clone(),
            last_seen: mem.last_seen.clone(),
        };
        for (v, theirs) in stored.last_seen {
            match merged.last_seen.get(&v) {
                Some(ours) if ours.seq >= theirs.seq => {}
                _ => {
                    merged.last_seen.insert(v, theirs);
                }
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![DEVICE_STATE_KEY, merged.encode()],
        )
        .map_err(store_err)?;
        tx.commit()?;
        Ok(merged)
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
        for table in ["base", "pending", "staging", "ancestor", "meta"] {
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
        for table in ["base", "pending", "staging", "ancestor", "meta"] {
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
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![IGNORED_DELETIONS_KEY],
            |r| r.get(0),
        )
        .optional()
        .map_err(store_err)?;
    bytes.map_or(Ok(Vec::new()), |b| decode_ignored(&b))
}

/// Append to the capped log, oldest entries dropped past the cap. One entry
/// per `(kind, id)`: a record refused again moves to the end with the latest
/// time. An unreadable log (edited file) starts again empty: logging never
/// blocks a commit.
fn append_ignored(conn: &Connection, new: &[(RecordKind, Id)]) -> Result<()> {
    if new.is_empty() {
        return Ok(());
    }
    let mut entries = ignored_in(conn).unwrap_or_default();
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
        params![IGNORED_DELETIONS_KEY, encode_ignored(&entries)],
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

/// A remote deletion `commit_remote` ignores: account params and keysets
/// (never deleted by a client in M2), and the vault key, meta or manifest of
/// a vault the device has seen (no vault deletion in M2, R14).
fn protected_from_remote_deletion(kind: RecordKind, id: &[u8], seen: &BTreeSet<Id>) -> bool {
    match kind {
        RecordKind::AccountParams | RecordKind::Keyset => true,
        RecordKind::VaultKey | RecordKind::VaultMeta | RecordKind::Manifest => {
            decode_id(id.to_vec()).is_ok_and(|v| seen.contains(&v))
        }
        RecordKind::Item => false,
    }
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

    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        let tx = self.write_tx()?;
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
        let (a, i1, i2, gone) = (Id::new(), Id::new(), Id::new(), Id::new());
        seed_base(&mut s, RecordKind::Item, gone, 1, item_data(vault, b"old"));
        s.put(rec(vault, RecordKind::Manifest, 1, b"m")).unwrap();
        s.put(rec(i1, RecordKind::Item, 1, &item_data(vault, b"1")))
            .unwrap();
        s.put(rec(vault, RecordKind::VaultMeta, 1, b"vm")).unwrap();
        s.put(rec(vault, RecordKind::VaultKey, 1, b"vk")).unwrap();
        s.put(rec(i2, RecordKind::Item, 1, &item_data(vault, b"2")))
            .unwrap();
        s.put(rec(a, RecordKind::AccountParams, 1, b"ap")).unwrap();
        s.put(rec(a, RecordKind::Keyset, 1, b"ks")).unwrap();
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
        seed_base(&mut s, RecordKind::Keyset, a, 1, b"a-old".to_vec());
        seed_base(&mut s, RecordKind::Manifest, m, 4, b"m".to_vec());
        seed_base(&mut s, RecordKind::Keyset, b, 2, b"b".to_vec());
        seed_base(&mut s, RecordKind::Keyset, c, 2, b"c".to_vec());
        seed_base(&mut s, RecordKind::Keyset, gone, 1, b"gone".to_vec());
        s.mark_pushed(RecordKind::Keyset, a, 9, Some(vec![1]))
            .unwrap();
        s.set_meta("tok", &[7]).unwrap();
        s.stage_remote(remote(
            RecordKind::Keyset,
            c,
            1,
            Some(b"stale page".to_vec()),
        ))
        .unwrap();
        s.put(rec(b, RecordKind::Keyset, 3, b"b-newer")).unwrap();
        s.delete(RecordKind::Keyset, gone).unwrap();

        // Begin: tags, staging and token are gone, nothing is pending yet.
        let pending_before = s.pending_changes().unwrap().len();
        s.begin_zone_reset("tok").unwrap();
        assert!(s.full_fetch_pending().unwrap());
        assert_eq!(s.meta("tok").unwrap(), None);
        assert_eq!(count(&s, "staging"), 0);
        assert_eq!(s.pending_changes().unwrap().len(), pending_before);
        assert_eq!(s.server_meta(RecordKind::Keyset, c).unwrap(), None);

        // The new zone returns a newer `a` and the manifest.
        s.stage_remote(RemoteChange {
            kind: RecordKind::Keyset,
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
            s.get(RecordKind::Keyset, a).unwrap(),
            Some(rec(a, RecordKind::Keyset, 12, b"a-newer"))
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
        seed_base(&mut s, RecordKind::Keyset, kept, 1, b"k".to_vec());
        seed_base(&mut s, RecordKind::Keyset, absent, 1, b"g".to_vec());
        seed_base(&mut s, RecordKind::Keyset, edited, 1, b"e".to_vec());
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
        s.put(rec(edited, RecordKind::Keyset, 2, b"e2")).unwrap();
        s.set_meta("tok", &[1]).unwrap();

        s.begin_full_fetch().unwrap();
        // The token is the caller's business in this mode.
        assert_eq!(s.meta("tok").unwrap(), Some(vec![1]));
        assert!(s.full_fetch_pending().unwrap());
        s.stage_remote(RemoteChange {
            kind: RecordKind::Keyset,
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
            s.server_meta(RecordKind::Keyset, kept).unwrap(),
            Some(vec![3])
        );
        // The item the server no longer lists in a vault it served is gone.
        assert_eq!(s.get(RecordKind::Item, gone_item).unwrap(), None);
        // Everything else the server did not return stays: stable kinds,
        // manifests, and the items of a vault it did not serve.
        assert!(s.get(RecordKind::Keyset, absent).unwrap().is_some());
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
        for table in ["base", "pending", "staging", "ancestor", "meta"] {
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
        for table in ["base", "pending", "staging", "ancestor", "meta"] {
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
        s.put(rec(id, RecordKind::Keyset, 3, b"k")).unwrap();
        s.mark_pushed(RecordKind::Keyset, id, 2, Some(vec![1]))
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
        seed_base(&mut s, RecordKind::Keyset, id, 1, b"base".to_vec());
        s.put(rec(id, RecordKind::Keyset, 2, b"local")).unwrap();
        s.stage_remote(remote(RecordKind::Keyset, id, 3, Some(b"remote".to_vec())))
            .unwrap();
        s.commit_remote().unwrap();
        assert_eq!(
            s.get(RecordKind::Keyset, id).unwrap(),
            Some(rec(id, RecordKind::Keyset, 2, b"local"))
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
}
