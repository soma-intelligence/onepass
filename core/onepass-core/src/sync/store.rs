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
use std::time::Duration;

use std::ops::Deref;

use rusqlite::{
    Connection, OptionalExtension, Savepoint, Transaction, TransactionBehavior, params,
};

use super::{Change, MAX_RECORD_BYTES, RemoteChange};
use crate::repo::{DeviceState, split_item_record};
use crate::store::{Record, RecordKind, RecordStore};
use crate::{Error, Id, Result};

const DEVICE_STATE_KEY: &str = "device_state";
const REQUEUE_PENDING_KEY: &str = "zone.requeue_pending";
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

    /// Step 1 of a server data loss (its zone was deleted and recreated): forget
    /// every `server_meta`, drop the staged pages (they come from the lost
    /// zone), delete the change token stored under `token_key` and persist the
    /// "requeue pending" flag. One transaction. Nothing becomes pending yet: a
    /// stale local row must not overwrite a newer version another device
    /// uploads meanwhile. See `requeue_missing`.
    pub fn begin_zone_reset(&mut self, token_key: &str) -> Result<()> {
        let tx = self.write_tx()?;
        tx.execute("UPDATE base SET server_meta = NULL", [])
            .map_err(store_err)?;
        tx.execute("DELETE FROM staging", []).map_err(store_err)?;
        tx.execute("DELETE FROM meta WHERE key = ?1", params![token_key])
            .map_err(store_err)?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![REQUEUE_PENDING_KEY, &[1u8][..]],
        )
        .map_err(store_err)?;
        tx.commit()
    }

    /// Whether `begin_zone_reset` ran and `requeue_missing` did not yet.
    pub fn requeue_pending(&self) -> Result<bool> {
        Ok(self.meta(REQUEUE_PENDING_KEY)?.is_some())
    }

    /// Step 2, after the `commit_remote` of a complete fetch from scratch: every
    /// `base` row still without `server_meta` (the server does not hold it) and
    /// without a pending row becomes a pending row with the same version and
    /// data, then the flag is cleared. One transaction, a no-op (false) without
    /// the flag. A manifest keeps its `base` row as ancestor (not held). Rows
    /// the server sent back got their `server_meta` from `commit_remote` and
    /// are left alone; a pending tombstone stays a tombstone.
    pub fn requeue_missing(&mut self) -> Result<bool> {
        if !self.requeue_pending()? {
            return Ok(false);
        }
        let tx = self.write_tx()?;
        tx.execute(
            "INSERT OR IGNORE INTO ancestor (kind, id, version, data)
             SELECT b.kind, b.id, b.version, b.data FROM base b
             WHERE b.kind = ?1 AND b.server_meta IS NULL
               AND NOT EXISTS (SELECT 1 FROM pending p WHERE p.kind = b.kind AND p.id = b.id)",
            params![RecordKind::Manifest.code()],
        )
        .map_err(store_err)?;
        tx.execute(
            "INSERT INTO pending (kind, id, version, data)
             SELECT b.kind, b.id, b.version, b.data FROM base b
             WHERE b.server_meta IS NULL
               AND NOT EXISTS (SELECT 1 FROM pending p WHERE p.kind = b.kind AND p.id = b.id)",
            [],
        )
        .map_err(store_err)?;
        tx.execute(
            "DELETE FROM meta WHERE key = ?1",
            params![REQUEUE_PENDING_KEY],
        )
        .map_err(store_err)?;
        tx.commit()?;
        Ok(true)
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
    pub fn commit_remote(&mut self) -> Result<Vec<Id>> {
        let tx = self.write_tx()?;
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
        for (kind, id, version, data, server_meta) in staged {
            let kind_code = kind;
            let kind = decode_kind(kind)?;
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
        match self.meta(DEVICE_STATE_KEY)? {
            Some(bytes) => DeviceState::decode(&bytes),
            None => Ok(DeviceState::default()),
        }
    }

    pub fn set_device_state(&mut self, s: &DeviceState) -> Result<()> {
        self.set_meta(DEVICE_STATE_KEY, &s.encode())
    }

    /// Whether an account params record is visible (pending or base).
    pub fn has_account(&self) -> Result<bool> {
        Ok(!self.list(RecordKind::AccountParams)?.is_empty())
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

        // Step 1: tags, staging and token are gone, nothing is pending yet.
        let pending_before = s.pending_changes().unwrap().len();
        s.begin_zone_reset("tok").unwrap();
        assert!(s.requeue_pending().unwrap());
        assert_eq!(s.meta("tok").unwrap(), None);
        assert_eq!(count(&s, "staging"), 0);
        assert_eq!(s.pending_changes().unwrap().len(), pending_before);
        assert_eq!(s.server_meta(RecordKind::Keyset, c).unwrap(), None);

        // The new zone returns a newer `a` and the manifest; they get their tags in commit_remote.
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

        // Step 2: only `c` (absent from the server, no pending row) is requeued.
        assert!(s.requeue_missing().unwrap());
        assert!(!s.requeue_pending().unwrap());
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
        // No flag, no change.
        assert!(!s.requeue_missing().unwrap());
        assert_eq!(s.pending_changes().unwrap().len(), 3);
    }

    #[test]
    fn requeued_manifest_is_not_held_and_flag_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sqlite");
        let m = Id::new();
        {
            let mut s = SyncStore::open(&path).unwrap();
            seed_base(&mut s, RecordKind::Manifest, m, 4, b"m".to_vec());
            s.begin_zone_reset("tok").unwrap();
        }
        // A restart between the steps: the flag is still there.
        let mut s = SyncStore::open(&path).unwrap();
        assert!(s.requeue_pending().unwrap());
        assert!(s.requeue_missing().unwrap());
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
