//! SQLite store: one table, WAL journal, full fsync on commit.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use super::{Record, RecordKind, RecordStore};
use crate::{Error, Id, Result};

pub struct SqliteStore {
    conn: Connection,
}

/// Only the SQLite error code goes into the error: never paths or data.
fn store_err(e: rusqlite::Error) -> Error {
    match e.sqlite_error_code() {
        Some(code) => Error::Store(format!("sqlite: {code:?}")),
        None => Error::Store("sqlite".into()),
    }
}

/// A row as stored: `(kind, id, version, data)`.
type Row = (i64, Vec<u8>, i64, Vec<u8>);

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

/// Rows come from a file that may have been edited: check every column.
fn decode((kind, id, version, data): Row) -> Result<Record> {
    let kind = u8::try_from(kind)
        .map_err(|_| Error::InvalidFormat("record kind"))
        .and_then(RecordKind::from_code)?;
    let id = Id(id
        .try_into()
        .map_err(|_| Error::InvalidFormat("record id"))?);
    let version = u64::try_from(version).map_err(|_| Error::InvalidFormat("record version"))?;
    Ok(Record {
        id,
        kind,
        version,
        data,
    })
}

impl SqliteStore {
    /// Open or create the database at `path`, in WAL mode with
    /// `synchronous = FULL` so a committed write survives a power loss.
    pub fn open(path: &Path) -> Result<SqliteStore> {
        let conn = Connection::open(path).map_err(store_err)?;
        let mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .map_err(store_err)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(Error::Store("sqlite: WAL unavailable".into()));
        }
        conn.execute_batch(
            "PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS records (
                 kind INTEGER NOT NULL,
                 id BLOB NOT NULL,
                 version INTEGER NOT NULL,
                 data BLOB NOT NULL,
                 PRIMARY KEY (kind, id)
             );",
        )
        .map_err(store_err)?;
        Ok(SqliteStore { conn })
    }

    /// Fold the WAL into the database and rebuild it, so that deleted rows
    /// do not linger in free pages or in the WAL (Travel Mode). In WAL mode
    /// `VACUUM` writes the rebuilt pages to the WAL: a second checkpoint
    /// copies them over the old file and truncates the WAL.
    pub fn compact(&self) -> Result<()> {
        self.checkpoint()?;
        self.conn.execute_batch("VACUUM;").map_err(store_err)?;
        self.checkpoint()
    }

    /// `wal_checkpoint(TRUNCATE)`; a busy result (a reader or writer kept
    /// the WAL from being folded) is an error, not a silent success.
    fn checkpoint(&self) -> Result<()> {
        let busy: i64 = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
            .map_err(store_err)?;
        if busy != 0 {
            return Err(Error::Store("sqlite: checkpoint busy".into()));
        }
        Ok(())
    }
}

impl RecordStore for SqliteStore {
    /// Versions above `i64::MAX` do not fit an SQLite integer and are refused.
    fn put(&mut self, r: Record) -> Result<()> {
        let version =
            i64::try_from(r.version).map_err(|_| Error::InvalidFormat("record version"))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO records (kind, id, version, data) VALUES (?1, ?2, ?3, ?4)",
                params![r.kind.code(), &r.id.0[..], version, r.data],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// One statement, so one implicit transaction: an `UPDATE` guarded by
    /// the expected version, or an `INSERT` that does nothing when the
    /// record exists. No row changed means another writer got there first.
    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
        put_if_version_on(&self.conn, &r, expected)
    }

    /// Every conditional write in one transaction: a conflict or a failure
    /// on any of them rolls all of them back.
    fn put_all_if_version(&mut self, writes: Vec<(Record, Option<u64>)>) -> Result<()> {
        let tx = self.conn.transaction().map_err(store_err)?;
        for (r, expected) in &writes {
            put_if_version_on(&tx, r, *expected)?;
        }
        tx.commit().map_err(store_err)
    }

    /// The conditional writes and the deletions in one transaction.
    fn put_all_if_version_and_delete(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
    ) -> Result<()> {
        let tx = self.conn.transaction().map_err(store_err)?;
        for (r, expected) in &writes {
            put_if_version_on(&tx, r, *expected)?;
        }
        for (kind, id) in deletes {
            delete_on(&tx, kind, id)?;
        }
        tx.commit().map_err(store_err)
    }

    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        self.conn
            .query_row(
                "SELECT kind, id, version, data FROM records WHERE kind = ?1 AND id = ?2",
                params![kind.code(), &id.0[..]],
                read_row,
            )
            .optional()
            .map_err(store_err)?
            .map(decode)
            .transpose()
    }

    fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
        let mut stmt = self
            .conn
            .prepare("SELECT kind, id, version, data FROM records WHERE kind = ?1")
            .map_err(store_err)?;
        let rows = stmt
            .query_map(params![kind.code()], read_row)
            .map_err(store_err)?;
        rows.map(|row| decode(row.map_err(store_err)?)).collect()
    }

    /// A signed list record is never deleted (spec 4.2: the lists only
    /// grow): `InvalidFormat("list record deletion")`, nothing written.
    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        delete_on(&self.conn, kind, id)
    }
}

/// `delete` on a connection or an open transaction. A signed list record is
/// never deleted: `InvalidFormat("list record deletion")`.
fn delete_on(conn: &Connection, kind: RecordKind, id: Id) -> Result<()> {
    if matches!(kind, RecordKind::DeviceList | RecordKind::VaultList) {
        return Err(Error::InvalidFormat("list record deletion"));
    }
    conn.execute(
        "DELETE FROM records WHERE kind = ?1 AND id = ?2",
        params![kind.code(), &id.0[..]],
    )
    .map_err(store_err)?;
    Ok(())
}

/// `put_if_version` on a connection or an open transaction.
fn put_if_version_on(conn: &Connection, r: &Record, expected: Option<u64>) -> Result<()> {
    let version = i64::try_from(r.version).map_err(|_| Error::InvalidFormat("record version"))?;
    let changed = match expected {
        None => conn.execute(
            "INSERT INTO records (kind, id, version, data) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (kind, id) DO NOTHING",
            params![r.kind.code(), &r.id.0[..], version, r.data],
        ),
        Some(old) => {
            // A version that does not fit an SQLite integer was never stored.
            let Ok(old) = i64::try_from(old) else {
                return Err(Error::Conflict);
            };
            conn.execute(
                "UPDATE records SET version = ?3, data = ?4
                 WHERE kind = ?1 AND id = ?2 AND version = ?5",
                params![r.kind.code(), &r.id.0[..], version, r.data, old],
            )
        }
    }
    .map_err(store_err)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_store_behaves_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let id = Id::new();
        {
            let mut s = SqliteStore::open(&path).unwrap();
            super::super::exercise(&mut s);
            s.put(Record {
                id,
                kind: RecordKind::Keyset,
                version: u64::from(u32::MAX) + 5,
                data: vec![1, 2, 3],
            })
            .unwrap();
        }
        let s = SqliteStore::open(&path).unwrap();
        let got = s.get(RecordKind::Keyset, id).unwrap().unwrap();
        assert_eq!(got.version, u64::from(u32::MAX) + 5);
        assert_eq!(got.data, vec![1, 2, 3]);
        let mode: String = s
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let sync: i64 = s
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2, "synchronous = FULL");
    }

    #[test]
    fn compact_keeps_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let mut s = SqliteStore::open(&path).unwrap();
        let marker: Vec<u8> = b"onepass-compact-marker-".repeat(8);
        let keep = Id::new();
        let gone = Id::new();
        for (id, data) in [(keep, b"kept".to_vec()), (gone, marker.clone())] {
            s.put(Record {
                id,
                kind: RecordKind::Item,
                version: 1,
                data,
            })
            .unwrap();
        }
        s.delete(RecordKind::Item, gone).unwrap();
        s.compact().unwrap();
        assert_eq!(
            s.get(RecordKind::Item, keep).unwrap().unwrap().data,
            b"kept".to_vec()
        );
        assert_eq!(s.get(RecordKind::Item, gone).unwrap(), None);
        assert_eq!(s.list(RecordKind::Item).unwrap().len(), 1);
        // The deleted row is gone from the files too, not just unlisted.
        let contains = |p: &Path| {
            std::fs::read(p)
                .map(|b| b.windows(marker.len()).any(|w| w == &marker[..]))
                .unwrap_or(false)
        };
        assert!(!contains(&path));
        assert!(!contains(&dir.path().join("db-wal")));
        drop(s);
        let s = SqliteStore::open(&path).unwrap();
        assert_eq!(s.list(RecordKind::Item).unwrap().len(), 1);
    }

    #[test]
    fn compact_reports_a_busy_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let mut s = SqliteStore::open(&path).unwrap();
        s.conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        let put = |s: &mut SqliteStore, n: u8| {
            s.put(Record {
                id: Id::new(),
                kind: RecordKind::Item,
                version: 1,
                data: vec![n],
            })
            .unwrap();
        };
        put(&mut s, 1);
        // A reader pinned on an older snapshot keeps the WAL from being
        // reset while the writer moves on.
        let reader = SqliteStore::open(&path).unwrap();
        reader.conn.execute_batch("BEGIN").unwrap();
        let _: i64 = reader
            .conn
            .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
            .unwrap();
        put(&mut s, 2);
        assert!(matches!(s.compact(), Err(Error::Store(_))));
        reader.conn.execute_batch("COMMIT").unwrap();
        s.compact().unwrap();
    }

    #[test]
    fn version_above_i64_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = SqliteStore::open(&dir.path().join("db")).unwrap();
        let r = Record {
            id: Id::new(),
            kind: RecordKind::Item,
            version: u64::MAX,
            data: vec![],
        };
        assert!(matches!(s.put(r), Err(Error::InvalidFormat(_))));
    }
}
