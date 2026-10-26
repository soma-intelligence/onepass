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

    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM records WHERE kind = ?1 AND id = ?2",
                params![kind.code(), &id.0[..]],
            )
            .map_err(store_err)?;
        Ok(())
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
