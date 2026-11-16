//! The key-use queue table of the SQLite stores (`SqliteStore`,
//! `SyncStore`): sealed rows under a keyed item tag, device-local, never
//! synced (`crate::key_use_queue`).
//!
//! Schema: an additive table, created when missing, as the autofill
//! history (`autofill_sql`). No `user_version` bump, so a downgrade keeps
//! opening the file.

use rusqlite::{Connection, params};

use super::KeyUseQueueRow;
use crate::{Error, Result};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS key_use_queue (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    item_tag BLOB NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS key_use_queue_item ON key_use_queue (item_tag, seq);
";

/// Only the SQLite error code goes into the error: never paths or data.
fn err(e: rusqlite::Error) -> Error {
    match e.sqlite_error_code() {
        Some(code) => Error::Store(format!("sqlite: {code:?}")),
        None => Error::Store("sqlite".into()),
    }
}

pub(crate) fn put(
    conn: &Connection,
    tag: &[u8; 32],
    replace: &[i64],
    data: &[u8],
    keep_total: usize,
) -> Result<()> {
    delete(conn, replace)?;
    conn.execute(
        "INSERT INTO key_use_queue (item_tag, data) VALUES (?1, ?2)",
        params![&tag[..], data],
    )
    .map_err(err)?;
    conn.execute(
        "DELETE FROM key_use_queue WHERE seq NOT IN
             (SELECT seq FROM key_use_queue ORDER BY seq DESC LIMIT ?1)",
        params![i64::try_from(keep_total).unwrap_or(i64::MAX)],
    )
    .map_err(err)?;
    Ok(())
}

pub(crate) fn rows(conn: &Connection, tag: Option<&[u8; 32]>) -> Result<Vec<KeyUseQueueRow>> {
    let read = |r: &rusqlite::Row<'_>| -> rusqlite::Result<(i64, Vec<u8>, Vec<u8>)> {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    };
    let raw: Vec<(i64, Vec<u8>, Vec<u8>)> = match tag {
        Some(t) => {
            let mut stmt = conn
                .prepare(
                    "SELECT seq, item_tag, data FROM key_use_queue WHERE item_tag = ?1 ORDER BY seq",
                )
                .map_err(err)?;
            stmt.query_map(params![&t[..]], read)
                .map_err(err)?
                .collect::<rusqlite::Result<_>>()
                .map_err(err)?
        }
        None => {
            let mut stmt = conn
                .prepare("SELECT seq, item_tag, data FROM key_use_queue ORDER BY seq")
                .map_err(err)?;
            stmt.query_map([], read)
                .map_err(err)?
                .collect::<rusqlite::Result<_>>()
                .map_err(err)?
        }
    };
    // A file may have been edited: a tag of another length is dropped.
    Ok(raw
        .into_iter()
        .filter_map(|(seq, tag, data)| Some((seq, <[u8; 32]>::try_from(tag).ok()?, data)))
        .collect())
}

pub(crate) fn delete(conn: &Connection, seqs: &[i64]) -> Result<()> {
    let mut stmt = conn
        .prepare("DELETE FROM key_use_queue WHERE seq = ?1")
        .map_err(err)?;
    for s in seqs {
        stmt.execute(params![s]).map_err(err)?;
    }
    Ok(())
}

pub(crate) fn clear(conn: &Connection) -> Result<usize> {
    conn.execute("DELETE FROM key_use_queue", []).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_replaces_caps_and_clears() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        put(&conn, &a, &[], b"a1", 3).unwrap();
        put(&conn, &b, &[], b"b1", 3).unwrap();
        let first = rows(&conn, Some(&a)).unwrap()[0].0;
        put(&conn, &a, &[first], b"a2", 3).unwrap();
        let of_a = rows(&conn, Some(&a)).unwrap();
        assert_eq!(of_a.len(), 1);
        assert_eq!(of_a[0].2, b"a2");
        put(&conn, &b, &[], b"b2", 3).unwrap();
        put(&conn, &b, &[], b"b3", 3).unwrap();
        let all: Vec<Vec<u8>> = rows(&conn, None)
            .unwrap()
            .into_iter()
            .map(|r| r.2)
            .collect();
        assert_eq!(all, vec![b"a2".to_vec(), b"b2".to_vec(), b"b3".to_vec()]);
        delete(&conn, &[rows(&conn, Some(&a)).unwrap()[0].0]).unwrap();
        assert_eq!(rows(&conn, None).unwrap().len(), 2);
        assert_eq!(clear(&conn).unwrap(), 2);
        assert!(rows(&conn, None).unwrap().is_empty());
    }
}
