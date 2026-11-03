//! The autofill history table of the SQLite stores (`SqliteStore`,
//! `SyncStore`): sealed rows under a keyed site tag, device-local, never
//! synced (`crate::autofill_history`).
//!
//! Schema: an additive table, created when missing. A database from before
//! it opens and gains it; an older build ignores it. No `user_version`
//! bump, so a downgrade keeps opening the file.

use rusqlite::{Connection, params};

use super::AutofillRow;
use crate::{Error, Result};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS autofill_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    site_tag BLOB NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS autofill_events_site ON autofill_events (site_tag, seq);
";

/// Only the SQLite error code goes into the error: never paths or data.
fn err(e: rusqlite::Error) -> Error {
    match e.sqlite_error_code() {
        Some(code) => Error::Store(format!("sqlite: {code:?}")),
        None => Error::Store("sqlite".into()),
    }
}

fn limit(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

pub(crate) fn append(
    conn: &Connection,
    tag: &[u8; 32],
    data: &[u8],
    keep_per_site: usize,
    keep_total: usize,
) -> Result<()> {
    conn.execute(
        "INSERT INTO autofill_events (site_tag, data) VALUES (?1, ?2)",
        params![&tag[..], data],
    )
    .map_err(err)?;
    conn.execute(
        "DELETE FROM autofill_events WHERE site_tag = ?1 AND seq NOT IN
             (SELECT seq FROM autofill_events WHERE site_tag = ?1 ORDER BY seq DESC LIMIT ?2)",
        params![&tag[..], limit(keep_per_site)],
    )
    .map_err(err)?;
    conn.execute(
        "DELETE FROM autofill_events WHERE seq NOT IN
             (SELECT seq FROM autofill_events ORDER BY seq DESC LIMIT ?1)",
        params![limit(keep_total)],
    )
    .map_err(err)?;
    Ok(())
}

pub(crate) fn rows(conn: &Connection, tag: Option<&[u8; 32]>) -> Result<Vec<AutofillRow>> {
    let read = |r: &rusqlite::Row<'_>| -> rusqlite::Result<(i64, Vec<u8>, Vec<u8>)> {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
    };
    let raw: Vec<(i64, Vec<u8>, Vec<u8>)> = match tag {
        Some(t) => {
            let mut stmt = conn
                .prepare(
                    "SELECT seq, site_tag, data FROM autofill_events WHERE site_tag = ?1 ORDER BY seq",
                )
                .map_err(err)?;
            stmt.query_map(params![&t[..]], read)
                .map_err(err)?
                .collect::<rusqlite::Result<_>>()
                .map_err(err)?
        }
        None => {
            let mut stmt = conn
                .prepare("SELECT seq, site_tag, data FROM autofill_events ORDER BY seq")
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
        .prepare("DELETE FROM autofill_events WHERE seq = ?1")
        .map_err(err)?;
    for s in seqs {
        stmt.execute(params![s]).map_err(err)?;
    }
    Ok(())
}

pub(crate) fn clear(conn: &Connection) -> Result<usize> {
    conn.execute("DELETE FROM autofill_events", []).map_err(err)
}
