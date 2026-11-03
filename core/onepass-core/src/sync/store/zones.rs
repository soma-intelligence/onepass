//! Shared zones in the `SyncStore` (sharing plan 2, Task 1).
//!
//! Ruling (plan 2 ledger): the private zone keeps the tables it has always
//! had (`base`, `pending`, `staging`, ...), untouched; every shared zone
//! lives in three tables of its own in the same file, keyed by
//! `(zone, kind, id)`: `zone_base`, `zone_pending`, `zone_staging`. One
//! local transaction still covers the private zone and any shared zone
//! (ruling A-8), and no existing row, query or migration changes.
//! Reads see `zone_pending` over `zone_base`, as for the private zone.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, params};

use super::{
    PhaseOutcome, StagedRow, SyncStore, TRUST_STATE_KEY, check_size, decode_id, decode_kind,
    delete_in, effective_version, set_meta_in, store_err, to_i64, write_pending,
};
use crate::share::{ShareAction, ShareState};
use crate::store::{Record, RecordKind, Zone, ZonePendingRow};
use crate::sync::{Change, RemoteChange};
use crate::trust::TrustState;
use crate::{Error, Id, Result};

pub(super) const ZONE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS zone_base (
    zone BLOB NOT NULL,
    kind INTEGER NOT NULL,
    id BLOB NOT NULL,
    version INTEGER NOT NULL,
    data BLOB NOT NULL,
    server_meta BLOB,
    PRIMARY KEY (zone, kind, id)
);
CREATE TABLE IF NOT EXISTS zone_pending (
    zone BLOB NOT NULL,
    kind INTEGER NOT NULL,
    id BLOB NOT NULL,
    version INTEGER NOT NULL,
    data BLOB,
    PRIMARY KEY (zone, kind, id)
);
CREATE TABLE IF NOT EXISTS zone_staging (
    zone BLOB NOT NULL,
    kind INTEGER NOT NULL,
    id BLOB NOT NULL,
    version INTEGER NOT NULL,
    data BLOB,
    server_meta BLOB,
    PRIMARY KEY (zone, kind, id)
);
CREATE TABLE IF NOT EXISTS zone_fetch (
    zone BLOB NOT NULL PRIMARY KEY
);
";

fn shared_key(zone: Zone) -> Result<Vec<u8>> {
    if !zone.is_shared() {
        return Err(Error::Store("private zone in a zone table".into()));
    }
    Ok(zone.key())
}

/// The version a read sees: the pending row (a pending deletion is none),
/// else the base row.
pub(super) fn zone_version(
    conn: &Connection,
    zone: Zone,
    kind: RecordKind,
    id: Id,
) -> Result<Option<u64>> {
    Ok(zone_get(conn, zone, kind, id)?.map(|r| r.version))
}

pub(super) fn zone_get(
    conn: &Connection,
    zone: Zone,
    kind: RecordKind,
    id: Id,
) -> Result<Option<Record>> {
    let z = shared_key(zone)?;
    let pending: Option<(i64, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT version, data FROM zone_pending WHERE zone = ?1 AND kind = ?2 AND id = ?3",
            params![&z, kind.code(), &id.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(store_err)?;
    let row = match pending {
        Some((v, Some(data))) => Some((v, data)),
        Some((_, None)) => None,
        None => conn
            .query_row(
                "SELECT version, data FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
                params![&z, kind.code(), &id.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(store_err)?,
    };
    row.map(|(v, data)| {
        Ok(Record {
            kind,
            id,
            version: u64::try_from(v).map_err(|_| Error::InvalidFormat("record version"))?,
            data,
        })
    })
    .transpose()
}

pub(super) fn zone_list(conn: &Connection, zone: Zone, kind: RecordKind) -> Result<Vec<Record>> {
    let z = shared_key(zone)?;
    let mut stmt = conn
        .prepare(
            "SELECT id FROM zone_base WHERE zone = ?1 AND kind = ?2
             UNION SELECT id FROM zone_pending WHERE zone = ?1 AND kind = ?2
             ORDER BY 1",
        )
        .map_err(store_err)?;
    let ids: Vec<Vec<u8>> = stmt
        .query_map(params![&z, kind.code()], |r| r.get(0))
        .map_err(store_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(store_err)?;
    let mut out = Vec::new();
    for id in ids {
        if let Some(r) = zone_get(conn, zone, kind, decode_id(id)?)? {
            out.push(r);
        }
    }
    Ok(out)
}

pub(super) fn zone_write(conn: &Connection, zone: Zone, r: &Record) -> Result<()> {
    let z = shared_key(zone)?;
    if r.kind.is_immutable()
        && zone_get(conn, zone, r.kind, r.id)?.is_some_and(|old| old.data != r.data)
    {
        return Err(Error::Conflict);
    }
    conn.execute(
        "INSERT OR REPLACE INTO zone_pending (zone, kind, id, version, data)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![&z, r.kind.code(), &r.id.0[..], to_i64(r.version)?, &r.data],
    )
    .map_err(store_err)?;
    Ok(())
}

/// A local deletion in a shared zone, queued for the push. The records
/// that only a signed change retires are never deleted by a client
/// (`InvalidFormat`); `drop_zone` is the way to forget a whole zone.
pub(super) fn zone_delete(conn: &Connection, zone: Zone, kind: RecordKind, id: Id) -> Result<()> {
    let z = shared_key(zone)?;
    if kind.server_deletion_refused() {
        return Err(Error::InvalidFormat("zone record deletion"));
    }
    let Some(current) = zone_get(conn, zone, kind, id)? else {
        return Ok(());
    };
    let in_base: bool = conn
        .query_row(
            "SELECT 1 FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
            params![&z, kind.code(), &id.0[..]],
            |_| Ok(()),
        )
        .optional()
        .map_err(store_err)?
        .is_some();
    if in_base {
        conn.execute(
            "INSERT OR REPLACE INTO zone_pending (zone, kind, id, version, data)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![&z, kind.code(), &id.0[..], to_i64(current.version)?],
        )
    } else {
        conn.execute(
            "DELETE FROM zone_pending WHERE zone = ?1 AND kind = ?2 AND id = ?3",
            params![&z, kind.code(), &id.0[..]],
        )
    }
    .map_err(store_err)?;
    Ok(())
}

pub(super) fn zones_in(conn: &Connection) -> Result<Vec<Zone>> {
    let mut stmt = conn
        .prepare(
            "SELECT zone FROM zone_base UNION SELECT zone FROM zone_pending
             UNION SELECT zone FROM zone_staging ORDER BY 1",
        )
        .map_err(store_err)?;
    let keys: Vec<Vec<u8>> = stmt
        .query_map([], |r| r.get(0))
        .map_err(store_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(store_err)?;
    keys.iter().map(|k| Zone::from_key(k)).collect()
}

pub(super) fn drop_zone_in(conn: &Connection, zone: Zone) -> Result<()> {
    let z = shared_key(zone)?;
    for table in ["zone_base", "zone_pending", "zone_staging", "zone_fetch"] {
        conn.execute(&format!("DELETE FROM {table} WHERE zone = ?1"), params![&z])
            .map_err(store_err)?;
    }
    if let Zone::Vault(id) = zone {
        conn.execute(
            "DELETE FROM meta WHERE key = ?1",
            params![share_state_key(id)],
        )
        .map_err(store_err)?;
    }
    Ok(())
}

/// Meta key prefix of a shared vault's local state (never synced).
const SHARE_STATE_PREFIX: &str = "share_state/";

fn share_state_key(vault: Id) -> String {
    let hex: String = vault.0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{SHARE_STATE_PREFIX}{hex}")
}

pub(super) fn share_state_in(conn: &Connection, vault: Id) -> Result<Option<ShareState>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![share_state_key(vault)],
            |r| r.get(0),
        )
        .optional()
        .map_err(store_err)?;
    bytes.map(|b| ShareState::decode(&b)).transpose()
}

pub(super) fn share_states_in(conn: &Connection) -> Result<Vec<ShareState>> {
    let mut stmt = conn
        .prepare("SELECT value FROM meta WHERE key >= ?1 AND key < ?2 ORDER BY key")
        .map_err(store_err)?;
    let rows: Vec<Vec<u8>> = stmt
        .query_map(params!["share_state/", "share_state0"], |r| r.get(0))
        .map_err(store_err)?
        .collect::<rusqlite::Result<_>>()
        .map_err(store_err)?;
    rows.iter().map(|b| ShareState::decode(b)).collect()
}

/// The kinds phase 1 of a resealing sends (spec 9.2 (a)).
fn phase_one_kind(kind: RecordKind) -> bool {
    matches!(
        kind,
        RecordKind::MemberKey | RecordKind::Attachment | RecordKind::Item
    )
}

/// Push order of a pending row in a shared zone (gap 1 of Task 9): what a
/// record names goes before it, so a reader never sees a manifest whose
/// body, envelope or items are not there yet; deletions last.
fn push_rank(kind: RecordKind, write: bool) -> u8 {
    if !write {
        return 7;
    }
    match kind {
        RecordKind::MemberKey => 0,
        RecordKind::Attachment => 1,
        RecordKind::Item => 2,
        RecordKind::VaultMeta => 3,
        RecordKind::Membership => 4,
        RecordKind::Manifest => 5,
        _ => 6,
    }
}

pub(super) fn zone_pending_rows(conn: &Connection, zone: Zone) -> Result<Vec<ZonePendingRow>> {
    let z = shared_key(zone)?;
    let mut stmt = conn
        .prepare("SELECT kind, id, version, data FROM zone_pending WHERE zone = ?1")
        .map_err(store_err)?;
    let rows = stmt
        .query_map(params![&z], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .map_err(store_err)?;
    rows.map(|row| {
        let (k, id, v, data) = row.map_err(store_err)?;
        Ok((
            decode_kind(k)?,
            decode_id(id)?,
            u64::try_from(v).map_err(|_| Error::InvalidFormat("record version"))?,
            data,
        ))
    })
    .collect()
}

pub(super) fn zone_base_version(
    conn: &Connection,
    zone: Zone,
    kind: RecordKind,
    id: Id,
) -> Result<Option<u64>> {
    let z = shared_key(zone)?;
    let v: Option<i64> = conn
        .query_row(
            "SELECT version FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
            params![&z, kind.code(), &id.0[..]],
            |r| r.get(0),
        )
        .optional()
        .map_err(store_err)?;
    v.map(|v| u64::try_from(v).map_err(|_| Error::InvalidFormat("record version")))
        .transpose()
}

pub(super) fn drop_pending_rows(
    conn: &Connection,
    zone: Zone,
    rows: &[(RecordKind, Id)],
) -> Result<()> {
    let z = shared_key(zone)?;
    for (kind, id) in rows {
        conn.execute(
            "DELETE FROM zone_pending WHERE zone = ?1 AND kind = ?2 AND id = ?3",
            params![&z, kind.code(), &id.0[..]],
        )
        .map_err(store_err)?;
    }
    Ok(())
}

/// One zoned write in `tx`: conditional on the version the caller read.
fn put_zoned_in(conn: &Connection, zone: Zone, r: &Record, expected: Option<u64>) -> Result<()> {
    check_size(&r.data)?;
    match zone {
        Zone::Private => {
            if effective_version(conn, r.kind, r.id)? != expected {
                return Err(Error::Conflict);
            }
            write_pending(conn, r)
        }
        _ => {
            if zone_version(conn, zone, r.kind, r.id)? != expected {
                return Err(Error::Conflict);
            }
            zone_write(conn, zone, r)
        }
    }
}

impl SyncStore {
    /// See `RecordStore::put_all_zoned`: one transaction (or savepoint).
    pub(super) fn put_all_zoned_tx(
        &mut self,
        writes: Vec<(Zone, Record, Option<u64>)>,
        deletes: Vec<(Zone, RecordKind, Id)>,
        trust: Option<&TrustState>,
        shares: &[ShareState],
    ) -> Result<()> {
        let tx = self.write_tx()?;
        for (zone, r, expected) in &writes {
            put_zoned_in(&tx, *zone, r, *expected)?;
        }
        for (zone, kind, id) in deletes {
            match zone {
                Zone::Private => delete_in(&tx, kind, id)?,
                _ => zone_delete(&tx, zone, kind, id)?,
            }
        }
        if let Some(trust) = trust {
            set_meta_in(&tx, TRUST_STATE_KEY, &trust.encode())?;
        }
        for s in shares {
            set_meta_in(&tx, &share_state_key(s.vault_id), &s.encode())?;
        }
        tx.commit()
    }

    /// The local writes of `zone` waiting to be pushed (the private zone:
    /// `pending_changes`), in push order (`push_rank`): envelopes, chunks,
    /// items, meta, body, manifest, other kinds, deletions last. While a
    /// resealing is pushed (`SharePush`), phase 1 sends the envelopes,
    /// chunks and items only, phase 2 every write, and deletions wait for
    /// phase 3 (spec 9.2).
    pub fn pending_changes_in(&self, zone: Zone) -> Result<Vec<Change>> {
        if !zone.is_shared() {
            return self.pending_changes();
        }
        self.read(|conn| {
            let state = match zone {
                Zone::Vault(v) => share_state_in(conn, v)?,
                _ => None,
            };
            // Spec 13.8: a vault whose access was refused sends nothing.
            if state.as_ref().is_some_and(|s| s.access_refused.is_some()) {
                return Ok(Vec::new());
            }
            let phase = state.and_then(|s| s.push).map(|p| p.phase);
            let mut rows = zone_pending_rows(conn, zone)?;
            rows.retain(|(kind, _, _, data)| match (phase, data.is_some()) {
                (Some(1), true) => phase_one_kind(*kind),
                (Some(1 | 2), false) => false,
                _ => true,
            });
            rows.sort_by_key(|(kind, id, _, data)| {
                (push_rank(*kind, data.is_some()), kind.code(), *id)
            });
            Ok(rows
                .into_iter()
                .map(|(kind, id, version, data)| Change {
                    kind,
                    id,
                    version,
                    data,
                })
                .collect())
        })
    }

    /// The confirmed (server) row of a record of shared `zone`, pending
    /// writes aside.
    pub fn zone_base_record(&self, zone: Zone, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        let z = shared_key(zone)?;
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT version, data FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
                params![&z, kind.code(), &id.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(store_err)?;
        row.map(|(v, data)| {
            Ok(Record {
                kind,
                id,
                version: u64::try_from(v).map_err(|_| Error::InvalidFormat("record version"))?,
                data,
            })
        })
        .transpose()
    }

    /// Move the resealing pushed in vault zone `zone` (`SharePush`) to its
    /// next phase once the writes of the current one are confirmed, in one
    /// transaction with the share state. Phase 2 confirmed: the old item
    /// records and envelopes are queued for deletion, the signed removal
    /// copy is written in the removed member's contact zone and the
    /// revocation of its credential is queued (spec 13.8: only after the
    /// body and manifest are confirmed). Phase 3 confirmed: the push is
    /// over. `Retry` (nothing written) while a write of the phase is
    /// pending, or when no resealing is pushed in `zone`.
    pub fn push_share_phase(&mut self, zone: Zone) -> Result<PhaseOutcome> {
        let Zone::Vault(vault) = zone else {
            return Ok(PhaseOutcome::Retry);
        };
        let tx = self.write_tx()?;
        let Some(mut state) = share_state_in(&tx, vault)? else {
            return Ok(PhaseOutcome::Retry);
        };
        let Some(mut push) = state.push.clone() else {
            return Ok(PhaseOutcome::Retry);
        };
        let rows = zone_pending_rows(&tx, zone)?;
        match push.phase {
            1 => {
                if rows
                    .iter()
                    .any(|(k, _, _, d)| d.is_some() && phase_one_kind(*k))
                {
                    return Ok(PhaseOutcome::Retry);
                }
                push.phase = 2;
                state.push = Some(push);
            }
            2 => {
                if rows.iter().any(|(_, _, _, d)| d.is_some()) {
                    return Ok(PhaseOutcome::Retry);
                }
                for id in &push.collect {
                    zone_delete(&tx, zone, RecordKind::Item, *id)?;
                }
                for id in &push.old_keys {
                    zone_delete(&tx, zone, RecordKind::MemberKey, *id)?;
                }
                if let Some((cz, id, data)) = &push.notice
                    && zone_get(&tx, *cz, RecordKind::ShareInvite, *id)?.is_none()
                {
                    zone_write(
                        &tx,
                        *cz,
                        &Record {
                            kind: RecordKind::ShareInvite,
                            id: *id,
                            version: 1,
                            data: data.clone(),
                        },
                    )?;
                }
                if let Some(credential_id) = push.revoke {
                    state.actions.push(ShareAction::RevokeCredential {
                        zone,
                        credential_id,
                    });
                }
                push.phase = 3;
                state.push = Some(push);
            }
            _ => {
                let left = rows.iter().any(|(k, id, _, d)| {
                    d.is_none()
                        && ((*k == RecordKind::Item && push.collect.contains(id))
                            || (*k == RecordKind::MemberKey && push.old_keys.contains(id)))
                });
                if left {
                    return Ok(PhaseOutcome::Retry);
                }
                state.push = None;
            }
        }
        set_meta_in(&tx, &share_state_key(vault), &state.encode())?;
        tx.commit()?;
        Ok(PhaseOutcome::Done)
    }

    /// The server confirmed `(kind, id, version)` in `zone`: the pending row
    /// of exactly that version moves to the base (a deletion removes it).
    pub fn mark_pushed_in(
        &mut self,
        zone: Zone,
        kind: RecordKind,
        id: Id,
        version: u64,
        server_meta: Option<Vec<u8>>,
    ) -> Result<()> {
        if !zone.is_shared() {
            return self.mark_pushed(kind, id, version, server_meta);
        }
        let z = zone.key();
        let v = to_i64(version)?;
        let tx = self.write_tx()?;
        let pending: Option<Option<Vec<u8>>> = tx
            .query_row(
                "SELECT data FROM zone_pending
                 WHERE zone = ?1 AND kind = ?2 AND id = ?3 AND version = ?4",
                params![&z, kind.code(), &id.0[..], v],
                |r| r.get(0),
            )
            .optional()
            .map_err(store_err)?;
        let Some(data) = pending else {
            return Ok(());
        };
        match data {
            Some(data) => tx.execute(
                "INSERT OR REPLACE INTO zone_base (zone, kind, id, version, data, server_meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![&z, kind.code(), &id.0[..], v, data, server_meta],
            ),
            None => tx.execute(
                "DELETE FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
                params![&z, kind.code(), &id.0[..]],
            ),
        }
        .map_err(store_err)?;
        tx.execute(
            "DELETE FROM zone_pending WHERE zone = ?1 AND kind = ?2 AND id = ?3",
            params![&z, kind.code(), &id.0[..]],
        )
        .map_err(store_err)?;
        tx.commit()
    }

    /// Stage a change fetched from `zone`'s mailbox.
    pub fn stage_remote_in(&mut self, zone: Zone, c: RemoteChange) -> Result<()> {
        if !zone.is_shared() {
            return self.stage_remote(c);
        }
        if c.data.as_deref().is_some_and(|d| check_size(d).is_err()) {
            return Ok(());
        }
        let Ok(v) = to_i64(c.version) else {
            return Ok(());
        };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO zone_staging (zone, kind, id, version, data, server_meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    zone.key(),
                    c.kind.code(),
                    &c.id.0[..],
                    v,
                    c.data,
                    c.server_meta
                ],
            )
            .map_err(store_err)?;
        Ok(())
    }

    /// A fetch of `zone` from scratch: staged pages dropped, server meta
    /// forgotten; the next `commit_remote_in` settles the items the server
    /// no longer lists (only when it served the vault manifest).
    pub fn begin_full_fetch_in(&mut self, zone: Zone) -> Result<()> {
        if !zone.is_shared() {
            return self.begin_full_fetch();
        }
        let z = zone.key();
        let tx = self.write_tx()?;
        tx.execute("DELETE FROM zone_staging WHERE zone = ?1", params![&z])
            .map_err(store_err)?;
        tx.execute(
            "UPDATE zone_base SET server_meta = NULL WHERE zone = ?1",
            params![&z],
        )
        .map_err(store_err)?;
        tx.execute(
            "INSERT OR IGNORE INTO zone_fetch (zone) VALUES (?1)",
            params![&z],
        )
        .map_err(store_err)?;
        tx.commit()
    }

    /// Apply the staged changes of `zone` to its base in one transaction.
    /// A deletion of a record only a signed change retires (memberships,
    /// families, member lineage, the immutable kinds) is refused and the
    /// local copy kept; an immutable row served with other bytes is
    /// ignored. Returns the ids of the manifests applied.
    pub fn commit_remote_in(&mut self, zone: Zone) -> Result<Vec<Id>> {
        if !zone.is_shared() {
            return self.commit_remote();
        }
        let z = zone.key();
        let tx = self.write_tx()?;
        let staged: Vec<StagedRow> = {
            let mut stmt = tx
                .prepare(
                    "SELECT kind, id, version, data, server_meta FROM zone_staging
                     WHERE zone = ?1 ORDER BY kind, id",
                )
                .map_err(store_err)?;
            let rows = stmt
                .query_map(params![&z], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .map_err(store_err)?;
            rows.collect::<rusqlite::Result<_>>().map_err(store_err)?
        };
        let full: bool = tx
            .query_row(
                "SELECT 1 FROM zone_fetch WHERE zone = ?1",
                params![&z],
                |_| Ok(()),
            )
            .optional()
            .map_err(store_err)?
            .is_some();
        let items_pending = zone_pending_rows(&tx, zone)?
            .iter()
            .any(|(k, _, _, d)| *k == RecordKind::Item && d.is_some());
        let mut manifests = BTreeSet::new();
        let mut served_items = BTreeSet::new();
        for (kind_code, id, version, data, server_meta) in staged {
            let kind = decode_kind(kind_code)?;
            let rid = decode_id(id.clone())?;
            if data.is_none() && kind.server_deletion_refused() {
                continue;
            }
            // An envelope of an old generation stays while item writes of
            // this device wait: the shared rebase opens them with it.
            if data.is_none() && kind == RecordKind::MemberKey && items_pending {
                continue;
            }
            if kind.is_immutable()
                && let Some(d) = data.as_deref()
            {
                let old: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT data FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
                        params![&z, kind_code, &id],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(store_err)?;
                if old.is_some_and(|o| o != d) {
                    continue;
                }
            }
            if kind == RecordKind::Manifest && data.is_some() {
                manifests.insert(rid);
            }
            if kind == RecordKind::Item && data.is_some() {
                served_items.insert(id.clone());
            }
            match data {
                Some(data) => tx.execute(
                    "INSERT OR REPLACE INTO zone_base (zone, kind, id, version, data, server_meta)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![&z, kind_code, &id, version, data, server_meta],
                ),
                None => tx.execute(
                    "DELETE FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
                    params![&z, kind_code, &id],
                ),
            }
            .map_err(store_err)?;
        }
        if full && !manifests.is_empty() {
            // The server is authoritative for the items of a vault whose
            // manifest it served in a fetch from scratch: an item row it did
            // not return (and no pending local write) goes.
            let mut stmt = tx
                .prepare(
                    "SELECT id FROM zone_base b WHERE zone = ?1 AND kind = ?2
                     AND NOT EXISTS (SELECT 1 FROM zone_pending p
                         WHERE p.zone = b.zone AND p.kind = b.kind AND p.id = b.id)",
                )
                .map_err(store_err)?;
            let ids: Vec<Vec<u8>> = stmt
                .query_map(params![&z, RecordKind::Item.code()], |r| r.get(0))
                .map_err(store_err)?
                .collect::<rusqlite::Result<_>>()
                .map_err(store_err)?;
            drop(stmt);
            for id in ids.into_iter().filter(|id| !served_items.contains(id)) {
                tx.execute(
                    "DELETE FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
                    params![&z, RecordKind::Item.code(), &id],
                )
                .map_err(store_err)?;
            }
        }
        if full {
            tx.execute("DELETE FROM zone_fetch WHERE zone = ?1", params![&z])
                .map_err(store_err)?;
        }
        tx.execute("DELETE FROM zone_staging WHERE zone = ?1", params![&z])
            .map_err(store_err)?;
        tx.commit()?;
        Ok(manifests.into_iter().collect())
    }

    /// The opaque server metadata kept with the base row of `zone`.
    pub fn server_meta_in(&self, zone: Zone, kind: RecordKind, id: Id) -> Result<Option<Vec<u8>>> {
        if !zone.is_shared() {
            return self.server_meta(kind, id);
        }
        Ok(self
            .conn
            .query_row(
                "SELECT server_meta FROM zone_base WHERE zone = ?1 AND kind = ?2 AND id = ?3",
                params![zone.key(), kind.code(), &id.0[..]],
                |r| r.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()
            .map_err(store_err)?
            .flatten())
    }
}
