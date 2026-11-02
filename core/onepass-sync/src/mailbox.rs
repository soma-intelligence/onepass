//! `Transport` over a OnePass mailbox (cross-platform spec 4.5, 4.6, 4.11).
//!
//! - `binding`: the mailbox's incarnation (`GET /v1/mailboxes/{m}`); a page
//!   of another incarnation during the round is `ZoneReset`.
//! - Server meta: the record's `seq`, 8 bytes big-endian; a write expects
//!   it (`Op::Put { expected }`).
//! - Cursor: 8 bytes big-endian, the `after` of the next incremental page.
//!   In the middle of a fetch from scratch: 17 bytes, `1 || after || head`,
//!   where `head` is the mailbox head at the first page; once the last page
//!   is read the cursor is that head, so the deletions written during the
//!   fetch come with the next incremental pages. `CursorExpired` (tombstones
//!   purged past the cursor) restarts from scratch: the page says
//!   `restarted_from_scratch`. So does a head below the cursor: the
//!   mailbox went back under the same incarnation (spec 11).
//! - Own writes are checked against the feed (spec 11): each write the
//!   server answered `Applied` with a seq must come back in the incremental
//!   pages with that seq or a later one for its key. Once a fetch reaches
//!   the head without it, the server answered for a write it never made (a
//!   batch applied in part): `unconfirmed` names it and the driver sends
//!   the local copy again. Writes only (a lost deletion leaves a record the
//!   other devices still read, nothing lost). Kept in memory: a restart of
//!   the app forgets it.
//! - Blob bodies are resolved (`fetch_body`, checked against their hash)
//!   before a change leaves the transport; a body that fails its check is
//!   `RecordUnreadable`.
//! - A record of an unknown kind is skipped.
//! - Send: one commit per batch, blob bodies announced and uploaded first;
//!   `Applied` saves each change with its seq, `Conflict` returns the
//!   server's row for the keys in conflict and `Failed` for the others.

use std::collections::BTreeMap;
use std::time::Duration;

use onepass_core::Id;
use onepass_core::store::RecordKind;
use onepass_core::sync::RemoteChange;
use onepass_mailbox::{MailboxApi, MailboxClient, MailboxError};
use onepass_mailbox_proto::{
    Body, COMMIT_BODY_MAX, COMMIT_OPS_MAX, CommitOp, CommitResponse, INLINE_MAX, Op,
    PAGE_MAX_RECORDS, RECORD_MAX, ServerRecord, blob_sha256,
};

use crate::transport::{BatchLimits, Outgoing, Page, SendResult, Transport, TransportError};

/// Room kept under `COMMIT_BODY_MAX` for the request's own framing.
const BODY_MARGIN: usize = 64 * 1024;

/// See the module doc. `A` is `MailboxClient` in the apps, the in-memory
/// client in tests.
pub struct MailboxTransport<A: MailboxApi = MailboxClient> {
    api: A,
    /// The incarnation `binding` read this round.
    incarnation: Option<u64>,
    page_limit: u32,
    /// Own writes not seen in the feed yet: key to the seq answered.
    awaiting: BTreeMap<(u8, [u8; 16]), u64>,
    /// Own writes the feed reached the head without (`unconfirmed`).
    lost: Vec<(u8, [u8; 16])>,
}

impl<A: MailboxApi> MailboxTransport<A> {
    pub fn new(api: A) -> Self {
        MailboxTransport {
            api,
            incarnation: None,
            page_limit: PAGE_MAX_RECORDS,
            awaiting: BTreeMap::new(),
            lost: Vec::new(),
        }
    }

    /// Pages of at most `limit` records (tests).
    pub fn with_page_limit(mut self, limit: u32) -> Self {
        self.set_page_limit(limit);
        self
    }

    /// Pages of at most `limit` records from now on (tests).
    pub fn set_page_limit(&mut self, limit: u32) {
        self.page_limit = limit.clamp(1, PAGE_MAX_RECORDS);
    }

    pub fn api(&self) -> &A {
        &self.api
    }

    pub fn api_mut(&mut self) -> &mut A {
        &mut self.api
    }

    /// Own writes seen in the feed: their seq or a later one for the key.
    fn saw(&mut self, records: &[ServerRecord]) {
        for r in records {
            if self
                .awaiting
                .get(&(r.kind, r.id))
                .is_some_and(|s| r.seq >= *s)
            {
                self.awaiting.remove(&(r.kind, r.id));
            }
        }
    }

    fn remote_change(&self, r: ServerRecord) -> Result<Option<RemoteChange>, TransportError> {
        let Ok(kind) = RecordKind::from_code(r.kind) else {
            return Ok(None);
        };
        let data = match &r.body {
            Some(b) => Some(self.api.fetch_body(b).map_err(transport_error)?),
            None => None,
        };
        Ok(Some(RemoteChange {
            kind,
            id: Id(r.id),
            version: r.version,
            data,
            server_meta: Some(r.seq.to_be_bytes().to_vec()),
        }))
    }
}

/// Where a fetch starts: incremental after a seq, or from scratch (after a
/// seq, with the head of its first page once read).
enum Cursor {
    Incremental(u64),
    Full { after: u64, head: Option<u64> },
}

fn decode_cursor(c: Option<&[u8]>) -> Result<Cursor, TransportError> {
    let bad = || TransportError::Other("mailbox cursor".into());
    match c {
        None => Ok(Cursor::Full {
            after: 0,
            head: None,
        }),
        Some(b) if b.len() == 8 => Ok(Cursor::Incremental(u64::from_be_bytes(
            b.try_into().map_err(|_| bad())?,
        ))),
        Some(b) if b.len() == 17 && b[0] == 1 => Ok(Cursor::Full {
            after: u64::from_be_bytes(b[1..9].try_into().map_err(|_| bad())?),
            head: Some(u64::from_be_bytes(b[9..17].try_into().map_err(|_| bad())?)),
        }),
        Some(_) => Err(bad()),
    }
}

fn seq_of(meta: Option<&[u8]>) -> Option<u64> {
    meta.and_then(|m| <[u8; 8]>::try_from(m).ok())
        .map(u64::from_be_bytes)
}

/// The mailbox errors as the driver sees them.
pub fn transport_error(e: MailboxError) -> TransportError {
    match e {
        MailboxError::Offline => TransportError::Offline,
        MailboxError::Retry { after } => TransportError::Retryable {
            after: after.map(|s| Duration::from_secs(u64::from(s))),
        },
        MailboxError::Stale => TransportError::Stale,
        MailboxError::IncarnationChanged { .. } => TransportError::ZoneReset,
        MailboxError::Integrity(_) => TransportError::RecordUnreadable,
        e => TransportError::Other(e.to_string()),
    }
}

/// The body a record of `data` goes out with: inline up to 16 KiB, a blob
/// reference up to 900 KiB.
fn body_for(data: &[u8]) -> Result<Body, TransportError> {
    if data.len() <= INLINE_MAX {
        Ok(Body::Inline(data.to_vec()))
    } else if data.len() <= RECORD_MAX {
        Ok(Body::Blob {
            sha256: blob_sha256(data),
            // At most RECORD_MAX: fits.
            size: data.len() as u32,
        })
    } else {
        Err(TransportError::Other("record too large".into()))
    }
}

impl<A: MailboxApi> Transport for MailboxTransport<A> {
    fn binding(&mut self) -> Result<u64, TransportError> {
        let info = self.api.info().map_err(transport_error)?;
        self.incarnation = Some(info.incarnation);
        Ok(info.incarnation)
    }

    fn fetch(&mut self, cursor: Option<&[u8]>) -> Result<Page, TransportError> {
        let mut restarted = false;
        let (after, full, mut head) = match decode_cursor(cursor)? {
            Cursor::Incremental(after) => (after, false, None),
            Cursor::Full { after, head } => (after, true, head),
        };
        let first = match self.api.changes(after, self.page_limit, full) {
            Err(MailboxError::CursorExpired) => None,
            // A head below what this device already read (or below the
            // head a fetch from scratch started at): the mailbox went back
            // under the same incarnation (an old backup, a hostile server).
            // Seqs below the cursor would never be read again: fetch from
            // scratch, the core refuses what is older than its copy.
            Ok(p) if p.head < after || head.is_some_and(|h| p.head < h) => None,
            Ok(p) => {
                self.saw(&p.records);
                if p.more {
                    Some(p)
                } else if full {
                    // The end of a fetch from scratch queues what the
                    // server lacks.
                    self.awaiting.clear();
                    Some(p)
                } else {
                    // Past the head: an own write still awaited is one the
                    // server never made.
                    let h = p.head;
                    let lost = &mut self.lost;
                    self.awaiting.retain(|k, s| {
                        if *s <= h {
                            lost.push(*k);
                        }
                        *s > h
                    });
                    Some(p)
                }
            }
            Err(e) => return Err(transport_error(e)),
        };
        if first.is_none() {
            self.awaiting.clear();
        }
        let (page, full) = match first {
            Some(p) => (p, full),
            None => {
                restarted = true;
                head = None;
                (
                    self.api
                        .changes(0, self.page_limit, true)
                        .map_err(transport_error)?,
                    true,
                )
            }
        };
        match self.incarnation {
            Some(i) if i != page.incarnation => return Err(TransportError::ZoneReset),
            Some(_) => {}
            None => self.incarnation = Some(page.incarnation),
        }
        let mut changes = Vec::with_capacity(page.records.len());
        for r in page.records {
            if let Some(c) = self.remote_change(r)? {
                changes.push(c);
            }
        }
        let cursor = if full {
            let head = head.unwrap_or(page.head);
            if page.more {
                let mut c = vec![1u8];
                c.extend(page.next_after.to_be_bytes());
                c.extend(head.to_be_bytes());
                c
            } else {
                head.to_be_bytes().to_vec()
            }
        } else {
            page.next_after.to_be_bytes().to_vec()
        };
        Ok(Page {
            changes,
            cursor: Some(cursor),
            more: page.more,
            restarted_from_scratch: restarted,
        })
    }

    fn send(&mut self, batch: &[Outgoing]) -> Result<Vec<SendResult>, TransportError> {
        let mut ops = Vec::with_capacity(batch.len());
        let mut blobs: Vec<&[u8]> = Vec::new();
        for o in batch {
            let op = match &o.change.data {
                Some(d) => {
                    let body = body_for(d)?;
                    if matches!(body, Body::Blob { .. }) {
                        blobs.push(d);
                    }
                    Op::Put {
                        expected: seq_of(o.server_meta.as_deref()),
                        body,
                    }
                }
                None => Op::Delete,
            };
            ops.push(CommitOp {
                kind: o.change.kind.code(),
                id: o.change.id.0,
                version: o.change.version,
                op,
            });
        }
        let response = self
            .api
            .commit_with_blobs(ops, &blobs)
            .map_err(transport_error)?;
        match response {
            CommitResponse::Applied { seqs } => {
                if seqs.len() != batch.len() {
                    return Err(TransportError::Other("commit answer".into()));
                }
                for (o, seq) in batch.iter().zip(&seqs) {
                    if let (Some(seq), true) = (seq, o.change.data.is_some()) {
                        self.awaiting
                            .insert((o.change.kind.code(), o.change.id.0), *seq);
                    }
                }
                Ok(batch
                    .iter()
                    .zip(seqs)
                    .map(|(o, seq)| SendResult::Saved {
                        kind: o.change.kind,
                        id: o.change.id,
                        server_meta: seq.map(|s| s.to_be_bytes().to_vec()),
                    })
                    .collect())
            }
            CommitResponse::Conflict { current } => {
                let mut out = Vec::with_capacity(batch.len());
                for o in batch {
                    let found = current
                        .iter()
                        .find(|c| c.kind == o.change.kind.code() && c.id == o.change.id.0);
                    out.push(match found {
                        Some(c) => match &c.server {
                            Some(r) => match self.remote_change(r.clone())? {
                                Some(rc) => SendResult::Conflict(rc),
                                None => SendResult::Failed {
                                    kind: o.change.kind,
                                    id: o.change.id,
                                },
                            },
                            // The key was never written (or its tombstone
                            // purged): nothing to expect.
                            None => SendResult::Conflict(RemoteChange {
                                kind: o.change.kind,
                                id: o.change.id,
                                version: 0,
                                data: None,
                                server_meta: None,
                            }),
                        },
                        None => SendResult::Failed {
                            kind: o.change.kind,
                            id: o.change.id,
                        },
                    });
                }
                Ok(out)
            }
        }
    }

    fn unconfirmed(&mut self) -> Vec<(RecordKind, Id)> {
        std::mem::take(&mut self.lost)
            .into_iter()
            .filter_map(|(k, id)| Some((RecordKind::from_code(k).ok()?, Id(id))))
            .collect()
    }

    fn limits(&self) -> BatchLimits {
        BatchLimits {
            max_records: COMMIT_OPS_MAX,
            max_bytes: COMMIT_BODY_MAX - BODY_MARGIN,
        }
    }
}
