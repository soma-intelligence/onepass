//! The organisation mailbox (plan `org`) and `OrgStore`, its client.
//!
//! An organisation keeps its shared state in one ordinary account mailbox
//! created through an invite of plan `org`. Four record kinds live there:
//!
//! - 29, org lineage, one record per generation, write-once on the server;
//! - 30, org roster, one record per seq, write-once on the server;
//! - 31, owner keyset, one record per owner account, replaced in place;
//! - 32, join request, one record per account asking to join, replaced in
//!   place and deleted once handled.
//!
//! Every body is opaque bytes here: this crate never decodes one, and every
//! trust decision (signatures, chains, who may write what) belongs to the
//! layer above (plan B). The only parsing is the 16 byte account prefix of
//! a join request frame.
//!
//! Record ids, 16 bytes, the first 16 bytes of SHA-256 of:
//!
//! - lineage: `"onepass/org-record-id/v1" || org_id || [29] || u64_be(g)`;
//! - roster: `"onepass/org-record-id/v1" || org_id || [30] || u64_be(seq)`;
//! - owner keyset: `"onepass/org-keyset-id/v1" || org_id || account_id`;
//! - join request: `"onepass/org-join-id/v1" || org_id || account_id`.
//!
//! A join request record's body is the frame `account_id || bytes`: the id
//! is a hash, so the account travels in the body, and a frame is kept on
//! read only if `join_record_id(org_id, prefix)` is the id it was read at.
//!
//! Versions: a lineage record carries its generation, a roster its seq, a
//! keyset or join request the current version plus 1 (1 when absent).
//! Reads ignore them.

use std::collections::BTreeMap;
use std::fmt;

use aws_lc_rs::digest::{Context, SHA256};
use onepass_mailbox_proto::{
    Body, CommitOp, CommitResponse, ORG_INVITE_USES, Op, PAGE_MAX_RECORDS, ServerRecord,
    blob_sha256,
};

use crate::{ChangeFeed, MailboxApi, MailboxError, blobs};

/// The org lineage record: write-once on the server.
pub const ORG_LINEAGE_KIND: u8 = 29;
/// The org roster record: write-once on the server.
pub const ORG_ROSTER_KIND: u8 = 30;
/// The org key set record: mutable.
pub const ORG_KEYSET_KIND: u8 = 31;
/// The org join record: mutable.
pub const ORG_JOIN_KIND: u8 = 32;

/// Most lineage records one `lineage_from` call returns; the caller asks
/// again from the last generation plus 1.
pub const ORG_READ_MAX: usize = 1024;

/// A join request as `join_requests` lists it: the account, its bytes.
pub type JoinRequest = ([u8; 16], Vec<u8>);

/// Most pages `join_requests` reads before it calls the server hostile: the
/// plan `org` holds at most 200 000 records (`max_records`), so an honest
/// feed ends within that many records, `PAGE_MAX_RECORDS` a page, plus one.
pub const ORG_FEED_PAGES_MAX: usize = 200_000 / PAGE_MAX_RECORDS as usize + 1;

/// Attempts of a keyset or join request rewrite before `Contended`.
const REWRITE_ATTEMPTS: usize = 4;

const RECORD_ID_LABEL: &[u8] = b"onepass/org-record-id/v1";
const KEYSET_ID_LABEL: &[u8] = b"onepass/org-keyset-id/v1";
const JOIN_ID_LABEL: &[u8] = b"onepass/org-join-id/v1";

/// Kinds the server accepts one put of per key and never deletes (29, 30).
pub fn is_immutable_kind(kind: u8) -> bool {
    kind == ORG_LINEAGE_KIND || kind == ORG_ROSTER_KIND
}

fn derive_id(parts: &[&[u8]]) -> [u8; 16] {
    let mut ctx = Context::new(&SHA256);
    for p in parts {
        ctx.update(p);
    }
    let d = ctx.finish();
    let mut id = [0u8; 16];
    id.copy_from_slice(&d.as_ref()[..16]);
    id
}

/// The id of the lineage record of `generation`.
pub fn lineage_record_id(org_id: &[u8; 16], generation: u64) -> [u8; 16] {
    derive_id(&[
        RECORD_ID_LABEL,
        org_id,
        &[ORG_LINEAGE_KIND],
        &generation.to_be_bytes(),
    ])
}

/// The id of the roster record of `seq`.
pub fn roster_record_id(org_id: &[u8; 16], seq: u64) -> [u8; 16] {
    derive_id(&[
        RECORD_ID_LABEL,
        org_id,
        &[ORG_ROSTER_KIND],
        &seq.to_be_bytes(),
    ])
}

/// The id of the owner keyset record of `account_id`.
pub fn keyset_record_id(org_id: &[u8; 16], account_id: &[u8; 16]) -> [u8; 16] {
    derive_id(&[KEYSET_ID_LABEL, org_id, account_id])
}

/// The id of the join request record of `account_id`.
pub fn join_record_id(org_id: &[u8; 16], account_id: &[u8; 16]) -> [u8; 16] {
    derive_id(&[JOIN_ID_LABEL, org_id, account_id])
}

/// `Some((account_id, request))` when `body` is at least 16 bytes and its
/// prefix hashes to `record_id`; `None` otherwise. Never panics.
pub fn parse_join_frame<'a>(
    org_id: &[u8; 16],
    record_id: &[u8; 16],
    body: &'a [u8],
) -> Option<([u8; 16], &'a [u8])> {
    let (prefix, rest) = body.split_first_chunk::<16>()?;
    (join_record_id(org_id, prefix) == *record_id).then_some((*prefix, rest))
}

/// What an `OrgStore` call can end with, besides its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgStoreError {
    /// A write-once record (lineage or roster) already holds other bytes,
    /// or a tombstone: the first write stands.
    Taken,
    /// A keyset or join request rewrite lost the race to other writers
    /// `REWRITE_ATTEMPTS` (4) times in a row.
    Contended,
    /// The mailbox call failed.
    Mailbox(MailboxError),
}

impl fmt::Display for OrgStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Taken => f.write_str("org record already written with other bytes"),
            Self::Contended => f.write_str("org record rewritten by others meanwhile, gave up"),
            Self::Mailbox(e) => write!(f, "org mailbox: {e}"),
        }
    }
}

impl std::error::Error for OrgStoreError {}

impl From<MailboxError> for OrgStoreError {
    fn from(e: MailboxError) -> Self {
        Self::Mailbox(e)
    }
}

/// What an org store offers (plan C swaps `OrgStore` for the hostile one).
pub trait OrgStoreApi {
    fn put_lineage(&mut self, generation: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError>;
    fn lineage_from(&mut self, generation: u64) -> Result<Vec<(u64, Vec<u8>)>, OrgStoreError>;
    fn put_roster(&mut self, seq: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError>;
    fn roster(&mut self, seq: u64) -> Result<Option<Vec<u8>>, OrgStoreError>;
    fn latest_roster(&mut self) -> Result<Option<(u64, Vec<u8>)>, OrgStoreError>;
    fn put_owner_keyset(
        &mut self,
        account_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<(), OrgStoreError>;
    fn owner_keyset(&mut self, account_id: [u8; 16]) -> Result<Option<Vec<u8>>, OrgStoreError>;
    fn put_join_request(
        &mut self,
        account_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<(), OrgStoreError>;
    fn join_requests(&mut self) -> Result<Vec<JoinRequest>, OrgStoreError>;
    fn delete_join_request(&mut self, account_id: [u8; 16]) -> Result<(), OrgStoreError>;
}

/// The client of an organisation mailbox: reads and writes its records as
/// opaque bytes over any `MailboxApi` opened on that mailbox.
pub struct OrgStore<A: MailboxApi> {
    api: A,
    org_id: [u8; 16],
    /// The last roster seq `latest_roster` found (0: none yet).
    roster_hint: u64,
}

impl<A: MailboxApi> OrgStore<A> {
    pub fn new(api: A, org_id: [u8; 16]) -> Self {
        Self {
            api,
            org_id,
            roster_hint: 0,
        }
    }

    pub fn org_id(&self) -> [u8; 16] {
        self.org_id
    }

    pub fn api(&self) -> &A {
        &self.api
    }

    pub fn into_api(self) -> A {
        self.api
    }

    /// Writes the lineage record of `generation` once. The same bytes
    /// already there is `Ok`, other bytes (or a tombstone) `Taken`.
    pub fn put_lineage(&mut self, generation: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError> {
        let id = lineage_record_id(&self.org_id, generation);
        self.put_once(ORG_LINEAGE_KIND, id, generation, &bytes)
    }

    /// The lineage records from `generation` up, ascending, up to the first
    /// absent one, `ORG_READ_MAX` at most.
    pub fn lineage_from(&mut self, generation: u64) -> Result<Vec<(u64, Vec<u8>)>, OrgStoreError> {
        let mut out = Vec::new();
        let mut g = generation;
        while out.len() < ORG_READ_MAX {
            let id = lineage_record_id(&self.org_id, g);
            let Some(data) = self.read(ORG_LINEAGE_KIND, id)? else {
                break;
            };
            out.push((g, data));
            match g.checked_add(1) {
                Some(n) => g = n,
                None => break,
            }
        }
        Ok(out)
    }

    /// Writes the roster of `seq` once, as `put_lineage` does.
    pub fn put_roster(&mut self, seq: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError> {
        let id = roster_record_id(&self.org_id, seq);
        self.put_once(ORG_ROSTER_KIND, id, seq, &bytes)
    }

    /// The roster of `seq`, `None` when absent (or a tombstone).
    pub fn roster(&mut self, seq: u64) -> Result<Option<Vec<u8>>, OrgStoreError> {
        let id = roster_record_id(&self.org_id, seq);
        self.read(ORG_ROSTER_KIND, id)
    }

    /// The roster of the highest seq, assuming the present seqs form one
    /// range from 1 (or from 0 when 1 is absent).
    pub fn latest_roster(&mut self) -> Result<Option<(u64, Vec<u8>)>, OrgStoreError> {
        let org_id = self.org_id;
        let api = &self.api;
        let start = self.roster_hint.max(1);
        let present = |seq: u64| -> Result<bool, OrgStoreError> {
            let r = api.record(ORG_ROSTER_KIND, roster_record_id(&org_id, seq))?;
            Ok(r.is_some_and(|r| r.body.is_some()))
        };
        let Some(seq) = last_present(start, present)? else {
            self.roster_hint = 0;
            return Ok(None);
        };
        // Deleted in between (a hostile server): read as absent.
        let Some(data) = self.roster(seq)? else {
            self.roster_hint = 0;
            return Ok(None);
        };
        self.roster_hint = seq;
        Ok(Some((seq, data)))
    }

    /// Writes (or replaces) the owner keyset of `account_id`.
    pub fn put_owner_keyset(
        &mut self,
        account_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<(), OrgStoreError> {
        let id = keyset_record_id(&self.org_id, &account_id);
        self.rewrite(ORG_KEYSET_KIND, id, &bytes)
    }

    /// The owner keyset of `account_id`, `None` when absent.
    pub fn owner_keyset(&mut self, account_id: [u8; 16]) -> Result<Option<Vec<u8>>, OrgStoreError> {
        let id = keyset_record_id(&self.org_id, &account_id);
        self.read(ORG_KEYSET_KIND, id)
    }

    /// Writes (or replaces) the join request of `account_id`, stored as the
    /// frame `account_id || bytes`.
    pub fn put_join_request(
        &mut self,
        account_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<(), OrgStoreError> {
        let id = join_record_id(&self.org_id, &account_id);
        let mut frame = Vec::with_capacity(16 + bytes.len());
        frame.extend_from_slice(&account_id);
        frame.extend_from_slice(&bytes);
        self.rewrite(ORG_JOIN_KIND, id, &frame)
    }

    /// Every live join request, one per account, sorted by account id. A
    /// frame whose prefix does not hash to the id it sits at is dropped.
    pub fn join_requests(&mut self) -> Result<Vec<JoinRequest>, OrgStoreError> {
        let mut feed = ChangeFeed::full();
        let mut live: BTreeMap<[u8; 16], Body> = BTreeMap::new();
        let mut pages = 0usize;
        loop {
            pages += 1;
            if pages > ORG_FEED_PAGES_MAX {
                return Err(MailboxError::Malformed("org join feed never ends").into());
            }
            let page = self.api.next_changes(&mut feed, PAGE_MAX_RECORDS)?;
            for r in page.records.into_iter().filter(|r| r.kind == ORG_JOIN_KIND) {
                match r.body {
                    Some(b) => live.insert(r.id, b),
                    None => live.remove(&r.id),
                };
            }
            if !page.more {
                break;
            }
        }
        let mut out: BTreeMap<[u8; 16], Vec<u8>> = BTreeMap::new();
        for (id, body) in live {
            let data = self.api.fetch_body(&body)?;
            if let Some((account, request)) = parse_join_frame(&self.org_id, &id, &data) {
                out.insert(account, request.to_vec());
            }
        }
        Ok(out.into_iter().collect())
    }

    /// Deletes the join request of `account_id`; nothing to delete is `Ok`.
    pub fn delete_join_request(&mut self, account_id: [u8; 16]) -> Result<(), OrgStoreError> {
        let id = join_record_id(&self.org_id, &account_id);
        let op = CommitOp {
            kind: ORG_JOIN_KIND,
            id,
            version: 0,
            op: Op::Delete,
        };
        match self.api.commit(vec![op])? {
            CommitResponse::Applied { .. } => Ok(()),
            CommitResponse::Conflict { .. } => {
                Err(MailboxError::Malformed("org delete answered with a conflict").into())
            }
        }
    }

    /// Mints a one-use invite of plan `managed` for a member's own account
    /// mailbox on this organisation's server, valid `ttl_hours` (1 to 168).
    /// Needs a manager credential on the org mailbox. Returns the 32 byte
    /// token to hand to the member's device, which spends it with
    /// `MailboxApi::create`.
    pub fn create_member_invite(&mut self, ttl_hours: u16) -> Result<Vec<u8>, OrgStoreError> {
        Ok(self.api.create_org_invite(ORG_INVITE_USES, ttl_hours)?)
    }

    /// The bytes of `(kind, id)`, `None` when absent or a tombstone.
    fn read(&self, kind: u8, id: [u8; 16]) -> Result<Option<Vec<u8>>, OrgStoreError> {
        match self.api.record(kind, id)? {
            Some(ServerRecord {
                body: Some(body), ..
            }) => Ok(Some(self.api.fetch_body(&body)?)),
            _ => Ok(None),
        }
    }

    /// One commit of a put, through Storage when the body is a blob.
    fn commit_put(
        &self,
        kind: u8,
        id: [u8; 16],
        version: u64,
        expected: Option<u64>,
        body: Body,
        data: &[u8],
    ) -> Result<CommitResponse, MailboxError> {
        let blob = matches!(body, Body::Blob { .. });
        let ops = vec![CommitOp {
            kind,
            id,
            version,
            op: Op::Put { expected, body },
        }];
        if blob {
            self.api.commit_with_blobs(ops, &[data])
        } else {
            self.api.commit(ops)
        }
    }

    /// A write-once put (kinds 29, 30).
    fn put_once(
        &self,
        kind: u8,
        id: [u8; 16],
        version: u64,
        data: &[u8],
    ) -> Result<(), OrgStoreError> {
        let body = blobs::body_for(data)?;
        if matches!(body, Body::Blob { .. })
            && let Some(r) = self.api.record(kind, id)?
        {
            // Already written: no upload, the answer is the comparison.
            return same_or_taken(r.body.as_ref(), data);
        }
        match self.commit_put(kind, id, version, None, body, data)? {
            CommitResponse::Applied { .. } => Ok(()),
            CommitResponse::Conflict { current } => {
                let row = current
                    .into_iter()
                    .find(|e| e.kind == kind && e.id == id)
                    .and_then(|e| e.server)
                    .ok_or(MailboxError::Malformed("org conflict without a row"))?;
                same_or_taken(row.body.as_ref(), data)
            }
        }
    }

    /// A put that replaces whatever is there (kinds 31, 32), retried on a
    /// conflict.
    fn rewrite(&self, kind: u8, id: [u8; 16], data: &[u8]) -> Result<(), OrgStoreError> {
        let body = blobs::body_for(data)?;
        for _ in 0..REWRITE_ATTEMPTS {
            let (expected, version) = match self.api.record(kind, id)? {
                None => (None, 1),
                Some(r) => {
                    let version = r
                        .version
                        .checked_add(1)
                        .ok_or(MailboxError::Malformed("org record version"))?;
                    (r.body.is_some().then_some(r.seq), version)
                }
            };
            match self.commit_put(kind, id, version, expected, body.clone(), data)? {
                CommitResponse::Applied { .. } => return Ok(()),
                CommitResponse::Conflict { .. } => continue,
            }
        }
        Err(OrgStoreError::Contended)
    }
}

impl<A: MailboxApi> OrgStoreApi for OrgStore<A> {
    fn put_lineage(&mut self, generation: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError> {
        OrgStore::put_lineage(self, generation, bytes)
    }

    fn lineage_from(&mut self, generation: u64) -> Result<Vec<(u64, Vec<u8>)>, OrgStoreError> {
        OrgStore::lineage_from(self, generation)
    }

    fn put_roster(&mut self, seq: u64, bytes: Vec<u8>) -> Result<(), OrgStoreError> {
        OrgStore::put_roster(self, seq, bytes)
    }

    fn roster(&mut self, seq: u64) -> Result<Option<Vec<u8>>, OrgStoreError> {
        OrgStore::roster(self, seq)
    }

    fn latest_roster(&mut self) -> Result<Option<(u64, Vec<u8>)>, OrgStoreError> {
        OrgStore::latest_roster(self)
    }

    fn put_owner_keyset(
        &mut self,
        account_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<(), OrgStoreError> {
        OrgStore::put_owner_keyset(self, account_id, bytes)
    }

    fn owner_keyset(&mut self, account_id: [u8; 16]) -> Result<Option<Vec<u8>>, OrgStoreError> {
        OrgStore::owner_keyset(self, account_id)
    }

    fn put_join_request(
        &mut self,
        account_id: [u8; 16],
        bytes: Vec<u8>,
    ) -> Result<(), OrgStoreError> {
        OrgStore::put_join_request(self, account_id, bytes)
    }

    fn join_requests(&mut self) -> Result<Vec<JoinRequest>, OrgStoreError> {
        OrgStore::join_requests(self)
    }

    fn delete_join_request(&mut self, account_id: [u8; 16]) -> Result<(), OrgStoreError> {
        OrgStore::delete_join_request(self, account_id)
    }
}

/// A write-once record the server already holds: `Ok` when its body is
/// ours (the same inline bytes, or the blob of our bytes), `Taken` for
/// anything else, a tombstone included.
fn same_or_taken(server: Option<&Body>, data: &[u8]) -> Result<(), OrgStoreError> {
    let same = match server {
        Some(Body::Inline(d)) => d.as_slice() == data,
        Some(Body::Blob { sha256, size }) => {
            *size as usize == data.len() && *sha256 == blob_sha256(data)
        }
        None => false,
    };
    if same {
        Ok(())
    } else {
        Err(OrgStoreError::Taken)
    }
}

/// The last present seq of the range `present` describes, read from
/// `start` (a hint), else from seq 1, else from seq 0; `None` when none of
/// them is present. Gallops up by doubling steps until a seq is absent (or
/// `u64::MAX` is reached), then binary searches between the last present
/// and the first absent seq: at most 130 calls of `present`.
fn last_present(
    start: u64,
    mut present: impl FnMut(u64) -> Result<bool, OrgStoreError>,
) -> Result<Option<u64>, OrgStoreError> {
    let mut lo = if present(start)? {
        start
    } else if start != 1 && present(1)? {
        1
    } else if start != 0 && present(0)? {
        0
    } else {
        return Ok(None);
    };
    let mut step = 1u64;
    let mut hi = loop {
        if lo == u64::MAX {
            return Ok(Some(lo));
        }
        let next = lo.saturating_add(step);
        if !present(next)? {
            break next;
        }
        lo = next;
        step = step.saturating_mul(2);
    };
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if present(mid)? {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Ok(Some(lo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use onepass_mailbox_proto::hex;

    #[test]
    fn record_ids_match_the_contract() {
        let org = [0x11; 16];
        let acc = [0x22; 16];
        assert_eq!(
            hex(&lineage_record_id(&org, 0)),
            "dc8ef7b81796c6a9c03d59b26c55a713"
        );
        assert_eq!(
            hex(&lineage_record_id(&org, 1)),
            "e453a14a433838dc656e5043ef0aad44"
        );
        assert_eq!(
            hex(&roster_record_id(&org, 1)),
            "7cdc97985555472b0db4428735239693"
        );
        assert_eq!(
            hex(&keyset_record_id(&org, &acc)),
            "e745734b9b9922bcb895dd678df31466"
        );
        assert_eq!(
            hex(&join_record_id(&org, &acc)),
            "eb9b09e595ba20f2c05f75920fe4db4a"
        );
    }

    #[test]
    fn join_frame_round_trip() {
        let org = [0x11; 16];
        let acc = [0x22; 16];
        let mut body = acc.to_vec();
        body.extend_from_slice(b"req");
        let id = join_record_id(&org, &acc);
        assert_eq!(parse_join_frame(&org, &id, &body), Some((acc, &b"req"[..])));
    }

    #[test]
    fn join_frame_refuses_short_and_wrong_id() {
        let org = [0x11; 16];
        let acc = [0x22; 16];
        let id = join_record_id(&org, &acc);
        for n in 0..16 {
            assert_eq!(parse_join_frame(&org, &id, &acc[..n]), None, "length {n}");
        }
        let mut body = acc.to_vec();
        body.extend_from_slice(b"req");
        assert_eq!(
            parse_join_frame(&org, &roster_record_id(&org, 1), &body),
            None
        );
        assert_eq!(parse_join_frame(&org, &id, &acc), Some((acc, &b""[..])));
    }

    fn ok(f: impl Fn(u64) -> bool) -> impl FnMut(u64) -> Result<bool, OrgStoreError> {
        move |s| Ok(f(s))
    }

    #[test]
    fn last_present_finds_the_end_of_a_range() {
        assert_eq!(last_present(1, ok(|s| s <= 37)), Ok(Some(37)));
        assert_eq!(last_present(1, ok(|_| false)), Ok(None));
        assert_eq!(last_present(1, ok(|s| s == 0)), Ok(Some(0)));
        // A hint inside the range, and a hint past its end.
        assert_eq!(last_present(20, ok(|s| s <= 37)), Ok(Some(37)));
        assert_eq!(last_present(50, ok(|s| s <= 37)), Ok(Some(37)));
        assert_eq!(last_present(50, ok(|s| s == 0)), Ok(Some(0)));
    }

    #[test]
    fn last_present_is_bounded_when_everything_exists() {
        let mut calls = 0u32;
        let r = last_present(1, |_| {
            calls += 1;
            Ok(true)
        });
        assert_eq!(r, Ok(Some(u64::MAX)));
        assert!(calls <= 130, "{calls} calls");
        // A range that ends just below the top takes the binary search.
        let mut calls = 0u32;
        let r = last_present(1, |s| {
            calls += 1;
            Ok(s < u64::MAX - 3)
        });
        assert_eq!(r, Ok(Some(u64::MAX - 4)));
        assert!(calls <= 130, "{calls} calls");
    }

    #[test]
    fn last_present_passes_errors_on() {
        let r = last_present(1, |_| Err(OrgStoreError::Mailbox(MailboxError::Offline)));
        assert_eq!(r, Err(OrgStoreError::Mailbox(MailboxError::Offline)));
    }
}
