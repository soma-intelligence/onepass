//! `FakeMailbox`: the mailbox server in memory, for tests of the sync
//! engine and the pairing transports.
//!
//! It follows the SQL of `mailbox/supabase/migrations/` and the edge
//! function, not a simplified reading of the spec: conditional writes on
//! `expected`, unconditional idempotent deletes, tombstones that cost 1
//! record and 128 bytes until purged, one seq per writing operation and
//! none for a refused batch, a conflict reply capped at 1 000 rows and
//! 4 MiB, pages bounded by their `head`, a full fetch that skips tombstones
//! and ignores `min_cursor`, `min_cursor` = highest purged seq, growth-only
//! quotas, enroll tickets checked and used once, blobs announced under an
//! upload generation and committed only while that generation's object is
//! in Storage, credential roles (a reader commits and uploads nothing, a
//! writer limited to `put_kinds` puts only those kinds and deletes nothing,
//! only a manager grants, changes roles, approves tickets and revokes
//! another credential, an owner is revoked only by itself and never
//! demoted, a limited writer announces no blob, the last manager stays),
//! locators (set by a manager, the two latest kept per mailbox, shared
//! freely between mailboxes, looked up without a key: up to 8 live
//! mailboxes, oldest registration first) and abandoning a mailbox (its
//! creator, still a manager, within 24 hours, while no other credential has
//! made a request or enrolled, at most one other exists and no child
//! lives; then every request on it is `not_found`, its locators gone), and
//! child mailboxes (created by a manager of an account mailbox for a fresh
//! owner key, the owner a manager and owner, plan `shared` or `contact` of
//! `seed.sql` whatever the parent's, no grandchild, live children of each
//! kind capped by the parent's plan, no enroll ticket, deleted by their
//! owner at any time).
//!
//! `FakeMailboxClient` runs the real client's request building and answer
//! checks (`crate::client`, `crate::blobs`), and every answer goes through
//! the strict proto codec: a test against the model checks what the real
//! client checks. The conformance suite runs the same cases here and
//! against a local Supabase stack.
//!
//! The rendezvous routes follow `rdv_put`, `rdv_get` and `rdv_close`:
//! chunks of at most 1 MiB written once (`409` again), `n` 0 to 4095 and
//! direction 0 or 1 (`no_route` otherwise, as the router answers), 66 MiB
//! per direction, a chunk readable 120 s after its write and rewritable
//! once purged, a session closed 600 s after its first chunk or by
//! `DELETE` (`not_found` from then on, its id never usable again), and a
//! read that waits up to `wait` seconds for its chunk.
//!
//! Not modelled: signatures, nonces and clock skew of requests (the fake
//! knows who calls), rate limits (`req_per_min` is reported, never
//! enforced; the 20 children a day per parent neither), per-IP limits (the minute bucket of the rendezvous and its
//! 200 MiB an hour included), frozen mailboxes, wake-ups and push.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use onepass_mailbox_proto::{
    BlobUrls, Body, COMMIT_BODY_MAX, COMMIT_OPS_MAX, ChangesPage, ChildKind, CommitOp,
    CommitResponse, ConflictEntry, CredentialId, CredentialRole, ErrorCode, INLINE_MAX,
    LOCATED_MAX, Limits, Located, MailboxCreated, MailboxId, MailboxInfo, Message, Op,
    PAGE_MAX_BYTES, PAGE_MAX_RECORDS, PushKind, RECORD_MAX, ServerConfig, ServerRecord, SetLocator,
    Sha256, SignedEnrollTicket, Usage, credential_id, decode, encode, hex, put_kinds_allow,
    ticket_hash, ticket_signed_bytes,
};

use crate::blobs::{BodyRef, blob_of, blob_set, check_answers, check_blob};
use crate::client::{
    check_changes_query, check_commit, check_page, check_record, child_request, commit_request,
    create_refusal, enroll_request, error_of, grant_request, issue_ticket, local, push_request,
    role_request,
};
use crate::drops::{
    DROP_LIFE_SECS, DROP_SLOTS, check_put as check_drop_put, check_slot as check_drop_slot,
};
use crate::rendezvous::{
    RDV_CHUNK_MAX, RDV_FRAMES_MAX, RDV_SESSION_BYTES_MAX, RdvRole, RdvTransport, Rendezvous,
};
use crate::{Credential, CredentialKey, MailboxApi, MailboxError};

/// Base URL of every fake mailbox: what its tickets name.
pub const FAKE_BASE_URL: &str = "https://mailbox.fake.invalid/functions/v1/mailbox";
/// Where the fake's signed Storage URLs point (never fetched).
const FAKE_STORAGE: &str = "https://storage.fake.invalid/object/";

/// Quota cost of a tombstone, bytes (`TOMBSTONE_COST` of the commit SQL).
const TOMBSTONE_COST: i64 = 128;
/// Smallest blob body: anything at most `INLINE_MAX` goes inline.
const BLOB_MIN: u32 = INLINE_MAX as u32 + 1;
/// The edge function's estimate of a record's encoded size beyond its data.
const RECORD_OVERHEAD: usize = 96;

/// Plan `selfhost` of `seed.sql`: what open signup gives.
fn selfhost() -> Limits {
    Limits {
        max_bytes: 1 << 40,
        max_records: 10_000_000,
        max_credentials: 256,
        req_per_min: 6000,
        max_commit_ops: 20_000,
    }
}

/// Plan `shared` of `seed.sql`: a child for a shared vault or a family.
fn shared() -> Limits {
    Limits {
        max_bytes: 128 << 20,
        max_records: 100_000,
        max_credentials: 80,
        req_per_min: 600,
        max_commit_ops: 20_000,
    }
}

/// Plan `contact` of `seed.sql`: the child of a pair of contacts.
fn contact() -> Limits {
    Limits {
        max_bytes: 16 << 20,
        max_records: 2_000,
        max_credentials: 4,
        req_per_min: 120,
        max_commit_ops: 2_000,
    }
}

/// Live children of each kind (shared, contact) an account mailbox holds:
/// plan `selfhost` of `seed.sql`, whatever limits the fake was given.
const MAX_CHILDREN: (usize, usize) = (1024, 4096);

/// Push targets a credential holds at most (`api_set_push_target`).
const PUSH_TARGETS_MAX: usize = 8;

/// `mailboxes.kind` of an account mailbox (2 shared, 3 contact).
const ACCOUNT: u8 = 1;

type Key = (u8, [u8; 16]);

#[derive(Debug, Clone)]
struct Row {
    seq: u64,
    version: u64,
    /// `None`: a tombstone.
    body: Option<Body>,
}

impl Row {
    /// Quota bytes of the row: its size, or `TOMBSTONE_COST`.
    fn cost(&self) -> i64 {
        match &self.body {
            None => TOMBSTONE_COST,
            Some(b) => body_size(b),
        }
    }

    fn server(&self, key: Key) -> ServerRecord {
        ServerRecord {
            seq: self.seq,
            kind: key.0,
            id: key.1,
            version: self.version,
            body: self.body.clone(),
        }
    }
}

fn body_size(b: &Body) -> i64 {
    match b {
        Body::Inline(d) => d.len() as i64,
        Body::Blob { size, .. } => i64::from(*size),
    }
}

fn inline_len(b: &Option<Body>) -> usize {
    match b {
        Some(Body::Inline(d)) => d.len(),
        _ => 0,
    }
}

#[derive(Debug, Clone)]
struct Blob {
    size: u32,
    refs: u32,
    generation: u64,
}

#[derive(Debug)]
struct Mbx {
    incarnation: u64,
    wake_topic: [u8; 16],
    next_seq: u64,
    min_cursor: u64,
    bytes_used: i64,
    records_count: i64,
    records: BTreeMap<Key, Row>,
    blobs: BTreeMap<Sha256, Blob>,
    /// The creator credential: the only one that may abandon it.
    created_by: Option<CredentialId>,
    /// Unix seconds.
    created_at: i64,
    /// Abandoned: every request on it is `not_found`.
    deleted: bool,
    /// Its plan.
    limits: Limits,
    /// 1 account, 2 shared, 3 contact (`mailboxes.kind`).
    kind: u8,
    /// The account mailbox a child was created under.
    parent: Option<MailboxId>,
}

impl Mbx {
    fn new(limits: Limits) -> Mbx {
        Mbx {
            limits,
            kind: ACCOUNT,
            parent: None,
            created_by: None,
            created_at: unix_now(),
            deleted: false,
            incarnation: random_incarnation(),
            wake_topic: random16(),
            next_seq: 1,
            min_cursor: 0,
            bytes_used: 0,
            records_count: 0,
            records: BTreeMap::new(),
            blobs: BTreeMap::new(),
        }
    }

    fn by_seq(&self) -> Vec<(Key, &Row)> {
        let mut rows: Vec<(Key, &Row)> = self.records.iter().map(|(k, r)| (*k, r)).collect();
        rows.sort_by_key(|(_, r)| r.seq);
        rows
    }
}

#[derive(Debug)]
struct Cred {
    mailbox: MailboxId,
    key: [u8; 32],
    revoked: bool,
    push: Option<(PushKind, Vec<u8>)>,
    /// Per-device push targets by tag (`push_targets`), 8 at most.
    targets: HashMap<[u8; 16], (PushKind, Vec<u8>)>,
    role: CredentialRole,
    /// Write role only: the kinds it may put; no delete when set.
    put_kinds: Option<[u8; 32]>,
    /// Revoked only by itself, never demoted (Task 24 sets it).
    owner: bool,
    /// Has authenticated a request (`first_used_at` in SQL).
    used: bool,
    /// Came in by an enroll ticket (`enrolled_by` in SQL).
    enrolled: bool,
}

impl Cred {
    /// What a creation, an enroll or a row from before roles holds.
    fn manager(mailbox: MailboxId, key: [u8; 32]) -> Cred {
        Cred {
            mailbox,
            key,
            revoked: false,
            push: None,
            targets: HashMap::new(),
            role: CredentialRole::Manage,
            put_kinds: None,
            owner: false,
            used: false,
            enrolled: false,
        }
    }
}

#[derive(Debug)]
struct State {
    limits: Limits,
    mailboxes: HashMap<MailboxId, Mbx>,
    /// Credential ids are unique across mailboxes (primary key in SQL).
    credentials: HashMap<CredentialId, Cred>,
    used_tickets: HashSet<Sha256>,
    /// (locator, mailbox) in registration order; at most 2 per mailbox.
    locators: Vec<([u8; 16], MailboxId)>,
    /// Storage: object name to bytes.
    objects: HashMap<String, Vec<u8>>,
    next_gen: u64,
    fail_next: VecDeque<MailboxError>,
    collect_before_commit: bool,
}

fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    aws_lc_rs::rand::fill(&mut b).expect("system random source");
    b
}

fn random_incarnation() -> u64 {
    let mut b = [0u8; 8];
    aws_lc_rs::rand::fill(&mut b).expect("system random source");
    // A Postgres bigint, as the SQL draws it.
    u64::from_be_bytes(b) & (i64::MAX as u64)
}

fn object_name(m: &MailboxId, sha: &Sha256, generation: u64) -> String {
    format!("{}/{}.{generation}", hex(m), hex(sha))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The strict codec on the way back, as the real client reads answers.
fn wire<M: Message>(m: &M) -> Result<M, MailboxError> {
    decode(&encode(m)).map_err(|_| MailboxError::Malformed("response"))
}

fn refused<T>(code: ErrorCode) -> Result<T, MailboxError> {
    Err(error_of(code, None))
}

impl State {
    /// The checks of `credential_key` and `_authenticate`, in their order.
    fn authenticate(&self, credential: &CredentialId, m: &MailboxId) -> Result<(), MailboxError> {
        let Some(c) = self.credentials.get(credential).filter(|c| c.mailbox == *m) else {
            return refused(ErrorCode::UnknownCredential);
        };
        if !self.mailboxes.contains_key(m) {
            return refused(ErrorCode::UnknownCredential);
        }
        if c.revoked {
            return refused(ErrorCode::RevokedCredential);
        }
        if self.mailboxes[m].deleted {
            return refused(ErrorCode::NotFound);
        }
        Ok(())
    }

    /// The authenticated caller's row.
    fn caller(&self, credential: &CredentialId) -> &Cred {
        self.credentials
            .get(credential)
            .expect("authenticated credential")
    }

    /// Active managers of `m` other than `except`.
    fn other_managers(&self, m: &MailboxId, except: &CredentialId) -> usize {
        self.credentials
            .iter()
            .filter(|(id, c)| {
                c.mailbox == *m && !c.revoked && c.role == CredentialRole::Manage && *id != except
            })
            .count()
    }

    /// `api_revoke_credential`, in its order.
    fn revoke(
        &mut self,
        caller: &CredentialId,
        m: &MailboxId,
        target: &CredentialId,
    ) -> Result<(), MailboxError> {
        if self.caller(caller).role != CredentialRole::Manage && target != caller {
            return refused(ErrorCode::Forbidden);
        }
        let Some(t) = self.credentials.get(target).filter(|c| c.mailbox == *m) else {
            return refused(ErrorCode::NotFound);
        };
        if t.revoked {
            return Ok(());
        }
        // In a child the owner stays until deletion, even against itself.
        if (t.owner && (target != caller || self.mailboxes[m].kind != ACCOUNT))
            || (t.role == CredentialRole::Manage && self.other_managers(m, target) == 0)
        {
            return refused(ErrorCode::Forbidden);
        }
        let t = self.credentials.get_mut(target).expect("found");
        t.revoked = true;
        t.push = None;
        t.targets.clear();
        Ok(())
    }

    /// `api_grant_credential` after the shapes (the client checked them).
    fn grant(
        &mut self,
        caller: &CredentialId,
        m: &MailboxId,
        key: [u8; 32],
        role: CredentialRole,
        put_kinds: Option<[u8; 32]>,
    ) -> Result<(), MailboxError> {
        if self.caller(caller).role != CredentialRole::Manage {
            return refused(ErrorCode::Forbidden);
        }
        if self.active_credentials(m) >= usize::from(self.mailboxes[m].limits.max_credentials) {
            return refused(ErrorCode::Quota);
        }
        let id = credential_id(&key);
        if self.credentials.contains_key(&id) {
            // In some mailbox, this one included, even revoked.
            return refused(ErrorCode::Malformed);
        }
        self.credentials.insert(
            id,
            Cred {
                role,
                put_kinds,
                ..Cred::manager(*m, key)
            },
        );
        Ok(())
    }

    /// `api_set_credential_role` after the shapes.
    fn set_role(
        &mut self,
        caller: &CredentialId,
        m: &MailboxId,
        target: &CredentialId,
        role: CredentialRole,
        put_kinds: Option<[u8; 32]>,
    ) -> Result<(), MailboxError> {
        if self.caller(caller).role != CredentialRole::Manage {
            return refused(ErrorCode::Forbidden);
        }
        let Some(t) = self
            .credentials
            .get(target)
            .filter(|c| c.mailbox == *m && !c.revoked)
        else {
            return refused(ErrorCode::NotFound);
        };
        let manage = CredentialRole::Manage;
        if (t.owner && role != manage)
            || (t.role == manage && role != manage && self.other_managers(m, target) == 0)
        {
            return refused(ErrorCode::Forbidden);
        }
        let t = self.credentials.get_mut(target).expect("found");
        t.role = role;
        t.put_kinds = put_kinds;
        Ok(())
    }

    /// Live children of `parent`, of `kind` (any when `None`).
    fn live_children(&self, parent: &MailboxId, kind: Option<u8>) -> usize {
        self.mailboxes
            .values()
            .filter(|x| x.parent == Some(*parent) && !x.deleted && kind.is_none_or(|k| x.kind == k))
            .count()
    }

    fn active_credentials(&self, m: &MailboxId) -> usize {
        self.credentials
            .values()
            .filter(|c| c.mailbox == *m && !c.revoked)
            .count()
    }

    /// The maintenance purge, for the tombstones of `only` (or every
    /// mailbox) whose seq is below `before`.
    fn purge(&mut self, only: Option<MailboxId>, before: u64) {
        for (id, mbx) in &mut self.mailboxes {
            if only.is_some_and(|o| o != *id) {
                continue;
            }
            let victims: Vec<(Key, u64)> = mbx
                .records
                .iter()
                .filter(|(_, r)| r.body.is_none() && r.seq < before)
                .map(|(k, r)| (*k, r.seq))
                .collect();
            for (k, seq) in &victims {
                mbx.records.remove(k);
                mbx.records_count -= 1;
                mbx.bytes_used -= TOMBSTONE_COST;
                mbx.min_cursor = mbx.min_cursor.max(*seq);
            }
        }
    }

    /// Maintenance and `mailbox-gc` at once: every unreferenced blob is
    /// collected and its object deleted (the real server waits 24 hours).
    fn collect(&mut self) -> usize {
        let mut gone = Vec::new();
        for (m, mbx) in &mut self.mailboxes {
            let orphans: Vec<Sha256> = mbx
                .blobs
                .iter()
                .filter(|(_, b)| b.refs == 0)
                .map(|(s, _)| *s)
                .collect();
            for s in orphans {
                let b = mbx.blobs.remove(&s).expect("listed");
                gone.push(object_name(m, &s, b.generation));
            }
        }
        for name in &gone {
            self.objects.remove(name);
        }
        gone.len()
    }

    fn commit(
        &mut self,
        caller: &CredentialId,
        m: &MailboxId,
        ops: &[CommitOp],
    ) -> Result<(CommitResponse, u16), MailboxError> {
        let (role, put_kinds) = {
            let c = self.caller(caller);
            (c.role, c.put_kinds)
        };
        if role == CredentialRole::Read {
            return refused(ErrorCode::Forbidden);
        }
        let limits = self.mailboxes[m].limits.clone();
        let objects = &self.objects;
        let mbx = self.mailboxes.get_mut(m).expect("authenticated mailbox");

        // Shapes the edge and SQL check (the client already refused most).
        let carried: usize = ops
            .iter()
            .map(|o| {
                16 + match &o.op {
                    Op::Put {
                        body: Body::Inline(d),
                        ..
                    } => d.len(),
                    Op::Put {
                        body: Body::Blob { .. },
                        ..
                    } => 32,
                    Op::Delete => 0,
                }
            })
            .sum();
        if carried > COMMIT_BODY_MAX || ops.len() > COMMIT_OPS_MAX {
            return refused(ErrorCode::TooLarge);
        }
        if let Some(set) = put_kinds
            && ops
                .iter()
                .any(|o| matches!(o.op, Op::Delete) || !put_kinds_allow(&set, o.kind))
        {
            return refused(ErrorCode::Forbidden);
        }
        if ops.len() > limits.max_commit_ops as usize {
            return refused(ErrorCode::TooLarge);
        }

        // Blob bodies: announced, the current generation's object in
        // Storage with that size, a referenced blob keeps its size.
        for o in ops {
            if let Op::Put {
                body: Body::Blob { sha256, size },
                ..
            } = &o.op
            {
                let ok = (BLOB_MIN..=RECORD_MAX as u32).contains(size)
                    && mbx.blobs.get(sha256).is_some_and(|b| {
                        !(b.refs > 0 && b.size != *size)
                            && objects
                                .get(&object_name(m, sha256, b.generation))
                                .is_some_and(|d| d.len() == *size as usize)
                    });
                if !ok {
                    return refused(ErrorCode::Malformed);
                }
            }
        }

        // Conflicts: a prefix, 1 000 rows and 4 MiB of data at most, the
        // first one always.
        let mut current = Vec::new();
        let mut acc = 0usize;
        for o in ops {
            let Op::Put { expected, .. } = &o.op else {
                continue;
            };
            let key = (o.kind, o.id);
            let cur = mbx.records.get(&key);
            let live = cur.is_some_and(|r| r.body.is_some());
            let conflicts = match expected {
                None => live,
                Some(e) => !live || cur.is_some_and(|r| r.seq != *e),
            };
            if !conflicts {
                continue;
            }
            acc += cur.map_or(0, |r| inline_len(&r.body));
            let n = current.len() + 1;
            if n == 1 || (n <= PAGE_MAX_RECORDS as usize && acc <= PAGE_MAX_BYTES) {
                current.push(ConflictEntry {
                    kind: o.kind,
                    id: o.id,
                    server: cur.map(|r| r.server(key)),
                });
            }
        }
        if !current.is_empty() {
            return Ok((CommitResponse::Conflict { current }, 409));
        }

        // The plan: which operations write, what the counters gain.
        let mut dbytes = 0i64;
        let mut drecords = 0i64;
        let mut writes = Vec::with_capacity(ops.len());
        for o in ops {
            let cur = mbx.records.get(&(o.kind, o.id));
            let live = cur.is_some_and(|r| r.body.is_some());
            let w = match &o.op {
                Op::Put { .. } => true,
                Op::Delete => live,
            };
            if w {
                let new_cost = match &o.op {
                    Op::Put { body, .. } => body_size(body),
                    Op::Delete => TOMBSTONE_COST,
                };
                dbytes += new_cost - cur.map_or(0, Row::cost);
                if cur.is_none() {
                    drecords += 1;
                }
            }
            writes.push(w);
        }
        let deletes_only = ops.iter().all(|o| matches!(o.op, Op::Delete));
        if !deletes_only
            && ((dbytes > 0 && mbx.bytes_used + dbytes > limits.max_bytes as i64)
                || (drecords > 0 && mbx.records_count + drecords > i64::from(limits.max_records)))
        {
            return refused(ErrorCode::Quota);
        }

        let mut seqs = Vec::with_capacity(ops.len());
        for (o, w) in ops.iter().zip(writes) {
            if !w {
                seqs.push(None);
                continue;
            }
            let seq = mbx.next_seq;
            mbx.next_seq += 1;
            let key = (o.kind, o.id);
            let body = match &o.op {
                Op::Put { body, .. } => Some(body.clone()),
                Op::Delete => None,
            };
            if let Some(Body::Blob { sha256, .. }) = &body {
                mbx.blobs.get_mut(sha256).expect("checked").refs += 1;
            }
            let old = mbx.records.insert(
                key,
                Row {
                    seq,
                    version: o.version,
                    body,
                },
            );
            if let Some(Row {
                body: Some(Body::Blob { sha256, .. }),
                ..
            }) = old
            {
                let b = mbx.blobs.get_mut(&sha256).expect("a referenced blob");
                b.refs -= 1;
            }
            seqs.push(Some(seq));
        }
        mbx.bytes_used += dbytes;
        mbx.records_count += drecords;
        Ok((CommitResponse::Applied { seqs }, 200))
    }

    fn changes(
        &self,
        m: &MailboxId,
        after: u64,
        limit: u32,
        full: bool,
    ) -> Result<ChangesPage, MailboxError> {
        let mbx = &self.mailboxes[m];
        if !full && after < mbx.min_cursor {
            return refused(ErrorCode::CursorExpired);
        }
        let head = mbx.next_seq - 1;
        let mut records = Vec::new();
        // The edge function's size estimate (stricter than the SQL's 4 MiB
        // of inline data).
        let mut size = 64usize;
        for (key, row) in mbx.by_seq() {
            if row.seq <= after || (full && row.body.is_none()) {
                continue;
            }
            if records.len() == limit as usize || row.seq > head {
                break;
            }
            size += RECORD_OVERHEAD + inline_len(&row.body);
            if size > PAGE_MAX_BYTES {
                break;
            }
            records.push(row.server(key));
        }
        let last = records.last().map(|r: &ServerRecord| r.seq);
        Ok(ChangesPage {
            incarnation: mbx.incarnation,
            min_cursor: mbx.min_cursor,
            head,
            next_after: last.unwrap_or(after),
            more: last.is_some_and(|l| l < head),
            records,
        })
    }

    fn enroll(
        &mut self,
        new_key: CredentialKey,
        ticket: &SignedEnrollTicket,
    ) -> Result<(), MailboxError> {
        let t = &ticket.ticket;
        let m = t.mailbox_id;
        let now = unix_now();
        // Edge: a representable deadline, the approver looked up in the
        // path mailbox, the ticket signature.
        if t.expires_at < 0 || t.expires_at > now + 86_400 {
            return refused(ErrorCode::Malformed);
        }
        let Some(approver) = self
            .credentials
            .get(&ticket.approver_credential)
            .filter(|c| c.mailbox == m)
        else {
            return refused(ErrorCode::UnknownCredential);
        };
        if UnparsedPublicKey::new(&ED25519, approver.key)
            .verify(&ticket_signed_bytes(t), &ticket.sig)
            .is_err()
        {
            return refused(ErrorCode::BadSignature);
        }
        // SQL, in its order.
        if t.expires_at > now + 900 {
            return refused(ErrorCode::Malformed);
        }
        if self.mailboxes.get(&m).is_none_or(|x| x.deleted) {
            return refused(ErrorCode::NotFound);
        }
        if approver.revoked {
            return refused(ErrorCode::RevokedCredential);
        }
        if approver.role != CredentialRole::Manage {
            return refused(ErrorCode::Forbidden);
        }
        if self.mailboxes[&m].kind != ACCOUNT {
            // A child takes members through grants only.
            return refused(ErrorCode::Forbidden);
        }
        if t.expires_at < now {
            return refused(ErrorCode::StaleRequest);
        }
        let id = new_key.id();
        if self.credentials.get(&id).is_some_and(|c| c.mailbox == m) {
            return refused(ErrorCode::Replay);
        }
        if self.active_credentials(&m) >= usize::from(self.mailboxes[&m].limits.max_credentials) {
            return refused(ErrorCode::Quota);
        }
        let hash = ticket_hash(ticket);
        if self.used_tickets.contains(&hash) {
            return refused(ErrorCode::Replay);
        }
        if self.credentials.contains_key(&id) {
            // Enrolled in another mailbox.
            return refused(ErrorCode::Malformed);
        }
        self.used_tickets.insert(hash);
        self.credentials.insert(
            id,
            Cred {
                enrolled: true,
                ..Cred::manager(m, new_key.to_bytes())
            },
        );
        Ok(())
    }

    /// `api_blob_announce`: (hash, needs upload, object name), by hash.
    fn announce(
        &mut self,
        caller: &CredentialId,
        m: &MailboxId,
        blobs: &[(Sha256, u32)],
    ) -> Result<Vec<(Sha256, bool, String)>, MailboxError> {
        let c = self.caller(caller);
        if c.role == CredentialRole::Read || c.put_kinds.is_some() {
            return refused(ErrorCode::Forbidden);
        }
        let max_bytes = self.mailboxes[m].limits.max_bytes as i64;
        let objects = &self.objects;
        let next_gen = &mut self.next_gen;
        let mbx = self.mailboxes.get_mut(m).expect("authenticated mailbox");
        let distinct: HashSet<&Sha256> = blobs.iter().map(|(s, _)| s).collect();
        if blobs.is_empty()
            || blobs.len() > PAGE_MAX_RECORDS as usize
            || distinct.len() != blobs.len()
            || blobs
                .iter()
                .any(|(_, z)| !(BLOB_MIN..=RECORD_MAX as u32).contains(z))
        {
            return refused(ErrorCode::Malformed);
        }
        let mut growth = 0i64;
        for (s, z) in blobs {
            match mbx.blobs.get(s) {
                Some(b) if b.refs > 0 && b.size != *z => return refused(ErrorCode::Malformed),
                Some(b) if b.refs == 0 => growth += i64::from(*z) - i64::from(b.size),
                Some(_) => {}
                None => growth += i64::from(*z),
            }
        }
        if growth > 0 {
            let pending: i64 = mbx
                .blobs
                .values()
                .filter(|b| b.refs == 0)
                .map(|b| i64::from(b.size))
                .sum();
            if mbx.bytes_used + pending + growth > max_bytes {
                return refused(ErrorCode::Quota);
            }
        }
        let mut out = Vec::with_capacity(blobs.len());
        for (s, z) in blobs {
            let b = mbx.blobs.entry(*s).or_insert_with(|| {
                *next_gen += 1;
                Blob {
                    size: *z,
                    refs: 0,
                    generation: *next_gen,
                }
            });
            if b.refs == 0 {
                b.size = *z;
            }
            let name = object_name(m, s, b.generation);
            let present = objects
                .get(&name)
                .is_some_and(|d| d.len() == b.size as usize);
            out.push((*s, !present, name));
        }
        out.sort_by_key(|o| o.0);
        Ok(out)
    }
}

/// A chunk is readable this long after its write, then purged.
const RDV_CHUNK_LIFE: Duration = Duration::from_secs(120);
/// A session is closed this long after its first chunk.
const RDV_SESSION_LIFE: Duration = Duration::from_secs(600);

type SessionId = [u8; 16];

#[derive(Debug)]
struct RdvSession {
    created: Duration,
    closed: bool,
    bytes: [u64; 2],
    /// (dir, n) to the chunk and when it was written.
    chunks: HashMap<(u8, u32), (Vec<u8>, Duration)>,
}

impl RdvSession {
    fn gone(&self, now: Duration) -> bool {
        self.closed || now.saturating_sub(self.created) > RDV_SESSION_LIFE
    }
}

#[derive(Debug, Default)]
struct RdvInner {
    sessions: HashMap<SessionId, RdvSession>,
    /// Time the tests made pass, on top of the real time.
    skipped: Duration,
    lose_next_answer: bool,
    /// The `n` of every read, per session and direction.
    reads: HashMap<(SessionId, u8), Vec<u32>>,
    /// Invite drops (`drop_put`, `drop_get`, `drop_delete`), on the same
    /// clock as the rendezvous.
    drops: HashMap<[u8; 16], FakeDrop>,
}

/// One invite drop: open until `expires` (72 hours after its first write,
/// or the moment of its delete), its slots written once.
#[derive(Debug)]
struct FakeDrop {
    expires: Duration,
    slots: [Option<Vec<u8>>; DROP_SLOTS as usize],
}

/// The rendezvous tables, apart from the mailbox state: a waiting read
/// holds no lock of the mailbox.
#[derive(Debug)]
struct Rdv {
    epoch: Instant,
    inner: Mutex<RdvInner>,
    written: Condvar,
}

impl Rdv {
    fn lock(&self) -> MutexGuard<'_, RdvInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self, inner: &RdvInner) -> Duration {
        self.epoch.elapsed() + inner.skipped
    }

    /// The router: direction 0 or 1, `n` below 4096.
    fn route(dir: u8, n: u32) -> Result<(), MailboxError> {
        if dir > 1 || n >= RDV_FRAMES_MAX {
            return refused(ErrorCode::NoRoute);
        }
        Ok(())
    }

    fn put(&self, s: SessionId, dir: u8, n: u32, data: &[u8]) -> Result<(), MailboxError> {
        Rdv::route(dir, n)?;
        if data.len() > RDV_CHUNK_MAX {
            return refused(ErrorCode::TooLarge);
        }
        let mut inner = self.lock();
        let now = self.now(&inner);
        // A refused first chunk starts nothing (the SQL rolls it back).
        if let Some(session) = inner.sessions.get_mut(&s) {
            if session.gone(now) {
                return refused(ErrorCode::NotFound);
            }
            if session.bytes[usize::from(dir)] + data.len() as u64 > RDV_SESSION_BYTES_MAX {
                return refused(ErrorCode::TooLarge);
            }
            match session.chunks.get(&(dir, n)) {
                Some((_, at)) if now.saturating_sub(*at) > RDV_CHUNK_LIFE => {
                    // Purged by the maintenance: the number is free again.
                    session.chunks.remove(&(dir, n));
                }
                Some(_) => return Err(MailboxError::FrameTaken),
                None => {}
            }
        }
        let session = inner.sessions.entry(s).or_insert_with(|| RdvSession {
            created: now,
            closed: false,
            bytes: [0; 2],
            chunks: HashMap::new(),
        });
        session.chunks.insert((dir, n), (data.to_vec(), now));
        session.bytes[usize::from(dir)] += data.len() as u64;
        let lost = std::mem::take(&mut inner.lose_next_answer);
        drop(inner);
        self.written.notify_all();
        if lost {
            return Err(MailboxError::Offline);
        }
        Ok(())
    }

    fn get(
        &self,
        s: SessionId,
        dir: u8,
        n: u32,
        wait: u8,
    ) -> Result<Option<Vec<u8>>, MailboxError> {
        Rdv::route(dir, n)?;
        if u64::from(wait) > 25 {
            return refused(ErrorCode::Malformed);
        }
        let until = Instant::now() + Duration::from_secs(wait.into());
        let mut inner = self.lock();
        inner.reads.entry((s, dir)).or_default().push(n);
        loop {
            let now = self.now(&inner);
            if let Some(session) = inner.sessions.get(&s) {
                if session.gone(now) {
                    return refused(ErrorCode::NotFound);
                }
                if let Some((data, at)) = session.chunks.get(&(dir, n))
                    && now.saturating_sub(*at) <= RDV_CHUNK_LIFE
                {
                    return Ok(Some(data.clone()));
                }
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            inner = self
                .written
                .wait_timeout(inner, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn close(&self, s: SessionId) {
        let mut inner = self.lock();
        let now = self.now(&inner);
        let session = inner.sessions.entry(s).or_insert_with(|| RdvSession {
            created: now,
            closed: true,
            bytes: [0; 2],
            chunks: HashMap::new(),
        });
        session.closed = true;
        session.chunks.clear();
        drop(inner);
        self.written.notify_all();
    }
}

/// One side of a rendezvous session on a `FakeMailbox`.
struct FakeRdv {
    fake: FakeMailbox,
    session: SessionId,
}

impl FakeRdv {
    /// The failure a test queued, if any.
    fn fault(&self) -> Result<(), MailboxError> {
        match self.fake.lock().fail_next.pop_front() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl RdvTransport for FakeRdv {
    fn put(&mut self, dir: u8, n: u32, chunk: &[u8]) -> Result<(), MailboxError> {
        self.fault()?;
        self.fake.rdv.put(self.session, dir, n, chunk)
    }

    fn get(&mut self, dir: u8, n: u32, wait: u8) -> Result<Option<Vec<u8>>, MailboxError> {
        self.fault()?;
        self.fake.rdv.get(self.session, dir, n, wait)
    }

    fn close(&mut self) -> Result<(), MailboxError> {
        self.fault()?;
        self.fake.rdv.close(self.session);
        Ok(())
    }
}

/// The mailbox server in memory. Clones share the same state.
#[derive(Clone)]
pub struct FakeMailbox {
    state: Arc<Mutex<State>>,
    rdv: Arc<Rdv>,
}

impl Default for FakeMailbox {
    fn default() -> Self {
        FakeMailbox::new()
    }
}

impl FakeMailbox {
    /// Open signup: every mailbox gets plan `selfhost` (`seed.sql`).
    pub fn new() -> FakeMailbox {
        FakeMailbox::with_limits(selfhost())
    }

    /// Every mailbox gets `limits` (a plan of its own).
    pub fn with_limits(limits: Limits) -> FakeMailbox {
        FakeMailbox {
            state: Arc::new(Mutex::new(State {
                limits,
                mailboxes: HashMap::new(),
                credentials: HashMap::new(),
                used_tickets: HashSet::new(),
                locators: Vec::new(),
                objects: HashMap::new(),
                next_gen: 0,
                fail_next: VecDeque::new(),
                collect_before_commit: false,
            })),
            rdv: Arc::new(Rdv {
                epoch: Instant::now(),
                inner: Mutex::new(RdvInner::default()),
                written: Condvar::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A client of this mailbox server with `credential`, no mailbox open.
    pub fn client(&self, credential: Credential) -> FakeMailboxClient {
        FakeMailboxClient {
            fake: self.clone(),
            credential,
            mailbox: None,
        }
    }

    /// The 90 day maintenance, for every tombstone of every mailbox whose
    /// seq is below `seq`: each frees 1 record and 128 bytes, and
    /// `min_cursor` rises to the highest seq purged.
    pub fn purge_tombstones_before(&self, seq: u64) {
        self.lock().purge(None, seq);
    }

    /// `purge_tombstones_before` for one mailbox.
    pub fn purge_tombstones_of(&self, mailbox: MailboxId, before: u64) {
        self.lock().purge(Some(mailbox), before);
    }

    /// Collects every blob no record references (the maintenance after 24
    /// hours, then `mailbox-gc`). Returns how many.
    pub fn collect_orphan_blobs(&self) -> usize {
        self.lock().collect()
    }

    /// The operator restores an old backup, or the server lost its data:
    /// every mailbox gets a new incarnation and is emptied (records, blobs,
    /// seqs, counters, used tickets). Mailboxes and credentials stay, so
    /// clients can see the new incarnation.
    pub fn lose_everything(&self) {
        let mut s = self.lock();
        for mbx in s.mailboxes.values_mut() {
            let fresh = Mbx {
                wake_topic: mbx.wake_topic,
                created_by: mbx.created_by,
                created_at: mbx.created_at,
                deleted: mbx.deleted,
                kind: mbx.kind,
                parent: mbx.parent,
                ..Mbx::new(mbx.limits.clone())
            };
            *mbx = fresh;
        }
        s.objects.clear();
        s.used_tickets.clear();
    }

    /// One side of rendezvous session `session` on this server.
    pub fn rendezvous(&self, session: [u8; 16], role: RdvRole) -> Rendezvous {
        let transport = FakeRdv {
            fake: self.clone(),
            session,
        };
        Rendezvous::with_transport(Box::new(transport), role)
    }

    /// A raw `PUT /v1/rendezvous/{s}/{dir}/{n}`, as any party may send.
    pub fn rdv_put_raw(
        &self,
        session: [u8; 16],
        dir: u8,
        n: u32,
        data: &[u8],
    ) -> Result<(), MailboxError> {
        self.rdv.put(session, dir, n, data)
    }

    /// A raw `GET` without waiting.
    pub fn rdv_get_raw(
        &self,
        session: [u8; 16],
        dir: u8,
        n: u32,
    ) -> Result<Option<Vec<u8>>, MailboxError> {
        self.rdv.get(session, dir, n, 0)
    }

    /// Chunks of one direction the session holds now.
    pub fn rdv_chunks(&self, session: [u8; 16], dir: u8) -> usize {
        self.rdv
            .lock()
            .sessions
            .get(&session)
            .map_or(0, |s| s.chunks.keys().filter(|(d, _)| *d == dir).count())
    }

    /// The `n` of every read of one direction, in order.
    pub fn rdv_reads(&self, session: [u8; 16], dir: u8) -> Vec<u32> {
        self.rdv
            .lock()
            .reads
            .get(&(session, dir))
            .cloned()
            .unwrap_or_default()
    }

    /// The session was closed (`DELETE`) or expired.
    pub fn rdv_closed(&self, session: [u8; 16]) -> bool {
        let inner = self.rdv.lock();
        let now = self.rdv.now(&inner);
        inner.sessions.get(&session).is_some_and(|s| s.gone(now))
    }

    /// Makes `d` pass for the rendezvous (chunk and session lifetimes).
    pub fn rdv_time_passes(&self, d: Duration) {
        self.rdv.lock().skipped += d;
        self.rdv.written.notify_all();
    }

    /// The next rendezvous write lands, but its answer is lost (`Offline`).
    pub fn rdv_lose_next_answer(&self) {
        self.rdv.lock().lose_next_answer = true;
    }

    /// `PUT /v1/drops/{d}/{slot}` (sharing spec 13.9): the rules of
    /// `drop_put`. Per-IP limits are not modelled.
    pub fn drop_put(&self, id: [u8; 16], slot: u8, bytes: &[u8]) -> Result<(), MailboxError> {
        check_drop_put(slot, bytes)?;
        let mut inner = self.rdv.lock();
        let now = self.rdv.now(&inner);
        let d = inner.drops.entry(id).or_insert_with(|| FakeDrop {
            expires: now + Duration::from_secs(DROP_LIFE_SECS),
            slots: Default::default(),
        });
        if now >= d.expires {
            return refused(ErrorCode::NotFound);
        }
        let s = &mut d.slots[usize::from(slot)];
        if s.is_some() {
            return Err(MailboxError::Conflict);
        }
        *s = Some(bytes.to_vec());
        Ok(())
    }

    /// `GET /v1/drops/{d}/{slot}`: `None` when nothing is there to read.
    pub fn drop_get(&self, id: [u8; 16], slot: u8) -> Result<Option<Vec<u8>>, MailboxError> {
        check_drop_slot(slot)?;
        let inner = self.rdv.lock();
        let now = self.rdv.now(&inner);
        Ok(inner
            .drops
            .get(&id)
            .filter(|d| now < d.expires)
            .and_then(|d| d.slots[usize::from(slot)].clone()))
    }

    /// `DELETE /v1/drops/{d}`: closed for good, even one never opened.
    pub fn drop_delete(&self, id: [u8; 16]) -> Result<(), MailboxError> {
        let mut inner = self.rdv.lock();
        let now = self.rdv.now(&inner);
        let d = inner.drops.entry(id).or_insert_with(|| FakeDrop {
            expires: now,
            slots: Default::default(),
        });
        d.expires = d.expires.min(now);
        d.slots = Default::default();
        Ok(())
    }

    /// `POST /v1/locate`: the live mailboxes holding `locator`, up to 8,
    /// oldest registration first (empty for none). No key, nothing counted
    /// (per-IP limits are not modelled).
    pub fn locate(&self, locator: [u8; 16]) -> Result<Vec<MailboxId>, MailboxError> {
        let s = self.lock();
        let ids: Vec<MailboxId> = s
            .locators
            .iter()
            .filter(|(l, m)| *l == locator && s.mailboxes.get(m).is_some_and(|x| !x.deleted))
            .map(|(_, m)| *m)
            .take(LOCATED_MAX)
            .collect();
        if ids.is_empty() {
            return Ok(vec![]);
        }
        Ok(wire(&Located { mailbox_ids: ids })?.mailbox_ids)
    }

    /// Makes `mailbox` `secs` seconds older (its creation moves back).
    pub fn age_mailbox(&self, mailbox: MailboxId, secs: i64) {
        if let Some(m) = self.lock().mailboxes.get_mut(&mailbox) {
            m.created_at -= secs;
        }
    }

    pub fn faults(&self) -> FaultHandle {
        FaultHandle {
            state: Arc::clone(&self.state),
        }
    }
}

/// Faults to inject into a `FakeMailbox` (the hostile-server tests of
/// Task 15 add theirs here).
pub struct FaultHandle {
    state: Arc<Mutex<State>>,
}

impl FaultHandle {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The next call of any client of this mailbox fails with `error`
    /// (queued: several calls queue several failures), without effect.
    pub fn fail_next(&self, error: MailboxError) {
        self.lock().fail_next.push_back(error);
    }

    /// Right before the next commit, the collector takes every unreferenced
    /// blob (the race of spec 4.11 between announce and commit).
    pub fn collect_before_next_commit(&self) {
        self.lock().collect_before_commit = true;
    }
}

/// A client of a `FakeMailbox`: the same checks as `MailboxClient`, no
/// network.
pub struct FakeMailboxClient {
    fake: FakeMailbox,
    credential: Credential,
    mailbox: Option<MailboxId>,
}

impl FakeMailboxClient {
    /// The server's state, or the failure a test queued for this call.
    fn state(&self) -> Result<MutexGuard<'_, State>, MailboxError> {
        let mut s = self.fake.lock();
        match s.fail_next.pop_front() {
            Some(e) => Err(e),
            None => Ok(s),
        }
    }

    fn open_mailbox(&self) -> Result<MailboxId, MailboxError> {
        self.mailbox
            .ok_or(MailboxError::Malformed("no mailbox open"))
    }

    /// The state with this credential authenticated in the open mailbox.
    fn signed(&self) -> Result<(MutexGuard<'_, State>, MailboxId), MailboxError> {
        let m = self.open_mailbox()?;
        let mut s = self.state()?;
        s.authenticate(&self.credential.id(), &m)?;
        // The nonce is recorded: the credential is no longer unused.
        s.credentials
            .get_mut(&self.credential.id())
            .expect("authenticated credential")
            .used = true;
        Ok((s, m))
    }

    fn lookup(&self, sha256: Sha256) -> Result<Option<Vec<u8>>, MailboxError> {
        let (s, m) = self.signed()?;
        let mbx = &s.mailboxes[&m];
        let referenced = mbx
            .records
            .values()
            .any(|r| matches!(&r.body, Some(Body::Blob { sha256: h, .. }) if *h == sha256));
        let name = mbx
            .blobs
            .get(&sha256)
            .filter(|_| referenced)
            .map(|b| object_name(&m, &sha256, b.generation));
        let urls = wire(&BlobUrls {
            urls: vec![(sha256, name.as_ref().map(|n| format!("{FAKE_STORAGE}{n}")))],
        })?;
        check_answers(&urls, &[sha256])?;
        let Some(name) = name else {
            return Ok(None);
        };
        // Storage answers 404 for an object that is gone.
        s.objects
            .get(&name)
            .cloned()
            .map(Some)
            .ok_or(MailboxError::Server(ErrorCode::NotFound))
    }
}

impl MailboxApi for FakeMailboxClient {
    fn server_config(&self) -> Result<ServerConfig, MailboxError> {
        let _s = self.state()?;
        wire(&ServerConfig {
            realtime_url: "wss://mailbox.fake.invalid/realtime/v1".into(),
            publishable_key: "fake".into(),
            open_signup: true,
        })
    }

    fn create(
        &mut self,
        invite: Option<&[u8]>,
        label: &[u8],
    ) -> Result<MailboxCreated, MailboxError> {
        let req = onepass_mailbox_proto::CreateMailbox {
            public_key: self.credential.public_key().to_bytes(),
            invite: invite.map(<[u8]>::to_vec),
            label: label.to_vec(),
        };
        req.check().map_err(local)?;
        let r = (|| {
            let mut s = self.state()?;
            let id = self.credential.id();
            if s.credentials.contains_key(&id) {
                // The key is enrolled in some mailbox (open signup ignores
                // the invite, as the SQL does).
                return refused(ErrorCode::Malformed);
            }
            let m = random16();
            let mbx = Mbx {
                created_by: Some(id),
                ..Mbx::new(s.limits.clone())
            };
            let created = MailboxCreated {
                mailbox_id: m,
                incarnation: mbx.incarnation,
                wake_topic: mbx.wake_topic,
            };
            s.mailboxes.insert(m, mbx);
            s.credentials.insert(id, Cred::manager(m, req.public_key));
            wire(&created)
        })();
        let created = create_refusal(r, invite.is_none())?;
        self.mailbox = Some(created.mailbox_id);
        Ok(created)
    }

    fn open(&mut self, mailbox: MailboxId) {
        self.mailbox = Some(mailbox);
    }

    fn mailbox(&self) -> Option<MailboxId> {
        self.mailbox
    }

    fn credential_key(&self) -> CredentialKey {
        self.credential.public_key()
    }

    fn info(&self) -> Result<MailboxInfo, MailboxError> {
        let (s, m) = self.signed()?;
        let mbx = &s.mailboxes[&m];
        let info = MailboxInfo {
            incarnation: mbx.incarnation,
            wake_topic: mbx.wake_topic,
            min_cursor: mbx.min_cursor,
            limits: mbx.limits.clone(),
            usage: Usage {
                bytes: mbx.bytes_used as u64,
                records: mbx.records_count as u32,
                credentials: s.active_credentials(&m) as u16,
            },
        };
        wire(&info)
    }

    fn changes(&self, after: u64, limit: u32, full: bool) -> Result<ChangesPage, MailboxError> {
        check_changes_query(after, limit)?;
        self.open_mailbox()?;
        let (s, m) = self.signed()?;
        let page = wire(&s.changes(&m, after, limit, full)?)?;
        check_page(after, limit, full, &page)?;
        Ok(page)
    }

    fn commit(&self, ops: Vec<CommitOp>) -> Result<CommitResponse, MailboxError> {
        self.open_mailbox()?;
        let (req, _body) = commit_request(ops)?;
        let (mut s, m) = self.signed()?;
        if std::mem::take(&mut s.collect_before_commit) {
            s.collect();
        }
        let (answer, status) = s.commit(&self.credential.id(), &m, &req.ops)?;
        let answer = wire(&answer)?;
        check_commit(&req.ops, &answer, status)?;
        Ok(answer)
    }

    fn record(&self, kind: u8, id: [u8; 16]) -> Result<Option<ServerRecord>, MailboxError> {
        if kind == 0 {
            return Err(MailboxError::Malformed("kind zero"));
        }
        let (s, m) = self.signed()?;
        let Some(row) = s.mailboxes[&m].records.get(&(kind, id)) else {
            return Ok(None);
        };
        let rec = wire(&row.server((kind, id)))?;
        check_record(kind, id, &rec)?;
        Ok(Some(rec))
    }

    fn enroll(&mut self, ticket: &SignedEnrollTicket, label: &[u8]) -> Result<(), MailboxError> {
        let req = enroll_request(ticket, label, self.credential.public_key(), FAKE_BASE_URL)?;
        self.state()?
            .enroll(self.credential.public_key(), &req.ticket)?;
        self.mailbox = Some(ticket.ticket.mailbox_id);
        Ok(())
    }

    fn revoke(&self, credential: CredentialId) -> Result<(), MailboxError> {
        let (mut s, m) = self.signed()?;
        s.revoke(&self.credential.id(), &m, &credential)
    }

    fn grant(
        &self,
        public_key: [u8; 32],
        role: CredentialRole,
        put_kinds: Option<[u8; 32]>,
        label: &[u8],
    ) -> Result<CredentialId, MailboxError> {
        self.open_mailbox()?;
        let req = grant_request(public_key, role, put_kinds, label)?;
        let (mut s, m) = self.signed()?;
        s.grant(
            &self.credential.id(),
            &m,
            req.public_key,
            req.role,
            req.put_kinds,
        )?;
        Ok(credential_id(&public_key))
    }

    fn set_role(
        &self,
        credential: CredentialId,
        role: CredentialRole,
        put_kinds: Option<[u8; 32]>,
    ) -> Result<(), MailboxError> {
        self.open_mailbox()?;
        let req = role_request(role, put_kinds)?;
        let (mut s, m) = self.signed()?;
        s.set_role(
            &self.credential.id(),
            &m,
            &credential,
            req.role,
            req.put_kinds,
        )
    }

    fn set_push(&self, kind: PushKind, token: &[u8]) -> Result<(), MailboxError> {
        let req = push_request(kind, token)?;
        let (mut s, _m) = self.signed()?;
        let c = s
            .credentials
            .get_mut(&self.credential.id())
            .expect("authenticated credential");
        c.push = (req.kind != PushKind::None).then_some((req.kind, req.token));
        Ok(())
    }

    fn set_push_target(
        &self,
        tag: [u8; 16],
        kind: PushKind,
        token: &[u8],
    ) -> Result<(), MailboxError> {
        let req = push_request(kind, token)?;
        let (mut s, _m) = self.signed()?;
        let c = s
            .credentials
            .get_mut(&self.credential.id())
            .expect("authenticated credential");
        if req.kind == PushKind::None {
            c.targets.remove(&tag);
            return Ok(());
        }
        if !c.targets.contains_key(&tag) && c.targets.len() >= PUSH_TARGETS_MAX {
            return refused(ErrorCode::Quota);
        }
        c.targets.insert(tag, (req.kind, req.token));
        Ok(())
    }

    fn set_locator(&self, locator: [u8; 16]) -> Result<(), MailboxError> {
        let req = wire(&SetLocator { locator })?;
        let (mut s, m) = self.signed()?;
        // The recovery locator is an account mailbox's only.
        if s.caller(&self.credential.id()).role != CredentialRole::Manage
            || s.mailboxes[&m].kind != ACCOUNT
        {
            return refused(ErrorCode::Forbidden);
        }
        if !s.locators.contains(&(req.locator, m)) {
            s.locators.push((req.locator, m));
        }
        // Keep the mailbox's 2 latest.
        if s.locators.iter().filter(|(_, o)| *o == m).count() > 2 {
            let oldest = s
                .locators
                .iter()
                .position(|(_, o)| *o == m)
                .expect("a row of m");
            s.locators.remove(oldest);
        }
        Ok(())
    }

    fn abandon(&self) -> Result<(), MailboxError> {
        let (mut s, m) = self.signed()?;
        let id = self.credential.id();
        let mbx = &s.mailboxes[&m];
        let others: Vec<&Cred> = s
            .credentials
            .iter()
            .filter(|(c, x)| x.mailbox == m && **c != id)
            .map(|(_, x)| x)
            .collect();
        let fresh = others.len() <= 1 && others.iter().all(|x| !x.used && !x.enrolled);
        let caller = s.caller(&id);
        let allowed = if mbx.kind != ACCOUNT {
            // A child: its owner, at any time.
            caller.owner && caller.role == CredentialRole::Manage
        } else {
            mbx.created_by == Some(id)
                && caller.role == CredentialRole::Manage
                && mbx.created_at > unix_now() - 86_400
                && fresh
                && s.live_children(&m, None) == 0
        };
        if !allowed {
            return refused(ErrorCode::Forbidden);
        }
        s.mailboxes.get_mut(&m).expect("authenticated").deleted = true;
        s.locators.retain(|(_, o)| *o != m);
        Ok(())
    }

    fn create_child(
        &self,
        kind: ChildKind,
        owner_public_key: [u8; 32],
        label: &[u8],
    ) -> Result<MailboxCreated, MailboxError> {
        self.open_mailbox()?;
        let req = child_request(kind, owner_public_key, label)?;
        let (mut s, parent) = self.signed()?;
        // `api_create_child` after the shapes, in its order.
        if s.caller(&self.credential.id()).role != CredentialRole::Manage
            || s.mailboxes[&parent].kind != ACCOUNT
        {
            return refused(ErrorCode::Forbidden);
        }
        let (kind, cap, limits) = match req.kind {
            ChildKind::Shared => (2, MAX_CHILDREN.0, shared()),
            ChildKind::Contact => (3, MAX_CHILDREN.1, contact()),
        };
        if s.live_children(&parent, Some(kind)) >= cap {
            return refused(ErrorCode::Quota);
        }
        let id = credential_id(&req.owner_public_key);
        if s.credentials.contains_key(&id) {
            // The key is in some mailbox.
            return refused(ErrorCode::Malformed);
        }
        let m = random16();
        let mbx = Mbx {
            created_by: Some(id),
            kind,
            parent: Some(parent),
            ..Mbx::new(limits)
        };
        let created = MailboxCreated {
            mailbox_id: m,
            incarnation: mbx.incarnation,
            wake_topic: mbx.wake_topic,
        };
        s.mailboxes.insert(m, mbx);
        s.credentials.insert(
            id,
            Cred {
                owner: true,
                ..Cred::manager(m, req.owner_public_key)
            },
        );
        wire(&created)
    }

    fn issue_ticket(
        &self,
        new_credential_pub: CredentialKey,
        now: i64,
    ) -> Result<SignedEnrollTicket, MailboxError> {
        issue_ticket(
            &self.credential,
            FAKE_BASE_URL,
            self.mailbox,
            new_credential_pub,
            now,
        )
    }

    fn upload_blobs(&self, blobs: &[&[u8]]) -> Result<(), MailboxError> {
        self.open_mailbox()?;
        let all = blob_set(blobs)?;
        for chunk in all.chunks(PAGE_MAX_RECORDS as usize) {
            let announced: Vec<(Sha256, u32)> =
                chunk.iter().map(|(h, d)| (*h, d.len() as u32)).collect();
            let (mut s, m) = self.signed()?;
            let rows = s.announce(&self.credential.id(), &m, &announced)?;
            let urls = wire(&BlobUrls {
                urls: rows
                    .iter()
                    .map(|(sha, up, name)| (*sha, up.then(|| format!("{FAKE_STORAGE}{name}"))))
                    .collect(),
            })?;
            let hashes: Vec<Sha256> = announced.iter().map(|(h, _)| *h).collect();
            check_answers(&urls, &hashes)?;
            for ((_, data), (_, url)) in chunk.iter().zip(&urls.urls) {
                if let Some(url) = url {
                    let name = url.strip_prefix(FAKE_STORAGE).expect("our own url");
                    // Storage with x-upsert false: an object already there
                    // stays (409, which the client takes as success).
                    s.objects
                        .entry(name.to_string())
                        .or_insert_with(|| data.to_vec());
                }
            }
        }
        Ok(())
    }

    fn fetch_body(&self, body: &Body) -> Result<Vec<u8>, MailboxError> {
        let (sha256, size) = match blob_of(body)? {
            BodyRef::Inline(d) => return Ok(d.to_vec()),
            BodyRef::Blob { sha256, size } => (sha256, size),
        };
        let data = self
            .lookup(sha256)?
            .ok_or(MailboxError::Server(ErrorCode::NotFound))?;
        check_blob(sha256, size, &data)?;
        Ok(data)
    }
}
