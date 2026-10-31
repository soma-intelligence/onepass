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
//! in Storage.
//!
//! `FakeMailboxClient` runs the real client's request building and answer
//! checks (`crate::client`, `crate::blobs`), and every answer goes through
//! the strict proto codec: a test against the model checks what the real
//! client checks. The conformance suite runs the same cases here and
//! against a local Supabase stack.
//!
//! Not modelled: signatures, nonces and clock skew of requests (the fake
//! knows who calls), rate limits (`req_per_min` is reported, never
//! enforced), per-IP limits, frozen mailboxes, wake-ups and push.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use onepass_mailbox_proto::{
    BlobUrls, Body, COMMIT_BODY_MAX, ChangesPage, CommitOp, CommitResponse, ConflictEntry,
    CredentialId, ErrorCode, INLINE_MAX, Limits, MailboxCreated, MailboxId, MailboxInfo, Message,
    Op, PAGE_MAX_BYTES, PAGE_MAX_RECORDS, PushKind, RECORD_MAX, ServerConfig, ServerRecord, Sha256,
    SignedEnrollTicket, Usage, decode, encode, hex, ticket_hash, ticket_signed_bytes,
};

use crate::blobs::{BodyRef, blob_of, blob_set, check_answers, check_blob};
use crate::client::{
    check_changes_query, check_commit, check_page, check_record, commit_request, create_refusal,
    enroll_request, error_of, issue_ticket, local, push_request,
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
}

impl Mbx {
    fn new() -> Mbx {
        Mbx {
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
}

#[derive(Debug)]
struct State {
    limits: Limits,
    mailboxes: HashMap<MailboxId, Mbx>,
    /// Credential ids are unique across mailboxes (primary key in SQL).
    credentials: HashMap<CredentialId, Cred>,
    used_tickets: HashSet<Sha256>,
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
        Ok(())
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
        m: &MailboxId,
        ops: &[CommitOp],
    ) -> Result<(CommitResponse, u16), MailboxError> {
        let limits = self.limits.clone();
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
        if carried > COMMIT_BODY_MAX || ops.len() > limits.max_commit_ops as usize {
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
        if !self.mailboxes.contains_key(&m) {
            return refused(ErrorCode::NotFound);
        }
        if approver.revoked {
            return refused(ErrorCode::RevokedCredential);
        }
        if t.expires_at < now {
            return refused(ErrorCode::StaleRequest);
        }
        let id = new_key.id();
        if self.credentials.get(&id).is_some_and(|c| c.mailbox == m) {
            return refused(ErrorCode::Replay);
        }
        if self.active_credentials(&m) >= usize::from(self.limits.max_credentials) {
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
                mailbox: m,
                key: new_key.to_bytes(),
                revoked: false,
                push: None,
            },
        );
        Ok(())
    }

    /// `api_blob_announce`: (hash, needs upload, object name), by hash.
    fn announce(
        &mut self,
        m: &MailboxId,
        blobs: &[(Sha256, u32)],
    ) -> Result<Vec<(Sha256, bool, String)>, MailboxError> {
        let max_bytes = self.limits.max_bytes as i64;
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

/// The mailbox server in memory. Clones share the same state.
#[derive(Clone)]
pub struct FakeMailbox {
    state: Arc<Mutex<State>>,
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
                objects: HashMap::new(),
                next_gen: 0,
                fail_next: VecDeque::new(),
                collect_before_commit: false,
            })),
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
            let wake_topic = mbx.wake_topic;
            *mbx = Mbx::new();
            mbx.wake_topic = wake_topic;
        }
        s.objects.clear();
        s.used_tickets.clear();
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
        let s = self.state()?;
        s.authenticate(&self.credential.id(), &m)?;
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
            let mbx = Mbx::new();
            let created = MailboxCreated {
                mailbox_id: m,
                incarnation: mbx.incarnation,
                wake_topic: mbx.wake_topic,
            };
            s.mailboxes.insert(m, mbx);
            s.credentials.insert(
                id,
                Cred {
                    mailbox: m,
                    key: req.public_key,
                    revoked: false,
                    push: None,
                },
            );
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
            limits: s.limits.clone(),
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
        let (answer, status) = s.commit(&m, &req.ops)?;
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
        match s
            .credentials
            .get_mut(&credential)
            .filter(|c| c.mailbox == m)
        {
            Some(c) => {
                c.revoked = true;
                c.push = None;
                Ok(())
            }
            None => refused(ErrorCode::NotFound),
        }
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
            let rows = s.announce(&m, &announced)?;
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
