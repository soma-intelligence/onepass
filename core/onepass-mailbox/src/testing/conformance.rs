//! One suite of mailbox behaviours, run against the in-memory model
//! (`tests/conformance_fake.rs`) and against a real local Supabase stack
//! (`tests/conformance_e2e.rs`), so the fast tests of the sync engine cannot
//! lie about the server (spec 11).
//!
//! Every case gets fresh mailboxes, asserts exact seqs (each mailbox counts
//! from 1), and panics with its own name in the message.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

use onepass_mailbox_proto::{
    Body, COMMIT_OPS_MAX, ChangesPage, ChildKind, CommitOp, CommitResponse, CredentialRole,
    ErrorCode, MailboxCreated, MailboxId, Op, PAGE_MAX_RECORDS, PushKind, ServerRecord,
    blob_sha256, put_kinds_of,
};

use crate::{ChangeFeed, ErrorCode as Code, MailboxApi, MailboxError, RdvRole, Rendezvous};

/// Where the suite runs. Clients all talk to the same server.
pub trait ConformanceTarget {
    /// A client with a fresh credential and no mailbox open.
    fn client(&mut self) -> Box<dyn MailboxApi>;

    /// The invite `create` sends (`None`: open signup). The quota case needs
    /// a plan of at most `QUOTA_CASE_MAX_RECORDS` records.
    fn invite(&self) -> Option<Vec<u8>>;

    /// Removes every tombstone of `mailbox` the way the 90 day maintenance
    /// does (each frees 1 record and 128 bytes, `min_cursor` rises to the
    /// highest seq purged).
    fn purge_tombstones(&mut self, mailbox: MailboxId);

    /// One side of rendezvous session `session` on the same server.
    fn rendezvous(&mut self, session: [u8; 16], role: RdvRole) -> Rendezvous;

    /// `POST /v1/locate` on the same server, unsigned (spec D.4): the live
    /// mailboxes holding `locator`, oldest registration first, empty when
    /// none.
    fn locate(&mut self, locator: [u8; 16]) -> Result<Vec<MailboxId>, MailboxError>;

    /// `PUT /v1/drops/{d}/{slot}` on the same server (sharing spec 13.9).
    fn drop_put(&mut self, id: [u8; 16], slot: u8, bytes: &[u8]) -> Result<(), MailboxError>;

    /// `GET /v1/drops/{d}/{slot}`.
    fn drop_get(&mut self, id: [u8; 16], slot: u8) -> Result<Option<Vec<u8>>, MailboxError>;

    /// `DELETE /v1/drops/{d}`.
    fn drop_delete(&mut self, id: [u8; 16]) -> Result<(), MailboxError>;

    /// Runs before each case (the end-to-end target clears the per-IP
    /// creation day window there: every case creates mailboxes).
    fn before_case(&mut self) {}
}

/// The quota case fills a mailbox to its plan: above this, it refuses to
/// run (point the target at a small plan instead).
pub const QUOTA_CASE_MAX_RECORDS: u32 = 200_000;

/// Kind used for the records of the suite.
const KIND: u8 = 5;

type Case = fn(&mut dyn ConformanceTarget);

/// Every case, in order. The name is the one a failure panics with.
pub const CASES: &[(&str, Case)] = &[
    ("create", create),
    ("info", info),
    ("conditional_write", conditional_write),
    ("atomic_batch_with_conflict", atomic_batch_with_conflict),
    ("conflict_reply_is_capped", conflict_reply_is_capped),
    ("idempotent_delete", idempotent_delete),
    ("pages_of_changes", pages_of_changes),
    ("full_fetch_skips_tombstones", full_fetch_skips_tombstones),
    ("cursor_expired_after_purge", cursor_expired_after_purge),
    ("enroll_by_ticket_then_replay", enroll_by_ticket_then_replay),
    ("revoked_credential_refused", revoked_credential_refused),
    ("blob_round_trip", blob_round_trip),
    ("record_quota", record_quota),
    ("rendezvous_round_trip", rendezvous_round_trip),
    ("rendezvous_written_once", rendezvous_written_once),
    ("grant_then_granted_key_reads", grant_then_granted_key_reads),
    ("reader_commit_forbidden", reader_commit_forbidden),
    ("limited_writer_kinds", limited_writer_kinds),
    ("manager_changes_role", manager_changes_role),
    ("locate_finds_mailbox", locate_finds_mailbox),
    ("abandoned_mailbox_is_gone", abandoned_mailbox_is_gone),
    (
        "abandon_needs_a_fresh_mailbox",
        abandon_needs_a_fresh_mailbox,
    ),
    ("child_round_trip", child_round_trip),
    ("child_grant_and_revoke", child_grant_and_revoke),
    ("push_target_round_trip", push_target_round_trip),
    ("drop_round_trip", drop_round_trip),
    ("drop_conflict", drop_conflict),
];

/// Runs every case of `CASES` against `target`. A failing case panics with
/// `conformance case <name>: <what failed>`.
pub fn run_conformance(target: &mut dyn ConformanceTarget) {
    for (name, case) in CASES {
        run_case(target, name, *case);
    }
}

/// Runs one case by name (`CASES`), for a focused rerun.
pub fn run_case(target: &mut dyn ConformanceTarget, name: &str, case: Case) {
    target.before_case();
    let outcome = catch_unwind(AssertUnwindSafe(|| case(target)));
    match outcome {
        Ok(()) => eprintln!("conformance case {name}: ok"),
        Err(e) => {
            let what = e
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| e.downcast_ref::<&str>().copied());
            match what {
                Some(w) => panic!("conformance case {name}: {w}"),
                None => resume_unwind(e),
            }
        }
    }
}

// ------------------------------------------------------------------ helpers

fn id(n: u32) -> [u8; 16] {
    let mut i = [0u8; 16];
    i[0] = 0xc0;
    i[12..].copy_from_slice(&n.to_be_bytes());
    i
}

fn put(n: u32, version: u64, expected: Option<u64>, data: &[u8]) -> CommitOp {
    CommitOp {
        kind: KIND,
        id: id(n),
        version,
        op: Op::Put {
            expected,
            body: Body::Inline(data.to_vec()),
        },
    }
}

fn del(n: u32, version: u64) -> CommitOp {
    CommitOp {
        kind: KIND,
        id: id(n),
        version,
        op: Op::Delete,
    }
}

fn applied(r: Result<CommitResponse, MailboxError>, what: &str) -> Vec<Option<u64>> {
    match r {
        Ok(CommitResponse::Applied { seqs }) => seqs,
        other => panic!("{what}: expected Applied, got {other:?}"),
    }
}

fn conflict(
    r: Result<CommitResponse, MailboxError>,
    what: &str,
) -> Vec<onepass_mailbox_proto::ConflictEntry> {
    match r {
        Ok(CommitResponse::Conflict { current }) => current,
        other => panic!("{what}: expected Conflict, got {other:?}"),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A client with a new mailbox of its own, open.
fn owner(t: &mut dyn ConformanceTarget) -> Box<dyn MailboxApi> {
    let mut c = t.client();
    let invite = t.invite();
    c.create(invite.as_deref(), b"conformance")
        .unwrap_or_else(|e| panic!("create: {e:?}"));
    c
}

/// A second client enrolled in `owner`'s mailbox by ticket.
fn enrolled(t: &mut dyn ConformanceTarget, owner: &dyn MailboxApi) -> Box<dyn MailboxApi> {
    let mut c = t.client();
    let ticket = owner
        .issue_ticket(c.credential_key(), now())
        .unwrap_or_else(|e| panic!("issue_ticket: {e:?}"));
    c.enroll(&ticket, b"second")
        .unwrap_or_else(|e| panic!("enroll: {e:?}"));
    c
}

fn page(c: &dyn MailboxApi, after: u64, limit: u32, full: bool) -> ChangesPage {
    c.changes(after, limit, full)
        .unwrap_or_else(|e| panic!("changes(after {after}, limit {limit}, full {full}): {e:?}"))
}

fn seqs(records: &[ServerRecord]) -> Vec<u64> {
    records.iter().map(|r| r.seq).collect()
}

fn usage(c: &dyn MailboxApi) -> (u64, u32, u16) {
    let u = c.info().expect("info").usage;
    (u.bytes, u.records, u.credentials)
}

// -------------------------------------------------------------------- cases

/// Create opens the new mailbox; the same key cannot create a second one.
fn create(t: &mut dyn ConformanceTarget) {
    let mut c = t.client();
    let invite = t.invite();
    let created = c.create(invite.as_deref(), b"conformance").expect("create");
    assert_eq!(
        c.mailbox(),
        Some(created.mailbox_id),
        "create opens the mailbox"
    );
    let again = c.create(invite.as_deref(), b"conformance");
    match (invite.is_some(), again) {
        (false, Err(MailboxError::InviteRequired)) => {}
        (true, Err(MailboxError::Server(ErrorCode::Malformed))) => {}
        (_, other) => panic!("same key, second create: {other:?}"),
    }
    // A second client creates a different mailbox.
    let d = owner(t);
    assert_ne!(
        d.mailbox(),
        Some(created.mailbox_id),
        "two mailboxes, two ids"
    );
}

/// Info echoes the creation and starts empty.
fn info(t: &mut dyn ConformanceTarget) {
    let mut c = t.client();
    let invite = t.invite();
    let created = c.create(invite.as_deref(), b"conformance").expect("create");
    let i = c.info().expect("info");
    assert_eq!(i.incarnation, created.incarnation, "incarnation");
    assert_eq!(i.wake_topic, created.wake_topic, "wake topic");
    assert_eq!(i.min_cursor, 0, "min_cursor of a new mailbox");
    assert_eq!(
        (i.usage.bytes, i.usage.records, i.usage.credentials),
        (0, 0, 1),
        "usage of a new mailbox"
    );
    assert!(i.limits.max_records > 0 && i.limits.max_bytes > 0, "limits");
    assert!(
        i.limits.max_commit_ops >= 1 && i.limits.max_commit_ops as usize <= COMMIT_OPS_MAX,
        "max_commit_ops within the protocol"
    );
    let empty = page(c.as_ref(), 0, 10, false);
    assert_eq!(
        (
            empty.head,
            empty.next_after,
            empty.more,
            empty.records.len()
        ),
        (0, 0, false, 0),
        "a new mailbox has no change"
    );
    assert_eq!(empty.incarnation, created.incarnation, "page incarnation");
}

/// `expected: None` passes on an absent key or a tombstone, `Some(s)` only
/// on a live row at seq `s`; a conflict returns the server row.
fn conditional_write(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    assert_eq!(
        applied(c.commit(vec![put(1, 1, None, b"a")]), "put absent"),
        [Some(1)]
    );
    let r = c.record(KIND, id(1)).expect("record").expect("present");
    assert_eq!(
        (r.seq, r.version, &r.body),
        (1, 1, &Some(Body::Inline(b"a".to_vec())))
    );

    let cur = conflict(
        c.commit(vec![put(1, 2, None, b"b")]),
        "put None on a live row",
    );
    assert_eq!(cur.len(), 1);
    assert_eq!((cur[0].kind, cur[0].id), (KIND, id(1)));
    let s = cur[0].server.as_ref().expect("server row");
    assert_eq!(
        (s.seq, s.version, &s.body),
        (1, 1, &Some(Body::Inline(b"a".to_vec())))
    );

    assert_eq!(
        applied(c.commit(vec![put(1, 2, Some(1), b"b")]), "put at seq"),
        [Some(2)]
    );
    let cur = conflict(
        c.commit(vec![put(1, 3, Some(1), b"c")]),
        "put at an old seq",
    );
    assert_eq!(cur[0].server.as_ref().map(|s| s.seq), Some(2));

    assert_eq!(applied(c.commit(vec![del(1, 3)]), "delete"), [Some(3)]);
    let r = c.record(KIND, id(1)).expect("record").expect("tombstone");
    assert_eq!((r.seq, r.version, &r.body), (3, 3, &None), "tombstone");

    let cur = conflict(
        c.commit(vec![put(1, 4, Some(3), b"d")]),
        "put Some on a tombstone",
    );
    let s = cur[0].server.as_ref().expect("tombstone in the conflict");
    assert_eq!((s.seq, &s.body), (3, &None));
    assert_eq!(
        applied(
            c.commit(vec![put(1, 4, None, b"d")]),
            "put None on a tombstone"
        ),
        [Some(4)]
    );

    let cur = conflict(
        c.commit(vec![put(2, 1, Some(9), b"x")]),
        "put Some on an absent key",
    );
    assert_eq!((cur[0].id, &cur[0].server), (id(2), &None));
    assert_eq!(c.record(KIND, id(2)).expect("record"), None, "absent key");
    assert_eq!(usage(c.as_ref()), (1, 1, 1), "one live row of one byte");
}

/// A batch with one conflict writes nothing and takes no seq.
fn atomic_batch_with_conflict(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    assert_eq!(
        applied(c.commit(vec![put(1, 1, None, b"x")]), "first"),
        [Some(1)]
    );
    let cur = conflict(
        c.commit(vec![
            put(2, 1, None, b"y"),
            put(1, 2, None, b"x2"),
            put(3, 1, None, b"z"),
            del(4, 1),
        ]),
        "batch with one conflict",
    );
    assert_eq!(cur.len(), 1, "only the conflicting key");
    assert_eq!(cur[0].id, id(1));
    assert_eq!(
        c.record(KIND, id(2)).expect("record"),
        None,
        "nothing written"
    );
    assert_eq!(
        c.record(KIND, id(3)).expect("record"),
        None,
        "nothing written"
    );
    assert_eq!(usage(c.as_ref()), (1, 1, 1), "counters unchanged");
    assert_eq!(
        applied(
            c.commit(vec![put(2, 1, None, b"y"), put(3, 1, None, b"z")]),
            "after"
        ),
        [Some(2), Some(3)],
        "no seq taken by the refused batch"
    );
    assert_eq!(page(c.as_ref(), 0, 10, false).head, 3);
}

/// More than 1000 conflicts: the reply is the first 1000, in batch order.
fn conflict_reply_is_capped(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    let n = PAGE_MAX_RECORDS + 1;
    let first: Vec<CommitOp> = (0..n).map(|i| put(i, 1, None, b"v")).collect();
    assert_eq!(applied(c.commit(first), "fill").len(), n as usize);
    let again: Vec<CommitOp> = (0..n).map(|i| put(i, 2, None, b"w")).collect();
    let cur = conflict(c.commit(again), "every key conflicts");
    assert_eq!(cur.len(), PAGE_MAX_RECORDS as usize, "capped at 1000 rows");
    for (i, e) in cur.iter().enumerate() {
        assert_eq!(e.id, id(i as u32), "a prefix in batch order");
        assert_eq!(e.server.as_ref().map(|s| s.seq), Some(i as u64 + 1));
    }
}

/// A delete is unconditional and idempotent: absent key and tombstone take
/// no seq; a tombstone costs 1 record and 128 bytes.
fn idempotent_delete(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    assert_eq!(applied(c.commit(vec![del(1, 1)]), "delete absent"), [None]);
    assert_eq!(usage(c.as_ref()), (0, 0, 1), "nothing stored");
    assert_eq!(
        applied(c.commit(vec![put(1, 1, None, b"xyz")]), "put"),
        [Some(1)]
    );
    assert_eq!(applied(c.commit(vec![del(1, 2)]), "delete live"), [Some(2)]);
    assert_eq!(
        applied(c.commit(vec![del(1, 3)]), "delete tombstone"),
        [None]
    );
    assert_eq!(
        usage(c.as_ref()),
        (128, 1, 1),
        "a tombstone costs 1 and 128"
    );
    assert_eq!(
        applied(
            c.commit(vec![del(1, 4), del(9, 1), put(2, 1, None, b"ab")]),
            "mixed"
        ),
        [None, None, Some(3)],
        "no-op deletes take no seq"
    );
    assert_eq!(usage(c.as_ref()), (130, 2, 1));
    let p = page(c.as_ref(), 0, 10, false);
    assert_eq!(
        seqs(&p.records),
        [2, 3],
        "the feed shows the tombstone once"
    );
}

/// 2 500 records come in pages of 1 000, 1 000 and 500.
fn pages_of_changes(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    let ops: Vec<CommitOp> = (0..2500)
        .map(|i| put(i, 1, None, &i.to_be_bytes()))
        .collect();
    let s = applied(c.commit(ops), "2500 puts");
    assert_eq!(s.first().copied().flatten(), Some(1));
    assert_eq!(s.last().copied().flatten(), Some(2500));

    let mut after = 0;
    for (n, (len, more)) in [(1000, true), (1000, true), (500, false)]
        .into_iter()
        .enumerate()
    {
        let p = page(c.as_ref(), after, 1000, false);
        let want: Vec<u64> = (after + 1..=after + len).collect();
        assert_eq!(seqs(&p.records), want, "page {n} seqs");
        assert_eq!(p.next_after, after + len, "page {n} next_after");
        assert_eq!(p.more, more, "page {n} more");
        assert_eq!(p.head, 2500, "page {n} head");
        after = p.next_after;
    }
    let end = page(c.as_ref(), 2500, 1000, false);
    assert_eq!(
        (end.records.len(), end.next_after, end.more),
        (0, 2500, false),
        "past the head"
    );

    // A small limit, and the feed through a full fetch.
    let p = page(c.as_ref(), 10, 3, false);
    assert_eq!(
        (seqs(&p.records), p.next_after, p.more),
        (vec![11, 12, 13], 13, true)
    );
    let mut feed = ChangeFeed::full();
    let mut got = Vec::new();
    loop {
        let fp = c.next_changes(&mut feed, 1000).expect("next_changes");
        got.extend(seqs(&fp.records));
        if fp.full_done {
            assert!(!fp.more, "nothing written during the fetch");
            break;
        }
        assert!(fp.more && fp.full, "a full page before the last");
    }
    assert_eq!(got.len(), 2500, "the full fetch reads every record once");
    assert_eq!(
        feed,
        ChangeFeed::incremental(2500, p.incarnation),
        "incremental from the first head"
    );
}

/// `after = 0`: a full fetch skips tombstones, an incremental one has them.
fn full_fetch_skips_tombstones(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    applied(
        c.commit(vec![
            put(1, 1, None, b"a"),
            put(2, 1, None, b"b"),
            put(3, 1, None, b"c"),
        ]),
        "three puts",
    );
    assert_eq!(applied(c.commit(vec![del(2, 2)]), "delete b"), [Some(4)]);
    let full = page(c.as_ref(), 0, 1000, true);
    assert_eq!(seqs(&full.records), [1, 3], "live rows only");
    assert!(full.records.iter().all(|r| r.body.is_some()));
    assert_eq!(
        (full.head, full.next_after, full.more),
        (4, 3, true),
        "more up to the head"
    );
    let rest = page(c.as_ref(), 3, 1000, true);
    assert_eq!(
        (rest.records.len(), rest.next_after, rest.more),
        (0, 3, false),
        "only a tombstone left"
    );

    let inc = page(c.as_ref(), 0, 1000, false);
    assert_eq!(seqs(&inc.records), [1, 3, 4], "tombstones included");
    assert_eq!(inc.records[2].body, None);
    assert_eq!((inc.next_after, inc.more), (4, false));

    let mut feed = ChangeFeed::full();
    let first = c.next_changes(&mut feed, 1000).expect("feed");
    assert_eq!(seqs(&first.records), [1, 3]);
    assert!(first.more && !first.full_done);
    let last = c.next_changes(&mut feed, 1000).expect("feed");
    assert!(last.full_done && !last.more && last.records.is_empty());
    assert_eq!(feed, ChangeFeed::incremental(4, full.incarnation));
}

/// After the purge, `after` below `min_cursor` is `CursorExpired`; a full
/// fetch still works, and the quota cost of the tombstone is freed.
fn cursor_expired_after_purge(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    applied(
        c.commit(vec![put(1, 1, None, b"a"), put(2, 1, None, b"bb")]),
        "two puts",
    );
    assert_eq!(applied(c.commit(vec![del(1, 2)]), "delete"), [Some(3)]);
    assert_eq!(usage(c.as_ref()), (130, 2, 1));
    let m = c.mailbox().expect("open");
    t.purge_tombstones(m);

    let i = c.info().expect("info");
    assert_eq!(i.min_cursor, 3, "min_cursor = highest seq purged");
    assert_eq!(
        (i.usage.bytes, i.usage.records),
        (2, 1),
        "tombstone cost freed"
    );
    assert_eq!(
        c.record(KIND, id(1)).expect("record"),
        None,
        "tombstone gone"
    );
    for after in [0, 2] {
        match c.changes(after, 1000, false) {
            Err(MailboxError::CursorExpired) => {}
            other => panic!("incremental after {after} below min_cursor: {other:?}"),
        }
    }
    let at = page(c.as_ref(), 3, 1000, false);
    assert_eq!(
        (at.records.len(), at.min_cursor, at.head),
        (0, 3, 3),
        "after = min_cursor is valid"
    );
    let full = page(c.as_ref(), 0, 1000, true);
    assert_eq!(seqs(&full.records), [2], "a full fetch ignores min_cursor");
    // The purged key is absent again: expected None writes it.
    assert_eq!(
        applied(c.commit(vec![put(1, 3, None, b"a")]), "rewrite"),
        [Some(4)]
    );
}

/// A ticket lets a second credential in once; the same ticket again is a
/// replay, and a ticket for another key is refused by the client.
fn enroll_by_ticket_then_replay(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let m = a.mailbox().expect("open");
    applied(a.commit(vec![put(1, 1, None, b"from a")]), "a writes");

    let mut b = t.client();
    let ticket = a.issue_ticket(b.credential_key(), now()).expect("ticket");
    b.enroll(&ticket, b"b").expect("enroll");
    assert_eq!(b.mailbox(), Some(m), "enroll opens the mailbox");
    let r = b.record(KIND, id(1)).expect("b reads").expect("a's record");
    assert_eq!(r.body, Some(Body::Inline(b"from a".to_vec())));
    applied(b.commit(vec![put(2, 1, None, b"from b")]), "b writes");
    assert!(
        a.record(KIND, id(2)).expect("a reads").is_some(),
        "a sees b's write"
    );
    assert_eq!(usage(a.as_ref()).2, 2, "two active credentials");

    match b.enroll(&ticket, b"b") {
        Err(MailboxError::Server(ErrorCode::Replay)) => {}
        other => panic!("same ticket again: {other:?}"),
    }
    let mut c = t.client();
    match c.enroll(&ticket, b"c") {
        Err(MailboxError::Malformed(_)) => {}
        other => panic!("ticket for another key: {other:?}"),
    }
    assert_eq!(c.mailbox(), None, "a refused enroll opens nothing");
    // A ticket the mailbox never issued: signed by a credential of another
    // mailbox, for this one.
    let stranger = owner(t);
    let mut forged = stranger
        .issue_ticket(c.credential_key(), now())
        .expect("ticket");
    forged.ticket.mailbox_id = m;
    match c.enroll(&forged, b"c") {
        Err(MailboxError::Server(ErrorCode::UnknownCredential | ErrorCode::BadSignature)) => {}
        other => panic!("ticket from outside the mailbox: {other:?}"),
    }
    assert_eq!(usage(a.as_ref()).2, 2, "still two credentials");
}

/// A revoked credential and a credential from elsewhere are refused.
fn revoked_credential_refused(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let m = a.mailbox().expect("open");
    let b = enrolled(t, a.as_ref());
    b.info().expect("b before revoke");
    let b_id = b.credential_key().id();
    a.revoke(b_id).expect("revoke");
    for (what, r) in [
        ("info", b.info().map(|_| ())),
        ("commit", b.commit(vec![put(1, 1, None, b"x")]).map(|_| ())),
        ("changes", b.changes(0, 10, false).map(|_| ())),
    ] {
        match r {
            Err(MailboxError::Server(ErrorCode::RevokedCredential)) => {}
            other => panic!("revoked credential, {what}: {other:?}"),
        }
    }
    a.revoke(b_id).expect("revoking twice changes nothing");
    assert_eq!(usage(a.as_ref()).2, 1, "one active credential");
    match a.revoke([7u8; 16]) {
        Err(MailboxError::Server(ErrorCode::NotFound)) => {}
        other => panic!("revoke an unknown credential: {other:?}"),
    }
    let mut s = t.client();
    s.open(m);
    match s.info() {
        Err(MailboxError::Server(ErrorCode::UnknownCredential)) => {}
        other => panic!("credential not in the mailbox: {other:?}"),
    }
    assert_eq!(
        page(a.as_ref(), 0, 10, false).head,
        0,
        "nothing written by b"
    );
}

/// A 20 KiB body goes through Storage and comes back identical.
fn blob_round_trip(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    let data: Vec<u8> = (0..20 * 1024u32).map(|i| (i * 31 + 7) as u8).collect();
    let sha256 = blob_sha256(&data);
    let body = Body::Blob {
        sha256,
        size: data.len() as u32,
    };
    let op = CommitOp {
        kind: KIND,
        id: id(1),
        version: 1,
        op: Op::Put {
            expected: None,
            body: body.clone(),
        },
    };
    match c.commit(vec![op.clone()]) {
        Err(MailboxError::Server(ErrorCode::Malformed)) => {}
        other => panic!("a blob never announced: {other:?}"),
    }
    assert_eq!(
        applied(c.commit_with_blobs(vec![op], &[&data]), "commit with blob"),
        [Some(1)]
    );
    let r = c.record(KIND, id(1)).expect("record").expect("present");
    assert_eq!(r.body.as_ref(), Some(&body));
    assert_eq!(c.fetch_body(&body).expect("fetch"), data, "same bytes back");
    let p = page(c.as_ref(), 0, 10, false);
    assert_eq!(p.records[0].body.as_ref(), Some(&body));
    assert_eq!(
        usage(c.as_ref()),
        (data.len() as u64, 1, 1),
        "a blob counts its size"
    );
    // Announcing it again uploads nothing and changes nothing.
    c.upload_blobs(&[&data]).expect("announce again");
    assert_eq!(usage(c.as_ref()), (data.len() as u64, 1, 1));
    // A blob nobody references cannot be read.
    let other = Body::Blob {
        sha256: blob_sha256(b"never written"),
        size: 20_000,
    };
    match c.fetch_body(&other) {
        Err(MailboxError::Server(ErrorCode::NotFound)) => {}
        other => panic!("unreferenced blob: {other:?}"),
    }
}

/// The plan's record count is a hard cap on growth; tombstones count until
/// purged; deletes always pass.
fn record_quota(t: &mut dyn ConformanceTarget) {
    let c = owner(t);
    let limits = c.info().expect("info").limits;
    let max = limits.max_records;
    assert!(
        max <= QUOTA_CASE_MAX_RECORDS,
        "plan allows {max} records: point the target at a plan of at most {QUOTA_CASE_MAX_RECORDS}"
    );
    let per = (limits.max_commit_ops as usize).min(COMMIT_OPS_MAX) as u32;
    let mut n = 0;
    while n < max {
        let end = (n + per).min(max);
        let ops: Vec<CommitOp> = (n..end).map(|i| put(i, 1, None, b"q")).collect();
        applied(c.commit(ops), "fill");
        n = end;
    }
    assert_eq!(usage(c.as_ref()).1, max, "full");
    match c.commit(vec![put(max, 1, None, b"q")]) {
        Err(MailboxError::Server(ErrorCode::Quota)) => {}
        other => panic!("one record over the plan: {other:?}"),
    }
    assert_eq!(
        c.record(KIND, id(max)).expect("record"),
        None,
        "nothing written"
    );
    assert_eq!(
        applied(c.commit(vec![del(0, 2)]), "a full mailbox deletes"),
        [Some(u64::from(max) + 1)]
    );
    assert_eq!(usage(c.as_ref()).1, max, "the tombstone still counts");
    match c.commit(vec![put(max, 1, None, b"q")]) {
        Err(MailboxError::Server(ErrorCode::Quota)) => {}
        other => panic!("new key while a tombstone counts: {other:?}"),
    }
    assert_eq!(
        applied(
            c.commit(vec![put(0, 3, None, b"q")]),
            "rewrite over the tombstone"
        ),
        [Some(u64::from(max) + 2)],
        "replacing a tombstone does not grow the count"
    );
    assert_eq!(
        applied(c.commit(vec![put(1, 2, Some(2), b"qq")]), "update"),
        [Some(u64::from(max) + 3)]
    );
}

// ------------------------------------------------------------ rendezvous

fn session_id() -> [u8; 16] {
    let mut s = [0u8; 16];
    aws_lc_rs::rand::fill(&mut s).expect("system random source");
    s
}

fn within(secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(secs)
}

/// A frame of 5 MiB of stream (5 chunks) and an empty one one way, a
/// frame back the other way, then a close the other side sees at once.
fn rendezvous_round_trip(t: &mut dyn ConformanceTarget) {
    let s = session_id();
    let mut newcomer = t.rendezvous(s, RdvRole::Newcomer);
    let mut approver = t.rendezvous(s, RdvRole::Approver);
    let big: Vec<u8> = (0..(5 << 20) - 4).map(|i: u32| (i % 251) as u8).collect();
    newcomer.send_frame(&big).expect("send 5 MiB");
    newcomer.send_frame(b"").expect("send empty");
    let got = approver
        .recv_frame(big.len(), within(30))
        .expect("recv 5 MiB");
    assert!(got == big, "5 MiB frame came back different");
    assert_eq!(
        approver.recv_frame(0, within(30)).expect("recv empty"),
        b"",
        "empty frame"
    );
    approver.send_frame(b"back").expect("send back");
    assert_eq!(
        newcomer.recv_frame(16, within(30)).expect("recv back"),
        b"back"
    );
    newcomer.close();
    let start = Instant::now();
    assert_eq!(
        approver.recv_frame(16, within(30)).unwrap_err(),
        MailboxError::Server(Code::NotFound),
        "a closed session"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "closed is answered, not waited out"
    );
}

/// A chunk number written twice is `FrameTaken`; the session is closed for
/// both sides and its id cannot start again.
fn rendezvous_written_once(t: &mut dyn ConformanceTarget) {
    let s = session_id();
    let mut first = t.rendezvous(s, RdvRole::Newcomer);
    let mut second = t.rendezvous(s, RdvRole::Newcomer);
    let mut approver = t.rendezvous(s, RdvRole::Approver);
    first.send_frame(b"first").expect("first write");
    assert_eq!(
        second.send_frame(b"intruder").unwrap_err(),
        MailboxError::FrameTaken,
        "the same chunk number again"
    );
    assert_eq!(
        approver.recv_frame(64, within(30)).unwrap_err(),
        MailboxError::Server(Code::NotFound),
        "closed by the refused writer"
    );
    let mut again = t.rendezvous(s, RdvRole::Newcomer);
    assert_eq!(
        again.send_frame(b"x").unwrap_err(),
        MailboxError::Server(Code::NotFound),
        "a closed id never starts again"
    );
}

// -------------------------------------------------------------------- roles

/// A credential `owner` grants with `role`, opened on its mailbox.
fn granted(
    t: &mut dyn ConformanceTarget,
    owner: &dyn MailboxApi,
    role: CredentialRole,
    put_kinds: Option<[u8; 32]>,
) -> Box<dyn MailboxApi> {
    let mut c = t.client();
    let key = c.credential_key();
    let id = owner
        .grant(key.to_bytes(), role, put_kinds, b"granted")
        .unwrap_or_else(|e| panic!("grant {role:?}: {e:?}"));
    assert_eq!(id, key.id(), "grant returns the key's credential id");
    c.open(owner.mailbox().expect("open"));
    c
}

fn forbidden<T: std::fmt::Debug>(r: Result<T, MailboxError>, what: &str) {
    match r {
        Err(MailboxError::Forbidden) => {}
        other => panic!("{what}: expected Forbidden, got {other:?}"),
    }
}

/// A key a manager grants signs requests at once, without a ticket; the
/// same key cannot be granted twice, and a reader grants nothing.
fn grant_then_granted_key_reads(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    applied(a.commit(vec![put(1, 1, None, b"from a")]), "a writes");
    let r = granted(t, a.as_ref(), CredentialRole::Read, None);
    r.info().expect("granted key signs info");
    let rec = r
        .record(KIND, id(1))
        .expect("reader reads")
        .expect("a's record");
    assert_eq!(rec.body, Some(Body::Inline(b"from a".to_vec())));
    assert_eq!(seqs(&page(r.as_ref(), 0, 10, false).records), vec![1]);
    assert_eq!(usage(a.as_ref()).2, 2, "two active credentials");

    match a.grant(
        r.credential_key().to_bytes(),
        CredentialRole::Read,
        None,
        b"again",
    ) {
        Err(MailboxError::Server(ErrorCode::Malformed)) => {}
        other => panic!("granting a key already in: {other:?}"),
    }
    let stranger = owner(t);
    match a.grant(
        stranger.credential_key().to_bytes(),
        CredentialRole::Read,
        None,
        b"x",
    ) {
        Err(MailboxError::Server(ErrorCode::Malformed)) => {}
        other => panic!("granting a key of another mailbox: {other:?}"),
    }
    let other = t.client();
    forbidden(
        r.grant(
            other.credential_key().to_bytes(),
            CredentialRole::Read,
            None,
            b"x",
        ),
        "a reader grants",
    );
    assert_eq!(usage(a.as_ref()).2, 2, "still two credentials");
}

/// A reader commits nothing, uploads nothing and revokes no one but itself.
fn reader_commit_forbidden(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let r = granted(t, a.as_ref(), CredentialRole::Read, None);
    forbidden(r.commit(vec![put(1, 1, None, b"x")]), "reader puts");
    forbidden(r.commit(vec![del(1, 1)]), "reader deletes");
    let big = vec![9u8; 20 * 1024];
    forbidden(r.upload_blobs(&[&big]), "reader uploads");
    forbidden(
        r.revoke(a.credential_key().id()),
        "reader revokes the owner",
    );
    assert_eq!(page(a.as_ref(), 0, 10, false).head, 0, "nothing written");
    r.revoke(r.credential_key().id())
        .expect("a reader revokes itself");
    match r.info() {
        Err(MailboxError::Server(ErrorCode::RevokedCredential)) => {}
        other => panic!("self revoked reader: {other:?}"),
    }
    a.info().expect("the owner is untouched");
}

/// A writer limited to kinds 14 to 17 puts those, nothing else, deletes
/// nothing and uploads no blob.
fn limited_writer_kinds(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let w = granted(
        t,
        a.as_ref(),
        CredentialRole::Write,
        Some(put_kinds_of(&[14, 15, 16, 17])),
    );
    let at = |kind: u8, n: u32| CommitOp {
        kind,
        id: id(n),
        version: 1,
        op: Op::Put {
            expected: None,
            body: Body::Inline(vec![kind]),
        },
    };
    let s = applied(
        w.commit(vec![at(14, 1), at(15, 2), at(16, 3), at(17, 4)]),
        "kinds 14 to 17",
    );
    assert_eq!(s, vec![Some(1), Some(2), Some(3), Some(4)]);
    forbidden(w.commit(vec![at(5, 5)]), "kind 5");
    forbidden(
        w.commit(vec![at(14, 6), at(5, 7)]),
        "kind 5 in a batch of 14",
    );
    forbidden(w.commit(vec![at(18, 8)]), "kind 18");
    let gone = CommitOp {
        kind: 14,
        id: id(1),
        version: 2,
        op: Op::Delete,
    };
    forbidden(w.commit(vec![gone]), "a delete of kind 14");
    let big = vec![3u8; 20 * 1024];
    forbidden(w.upload_blobs(&[&big]), "a limited writer uploads");
    assert_eq!(page(a.as_ref(), 0, 10, false).head, 4, "only the four puts");
    applied(
        a.commit(vec![put(9, 1, None, b"owner")]),
        "the owner writes kind 5",
    );
}

/// A manager changes roles; a demoted credential loses what it could do, a
/// promoted one manages, and the last manager stays a manager.
fn manager_changes_role(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let b = granted(t, a.as_ref(), CredentialRole::Write, None);
    let b_id = b.credential_key().id();
    applied(b.commit(vec![put(1, 1, None, b"b")]), "writer writes");
    a.set_role(b_id, CredentialRole::Read, None)
        .expect("demote to read");
    forbidden(b.commit(vec![put(2, 1, None, b"b")]), "demoted writer");
    forbidden(
        b.set_role(b_id, CredentialRole::Manage, None),
        "a reader promotes itself",
    );
    a.set_role(b_id, CredentialRole::Manage, None)
        .expect("promote");
    let c = granted(t, b.as_ref(), CredentialRole::Read, None);
    c.info().expect("granted by the promoted manager");
    match a.set_role([0xee; 16], CredentialRole::Read, None) {
        Err(MailboxError::Server(ErrorCode::NotFound)) => {}
        other => panic!("role of an unknown credential: {other:?}"),
    }
    // b demotes a; b is then the last manager and keeps its role.
    let a_id = a.credential_key().id();
    b.set_role(a_id, CredentialRole::Read, None)
        .expect("demote a");
    forbidden(a.revoke(b_id), "a reader revokes a manager");
    forbidden(
        b.set_role(b_id, CredentialRole::Write, None),
        "last manager demotes itself",
    );
    forbidden(b.revoke(b_id), "last manager revokes itself");
    b.revoke(a_id).expect("the manager revokes a");
    b.info().expect("the last manager is still in");
}

// ------------------------------------------------------------ locator

/// A manager adds locators, anyone finds the mailbox by them without a key.
/// A mailbox keeps its two latest (old and new during a rotation), setting
/// one again changes nothing, a reader sets none. A locator is not unique:
/// another mailbox may hold it too, both are answered oldest first, and an
/// abandoned one drops out.
fn locate_finds_mailbox(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let m = a.mailbox().expect("open");
    let (first, second, third) = (session_id(), session_id(), session_id());
    assert!(t.locate(first).expect("unknown locator").is_empty());
    a.set_locator(first).expect("manager sets the locator");
    assert_eq!(t.locate(first).expect("locate"), vec![m]);
    a.set_locator(second).expect("a second locator");
    assert_eq!(
        t.locate(first).expect("old locator"),
        vec![m],
        "old and new coexist"
    );
    assert_eq!(t.locate(second).expect("new locator"), vec![m]);
    a.set_locator(first).expect("the same pair again");
    a.set_locator(third).expect("a third locator");
    assert!(
        t.locate(first).expect("oldest").is_empty(),
        "the oldest is dropped"
    );
    assert_eq!(t.locate(second).expect("second"), vec![m]);
    assert_eq!(t.locate(third).expect("third"), vec![m]);

    let r = granted(t, a.as_ref(), CredentialRole::Read, None);
    forbidden(r.set_locator(session_id()), "a reader sets the locator");

    let other = owner(t);
    let o = other.mailbox().expect("open");
    other
        .set_locator(second)
        .expect("a locator another mailbox holds");
    assert_eq!(
        t.locate(second).expect("shared"),
        vec![m, o],
        "both, oldest first"
    );
    other.abandon().expect("the other side abandons");
    assert_eq!(
        t.locate(second).expect("after abandon"),
        vec![m],
        "deleted excluded"
    );
}

/// The creator abandons its fresh mailbox, which holds a record, a locator
/// and the unused recovery credential: every request on it is then
/// not_found, its locator finds nothing. Nobody else may abandon it.
fn abandoned_mailbox_is_gone(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    applied(a.commit(vec![put(1, 1, None, b"a")]), "a writes");
    let loc = session_id();
    a.set_locator(loc).expect("set locator");
    // The recovery credential: granted, never used before the abandon.
    let recovery = granted(t, a.as_ref(), CredentialRole::Manage, None);

    a.abandon().expect("the creator abandons");
    let gone = |r: Result<(), MailboxError>, what: &str| match r {
        Err(MailboxError::Server(Code::NotFound)) => {}
        other => panic!("{what} on an abandoned mailbox: {other:?}"),
    };
    gone(a.info().map(drop), "info");
    gone(recovery.info().map(drop), "info of the recovery credential");
    gone(recovery.abandon(), "abandon by the recovery credential");
    gone(a.changes(0, 10, false).map(drop), "changes");
    gone(a.commit(vec![put(2, 1, None, b"b")]).map(drop), "commit");
    gone(a.record(KIND, id(1)).map(drop), "record");
    gone(a.set_locator(session_id()), "set locator");
    gone(a.abandon(), "abandon again");
    assert!(t.locate(loc).expect("locate").is_empty(), "not located");

    let b = owner(t);
    b.set_locator(loc)
        .expect("another mailbox sets the locator");
    assert_eq!(
        t.locate(loc).expect("locate"),
        vec![b.mailbox().expect("open")]
    );
}

/// Abandon needs the creator, still a manager, on a mailbox nobody else has
/// used: a demoted creator, an enrolled device or another credential's
/// commit each end it, and only the creator may abandon.
fn abandon_needs_a_fresh_mailbox(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let g = granted(t, a.as_ref(), CredentialRole::Manage, None);
    forbidden(g.abandon(), "a granted manager abandons");
    g.set_role(a.credential_key().id(), CredentialRole::Read, None)
        .expect("demote the creator");
    forbidden(a.abandon(), "the creator demoted to read");

    let b = owner(t);
    let e = enrolled(t, b.as_ref());
    forbidden(b.abandon(), "another device enrolled");
    forbidden(e.abandon(), "an enrolled device abandons");

    let c = owner(t);
    let w = granted(t, c.as_ref(), CredentialRole::Write, None);
    applied(
        w.commit(vec![put(1, 1, None, b"w")]),
        "another credential writes",
    );
    forbidden(c.abandon(), "another credential committed");

    for (x, what) in [(&a, "a"), (&b, "b"), (&c, "c")] {
        x.info()
            .unwrap_or_else(|e| panic!("{what} still there: {e:?}"));
    }
}

/// `parent` creates a child of `kind` owned by a fresh key; the owner's
/// client comes back with the child open.
fn child(
    t: &mut dyn ConformanceTarget,
    parent: &dyn MailboxApi,
    kind: ChildKind,
) -> (Box<dyn MailboxApi>, MailboxCreated) {
    let mut o = t.client();
    let created = parent
        .create_child(kind, o.credential_key().to_bytes(), b"child")
        .unwrap_or_else(|e| panic!("create child {kind:?}: {e:?}"));
    assert_ne!(
        Some(created.mailbox_id),
        parent.mailbox(),
        "a child is a mailbox of its own"
    );
    o.open(created.mailbox_id);
    (o, created)
}

/// A manager of an account mailbox creates a child owned by a fresh key.
/// The owner commits and reads in it, under the child's own plan (shared:
/// 80 credentials, contact: 4); the child holds no grandchild and takes no
/// enroll ticket; a reader of the parent creates nothing; the parent is not
/// abandoned while a child lives, and is once its owners deleted them.
fn child_round_trip(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let (o, created) = child(t, a.as_ref(), ChildKind::Shared);
    let info = o.info().expect("the owner signs info in its child");
    assert_eq!(
        (info.incarnation, info.wake_topic),
        (created.incarnation, created.wake_topic)
    );
    assert_eq!(info.limits.max_credentials, 80, "plan shared");
    assert_eq!(info.usage.credentials, 1, "the owner alone");
    assert_eq!(
        applied(o.commit(vec![put(1, 1, None, b"shared")]), "owner writes"),
        vec![Some(1)]
    );
    let rec = o
        .record(KIND, id(1))
        .expect("owner reads")
        .expect("its record");
    assert_eq!(rec.body, Some(Body::Inline(b"shared".to_vec())));
    assert_eq!(seqs(&page(o.as_ref(), 0, 10, false).records), vec![1]);
    assert_eq!(
        usage(a.as_ref()).1,
        0,
        "the parent counts none of the child"
    );

    let (c, _) = child(t, a.as_ref(), ChildKind::Contact);
    assert_eq!(
        c.info().expect("contact owner").limits.max_credentials,
        4,
        "plan contact"
    );

    let stranger = t.client();
    forbidden(
        o.create_child(
            ChildKind::Contact,
            stranger.credential_key().to_bytes(),
            b"x",
        ),
        "a child of a child",
    );
    let r = granted(t, a.as_ref(), CredentialRole::Read, None);
    forbidden(
        r.create_child(
            ChildKind::Shared,
            stranger.credential_key().to_bytes(),
            b"x",
        ),
        "a reader of the parent creates a child",
    );
    match a.create_child(ChildKind::Shared, a.credential_key().to_bytes(), b"x") {
        Err(MailboxError::Server(ErrorCode::Malformed)) => {}
        other => panic!("an owner key some mailbox holds: {other:?}"),
    }
    let mut n = t.client();
    let ticket = o
        .issue_ticket(n.credential_key(), now())
        .expect("issue_ticket");
    forbidden(n.enroll(&ticket, b"device"), "an enroll ticket of a child");

    // `a` is no longer fresh (its reader made a request): a new parent
    // shows the child rule alone.
    let p = owner(t);
    let (po, _) = child(t, p.as_ref(), ChildKind::Contact);
    forbidden(p.abandon(), "a parent with a live child");
    po.abandon().expect("the owner deletes its child");
    match po.info() {
        Err(MailboxError::Server(Code::NotFound)) => {}
        other => panic!("a deleted child: {other:?}"),
    }
    p.abandon().expect("the parent once its child is gone");

    o.abandon()
        .expect("the owner deletes its child at any time");
    c.abandon().expect("the contact owner deletes its child");
    a.info().expect("the parent stays");
}

/// The owner grants a member's key: it reads and writes at once, revokes
/// neither the owner nor the child, and once the owner revokes it, gets
/// nothing more.
fn child_grant_and_revoke(t: &mut dyn ConformanceTarget) {
    let a = owner(t);
    let (o, _) = child(t, a.as_ref(), ChildKind::Shared);
    applied(o.commit(vec![put(1, 1, None, b"owner")]), "owner writes");
    let m = granted(t, o.as_ref(), CredentialRole::Write, None);
    let rec = m
        .record(KIND, id(1))
        .expect("member reads")
        .expect("the owner's record");
    assert_eq!(rec.body, Some(Body::Inline(b"owner".to_vec())));
    assert_eq!(
        applied(m.commit(vec![put(2, 1, None, b"member")]), "member writes"),
        vec![Some(2)]
    );
    forbidden(
        m.revoke(o.credential_key().id()),
        "a member revokes the owner",
    );
    forbidden(m.abandon(), "a member deletes the child");
    assert_eq!(usage(o.as_ref()).2, 2, "owner and member");

    o.revoke(m.credential_key().id())
        .expect("the owner revokes the member");
    for (what, r) in [
        ("info", m.info().map(drop)),
        ("record", m.record(KIND, id(1)).map(drop)),
        ("changes", m.changes(0, 10, false).map(drop)),
        ("commit", m.commit(vec![put(3, 1, None, b"x")]).map(drop)),
    ] {
        match r {
            Err(MailboxError::Server(ErrorCode::RevokedCredential)) => {}
            other => panic!("revoked member, {what}: {other:?}"),
        }
    }
    assert_eq!(usage(o.as_ref()).2, 1, "the owner alone");
    assert_eq!(seqs(&page(o.as_ref(), 0, 10, false).records), vec![1, 2]);

    // With another manager in, the owner still cannot revoke itself: a
    // child keeps its owner until deleted. No recovery locator on a child.
    let mg = granted(t, o.as_ref(), CredentialRole::Manage, None);
    forbidden(
        o.revoke(o.credential_key().id()),
        "the owner revokes itself",
    );
    forbidden(o.set_locator(session_id()), "the owner sets a locator");
    forbidden(mg.set_locator(session_id()), "a manager sets a locator");
    o.info().expect("the owner is still in");
}

// ------------------------------------------------------------ invite drops

/// A fresh drop id per run, so the end-to-end target never meets a drop a
/// previous run left behind.
fn fresh_drop_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    aws_lc_rs::rand::fill(&mut id).expect("random drop id");
    id
}

fn drop_round_trip(t: &mut dyn ConformanceTarget) {
    let d = fresh_drop_id();
    assert_eq!(t.drop_get(d, 0).expect("empty drop"), None);
    let big = vec![0x5a; crate::DROP_MAX];
    t.drop_put(d, 0, b"invite").expect("slot 0");
    t.drop_put(d, 3, &big).expect("slot 3, 64 KiB");
    assert_eq!(
        t.drop_get(d, 0).expect("read 0").as_deref(),
        Some(&b"invite"[..])
    );
    assert_eq!(t.drop_get(d, 3).expect("read 3"), Some(big));
    assert_eq!(t.drop_get(d, 1).expect("unwritten slot"), None);
    t.drop_delete(d).expect("delete");
    assert_eq!(t.drop_get(d, 0).expect("deleted"), None);
    assert_eq!(
        t.drop_put(d, 1, b"late"),
        Err(MailboxError::Server(Code::NotFound)),
        "a deleted drop never opens again"
    );
}

fn drop_conflict(t: &mut dyn ConformanceTarget) {
    let d = fresh_drop_id();
    t.drop_put(d, 2, b"first").expect("first write");
    assert_eq!(t.drop_put(d, 2, b"second"), Err(MailboxError::Conflict));
    assert_eq!(
        t.drop_get(d, 2).expect("read").as_deref(),
        Some(&b"first"[..])
    );
}

// ------------------------------------------------------------ push targets

fn push_target_round_trip(t: &mut dyn ConformanceTarget) {
    let mut c = t.client();
    c.create(t.invite().as_deref(), b"").expect("create");
    let tag = |n: u8| [n; 16];
    for n in 0..8 {
        c.set_push_target(tag(n), PushKind::Apns, &[n, 1])
            .expect("eight targets");
    }
    assert_eq!(
        c.set_push_target(tag(8), PushKind::Fcm, b"t"),
        Err(MailboxError::Server(Code::Quota)),
        "a ninth target"
    );
    c.set_push_target(tag(3), PushKind::Fcm, b"replaced")
        .expect("replace within the cap");
    c.set_push_target(tag(3), PushKind::None, b"")
        .expect("delete");
    c.set_push_target(tag(8), PushKind::UnifiedPush, b"now fits")
        .expect("room after a delete");
    assert!(matches!(
        c.set_push_target(tag(9), PushKind::Apns, b""),
        Err(MailboxError::Malformed(_))
    ));
}
