//! The conformance suite against the in-memory mailbox, plus the behaviours
//! only the model can stage (lost data, a collected blob).

use onepass_mailbox::testing::{ConformanceTarget, FakeMailbox, run_conformance};
use std::time::Duration;

use onepass_mailbox::{
    ChangeFeed, Credential, ErrorCode, MailboxApi, MailboxError, RdvRole, Rendezvous,
};
use onepass_mailbox_proto::{Body, CommitOp, CommitResponse, Limits, MailboxId, Op, blob_sha256};

/// The plan the end-to-end run uses too (see mailbox/scripts/e2e-admin.sh).
fn conformance_limits() -> Limits {
    Limits {
        max_bytes: 64 << 20,
        max_records: 3000,
        max_credentials: 16,
        req_per_min: 6000,
        max_commit_ops: 20_000,
    }
}

struct Fake(FakeMailbox);

impl ConformanceTarget for Fake {
    fn client(&mut self) -> Box<dyn MailboxApi> {
        Box::new(self.0.client(Credential::generate().unwrap()))
    }

    fn invite(&self) -> Option<Vec<u8>> {
        None
    }

    fn purge_tombstones(&mut self, mailbox: MailboxId) {
        self.0.purge_tombstones_of(mailbox, u64::MAX);
    }

    fn rendezvous(&mut self, session: [u8; 16], role: RdvRole) -> Rendezvous {
        self.0.rendezvous(session, role)
    }

    fn locate(&mut self, locator: [u8; 16]) -> Result<Vec<MailboxId>, MailboxError> {
        self.0.locate(locator)
    }
}

#[test]
fn conformance_fake() {
    run_conformance(&mut Fake(FakeMailbox::with_limits(conformance_limits())));
}

fn put(n: u8, data: &[u8]) -> CommitOp {
    CommitOp {
        kind: 5,
        id: [n; 16],
        version: 1,
        op: Op::Put {
            expected: None,
            body: Body::Inline(data.to_vec()),
        },
    }
}

#[test]
fn default_plan_is_selfhost() {
    let fake = FakeMailbox::new();
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(None, b"").unwrap();
    let l = c.info().unwrap().limits;
    assert_eq!(
        (l.max_records, l.max_credentials, l.max_commit_ops),
        (10_000_000, 256, 20_000)
    );
}

#[test]
fn lose_everything_changes_the_incarnation() {
    let fake = FakeMailbox::new();
    let mut c = fake.client(Credential::generate().unwrap());
    let created = c.create(None, b"").unwrap();
    c.commit(vec![put(1, b"a")]).unwrap();
    fake.lose_everything();
    let i = c.info().unwrap();
    assert_ne!(i.incarnation, created.incarnation);
    assert_eq!((i.usage.records, i.usage.bytes), (0, 0));
    let p = c.changes(0, 10, false).unwrap();
    assert_eq!((p.head, p.records.len()), (0, 0));
    assert_eq!(c.record(5, [1; 16]).unwrap(), None);
    // A feed in a full fetch refuses a page from another incarnation.
    c.commit(vec![put(1, b"a"), put(2, b"b")]).unwrap();
    let mut feed = ChangeFeed::full();
    c.next_changes(&mut feed, 1).unwrap();
    fake.lose_everything();
    c.commit(vec![put(1, b"a"), put(2, b"b")]).unwrap();
    assert!(matches!(
        c.next_changes(&mut feed, 1),
        Err(MailboxError::IncarnationChanged { .. })
    ));
}

#[test]
fn purge_before_a_seq_keeps_later_tombstones() {
    let fake = FakeMailbox::new();
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(None, b"").unwrap();
    c.commit(vec![put(1, b"a"), put(2, b"b")]).unwrap();
    let del = |n: u8| CommitOp {
        kind: 5,
        id: [n; 16],
        version: 2,
        op: Op::Delete,
    };
    c.commit(vec![del(1)]).unwrap(); // seq 3
    c.commit(vec![del(2)]).unwrap(); // seq 4
    fake.purge_tombstones_before(4);
    let i = c.info().unwrap();
    assert_eq!((i.min_cursor, i.usage.records), (3, 1));
    assert_eq!(c.record(5, [2; 16]).unwrap().map(|r| r.seq), Some(4));
}

#[test]
fn collected_blob_is_announced_again() {
    let fake = FakeMailbox::new();
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(None, b"").unwrap();
    let data = vec![9u8; 17 * 1024];
    let body = Body::Blob {
        sha256: blob_sha256(&data),
        size: data.len() as u32,
    };
    let op = |v| CommitOp {
        kind: 5,
        id: [1; 16],
        version: v,
        op: Op::Put {
            expected: None,
            body: body.clone(),
        },
    };
    c.upload_blobs(&[&data]).unwrap();
    // The collector takes the unreferenced blob before the commit.
    assert_eq!(fake.collect_orphan_blobs(), 1);
    assert!(matches!(
        c.commit(vec![op(1)]),
        Err(MailboxError::Server(onepass_mailbox::ErrorCode::Malformed))
    ));
    fake.faults().collect_before_next_commit();
    let r = c.commit_with_blobs(vec![op(1)], &[&data]).unwrap();
    assert_eq!(
        r,
        CommitResponse::Applied {
            seqs: vec![Some(1)]
        }
    );
    assert_eq!(c.fetch_body(&body).unwrap(), data);
}

#[test]
fn injected_failure_comes_back_once() {
    let fake = FakeMailbox::new();
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(None, b"").unwrap();
    fake.faults().fail_next(MailboxError::Offline);
    assert_eq!(c.info().unwrap_err(), MailboxError::Offline);
    c.info().unwrap();
}

fn code<T>(r: Result<T, MailboxError>) -> Option<ErrorCode> {
    match r {
        Err(MailboxError::Server(c)) => Some(c),
        _ => None,
    }
}

/// The rendezvous rules of `rdv_put`, `rdv_get` and `rdv_close`.
#[test]
fn rendezvous_rules_follow_the_sql() {
    let fake = FakeMailbox::new();
    let s = [3; 16];
    // The router: direction 0 or 1, n below 4096; 1 MiB a chunk.
    assert_eq!(
        code(fake.rdv_put_raw(s, 2, 0, b"x")),
        Some(ErrorCode::NoRoute)
    );
    assert_eq!(
        code(fake.rdv_put_raw(s, 0, 4096, b"x")),
        Some(ErrorCode::NoRoute)
    );
    assert_eq!(
        fake.rdv_put_raw(s, 0, 0, &vec![0; (1 << 20) + 1]),
        Err(MailboxError::TooLarge)
    );
    // Not started yet: absent, not closed.
    assert_eq!(fake.rdv_get_raw(s, 0, 0), Ok(None));
    fake.rdv_put_raw(s, 0, 4095, b"").unwrap();
    assert_eq!(fake.rdv_get_raw(s, 0, 4095), Ok(Some(vec![])));
    // Written once, then readable for 120 s, then rewritable.
    fake.rdv_put_raw(s, 0, 0, b"a").unwrap();
    assert_eq!(
        fake.rdv_put_raw(s, 0, 0, b"b"),
        Err(MailboxError::FrameTaken)
    );
    assert_eq!(fake.rdv_get_raw(s, 0, 0), Ok(Some(b"a".to_vec())));
    fake.rdv_time_passes(Duration::from_secs(121));
    assert_eq!(fake.rdv_get_raw(s, 0, 0), Ok(None));
    fake.rdv_put_raw(s, 0, 0, b"b").unwrap();
    // 66 MiB per direction (exactly 66 MiB passes), counted on every write.
    let mib = vec![0; 1 << 20];
    for n in 1..66 {
        fake.rdv_put_raw(s, 1, n, &mib).unwrap();
    }
    fake.rdv_put_raw(s, 1, 66, &mib[..(1 << 20) - 1]).unwrap();
    fake.rdv_put_raw(s, 1, 67, b"x").unwrap();
    assert_eq!(
        fake.rdv_put_raw(s, 1, 68, b"x"),
        Err(MailboxError::TooLarge)
    );
    fake.rdv_put_raw(s, 0, 1, b"x").unwrap();
    // Closed 600 s after its first chunk.
    fake.rdv_time_passes(Duration::from_secs(480));
    assert!(fake.rdv_closed(s));
    assert_eq!(code(fake.rdv_get_raw(s, 0, 0)), Some(ErrorCode::NotFound));
    assert_eq!(
        code(fake.rdv_put_raw(s, 0, 2, b"x")),
        Some(ErrorCode::NotFound)
    );
    // A close before any chunk spends the id too.
    let t = [4; 16];
    fake.rendezvous(t, RdvRole::Approver).close();
    assert_eq!(
        code(fake.rdv_put_raw(t, 0, 0, b"x")),
        Some(ErrorCode::NotFound)
    );
}

#[test]
fn rendezvous_retries_a_busy_server() {
    let fake = FakeMailbox::new();
    let s = [5; 16];
    let mut n = fake.rendezvous(s, RdvRole::Newcomer);
    fake.faults()
        .fail_next(MailboxError::Retry { after: Some(1) });
    n.send_frame(b"hi").unwrap();
    let mut a = fake.rendezvous(s, RdvRole::Approver);
    fake.faults().fail_next(MailboxError::Offline);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    assert_eq!(a.recv_frame(8, deadline).unwrap(), b"hi");
}

/// A day after its creation, not even the creator abandons an account
/// mailbox (`api_delete_mailbox`: created_at within 24 hours).
#[test]
fn abandon_refused_after_day() {
    let fake = FakeMailbox::new();
    let mut c = fake.client(Credential::generate().unwrap());
    let m = c.create(None, b"").unwrap().mailbox_id;
    fake.age_mailbox(m, 86_400);
    assert_eq!(c.abandon(), Err(MailboxError::Forbidden));
    c.info().expect("still there");
    let mut fresh = fake.client(Credential::generate().unwrap());
    let f = fresh.create(None, b"").unwrap().mailbox_id;
    fake.age_mailbox(f, 86_399);
    fresh.abandon().expect("within the day");
}

/// Nine mailboxes on one locator: the eight oldest, in order; an abandoned
/// one drops out and the ninth comes in. (The conformance suite cannot make
/// nine mailboxes in one case on a real server: five creations a day per IP.)
#[test]
fn locate_answers_eight_oldest_first() {
    let fake = FakeMailbox::new();
    let loc = [0x42; 16];
    let clients: Vec<_> = (0..9)
        .map(|_| {
            let mut c = fake.client(Credential::generate().unwrap());
            c.create(None, b"").unwrap();
            c.set_locator(loc).unwrap();
            c
        })
        .collect();
    let ids: Vec<_> = clients.iter().map(|c| c.mailbox().unwrap()).collect();
    assert_eq!(fake.locate(loc).unwrap(), ids[..8]);
    clients[0].abandon().unwrap();
    assert_eq!(fake.locate(loc).unwrap(), ids[1..]);
}
