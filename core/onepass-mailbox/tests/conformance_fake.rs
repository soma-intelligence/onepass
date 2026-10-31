//! The conformance suite against the in-memory mailbox, plus the behaviours
//! only the model can stage (lost data, a collected blob).

use onepass_mailbox::testing::{ConformanceTarget, FakeMailbox, run_conformance};
use onepass_mailbox::{ChangeFeed, Credential, MailboxApi, MailboxError};
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
        Err(MailboxError::Malformed(_))
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
