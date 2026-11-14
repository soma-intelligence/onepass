//! `OrgStore` against the in-memory mailbox on plan `org`: write-once
//! lineage and roster records, mutable keysets and join requests, the
//! answers a hostile or racing server can give.

use onepass_mailbox::org::{
    ORG_JOIN_KIND, ORG_LINEAGE_KIND, ORG_READ_MAX, join_record_id, lineage_record_id,
};
use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient, org_plan};
use onepass_mailbox::{Credential, MailboxApi, MailboxError, OrgStore, OrgStoreError};
use onepass_mailbox_proto::{Body, CommitOp, Op, ServerRecord};

const ORG: [u8; 16] = [7; 16];

fn setup() -> (FakeMailbox, OrgStore<FakeMailboxClient>) {
    let fake = FakeMailbox::with_limits(org_plan());
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(None, b"org").unwrap();
    (fake, OrgStore::new(c, ORG))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn second(fake: &FakeMailbox, owner: &FakeMailboxClient) -> OrgStore<FakeMailboxClient> {
    let mut c = fake.client(Credential::generate().unwrap());
    let ticket = owner.issue_ticket(c.credential_key(), now()).unwrap();
    c.enroll(&ticket, b"second").unwrap();
    OrgStore::new(c, ORG)
}

fn records(s: &OrgStore<FakeMailboxClient>) -> u64 {
    u64::from(s.api().info().unwrap().usage.records)
}

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31) ^ seed).collect()
}

#[test]
fn put_lineage_then_read_from_zero() {
    let (_f, mut s) = setup();
    s.put_lineage(0, b"a".to_vec()).unwrap();
    s.put_lineage(1, b"b".to_vec()).unwrap();
    s.put_lineage(2, b"c".to_vec()).unwrap();
    assert_eq!(
        s.lineage_from(0).unwrap(),
        vec![(0, b"a".to_vec()), (1, b"b".to_vec()), (2, b"c".to_vec())]
    );
    assert_eq!(s.lineage_from(2).unwrap(), vec![(2, b"c".to_vec())]);
}

#[test]
fn lineage_stops_at_the_first_gap() {
    let (_f, mut s) = setup();
    for g in [0, 1, 3] {
        s.put_lineage(g, vec![g as u8]).unwrap();
    }
    assert_eq!(s.lineage_from(0).unwrap(), vec![(0, vec![0]), (1, vec![1])]);
}

#[test]
fn lineage_from_is_capped() {
    let (_f, mut s) = setup();
    for g in 0..(ORG_READ_MAX as u64 + 5) {
        s.put_lineage(g, g.to_be_bytes().to_vec()).unwrap();
    }
    let first = s.lineage_from(0).unwrap();
    assert_eq!(first.len(), ORG_READ_MAX);
    let last = first.last().unwrap().0;
    let rest = s.lineage_from(last + 1).unwrap();
    assert_eq!(rest.len(), 5);
    assert_eq!(rest.last().unwrap().0, ORG_READ_MAX as u64 + 4);
}

#[test]
fn put_lineage_same_bytes_twice_is_ok() {
    let (_f, mut s) = setup();
    s.put_lineage(0, b"a".to_vec()).unwrap();
    assert_eq!(s.put_lineage(0, b"a".to_vec()), Ok(()));
}

#[test]
fn put_lineage_other_bytes_is_taken() {
    let (_f, mut s) = setup();
    s.put_lineage(0, b"a".to_vec()).unwrap();
    assert_eq!(s.put_lineage(0, b"x".to_vec()), Err(OrgStoreError::Taken));
    assert_eq!(s.lineage_from(0).unwrap(), vec![(0, b"a".to_vec())]);
}

#[test]
fn put_lineage_retry_after_lost_reply_is_ok() {
    let (fake, mut s) = setup();
    let before = records(&s);
    fake.faults().drop_commit_reply();
    assert!(s.put_lineage(0, b"a".to_vec()).is_err());
    assert_eq!(s.put_lineage(0, b"a".to_vec()), Ok(()));
    assert_eq!(records(&s), before + 1);
    assert_eq!(s.lineage_from(0).unwrap(), vec![(0, b"a".to_vec())]);
}

#[test]
fn lineage_tombstone_is_a_gap() {
    let (fake, mut s) = setup();
    s.put_lineage(0, b"a".to_vec()).unwrap();
    fake.faults().inject(ServerRecord {
        seq: 0,
        kind: ORG_LINEAGE_KIND,
        id: lineage_record_id(&ORG, 1),
        version: 1,
        body: None,
    });
    s.put_lineage(2, b"c".to_vec()).unwrap();
    assert_eq!(s.lineage_from(0).unwrap(), vec![(0, b"a".to_vec())]);
    assert_eq!(s.put_lineage(1, b"b".to_vec()), Err(OrgStoreError::Taken));
}

#[test]
fn latest_roster_none_when_empty() {
    let (_f, mut s) = setup();
    assert_eq!(s.latest_roster(), Ok(None));
}

#[test]
fn latest_roster_finds_the_newest() {
    let (_f, mut s) = setup();
    for seq in 1..=9u64 {
        s.put_roster(seq, vec![seq as u8; 3]).unwrap();
    }
    assert_eq!(s.latest_roster(), Ok(Some((9, vec![9; 3]))));
    s.put_roster(10, vec![10; 3]).unwrap();
    assert_eq!(s.latest_roster(), Ok(Some((10, vec![10; 3]))));
    assert_eq!(s.roster(4), Ok(Some(vec![4; 3])));
    assert_eq!(s.roster(11), Ok(None));
}

#[test]
fn latest_roster_from_seq_zero() {
    let (_f, mut s) = setup();
    s.put_roster(0, b"zero".to_vec()).unwrap();
    assert_eq!(s.latest_roster(), Ok(Some((0, b"zero".to_vec()))));
}

#[test]
fn second_writer_of_a_roster_seq_is_taken() {
    let (fake, mut a) = setup();
    let mut b = second(&fake, a.api());
    assert_eq!(a.put_roster(3, b"from a".to_vec()), Ok(()));
    assert_eq!(
        b.put_roster(3, b"from b".to_vec()),
        Err(OrgStoreError::Taken)
    );
    assert_eq!(b.roster(3), Ok(Some(b"from a".to_vec())));
    assert_eq!(a.roster(3), Ok(Some(b"from a".to_vec())));
}

#[test]
fn put_roster_blob_round_trip() {
    let (_f, mut s) = setup();
    let sizes = [16 * 1024, 16 * 1024 + 1, 900 * 1024];
    for (i, n) in sizes.iter().enumerate() {
        let data = bytes(*n, i as u8);
        let seq = i as u64 + 1;
        s.put_roster(seq, data.clone()).unwrap();
        assert_eq!(s.latest_roster(), Ok(Some((seq, data.clone()))));
        // The same blob again is answered from the record, not uploaded.
        assert_eq!(s.put_roster(seq, data), Ok(()));
    }
    let other = bytes(900 * 1024, 0xee);
    assert_eq!(s.put_roster(3, other), Err(OrgStoreError::Taken));
}

#[test]
fn put_roster_over_record_max_is_too_large() {
    let (_f, mut s) = setup();
    let before = records(&s);
    assert_eq!(
        s.put_roster(1, vec![0; 900 * 1024 + 1]),
        Err(OrgStoreError::Mailbox(MailboxError::TooLarge))
    );
    assert_eq!(records(&s), before);
}

#[test]
fn owner_keyset_replace_and_read() {
    let (_f, mut s) = setup();
    let acc = [0x22; 16];
    s.put_owner_keyset(acc, b"one".to_vec()).unwrap();
    s.put_owner_keyset(acc, b"two".to_vec()).unwrap();
    assert_eq!(s.owner_keyset(acc), Ok(Some(b"two".to_vec())));
    assert_eq!(s.owner_keyset([0x33; 16]), Ok(None));
}

#[test]
fn join_requests_list_and_delete() {
    let (_f, mut s) = setup();
    let a1 = [0x02; 16];
    let a2 = [0x01; 16];
    s.put_join_request(a1, b"r1".to_vec()).unwrap();
    s.put_join_request(a2, b"r2".to_vec()).unwrap();
    s.put_join_request(a1, b"r1'".to_vec()).unwrap();
    assert_eq!(
        s.join_requests().unwrap(),
        vec![(a2, b"r2".to_vec()), (a1, b"r1'".to_vec())]
    );
    s.delete_join_request(a1).unwrap();
    s.delete_join_request(a1).unwrap();
    assert_eq!(s.join_requests().unwrap(), vec![(a2, b"r2".to_vec())]);
    // A request after a delete writes over the tombstone.
    s.put_join_request(a1, b"again".to_vec()).unwrap();
    assert_eq!(
        s.join_requests().unwrap(),
        vec![(a2, b"r2".to_vec()), (a1, b"again".to_vec())]
    );
}

#[test]
fn join_requests_drop_frames_at_wrong_ids() {
    let (fake, mut s) = setup();
    let a1 = [0x01; 16];
    let a2 = [0x02; 16];
    let a3 = [0x03; 16];
    s.put_join_request(a3, b"ok".to_vec()).unwrap();
    let mut wrong = a2.to_vec();
    wrong.extend_from_slice(b"x");
    fake.faults().inject(ServerRecord {
        seq: 0,
        kind: ORG_JOIN_KIND,
        id: join_record_id(&ORG, &a1),
        version: 1,
        body: Some(Body::Inline(wrong)),
    });
    fake.faults().inject(ServerRecord {
        seq: 0,
        kind: ORG_JOIN_KIND,
        id: join_record_id(&ORG, &a2),
        version: 1,
        body: Some(Body::Inline(vec![1, 2, 3])),
    });
    assert_eq!(s.join_requests().unwrap(), vec![(a3, b"ok".to_vec())]);
}

#[test]
fn org_delete_of_lineage_is_forbidden() {
    let (_f, mut s) = setup();
    s.put_lineage(0, b"a".to_vec()).unwrap();
    let r = s.api().commit(vec![CommitOp {
        kind: ORG_LINEAGE_KIND,
        id: lineage_record_id(&ORG, 0),
        version: 1,
        op: Op::Delete,
    }]);
    assert_eq!(r, Err(MailboxError::Forbidden));
    assert_eq!(s.lineage_from(0).unwrap(), vec![(0, b"a".to_vec())]);
}
