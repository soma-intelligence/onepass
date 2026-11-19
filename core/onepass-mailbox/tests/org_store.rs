//! `OrgStore` against the in-memory mailbox on plan `org`: write-once
//! lineage and roster records, mutable keysets and join requests, the
//! answers a hostile or racing server can give.

use onepass_mailbox::org::{
    ORG_FEED_PAGES_MAX, ORG_JOIN_KIND, ORG_LINEAGE_KIND, ORG_READ_MAX, join_record_id,
    lineage_record_id,
};
use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient, org_plan};
use onepass_mailbox::{
    ChangeFeed, Credential, MailboxApi, MailboxError, OrgStore, OrgStoreApi, OrgStoreError,
};
use onepass_mailbox_proto::{
    Body, ChangesPage, ChildKind, CommitOp, CommitResponse, CredentialId, CredentialRole,
    MailboxCreated, MailboxId, MailboxInfo, Op, PushKind, ServerConfig, ServerRecord,
    SignedEnrollTicket, put_kinds_of,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
fn join_feed_first_call_is_full_and_reset() {
    let (_f, mut s) = setup();
    s.put_join_request([2; 16], b"r2".to_vec()).unwrap();
    s.put_join_request([1; 16], b"r1".to_vec()).unwrap();
    let mut feed = ChangeFeed::full();
    let d = s.join_requests_since(&mut feed).unwrap();
    assert!(d.reset);
    assert_eq!(
        d.upserts,
        vec![([1; 16], b"r1".to_vec()), ([2; 16], b"r2".to_vec())]
    );
    assert!(d.removed.is_empty());
    assert!(!feed.is_full());
}

#[test]
fn join_feed_second_call_gives_only_new() {
    let (_f, mut s) = setup();
    s.put_join_request([1; 16], b"r1".to_vec()).unwrap();
    s.put_join_request([2; 16], b"r2".to_vec()).unwrap();
    let mut feed = ChangeFeed::full();
    s.join_requests_since(&mut feed).unwrap();
    s.put_join_request([3; 16], b"r3".to_vec()).unwrap();
    let d = s.join_requests_since(&mut feed).unwrap();
    assert!(!d.reset);
    assert_eq!(d.upserts, vec![([3; 16], b"r3".to_vec())]);
    assert!(d.removed.is_empty());
    let d = s.join_requests_since(&mut feed).unwrap();
    assert!(!d.reset);
    assert!(d.upserts.is_empty() && d.removed.is_empty());
}

#[test]
fn join_feed_reports_deletion() {
    let (_f, mut s) = setup();
    let (a1, a2) = ([1; 16], [2; 16]);
    s.put_join_request(a1, b"r1".to_vec()).unwrap();
    s.put_join_request(a2, b"r2".to_vec()).unwrap();
    let mut feed = ChangeFeed::full();
    s.join_requests_since(&mut feed).unwrap();
    s.delete_join_request(a1).unwrap();
    let d = s.join_requests_since(&mut feed).unwrap();
    assert!(!d.reset);
    assert!(d.upserts.is_empty());
    assert_eq!(d.removed, vec![join_record_id(&ORG, &a1)]);
    let d = s.join_requests_since(&mut feed).unwrap();
    assert!(d.removed.is_empty());
}

#[test]
fn join_feed_rewrite_is_an_upsert() {
    let (_f, mut s) = setup();
    let a1 = [1; 16];
    s.put_join_request(a1, b"old".to_vec()).unwrap();
    let mut feed = ChangeFeed::full();
    s.join_requests_since(&mut feed).unwrap();
    s.put_join_request(a1, b"new".to_vec()).unwrap();
    s.put_join_request(a1, b"newer".to_vec()).unwrap();
    let d = s.join_requests_since(&mut feed).unwrap();
    assert_eq!(d.upserts, vec![(a1, b"newer".to_vec())]);
    assert!(d.removed.is_empty() && !d.reset);
}

#[test]
fn join_feed_delete_then_repost_is_an_upsert_only() {
    let (_f, mut s) = setup();
    let a1 = [1; 16];
    s.put_join_request(a1, b"old".to_vec()).unwrap();
    let mut feed = ChangeFeed::full();
    s.join_requests_since(&mut feed).unwrap();
    s.delete_join_request(a1).unwrap();
    s.put_join_request(a1, b"again".to_vec()).unwrap();
    let d = s.join_requests_since(&mut feed).unwrap();
    assert_eq!(d.upserts, vec![(a1, b"again".to_vec())]);
    assert!(d.removed.is_empty());
}

#[test]
fn join_feed_restarts_full_on_a_new_incarnation() {
    let (_f, mut s) = setup();
    s.put_join_request([1; 16], b"r1".to_vec()).unwrap();
    let mut feed = ChangeFeed::full();
    s.join_requests_since(&mut feed).unwrap();
    let wrong = feed.incarnation().unwrap() + 1;
    let mut stale = ChangeFeed::incremental(feed.after(), wrong);
    let d = s.join_requests_since(&mut stale).unwrap();
    assert!(d.reset);
    assert_eq!(d.upserts, vec![([1; 16], b"r1".to_vec())]);
    assert_eq!(stale.incarnation(), feed.incarnation());
    assert!(!stale.is_full());
}

#[test]
fn join_feed_ignores_other_kinds() {
    let (_f, mut s) = setup();
    let mut feed = ChangeFeed::full();
    s.join_requests_since(&mut feed).unwrap();
    s.put_roster(1, b"r".to_vec()).unwrap();
    let d = s.join_requests_since(&mut feed).unwrap();
    assert!(d.upserts.is_empty() && d.removed.is_empty() && !d.reset);
}

#[test]
fn trait_reaches_the_mailbox_and_member_invites() {
    let fake = FakeMailbox::org();
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(Some(b"org invite"), b"org").unwrap();
    let mut s = OrgStore::new(c, ORG);
    let api: &mut dyn OrgStoreApi = &mut s;
    assert!(api.mailbox().info().is_ok());
    let key = Credential::generate().unwrap().public_key().to_bytes();
    api.mailbox()
        .grant(key, CredentialRole::Write, None, b"x")
        .unwrap();
    assert_eq!(api.mailbox().info().unwrap().usage.credentials, 2);
    assert_eq!(api.create_member_invite(24).unwrap().len(), 32);
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

/// An invitee holds a Write credential limited to kind 32. Its join request
/// is larger than INLINE_MAX (a genesis carries an SLH-DSA signature), so it
/// travels as a blob; a manager reads it back. The limited writer still puts
/// no other kind and deletes nothing.
#[test]
fn limited_writer_posts_a_blob_join_request() {
    let (fake, owner) = setup();
    let cred = Credential::generate().unwrap();
    owner
        .api()
        .grant(
            cred.public_key().to_bytes(),
            CredentialRole::Write,
            Some(put_kinds_of(&[ORG_JOIN_KIND])),
            b"invitee",
        )
        .unwrap();
    let mut c = fake.client(cred);
    c.open(owner.api().mailbox().unwrap());
    let mut invitee = OrgStore::new(c, ORG);
    let account = [0x05; 16];
    let request = bytes(40 * 1024, 9);
    assert!(request.len() > onepass_mailbox_proto::INLINE_MAX);
    invitee.put_join_request(account, request.clone()).unwrap();
    // Replacing it (a retry, a new request) works the same way.
    invitee.put_join_request(account, request.clone()).unwrap();
    let mut manager = owner;
    assert_eq!(
        manager.join_requests().unwrap(),
        vec![(account, request.clone())]
    );
    // The announce binds nothing: any other kind, and any delete, is refused.
    assert!(matches!(
        invitee.put_owner_keyset(account, bytes(20 * 1024, 1)),
        Err(OrgStoreError::Mailbox(MailboxError::Forbidden))
    ));
    assert!(matches!(
        invitee.delete_join_request(account),
        Err(OrgStoreError::Mailbox(MailboxError::Forbidden))
    ));
    assert_eq!(manager.join_requests().unwrap(), vec![(account, request)]);
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

/// A mailbox whose feed never ends: every `changes` answers an empty page
/// with `more = true`. Everything else goes to the real fake. Panics past
/// 10 000 calls so a missing bound fails instead of hanging.
struct EndlessFeed {
    inner: FakeMailboxClient,
    calls: Arc<AtomicUsize>,
}

impl MailboxApi for EndlessFeed {
    fn server_config(&self) -> Result<ServerConfig, MailboxError> {
        self.inner.server_config()
    }
    fn create(
        &mut self,
        invite: Option<&[u8]>,
        label: &[u8],
    ) -> Result<MailboxCreated, MailboxError> {
        self.inner.create(invite, label)
    }
    fn open(&mut self, mailbox: MailboxId) {
        self.inner.open(mailbox)
    }
    fn mailbox(&self) -> Option<MailboxId> {
        self.inner.mailbox()
    }
    fn credential_key(&self) -> onepass_mailbox::CredentialKey {
        self.inner.credential_key()
    }
    fn info(&self) -> Result<MailboxInfo, MailboxError> {
        self.inner.info()
    }
    fn changes(&self, after: u64, _limit: u32, _full: bool) -> Result<ChangesPage, MailboxError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        assert!(n <= 10_000, "join_requests never stopped reading pages");
        Ok(ChangesPage {
            incarnation: 1,
            min_cursor: 0,
            head: after,
            records: Vec::new(),
            next_after: after,
            more: true,
        })
    }
    fn commit(&self, ops: Vec<CommitOp>) -> Result<CommitResponse, MailboxError> {
        self.inner.commit(ops)
    }
    fn record(&self, kind: u8, id: [u8; 16]) -> Result<Option<ServerRecord>, MailboxError> {
        self.inner.record(kind, id)
    }
    fn enroll(&mut self, ticket: &SignedEnrollTicket, label: &[u8]) -> Result<(), MailboxError> {
        self.inner.enroll(ticket, label)
    }
    fn revoke(&self, credential: CredentialId) -> Result<(), MailboxError> {
        self.inner.revoke(credential)
    }
    fn grant(
        &self,
        public_key: [u8; 32],
        role: CredentialRole,
        put_kinds: Option<[u8; 32]>,
        label: &[u8],
    ) -> Result<CredentialId, MailboxError> {
        self.inner.grant(public_key, role, put_kinds, label)
    }
    fn set_role(
        &self,
        credential: CredentialId,
        role: CredentialRole,
        put_kinds: Option<[u8; 32]>,
    ) -> Result<(), MailboxError> {
        self.inner.set_role(credential, role, put_kinds)
    }
    fn set_push(&self, kind: PushKind, token: &[u8]) -> Result<(), MailboxError> {
        self.inner.set_push(kind, token)
    }
    fn set_push_target(
        &self,
        tag: [u8; 16],
        kind: PushKind,
        token: &[u8],
    ) -> Result<(), MailboxError> {
        self.inner.set_push_target(tag, kind, token)
    }
    fn set_locator(&self, locator: [u8; 16]) -> Result<(), MailboxError> {
        self.inner.set_locator(locator)
    }
    fn abandon(&self) -> Result<(), MailboxError> {
        self.inner.abandon()
    }
    fn create_child(
        &self,
        kind: ChildKind,
        owner_public_key: [u8; 32],
        label: &[u8],
    ) -> Result<MailboxCreated, MailboxError> {
        self.inner.create_child(kind, owner_public_key, label)
    }
    fn create_org_invite(&self, uses: u16, ttl_hours: u16) -> Result<Vec<u8>, MailboxError> {
        self.inner.create_org_invite(uses, ttl_hours)
    }
    fn issue_ticket(
        &self,
        new_credential_pub: onepass_mailbox::CredentialKey,
        now: i64,
    ) -> Result<SignedEnrollTicket, MailboxError> {
        self.inner.issue_ticket(new_credential_pub, now)
    }
    fn upload_blobs(&self, blobs: &[&[u8]]) -> Result<(), MailboxError> {
        self.inner.upload_blobs(blobs)
    }
    fn fetch_body(&self, body: &Body) -> Result<Vec<u8>, MailboxError> {
        self.inner.fetch_body(body)
    }
}

#[test]
fn join_requests_stops_on_an_endless_feed() {
    let fake = FakeMailbox::with_limits(org_plan());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut s = OrgStore::new(
        EndlessFeed {
            inner: fake.client(Credential::generate().unwrap()),
            calls: calls.clone(),
        },
        ORG,
    );
    assert!(matches!(
        s.join_requests(),
        Err(OrgStoreError::Mailbox(MailboxError::Malformed(_)))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), ORG_FEED_PAGES_MAX);
}

#[test]
fn put_roster_blob_retry_after_lost_reply_is_ok() {
    let (fake, mut s) = setup();
    let data = bytes(20 * 1024, 5);
    fake.faults().drop_commit_reply();
    assert!(s.put_roster(4, data.clone()).is_err());
    assert_eq!(s.put_roster(4, data.clone()), Ok(()));
    assert_eq!(s.roster(4).unwrap(), Some(data));
}
