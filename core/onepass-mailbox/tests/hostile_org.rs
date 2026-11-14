//! `HostileOrgStore` over an honest `OrgStore`: each lie, and the writes
//! that pass through untouched.

use onepass_mailbox::testing::hostile_org::HostileOrgStore;
use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient, org_plan};
use onepass_mailbox::{Credential, MailboxApi, OrgStore, OrgStoreApi};

const ORG: [u8; 16] = [5; 16];

type Hostile = HostileOrgStore<OrgStore<FakeMailboxClient>>;

fn setup() -> (FakeMailbox, Hostile) {
    let fake = FakeMailbox::with_limits(org_plan());
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(None, b"org").unwrap();
    let mut h = HostileOrgStore::new(OrgStore::new(c, ORG));
    for g in 0..=2u8 {
        h.put_lineage(u64::from(g), vec![b'l', g]).unwrap();
    }
    for s in 1..=3u8 {
        h.put_roster(u64::from(s), vec![b'r', s]).unwrap();
    }
    (fake, h)
}

fn l(g: u8) -> (u64, Vec<u8>) {
    (u64::from(g), vec![b'l', g])
}

fn r(s: u8) -> Vec<u8> {
    vec![b'r', s]
}

#[test]
fn honest_by_default() {
    let (_f, mut h) = setup();
    assert_eq!(h.lineage_from(0).unwrap(), vec![l(0), l(1), l(2)]);
    assert_eq!(h.latest_roster().unwrap(), Some((3, r(3))));
    assert_eq!(h.roster(2).unwrap(), Some(r(2)));
    assert_eq!(h.inner().latest_roster().unwrap(), Some((3, r(3))));
}

#[test]
fn withhold_newest_roster_serves_seq_2() {
    let (_f, mut h) = setup();
    h.withhold_newest_roster();
    assert_eq!(h.latest_roster().unwrap(), Some((2, r(2))));
}

#[test]
fn withhold_newest_roster_with_one_roster_is_none() {
    let fake = FakeMailbox::with_limits(org_plan());
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(None, b"org").unwrap();
    let mut h = HostileOrgStore::new(OrgStore::new(c, ORG));
    h.withhold_newest_roster();
    assert_eq!(h.latest_roster().unwrap(), None);
    h.put_roster(1, r(1)).unwrap();
    assert_eq!(h.latest_roster().unwrap(), None);
}

#[test]
fn replay_roster_serves_the_old_one() {
    let (_f, mut h) = setup();
    h.replay_roster(1);
    assert_eq!(h.latest_roster().unwrap(), Some((1, r(1))));
}

#[test]
fn fork_roster_at_the_head() {
    let (_f, mut h) = setup();
    h.fork_roster(3, b"x".to_vec());
    assert_eq!(h.latest_roster().unwrap(), Some((3, b"x".to_vec())));
    assert_eq!(h.roster(3).unwrap(), Some(b"x".to_vec()));
    assert_eq!(h.roster(2).unwrap(), Some(r(2)));
}

#[test]
fn fork_roster_ahead() {
    let (_f, mut h) = setup();
    h.fork_roster(4, b"y".to_vec());
    assert_eq!(h.latest_roster().unwrap(), Some((4, b"y".to_vec())));
    assert_eq!(h.roster(4).unwrap(), Some(b"y".to_vec()));
}

#[test]
fn fork_roster_behind_leaves_latest_alone() {
    let (_f, mut h) = setup();
    h.fork_roster(1, b"z".to_vec());
    assert_eq!(h.latest_roster().unwrap(), Some((3, r(3))));
    assert_eq!(h.roster(1).unwrap(), Some(b"z".to_vec()));
}

#[test]
fn fork_lineage_replaces_one_record() {
    let (_f, mut h) = setup();
    h.fork_lineage(1, b"z".to_vec());
    assert_eq!(
        h.lineage_from(0).unwrap(),
        vec![l(0), (1, b"z".to_vec()), l(2)]
    );
    assert_eq!(h.lineage_from(2).unwrap(), vec![l(2)]);
}

#[test]
fn withhold_lineage_from_truncates() {
    let (_f, mut h) = setup();
    h.withhold_lineage_from(1);
    assert_eq!(h.lineage_from(0).unwrap(), vec![l(0)]);
    assert_eq!(h.lineage_from(1).unwrap(), vec![]);
}

#[test]
fn drop_join_requests() {
    let (_f, mut h) = setup();
    h.put_join_request([1; 16], b"a".to_vec()).unwrap();
    h.put_join_request([2; 16], b"b".to_vec()).unwrap();
    assert_eq!(h.join_requests().unwrap().len(), 2);
    h.drop_join_request([1; 16]);
    assert_eq!(h.join_requests().unwrap(), vec![([2; 16], b"b".to_vec())]);
    h.drop_all_join_requests();
    assert!(h.join_requests().unwrap().is_empty());
}

#[test]
fn writes_pass_through() {
    let (_f, mut h) = setup();
    h.withhold_newest_roster();
    h.replay_roster(1);
    h.fork_roster(4, b"y".to_vec());
    h.fork_lineage(1, b"z".to_vec());
    h.withhold_lineage_from(1);
    h.drop_all_join_requests();
    h.put_roster(4, b"w".to_vec()).unwrap();
    h.put_lineage(3, b"l3".to_vec()).unwrap();
    h.put_join_request([9; 16], b"j".to_vec()).unwrap();
    h.put_owner_keyset([8; 16], b"k".to_vec()).unwrap();
    assert_eq!(h.inner().roster(4).unwrap(), Some(b"w".to_vec()));
    assert_eq!(
        h.inner().lineage_from(3).unwrap(),
        vec![(3, b"l3".to_vec())]
    );
    assert_eq!(h.inner().join_requests().unwrap().len(), 1);
    assert_eq!(h.owner_keyset([8; 16]).unwrap(), Some(b"k".to_vec()));
    h.delete_join_request([9; 16]).unwrap();
    assert!(h.inner().join_requests().unwrap().is_empty());
}

#[test]
fn honest_disarms() {
    let (_f, mut h) = setup();
    h.withhold_newest_roster();
    h.replay_roster(1);
    h.fork_roster(3, b"x".to_vec());
    h.fork_lineage(1, b"z".to_vec());
    h.withhold_lineage_from(2);
    h.drop_all_join_requests();
    h.honest();
    assert_eq!(h.lineage_from(0).unwrap(), vec![l(0), l(1), l(2)]);
    assert_eq!(h.latest_roster().unwrap(), Some((3, r(3))));
    assert_eq!(h.roster(3).unwrap(), Some(r(3)));
    h.put_join_request([1; 16], b"a".to_vec()).unwrap();
    assert_eq!(h.join_requests().unwrap().len(), 1);
}

#[test]
fn withhold_newest_roster_reaches_seq_0() {
    let fake = FakeMailbox::with_limits(org_plan());
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(None, b"org").unwrap();
    let mut h = HostileOrgStore::new(OrgStore::new(c, ORG));
    h.put_roster(0, r(0)).unwrap();
    h.withhold_newest_roster();
    assert_eq!(h.latest_roster().unwrap(), None);
    h.put_roster(1, r(1)).unwrap();
    assert_eq!(h.latest_roster().unwrap(), Some((0, r(0))));
}
