//! Org-minted invites against the in-memory mailbox: a manager of an org
//! mailbox mints one-use invites of plan `managed`, and a member's device
//! creates its own account mailbox with one (`api_org_invite` of
//! 20261113130000_mailbox_org_invites.sql).

use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient, managed_plan, org_plan};
use onepass_mailbox::{Credential, MailboxApi, MailboxError, OrgStore, OrgStoreError};
use onepass_mailbox_proto::{ChildKind, CredentialRole, ErrorCode};

const ORG: [u8; 16] = [7; 16];

/// An org server and the client of the org mailbox's creator (a manager).
fn org() -> (FakeMailbox, FakeMailboxClient) {
    let fake = FakeMailbox::org();
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(Some(b"org invite"), b"org").unwrap();
    (fake, c)
}

/// A credential granted `role` in the mailbox `by` has open.
fn granted(fake: &FakeMailbox, by: &FakeMailboxClient, role: CredentialRole) -> FakeMailboxClient {
    let cred = Credential::generate().unwrap();
    by.grant(cred.public_key().to_bytes(), role, None, b"member")
        .unwrap();
    let mut c = fake.client(cred);
    c.open(by.mailbox().unwrap());
    c
}

/// A fresh device that creates its own mailbox with `token`.
fn member(fake: &FakeMailbox, token: &[u8]) -> Result<FakeMailboxClient, MailboxError> {
    let mut c = fake.client(Credential::generate().unwrap());
    c.create(Some(token), b"member").map(|_| c)
}

#[test]
fn org_server_mailboxes_are_on_plan_org() {
    let (_fake, o) = org();
    assert_eq!(o.info().unwrap().limits, org_plan());
}

#[test]
fn manager_mints_and_a_fresh_client_creates_a_managed_mailbox() {
    let (fake, o) = org();
    let token = o.create_org_invite(1, 24).unwrap();
    assert_eq!(token.len(), 32);
    let m = member(&fake, &token).unwrap();
    assert_eq!(m.info().unwrap().limits, managed_plan());
    assert_ne!(m.mailbox(), o.mailbox());
    // A granted manager mints too, and every token differs.
    let om = granted(&fake, &o, CredentialRole::Manage);
    let other = om.create_org_invite(1, 168).unwrap();
    assert_ne!(other, token);
    assert_eq!(
        member(&fake, &other).unwrap().info().unwrap().limits,
        managed_plan()
    );
}

#[test]
fn managed_plan_is_free_with_32_credentials() {
    let p = managed_plan();
    assert_eq!(p.max_bytes, 256 << 20);
    assert_eq!(p.max_records, 100_000);
    assert_eq!(p.max_credentials, 32);
    assert_eq!(p.req_per_min, 120);
    assert_eq!(p.max_commit_ops, 20_000);
}

#[test]
fn org_store_creates_a_member_invite() {
    let (fake, o) = org();
    let mut store = OrgStore::new(o, ORG);
    let token = store.create_member_invite(72).unwrap();
    assert_eq!(
        member(&fake, &token).unwrap().info().unwrap().limits,
        managed_plan()
    );
    // A ttl outside 1 to 168 hours never leaves the client.
    for ttl in [0, 169] {
        assert_eq!(
            store.create_member_invite(ttl),
            Err(OrgStoreError::Mailbox(MailboxError::Malformed("request")))
        );
    }
}

#[test]
fn token_single_use() {
    let (fake, o) = org();
    let token = o.create_org_invite(1, 24).unwrap();
    member(&fake, &token).unwrap();
    assert_eq!(
        member(&fake, &token).err(),
        Some(MailboxError::Server(ErrorCode::NotFound))
    );
}

#[test]
fn uses_other_than_one_and_bad_ttl_are_refused_before_sending() {
    let (_fake, o) = org();
    for (uses, ttl) in [(0, 24), (2, 24), (1, 0), (1, 169)] {
        assert_eq!(
            o.create_org_invite(uses, ttl),
            Err(MailboxError::Malformed("request")),
            "uses {uses} ttl {ttl}"
        );
    }
}

#[test]
fn non_org_mailbox_refused() {
    // An ordinary server: its mailboxes are not on plan org.
    let fake = FakeMailbox::new();
    let mut a = fake.client(Credential::generate().unwrap());
    a.create(None, b"account").unwrap();
    assert_eq!(a.create_org_invite(1, 24), Err(MailboxError::Forbidden));
    // Nor is a managed mailbox on the org server.
    let (fake, o) = org();
    let m = member(&fake, &o.create_org_invite(1, 24).unwrap()).unwrap();
    assert_eq!(m.create_org_invite(1, 24), Err(MailboxError::Forbidden));
}

#[test]
fn child_refused() {
    let (fake, o) = org();
    let m = member(&fake, &o.create_org_invite(1, 24).unwrap()).unwrap();
    let owner = Credential::generate().unwrap();
    let child = m
        .create_child(ChildKind::Shared, owner.public_key().to_bytes(), b"vault")
        .unwrap();
    let mut c = fake.client(owner);
    c.open(child.mailbox_id);
    assert_eq!(c.create_org_invite(1, 24), Err(MailboxError::Forbidden));
}

#[test]
fn org_mailbox_holds_no_child() {
    // Plan org caps live children at 0 of each kind.
    let (_fake, o) = org();
    let owner = Credential::generate().unwrap().public_key().to_bytes();
    assert_eq!(
        o.create_child(ChildKind::Shared, owner, b"vault").err(),
        Some(MailboxError::Server(ErrorCode::Quota))
    );
}

#[test]
fn role_1_and_2_refused() {
    let (fake, o) = org();
    for role in [CredentialRole::Read, CredentialRole::Write] {
        let c = granted(&fake, &o, role);
        assert_eq!(
            c.create_org_invite(1, 24),
            Err(MailboxError::Forbidden),
            "{role:?}"
        );
    }
}

#[test]
fn revoked_manager_refused() {
    let (fake, o) = org();
    let om = granted(&fake, &o, CredentialRole::Manage);
    o.revoke(om.credential_key().id()).unwrap();
    assert_eq!(
        om.create_org_invite(1, 24),
        Err(MailboxError::Server(ErrorCode::RevokedCredential))
    );
}

#[test]
fn the_201st_of_a_day_is_refused() {
    let (fake, o) = org();
    for _ in 0..200 {
        o.create_org_invite(1, 1).unwrap();
    }
    match o.create_org_invite(1, 1) {
        Err(MailboxError::Retry { after: Some(s) }) => assert!((1..=86_400).contains(&s)),
        other => panic!("201st: {other:?}"),
    }
    // The count is the org mailbox's own.
    let (_fake2, o2) = {
        let mut c = fake.client(Credential::generate().unwrap());
        c.create(Some(b"second org"), b"org 2").unwrap();
        (fake.clone(), c)
    };
    o2.create_org_invite(1, 1).unwrap();
}

#[test]
fn forwarded_through_a_box() {
    let (fake, o) = org();
    let boxed: Box<dyn MailboxApi> = Box::new(o);
    let token = boxed.create_org_invite(1, 24).unwrap();
    member(&fake, &token).unwrap();
}
