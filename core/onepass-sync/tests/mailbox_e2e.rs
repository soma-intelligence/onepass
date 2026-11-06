//! The sync round against a real mailbox on a LOCAL Supabase stack (the
//! setup of `onepass-mailbox/tests/conformance_e2e.rs`):
//!
//!   ONEPASS_MAILBOX_E2E_URL     base URL of the function, for example
//!                               http://127.0.0.1:57421/functions/v1/mailbox
//!   ONEPASS_MAILBOX_E2E_INVITE  invite, when open signup is off
//!
//! Without ONEPASS_MAILBOX_E2E_URL each test prints why and passes.

#[path = "../../onepass-core/tests/common/mod.rs"]
mod common;

use common::*;
use onepass_core::synchome::SyncBackend;
use onepass_mailbox::{Credential, Endpoint, MailboxClient};
use onepass_sync::{MailboxTransport, RoundHooks, RoundStatus, SyncDriver};

struct Real {
    dev: Device,
    driver: SyncDriver<MailboxTransport<MailboxClient>>,
    now: i64,
}

impl Real {
    fn new(dev: Device, client: MailboxClient, url: &str) -> Real {
        let home = SyncBackend::Mailbox {
            url: url.into(),
            mailbox_id: client.mailbox().expect("a mailbox open"),
        };
        Real {
            dev,
            driver: SyncDriver::new(MailboxTransport::new(client), home),
            now: wall(),
        }
    }

    fn settle(&mut self) {
        for _ in 0..5 {
            let mut store = self.dev.store();
            let hooks = self.dev.repo.as_mut().map(|r| r as &mut dyn RoundHooks);
            self.now += 60;
            let r = self.driver.run_round(&mut store, hooks, self.now);
            if r.status == RoundStatus::Idle && !r.rerun {
                return;
            }
        }
        panic!("no idle round against the local mailbox");
    }
}

fn wall() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// The endpoint, or `None` (and why) when the stack is not set up.
fn endpoint() -> Option<(Endpoint, Option<Vec<u8>>)> {
    let Ok(url) = std::env::var("ONEPASS_MAILBOX_E2E_URL") else {
        println!("skipped: ONEPASS_MAILBOX_E2E_URL unset");
        return None;
    };
    let invite = std::env::var("ONEPASS_MAILBOX_E2E_INVITE")
        .ok()
        .map(String::into_bytes);
    Some((
        Endpoint {
            base_url: url,
            extra_ca_pem: None,
        },
        invite,
    ))
}

/// A creates the account and a mailbox, B is enrolled by ticket; A syncs
/// `users`, B syncs locked then unlocks.
fn two_real(users: &[&str]) -> Option<(Real, Real, Vec<Item>)> {
    let (endpoint, invite) = endpoint()?;
    let url = endpoint.base_url.clone();
    let mut ca = MailboxClient::new(endpoint.clone(), Credential::generate().unwrap()).unwrap();
    ca.create(invite.as_deref(), b"e2e a").expect("create");
    let mut cb = MailboxClient::new(endpoint, Credential::generate().unwrap()).unwrap();
    let ticket = ca.issue_ticket(cb.credential_key(), wall()).unwrap();
    cb.enroll(&ticket, b"e2e b").expect("enroll");

    let (mut a, sk) = Device::create();
    let v = a.vault().id;
    let items: Vec<Item> = users
        .iter()
        .enumerate()
        .map(|(i, u)| login(v, u, T0 + i as i64))
        .collect();
    for i in &items {
        a.save(i);
    }
    let mut a = Real::new(a, ca, &url);
    a.settle();
    let mut b = Real::new(Device::empty(), cb, &url);
    b.settle();
    b.dev.unlock(&sk);
    b.settle();
    Some((a, b, items))
}

#[test]
fn second_device_restores_through_remote() {
    let Some((mut a, mut b, items)) = two_real(&["alice", "bob"]) else {
        return;
    };
    assert_eq!(users(&b.dev.items()), users(&items));
    assert_eq!(b.dev.items(), a.dev.items());
    a.settle();
}

#[test]
fn concurrent_edits_converge_on_both_devices() {
    let Some((mut a, mut b, items)) = two_real(&["alice", "bob"]) else {
        return;
    };
    a.dev.save(&edited(&items[0], "alice2", T0 + 10));
    b.dev.save(&edited(&items[1], "bob2", T0 + 11));
    a.settle();
    b.settle();
    a.settle();
    assert_eq!(users(&a.dev.items()), ["alice2", "bob2"]);
    assert_eq!(a.dev.items(), b.dev.items());
}
