//! The harness the sync tests share: devices from the core's two-device
//! harness, a transport a test can tamper with, and a device with its
//! driver on an in-memory mailbox.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::common::*;
use onepass_core::synchome::SyncBackend;
use onepass_mailbox::testing::{FakeMailbox, FakeMailboxClient};
use onepass_mailbox::{Credential, MailboxApi};
use onepass_sync::{
    BatchLimits, MailboxTransport, Outgoing, Page, RoundHooks, RoundReport, RoundStatus,
    SendResult, SyncDriver, Transport, TransportError,
};
pub const NOW: i64 = 1_790_000_000;
pub const URL: &str = "https://mailbox.example.org/functions/v1/mailbox";

// ---------------------------------------------------------------- tamper

/// What a test makes the transport do on top of the mailbox.
#[derive(Default)]
pub struct Tamper {
    /// Added to the next page.
    pub inject: Vec<RemoteChange>,
    /// The next fetch calls fail with these, in order.
    pub fail_fetch: VecDeque<TransportError>,
    /// The fetch with this ordinal (`fetches` once counted) fails.
    pub fail_on_fetch: Option<(usize, TransportError)>,
    /// The sends after this many succeed fail with `Offline`.
    pub sends_before_offline: Option<usize>,
    /// Runs once, right before the next send.
    pub before_send: Option<Box<dyn FnOnce()>>,
    /// Saved writes come back without server meta.
    pub strip_meta: bool,
    pub limits: Option<BatchLimits>,
    /// Every batch sent: kind and whether it is a write.
    pub batches: Vec<Vec<(RecordKind, Id, bool)>>,
    pub results: Vec<Vec<SendResult>>,
    pub fetches: usize,
}

pub struct Tampered {
    pub inner: MailboxTransport<FakeMailboxClient>,
    pub t: Rc<RefCell<Tamper>>,
}

impl Transport for Tampered {
    fn binding(&mut self) -> std::result::Result<u64, TransportError> {
        self.inner.binding()
    }

    fn fetch(&mut self, cursor: Option<&[u8]>) -> std::result::Result<Page, TransportError> {
        let mut t = self.t.borrow_mut();
        t.fetches += 1;
        if let Some(e) = t.fail_fetch.pop_front() {
            return Err(e);
        }
        if let Some((n, e)) = &t.fail_on_fetch
            && *n == t.fetches
        {
            return Err(e.clone());
        }
        let mut page = self.inner.fetch(cursor)?;
        page.changes.append(&mut t.inject);
        Ok(page)
    }

    fn send(&mut self, batch: &[Outgoing]) -> std::result::Result<Vec<SendResult>, TransportError> {
        let hook = self.t.borrow_mut().before_send.take();
        if let Some(hook) = hook {
            hook();
        }
        let mut t = self.t.borrow_mut();
        if let Some(n) = t.sends_before_offline {
            if n == 0 {
                return Err(TransportError::Offline);
            }
            t.sends_before_offline = Some(n - 1);
        }
        t.batches.push(
            batch
                .iter()
                .map(|o| (o.change.kind, o.change.id, o.change.data.is_some()))
                .collect(),
        );
        let mut results = self.inner.send(batch)?;
        if t.strip_meta {
            for r in &mut results {
                if let SendResult::Saved { server_meta, .. } = r {
                    *server_meta = None;
                }
            }
        }
        t.results.push(results.clone());
        Ok(results)
    }

    fn limits(&self) -> BatchLimits {
        self.t.borrow().limits.unwrap_or(self.inner.limits())
    }

    fn unconfirmed(&mut self) -> Vec<(RecordKind, Id)> {
        self.inner.unconfirmed()
    }
}

// ---------------------------------------------------------------- sides

/// A device and its driver on the mailbox.
pub struct Side {
    pub dev: Device,
    pub driver: SyncDriver<Tampered>,
    pub t: Rc<RefCell<Tamper>>,
    pub now: i64,
}

impl Side {
    pub fn new(dev: Device, client: FakeMailboxClient, home: SyncBackend) -> Side {
        let t = Rc::new(RefCell::new(Tamper::default()));
        let transport = Tampered {
            inner: MailboxTransport::new(client),
            t: t.clone(),
        };
        Side {
            dev,
            driver: SyncDriver::new(transport, home),
            t,
            now: NOW,
        }
    }

    /// One round, unlocked if the device is.
    pub fn round(&mut self) -> RoundReport {
        let mut store = self.dev.store();
        let hooks = self.dev.repo.as_mut().map(|r| r as &mut dyn RoundHooks);
        self.now += 60;
        self.driver.run_round(&mut store, hooks, self.now)
    }

    /// Rounds until one is idle (five at most).
    pub fn settle(&mut self) -> RoundReport {
        for _ in 0..5 {
            let r = self.round();
            if r.status == RoundStatus::Idle && !r.rerun {
                return r;
            }
        }
        panic!("no idle round: {:?}", self.round());
    }

    pub fn pending(&self) -> Vec<Change> {
        self.dev.store().pending_changes().unwrap()
    }
}

pub fn home_of(client: &FakeMailboxClient) -> SyncBackend {
    SyncBackend::Mailbox {
        url: URL.into(),
        mailbox_id: client.mailbox().unwrap(),
    }
}

/// The wall clock, Unix seconds (tickets are checked against it).
pub fn wall() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A mailbox, its owner's client and a second client enrolled by ticket.
pub fn mailbox() -> (FakeMailbox, FakeMailboxClient, FakeMailboxClient) {
    let fake = FakeMailbox::new();
    let mut owner = fake.client(Credential::generate().unwrap());
    owner.create(None, b"a").unwrap();
    let mut second = fake.client(Credential::generate().unwrap());
    let ticket = owner.issue_ticket(second.credential_key(), wall()).unwrap();
    second.enroll(&ticket, b"b").unwrap();
    (fake, owner, second)
}

/// A creates the account with `users` and syncs; B, empty, syncs locked,
/// then unlocks.
pub fn two_sides(users: &[&str]) -> (FakeMailbox, Side, Side, SecretKey, Vec<Item>) {
    let (fake, ca, cb) = mailbox();
    let home = home_of(&ca);
    let (mut a, sk) = Device::create();
    let v = a.vault().id;
    let items: Vec<Item> = users
        .iter()
        .enumerate()
        .map(|(i, u)| login(v, u, 1_700_000_000 + i as i64))
        .collect();
    for i in &items {
        a.save(i);
    }
    let mut a = Side::new(a, ca, home.clone());
    assert_eq!(a.settle().status, RoundStatus::Idle);
    let mut b = Side::new(Device::empty(), cb, home);
    let r = b.round();
    assert_eq!(r.status, RoundStatus::Idle, "{r:?}");
    b.dev.unlock(&sk);
    (fake, a, b, sk, items)
}

// ---------------------------------------------------------------- tests
