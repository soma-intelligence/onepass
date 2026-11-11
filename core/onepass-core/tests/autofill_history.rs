//! The device's autofill history: sealed rows in the SyncStore file, the
//! learned order per browser profile, the switch, clear, forget a site,
//! retention and caps, a database from before the table, and nothing on
//! the sync outbox.

mod common;

use common::*;
use onepass_core::autofill_history::{
    AutofillAction, AutofillEvent, BrowserKind, ClientContext, EventSource, MAX_PER_SITE,
    RETENTION_DAYS,
};
use onepass_core::fill_plan::score::{
    Candidate, CandidateKind, MatchQuality, Tiebreak, UsageSignal, order,
};

fn client(profile: &str) -> ClientContext {
    ClientContext {
        browser: BrowserKind::Chrome,
        profile_id: Some(profile.into()),
        profile_name: Some(format!("Profile {profile}")),
    }
}

fn event(item: Id, action: AutofillAction, c: &ClientContext, when: i64) -> AutofillEvent {
    AutofillEvent {
        at: at(when),
        action,
        source: EventSource::Extension,
        site: "example.com".into(),
        item_id: Some(item),
        rank: Some(0),
        shown: vec![],
        client: c.clone(),
        device_id: None,
    }
}

fn cand(item: Id, usage: Option<UsageSignal>, affinity: i64) -> Candidate {
    Candidate {
        item_id: item,
        kind: CandidateKind::Login,
        quality: MatchQuality::Exact,
        favorite: false,
        updated_at: 0,
        title: "same".into(),
        username_hash: None,
        usage,
        has_totp: false,
        affinity,
        private_vault: true,
    }
}

fn rows(dev: &Device) -> Vec<(Vec<u8>, Vec<u8>)> {
    let conn = rusqlite::Connection::open(&dev.path).unwrap();
    let mut stmt = conn
        .prepare("SELECT site_tag, data FROM autofill_events ORDER BY seq")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn work_profile_learns_its_account_and_rows_are_sealed() {
    let (mut dev, _sk) = Device::create();
    let (work_acct, home_acct) = (Id::new(), Id::new());
    let (work, home) = (client("work-1"), client("home-2"));
    assert!(dev.repo().autofill_history_enabled().unwrap());
    for t in 0..2 {
        assert!(
            dev.repo()
                .record_autofill_event(event(work_acct, AutofillAction::Picked, &work, T0 + t))
                .unwrap()
        );
    }
    dev.repo()
        .record_autofill_event(event(home_acct, AutofillAction::Picked, &home, T0 + 10))
        .unwrap();
    // The home account was used last on the site (any profile).
    let last = Some(UsageSignal {
        last_on_site: true,
        same_shape: false,
        count: 1,
        last_at: T0 + 10,
    });
    let now = at(T0 + 20);
    let rank = |dev: &mut Device, c: &ClientContext| -> Id {
        let aff = dev.repo().autofill_affinity("example.com", c, now).unwrap();
        let get = |id: Id| aff.get(&id).copied().unwrap_or(0);
        let mut v = vec![
            cand(home_acct, last, get(home_acct)),
            cand(work_acct, None, get(work_acct)),
        ];
        order(&mut v, None, T0 + 20, Tiebreak::Title);
        v[0].item_id
    };
    assert_eq!(rank(&mut dev, &work), work_acct);
    assert_eq!(rank(&mut dev, &home), home_acct);

    // On disk: neither the site nor the profile in clear, and the events
    // survive a lock and an unlock.
    let raw = rows(&dev);
    assert_eq!(raw.len(), 3);
    for (tag, data) in &raw {
        assert_eq!(tag.len(), 32);
        for needle in ["example.com", "work-1", "Profile work"] {
            assert!(!String::from_utf8_lossy(data).contains(needle));
            assert!(!String::from_utf8_lossy(tag).contains(needle));
        }
    }
    let evs = dev
        .repo()
        .autofill_events_for_site("example.com", now)
        .unwrap();
    assert_eq!(evs.len(), 3);
    assert_eq!(evs[0].client, work);
    // Device-local: nothing for the server.
    let before = outbox(&dev).len();
    dev.repo()
        .record_autofill_event(event(work_acct, AutofillAction::Filled, &work, T0 + 30))
        .unwrap();
    assert_eq!(outbox(&dev).len(), before);
}

#[test]
fn switch_off_erases_and_stops_recording() {
    let (mut dev, _sk) = Device::create();
    let c = client("p");
    let item = Id::new();
    dev.repo()
        .record_autofill_event(event(item, AutofillAction::Picked, &c, T0))
        .unwrap();
    assert_eq!(dev.repo().autofill_history_count().unwrap(), 1);
    dev.repo().set_autofill_history_enabled(false).unwrap();
    assert!(!dev.repo().autofill_history_enabled().unwrap());
    assert_eq!(dev.repo().autofill_history_count().unwrap(), 0);
    assert!(
        !dev.repo()
            .record_autofill_event(event(item, AutofillAction::Picked, &c, T0 + 1))
            .unwrap()
    );
    assert!(
        dev.repo()
            .autofill_affinity("example.com", &c, at(T0 + 2))
            .unwrap()
            .is_empty()
    );
    assert!(rows(&dev).is_empty());
    // The switch is per device and survives a reopen.
    let sk = _sk;
    dev.lock();
    dev.unlock(&sk);
    assert!(!dev.repo().autofill_history_enabled().unwrap());
    dev.repo().set_autofill_history_enabled(true).unwrap();
    assert!(
        dev.repo()
            .record_autofill_event(event(item, AutofillAction::Picked, &c, T0 + 3))
            .unwrap()
    );
}

#[test]
fn clear_and_forget_site() {
    let (mut dev, _sk) = Device::create();
    let c = client("p");
    let item = Id::new();
    dev.repo()
        .record_autofill_event(event(item, AutofillAction::Picked, &c, T0))
        .unwrap();
    let mut other = event(item, AutofillAction::Picked, &c, T0);
    other.site = "other.org".into();
    dev.repo().record_autofill_event(other).unwrap();
    assert_eq!(dev.repo().forget_site_usage("example.com").unwrap(), 0);
    let now = at(T0 + 1);
    assert!(
        dev.repo()
            .autofill_events_for_site("example.com", now)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        dev.repo()
            .autofill_events_for_site("other.org", now)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(dev.repo().clear_autofill_history().unwrap(), 1);
    assert_eq!(dev.repo().autofill_history_count().unwrap(), 0);
}

#[test]
fn retention_and_caps() {
    let (mut dev, _sk) = Device::create();
    let c = client("p");
    let item = Id::new();
    dev.repo()
        .record_autofill_event(event(item, AutofillAction::Picked, &c, T0))
        .unwrap();
    // Past the retention: not read, and deleted on the way.
    let late = at(T0 + (RETENTION_DAYS + 1) * 86_400);
    assert!(
        dev.repo()
            .autofill_events_for_site("example.com", late)
            .unwrap()
            .is_empty()
    );
    assert!(rows(&dev).is_empty());
    for t in 0..(MAX_PER_SITE as i64 + 5) {
        dev.repo()
            .record_autofill_event(event(item, AutofillAction::Shown, &c, T0 + t))
            .unwrap();
    }
    let evs = dev
        .repo()
        .autofill_events_for_site("example.com", at(T0 + 1000))
        .unwrap();
    assert_eq!(evs.len(), MAX_PER_SITE);
    // The oldest went first.
    assert_eq!(evs[0].at, at(T0 + 5));
}

#[test]
fn invalid_events_are_refused() {
    let (mut dev, _sk) = Device::create();
    let mut e = event(Id::new(), AutofillAction::Picked, &client("p"), T0);
    e.client.profile_id = Some("not opaque!".into());
    assert!(matches!(
        dev.repo().record_autofill_event(e),
        Err(Error::Validation(_))
    ));
    assert_eq!(dev.repo().autofill_history_count().unwrap(), 0);
}

/// A device file from before the table opens, gains it, keeps its rows.
#[test]
fn database_from_before_the_table_opens() {
    let (mut dev, sk) = Device::create();
    dev.lock();
    {
        let conn = rusqlite::Connection::open(&dev.path).unwrap();
        conn.execute_batch("DROP INDEX autofill_events_site; DROP TABLE autofill_events;")
            .unwrap();
    }
    dev.unlock(&sk);
    dev.repo()
        .record_autofill_event(event(Id::new(), AutofillAction::Picked, &client("p"), T0))
        .unwrap();
    assert_eq!(rows(&dev).len(), 1);
}

/// Rows sealed under another account's keys never open: dropped.
#[test]
fn rows_of_another_keyset_are_dropped() {
    let (mut a, _ska) = Device::create();
    let (mut b, _skb) = Device::create();
    let c = client("p");
    a.repo()
        .record_autofill_event(event(Id::new(), AutofillAction::Picked, &c, T0))
        .unwrap();
    // A's rows copied into B's file: B cannot open them and drops them.
    let raw = rows(&a);
    {
        let conn = rusqlite::Connection::open(&b.path).unwrap();
        for (tag, data) in &raw {
            conn.execute(
                "INSERT INTO autofill_events (site_tag, data) VALUES (?1, ?2)",
                rusqlite::params![tag, data],
            )
            .unwrap();
        }
    }
    assert_eq!(b.repo().prune_autofill_history(at(T0)).unwrap(), 1);
    assert!(rows(&b).is_empty());
}
