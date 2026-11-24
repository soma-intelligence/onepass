//! The Mac fill helper's client (spec 2026-11-23-mac-fill-anywhere,
//! `BridgeClient`): `DesktopFillClient` against the production bridge,
//! served over a real Unix socket by an in-process listener that admits
//! every connection as the fill helper (no code signature in tests).
//! Mac only: the socket admission of the fill helper is.
#![cfg(target_os = "macos")]

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use onepass_bridge::framing::{read_frame, write_frame};
use onepass_bridge::wire::{self, Envelope};
use onepass_ffi::*;
use tempfile::TempDir;

const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
const SLACK: &str = "com.tinyspeck.slackmacgap";
const ATLAS: &str = "https://atlas-cloud.test";
const PASSWORD: &str = "Slack-Pass-0042";
const USER: &str = "alex@atlas.dev";

#[derive(Debug, Clone, PartialEq)]
enum Event {
    /// Extension id and verified browser of a stored pairing.
    Stored(String, String),
    Requested,
    /// The first frame of a connection.
    Opening(Vec<u8>),
}

struct Delegate(Mutex<Sender<Event>>);

impl BridgeDelegate for Delegate {
    fn pairing_requested(&self, _request: FfiBridgePairingRequest) {
        let _ = self.0.lock().unwrap().send(Event::Requested);
    }
    fn pairing_ended(&self, _request_id: u64) {}
    fn pairing_stored(&self, p: FfiBridgePairing) {
        let _ = self
            .0
            .lock()
            .unwrap()
            .send(Event::Stored(p.extension_id, p.verified_browser));
    }
    fn pairing_used(&self, _pairing_id: String, _at: u64) {}
    fn unlock_requested(&self, _pairing_id: String, _origin_host: Option<String>) {}
    fn confirm_reprompt(
        &self,
        _slot: String,
        _vault_id: String,
        _item_id: String,
        _pairing_id: String,
        _origin_host: Option<String>,
    ) -> bool {
        false
    }
    fn fill_served(&self, _slot: String, _pairing_id: String, _kind: String) {}
    fn vault_changed(&self, _slot: String, _vault_id: Option<String>) {}
    fn note(&self, _message: String) {}
}

/// The helper's keychain item, in memory.
#[derive(Default)]
struct MemStore {
    record: Mutex<Option<Vec<u8>>>,
    saves: AtomicUsize,
}

impl FillPairingStore for MemStore {
    fn load(&self) -> Option<Vec<u8>> {
        self.record.lock().unwrap().clone()
    }
    fn save(&self, record: Vec<u8>) {
        self.saves.fetch_add(1, Ordering::SeqCst);
        *self.record.lock().unwrap() = Some(record);
    }
}

struct Rig {
    _dir: TempDir,
    server: Arc<BridgeServer>,
    session: Arc<Session>,
    events: Receiver<Event>,
    socket: PathBuf,
}

/// An unlocked account with the Slack login (an app entry for Slack and
/// the Atlas page), the bridge, and a listener on `<dir>/bridge.sock`.
fn rig() -> (Rig, String) {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(db, "Café-étoile".into(), FAST).unwrap();
    let (tx, events) = channel();
    let audit = dir.path().join("bridge-audit.jsonl");
    let server = BridgeServer::new(
        Arc::new(Delegate(Mutex::new(tx.clone()))),
        Vec::new(),
        Vec::new(),
        audit.to_string_lossy().into_owned(),
    );
    server.set_session(Some(created.session.clone()), USER.into());
    let item = slack_login(&created.session);
    let socket = dir.path().join("bridge.sock");
    listen(&server, &socket, tx);
    (
        Rig {
            _dir: dir,
            server,
            session: created.session,
            events,
            socket,
        },
        item,
    )
}

/// Serve every connection to `path` as the socket serves the admitted
/// fill helper, after reading its opening frame.
fn listen(server: &Arc<BridgeServer>, path: &std::path::Path, events: Sender<Event>) {
    let listener = UnixListener::bind(path).unwrap();
    let server = server.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let (server, events) = (server.clone(), events.clone());
            thread::Builder::new()
                .stack_size(16 << 20)
                .spawn(move || {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let Ok(Some(first)) = read_frame(&mut stream) else {
                        return;
                    };
                    let _ = events.send(Event::Opening(first));
                    stream.set_read_timeout(None).unwrap();
                    serve_fill_for_tests(&server, stream);
                })
                .unwrap();
        }
    });
}

fn slack_login(session: &Arc<Session>) -> String {
    let vault = session.vaults().unwrap()[0].id.clone();
    let mut item = session
        .new_item(vault, FfiItemType::Login, "Slack".into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "username" => f.value = FfiFieldValue::Text { value: USER.into() },
            "password" => {
                f.value = FfiFieldValue::Password {
                    value: PASSWORD.into(),
                }
            }
            _ => {}
        }
    }
    item.urls = vec![
        FfiUrl {
            label: "Slack".into(),
            url: format!("macapp://{SLACK}"),
            rule: FfiMatchRule::ExactHost,
            primary: true,
        },
        FfiUrl {
            label: String::new(),
            url: ATLAS.into(),
            rule: FfiMatchRule::Domain,
            primary: false,
        },
    ];
    session.save_item(item).unwrap().id
}

fn client(rig: &Rig, store: &Arc<MemStore>) -> Arc<DesktopFillClient> {
    DesktopFillClient::connect_for_tests(rig.socket.to_string_lossy().into_owned(), store.clone())
        .unwrap()
}

fn drain(events: &Receiver<Event>) -> Vec<Event> {
    thread::sleep(Duration::from_millis(100));
    events.try_iter().collect()
}

fn slack() -> FfiFillTarget {
    FfiFillTarget::App {
        bundle_id: SLACK.into(),
        app_name: Some("Slack".into()),
    }
}

#[test]
fn connects_and_pairs_once() {
    let (rig, _) = rig();
    let store = Arc::new(MemStore::default());
    let c = client(&rig, &store);
    assert_eq!(c.status().unwrap(), FfiFillStatus::Unlocked);
    assert_eq!(store.saves.load(Ordering::SeqCst), 1);
    let events = drain(&rig.events);
    assert_eq!(
        events[0],
        Event::Opening(br#"{"onepass_relay":1}"#.to_vec()),
        "{events:?}"
    );
    assert!(
        events.contains(&Event::Stored("fill".into(), "OnePass Fill".into())),
        "{events:?}"
    );
    assert!(!events.contains(&Event::Requested), "no pairing sheet");
    drop(c);

    // A second helper run reuses the stored record: no new pairing.
    let c = client(&rig, &store);
    assert_eq!(c.status().unwrap(), FfiFillStatus::Unlocked);
    assert_eq!(store.saves.load(Ordering::SeqCst), 1);
    let events = drain(&rig.events);
    assert!(
        events.iter().all(|e| matches!(e, Event::Opening(_))),
        "{events:?}"
    );
    assert_eq!(rig.server.pairings().len(), 1);
}

#[test]
fn revoked_pairing_pairs_again_and_saves_the_new_record() {
    let (rig, _) = rig();
    let store = Arc::new(MemStore::default());
    drop(client(&rig, &store));
    let first = store.load().unwrap();
    let id = rig.server.pairings()[0].pairing_id.clone();
    rig.server.forget_pairing(id.clone());

    let c = client(&rig, &store);
    assert_eq!(c.status().unwrap(), FfiFillStatus::Unlocked);
    assert_eq!(store.saves.load(Ordering::SeqCst), 2);
    assert_ne!(store.load().unwrap(), first);
    let pairings = rig.server.pairings();
    assert_eq!(pairings.len(), 1);
    assert_ne!(pairings[0].pairing_id, id);
}

#[test]
fn unreadable_record_pairs_again() {
    let (rig, _) = rig();
    let store = Arc::new(MemStore::default());
    *store.record.lock().unwrap() = Some(vec![0xff; 7]);
    let c = client(&rig, &store);
    assert_eq!(c.status().unwrap(), FfiFillStatus::Unlocked);
    assert_eq!(store.saves.load(Ordering::SeqCst), 1);
}

#[test]
fn lists_slack_for_bundle_id() {
    let (rig, item) = rig();
    let store = Arc::new(MemStore::default());
    let c = client(&rig, &store);
    let rows = c.list_for_app(SLACK.into(), Some("Slack".into())).unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].title, "Slack");
    assert_eq!(rows[0].subtitle, USER);
    assert_eq!(rows[0].match_quality, Some(FfiFillMatch::ExactHost));
    assert!(rows[0].has_password);
    assert_eq!(rows[0].item_id.replace('-', ""), item);

    // Another app with no entry and no title word gives nothing.
    let none = c.list_for_app("com.example.other".into(), None).unwrap();
    assert!(none.is_empty(), "{none:?}");

    // The page of a browser without the extension (same host as the
    // login's Atlas entry).
    let rows = c.list_for_url(ATLAS.into()).unwrap();
    assert_eq!(rows[0].title, "Slack", "{rows:?}");
    assert_eq!(rows[0].match_quality, Some(FfiFillMatch::ExactHost));
    let rows = c
        .list_for_url("https://login.atlas-cloud.test".into())
        .unwrap();
    assert_eq!(
        rows[0].match_quality,
        Some(FfiFillMatch::Domain),
        "{rows:?}"
    );
}

#[test]
fn fills_password_value() {
    let (rig, _) = rig();
    let store = Arc::new(MemStore::default());
    let c = client(&rig, &store);
    let row = c.list_for_app(SLACK.into(), None).unwrap().remove(0);
    let v = c
        .fill(slack(), row.item_id.clone(), FfiFillField::Password, false)
        .unwrap();
    assert_eq!(v.value(), PASSWORD);
    let v = c
        .fill(slack(), row.item_id.clone(), FfiFillField::Username, false)
        .unwrap();
    assert_eq!(v.value(), USER);
    // No one-time code on this login: nothing to fill.
    assert_eq!(
        c.fill(slack(), row.item_id.clone(), FfiFillField::Totp, false)
            .unwrap_err(),
        OnePassError::NotFound
    );

    // The key usage log names the app.
    let vault = rig.session.vaults().unwrap()[0].id.clone();
    let log = rig
        .session
        .item_key_uses(vault, row.item_id.replace('-', ""))
        .unwrap();
    assert!(!log.is_empty());
    assert!(
        log.iter()
            .all(|u| u.channel == FfiKeyUseChannel::DesktopFill && u.client == "Slack"),
        "{log:?}"
    );
}

#[test]
fn fill_with_remember_adds_the_app_entry() {
    let (rig, _) = rig();
    let store = Arc::new(MemStore::default());
    let c = client(&rig, &store);
    let row = c.list_for_url(ATLAS.into()).unwrap().remove(0);
    let other = FfiFillTarget::App {
        bundle_id: "com.example.atlas".into(),
        app_name: Some("Atlas".into()),
    };
    let v = c
        .fill(other, row.item_id.clone(), FfiFillField::Password, true)
        .unwrap();
    assert_eq!(v.value(), PASSWORD);
    let rows = c.list_for_app("com.example.atlas".into(), None).unwrap();
    assert_eq!(rows[0].item_id, row.item_id, "{rows:?}");
}

#[test]
fn url_target_fills_on_a_matching_page_only() {
    let (rig, _) = rig();
    let store = Arc::new(MemStore::default());
    let c = client(&rig, &store);
    let row = c.list_for_url(ATLAS.into()).unwrap().remove(0);
    let page = |url: &str| FfiFillTarget::Url {
        url: url.into(),
        app_name: Some("Arc".into()),
    };
    let v = c
        .fill(
            page(ATLAS),
            row.item_id.clone(),
            FfiFillField::Password,
            true,
        )
        .unwrap();
    assert_eq!(v.value(), PASSWORD);
    // Filled as the page's fill, logged under the browser's name; nothing
    // remembered.
    let vault = rig.session.vaults().unwrap()[0].id.clone();
    let log = rig
        .session
        .item_key_uses(vault.clone(), row.item_id.replace('-', ""))
        .unwrap();
    assert_eq!(
        (log[0].channel, log[0].client.as_str()),
        (FfiKeyUseChannel::DesktopFill, "Arc")
    );
    let urls = rig
        .session
        .item(vault, row.item_id.replace('-', ""))
        .unwrap()
        .urls;
    assert_eq!(urls.len(), 2, "{urls:?}");

    // The page changed between the list and the fill: no value.
    assert_eq!(
        c.fill(
            page("https://evil.test"),
            row.item_id.clone(),
            FfiFillField::Password,
            false
        )
        .unwrap_err(),
        OnePassError::Validation {
            field: "bridge".into(),
            reason: "origin_mismatch".into()
        }
    );
    let audit = std::fs::read_to_string(rig._dir.path().join("bridge-audit.jsonl")).unwrap();
    assert!(!audit.contains("evil.test"), "{audit}");
}

#[test]
fn locked_vault_asks_unlock() {
    let (rig, item) = rig();
    let store = Arc::new(MemStore::default());
    let c = client(&rig, &store);
    rig.session.lock();
    assert_eq!(c.status().unwrap(), FfiFillStatus::Locked);
    assert_eq!(
        c.list_for_app(SLACK.into(), None).unwrap_err(),
        OnePassError::Locked
    );
    assert_eq!(
        c.fill(slack(), item, FfiFillField::Password, false)
            .unwrap_err(),
        OnePassError::Locked
    );
}

#[test]
fn app_closed_reports_app_closed() {
    let dir = TempDir::new().unwrap();
    let path = dir
        .path()
        .join("bridge.sock")
        .to_string_lossy()
        .into_owned();
    let store = Arc::new(MemStore::default());
    let c = DesktopFillClient::connect_for_tests(path, store.clone()).unwrap();
    assert_eq!(c.status().unwrap(), FfiFillStatus::AppClosed);
    assert_eq!(
        c.list_for_app(SLACK.into(), None).unwrap_err(),
        OnePassError::AppClosed
    );
    assert_eq!(c.unlock().unwrap(), FfiFillStatus::AppClosed);
    assert_eq!(store.saves.load(Ordering::SeqCst), 0);
}

#[test]
fn app_started_later_is_reached() {
    let (rig, _) = rig();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("late.sock");
    let store = Arc::new(MemStore::default());
    let c =
        DesktopFillClient::connect_for_tests(path.to_string_lossy().into_owned(), store.clone())
            .unwrap();
    assert_eq!(c.status().unwrap(), FfiFillStatus::AppClosed);
    let (tx, _rx) = channel();
    listen(&rig.server, &path, tx);
    assert_eq!(c.status().unwrap(), FfiFillStatus::Unlocked);
    assert_eq!(store.saves.load(Ordering::SeqCst), 1);
}

#[test]
fn blocked_helper_gets_not_allowed() {
    let (rig, _) = rig();
    rig.server.set_blocked_auto(vec!["fill".into()]);
    let store = Arc::new(MemStore::default());
    let err = DesktopFillClient::connect_for_tests(
        rig.socket.to_string_lossy().into_owned(),
        store.clone(),
    )
    .err()
    .unwrap();
    assert_eq!(
        err,
        OnePassError::Validation {
            field: "bridge".into(),
            reason: "not_allowed".into()
        }
    );
    assert_eq!(store.saves.load(Ordering::SeqCst), 0);
}

#[test]
fn unlock_asks_the_app_and_answers_the_state() {
    let (rig, _) = rig();
    let store = Arc::new(MemStore::default());
    let c = client(&rig, &store);
    assert_eq!(c.unlock().unwrap(), FfiFillStatus::Unlocked);
    rig.session.lock();
    // The app only comes forward: still locked until the user unlocks.
    assert_eq!(c.unlock().unwrap(), FfiFillStatus::Locked);
    assert_eq!(c.status().unwrap(), FfiFillStatus::Locked);
}

/// The switches of `listen_relay`, each for the app's next reply.
struct Relay {
    /// Swallow it and cut the helper's connection.
    drop: Arc<AtomicBool>,
    /// Swallow it and keep the connection up (the helper waits in vain).
    stall: Arc<AtomicBool>,
}

/// `listen_relay`'s drop switch only.
fn listen_dropping(server: &Arc<BridgeServer>, path: &std::path::Path) -> Arc<AtomicBool> {
    listen_relay(server, path).drop
}

/// A listener that serves the fill helper through a relay of frames, so a
/// test can lose or stall a reply after the app served the request.
fn listen_relay(server: &Arc<BridgeServer>, path: &std::path::Path) -> Relay {
    let relay = Relay {
        drop: Arc::new(AtomicBool::new(false)),
        stall: Arc::new(AtomicBool::new(false)),
    };
    let listener = UnixListener::bind(path).unwrap();
    let (server, flag, stall) = (server.clone(), relay.drop.clone(), relay.stall.clone());
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut helper) = conn else { continue };
            let (server, flag, stall) = (server.clone(), flag.clone(), stall.clone());
            thread::spawn(move || {
                // The opening frame is the socket's, not the host loop's.
                let Ok(Some(_)) = read_frame(&mut helper) else {
                    return;
                };
                let (mut to_app, app) = UnixStream::pair().unwrap();
                thread::Builder::new()
                    .stack_size(16 << 20)
                    .spawn(move || serve_fill_for_tests(&server, app))
                    .unwrap();
                let (mut up_from, mut up_to) =
                    (helper.try_clone().unwrap(), to_app.try_clone().unwrap());
                thread::spawn(move || {
                    while let Ok(Some(f)) = read_frame(&mut up_from) {
                        if write_frame(&mut up_to, &f).is_err() {
                            break;
                        }
                    }
                    let _ = up_to.shutdown(Shutdown::Both);
                });
                while let Ok(Some(f)) = read_frame(&mut to_app) {
                    let reply = matches!(wire::parse(&f), Ok(Envelope::Msg(_)));
                    if reply && flag.swap(false, Ordering::SeqCst) {
                        let _ = helper.shutdown(Shutdown::Both);
                        let _ = to_app.shutdown(Shutdown::Both);
                        return;
                    }
                    if reply && stall.swap(false, Ordering::SeqCst) {
                        continue;
                    }
                    if write_frame(&mut helper, &f).is_err() {
                        break;
                    }
                }
                let _ = helper.shutdown(Shutdown::Both);
            });
        }
    });
    relay
}

/// `fill_for_app` lines of the bridge journal: one per fill served (the
/// key usage log coalesces repeated uses).
fn fills_of(rig: &Rig) -> usize {
    let audit = rig._dir.path().join("bridge-audit.jsonl");
    std::fs::read_to_string(audit)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("\"fill_for_app\""))
        .count()
}

#[test]
fn lost_fill_is_never_sent_twice() {
    let (rig, _) = rig();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("relay.sock");
    let drop_reply = listen_dropping(&rig.server, &path);
    let store = Arc::new(MemStore::default());
    let c =
        DesktopFillClient::connect_for_tests(path.to_string_lossy().into_owned(), store).unwrap();
    let row = c.list_for_app(SLACK.into(), None).unwrap().remove(0);

    drop_reply.store(true, Ordering::SeqCst);
    assert_eq!(
        c.fill(slack(), row.item_id.clone(), FfiFillField::Password, false)
            .unwrap_err(),
        OnePassError::AppClosed
    );
    // The app served it once, and only once.
    assert_eq!(fills_of(&rig), 1);
    assert!(!drop_reply.load(Ordering::SeqCst));

    // The next fill opens a new connection: one more, not two.
    let v = c
        .fill(slack(), row.item_id.clone(), FfiFillField::Password, false)
        .unwrap();
    assert_eq!(v.value(), PASSWORD);
    assert_eq!(fills_of(&rig), 2);
}

#[test]
fn lost_read_is_sent_again_once() {
    let (rig, _) = rig();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("relay.sock");
    let drop_reply = listen_dropping(&rig.server, &path);
    let store = Arc::new(MemStore::default());
    let c =
        DesktopFillClient::connect_for_tests(path.to_string_lossy().into_owned(), store).unwrap();
    drop_reply.store(true, Ordering::SeqCst);
    let rows = c.list_for_app(SLACK.into(), None).unwrap();
    assert_eq!(rows[0].title, "Slack");
    assert!(!drop_reply.load(Ordering::SeqCst));
}

#[test]
fn stalled_reply_times_out_and_is_never_sent_again() {
    let (rig, _) = rig();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("relay.sock");
    let relay = listen_relay(&rig.server, &path);
    let store = Arc::new(MemStore::default());
    let c = DesktopFillClient::connect_for_tests_with_timeout(
        path.to_string_lossy().into_owned(),
        store,
        Duration::from_millis(800),
    )
    .unwrap();
    let row = c.list_for_app(SLACK.into(), None).unwrap().remove(0);
    let timeout = OnePassError::Validation {
        field: "bridge".into(),
        reason: "timeout".into(),
    };

    relay.stall.store(true, Ordering::SeqCst);
    assert_eq!(
        c.fill(slack(), row.item_id.clone(), FfiFillField::Password, false)
            .unwrap_err(),
        timeout
    );
    assert_eq!(fills_of(&rig), 1);

    // A read that times out is not retried either.
    relay.stall.store(true, Ordering::SeqCst);
    assert_eq!(c.list_for_app(SLACK.into(), None).unwrap_err(), timeout);
    assert!(!relay.stall.load(Ordering::SeqCst));

    // The next call opens a new connection.
    assert_eq!(c.status().unwrap(), FfiFillStatus::Unlocked);
    assert_eq!(fills_of(&rig), 1);
}
