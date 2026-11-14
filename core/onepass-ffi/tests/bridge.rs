//! The production bridge over a real unlocked session: the extension role
//! played in Rust with `onepass-bridge`, the app's delegate scripted.
//! Run with `--features dev-fast-kdf`.
//!
//! Unix only: these tests drive the socket hosts (SSH agent, MCP, bridge),
//! whose Windows named pipes come with milestone X3.
#![cfg(unix)]

use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use onepass_bridge::channel::Channel;
use onepass_bridge::framing::{read_frame, write_frame};
use onepass_bridge::pairing::{ExtPairing, PairingRecord};
use onepass_bridge::session;
use onepass_bridge::wire::{self, Envelope};
use onepass_ffi::*;
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
const ATLAS: &str = "https://atlas-cloud.test";
const CHROME_EXT: &str = "abcdefghijklmnopabcdefghijklmnop";
#[cfg(target_os = "macos")]
const CHROME: &str = "team:EQHXZ8M8AV:com.google.Chrome";

#[derive(Debug, Clone, PartialEq)]
enum Event {
    Requested(FfiBridgePairingRequest),
    Ended(u64),
    /// Pairing id, extension id, verified browser ("" after the code flow).
    Stored(String, String, String),
    Used(String),
    /// The pairing that asks and the host of the page, when given.
    Unlock(String, Option<String>),
    /// The slot of the item's account, the pairing that asks and the host
    /// of the page the secret is for.
    Reprompt(String, String, Option<String>),
    /// Slot, pairing, kind.
    Served(String, String, String),
    /// The slot written, and the vault when one is named.
    Changed(String, Option<String>),
}

/// Records every call; answers pairing requests with `approve` (none: never).
struct Delegate {
    events: Sender<Event>,
    log: Mutex<Vec<String>>,
    /// Report `fill_served` as an event.
    served: Arc<std::sync::atomic::AtomicBool>,
}

impl BridgeDelegate for Delegate {
    fn pairing_requested(&self, request: FfiBridgePairingRequest) {
        let _ = self.events.send(Event::Requested(request));
    }
    fn pairing_ended(&self, request_id: u64) {
        let _ = self.events.send(Event::Ended(request_id));
    }
    fn pairing_stored(&self, p: FfiBridgePairing) {
        assert_eq!(p.key.len(), 32);
        let _ = self.events.send(Event::Stored(
            p.pairing_id,
            p.extension_id,
            p.verified_browser,
        ));
    }
    fn pairing_used(&self, pairing_id: String, _at: u64) {
        let _ = self.events.send(Event::Used(pairing_id));
    }
    fn unlock_requested(&self, pairing_id: String, origin_host: Option<String>) {
        let _ = self.events.send(Event::Unlock(pairing_id, origin_host));
    }
    fn confirm_reprompt(
        &self,
        slot: String,
        _vault_id: String,
        _item_id: String,
        pairing_id: String,
        origin_host: Option<String>,
    ) -> bool {
        let _ = self
            .events
            .send(Event::Reprompt(slot, pairing_id, origin_host));
        false
    }
    fn fill_served(&self, slot: String, pairing_id: String, kind: String) {
        // Only the tests of this signal listen to it.
        if self.served.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = self.events.send(Event::Served(slot, pairing_id, kind));
        }
    }
    fn vault_changed(&self, slot: String, vault_id: Option<String>) {
        let _ = self.events.send(Event::Changed(slot, vault_id));
    }
    fn note(&self, message: String) {
        self.log.lock().unwrap().push(message);
    }
}

struct Rig {
    _dir: TempDir,
    /// Turn on to receive `Event::Served`.
    served: Arc<std::sync::atomic::AtomicBool>,
    server: Arc<BridgeServer>,
    session: Arc<Session>,
    events: Receiver<Event>,
    record: PairingRecord,
    audit: std::path::PathBuf,
}

fn rig() -> Rig {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(db, "Café-étoile".into(), FAST).unwrap();
    let (tx, events) = channel();
    let record = PairingRecord {
        pairing_id: [7; 16],
        key: Zeroizing::new([9; 32]),
        ext_name: "OnePass".into(),
        browser: "Chrome".into(),
        created_at: 1,
    };
    let audit = dir.path().join("bridge-audit.jsonl");
    let served = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = BridgeServer::new(
        Arc::new(Delegate {
            events: tx,
            log: Mutex::new(Vec::new()),
            served: served.clone(),
        }),
        vec![FfiBridgePairing {
            pairing_id: "07".repeat(16),
            key: vec![9; 32],
            ext_name: "OnePass".into(),
            browser: "Chrome".into(),
            extension_id: "ext".into(),
            verified_browser: String::new(),
            created_at: 1,
            last_used: 1,
        }],
        vec!["ext".into(), CHROME_EXT.into()],
        audit.to_string_lossy().into_owned(),
    );
    server.set_session(Some(created.session.clone()), "alex@atlas.dev".into());
    Rig {
        _dir: dir,
        served,
        server,
        session: created.session,
        events,
        record,
        audit,
    }
}

/// The extension's end of one connection served on a thread.
struct Ext {
    s: UnixStream,
    done: thread::JoinHandle<()>,
}

fn connect(rig: &Rig, extension_id: &str, allowed: bool) -> Ext {
    let (ext, app) = UnixStream::pair().unwrap();
    ext.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let server = rig.server.clone();
    let id = extension_id.to_owned();
    let done = thread::spawn(move || serve_for_tests(&server, app, &id, allowed));
    Ext { s: ext, done }
}

impl Ext {
    fn send(&mut self, env: &Envelope) {
        write_frame(&mut self.s, &wire::to_bytes(env)).unwrap();
    }
    fn recv(&mut self) -> Envelope {
        wire::parse(&read_frame(&mut self.s).unwrap().unwrap()).unwrap()
    }
    fn open(&mut self, record: &PairingRecord) -> Channel {
        let (pending, hello) = session::ext_hello(record).unwrap();
        self.send(&Envelope::Hello(hello));
        let Envelope::Welcome(w) = self.recv() else {
            panic!("welcome")
        };
        let (ch, finish) = pending.on_welcome(w, 1).unwrap();
        self.send(&Envelope::Finish(finish));
        ch
    }
    fn request(&mut self, ch: &mut Channel, req: Value) -> Value {
        self.send(&ch.seal(req.to_string().as_bytes()).unwrap());
        let Envelope::Msg(m) = self.recv() else {
            panic!("msg")
        };
        serde_json::from_slice(&ch.open(&m).unwrap()).unwrap()
    }
    fn end(self) {
        drop(self.s);
        self.done.join().unwrap();
    }
}

fn next(events: &Receiver<Event>) -> Event {
    events.recv_timeout(Duration::from_secs(30)).unwrap()
}

#[test]
fn session_serves_the_unlocked_vault_and_sees_the_lock() {
    let rig = rig();
    let mut ext = connect(&rig, "ext", true);
    let mut ch = ext.open(&rig.record);
    assert_eq!(next(&rig.events), Event::Used("07".repeat(16)));
    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(st["ok"]["locked"], false, "{st}");
    assert_eq!(st["ok"]["account"], "alex@atlas.dev");
    let v = ext.request(&mut ch, json!({"id": 2, "op": "vaults"}));
    assert_eq!(v["ok"]["vaults"].as_array().unwrap().len(), 1, "{v}");

    // A lock in the app is seen by the next request.
    rig.session.lock();
    let st = ext.request(&mut ch, json!({"id": 3, "op": "status"}));
    assert_eq!(st["ok"]["locked"], true, "{st}");
    let v = ext.request(&mut ch, json!({"id": 4, "op": "vaults"}));
    assert_eq!(v["err"]["code"], "locked", "{v}");
    // Unlock from the extension only brings the app forward.
    let u = ext.request(&mut ch, json!({"id": 5, "op": "unlock"}));
    assert_eq!(u["ok"]["locked"], true, "{u}");
    assert_eq!(next(&rig.events), Event::Unlock("07".repeat(16), None));
    ext.end();
}

#[test]
fn cleared_session_reads_as_locked() {
    let rig = rig();
    rig.server.set_session(None, String::new());
    let mut ext = connect(&rig, "ext", true);
    let mut ch = ext.open(&rig.record);
    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(st["ok"]["locked"], true, "{st}");
    ext.end();
}

#[test]
fn excluded_vaults_are_invisible() {
    let rig = rig();
    let vault_id = rig.session.vaults().unwrap()[0].id.clone();
    rig.server.set_excluded_vaults(vec![vault_id]).unwrap();
    let mut ext = connect(&rig, "ext", true);
    let mut ch = ext.open(&rig.record);
    let v = ext.request(&mut ch, json!({"id": 1, "op": "vaults"}));
    assert_eq!(v["ok"]["vaults"].as_array().unwrap().len(), 0, "{v}");
    ext.end();
}

#[test]
fn save_login_writes_the_app_vault_and_tells_the_app() {
    let rig = rig();
    let mut ext = connect(&rig, "ext", true);
    let mut ch = ext.open(&rig.record);
    let _ = next(&rig.events);
    let v = ext.request(&mut ch, json!({"id": 1, "op": "vaults"}));
    let vault_id = v["ok"]["vaults"][0]["id"].clone();
    let saved = ext.request(
        &mut ch,
        json!({"id": 2, "op": "save_login", "ctx": "save_prompt", "origin": ATLAS,
               "title": "Atlas Cloud", "username": "alex@atlas.dev",
               "password": "Dev-Pass-0042", "vault_id": vault_id, "rule": "domain",
               "tags": []}),
    );
    assert!(saved["ok"]["item_id"].is_string(), "{saved}");
    assert_eq!(
        next(&rig.events),
        Event::Changed(
            "primary".into(),
            Some(rig.session.vaults().unwrap()[0].id.clone())
        )
    );
    let titles: Vec<String> = rig
        .session
        .item_summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert!(titles.contains(&"Atlas Cloud".to_owned()), "{titles:?}");
    // The fill is journaled without the password.
    let found = ext.request(
        &mut ch,
        json!({"id": 3, "op": "list_for_origin", "ctx": "menu", "origin": ATLAS}),
    );
    let item_id = found["ok"]["items"][0]["item_id"].clone();
    let fill = ext.request(
        &mut ch,
        json!({"id": 4, "op": "fill_login", "ctx": "menu", "item_id": item_id, "origin": ATLAS,
               "fields": ["username", "password"]}),
    );
    assert_eq!(fill["ok"]["password"], "Dev-Pass-0042", "{fill}");
    ext.end();
    let audit = std::fs::read_to_string(&rig.audit).unwrap();
    assert!(audit.contains("fill_login"), "{audit}");
    assert!(!audit.contains("Dev-Pass-0042"));
    // One account: the journal and the wire name none.
    assert!(!audit.contains("account"), "{audit}");
    assert!(found["ok"]["items"][0].get("account").is_none(), "{found}");
}

/// Pair with the app, the delegate answering `approve`; returns the reply
/// to `pair_reveal` onwards.
fn pair(rig: &Rig, approve: bool) -> (Ext, Envelope, Option<FfiBridgePairingRequest>) {
    let mut ext = connect(rig, "ext", true);
    let (mut p, hello) = ExtPairing::start("OnePass", "Chrome", 1).unwrap();
    ext.send(&Envelope::PairHello(hello));
    let Envelope::PairOffer(offer) = ext.recv() else {
        panic!("offer")
    };
    let (reveal, sas) = p.on_offer(offer).unwrap();
    ext.send(&Envelope::PairReveal(reveal));
    assert_eq!(ext.recv(), Envelope::PairSas);
    let Event::Requested(req) = next(&rig.events) else {
        panic!("request")
    };
    // The app shows the host's code, the same the extension shows.
    assert_eq!(req.code, sas.0);
    assert_eq!(req.extension_id, "ext");
    assert_eq!(
        (req.ext_name.as_str(), req.browser.as_str()),
        ("OnePass", "Chrome")
    );
    rig.server.answer_pairing(req.request_id, approve);
    // A second answer changes nothing.
    rig.server.answer_pairing(req.request_id, !approve);
    let reply = ext.recv();
    assert_eq!(next(&rig.events), Event::Ended(req.request_id));
    if let Envelope::PairDone(done) = &reply {
        p.on_done(done.clone(), 1).unwrap();
        let (confirm, _) = p.confirm(1).unwrap();
        ext.send(&Envelope::PairConfirm(confirm));
        assert_eq!(ext.recv(), Envelope::PairOk);
    }
    (ext, reply, Some(req))
}

#[test]
fn approved_pairing_is_stored_through_the_delegate() {
    let rig = rig();
    let (ext, reply, _) = pair(&rig, true);
    assert!(matches!(reply, Envelope::PairDone(_)));
    let Event::Stored(id, ext_id, verified) = next(&rig.events) else {
        panic!("stored")
    };
    assert_eq!(ext_id, "ext");
    assert_eq!(verified, "");
    assert!(
        rig.server
            .pairings()
            .iter()
            .any(|p| p.pairing_id == id && p.key.is_empty())
    );
    ext.end();
}

#[test]
fn refused_pairing_stores_nothing() {
    let rig = rig();
    let (ext, reply, _) = pair(&rig, false);
    let Envelope::Error(e) = reply else {
        panic!("error")
    };
    assert_eq!(e.code, "not_allowed");
    ext.end();
    assert_eq!(rig.server.pairings().len(), 1);
    assert!(rig.events.try_recv().is_err());
}

#[test]
fn forgotten_pairing_is_unknown() {
    let rig = rig();
    rig.server.forget_pairing("07".repeat(16));
    let mut ext = connect(&rig, "ext", true);
    let (_pending, hello) = session::ext_hello(&rig.record).unwrap();
    ext.send(&Envelope::Hello(hello));
    let Envelope::Error(e) = ext.recv() else {
        panic!("error")
    };
    assert_eq!(e.code, "unknown_pairing");
    ext.end();
}

#[test]
fn extension_not_in_the_list_is_refused() {
    let rig = rig();
    let mut ext = connect(&rig, "other", false);
    let (_pending, hello) = session::ext_hello(&rig.record).unwrap();
    ext.send(&Envelope::Hello(hello));
    let Envelope::Error(e) = ext.recv() else {
        panic!("error")
    };
    assert_eq!(e.code, "not_allowed");
    ext.end();
    assert!(rig.events.try_recv().is_err());
}

#[test]
fn unsigned_test_process_cannot_start_the_server() {
    let rig = rig();
    let dir = TempDir::new().unwrap();
    assert!(
        rig.server
            .start(dir.path().to_string_lossy().into_owned())
            .is_err()
    );
    assert!(!rig.server.is_running());
}

/// One connection admitted as the app's socket would admit it: the relay
/// with `launcher`, or Safari when `extension_id` is `None`.
#[cfg(target_os = "macos")]
fn admitted(rig: &Rig, extension_id: Option<&str>, launcher: Option<&str>) -> Ext {
    let (ext, app) = UnixStream::pair().unwrap();
    ext.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let server = rig.server.clone();
    let id = extension_id.map(str::to_owned);
    let launcher = launcher.map(str::to_owned);
    let done = thread::spawn(move || match id {
        Some(id) => serve_relay_for_tests(&server, app, &id, launcher.as_deref()),
        None => serve_safari_for_tests(&server, app),
    });
    Ext { s: ext, done }
}

/// An automatic pairing from the extension's side: `None` when the app
/// refused it, else the record.
#[cfg(target_os = "macos")]
fn auto_pair(ext: &mut Ext) -> Result<PairingRecord, String> {
    let (mut p, mut hello) = ExtPairing::start("OnePass", "Chrome", 1).unwrap();
    hello.auto = true;
    ext.send(&Envelope::PairHello(hello));
    let offer = match ext.recv() {
        Envelope::PairOffer(o) => o,
        Envelope::Error(e) => return Err(e.code),
        other => panic!("{other:?}"),
    };
    let (reveal, _) = p.on_offer(offer).unwrap();
    ext.send(&Envelope::PairReveal(reveal));
    assert_eq!(ext.recv(), Envelope::PairAuto);
    let Envelope::PairDone(done) = ext.recv() else {
        panic!("done")
    };
    p.on_done(done, 1).unwrap();
    let (confirm, record) = p.confirm(1).unwrap();
    ext.send(&Envelope::PairConfirm(confirm));
    assert_eq!(ext.recv(), Envelope::PairOk);
    Ok(record)
}

#[cfg(target_os = "macos")]
#[test]
fn chrome_vouched_by_signature_pairs_without_a_request() {
    let rig = rig();
    let mut ext = admitted(&rig, Some(CHROME_EXT), Some(CHROME));
    let record = auto_pair(&mut ext).unwrap();
    let Event::Stored(id, ext_id, verified) = next(&rig.events) else {
        panic!("stored")
    };
    assert_eq!(
        (ext_id.as_str(), verified.as_str()),
        (CHROME_EXT, "Google Chrome")
    );
    assert_eq!(
        id,
        record
            .pairing_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    // The session on the same port still reads only the unlocked vault.
    let mut ch = ext.open(&record);
    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(st["ok"]["locked"], false, "{st}");
    ext.end();
    assert!(
        rig.events
            .try_iter()
            .all(|e| !matches!(e, Event::Requested(_))),
        "no pairing sheet"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn safari_pairs_automatically() {
    let rig = rig();
    let mut ext = admitted(&rig, None, None);
    auto_pair(&mut ext).unwrap();
    let Event::Stored(_, ext_id, verified) = next(&rig.events) else {
        panic!("stored")
    };
    assert_eq!((ext_id.as_str(), verified.as_str()), ("safari", "Safari"));
    ext.end();
}

#[cfg(target_os = "macos")]
#[test]
fn unknown_launcher_is_refused_silently() {
    let rig = rig();
    for launcher in [
        None,
        Some("team:AAAAAAAAAA:com.google.Chrome"),
        Some("adhoc:00ff"),
    ] {
        let mut ext = admitted(&rig, Some(CHROME_EXT), launcher);
        assert_eq!(auto_pair(&mut ext).unwrap_err(), "not_allowed");
        ext.end();
    }
    // No sheet, nothing stored.
    assert!(rig.events.try_recv().is_err());
    assert_eq!(rig.server.pairings().len(), 1);
}

#[cfg(target_os = "macos")]
#[test]
fn revoked_extension_stays_out_until_a_code_pairing() {
    let rig = rig();
    rig.server.set_blocked_auto(vec![CHROME_EXT.into()]);
    let mut ext = admitted(&rig, Some(CHROME_EXT), Some(CHROME));
    assert_eq!(auto_pair(&mut ext).unwrap_err(), "not_allowed");
    ext.end();
    assert_eq!(rig.server.blocked_auto(), vec![CHROME_EXT.to_owned()]);

    // The user pairs it with the code and Touch ID: the block is lifted.
    let mut ext = admitted(&rig, Some(CHROME_EXT), Some(CHROME));
    let (mut p, hello) = ExtPairing::start("OnePass", "Chrome", 1).unwrap();
    ext.send(&Envelope::PairHello(hello));
    let Envelope::PairOffer(offer) = ext.recv() else {
        panic!("offer")
    };
    let (reveal, _) = p.on_offer(offer).unwrap();
    ext.send(&Envelope::PairReveal(reveal));
    assert_eq!(ext.recv(), Envelope::PairSas);
    let Event::Requested(req) = next(&rig.events) else {
        panic!("request")
    };
    rig.server.answer_pairing(req.request_id, true);
    let Envelope::PairDone(done) = ext.recv() else {
        panic!("done")
    };
    p.on_done(done, 1).unwrap();
    let (confirm, _) = p.confirm(1).unwrap();
    ext.send(&Envelope::PairConfirm(confirm));
    assert_eq!(ext.recv(), Envelope::PairOk);
    ext.end();
    assert!(rig.server.blocked_auto().is_empty());

    let mut ext = admitted(&rig, Some(CHROME_EXT), Some(CHROME));
    auto_pair(&mut ext).unwrap();
    ext.end();
}

/// The extension's end of an in-process connection (iOS Safari handler).
fn in_process(rig: &Rig) -> UnixStream {
    use std::os::fd::FromRawFd;
    let fd = rig.server.connect_in_process().unwrap();
    // SAFETY: `connect_in_process` hands over a fresh descriptor we now own.
    let s = unsafe { UnixStream::from_raw_fd(fd) };
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s
}

/// `auto_pair` on any stream, for the in-process connection.
fn auto_pair_on(s: &mut UnixStream) -> Result<PairingRecord, String> {
    let send = |s: &mut UnixStream, env: &Envelope| write_frame(s, &wire::to_bytes(env)).unwrap();
    let recv = |s: &mut UnixStream| wire::parse(&read_frame(s).unwrap().unwrap()).unwrap();
    let (mut p, mut hello) = ExtPairing::start("OnePass", "Safari", 1).unwrap();
    hello.auto = true;
    send(s, &Envelope::PairHello(hello));
    let offer = match recv(s) {
        Envelope::PairOffer(o) => o,
        Envelope::Error(e) => return Err(e.code),
        other => panic!("{other:?}"),
    };
    let (reveal, _) = p.on_offer(offer).unwrap();
    send(s, &Envelope::PairReveal(reveal));
    assert_eq!(recv(s), Envelope::PairAuto);
    let Envelope::PairDone(done) = recv(s) else {
        panic!("done")
    };
    p.on_done(done, 1).unwrap();
    let (confirm, record) = p.confirm(1).unwrap();
    send(s, &Envelope::PairConfirm(confirm));
    assert_eq!(recv(s), Envelope::PairOk);
    Ok(record)
}

#[test]
fn in_process_safari_pairs_without_a_code_and_serves_the_vault() {
    let rig = rig();
    let mut s = in_process(&rig);
    let record = auto_pair_on(&mut s).unwrap();
    let Event::Stored(_, ext_id, verified) = next(&rig.events) else {
        panic!("stored")
    };
    assert_eq!((ext_id.as_str(), verified.as_str()), ("safari", "Safari"));
    drop(s);

    // A new connection opens a session with the stored pairing.
    let s = in_process(&rig);
    let mut ext = Ext {
        s,
        done: thread::spawn(|| {}),
    };
    let mut ch = ext.open(&record);
    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(st["ok"]["locked"], false, "{st}");
    rig.session.lock();
    let st = ext.request(&mut ch, json!({"id": 2, "op": "status"}));
    assert_eq!(st["ok"]["locked"], true, "{st}");
    ext.end();
    assert!(
        rig.events
            .try_iter()
            .all(|e| !matches!(e, Event::Requested(_))),
        "no pairing sheet"
    );
}

#[test]
fn in_process_safari_revoked_is_refused_silently() {
    let rig = rig();
    rig.server.set_blocked_auto(vec!["safari".into()]);
    let mut s = in_process(&rig);
    assert_eq!(auto_pair_on(&mut s).unwrap_err(), "not_allowed");
    drop(s);
    assert!(rig.events.try_recv().is_err());
    assert_eq!(rig.server.pairings().len(), 1);
}

// Added accounts (owner ruling of 2026-11-10, which reverses ruling P7):
// one bridge, one socket, a session per account.

const HOME_PASSWORD: &str = "Home-Pass-0001";
const WORK_PASSWORD: &str = "Work-Pass-0002";
const WORK_SLOT: &str = "0123456789abcdef0123456789abcdef";
const HOME_NAME: &str = "alex@atlas.dev";
const WORK_NAME: &str = "Soma Labs";

struct Two {
    rig: Rig,
    _dir: TempDir,
    work: Arc<Session>,
    home_vault: String,
    work_vault: String,
    home_item: String,
    work_item: String,
}

fn account(slot: &str, session: Option<&Arc<Session>>, name: &str) -> FfiBridgeAccount {
    FfiBridgeAccount {
        slot: slot.into(),
        session: session.cloned(),
        account_name: name.into(),
        excluded_vault_ids: Vec::new(),
    }
}

/// A saved Login of `ATLAS` in the first vault of `session`.
fn atlas_login(session: &Arc<Session>, title: &str, user: &str, password: &str) -> FfiItem {
    let vault = session.vaults().unwrap()[0].id.clone();
    let mut item = session
        .new_item(vault, FfiItemType::Login, title.into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "username" => f.value = FfiFieldValue::Text { value: user.into() },
            "password" => {
                f.value = FfiFieldValue::Password {
                    value: password.into(),
                }
            }
            _ => {}
        }
    }
    item.urls = vec![FfiUrl {
        label: String::new(),
        url: ATLAS.into(),
        rule: FfiMatchRule::Domain,
        primary: true,
    }];
    session.save_item(item).unwrap()
}

/// The rig with an added account in `slot`, both unlocked, a Login of
/// `ATLAS` in each.
fn two_in(slot: &str) -> Two {
    let rig = rig();
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("work.db").to_string_lossy().into_owned();
    let work = create_account_with_kdf(db, "Café-étoile".into(), FAST)
        .unwrap()
        .session;
    let home_item = atlas_login(&rig.session, "Atlas home", "home@atlas.dev", HOME_PASSWORD).id;
    let work_item = atlas_login(&work, "Atlas work", "work@atlas.dev", WORK_PASSWORD).id;
    rig.server
        .set_sessions(vec![
            account("primary", Some(&rig.session), HOME_NAME),
            account(slot, Some(&work), WORK_NAME),
        ])
        .unwrap();
    Two {
        home_vault: rig.session.vaults().unwrap()[0].id.clone(),
        work_vault: work.vaults().unwrap()[0].id.clone(),
        rig,
        _dir: dir,
        work,
        home_item,
        work_item,
    }
}

fn two() -> Two {
    two_in(WORK_SLOT)
}

/// An open session of the paired extension, the `Used` event consumed.
fn open(rig: &Rig) -> (Ext, Channel) {
    let mut ext = connect(rig, "ext", true);
    let ch = ext.open(&rig.record);
    assert_eq!(next(&rig.events), Event::Used("07".repeat(16)));
    (ext, ch)
}

fn listed(ext: &mut Ext, ch: &mut Channel, id: u64, origin: &str) -> Vec<(String, String)> {
    let v = ext.request(
        ch,
        json!({"id": id, "op": "list_for_origin", "ctx": "menu", "origin": origin}),
    );
    v["ok"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("{v}"))
        .iter()
        .map(|s| {
            (
                s["title"].as_str().unwrap().to_owned(),
                s["account"].as_str().unwrap_or("-").to_owned(),
            )
        })
        .collect()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect()
}

fn fill_of(ext: &mut Ext, ch: &mut Channel, id: u64, item: &str) -> Value {
    ext.request(
        ch,
        json!({"id": id, "op": "fill_login", "ctx": "menu", "item_id": hyphenated(item),
               "origin": ATLAS, "fields": ["username", "password"]}),
    )
}

/// An item id as the bridge writes it (the FFI gives 32 hex characters).
fn hyphenated(hex: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn titles_of(session: &Arc<Session>) -> Vec<String> {
    session
        .item_summaries()
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect()
}

#[test]
fn items_of_two_accounts_are_offered_with_their_account() {
    let t = two();
    let (mut ext, mut ch) = open(&t.rig);
    // The status is the primary account's; the vaults of both are counted.
    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(st["ok"]["locked"], false, "{st}");
    assert_eq!(st["ok"]["account"], HOME_NAME);
    assert_eq!(st["ok"]["vaults"], 2);
    // The primary account's vault first: a new login defaults to it.
    let v = ext.request(&mut ch, json!({"id": 2, "op": "vaults"}));
    let vaults = v["ok"]["vaults"].as_array().unwrap();
    assert_eq!(vaults.len(), 2, "{v}");
    assert_eq!(vaults[0]["id"], hyphenated(&t.home_vault));
    assert_eq!(vaults[0]["account"], HOME_NAME);
    assert_eq!(vaults[1]["id"], hyphenated(&t.work_vault));
    assert_eq!(vaults[1]["account"], WORK_NAME);
    assert_eq!(
        listed(&mut ext, &mut ch, 3, ATLAS),
        pairs(&[("Atlas home", HOME_NAME), ("Atlas work", WORK_NAME)])
    );
    ext.end();
}

#[test]
fn a_locked_added_account_gives_nothing_and_asks_nothing() {
    let t = two();
    t.work.lock();
    let (mut ext, mut ch) = open(&t.rig);
    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(
        (&st["ok"]["locked"], &st["ok"]["vaults"]),
        (&json!(false), &json!(1))
    );
    // One account answers: nothing on the wire says there is another.
    assert_eq!(
        listed(&mut ext, &mut ch, 2, ATLAS),
        pairs(&[("Atlas home", "-")])
    );
    let v = ext.request(&mut ch, json!({"id": 3, "op": "vaults"}));
    assert_eq!(v["ok"]["vaults"].as_array().unwrap().len(), 1, "{v}");
    assert!(v["ok"]["vaults"][0].get("account").is_none(), "{v}");
    // Its items and vaults are unknown, not "locked".
    let fill = fill_of(&mut ext, &mut ch, 4, &t.work_item);
    assert_eq!(fill["err"]["code"], "not_found", "{fill}");
    let saved = ext.request(
        &mut ch,
        json!({"id": 5, "op": "save_login", "ctx": "save_prompt", "origin": ATLAS,
               "title": "", "username": "x@atlas.dev", "password": "Other-Pass-0003",
               "vault_id": hyphenated(&t.work_vault), "rule": "domain", "tags": []}),
    );
    assert_eq!(saved["err"]["code"], "not_found", "{saved}");
    // The same with no session at all for the slot.
    t.rig
        .server
        .set_sessions(vec![
            account("primary", Some(&t.rig.session), HOME_NAME),
            account(WORK_SLOT, None, WORK_NAME),
        ])
        .unwrap();
    assert_eq!(
        listed(&mut ext, &mut ch, 6, ATLAS),
        pairs(&[("Atlas home", "-")])
    );
    ext.end();
    // No unlock was asked, no prompt shown, nothing written.
    assert!(t.rig.events.try_recv().is_err());
}

#[test]
fn a_fill_from_the_added_account_is_journaled_under_it() {
    let t = two();
    let (mut ext, mut ch) = open(&t.rig);
    listed(&mut ext, &mut ch, 1, ATLAS);
    let fill = fill_of(&mut ext, &mut ch, 2, &t.work_item);
    assert_eq!(fill["ok"]["password"], WORK_PASSWORD, "{fill}");
    let fill = fill_of(&mut ext, &mut ch, 3, &t.home_item);
    assert_eq!(fill["ok"]["password"], HOME_PASSWORD, "{fill}");
    // The fill worked: remembered in the item's own account, usage and
    // history, never in the other one.
    let noted = ext.request(
        &mut ch,
        json!({"id": 4, "op": "note_fill", "ctx": "chain", "item_id": hyphenated(&t.work_item),
               "origin": ATLAS, "roles": ["username", "current_password"], "intent": "login",
               "steps": ["fill"]}),
    );
    assert!(noted.get("ok").is_some(), "{noted}");
    assert_eq!(
        next(&t.rig.events),
        Event::Changed(WORK_SLOT.into(), Some(t.work_vault.clone()))
    );
    assert_eq!(t.work.autofill_history_count().unwrap(), 1);
    assert_eq!(t.rig.session.autofill_history_count().unwrap(), 0);
    ext.end();
    let lines: Vec<Value> = std::fs::read_to_string(&t.rig.audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let account_of = |item: &str| -> Vec<&Value> {
        lines
            .iter()
            .filter(|l| l["item_id"] == hyphenated(item))
            .map(|l| &l["account"])
            .collect()
    };
    assert_eq!(
        account_of(&t.work_item),
        [&json!(WORK_SLOT), &json!(WORK_SLOT)]
    );
    assert_eq!(account_of(&t.home_item), [&json!("primary")]);
    let text = std::fs::read_to_string(&t.rig.audit).unwrap();
    assert!(!text.contains(WORK_PASSWORD) && !text.contains(HOME_PASSWORD));
}

#[test]
fn a_new_login_lands_in_the_primary_account_and_an_update_stays_home() {
    let t = two();
    let (mut ext, mut ch) = open(&t.rig);
    // As the extension does: the first vault listed.
    let v = ext.request(&mut ch, json!({"id": 1, "op": "vaults"}));
    let first = v["ok"]["vaults"][0]["id"].clone();
    let saved = ext.request(
        &mut ch,
        json!({"id": 2, "op": "save_login", "ctx": "save_prompt",
               "origin": "https://new-site.test", "title": "New site",
               "username": "alex@new-site.test", "password": "New-Pass-0004",
               "vault_id": first, "rule": "domain", "tags": []}),
    );
    assert!(saved["ok"]["item_id"].is_string(), "{saved}");
    assert_eq!(
        next(&t.rig.events),
        Event::Changed("primary".into(), Some(t.home_vault.clone()))
    );
    assert!(titles_of(&t.rig.session).contains(&"New site".to_owned()));
    assert!(!titles_of(&t.work).contains(&"New site".to_owned()));

    // The password of the added account's login changes: it stays there.
    let updated = ext.request(
        &mut ch,
        json!({"id": 3, "op": "update_password", "ctx": "save_prompt",
               "item_id": hyphenated(&t.work_item), "origin": ATLAS,
               "password": "Rotated-Pass-0005"}),
    );
    assert!(updated.get("ok").is_some(), "{updated}");
    assert_eq!(
        next(&t.rig.events),
        Event::Changed(WORK_SLOT.into(), Some(t.work_vault.clone()))
    );
    assert_eq!(titles_of(&t.work), ["Atlas work"]);
    assert!(!titles_of(&t.rig.session).contains(&"Atlas work".to_owned()));
    let fill = fill_of(&mut ext, &mut ch, 4, &t.work_item);
    assert_eq!(fill["ok"]["password"], "Rotated-Pass-0005", "{fill}");

    // A vault of the added account, chosen in the save form: saved there.
    let saved = ext.request(
        &mut ch,
        json!({"id": 5, "op": "save_login", "ctx": "save_prompt",
               "origin": "https://work-site.test", "title": "Work site",
               "username": "alex@work-site.test", "password": "New-Pass-0006",
               "vault_id": hyphenated(&t.work_vault), "rule": "domain", "tags": []}),
    );
    assert!(saved["ok"]["item_id"].is_string(), "{saved}");
    assert_eq!(
        next(&t.rig.events),
        Event::Changed(WORK_SLOT.into(), Some(t.work_vault.clone()))
    );
    assert!(titles_of(&t.work).contains(&"Work site".to_owned()));
    assert!(!titles_of(&t.rig.session).contains(&"Work site".to_owned()));
    ext.end();
}

#[test]
fn reprompt_is_asked_for_the_account_of_the_item() {
    let t = two();
    let mut item = t
        .work
        .item_summaries()
        .unwrap()
        .into_iter()
        .find(|s| s.id == t.work_item)
        .map(|s| t.work.item(s.vault_id, s.id).unwrap())
        .unwrap();
    item.reprompt = true;
    t.work.save_item(item).unwrap();
    let (mut ext, mut ch) = open(&t.rig);
    // The scripted app refuses: the secret stays, the other account's
    // login is served without a prompt.
    let fill = fill_of(&mut ext, &mut ch, 1, &t.work_item);
    assert_eq!(fill["err"]["code"], "reprompt_required", "{fill}");
    assert_eq!(
        next(&t.rig.events),
        Event::Reprompt(
            WORK_SLOT.into(),
            "07".repeat(16),
            Some("atlas-cloud.test".into())
        )
    );
    let fill = fill_of(&mut ext, &mut ch, 2, &t.home_item);
    assert_eq!(fill["ok"]["password"], HOME_PASSWORD, "{fill}");
    ext.end();
    assert!(t.rig.events.try_recv().is_err());
}

#[test]
fn hidden_vaults_are_hidden_per_account() {
    let t = two();
    let mut work = account(WORK_SLOT, Some(&t.work), WORK_NAME);
    work.excluded_vault_ids = vec![t.work_vault.clone()];
    t.rig
        .server
        .set_sessions(vec![
            account("primary", Some(&t.rig.session), HOME_NAME),
            work,
        ])
        .unwrap();
    let (mut ext, mut ch) = open(&t.rig);
    // The added account answers nothing: one account on the wire.
    assert_eq!(
        listed(&mut ext, &mut ch, 1, ATLAS),
        pairs(&[("Atlas home", "-")])
    );
    let fill = fill_of(&mut ext, &mut ch, 2, &t.work_item);
    assert_eq!(fill["err"]["code"], "not_found", "{fill}");
    // The app-wide list still hides a vault of any account.
    t.rig
        .server
        .set_sessions(vec![
            account("primary", Some(&t.rig.session), HOME_NAME),
            account(WORK_SLOT, Some(&t.work), WORK_NAME),
        ])
        .unwrap();
    assert_eq!(listed(&mut ext, &mut ch, 3, ATLAS).len(), 2);
    t.rig
        .server
        .set_excluded_vaults(vec![t.work_vault.clone()])
        .unwrap();
    assert_eq!(
        listed(&mut ext, &mut ch, 4, ATLAS),
        pairs(&[("Atlas home", "-")])
    );
    ext.end();
}

#[test]
fn the_status_follows_the_primary_account() {
    let t = two();
    let (mut ext, mut ch) = open(&t.rig);
    t.rig.session.lock();
    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(st["ok"]["locked"], true, "{st}");
    assert_eq!(st["ok"]["vaults"], 0);
    // The added account is open, and still nothing of it is served.
    let v = ext.request(
        &mut ch,
        json!({"id": 2, "op": "list_for_origin", "ctx": "menu", "origin": ATLAS}),
    );
    assert_eq!(v["err"]["code"], "locked", "{v}");
    let fill = fill_of(&mut ext, &mut ch, 3, &t.work_item);
    assert_eq!(fill["err"]["code"], "locked", "{fill}");
    // No primary account in the list: locked too.
    t.rig
        .server
        .set_sessions(vec![account(WORK_SLOT, Some(&t.work), WORK_NAME)])
        .unwrap();
    let st = ext.request(&mut ch, json!({"id": 4, "op": "status"}));
    assert_eq!(st["ok"]["locked"], true, "{st}");
    ext.end();
}

#[test]
fn one_listed_session_is_the_single_account_bridge() {
    let rig = rig();
    let item = atlas_login(&rig.session, "Atlas home", "home@atlas.dev", HOME_PASSWORD).id;
    rig.server
        .set_sessions(vec![account("primary", Some(&rig.session), HOME_NAME)])
        .unwrap();
    let (mut ext, mut ch) = open(&rig);
    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(
        st,
        json!({"id": 1, "ok": {"locked": false, "account": HOME_NAME, "vaults": 1}})
    );
    let v = ext.request(
        &mut ch,
        json!({"id": 2, "op": "list_for_origin", "ctx": "menu", "origin": ATLAS}),
    );
    assert_eq!(v["ok"]["items"][0].as_object().unwrap().len(), 12, "{v}");
    let fill = fill_of(&mut ext, &mut ch, 3, &item);
    assert_eq!(fill["ok"]["password"], HOME_PASSWORD, "{fill}");
    ext.end();
    let audit = std::fs::read_to_string(&rig.audit).unwrap();
    let line: Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
    assert_eq!(line.as_object().unwrap().len(), 5, "{line}");
    // A slot that is no slot is refused, and so is one listed twice.
    assert!(
        rig.server
            .set_sessions(vec![account("../x", Some(&rig.session), HOME_NAME)])
            .is_err()
    );
    assert!(
        rig.server
            .set_sessions(vec![
                account("primary", Some(&rig.session), HOME_NAME),
                account("primary", Some(&rig.session), HOME_NAME),
            ])
            .is_err()
    );
}

#[test]
fn a_claimed_domain_puts_its_account_first() {
    // The directory AutoFill routes with: the added account claims the
    // site's domain.
    let folder = TempDir::new().unwrap();
    let f = folder.path().to_string_lossy().into_owned();
    let slot = account_directory_add(
        f.clone(),
        FfiAccountKind::Business,
        WORK_NAME.into(),
        FfiAccountColor::Orange,
    )
    .unwrap();
    account_directory_update(
        f.clone(),
        slot.clone(),
        WORK_NAME.into(),
        FfiAccountColor::Orange,
        vec!["atlas-cloud.test".into()],
    )
    .unwrap();
    let t = two_in(&slot);
    let (mut ext, mut ch) = open(&t.rig);
    // No directory given: every host is the primary account's.
    assert_eq!(
        listed(&mut ext, &mut ch, 1, ATLAS),
        pairs(&[("Atlas home", HOME_NAME), ("Atlas work", WORK_NAME)])
    );
    t.rig.server.set_routing_folder(Some(f));
    assert_eq!(
        listed(&mut ext, &mut ch, 2, "https://app.atlas-cloud.test/login"),
        pairs(&[("Atlas work", WORK_NAME), ("Atlas home", HOME_NAME)])
    );
    // The account that claims the domain is locked: the primary answers.
    t.work.lock();
    assert_eq!(
        listed(&mut ext, &mut ch, 3, ATLAS),
        pairs(&[("Atlas home", "-")])
    );
    ext.end();
}

#[test]
fn pairing_and_the_allowed_list_gate_every_account() {
    // The checks made before any vault is read do not depend on how many
    // accounts are open: nothing of either is reached without them.
    let t = two();
    // An extension the app does not serve.
    let mut ext = connect(&t.rig, "other", false);
    let (_pending, hello) = session::ext_hello(&t.rig.record).unwrap();
    ext.send(&Envelope::Hello(hello));
    let Envelope::Error(e) = ext.recv() else {
        panic!("error")
    };
    assert_eq!(e.code, "not_allowed");
    ext.end();
    // A pairing the user forgot.
    t.rig.server.forget_pairing("07".repeat(16));
    let mut ext = connect(&t.rig, "ext", true);
    let (_pending, hello) = session::ext_hello(&t.rig.record).unwrap();
    ext.send(&Envelope::Hello(hello));
    let Envelope::Error(e) = ext.recv() else {
        panic!("error")
    };
    assert_eq!(e.code, "unknown_pairing");
    ext.end();
    assert!(t.rig.events.try_recv().is_err());
    assert!(!t.rig.audit.exists());
}

#[test]
fn a_login_of_the_added_account_is_refused_on_another_site() {
    // The origin check is the item's, whichever account holds it.
    let t = two();
    let (mut ext, mut ch) = open(&t.rig);
    let fill = ext.request(
        &mut ch,
        json!({"id": 1, "op": "fill_login", "ctx": "menu",
               "item_id": hyphenated(&t.work_item), "origin": "https://atlas-cloud.test.evil.test",
               "fields": ["password"]}),
    );
    assert_eq!(fill["err"]["code"], "origin_mismatch", "{fill}");
    ext.end();
    assert!(!t.rig.audit.exists());
}

// The signals the app binds an unlock to, and its idle timer.

#[test]
fn unlock_and_served_secrets_name_the_client_and_the_site() {
    let t = two();
    t.rig
        .served
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (mut ext, mut ch) = open(&t.rig);
    let pairing = "07".repeat(16);
    // The gesture's page goes with the unlock request.
    let u = ext.request(
        &mut ch,
        json!({"id": 1, "op": "unlock", "origin": "https://app.atlas-cloud.test/login"}),
    );
    assert_eq!(u["ok"]["locked"], false, "{u}");
    assert_eq!(
        next(&t.rig.events),
        Event::Unlock(pairing.clone(), Some("app.atlas-cloud.test".into()))
    );
    // A list, a plan-less status: nothing served.
    listed(&mut ext, &mut ch, 2, ATLAS);
    ext.request(&mut ch, json!({"id": 3, "op": "status"}));
    // Each fill, under the account of its item.
    fill_of(&mut ext, &mut ch, 4, &t.home_item);
    assert_eq!(
        next(&t.rig.events),
        Event::Served("primary".into(), pairing.clone(), "fill_login".into())
    );
    fill_of(&mut ext, &mut ch, 5, &t.work_item);
    assert_eq!(
        next(&t.rig.events),
        Event::Served(WORK_SLOT.into(), pairing.clone(), "fill_login".into())
    );
    // A refused fill serves nothing.
    let refused = ext.request(
        &mut ch,
        json!({"id": 6, "op": "fill_login", "ctx": "menu",
               "item_id": hyphenated(&t.work_item), "origin": "https://evil.test",
               "fields": ["password"]}),
    );
    assert_eq!(refused["err"]["code"], "origin_mismatch", "{refused}");
    ext.end();
    assert!(t.rig.events.try_recv().is_err());
}

#[test]
fn history_goes_to_the_home_of_the_item_even_with_the_primary_hidden() {
    // Two accounts open, every vault of the primary one hidden: the added
    // account answers alone, and its item's history is its own.
    let t = two();
    let mut primary = account("primary", Some(&t.rig.session), HOME_NAME);
    primary.excluded_vault_ids = vec![t.home_vault.clone()];
    t.rig
        .server
        .set_sessions(vec![primary, account(WORK_SLOT, Some(&t.work), WORK_NAME)])
        .unwrap();
    let (mut ext, mut ch) = open(&t.rig);
    assert_eq!(
        listed(&mut ext, &mut ch, 1, ATLAS),
        pairs(&[("Atlas work", "-")])
    );
    fill_of(&mut ext, &mut ch, 2, &t.work_item);
    let noted = ext.request(
        &mut ch,
        json!({"id": 3, "op": "note_autofill", "ctx": "menu", "origin": ATLAS,
               "action": "picked", "item_id": hyphenated(&t.work_item), "rank": 0,
               "shown": [hyphenated(&t.work_item)]}),
    );
    assert!(noted.get("ok").is_some(), "{noted}");
    ext.end();
    assert_eq!(t.work.autofill_history_count().unwrap(), 1);
    assert_eq!(t.rig.session.autofill_history_count().unwrap(), 0);
}

#[test]
fn a_new_login_on_a_claimed_domain_defaults_to_its_account() {
    let folder = TempDir::new().unwrap();
    let f = folder.path().to_string_lossy().into_owned();
    let slot = account_directory_add(
        f.clone(),
        FfiAccountKind::Business,
        WORK_NAME.into(),
        FfiAccountColor::Orange,
    )
    .unwrap();
    account_directory_update(
        f.clone(),
        slot.clone(),
        WORK_NAME.into(),
        FfiAccountColor::Orange,
        vec!["claimed.test".into()],
    )
    .unwrap();
    let t = two_in(&slot);
    t.rig.server.set_routing_folder(Some(f));
    let (mut ext, mut ch) = open(&t.rig);
    // The vault list of the page starts with the claiming account's vault,
    // and a save that names no vault lands there.
    let v = ext.request(
        &mut ch,
        json!({"id": 1, "op": "vaults", "origin": "https://app.claimed.test"}),
    );
    assert_eq!(v["ok"]["vaults"][0]["id"], hyphenated(&t.work_vault), "{v}");
    let saved = ext.request(
        &mut ch,
        json!({"id": 2, "op": "save_login", "ctx": "save_prompt",
               "origin": "https://app.claimed.test", "title": "Claimed",
               "username": "alex@claimed.test", "password": "New-Pass-0007",
               "vault_id": "", "rule": "domain", "tags": []}),
    );
    assert!(saved["ok"]["item_id"].is_string(), "{saved}");
    assert_eq!(
        next(&t.rig.events),
        Event::Changed(slot.clone(), Some(t.work_vault.clone()))
    );
    assert!(titles_of(&t.work).contains(&"Claimed".to_owned()));
    // Any other site: the primary account.
    let saved = ext.request(
        &mut ch,
        json!({"id": 3, "op": "save_login", "ctx": "save_prompt",
               "origin": "https://elsewhere.test", "title": "Elsewhere",
               "username": "alex@elsewhere.test", "password": "New-Pass-0008",
               "vault_id": "", "rule": "domain", "tags": []}),
    );
    assert!(saved["ok"]["item_id"].is_string(), "{saved}");
    assert_eq!(
        next(&t.rig.events),
        Event::Changed("primary".into(), Some(t.home_vault.clone()))
    );
    assert!(titles_of(&t.rig.session).contains(&"Elsewhere".to_owned()));
    ext.end();
}
