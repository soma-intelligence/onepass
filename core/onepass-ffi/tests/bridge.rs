//! The production bridge over a real unlocked session: the extension role
//! played in Rust with `onepass-bridge`, the app's delegate scripted.
//! Run with `--features dev-fast-kdf`.

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

#[derive(Debug, Clone, PartialEq)]
enum Event {
    Requested(FfiBridgePairingRequest),
    Ended(u64),
    Stored(String, String),
    Used(String),
    Unlock,
    Reprompt,
    Changed,
}

/// Records every call; answers pairing requests with `approve` (none: never).
struct Delegate {
    events: Sender<Event>,
    log: Mutex<Vec<String>>,
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
        let _ = self
            .events
            .send(Event::Stored(p.pairing_id, p.extension_id));
    }
    fn pairing_used(&self, pairing_id: String, _at: u64) {
        let _ = self.events.send(Event::Used(pairing_id));
    }
    fn unlock_requested(&self) {
        let _ = self.events.send(Event::Unlock);
    }
    fn confirm_reprompt(&self, _vault_id: String, _item_id: String) -> bool {
        let _ = self.events.send(Event::Reprompt);
        false
    }
    fn vault_changed(&self) {
        let _ = self.events.send(Event::Changed);
    }
    fn note(&self, message: String) {
        self.log.lock().unwrap().push(message);
    }
}

struct Rig {
    _dir: TempDir,
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
    let server = BridgeServer::new(
        Arc::new(Delegate {
            events: tx,
            log: Mutex::new(Vec::new()),
        }),
        vec![FfiBridgePairing {
            pairing_id: "07".repeat(16),
            key: vec![9; 32],
            ext_name: "OnePass".into(),
            browser: "Chrome".into(),
            extension_id: "ext".into(),
            created_at: 1,
            last_used: 1,
        }],
        vec!["ext".into()],
        audit.to_string_lossy().into_owned(),
    );
    server.set_session(Some(created.session.clone()), "alex@atlas.dev".into());
    Rig {
        _dir: dir,
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
    assert_eq!(next(&rig.events), Event::Unlock);
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
    assert_eq!(next(&rig.events), Event::Changed);
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
    let Event::Stored(id, ext_id) = next(&rig.events) else {
        panic!("stored")
    };
    assert_eq!(ext_id, "ext");
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
