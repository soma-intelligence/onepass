//! Integration tests: the host binary over stdin/stdout, the extension
//! role played in Rust with the bridge crate.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::{Duration, Instant};

use onepass_bridge::channel::Channel;
use onepass_bridge::framing::{MAX_FRAME, read_frame, write_frame};
use onepass_bridge::pairing::{ExtPairing, PairingRecord};
use onepass_bridge::session;
use onepass_bridge::wire::{self, B64, B64Vec, Envelope, Msg};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const BIN: &str = env!("CARGO_BIN_EXE_onepass-native-host");
const EXT_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
const ATLAS: &str = "https://atlas-cloud.test";
const ATLAS_PASSWORD: &str = "Atl4s-Pass-0001";
/// Generous: the first session builds the fixture store (debug build).
const WAIT: Duration = Duration::from_secs(120);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/e2e.json")
}

struct Env {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    config: PathBuf,
}

fn setup(approval: &str, extra: Value) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let config = tmp.path().join("native-host.json");
    let mut cfg = json!({
        "data_dir": data,
        "allowed_extensions": [EXT_ID, "onepass@somalabs.me"],
        "source": {"kind": "fixture", "path": fixture()},
        "approval": approval,
    });
    for (k, v) in extra.as_object().unwrap() {
        cfg[k] = v.clone();
    }
    fs::write(&config, serde_json::to_vec(&cfg).unwrap()).unwrap();
    Env {
        _tmp: tmp,
        data,
        config,
    }
}

/// A running host and a reader thread over its stdout.
struct Host {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: Receiver<Option<Vec<u8>>>,
}

impl Host {
    fn spawn(env: &Env, caller: &[&str]) -> Host {
        Host::spawn_with(env, caller, &[])
    }

    fn spawn_with(env: &Env, caller: &[&str], vars: &[(&str, &str)]) -> Host {
        let mut cmd = Command::new(BIN);
        cmd.arg("--config")
            .arg(&env.config)
            .args(caller)
            .env_remove("ONEPASS_NATIVE_HOST_CONFIG")
            .env_remove("ONEPASS_PASSWORD")
            .env_remove("ONEPASS_DEV_ALLOW_ENV_PASSWORD");
        for (k, v) in vars {
            cmd.env(k, v);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().unwrap();
        let (tx, rx) = channel();
        thread::spawn(move || {
            loop {
                match read_frame(&mut stdout) {
                    Ok(Some(f)) => {
                        if tx.send(Some(f)).is_err() {
                            return;
                        }
                    }
                    _ => {
                        let _ = tx.send(None);
                        return;
                    }
                }
            }
        });
        Host {
            child,
            stdin,
            frames: rx,
        }
    }

    fn chrome(env: &Env) -> Host {
        Host::spawn(env, &[&format!("chrome-extension://{EXT_ID}/")])
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        let w = self.stdin.as_mut().unwrap();
        let _ = w.write_all(bytes);
        let _ = w.flush();
    }

    fn send(&mut self, env: &Envelope) {
        write_frame(self.stdin.as_mut().unwrap(), &wire::to_bytes(env)).unwrap();
    }

    /// Next frame, `None` once stdout is closed.
    fn recv_raw(&mut self) -> Option<Vec<u8>> {
        match self.frames.recv_timeout(WAIT) {
            Ok(f) => f,
            Err(RecvTimeoutError::Disconnected) => None,
            Err(RecvTimeoutError::Timeout) => panic!("host did not answer"),
        }
    }

    fn recv(&mut self) -> Envelope {
        let f = self.recv_raw().expect("host closed");
        wire::parse(&f).unwrap()
    }

    fn close_stdin(&mut self) {
        self.stdin = None;
    }

    fn wait(mut self) -> ExitStatus {
        self.close_stdin();
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("host did not exit");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Stdout closes without another frame, and the process exits 0.
    fn expect_closed(mut self) {
        assert!(self.recv_raw().is_none(), "unexpected frame after close");
        assert!(self.wait().success());
    }
}

fn error_code(env: Envelope) -> String {
    match env {
        Envelope::Error(e) => e.code,
        other => panic!("not an error: {other:?}"),
    }
}

fn log_text(env: &Env) -> String {
    fs::read_to_string(env.data.join("native-host.log")).unwrap_or_default()
}

/// Run a pairing up to `pair_sas`, then `approve` (between `pair_sas`
/// and `pair_done`), and finish it. Returns the extension's record.
fn pair_with(env: &Env, approve: impl FnOnce(&str)) -> PairingRecord {
    let mut host = Host::chrome(env);
    let (mut ext, hello) = ExtPairing::start("OnePass", "Chromium", now()).unwrap();
    host.send(&Envelope::PairHello(hello));
    let Envelope::PairOffer(offer) = host.recv() else {
        panic!("expected pair_offer")
    };
    let (reveal, sas) = ext.on_offer(offer).unwrap();
    host.send(&Envelope::PairReveal(reveal));
    assert_eq!(host.recv(), Envelope::PairSas);
    approve(&sas.0);
    let Envelope::PairDone(done) = host.recv() else {
        panic!("expected pair_done")
    };
    ext.on_done(done, now()).unwrap();
    let (confirm, record) = ext.confirm(now()).unwrap();
    host.send(&Envelope::PairConfirm(confirm));
    assert_eq!(host.recv(), Envelope::PairOk);
    assert!(host.wait().success());
    record
}

fn pair(env: &Env) -> PairingRecord {
    let mut code = String::new();
    let rec = pair_with(env, |sas| code = sas.to_owned());
    assert!(
        log_text(env).contains(&format!("pairing code: {code}")),
        "auto mode logs the code"
    );
    rec
}

/// A session over a new host process: the channel to talk with.
fn open_session(env: &Env, rec: &PairingRecord) -> (Host, Channel) {
    let mut host = Host::chrome(env);
    let (pending, hello) = session::ext_hello(rec).unwrap();
    host.send(&Envelope::Hello(hello));
    let Envelope::Welcome(welcome) = host.recv() else {
        panic!("expected welcome")
    };
    let (ch, finish) = pending.on_welcome(welcome, now()).unwrap();
    host.send(&Envelope::Finish(finish));
    (host, ch)
}

fn request(host: &mut Host, ch: &mut Channel, req: Value) -> Value {
    let env = ch.seal(&serde_json::to_vec(&req).unwrap()).unwrap();
    host.send(&env);
    let Envelope::Msg(m) = host.recv() else {
        panic!("expected msg")
    };
    let plain = ch.open(&m).unwrap();
    serde_json::from_slice(&plain).unwrap()
}

#[test]
fn pairing_then_session_then_fill() {
    let env = setup("auto", json!({}));
    let rec = pair(&env);
    let (mut host, mut ch) = open_session(&env, &rec);

    let status = request(&mut host, &mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(status["ok"]["locked"], false, "{status}");

    let list = request(
        &mut host,
        &mut ch,
        json!({"id": 2, "op": "list_for_origin", "ctx": "menu", "origin": ATLAS}),
    );
    let items = list["ok"]["items"].as_array().expect("items");
    let titles: Vec<&str> = items.iter().map(|i| i["title"].as_str().unwrap()).collect();
    assert!(titles.contains(&"Atlas Cloud"), "{titles:?}");
    assert!(titles.contains(&"Atlas Cloud (multi)"), "{titles:?}");
    assert!(!titles.contains(&"Atlas ancien"));
    assert!(!titles.contains(&"Atlas cache"));
    assert!(!list.to_string().contains(ATLAS_PASSWORD));
    let id = items.iter().find(|i| i["title"] == "Atlas Cloud").unwrap()["item_id"].clone();

    let fill = request(
        &mut host,
        &mut ch,
        json!({"id": 3, "op": "fill_login", "ctx": "menu", "item_id": id,
               "origin": ATLAS, "fields": ["username", "password", "totp"]}),
    );
    assert_eq!(fill["ok"]["username"], "alex@atlas.dev", "{fill}");
    assert_eq!(fill["ok"]["password"], ATLAS_PASSWORD);
    assert_eq!(fill["ok"]["totp"].as_str().unwrap().len(), 6);

    // Wrong origin: refused by the host.
    let evil = request(
        &mut host,
        &mut ch,
        json!({"id": 4, "op": "fill_login", "ctx": "menu", "item_id": id,
               "origin": "https://atlas-cloud.test.evil.test", "fields": ["password"]}),
    );
    assert_eq!(evil["err"]["code"], "origin_mismatch", "{evil}");
    assert!(host.wait().success());

    // Journal and audit: written, without secrets.
    let log = log_text(&env);
    assert!(log.contains("DEV MODE"));
    assert!(!log.contains(ATLAS_PASSWORD));
    let audit = fs::read_to_string(env.data.join("audit.log")).unwrap();
    assert!(audit.contains("fill_login"), "{audit}");
    assert!(!audit.contains(ATLAS_PASSWORD));
    let mode = fs::metadata(env.data.join("audit.log"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn plan_fill_round_trip() {
    let env = setup("auto", json!({}));
    let rec = pair(&env);
    let (mut host, mut ch) = open_session(&env, &rec);

    let salt = request(
        &mut host,
        &mut ch,
        json!({"id": 1, "op": "fill_salt", "ctx": "menu"}),
    );
    assert_eq!(salt["ok"]["salt"].as_str().unwrap().len(), 64, "{salt}");

    let form = json!({"form_ref": "f1",
        "intent_hints": {"kind": "login", "signup_words": false, "reset_words": false,
                         "checkout_words": false, "ignore": false},
        "step_index": null,
        "fields": [
            {"field_ref": "u1", "role": "username", "confidence": 0.9, "visible": true,
             "prefilled": "empty"},
            {"field_ref": "p1", "role": "current_password", "confidence": 0.9,
             "visible": true, "prefilled": "empty"}],
        "buttons": [{"button_ref": "b1", "class": "submit"}]});
    let context = json!({"origin": ATLAS, "top_origin": ATLAS, "frame_kind": "top",
                         "forms": [form], "typed_username_hash": null});
    let plan = request(
        &mut host,
        &mut ch,
        json!({"id": 2, "op": "plan_fill", "ctx": "menu", "origin": ATLAS,
               "context": context}),
    );
    let p = &plan["ok"]["plan"];
    assert_eq!(p["intent"], "login", "{plan}");
    // Atlas Cloud and Atlas Cloud (multi) tie: a menu, never a chain.
    assert_eq!(p["action"], "show_menu", "{plan}");
    let first = p["groups"][0]["item_id"].as_str().unwrap().to_owned();
    assert_eq!(first.len(), 36, "hyphenated id: {first}");
    assert_eq!(p["alternatives"].as_array().unwrap().len(), 1, "{plan}");
    assert!(!plan.to_string().contains(ATLAS_PASSWORD));

    let noted = request(
        &mut host,
        &mut ch,
        json!({"id": 3, "op": "note_fill", "ctx": "chain", "item_id": first,
               "origin": ATLAS, "roles": ["username", "current_password"],
               "intent": "login", "steps": ["fill"]}),
    );
    assert_eq!(noted["ok"], json!({}), "{noted}");
    let again = request(
        &mut host,
        &mut ch,
        json!({"id": 4, "op": "plan_fill", "ctx": "menu", "origin": ATLAS,
               "context": context}),
    );
    assert_eq!(again["ok"]["plan"]["confidence"], "high", "{again}");
    assert_eq!(again["ok"]["plan"]["groups"][0]["item_id"], first.as_str());
    assert!(host.wait().success());

    let audit = fs::read_to_string(env.data.join("audit.log")).unwrap();
    assert!(audit.contains("plan_fill"), "{audit}");
    assert!(audit.contains("note_fill"), "{audit}");
    assert!(!audit.contains("\"u1\""), "{audit}");
    assert!(!audit.contains("current_password"), "{audit}");
}

#[test]
fn firefox_arguments_are_accepted() {
    let env = setup("auto", json!({}));
    let mut host = Host::spawn(
        &env,
        &["/x/me.somalabs.onepass.dev.json", "onepass@somalabs.me"],
    );
    let (_ext, hello) = ExtPairing::start("OnePass", "Firefox", now()).unwrap();
    host.send(&Envelope::PairHello(hello));
    assert!(matches!(host.recv(), Envelope::PairOffer(_)));
    assert!(host.wait().success());
}

#[test]
fn unknown_pairing_error() {
    let env = setup("auto", json!({}));
    let rec = PairingRecord {
        pairing_id: [7; 16],
        key: Zeroizing::new([9; 32]),
        ext_name: "OnePass".into(),
        browser: "Chromium".into(),
        created_at: now(),
    };
    let mut host = Host::chrome(&env);
    let (_pending, hello) = session::ext_hello(&rec).unwrap();
    host.send(&Envelope::Hello(hello));
    assert_eq!(error_code(host.recv()), "unknown_pairing");
    host.expect_closed();
}

#[test]
fn disallowed_extension_rejected() {
    let env = setup("auto", json!({}));
    let mut host = Host::spawn(
        &env,
        &["chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/"],
    );
    let (_ext, hello) = ExtPairing::start("OnePass", "Chromium", now()).unwrap();
    host.send(&Envelope::PairHello(hello));
    assert_eq!(error_code(host.recv()), "not_allowed");
    host.expect_closed();
    assert!(!env.data.join("pairings.json").exists());
    // The rejected id is attacker input: never in the journal.
    assert!(!log_text(&env).contains("zzzzzzzz"));

    // No caller argument at all: rejected too.
    let mut host = Host::spawn(&env, &[]);
    let (_ext, hello) = ExtPairing::start("OnePass", "Chromium", now()).unwrap();
    host.send(&Envelope::PairHello(hello));
    assert_eq!(error_code(host.recv()), "not_allowed");
    host.expect_closed();
}

#[test]
fn oversized_frame_closes() {
    let env = setup("auto", json!({}));
    let mut host = Host::chrome(&env);
    let mut data = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
    data.extend_from_slice(&[b'{'; 64]);
    host.send_raw(&data);
    host.expect_closed();
}

#[test]
fn garbage_json_closes_without_panic() {
    let env = setup("auto", json!({}));
    let mut host = Host::chrome(&env);
    let garbage = b"{not json at all \xff\xfe";
    let mut data = (garbage.len() as u32).to_le_bytes().to_vec();
    data.extend_from_slice(garbage);
    host.send_raw(&data);
    assert_eq!(error_code(host.recv()), "bad_frame");
    host.expect_closed();
    assert!(!log_text(&env).contains("not json"));
}

#[test]
fn truncated_frame_closes() {
    let env = setup("auto", json!({}));
    let mut host = Host::chrome(&env);
    host.send_raw(&[200, 0, 0, 0, b'{']);
    host.close_stdin();
    host.expect_closed();
}

#[test]
fn unknown_version_gets_version_error() {
    let env = setup("auto", json!({}));
    let mut host = Host::chrome(&env);
    let body = br#"{"v":2,"t":"hello"}"#;
    let mut data = (body.len() as u32).to_le_bytes().to_vec();
    data.extend_from_slice(body);
    host.send_raw(&data);
    let raw = host.recv_raw().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&raw).unwrap(),
        json!({"v": 1, "t": "error", "code": "version"})
    );
    host.expect_closed();
}

#[test]
fn pairings_file_mode_0600() {
    let env = setup("auto", json!({}));
    pair(&env);
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&env.data.join("pairings.json")), 0o600);
    assert_eq!(mode(&env.data), 0o700);
    let text = fs::read_to_string(env.data.join("pairings.json")).unwrap();
    assert!(text.contains(EXT_ID), "the extension id is stored");
}

#[test]
fn file_approval_mode() {
    let env = setup("file", json!({}));
    let pending = env.data.join("pending-pairing.json");
    let approved = env.data.join("pairing-approved");
    let rec = pair_with(&env, |sas| {
        let deadline = Instant::now() + WAIT;
        while !pending.exists() {
            assert!(Instant::now() < deadline, "no pending-pairing.json");
            thread::sleep(Duration::from_millis(20));
        }
        // The file may be in the middle of its rename: read until whole.
        let p: Value = loop {
            if let Ok(v) = serde_json::from_slice(&fs::read(&pending).unwrap_or_default()) {
                break v;
            }
            thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(p["sas"], sas);
        assert_eq!(p["ext_name"], "OnePass");
        assert_eq!(p["browser"], "Chromium");
        let mode = fs::metadata(&pending).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let st = Command::new(BIN)
            .arg("approve")
            .arg(sas)
            .arg("--config")
            .arg(&env.config)
            .env_remove("ONEPASS_NATIVE_HOST_CONFIG")
            .status()
            .unwrap();
        assert!(st.success());
    });
    assert!(!pending.exists(), "pending file removed");
    assert!(!approved.exists(), "approval file removed");
    // The pairing works for a session.
    let (mut host, mut ch) = open_session(&env, &rec);
    let status = request(&mut host, &mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(status["ok"]["locked"], false);
    assert!(host.wait().success());
}

#[test]
fn locked_fixture_unlocks_and_reprompt_follows_config() {
    let env = setup("auto", json!({"unlocked": false, "reprompt": "allow"}));
    let rec = pair(&env);
    let (mut host, mut ch) = open_session(&env, &rec);
    let status = request(&mut host, &mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(status["ok"]["locked"], true, "{status}");
    let list = request(
        &mut host,
        &mut ch,
        json!({"id": 2, "op": "list_for_origin", "ctx": "menu", "origin": ATLAS}),
    );
    assert_eq!(list["err"]["code"], "locked", "{list}");
    let unlock = request(&mut host, &mut ch, json!({"id": 3, "op": "unlock"}));
    assert_eq!(unlock["ok"]["locked"], false, "{unlock}");
    let list = request(
        &mut host,
        &mut ch,
        json!({"id": 4, "op": "list_for_origin", "ctx": "menu",
               "origin": "https://vault.atlas-cloud.test"}),
    );
    let id = list["ok"]["items"][0]["item_id"].clone();
    let fill = request(
        &mut host,
        &mut ch,
        json!({"id": 5, "op": "fill_login", "ctx": "menu", "item_id": id,
               "origin": "https://vault.atlas-cloud.test", "fields": ["password"]}),
    );
    assert_eq!(fill["ok"]["password"], "Repr-Pass-0007", "{fill}");
    assert!(host.wait().success());
}

#[test]
fn tampered_session_frame_closes() {
    let env = setup("auto", json!({}));
    let rec = pair(&env);
    let (mut host, mut ch) = open_session(&env, &rec);
    let Envelope::Msg(m) = ch.seal(br#"{"id":1,"op":"status"}"#).unwrap() else {
        panic!()
    };
    let mut d = m.d.0.clone();
    d[0] ^= 1;
    host.send(&Envelope::Msg(Msg {
        c: m.c,
        d: B64Vec(d),
    }));
    host.expect_closed();
}

#[test]
fn wrong_finish_mac_closes() {
    let env = setup("auto", json!({}));
    let rec = pair(&env);
    let mut host = Host::chrome(&env);
    let (_pending, hello) = session::ext_hello(&rec).unwrap();
    host.send(&Envelope::Hello(hello));
    assert!(matches!(host.recv(), Envelope::Welcome(_)));
    host.send(&Envelope::Finish(wire::Finish { mac: B64([0; 32]) }));
    assert_eq!(error_code(host.recv()), "bad_mac");
    host.expect_closed();
}

/// A dev data directory in the CLI format: `device.bin` (postcard of the
/// Secret Key and the versioned device state bytes) next to `vault.sqlite`.
fn make_dev_account(dir: &Path, password: &str) {
    use onepass_core::crypto::{DEV_KDF_FLOOR, KdfParams};
    use onepass_core::model::{FieldValue, ItemType, ItemUrl, MatchRule, new_item};
    use onepass_core::repo::{DeviceState, Repository};
    use onepass_core::store::SqliteStore;

    #[derive(serde::Serialize)]
    struct DeviceFile<'a> {
        secret_key: &'a str,
        #[serde(with = "onepass_core::format::device_state_bytes")]
        state: &'a DeviceState,
    }

    fs::create_dir_all(dir).unwrap();
    let mut kdf = KdfParams::new_default().unwrap();
    (kdf.m_kib, kdf.t, kdf.p) = DEV_KDF_FLOOR;
    let store = SqliteStore::open(&dir.join("vault.sqlite")).unwrap();
    let (mut repo, key) = Repository::create_account(store, password, kdf).unwrap();
    let vault = repo.vaults().unwrap().remove(0);
    let mut item = new_item(ItemType::Login, vault.id, "Atlas Cloud");
    item.field_mut("username").unwrap().value = FieldValue::Text("alex@atlas.dev".into());
    item.field_mut("password").unwrap().value =
        FieldValue::Password(Zeroizing::new("Dev-Pass-0042".into()));
    item.urls.push(ItemUrl {
        label: "site web".into(),
        url: ATLAS.into(),
        rule: MatchRule::Domain,
        primary: true,
    });
    repo.save_item(&vault, item).unwrap();
    let secret = key.to_display();
    let bytes = postcard::to_allocvec(&DeviceFile {
        secret_key: &secret,
        state: repo.device_state(),
    })
    .unwrap();
    fs::write(dir.join("device.bin"), bytes).unwrap();
}

#[test]
fn dev_source_serves_the_cli_vault() {
    let env = setup("auto", json!({"source": {"kind": "dev"}}));
    let password = "correct horse battery staple";
    make_dev_account(&env.data, password);
    let rec = pair(&env);
    let vars = [
        ("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1"),
        ("ONEPASS_PASSWORD", password),
    ];

    let caller = format!("chrome-extension://{EXT_ID}/");
    let session_with = |vars: &[(&str, &str)]| {
        let mut host = Host::spawn_with(&env, &[&caller], vars);
        let (pending, hello) = session::ext_hello(&rec).unwrap();
        host.send(&Envelope::Hello(hello));
        let Envelope::Welcome(welcome) = host.recv() else {
            panic!("expected welcome")
        };
        let (ch, finish) = pending.on_welcome(welcome, now()).unwrap();
        host.send(&Envelope::Finish(finish));
        (host, ch)
    };

    let (mut host, mut ch) = session_with(&vars);
    let list = request(
        &mut host,
        &mut ch,
        json!({"id": 1, "op": "list_for_origin", "ctx": "menu", "origin": ATLAS}),
    );
    let id = list["ok"]["items"][0]["item_id"].clone();
    let fill = request(
        &mut host,
        &mut ch,
        json!({"id": 2, "op": "fill_login", "ctx": "menu", "item_id": id,
               "origin": ATLAS, "fields": ["password"]}),
    );
    assert_eq!(fill["ok"]["password"], "Dev-Pass-0042", "{fill}");
    assert!(host.wait().success());
    assert!(!log_text(&env).contains(password));

    // Without the environment password the vault stays locked.
    let (mut host, mut ch) = session_with(&[]);
    let status = request(&mut host, &mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(status["ok"]["locked"], true, "{status}");
    let unlock = request(&mut host, &mut ch, json!({"id": 2, "op": "unlock"}));
    assert_eq!(unlock["ok"]["locked"], true, "{unlock}");
    assert!(host.wait().success());
}

/// `device.bin` as the CLI writes it.
#[derive(serde::Deserialize, serde::Serialize)]
struct DeviceBin {
    secret_key: String,
    #[serde(with = "onepass_core::format::device_state_bytes")]
    state: onepass_core::repo::DeviceState,
}

fn device_bin(dir: &Path) -> DeviceBin {
    postcard::from_bytes(&fs::read(dir.join("device.bin")).unwrap()).unwrap()
}

#[test]
fn dev_writes_persist_device_state_and_detect_rollback() {
    let env = setup("auto", json!({"source": {"kind": "dev"}}));
    let password = "correct horse battery staple";
    make_dev_account(&env.data, password);
    let rec = pair(&env);
    let vars = [
        ("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1"),
        ("ONEPASS_PASSWORD", password),
    ];
    let caller = format!("chrome-extension://{EXT_ID}/");
    let session_with = |vars: &[(&str, &str)]| {
        let mut host = Host::spawn_with(&env, &[&caller], vars);
        let (pending, hello) = session::ext_hello(&rec).unwrap();
        host.send(&Envelope::Hello(hello));
        let Envelope::Welcome(welcome) = host.recv() else {
            panic!("expected welcome")
        };
        let (ch, finish) = pending.on_welcome(welcome, now()).unwrap();
        host.send(&Envelope::Finish(finish));
        (host, ch)
    };

    let before = device_bin(&env.data);
    let seq_before: Vec<u64> = before.state.last_seen.values().map(|m| m.seq).collect();
    let old_store = fs::read(env.data.join("vault.sqlite")).unwrap();

    let (mut host, mut ch) = session_with(&vars);
    let vaults = request(&mut host, &mut ch, json!({"id": 1, "op": "vaults"}));
    let vault_id = vaults["ok"]["vaults"][0]["id"].clone();
    let saved = request(
        &mut host,
        &mut ch,
        json!({"id": 2, "op": "save_login", "ctx": "save_prompt", "origin": ATLAS,
               "title": "Atlas Cloud 2", "username": "alex.ops@atlas.dev",
               "password": "Dev-Pass-0043", "vault_id": vault_id, "rule": "domain",
               "tags": []}),
    );
    assert!(saved["ok"]["item_id"].is_string(), "{saved}");
    assert!(host.wait().success());

    // device.bin: same Secret Key, last seen manifest advanced, 0600.
    let after = device_bin(&env.data);
    assert_eq!(after.secret_key, before.secret_key);
    let seq_after: Vec<u64> = after.state.last_seen.values().map(|m| m.seq).collect();
    assert_eq!(seq_after.len(), seq_before.len());
    assert!(
        seq_after.iter().zip(&seq_before).any(|(a, b)| a > b),
        "{seq_before:?} -> {seq_after:?}"
    );
    let mode = fs::metadata(env.data.join("device.bin"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    // Roll vault.sqlite back to before the write: refused, vault locked.
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(env.data.join(format!("vault.sqlite{suffix}")));
    }
    fs::write(env.data.join("vault.sqlite"), old_store).unwrap();
    let (mut host, mut ch) = session_with(&vars);
    let status = request(&mut host, &mut ch, json!({"id": 1, "op": "status"}));
    let list = request(
        &mut host,
        &mut ch,
        json!({"id": 2, "op": "list_for_origin", "ctx": "menu", "origin": ATLAS}),
    );
    assert!(
        status["ok"]["locked"] == true || list.get("err").is_some(),
        "rollback went unnoticed: {status} {list}"
    );
    assert!(host.wait().success());
}

const DEV_PASSWORD: &str = "correct horse battery staple";

/// A dev account and a pairing, for the device state tests.
fn dev_env() -> (Env, PairingRecord) {
    let env = setup("auto", json!({"source": {"kind": "dev"}}));
    make_dev_account(&env.data, DEV_PASSWORD);
    let rec = pair(&env);
    (env, rec)
}

/// A session over a new dev host process, unlocked by the environment.
fn dev_session(env: &Env, rec: &PairingRecord) -> (Host, Channel) {
    let caller = format!("chrome-extension://{EXT_ID}/");
    let vars = [
        ("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1"),
        ("ONEPASS_PASSWORD", DEV_PASSWORD),
    ];
    let mut host = Host::spawn_with(env, &[&caller], &vars);
    let (pending, hello) = session::ext_hello(rec).unwrap();
    host.send(&Envelope::Hello(hello));
    let Envelope::Welcome(welcome) = host.recv() else {
        panic!("expected welcome")
    };
    let (ch, finish) = pending.on_welcome(welcome, now()).unwrap();
    host.send(&Envelope::Finish(finish));
    (host, ch)
}

/// Open the dev account as the CLI does (or another device syncing the
/// store), run `f`, and rewrite `device.bin` only when `persist`.
fn cli_style<T>(
    dir: &Path,
    persist: bool,
    f: impl FnOnce(&mut onepass_core::repo::Repository<onepass_core::store::SqliteStore>) -> T,
) -> T {
    use onepass_core::crypto::SecretKey;
    use onepass_core::repo::Repository;
    use onepass_core::store::SqliteStore;

    let file = device_bin(dir);
    let key = SecretKey::parse(&file.secret_key).unwrap();
    let store = SqliteStore::open(&dir.join("vault.sqlite")).unwrap();
    let mut repo = Repository::unlock(store, DEV_PASSWORD, &key, file.state).unwrap();
    let out = f(&mut repo);
    if persist {
        let new = DeviceBin {
            secret_key: file.secret_key,
            state: repo.device_state().clone(),
        };
        fs::write(dir.join("device.bin"), postcard::to_allocvec(&new).unwrap()).unwrap();
    }
    out
}

/// Save a new note in the vault at `index` (vaults sorted by id): the
/// manifest of that vault moves one seq ahead. Returns the vault id.
fn add_note(
    repo: &mut onepass_core::repo::Repository<onepass_core::store::SqliteStore>,
    index: usize,
    title: &str,
) -> onepass_core::Id {
    use onepass_core::model::{FieldValue, ItemType, new_item};
    let vault = repo.vaults().unwrap().remove(index);
    let mut item = new_item(ItemType::SecureNote, vault.id, title);
    item.field_mut("content").unwrap().value = FieldValue::Text("note".into());
    repo.save_item(&vault, item).unwrap();
    vault.id
}

/// Fold the WAL of `vault.sqlite` into the file (another connection may be
/// open, but idle).
fn fold_wal(dir: &Path) {
    let store = onepass_core::store::SqliteStore::open(&dir.join("vault.sqlite")).unwrap();
    store.compact().unwrap();
}

/// A consistent copy of `vault.sqlite`: the WAL folded in first.
fn store_snapshot(dir: &Path) -> Vec<u8> {
    fold_wal(dir);
    fs::read(dir.join("vault.sqlite")).unwrap()
}

/// Put `snapshot` back as `vault.sqlite`, without the WAL of later writes.
fn store_restore(dir: &Path, snapshot: &[u8]) {
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(dir.join(format!("vault.sqlite{suffix}")));
    }
    fs::write(dir.join("vault.sqlite"), snapshot).unwrap();
}

fn seen_seq(dir: &Path, vault: onepass_core::Id) -> u64 {
    device_bin(dir).state.last_seen[&vault].seq
}

fn list_atlas(host: &mut Host, ch: &mut Channel, id: u64) -> Value {
    request(
        host,
        ch,
        json!({"id": id, "op": "list_for_origin", "ctx": "menu", "origin": ATLAS}),
    )
}

#[test]
fn dev_reads_persist_device_state() {
    let (env, rec) = dev_env();
    // The store moves ahead of device.bin (another writer, not persisted).
    let vault = cli_style(&env.data, false, |repo| add_note(repo, 0, "Atlas Two"));
    let before = seen_seq(&env.data, vault);

    let (mut host, mut ch) = dev_session(&env, &rec);
    let list = list_atlas(&mut host, &mut ch, 1);
    assert!(list["ok"]["items"].is_array(), "{list}");
    assert!(host.wait().success());

    assert_eq!(seen_seq(&env.data, vault), before + 1, "read not persisted");
}

#[test]
fn dev_host_never_regresses_a_cli_advance() {
    use onepass_core::vault::VaultMeta;
    let (env, rec) = dev_env();
    // A second vault, created and persisted by the CLI.
    cli_style(&env.data, true, |repo| {
        repo.create_vault(VaultMeta {
            name: "Second".into(),
            icon: "folder".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        })
        .unwrap();
    });

    let (mut host, mut ch) = dev_session(&env, &rec);
    let vaults = request(&mut host, &mut ch, json!({"id": 1, "op": "vaults"}));
    let first = vaults["ok"]["vaults"][0]["id"].clone();
    assert!(first.is_string(), "{vaults}");

    // Between two host operations the CLI advances the other vault.
    let other = cli_style(&env.data, true, |repo| add_note(repo, 1, "Elsewhere"));
    let advanced = seen_seq(&env.data, other);

    let saved = request(
        &mut host,
        &mut ch,
        json!({"id": 2, "op": "save_login", "ctx": "save_prompt", "origin": ATLAS,
               "title": "Atlas Cloud 2", "username": "alex.ops@atlas.dev",
               "password": "Dev-Pass-0043", "vault_id": first, "rule": "domain",
               "tags": []}),
    );
    assert!(saved["ok"]["item_id"].is_string(), "{saved}");
    assert!(host.wait().success());

    assert_eq!(
        seen_seq(&env.data, other),
        advanced,
        "the host regressed the last seen manifest"
    );
}

#[test]
fn dev_rollback_after_a_host_read_is_refused() {
    let (env, rec) = dev_env();
    let old_store = store_snapshot(&env.data);
    // The store moves ahead of device.bin; only the host sees it.
    cli_style(&env.data, false, |repo| add_note(repo, 0, "Atlas Two"));

    let (mut host, mut ch) = dev_session(&env, &rec);
    let list = list_atlas(&mut host, &mut ch, 1);
    assert!(list["ok"]["items"].is_array(), "{list}");
    assert!(host.wait().success());

    // Roll vault.sqlite back to before that write.
    store_restore(&env.data, &old_store);
    let (mut host, mut ch) = dev_session(&env, &rec);
    let status = request(&mut host, &mut ch, json!({"id": 1, "op": "status"}));
    let list = list_atlas(&mut host, &mut ch, 2);
    assert!(
        status["ok"]["locked"] == true || list["err"]["code"] == "internal",
        "rollback went unnoticed: {status} {list}"
    );
    assert!(host.wait().success());
    // Refused for the rollback, not for a damaged store.
    assert!(
        log_text(&env).contains("manifest rollback detected"),
        "{}",
        log_text(&env)
    );
}

#[test]
fn dev_host_refreshes_device_state_before_each_operation() {
    let (env, rec) = dev_env();
    let old_store = store_snapshot(&env.data);

    let (mut host, mut ch) = dev_session(&env, &rec);
    let status = request(&mut host, &mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(status["ok"]["locked"], false, "{status}");

    // While the host is open, the CLI accepts a newer manifest and persists
    // it, then vault.sqlite is rolled back under both.
    cli_style(&env.data, true, |repo| add_note(repo, 0, "Atlas Two"));
    // The host still holds a connection, so the CLI write stays in the WAL;
    // fold it so the restore below really drops it.
    fold_wal(&env.data);
    store_restore(&env.data, &old_store);

    let list = list_atlas(&mut host, &mut ch, 2);
    assert_eq!(
        list["err"]["code"], "internal",
        "rollback went unnoticed: {list}"
    );
    assert!(host.wait().success());
    assert!(
        log_text(&env).contains("manifest rollback detected"),
        "{}",
        log_text(&env)
    );
}
