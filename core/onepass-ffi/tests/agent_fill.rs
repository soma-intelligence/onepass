//! `fill_in_browser` end to end in the app's Rust layer (spec 2026-11-07,
//! plan task 6): an MCP session served by `McpHost` (the test plays the
//! relay) and a browser bridge session served by `BridgeServer` (the test
//! plays the Chrome extension over a real encrypted session), meeting in
//! the process's agent hub.
//! Run with `--features dev-fast-kdf`.
//!
//! The hub is one per process: every test here that uses it (any bridge
//! session or MCP fill) must hold [`one_at_a_time`] for its whole run.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use onepass_bridge::channel::Channel;
use onepass_bridge::framing::{read_frame, write_frame};
use onepass_bridge::pairing::PairingRecord;
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
const PASSWORD: &str = "Dev-Pass-0042";

/// The hub is one per process: the tests of this file take turns.
fn one_at_a_time() -> MutexGuard<'static, ()> {
    static TURN: Mutex<()> = Mutex::new(());
    TURN.lock().unwrap_or_else(|e| e.into_inner())
}

// ---- the app's two delegates

struct Quiet;

impl BridgeDelegate for Quiet {
    fn pairing_requested(&self, _request: FfiBridgePairingRequest) {}
    fn pairing_ended(&self, _request_id: u64) {}
    fn pairing_stored(&self, _pairing: FfiBridgePairing) {}
    fn pairing_used(&self, _pairing_id: String, _at: u64) {}
    fn unlock_requested(&self) {}
    fn confirm_reprompt(&self, _vault_id: String, _item_id: String) -> bool {
        false
    }
    fn vault_changed(&self) {}
    fn note(&self, _message: String) {}
}

/// Runs while the user is being asked (a test moves the page there).
type OnApprove = Box<dyn Fn() + Send + Sync>;

/// Approves everything and records what it was shown.
struct Accepting {
    asked: Mutex<Vec<FfiApprovalRequest>>,
    during: Mutex<Option<OnApprove>>,
}

impl FfiDeveloperUi for Accepting {
    fn approve(&self, request: FfiApprovalRequest) -> FfiAnswer {
        self.asked.lock().unwrap().push(request);
        if let Some(f) = self.during.lock().unwrap().take() {
            f();
        }
        FfiAnswer {
            decision: FfiDecision::AllowOnce,
            approved_on: Some("mac".into()),
        }
    }
    fn verify_presence(&self, _reason: String) -> bool {
        true
    }
    fn pair_request(&self, _client: FfiMcpClient) -> bool {
        true
    }
}

// ---- the fixture: one session, the bridge and the MCP host over it

struct Rig {
    dir: TempDir,
    session: Arc<Session>,
    vault_id: String,
    server: Arc<BridgeServer>,
    record: PairingRecord,
    ui: Arc<Accepting>,
    host: Arc<McpHost>,
}

impl Rig {
    fn data(&self) -> String {
        self.dir.path().join("dev").display().to_string()
    }
    fn mcp_socket(&self) -> String {
        self.dir
            .path()
            .join("dev")
            .join("mcp.sock")
            .display()
            .to_string()
    }
}

fn rig() -> Rig {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(db, "Café-étoile".into(), FAST).unwrap();
    let session = created.session;
    let vault = session.vaults().unwrap().remove(0);
    let vault_id = vault.id.clone();

    // A login for the site, in a vault exposed to agents with `fill`.
    let mut item = session
        .new_item(vault_id.clone(), FfiItemType::Login, "Atlas Cloud".into())
        .unwrap();
    for f in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match f.id.as_str() {
            "username" => {
                f.value = FfiFieldValue::Text {
                    value: "alex@atlas.dev".into(),
                }
            }
            "password" => {
                f.value = FfiFieldValue::Password {
                    value: PASSWORD.into(),
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
    session.save_item(item).unwrap();
    let mut meta = vault.meta.clone();
    meta.mcp_access = true;
    session.update_vault(vault_id.clone(), meta).unwrap();
    let data = dir.path().join("dev").display().to_string();
    session
        .clone()
        .set_mcp_policy(
            data.clone(),
            vec![FfiClientScopes {
                vault_id: vault_id.clone(),
                scopes: vec!["metadata".into(), "fill".into()],
            }],
            false,
        )
        .unwrap();

    let record = PairingRecord {
        pairing_id: [7; 16],
        key: Zeroizing::new([9; 32]),
        ext_name: "OnePass".into(),
        browser: "Chrome".into(),
        created_at: 1,
    };
    let server = BridgeServer::new(
        Arc::new(Quiet),
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
        vec!["ext".into()],
        dir.path()
            .join("bridge-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );
    server.set_session(Some(session.clone()), "alex@atlas.dev".into());

    let ui = Arc::new(Accepting {
        asked: Mutex::new(Vec::new()),
        during: Mutex::new(None),
    });
    let host = McpHost::start_any_relay_for_tests(
        session.clone(),
        FfiMcpHostConfig {
            data_dir: data,
            socket_path: dir
                .path()
                .join("dev")
                .join("mcp.sock")
                .display()
                .to_string(),
            relay_path: "/unused".into(),
            protected_dirs: vec![dir.path().display().to_string()],
        },
        ui.clone(),
    )
    .unwrap();
    Rig {
        dir,
        session,
        vault_id,
        server,
        record,
        ui,
        host,
    }
}

// ---- the extension, over a real bridge session

struct Ext {
    s: UnixStream,
    ch: Channel,
    done: thread::JoinHandle<()>,
}

impl Ext {
    fn connect(rig: &Rig) -> Ext {
        let (s, app) = UnixStream::pair().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(40))).unwrap();
        let server = rig.server.clone();
        let done = thread::spawn(move || serve_for_tests(&server, app, "ext", true));
        let mut s = s;
        let (pending, hello) = session::ext_hello(&rig.record).unwrap();
        write_frame(&mut s, &wire::to_bytes(&Envelope::Hello(hello))).unwrap();
        let Envelope::Welcome(w) = wire::parse(&read_frame(&mut s).unwrap().unwrap()).unwrap()
        else {
            panic!("welcome")
        };
        let (ch, finish) = pending.on_welcome(w, 1).unwrap();
        write_frame(&mut s, &wire::to_bytes(&Envelope::Finish(finish))).unwrap();
        Ext { s, ch, done }
    }

    fn request(&mut self, req: Value) -> Value {
        let sealed = self.ch.seal(req.to_string().as_bytes()).unwrap();
        write_frame(&mut self.s, &wire::to_bytes(&sealed)).unwrap();
        let Envelope::Msg(m) = wire::parse(&read_frame(&mut self.s).unwrap().unwrap()).unwrap()
        else {
            panic!("msg")
        };
        serde_json::from_slice(&self.ch.open(&m).unwrap()).unwrap()
    }

    fn end(self) {
        drop(self.s);
        self.done.join().unwrap();
    }
}

/// What the fake extension answers to a fill job.
#[derive(Clone, Copy)]
enum OnFill {
    /// Asks the host for the values with the agent context, then reports
    /// the two fields filled.
    Fill,
    /// The tab changed while the user approved.
    TabSwitched,
}

/// What the fake extension saw.
#[derive(Debug, Default)]
struct Seen {
    probe_url: String,
    fill_job: Value,
    /// The password the host gave for the ticket (checked, never printed).
    got_password: bool,
}

/// Plays the extension on its own thread: long-polls `agent_wait`, answers
/// the probe with the Atlas tab, then the fill job as `on_fill` says.
fn extension(rig: &Rig, on_fill: OnFill) -> thread::JoinHandle<Seen> {
    let mut ext = Ext::connect(rig);
    thread::spawn(move || {
        let mut seen = Seen::default();
        let mut id = 1;
        loop {
            id += 1;
            let w = ext.request(json!({"id": id, "op": "agent_wait"}));
            assert!(w.get("ok").is_some(), "{w}");
            let job = w["ok"]["job"].clone();
            match job["job"].as_str() {
                None => continue,
                Some("probe") => {
                    seen.probe_url = job["url"].as_str().unwrap().to_owned();
                    id += 1;
                    let ack = ext.request(json!({"id": id, "op": "agent_probe_result",
                        "request_id": job["request_id"],
                        "result": {"ok": {"tab_title": "Atlas Cloud - Sign in",
                            "origin": ATLAS, "document_id": "doc-1"}}}));
                    assert_eq!(ack["ok"], json!({}), "{ack}");
                }
                Some("fill") => {
                    seen.fill_job = job.clone();
                    let result = match on_fill {
                        OnFill::Fill => {
                            id += 1;
                            let values = ext.request(json!({"id": id, "op": "fill_login",
                                "ctx": "agent", "agent_request": job["request_id"],
                                "item_id": job["item_id"], "origin": ATLAS,
                                "fields": ["username", "password"]}));
                            seen.got_password = values["ok"]["password"] == PASSWORD;
                            json!({"ok": {"filled": ["username", "password"], "submitted": false}})
                        }
                        OnFill::TabSwitched => json!({"err": "tab_mismatch"}),
                    };
                    id += 1;
                    let ack = ext.request(json!({"id": id, "op": "agent_fill_result",
                        "request_id": job["request_id"], "result": result}));
                    assert_eq!(ack["ok"], json!({}), "{ack}");
                    break;
                }
                Some(other) => panic!("unexpected job {other}"),
            }
        }
        ext.end();
        seen
    })
}

// ---- the agent, over the MCP relay socket

struct Relay {
    out: UnixStream,
    input: BufReader<UnixStream>,
}

impl Relay {
    fn connect(socket: &str) -> Relay {
        let out = UnixStream::connect(socket).unwrap();
        out.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let input = BufReader::new(out.try_clone().unwrap());
        let mut r = Relay { out, input };
        r.send(json!({"t": "hello", "v": 1, "client": {
            "id": "team:TEAMID0001:com.exemple.agent", "label": "Agent Exemple",
            "signed": true, "hardened": null,
            "code": {"kind": "team", "team_id": "TEAMID0001", "identifier": "com.exemple.agent"},
            "chain": ["team:TEAMID0001:com.exemple.agent"],
        }}));
        r
    }

    fn send(&mut self, v: Value) {
        let mut line = v.to_string();
        line.push('\n');
        self.out.write_all(line.as_bytes()).unwrap();
    }

    /// One JSON-RPC request and its reply (notifications skipped).
    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        let rpc = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send(json!({"t": "mcp", "line": rpc.to_string()}));
        loop {
            let mut line = String::new();
            self.input.read_line(&mut line).unwrap();
            let msg: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(msg["t"], "mcp", "{msg}");
            let reply: Value = serde_json::from_str(msg["line"].as_str().unwrap()).unwrap();
            if reply.get("method").is_some() && reply.get("id").is_none() {
                continue;
            }
            return reply;
        }
    }
}

/// An agent session, paired, with `fill` on the vault.
fn agent(rig: &Rig) -> Relay {
    let mut r = Relay::connect(&rig.mcp_socket());
    let init = r.call(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "onepass");
    let mut clients = Vec::new();
    for _ in 0..250 {
        clients = rig.session.clone().paired_clients(rig.data()).unwrap();
        if !clients.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(clients.len(), 1);
    rig.session
        .clone()
        .set_client_scopes(
            rig.data(),
            clients[0].id.clone(),
            rig.vault_id.clone(),
            vec!["metadata".into(), "fill".into()],
        )
        .unwrap();
    r
}

fn wait_for_listener(rig: &Rig) {
    let hub = rig.server.agent_hub();
    for _ in 0..250 {
        if hub.has_listener() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("the extension never polled");
}

fn fill_in_browser(r: &mut Relay) -> Value {
    r.call(
        2,
        "tools/call",
        json!({"name": "fill_in_browser", "arguments": {
            "query": "Atlas Cloud", "url": format!("{ATLAS}/login"), "kind": "login",
            "target": {"browser": "chrome"}}}),
    )
}

#[test]
fn mcp_fill_reaches_the_extension_through_the_bridge() {
    let _turn = one_at_a_time();
    let rig = rig();
    let mut r = agent(&rig);
    let ext = extension(&rig, OnFill::Fill);
    wait_for_listener(&rig);

    let reply = fill_in_browser(&mut r);
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"],
        json!({"filled": ["username", "password"], "submitted": false})
    );
    assert!(!reply.to_string().contains(PASSWORD));

    let seen = ext.join().unwrap();
    assert_eq!(seen.probe_url, format!("{ATLAS}/login"));
    assert_eq!(seen.fill_job["kind"], "login");
    assert_eq!(seen.fill_job["submit"], false);
    assert_eq!(seen.fill_job["document_id"], "doc-1");
    assert!(seen.got_password, "the ticket did not open the values");
    // The user was asked once, shown the tab the extension reported.
    let asked = rig.ui.asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].action, "fill_login");
    assert!(
        asked[0]
            .details
            .iter()
            .any(|d| d.label == "tab" && d.value == "Atlas Cloud - Sign in"),
        "{:?}",
        asked[0].details
    );
    drop(asked);
    // The ticket was good once: the hub holds nothing more.
    let request = seen.fill_job["request_id"].as_u64().unwrap();
    assert!(!rig.server.agent_hub().ticket_held(request));
    rig.host.stop();
}

#[test]
fn tab_switched_during_approval_is_tab_mismatch() {
    let _turn = one_at_a_time();
    let rig = rig();
    let mut r = agent(&rig);
    let ext = extension(&rig, OnFill::TabSwitched);
    wait_for_listener(&rig);

    let reply = fill_in_browser(&mut r);
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("tab_mismatch"), "{text}");

    let seen = ext.join().unwrap();
    assert_eq!(seen.fill_job["kind"], "login");
    assert!(!seen.got_password);
    assert_eq!(rig.ui.asked.lock().unwrap().len(), 1);
    rig.host.stop();
}

// ---- phase 2: a local Chrome driven over CDP (the fake DevTools server)

use onepass_cdp::fake::{FakeCdp, card_page, login_page};

const CARD_NUMBER: &str = "4111111111111111";
const CVV: &str = "737";

/// `fill_in_browser` with these arguments, as call `id`.
fn fill_call(r: &mut Relay, id: u64, args: Value) -> Value {
    r.call(
        id,
        "tools/call",
        json!({"name": "fill_in_browser", "arguments": args}),
    )
}

fn refusal(reply: &Value) -> String {
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A test card in the rig's vault, with every field the fill writes.
fn add_card(rig: &Rig) {
    let mut card = rig
        .session
        .new_item(
            rig.vault_id.clone(),
            FfiItemType::CreditCard,
            "Visa test".into(),
        )
        .unwrap();
    for f in card.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        f.value = match f.id.as_str() {
            "cardholder" => FfiFieldValue::Text {
                value: "Alex Test".into(),
            },
            "number" => FfiFieldValue::Concealed {
                value: CARD_NUMBER.into(),
            },
            "expiry" => FfiFieldValue::MonthYear {
                year: 2031,
                month: 8,
            },
            "cvv" => FfiFieldValue::Concealed { value: CVV.into() },
            _ => continue,
        };
    }
    rig.session.save_item(card).unwrap();
}

/// The fill entries of the MCP audit log, oldest first, as stored (the
/// log verifies; the raw lines carry the destination the report leaves out).
fn fill_audit(rig: &Rig) -> Vec<Value> {
    let report = rig.session.clone().audit_report(rig.data()).unwrap();
    assert_eq!(report.problem, None);
    let log = std::fs::read_to_string(rig.dir.path().join("dev").join("audit.log")).unwrap();
    log.lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|e| e["action"].as_str().is_some_and(|a| a.starts_with("fill_")))
        .collect()
}

/// No `Runtime.*` command ever reached the browser.
fn no_runtime(cdp: &FakeCdp) {
    assert!(
        cdp.methods().iter().all(|m| !m.starts_with("Runtime.")),
        "{:?}",
        cdp.methods()
    );
}

#[test]
fn cdp_target_fills_a_local_fake_page() {
    let _turn = one_at_a_time();
    let rig = rig();
    let mut r = agent(&rig);
    let url = format!("{ATLAS}/login");
    let cdp = FakeCdp::start(&url, "Atlas Cloud - Sign in", login_page(&url));

    let reply = fill_call(
        &mut r,
        2,
        json!({"query": "Atlas Cloud", "url": url, "kind": "login", "submit": true,
            "target": {"cdp": cdp.ws_url()}}),
    );
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"],
        json!({"filled": ["username", "password"], "submitted": true})
    );
    assert!(!reply.to_string().contains(PASSWORD));

    // The values went into the two top-frame fields, by insertText only,
    // never into the child frame's password field (21); then a click.
    assert_eq!(cdp.inserted(), vec!["alex@atlas.dev", PASSWORD]);
    assert_eq!(cdp.field_text(11).as_deref(), Some("alex@atlas.dev"));
    assert_eq!(cdp.field_text(12).as_deref(), Some(PASSWORD));
    assert_eq!(cdp.field_text(21).as_deref(), Some(""));
    no_runtime(&cdp);
    let methods = cdp.methods();
    let last_insert = methods
        .iter()
        .rposition(|m| m == "Input.insertText")
        .unwrap();
    let press = methods
        .iter()
        .position(|m| m == "Input.dispatchMouseEvent")
        .expect("the sign-in button was clicked");
    assert!(last_insert < press, "{methods:?}");

    // The user was asked once: the panel says CDP, then the page title.
    let asked = rig.ui.asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].action, "fill_login");
    let labels: Vec<(&str, &str)> = asked[0]
        .details
        .iter()
        .map(|d| (d.label.as_str(), d.value.as_str()))
        .collect();
    assert_eq!(
        labels,
        vec![
            ("site", "atlas-cloud.test"),
            ("browser", "cdp"),
            ("tab", "Atlas Cloud - Sign in")
        ]
    );
    drop(asked);

    // The page moves to another origin while the user approves: the fill
    // is refused and nothing more is typed.
    let before = cdp.inserted().len();
    let cdp = Arc::new(cdp);
    let moved = cdp.clone();
    *rig.ui.during.lock().unwrap() =
        Some(Box::new(move || moved.navigate("https://evil.test/login")));
    let reply = fill_call(
        &mut r,
        3,
        json!({"query": "Atlas Cloud", "url": url, "kind": "login",
            "target": {"cdp": cdp.ws_url()}}),
    );
    assert!(refusal(&reply).starts_with("origin_mismatch"), "{reply}");
    assert_eq!(rig.ui.asked.lock().unwrap().len(), 2);
    assert_eq!(cdp.inserted().len(), before);
    // And a page already elsewhere is refused before anyone is asked, as a
    // tab on another site (the Chrome name), or a page not over HTTPS.
    let reply = fill_call(
        &mut r,
        4,
        json!({"query": "Atlas Cloud", "url": url, "kind": "login",
            "target": {"cdp": cdp.ws_url()}}),
    );
    assert!(refusal(&reply).starts_with("tab_mismatch"), "{reply}");
    cdp.navigate("http://atlas-cloud.test/login");
    let reply = fill_call(
        &mut r,
        5,
        json!({"query": "Atlas Cloud", "url": url, "kind": "login",
            "target": {"cdp": cdp.ws_url()}}),
    );
    assert!(refusal(&reply).starts_with("tab_mismatch"), "{reply}");
    assert_eq!(rig.ui.asked.lock().unwrap().len(), 2);

    // One entry per call: the fill (origin, submitted), the fill that
    // failed after approval, the refusals at the probe. No value in any.
    let audit = fill_audit(&rig);
    assert_eq!(audit.len(), 4, "{audit:?}");
    for e in &audit {
        assert_eq!(e["action"], "fill_login");
        assert_eq!(e["destination"], ATLAS);
        let line = e.to_string();
        assert!(
            !line.contains(PASSWORD) && !line.contains("alex@atlas.dev"),
            "{line}"
        );
    }
    assert_eq!(audit[0]["outcome"], "ok");
    assert_eq!(audit[0]["field"], "submitted");
    assert_eq!(audit[1]["outcome"], "origin_mismatch");
    assert_eq!(audit[1]["decision"], "once");
    assert!(audit[1]["field"].is_null(), "{:?}", audit[1]);
    assert_eq!(audit[2]["outcome"], "tab_mismatch");
    assert_eq!(audit[3]["outcome"], "tab_mismatch");
    rig.host.stop();
}

#[test]
fn cdp_target_with_remote_host_is_cdp_not_local() {
    let _turn = one_at_a_time();
    let rig = rig();
    let mut r = agent(&rig);
    let url = format!("{ATLAS}/login");
    for (id, addr) in [
        (2, "ws://198.51.100.7:9222/devtools/page/x".to_owned()),
        (3, "ws://localhost:9222/devtools/page/x".to_owned()),
    ] {
        let reply = fill_call(
            &mut r,
            id,
            json!({"query": "Atlas Cloud", "url": url, "kind": "login",
                "target": {"cdp": addr}}),
        );
        assert!(refusal(&reply).starts_with("cdp_not_local"), "{reply}");
    }
    assert!(rig.ui.asked.lock().unwrap().is_empty());
    let audit = fill_audit(&rig);
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert!(audit.iter().all(|e| e["outcome"] == "cdp_not_local"));
    rig.host.stop();
}

#[test]
fn cdp_target_without_ws_scheme_is_cdp_not_local() {
    let _turn = one_at_a_time();
    let rig = rig();
    let mut r = agent(&rig);
    let url = format!("{ATLAS}/login");
    let cdp = FakeCdp::start(&url, "Atlas Cloud - Sign in", login_page(&url));
    let port = cdp.port();
    for (id, addr) in [
        (2, format!("http://127.0.0.1:{port}/devtools/page/FAKE")),
        (3, format!("wss://127.0.0.1:{port}/devtools/page/FAKE")),
        (4, format!("127.0.0.1:{port}")),
    ] {
        let reply = fill_call(
            &mut r,
            id,
            json!({"query": "Atlas Cloud", "url": url, "kind": "login",
                "target": {"cdp": addr}}),
        );
        assert!(refusal(&reply).starts_with("cdp_not_local"), "{reply}");
    }
    // Refused before any connection: the browser saw nothing.
    assert!(cdp.commands().is_empty());
    assert!(rig.ui.asked.lock().unwrap().is_empty());
    rig.host.stop();
}

#[test]
fn cdp_card_never_clicks() {
    let _turn = one_at_a_time();
    let rig = rig();
    add_card(&rig);
    let mut r = agent(&rig);
    let url = format!("{ATLAS}/checkout");
    let cdp = FakeCdp::start(&url, "Checkout", card_page(&url));

    // Submit is refused for a card before any prompt or connection.
    let reply = fill_call(
        &mut r,
        2,
        json!({"query": "Visa test", "url": url, "kind": "card", "submit": true,
            "target": {"cdp": cdp.ws_url()}}),
    );
    assert!(refusal(&reply).starts_with("submit_not_allowed"), "{reply}");
    assert!(cdp.commands().is_empty());
    assert!(rig.ui.asked.lock().unwrap().is_empty());

    let reply = fill_call(
        &mut r,
        3,
        json!({"query": "Visa test", "url": url, "kind": "card",
            "target": {"cdp": cdp.ws_url()}}),
    );
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"],
        json!({"filled": ["number", "cardholder", "expiry", "cvv"], "submitted": false})
    );
    let text = reply.to_string();
    assert!(
        !text.contains(CARD_NUMBER) && !text.contains("1111"),
        "{text}"
    );
    assert_eq!(cdp.field_text(31).as_deref(), Some(CARD_NUMBER));
    assert_eq!(cdp.field_text(32).as_deref(), Some("Alex Test"));
    assert_eq!(cdp.field_text(33).as_deref(), Some("08/31"));
    assert_eq!(cdp.field_text(34).as_deref(), Some(CVV));
    // The Pay now button (35) is never touched.
    let methods = cdp.methods();
    assert!(
        !methods
            .iter()
            .any(|m| m == "Input.dispatchMouseEvent" || m == "DOM.getBoxModel"),
        "{methods:?}"
    );
    no_runtime(&cdp);
    let asked = rig.ui.asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].action, "fill_card");
    assert!(
        asked[0]
            .details
            .iter()
            .any(|d| d.label == "browser" && d.value == "cdp")
    );
    drop(asked);
    let audit = fill_audit(&rig);
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert_eq!(audit[0]["action"], "fill_card");
    assert_eq!(audit[0]["outcome"], "submit_not_allowed");
    assert_eq!(audit[1]["action"], "fill_card");
    assert_eq!(audit[1]["outcome"], "ok");
    assert_eq!(audit[1]["field"], "filled");
    assert_eq!(audit[1]["destination"], ATLAS);
    let line = audit[1].to_string();
    assert!(!line.contains(CARD_NUMBER) && !line.contains(CVV), "{line}");
    rig.host.stop();
}
