//! Agent-ready end to end (spec 2026-10-28-agent-ready, section 1, success
//! criterion): an agent on a locked Mac asks for `run_with_secrets`, the
//! owner's iPhone unlocks the Mac for agents and approves the request, the
//! command runs with the secret injected and masked, and the signed audit
//! log names the iPhone.
//!
//! The pieces:
//! - the agent is this test, speaking MCP JSON-RPC on the stdio of the real
//!   relay binary (`onepass-mcp --socket`), so the gate and the server check
//!   the relay's code identity against the binary file (no test bypass);
//! - the app is the FFI on a temp account: `McpGate` while locked, an
//!   `FfiGateUi` that drives `RemoteUnlocker`, then `hand_over`;
//! - the iPhone is a second `Session` of the same account in its own temp
//!   store, kept in step by a fake sync; CloudKit is Swift only, so the
//!   sealed blobs are passed in process.
//!
//! The approval race (Mac panel against `RemoteApprover`) is Swift. Here
//! the `FfiDeveloperUi` callback plays the app's side of it: it seals the
//! request to the phone, the phone answers, the Mac opens the sealed answer
//! with `open_remote_response`, and only then the callback returns the
//! phone's decision with its origin `phone:<device_id>`.
//!
//! Synthetic data only. Run with `--features dev-fast-kdf`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use onepass_ffi::*;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const SECRET: &str = "jeton-secret-atlas-42";
const PENDING: &str = "Approve on your Mac or iPhone. Code: ";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};
/// Longest wait for any one step (the machine may be loaded).
const STEP: Duration = Duration::from_secs(60);

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn db_path(dir: &Path) -> String {
    dir.join("onepass.db").to_string_lossy().into_owned()
}

// ---- the real relay binary

static BUILD: Once = Once::new();

/// `target/<profile>/onepass-mcp`, next to this test's `deps` folder,
/// built once per run (Cargo only builds another package's binaries for
/// that package's own tests).
fn relay_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile = exe.parent().and_then(Path::parent).unwrap().to_path_buf();
    BUILD.call_once(|| {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.args([
            "build",
            "--quiet",
            "-p",
            "onepass-mcp-relay",
            "--bin",
            "onepass-mcp",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"));
        if profile.file_name().is_some_and(|p| p == "release") {
            cmd.arg("--release");
        }
        let status = cmd.status().unwrap();
        assert!(status.success(), "building the relay failed");
    });
    let relay = profile.join("onepass-mcp");
    assert!(relay.is_file(), "no relay at {}", relay.display());
    relay
}

/// The agent's side of the relay: stdin to write JSON-RPC lines, stdout
/// lines arriving on a channel (read on their own thread).
struct Agent {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Value>,
}

impl Agent {
    fn launch(relay: &Path, socket: &str) -> Agent {
        let mut child = Command::new(relay)
            .arg("--socket")
            .arg(socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = channel();
        thread::spawn(move || {
            for line in stdout.lines() {
                let Ok(line) = line else { break };
                let v: Value = serde_json::from_str(&line).expect("stdout carries JSON lines");
                if tx.send(v).is_err() {
                    break;
                }
            }
        });
        Agent {
            child,
            stdin,
            lines,
        }
    }

    fn send(&mut self, id: u64, method: &str, params: Value) {
        let rpc = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(format!("{rpc}\n").as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    /// Every line up to the reply to `id`: (notifications, reply).
    fn until_reply(&mut self, id: u64) -> (Vec<Value>, Value) {
        let mut notes = Vec::new();
        loop {
            let v = self
                .lines
                .recv_timeout(STEP)
                .unwrap_or_else(|_| panic!("no reply to {id}; seen {notes:?}"));
            if v["id"] == id && v.get("method").is_none() {
                return (notes, v);
            }
            notes.push(v);
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        // End of stdin ends the relay.
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

// ---- two devices of one account

/// The server accepts every pending row of `path`; returns them.
fn push(path: &str) -> Vec<FfiRecordChange> {
    let h = open_sync_store(path.into()).unwrap();
    let changes = h.pending_changes().unwrap();
    for c in &changes {
        h.mark_pushed(c.kind, c.id.clone(), c.version, Some(b"tag".to_vec()))
            .unwrap();
    }
    changes
}

/// Push `from`, then fetch those rows into `to`.
fn sync(from: &str, to: &str) {
    let changes = push(from);
    let h = open_sync_store(to.into()).unwrap();
    for c in changes {
        h.stage_remote(FfiRemoteRecord {
            kind: c.kind,
            id: c.id,
            version: c.version,
            data: c.data,
            server_meta: Some(b"tag".to_vec()),
        })
        .unwrap();
    }
    h.commit_remote().unwrap();
}

struct Device {
    dir: TempDir,
    path: String,
    session: Arc<Session>,
    secret_key: String,
    id: String,
    keys: FfiApproverKeys,
}

/// The Mac (account creator) and the iPhone (paired with a full grant),
/// both registered as approvers, every list synced both ways.
fn mac_and_phone() -> (Device, Device) {
    let dir = TempDir::new().unwrap();
    let path = db_path(dir.path());
    let created = create_account_with_kdf(path.clone(), PASSWORD.into(), FAST).unwrap();
    let mac_id = created
        .session
        .register_this_device(
            "Mac de Camille".into(),
            FfiDeviceKind::Mac,
            FfiDeviceMode::Personal,
        )
        .unwrap();
    push(&path);

    let n = PairingNewcomer::new(
        "iPhone de Camille".into(),
        FfiDeviceKind::Phone,
        FfiDeviceMode::Personal,
        now(),
    )
    .unwrap();
    let a = PairingApprover::begin(n.qr_text(), n.hello(), now()).unwrap();
    n.on_key_exchange(a.key_exchange(), now()).unwrap();
    a.on_frame(n.confirm().unwrap()).unwrap();
    let frame = a
        .seal_full_grant(
            created.session.clone(),
            created.secret_key.clone(),
            FfiDeviceMode::Personal,
            false,
        )
        .unwrap();
    n.open(frame).unwrap();
    let phone_dir = TempDir::new().unwrap();
    let phone_path = db_path(phone_dir.path());
    let unlocked = n
        .import_snapshot(phone_path.clone(), PASSWORD.into())
        .unwrap();
    let phone_secret = n.take_secret_key().unwrap();
    sync(&path, &phone_path);

    let mac_keys = generate_approver_keys().unwrap();
    created
        .session
        .register_approver(mac_keys.clone(), FfiApproverRole::Mac)
        .unwrap();
    sync(&path, &phone_path);
    let phone_keys = generate_approver_keys().unwrap();
    unlocked
        .session
        .register_approver(phone_keys.clone(), FfiApproverRole::Phone)
        .unwrap();
    sync(&phone_path, &path);

    let mac = Device {
        dir,
        path,
        session: created.session,
        secret_key: created.secret_key,
        id: mac_id,
        keys: mac_keys,
    };
    let phone = Device {
        dir: phone_dir,
        path: phone_path,
        session: unlocked.session,
        secret_key: phone_secret,
        id: n.device_id(),
        keys: phone_keys,
    };
    (mac, phone)
}

/// Remote unlock enrolled from the open Mac: the Mac keeps `C`, the phone
/// keeps `K_r` (after its Face ID, here implied).
fn enroll(mac: &Device, phone: &Device) -> (Vec<u8>, Vec<u8>) {
    let auk = verify_password(mac.path.clone(), PASSWORD.into(), mac.secret_key.clone()).unwrap();
    let enrollment = mac
        .session
        .remote_unlock_enroll(mac.keys.clone(), phone.id.clone(), auk)
        .unwrap();
    let opened = phone
        .session
        .open_remote_request(phone.keys.clone(), enrollment.transfer_request.blob.clone())
        .unwrap();
    assert_eq!(opened.kind, FfiRemoteKind::Pair);
    let k_r = phone
        .session
        .accept_enrollment(phone.keys.clone(), enrollment.transfer_request.blob.clone())
        .unwrap();
    let ack = phone
        .session
        .seal_remote_response(
            phone.keys.clone(),
            enrollment.transfer_request.blob,
            FfiRemoteDecision::Once,
            None,
        )
        .unwrap();
    mac.session
        .open_remote_response(mac.keys.clone(), ack)
        .unwrap();
    (enrollment.c, k_r)
}

/// The phone: a session of the account, its approver keys, the `K_r` it
/// keeps, and what it was shown.
struct Phone {
    session: Arc<Session>,
    keys: FfiApproverKeys,
    id: String,
    k_r: Vec<u8>,
    shown: Mutex<Vec<FfiOpenedRequest>>,
}

impl Phone {
    /// Opens a Mac request (the screen the owner sees) and answers it,
    /// with `K_r` for an unlock request.
    fn answer(&self, blob: Vec<u8>, decision: FfiRemoteDecision) -> Vec<u8> {
        let opened = self
            .session
            .open_remote_request(self.keys.clone(), blob.clone())
            .unwrap();
        let unlock = (opened.kind == FfiRemoteKind::ApproveAndUnlock).then(|| self.k_r.clone());
        self.shown.lock().unwrap().push(opened);
        self.session
            .seal_remote_response(self.keys.clone(), blob, decision, unlock)
            .unwrap()
    }
}

// ---- the app

/// The app while locked: asked by the gate, it sends the unlock request to
/// the phone, opens the agents-only session with the answer, and gives it
/// to the code that hands the gate over.
struct LockedApp {
    mac_path: String,
    mac_keys: FfiApproverKeys,
    c: Vec<u8>,
    phone: Arc<Phone>,
    asked: Mutex<Vec<FfiMcpClient>>,
    opened: Mutex<Sender<Arc<Session>>>,
}

impl FfiGateUi for LockedApp {
    fn locked_request(&self, client: FfiMcpClient) -> bool {
        let label = client.label.clone();
        self.asked.lock().unwrap().push(client);
        let unlocker = RemoteUnlocker::new(self.mac_path.clone(), self.mac_keys.clone()).unwrap();
        let sealed = unlocker
            .begin(
                self.phone.id.clone(),
                FfiRequestBody {
                    client: label,
                    client_verified: true,
                    action: "unlock".into(),
                    details: Vec::new(),
                    targets: Vec::new(),
                    remember_allowed: false,
                    strong_required: false,
                    confirm_code: String::new(),
                    window_minutes: None,
                },
                60,
            )
            .unwrap();
        // CloudKit in between: the blob goes as is.
        let response = self.phone.answer(sealed.blob, FfiRemoteDecision::Once);
        match unlocker.finish(response, self.c.clone()) {
            Ok(session) => {
                self.opened.lock().unwrap().send(session).unwrap();
                true
            }
            Err(_) => false,
        }
    }
}

/// The app once open for agents: the approval race, where the phone wins.
/// It seals the guard's request to the phone, and returns the phone's
/// decision only once the Mac opened and verified the sealed answer.
struct ApprovingApp {
    session: Mutex<Option<Arc<Session>>>,
    mac_keys: FfiApproverKeys,
    phone: Arc<Phone>,
    asked: Mutex<Vec<FfiApprovalRequest>>,
}

impl FfiDeveloperUi for ApprovingApp {
    fn approve(&self, request: FfiApprovalRequest) -> FfiAnswer {
        let session = self.session.lock().unwrap().clone().unwrap();
        let sealed = session
            .seal_remote_request(
                self.mac_keys.clone(),
                self.phone.id.clone(),
                FfiRemoteKind::Approve,
                FfiRequestBody {
                    client: request.client.clone(),
                    client_verified: request.client_verified,
                    action: request.action.clone(),
                    details: request.details.clone(),
                    targets: request
                        .targets
                        .iter()
                        .map(|t| {
                            let field = t.field.as_deref().unwrap_or("");
                            format!("{} / {} / {field}", t.vault, t.item)
                        })
                        .collect(),
                    remember_allowed: request.remember_allowed,
                    strong_required: request.strong_required,
                    confirm_code: request.confirm_code.clone(),
                    window_minutes: None,
                },
            )
            .unwrap();
        self.asked.lock().unwrap().push(request);
        let blob = self.phone.answer(sealed.blob, FfiRemoteDecision::Once);
        let answer = session
            .open_remote_response(self.mac_keys.clone(), blob)
            .unwrap();
        assert_eq!(answer.request_id, sealed.request_id);
        let decision = match answer.decision {
            FfiRemoteDecision::Denied => FfiDecision::Deny,
            FfiRemoteDecision::Once => FfiDecision::AllowOnce,
            FfiRemoteDecision::Grant5m => FfiDecision::AllowForMinutes { minutes: 5 },
        };
        FfiAnswer {
            decision,
            approved_on: Some(format!("phone:{}", answer.from)),
        }
    }
    fn verify_presence(&self, _reason: String) -> bool {
        panic!("a phone approval asks no Touch ID on the Mac")
    }
    fn pair_request(&self, _client: FfiMcpClient) -> bool {
        panic!("the agent was paired before the owner left")
    }
}

// ---- the test

#[test]
fn locked_mac_phone_unlocks_and_approves_run_with_secrets() {
    let relay = relay_binary();
    let (mac, phone) = mac_and_phone();
    let data = mac.dir.path().join("dev").display().to_string();
    let socket = mac.dir.path().join("dev").join("mcp.sock");
    let socket = socket.display().to_string();

    // Before leaving the Mac, the owner exposes a vault to agents, pairs
    // the agent (this test binary, the relay's parent) and enrolls remote
    // unlock with the phone.
    let vault = mac.session.vaults().unwrap().remove(0);
    let mut meta = vault.meta.clone();
    meta.mcp_access = true;
    mac.session.update_vault(vault.id.clone(), meta).unwrap();
    mac.session
        .clone()
        .set_mcp_policy(
            data.clone(),
            vec![FfiClientScopes {
                vault_id: vault.id.clone(),
                scopes: vec!["metadata".into(), "use".into()],
            }],
            true,
        )
        .unwrap();
    let mut note = mac
        .session
        .new_item(
            vault.id.clone(),
            FfiItemType::SecureNote,
            "Jeton Atlas".into(),
        )
        .unwrap();
    for f in note.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if f.id == "content" {
            f.value = FfiFieldValue::Text {
                value: SECRET.into(),
            };
        }
    }
    mac.session.save_item(note).unwrap();
    let reference = format!("onepass://{}/Jeton Atlas/content", vault.meta.name);
    let agent_id = mac
        .session
        .clone()
        .pair_program(
            data.clone(),
            std::env::current_exe().unwrap().display().to_string(),
        )
        .unwrap();
    mac.session
        .clone()
        .set_client_scopes(
            data.clone(),
            agent_id.clone(),
            vault.id.clone(),
            vec!["metadata".into(), "use".into()],
        )
        .unwrap();
    let (c, k_r) = enroll(&mac, &phone);
    sync(&mac.path, &phone.path);
    mac.session.lock();
    assert!(mac.session.vaults().is_err());

    let phone = Arc::new(Phone {
        session: phone.session.clone(),
        keys: phone.keys.clone(),
        id: phone.id.clone(),
        k_r,
        shown: Mutex::new(Vec::new()),
    });

    // The locked app listens through the gate, which checks the relay
    // against the binary file.
    let (opened_tx, opened_rx) = channel();
    let locked = Arc::new(LockedApp {
        mac_path: mac.path.clone(),
        mac_keys: mac.keys.clone(),
        c,
        phone: phone.clone(),
        asked: Mutex::new(Vec::new()),
        opened: Mutex::new(opened_tx),
    });
    let gate = McpGate::start(
        socket.clone(),
        relay.display().to_string(),
        data.clone(),
        locked.clone(),
    )
    .unwrap();

    // The agent starts its MCP server (the relay) and says hello: the gate
    // answers the handshake itself and asks nobody yet.
    let mut agent = Agent::launch(&relay, &socket);
    agent.send(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "agent-e2e", "version": "1"}}),
    );
    let (_, init) = agent.until_reply(1);
    assert_eq!(init["result"]["serverInfo"]["name"], "onepass", "{init}");
    agent.send(2, "tools/list", json!({}));
    let (_, tools) = agent.until_reply(2);
    assert!(tools.to_string().contains("run_with_secrets"), "{tools}");
    assert!(locked.asked.lock().unwrap().is_empty());

    // Step 1: the agent runs a command with one reference. The gate asks
    // the app, the phone unlocks the Mac for agents.
    agent.send(
        3,
        "tools/call",
        json!({"name": "run_with_secrets", "arguments": {
            "command": ["sh", "-c", "printf 'token=%s' \"$TOKEN\""],
            "env": {"TOKEN": reference}}}),
    );
    let session = opened_rx.recv_timeout(STEP).expect("remote unlock");
    assert!(session.is_agent_only());
    assert!(session.agent_window_ends_at().unwrap() > now());
    {
        let asked = locked.asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].id, agent_id);
        let shown = phone.shown.lock().unwrap();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].kind, FfiRemoteKind::ApproveAndUnlock);
        assert_eq!(shown[0].from, mac.id);
        assert_eq!(shown[0].body.window_minutes, Some(60));
    }
    // The Mac's own screens stay locked.
    assert!(mac.session.vaults().is_err());

    let app = Arc::new(ApprovingApp {
        session: Mutex::new(Some(session.clone())),
        mac_keys: mac.keys.clone(),
        phone: phone.clone(),
        asked: Mutex::new(Vec::new()),
    });
    let host = gate
        .hand_over(
            session.clone(),
            FfiMcpHostConfig {
                data_dir: data.clone(),
                socket_path: socket.clone(),
                relay_path: relay.display().to_string(),
                protected_dirs: vec![mac.dir.path().display().to_string()],
            },
            app.clone(),
        )
        .unwrap();
    drop(gate);

    // Step 2: the server gets the call the gate held; the phone approves
    // it through the normal race.
    let (notes, ran) = agent.until_reply(3);

    // The pending notice came first, with the code the phone showed.
    let code = {
        let asked = app.asked.lock().unwrap();
        assert_eq!(asked.len(), 1, "one approval");
        assert_eq!(asked[0].surface, "mcp");
        assert_eq!(asked[0].action, "run_with_secrets");
        assert!(!asked[0].strong_required);
        asked[0].confirm_code.clone()
    };
    assert_eq!(code.chars().count(), 4, "{code}");
    let shown = phone.shown.lock().unwrap().clone();
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[1].kind, FfiRemoteKind::Approve);
    assert_eq!(shown[1].body.confirm_code, code);
    assert_eq!(shown[1].body.action, "run_with_secrets");
    let notice = notes
        .iter()
        .find(|n| n["method"] == "notifications/message")
        .unwrap_or_else(|| panic!("no pending notice in {notes:?}"));
    assert_eq!(notice["params"]["data"], format!("{PENDING}{code}"));

    // The command ran with the secret, which the agent never sees.
    let text = ran.to_string();
    assert_eq!(ran["result"]["isError"], false, "{text}");
    assert!(!text.contains(SECRET), "{text}");
    assert!(text.contains("token=<concealed:TOKEN>"), "{text}");
    for n in &notes {
        assert!(!n.to_string().contains(SECRET), "{n}");
    }

    drop(agent);
    host.stop();

    // The signed audit log verifies and names the phone.
    let report = session.clone().audit_report(data.clone()).unwrap();
    assert!(report.problem.is_none(), "{report:?}");
    let entry = report
        .entries
        .iter()
        .find(|e| e.action == "run_with_secrets")
        .expect("run_with_secrets audited");
    // The client column is the verified program's label.
    assert!(entry.client.starts_with("agent_ready_e2e"), "{entry:?}");
    assert_eq!(
        entry.approved_on.as_deref(),
        Some(format!("phone:{}", phone.id).as_str())
    );
    let log = std::fs::read_to_string(mac.dir.path().join("dev").join("audit.log")).unwrap();
    assert!(!log.contains(SECRET));

    session.lock();
    assert!(session.vaults().is_err());
}
