//! Remote approval and remote unlock over the UniFFI surface (agent-ready
//! spec 5 and 6): a Mac and an iPhone, two temp stores of one account kept
//! in step by a fake sync (pending rows of one into the base of the other,
//! as the server would), the transport played by passing the blobs.
//! Synthetic data only. Run with `--features dev-fast-kdf`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use onepass_bridge::channel::Channel;
use onepass_bridge::framing::{read_frame, write_frame};
use onepass_bridge::pairing::PairingRecord;
use onepass_bridge::session;
use onepass_bridge::wire::{self, Envelope};
use onepass_ffi::*;
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASSWORD: &str = "Café-étoile";
const NEW_PASSWORD: &str = "Nouveau-mot-de-passe-Atlas";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

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

/// The Mac (account creator, registered) and the iPhone (paired with a full
/// grant), both enrolled as approvers, every list synced both ways.
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

fn body(action: &str) -> FfiRequestBody {
    FfiRequestBody {
        client: "Agent Exemple".into(),
        client_verified: true,
        action: action.into(),
        details: vec![FfiDetail {
            label: "Commande".into(),
            value: "deploy --staging".into(),
        }],
        targets: vec!["Personnel / Jeton Atlas / content".into()],
        remember_allowed: true,
        strong_required: false,
        confirm_code: "kq".into(),
        window_minutes: None,
    }
}

/// Enroll remote unlock, the phone keeps `K_r`; returns `(C, K_r)`.
fn enroll(mac: &Device, phone: &Device) -> (Vec<u8>, Vec<u8>) {
    let auk = verify_password(mac.path.clone(), PASSWORD.into(), mac.secret_key.clone()).unwrap();
    let enrollment = mac
        .session
        .remote_unlock_enroll(mac.keys.clone(), phone.id.clone(), auk)
        .unwrap();
    assert_eq!(enrollment.transfer_request.to, phone.id);
    let opened = phone
        .session
        .open_remote_request(phone.keys.clone(), enrollment.transfer_request.blob.clone())
        .unwrap();
    assert_eq!(opened.kind, FfiRemoteKind::Pair);
    assert_eq!(opened.from, mac.id);
    assert_eq!(opened.from_name, "Mac de Camille");
    assert_eq!(opened.body.confirm_code, enrollment.confirm_code);
    let k_r = opened.transfer_key.clone().unwrap();
    assert_eq!(k_r.len(), 32);
    let ack = phone
        .session
        .seal_remote_response(
            phone.keys.clone(),
            enrollment.transfer_request.blob,
            FfiRemoteDecision::Once,
            None,
        )
        .unwrap();
    let r = mac
        .session
        .open_remote_response(mac.keys.clone(), ack)
        .unwrap();
    assert_eq!(r.decision, FfiRemoteDecision::Once);
    (enrollment.c, k_r)
}

/// A locked Mac asks, the phone approves with `K_r`, the Mac finishes.
fn remote_unlock(
    mac: &Device,
    phone: &Device,
    c: &[u8],
    k_r: &[u8],
    window: u32,
) -> Result<Arc<Session>, OnePassError> {
    let unlocker = RemoteUnlocker::new(mac.path.clone(), mac.keys.clone()).unwrap();
    let sealed = unlocker
        .begin(phone.id.clone(), body("list_vaults"), window)
        .unwrap();
    assert_eq!(sealed.to, phone.id);
    let opened = phone
        .session
        .open_remote_request(phone.keys.clone(), sealed.blob.clone())
        .unwrap();
    assert_eq!(opened.kind, FfiRemoteKind::ApproveAndUnlock);
    assert_eq!(opened.body.window_minutes, Some(window));
    assert!(opened.transfer_key.is_none());
    let response = phone
        .session
        .seal_remote_response(
            phone.keys.clone(),
            sealed.blob,
            FfiRemoteDecision::Once,
            Some(k_r.to_vec()),
        )
        .unwrap();
    unlocker.finish(response, c.to_vec())
}

/// An agents-only session of a Mac, opened from the phone.
fn agent_only() -> (Device, Device, Arc<Session>) {
    let (mac, phone) = mac_and_phone();
    let (c, k_r) = enroll(&mac, &phone);
    mac.session.lock();
    let s = remote_unlock(&mac, &phone, &c, &k_r, 60).unwrap();
    assert!(s.is_agent_only());
    (mac, phone, s)
}

#[test]
fn mac_request_phone_response_round_trip() {
    let (mac, phone) = mac_and_phone();

    // Both see both approvers, named after the device list.
    for d in [&mac, &phone] {
        let list = d.session.approvers().unwrap();
        assert_eq!(list.len(), 2, "{list:?}");
        let m = list.iter().find(|a| a.device_id == mac.id).unwrap();
        assert_eq!(m.role, FfiApproverRole::Mac);
        assert_eq!(m.device_name, "Mac de Camille");
        let p = list.iter().find(|a| a.device_id == phone.id).unwrap();
        assert_eq!(p.role, FfiApproverRole::Phone);
        assert_eq!(p.device_name, "iPhone de Camille");
    }

    let sealed = mac
        .session
        .seal_remote_request(
            mac.keys.clone(),
            phone.id.clone(),
            FfiRemoteKind::Approve,
            body("run_with_secrets"),
        )
        .unwrap();
    assert_eq!(sealed.request_id.len(), 16);
    assert_eq!(sealed.to, phone.id);
    assert!(sealed.expires_at > now() && sealed.expires_at <= now() + 60);
    // The transport sees no detail of the request.
    let wire = String::from_utf8_lossy(&sealed.blob);
    assert!(!wire.contains("deploy --staging") && !wire.contains("Jeton Atlas"));

    let opened = phone
        .session
        .open_remote_request(phone.keys.clone(), sealed.blob.clone())
        .unwrap();
    assert_eq!(opened.request_id, sealed.request_id);
    assert_eq!(opened.kind, FfiRemoteKind::Approve);
    assert_eq!(opened.from, mac.id);
    assert_eq!(opened.from_name, "Mac de Camille");
    assert_eq!(opened.body, body("run_with_secrets"));
    assert_eq!(opened.expires_at, sealed.expires_at);

    // The phone signs with its key, the Mac checks it against the list.
    let response = phone
        .session
        .seal_remote_response(
            phone.keys.clone(),
            sealed.blob.clone(),
            FfiRemoteDecision::Grant5m,
            None,
        )
        .unwrap();
    // A key of another device does not answer for the phone.
    let stranger = generate_approver_keys().unwrap();
    assert!(
        phone
            .session
            .seal_remote_response(stranger, sealed.blob.clone(), FfiRemoteDecision::Once, None)
            .and_then(|b| mac.session.open_remote_response(mac.keys.clone(), b))
            .is_err()
    );
    let answer = mac
        .session
        .open_remote_response(mac.keys.clone(), response.clone())
        .unwrap();
    assert_eq!(answer.request_id, sealed.request_id);
    assert_eq!(answer.from, phone.id);
    assert_eq!(answer.decision, FfiRemoteDecision::Grant5m);
    // One answer per request: the same one again is refused.
    assert_eq!(
        mac.session
            .open_remote_response(mac.keys.clone(), response)
            .unwrap_err(),
        OnePassError::Integrity {
            kind: "remote_unknown_request".into()
        }
    );
    // The phone accepts a request once.
    assert_eq!(
        phone
            .session
            .open_remote_request(phone.keys.clone(), sealed.blob)
            .unwrap_err(),
        OnePassError::Integrity {
            kind: "remote_replay".into()
        }
    );
    // A request it never opened is not answered.
    let other = mac
        .session
        .seal_remote_request(
            mac.keys.clone(),
            phone.id.clone(),
            FfiRemoteKind::Approve,
            body("reveal_secret"),
        )
        .unwrap();
    assert!(
        phone
            .session
            .seal_remote_response(
                phone.keys.clone(),
                other.blob,
                FfiRemoteDecision::Once,
                None
            )
            .is_err()
    );
    // Unlock kinds have their own entry points.
    assert!(
        mac.session
            .seal_remote_request(
                mac.keys.clone(),
                phone.id.clone(),
                FfiRemoteKind::ApproveAndUnlock,
                body("x"),
            )
            .is_err()
    );
}

#[test]
fn remote_unlock_end_to_end() {
    let (mac, phone) = mac_and_phone();
    let (c, k_r) = enroll(&mac, &phone);
    assert!(!mac.session.is_agent_only());
    assert_eq!(mac.session.agent_window_ends_at(), None);
    mac.session.lock();
    assert!(throttle_state(mac.path.clone()).unwrap().may_request);

    let before = now();
    let s = remote_unlock(&mac, &phone, &c, &k_r, 30).unwrap();
    assert!(s.is_agent_only());
    let ends = s.agent_window_ends_at().unwrap();
    assert!(
        ends >= before + 30 * 60 && ends <= now() + 30 * 60,
        "{ends}"
    );
    // The agents-only session reads the vault.
    assert_eq!(s.vaults().unwrap().len(), 1);
    assert_eq!(s.this_device_id(), Some(mac.id.clone()));
    // One request per 10 minutes.
    assert!(!throttle_state(mac.path.clone()).unwrap().may_request);
    let unlocker = RemoteUnlocker::new(mac.path.clone(), mac.keys.clone()).unwrap();
    assert!(
        unlocker
            .begin(phone.id.clone(), body("list_vaults"), 60)
            .is_err()
    );
    // A full session cannot enroll from an agents-only one.
    let auk = verify_password(mac.path.clone(), PASSWORD.into(), mac.secret_key.clone()).unwrap();
    assert_eq!(
        s.remote_unlock_enroll(mac.keys.clone(), phone.id.clone(), auk)
            .err(),
        Some(OnePassError::Locked)
    );
    s.lock();
    assert!(s.vaults().is_err());
}

#[test]
fn a_denied_unlock_counts_against_the_throttle() {
    let (mac, phone) = mac_and_phone();
    let (c, _k_r) = enroll(&mac, &phone);
    mac.session.lock();
    let unlocker = RemoteUnlocker::new(mac.path.clone(), mac.keys.clone()).unwrap();
    let sealed = unlocker
        .begin(phone.id.clone(), body("list_vaults"), 60)
        .unwrap();
    phone
        .session
        .open_remote_request(phone.keys.clone(), sealed.blob.clone())
        .unwrap();
    let denied = phone
        .session
        .seal_remote_response(
            phone.keys.clone(),
            sealed.blob,
            FfiRemoteDecision::Denied,
            None,
        )
        .unwrap();
    assert_eq!(
        unlocker.finish(denied, c).err(),
        Some(OnePassError::Validation {
            field: "remote_unlock".into(),
            reason: "denied".into()
        })
    );
    assert!(!throttle_state(mac.path.clone()).unwrap().may_request);
}

#[test]
fn stale_c_after_password_change_reports_stale() {
    let (mac, phone) = mac_and_phone();
    let (c, k_r) = enroll(&mac, &phone);
    // The password changes on the phone; the Mac fetches it while locked.
    mac.session.lock();
    phone
        .session
        .change_password(
            PASSWORD.into(),
            phone.secret_key.clone(),
            NEW_PASSWORD.into(),
        )
        .unwrap();
    sync(&phone.path, &mac.path);

    assert_eq!(
        remote_unlock(&mac, &phone, &c, &k_r, 60).err(),
        Some(OnePassError::RemoteUnlockStale)
    );
    // The new password still opens the Mac.
    unlock_with_password(
        mac.path.clone(),
        NEW_PASSWORD.into(),
        mac.secret_key.clone(),
    )
    .unwrap();
}

#[test]
fn phone_replay_guard_survives_new_session() {
    let (mac, phone) = mac_and_phone();
    let sealed = mac
        .session
        .seal_remote_request(
            mac.keys.clone(),
            phone.id.clone(),
            FfiRemoteKind::Approve,
            body("run_with_secrets"),
        )
        .unwrap();
    phone
        .session
        .open_remote_request(phone.keys.clone(), sealed.blob.clone())
        .unwrap();
    phone.session.lock();
    let again = unlock_with_password(
        phone.path.clone(),
        PASSWORD.into(),
        phone.secret_key.clone(),
    )
    .unwrap();
    assert_eq!(
        again
            .session
            .open_remote_request(phone.keys.clone(), sealed.blob)
            .unwrap_err(),
        OnePassError::Integrity {
            kind: "remote_replay".into()
        }
    );
}

// ---- browser bridge

struct Delegate(Sender<()>);

impl BridgeDelegate for Delegate {
    fn pairing_requested(&self, _request: FfiBridgePairingRequest) {}
    fn pairing_ended(&self, _request_id: u64) {}
    fn pairing_stored(&self, _p: FfiBridgePairing) {}
    fn pairing_used(&self, _pairing_id: String, _at: u64) {}
    fn unlock_requested(&self) {
        let _ = self.0.send(());
    }
    fn confirm_reprompt(&self, _vault_id: String, _item_id: String) -> bool {
        false
    }
    fn vault_changed(&self) {}
    fn note(&self, _message: String) {}
}

struct Ext {
    s: UnixStream,
    done: thread::JoinHandle<()>,
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
}

#[test]
fn agent_only_session_refused_by_browser_bridge() {
    let (mac, _phone, s) = agent_only();
    let (tx, unlocks) = channel();
    let record = PairingRecord {
        pairing_id: [7; 16],
        key: Zeroizing::new([9; 32]),
        ext_name: "OnePass".into(),
        browser: "Chrome".into(),
        created_at: 1,
    };
    let server = BridgeServer::new(
        Arc::new(Delegate(tx)),
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
        mac.dir
            .path()
            .join("bridge-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );
    server.set_session(Some(s.clone()), "alex@atlas.dev".into());
    let (ext, app) = UnixStream::pair().unwrap();
    ext.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let srv = server.clone();
    let done = thread::spawn(move || serve_for_tests(&srv, app, "ext", true));
    let mut ext = Ext { s: ext, done };
    let mut ch = ext.open(&record);

    let st = ext.request(&mut ch, json!({"id": 1, "op": "status"}));
    assert_eq!(st["ok"]["locked"], true, "{st}");
    let v = ext.request(&mut ch, json!({"id": 2, "op": "vaults"}));
    assert_eq!(v["err"]["code"], "locked", "{v}");
    let u = ext.request(&mut ch, json!({"id": 3, "op": "unlock"}));
    assert_eq!(u["ok"]["locked"], true, "{u}");
    unlocks.recv_timeout(Duration::from_secs(30)).unwrap();
    // The session itself stays open for the agents.
    assert_eq!(s.vaults().unwrap().len(), 1);
    drop(ext.s);
    ext.done.join().unwrap();
}

// ---- MCP, with the fake relay of the milestone 7 tests

struct ScriptedUi;

impl FfiDeveloperUi for ScriptedUi {
    fn approve(&self, _request: FfiApprovalRequest) -> FfiDecision {
        FfiDecision::AllowOnce
    }
    fn verify_presence(&self, _reason: String) -> bool {
        true
    }
    fn pair_request(&self, _client: FfiMcpClient) -> bool {
        true
    }
}

struct Relay {
    out: UnixStream,
    input: BufReader<UnixStream>,
}

impl Relay {
    fn connect(socket: &str, client: Value) -> Relay {
        let out = UnixStream::connect(socket).unwrap();
        let input = BufReader::new(out.try_clone().unwrap());
        let mut r = Relay { out, input };
        r.send(json!({"t": "hello", "v": 1, "client": client}));
        r
    }

    fn send(&mut self, v: Value) {
        let mut line = v.to_string();
        line.push('\n');
        self.out.write_all(line.as_bytes()).unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        self.input.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        let rpc = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send(json!({"t": "mcp", "line": rpc.to_string()}));
        loop {
            let msg = self.recv();
            assert_eq!(msg["t"], "mcp", "{msg}");
            let line: Value = serde_json::from_str(msg["line"].as_str().unwrap()).unwrap();
            if line.get("method").is_some() && line.get("id").is_none() {
                continue;
            }
            return line;
        }
    }
}

#[test]
fn agent_only_session_serves_mcp() {
    let (mac, phone) = mac_and_phone();
    let data = mac.dir.path().join("dev").display().to_string();
    let socket = mac.dir.path().join("dev").join("mcp.sock");
    // The owner exposed a vault to agents before leaving the Mac.
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
                scopes: vec!["metadata".into()],
            }],
            true,
        )
        .unwrap();
    let (c, k_r) = enroll(&mac, &phone);
    mac.session.lock();
    let s = remote_unlock(&mac, &phone, &c, &k_r, 60).unwrap();
    assert!(s.is_agent_only());

    let host = McpHost::start_any_relay_for_tests(
        s.clone(),
        FfiMcpHostConfig {
            data_dir: data.clone(),
            socket_path: socket.display().to_string(),
            relay_path: "/unused".into(),
            protected_dirs: vec![mac.dir.path().display().to_string()],
        },
        Arc::new(ScriptedUi),
    )
    .unwrap();
    let mut r = Relay::connect(
        &socket.display().to_string(),
        json!({
            "id": "team:TEAMID0001:com.exemple.agent", "label": "Agent Exemple",
            "signed": true, "hardened": null,
            "code": {"kind": "team", "team_id": "TEAMID0001", "identifier": "com.exemple.agent"},
            "chain": ["team:TEAMID0001:com.exemple.agent"],
        }),
    );
    let init = r.call(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "onepass");
    let mut paired = false;
    for _ in 0..200 {
        if !s.clone().paired_clients(data.clone()).unwrap().is_empty() {
            paired = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(paired);
    let listed = r.call(
        2,
        "tools/call",
        json!({"name": "list_vaults", "arguments": {}}),
    );
    assert_eq!(listed["result"]["isError"], false, "{listed}");
    assert!(listed.to_string().contains(&vault.meta.name), "{listed}");
    drop(r);
    host.stop();
}
