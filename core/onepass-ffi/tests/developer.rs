//! The SSH agent served by the app, SSH Key items, the MCP policy, grants
//! and the audit log, through the UniFFI surface with a scripted app UI.
//! Run with `--features dev-fast-kdf`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use onepass_ffi::*;
use tempfile::TempDir;

const PASSWORD: &str = "Café-étoile";
const FAST: FfiKdfParams = FfiKdfParams {
    m_kib: 8192,
    t: 1,
    p: 1,
};

/// The app's UI, scripted: a fixed answer, a fixed presence result, and
/// what it was asked.
struct ScriptedUi {
    answer: Mutex<FfiDecision>,
    /// Where the answer says it was given.
    origin: Mutex<Option<String>>,
    present: bool,
    pair: bool,
    asked: Mutex<Vec<FfiApprovalRequest>>,
    presence_checks: AtomicUsize,
}

impl ScriptedUi {
    fn new(answer: FfiDecision, present: bool) -> Arc<ScriptedUi> {
        Arc::new(ScriptedUi {
            answer: Mutex::new(answer),
            origin: Mutex::new(None),
            present,
            pair: true,
            asked: Mutex::new(Vec::new()),
            presence_checks: AtomicUsize::new(0),
        })
    }
}

impl FfiDeveloperUi for ScriptedUi {
    fn approve(&self, request: FfiApprovalRequest) -> FfiAnswer {
        self.asked.lock().unwrap().push(request);
        FfiAnswer {
            decision: *self.answer.lock().unwrap(),
            approved_on: self.origin.lock().unwrap().clone(),
        }
    }
    fn verify_presence(&self, _reason: String) -> bool {
        self.presence_checks.fetch_add(1, Ordering::SeqCst);
        self.present
    }
    fn pair_request(&self, _client: FfiMcpClient) -> bool {
        self.pair
    }
}

struct Fixture {
    dir: TempDir,
    session: Arc<Session>,
    vault_id: String,
}

impl Fixture {
    fn mcp_socket(&self) -> String {
        self.dir
            .path()
            .join("dev")
            .join("mcp.sock")
            .display()
            .to_string()
    }
    fn data(&self) -> String {
        self.dir.path().join("dev").display().to_string()
    }
    fn socket(&self) -> String {
        self.dir
            .path()
            .join("dev")
            .join("ssh.sock")
            .display()
            .to_string()
    }
}

fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("onepass.db").to_string_lossy().into_owned();
    let created = create_account_with_kdf(path, PASSWORD.into(), FAST).unwrap();
    let vault_id = created.session.vaults().unwrap()[0].id.clone();
    Fixture {
        dir,
        session: created.session,
        vault_id,
    }
}

fn new_key(fx: &Fixture, title: &str, agent: bool) -> FfiNewSshKey {
    FfiNewSshKey {
        vault_id: fx.vault_id.clone(),
        title: title.into(),
        hosts: vec!["github.com".into()],
        use_in_agent: agent,
        confirm_each_use: false,
        comment: None,
    }
}

fn start(fx: &Fixture, ui: Arc<ScriptedUi>, presence: bool) -> Arc<SshAgentHost> {
    SshAgentHost::start(
        fx.session.clone(),
        FfiSshAgentConfig {
            data_dir: fx.data(),
            socket_path: fx.socket(),
            allow_forwarded: false,
            known_hosts: Vec::new(),
            require_presence: presence,
        },
        ui,
    )
    .unwrap()
}

// ---- ssh-agent wire, client side

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn request(sock: &mut UnixStream, body: &[u8]) -> Vec<u8> {
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    sock.write_all(&frame).unwrap();
    let mut len = [0u8; 4];
    sock.read_exact(&mut len).unwrap();
    let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
    sock.read_exact(&mut reply).unwrap();
    reply
}

fn public_blob(line: &str) -> Vec<u8> {
    let b64 = line.split(' ').nth(1).unwrap();
    data_encoding::BASE64.decode(b64.as_bytes()).unwrap()
}

fn sign_request(blob: &[u8]) -> Vec<u8> {
    let mut body = vec![13u8];
    put_string(&mut body, blob);
    put_string(&mut body, b"session data to sign");
    body.extend_from_slice(&0u32.to_be_bytes());
    body
}

#[test]
fn agent_lists_and_signs_with_approval_and_presence() {
    let fx = fixture();
    fx.session
        .generate_ssh_key(FfiSshKeyType::Ed25519, new_key(&fx, "Github", true))
        .unwrap();
    fx.session
        .generate_ssh_key(FfiSshKeyType::EcdsaP256, new_key(&fx, "Hors agent", false))
        .unwrap();
    let keys = fx.session.agent_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].title, "Github");
    assert_eq!(keys[0].hosts, vec!["github.com".to_string()]);
    assert!(keys[0].public_key.starts_with("ssh-ed25519 "));

    let ui = ScriptedUi::new(FfiDecision::AllowOnce, true);
    let host = start(&fx, ui.clone(), true);
    assert!(host.is_running());
    let mut sock = UnixStream::connect(fx.socket()).unwrap();
    let ids = request(&mut sock, &[11]);
    assert_eq!(ids[0], 12);
    assert_eq!(u32::from_be_bytes(ids[1..5].try_into().unwrap()), 1);

    let blob = public_blob(&keys[0].public_key);
    let signed = request(&mut sock, &sign_request(&blob));
    assert_eq!(signed[0], 14, "SIGN_RESPONSE");
    assert_eq!(ui.asked.lock().unwrap().len(), 1);
    assert_eq!(ui.asked.lock().unwrap()[0].surface, "ssh");
    assert_eq!(ui.presence_checks.load(Ordering::SeqCst), 1);

    // Denied: FAILURE, and the audit log has both, verified.
    *ui.answer.lock().unwrap() = FfiDecision::Deny;
    let refused = request(&mut sock, &sign_request(&blob));
    assert_eq!(refused, vec![5]);
    drop(sock);
    host.stop();
    assert!(!host.is_running());
    assert!(!std::path::Path::new(&fx.socket()).exists());

    let report = fx.session.clone().audit_report(fx.data()).unwrap();
    assert!(report.problem.is_none());
    assert!(report.entries.len() >= 2);
    assert!(report.entries.iter().all(|e| e.surface == "ssh"));
    assert!(
        report
            .entries
            .iter()
            .any(|e| e.item.as_deref() == Some("Github"))
    );
}

#[test]
fn a_failed_presence_check_refuses_the_signature() {
    let fx = fixture();
    fx.session
        .generate_ssh_key(FfiSshKeyType::Ed25519, new_key(&fx, "Github", true))
        .unwrap();
    let blob = public_blob(&fx.session.agent_keys().unwrap()[0].public_key);
    let ui = ScriptedUi::new(FfiDecision::AllowOnce, false);
    let host = start(&fx, ui, true);
    let mut sock = UnixStream::connect(fx.socket()).unwrap();
    assert_eq!(request(&mut sock, &sign_request(&blob)), vec![5]);
    host.stop();
}

#[test]
fn a_phone_approval_skips_the_mac_presence_check() {
    let fx = fixture();
    fx.session
        .generate_ssh_key(FfiSshKeyType::Ed25519, new_key(&fx, "Github", true))
        .unwrap();
    let blob = public_blob(&fx.session.agent_keys().unwrap()[0].public_key);
    // Touch ID would fail: only the phone's Face ID stands behind the answer.
    let ui = ScriptedUi::new(FfiDecision::AllowOnce, false);
    *ui.origin.lock().unwrap() = Some("phone:7f3a9c".into());
    let host = start(&fx, ui.clone(), true);
    let mut sock = UnixStream::connect(fx.socket()).unwrap();
    let signed = request(&mut sock, &sign_request(&blob));
    assert_eq!(signed[0], 14, "SIGN_RESPONSE");
    assert_eq!(ui.presence_checks.load(Ordering::SeqCst), 0);

    // Answered on the Mac, or from a place the audit refuses: Touch ID again.
    for origin in [Some("mac"), Some("phone:bad id"), None] {
        *ui.origin.lock().unwrap() = origin.map(String::from);
        assert_eq!(
            request(&mut sock, &sign_request(&blob)),
            vec![5],
            "{origin:?}"
        );
    }
    assert_eq!(ui.presence_checks.load(Ordering::SeqCst), 3);
    drop(sock);
    host.stop();
}

#[test]
fn a_locked_session_offers_no_key() {
    let fx = fixture();
    fx.session
        .generate_ssh_key(FfiSshKeyType::Ed25519, new_key(&fx, "Github", true))
        .unwrap();
    let host = start(&fx, ScriptedUi::new(FfiDecision::AllowOnce, true), false);
    fx.session.lock();
    let mut sock = UnixStream::connect(fx.socket()).unwrap();
    let ids = request(&mut sock, &[11]);
    // Either an empty list or a failure: never a key.
    assert!(ids == vec![5] || ids[1..5] == [0, 0, 0, 0], "{ids:?}");
    host.stop();
}

#[test]
fn a_second_agent_on_the_same_socket_is_refused() {
    let fx = fixture();
    let ui = ScriptedUi::new(FfiDecision::AllowOnce, true);
    let host = start(&fx, ui.clone(), false);
    let second = SshAgentHost::start(
        fx.session.clone(),
        FfiSshAgentConfig {
            data_dir: fx.data(),
            socket_path: fx.socket(),
            allow_forwarded: false,
            known_hosts: Vec::new(),
            require_presence: false,
        },
        ui,
    );
    assert!(second.is_err());
    host.stop();
}

/// The real `ssh-add` lists the key through the app's agent, when the tool
/// is installed.
#[test]
fn ssh_add_lists_the_vault_key() {
    if !std::path::Path::new("/usr/bin/ssh-add").exists() {
        eprintln!("ssh-add missing: skipped");
        return;
    }
    let fx = fixture();
    fx.session
        .generate_ssh_key(FfiSshKeyType::Ed25519, new_key(&fx, "Github", true))
        .unwrap();
    let fingerprint = fx.session.agent_keys().unwrap()[0].fingerprint.clone();
    let host = start(&fx, ScriptedUi::new(FfiDecision::AllowOnce, true), false);
    let out = std::process::Command::new("/usr/bin/ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", fx.socket())
        .output()
        .unwrap();
    host.stop();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(&fingerprint), "{text}");
}

#[test]
fn imported_keys_keep_their_public_key_and_bad_input_is_refused() {
    let fx = fixture();
    let ed = fx
        .session
        .generate_ssh_key(FfiSshKeyType::Ed25519, new_key(&fx, "Source", false))
        .unwrap();
    let item = fx.session.item(fx.vault_id.clone(), ed).unwrap();
    let pem = item
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find_map(|f| match &f.value {
            FfiFieldValue::SshKey { value } => Some(value.private_pem.clone()),
            _ => None,
        })
        .unwrap();
    assert!(!ssh_key_is_encrypted(pem.clone()));
    fx.session
        .import_ssh_key(pem, None, new_key(&fx, "Importée", true))
        .unwrap();
    assert_eq!(fx.session.agent_keys().unwrap().len(), 1);
    assert!(
        fx.session
            .import_ssh_key("not a key".into(), None, new_key(&fx, "X", true))
            .is_err()
    );
    let mut bad = new_key(&fx, "Y", true);
    bad.hosts = vec!["deux mots".into()];
    assert!(
        fx.session
            .generate_ssh_key(FfiSshKeyType::Ed25519, bad)
            .is_err()
    );
}

#[test]
fn the_app_policy_exposes_only_what_it_lists() {
    let fx = fixture();
    let policy = fx.session.clone().mcp_policy(fx.data()).unwrap();
    assert!(policy.vaults.iter().all(|v| v.scopes.is_empty()));
    fx.session
        .clone()
        .set_mcp_policy(
            fx.data(),
            vec![FfiClientScopes {
                vault_id: fx.vault_id.clone(),
                scopes: vec!["metadata".into(), "use".into()],
            }],
            false,
        )
        .unwrap();
    let policy = fx.session.clone().mcp_policy(fx.data()).unwrap();
    assert!(!policy.allow_generate);
    let v = policy
        .vaults
        .iter()
        .find(|v| v.vault_id == fx.vault_id)
        .unwrap();
    assert_eq!(v.scopes, vec!["metadata".to_string(), "use".to_string()]);
    assert!(
        fx.session
            .clone()
            .set_mcp_policy(
                fx.data(),
                vec![FfiClientScopes {
                    vault_id: fx.vault_id.clone(),
                    scopes: vec!["admin".into()],
                }],
                true,
            )
            .is_err()
    );
    // A tampered file is refused, never read as "nothing".
    let file = fx.dir.path().join("dev").join("mcp-policy.json");
    let mut text = std::fs::read_to_string(&file).unwrap();
    text = text.replacen("metadata", "reveal\\\",\\\"metadata", 1);
    std::fs::write(&file, text).unwrap();
    assert!(matches!(
        fx.session.clone().mcp_policy(fx.data()),
        Err(OnePassError::Integrity { .. })
    ));
}

#[test]
fn programs_pair_and_unpair_and_the_audit_log_rotates() {
    let fx = fixture();
    let data = fx.data();
    let id = fx
        .session
        .clone()
        .pair_program(data.clone(), "/usr/bin/true".into())
        .unwrap();
    // macOS signs /usr/bin/true; other systems have no code signature.
    if cfg!(target_os = "macos") {
        assert!(
            id.starts_with("platform:") || id.starts_with("adhoc:"),
            "{id}"
        );
    } else {
        assert!(id.starts_with("unsigned:"), "{id}");
    }
    let clients = fx.session.clone().paired_clients(data.clone()).unwrap();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].surface, "mcp");
    fx.session
        .clone()
        .set_client_scopes(
            data.clone(),
            id.clone(),
            fx.vault_id.clone(),
            vec!["metadata".into()],
        )
        .unwrap();
    let clients = fx.session.clone().paired_clients(data.clone()).unwrap();
    assert_eq!(clients[0].scopes[0].scopes, vec!["metadata".to_string()]);
    fx.session.clone().unpair_client(data.clone(), id).unwrap();
    assert!(
        fx.session
            .clone()
            .paired_clients(data.clone())
            .unwrap()
            .is_empty()
    );
    assert!(
        fx.session
            .clone()
            .live_grants(data.clone())
            .unwrap()
            .is_empty()
    );
    fx.session
        .clone()
        .revoke_grants(data.clone(), None)
        .unwrap();

    std::fs::write(fx.dir.path().join("dev").join("audit.log"), "garbage\n").unwrap();
    let report = fx.session.clone().audit_report(data.clone()).unwrap();
    assert!(report.problem.is_some());
    fx.session.clone().rotate_audit_log(data.clone()).unwrap();
    let report = fx.session.clone().audit_report(data).unwrap();
    // The new log starts with the signed record of the rotation.
    assert!(report.problem.is_none(), "{report:?}");
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].action, "audit_log_rotated");
}

// ---- MCP server, with the test playing the relay

mod mcp {
    use super::*;
    use std::io::{BufRead, BufReader};

    struct Relay {
        out: UnixStream,
        input: BufReader<UnixStream>,
    }

    impl Relay {
        fn connect(socket: &str, client: serde_json::Value) -> Relay {
            let out = UnixStream::connect(socket).unwrap();
            out.set_read_timeout(Some(std::time::Duration::from_secs(20)))
                .unwrap();
            let input = BufReader::new(out.try_clone().unwrap());
            let mut r = Relay { out, input };
            r.send(serde_json::json!({"t": "hello", "v": 1, "client": client}));
            r
        }

        fn send(&mut self, v: serde_json::Value) {
            let mut line = v.to_string();
            line.push('\n');
            self.out.write_all(line.as_bytes()).unwrap();
        }

        /// Sends one JSON-RPC request without waiting for its reply.
        fn request(&mut self, id: u64, method: &str, params: serde_json::Value) {
            let rpc =
                serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
            self.send(serde_json::json!({"t": "mcp", "line": rpc.to_string()}));
        }

        /// The next JSON-RPC reply (notifications skipped).
        fn reply(&mut self) -> serde_json::Value {
            loop {
                let msg = self.recv();
                assert_eq!(msg["t"], "mcp", "{msg}");
                let line: serde_json::Value =
                    serde_json::from_str(msg["line"].as_str().unwrap()).unwrap();
                if line.get("method").is_some() && line.get("id").is_none() {
                    continue;
                }
                return line;
            }
        }

        /// True once the app closed the connection.
        fn closed(&mut self) -> bool {
            let mut line = String::new();
            matches!(self.input.read_line(&mut line), Ok(0) | Err(_))
        }

        fn recv(&mut self) -> serde_json::Value {
            let mut line = String::new();
            self.input.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        }

        /// One JSON-RPC request; answers the relay requests (exec) the
        /// app sends meanwhile with `exec`, until the response comes.
        fn call(
            &mut self,
            id: u64,
            method: &str,
            params: serde_json::Value,
            exec: &dyn Fn(&serde_json::Value) -> serde_json::Value,
        ) -> serde_json::Value {
            let rpc =
                serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
            self.send(serde_json::json!({"t": "mcp", "line": rpc.to_string()}));
            loop {
                let msg = self.recv();
                match msg["t"].as_str().unwrap() {
                    "mcp" => {
                        let line: serde_json::Value =
                            serde_json::from_str(msg["line"].as_str().unwrap()).unwrap();
                        // A notification (pending approval) is not the reply.
                        if line.get("method").is_some() && line.get("id").is_none() {
                            continue;
                        }
                        return line;
                    }
                    "exec" => {
                        let reply = exec(&msg);
                        self.send(reply);
                    }
                    other => panic!("unexpected {other}"),
                }
            }
        }
    }

    fn signed_client() -> serde_json::Value {
        serde_json::json!({
            "id": "team:TEAMID0001:com.exemple.agent", "label": "Agent Exemple",
            "signed": true, "hardened": null,
            "code": {"kind": "team", "team_id": "TEAMID0001", "identifier": "com.exemple.agent"},
            "chain": ["team:TEAMID0001:com.exemple.agent"],
        })
    }

    fn no_exec(_: &serde_json::Value) -> serde_json::Value {
        panic!("no command expected")
    }

    /// A vault exposed with metadata and use, holding one note.
    fn exposed(fx: &Fixture) -> String {
        let vault = fx
            .session
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.id == fx.vault_id)
            .unwrap();
        let mut meta = vault.meta.clone();
        meta.mcp_access = true;
        fx.session.update_vault(fx.vault_id.clone(), meta).unwrap();
        fx.session
            .clone()
            .set_mcp_policy(
                fx.data(),
                vec![FfiClientScopes {
                    vault_id: fx.vault_id.clone(),
                    scopes: vec!["metadata".into(), "use".into()],
                }],
                true,
            )
            .unwrap();
        let mut note = fx
            .session
            .new_item(
                fx.vault_id.clone(),
                FfiItemType::SecureNote,
                "Jeton Atlas".into(),
            )
            .unwrap();
        for f in note.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
            if f.id == "content" {
                f.value = FfiFieldValue::Text {
                    value: "jeton-secret-atlas-42".into(),
                };
            }
        }
        fx.session.save_item(note).unwrap();
        // References name the vault and the item (names or hyphenated ids).
        format!("onepass://{}/Jeton Atlas/content", vault.meta.name)
    }

    fn start(fx: &Fixture, ui: Arc<ScriptedUi>) -> Arc<McpHost> {
        McpHost::start_any_relay_for_tests(
            fx.session.clone(),
            FfiMcpHostConfig {
                data_dir: fx.data(),
                socket_path: fx.mcp_socket(),
                relay_path: "/unused".into(),
                protected_dirs: vec![fx.dir.path().display().to_string()],
            },
            ui,
        )
        .unwrap()
    }

    fn initialize(r: &mut Relay) {
        let init = r.call(
            1,
            "initialize",
            serde_json::json!({"protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"}}),
            &no_exec,
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "onepass");
    }

    #[test]
    fn a_signed_client_pairs_lists_and_runs_with_masked_secrets() {
        let fx = fixture();
        let reference = exposed(&fx);
        let ui = ScriptedUi::new(FfiDecision::AllowOnce, true);
        let host = start(&fx, ui.clone());
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        initialize(&mut r);
        // Pairing runs beside the session: wait for the user's answer.
        let mut clients = Vec::new();
        for _ in 0..200 {
            clients = fx.session.clone().paired_clients(fx.data()).unwrap();
            if !clients.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, "team:TEAMID0001:com.exemple.agent");

        let listed = r.call(
            2,
            "tools/call",
            serde_json::json!({"name": "list_vaults", "arguments": {}}),
            &no_exec,
        );
        assert_eq!(listed["result"]["isError"], false, "{listed}");

        let ran = r.call(
            3,
            "tools/call",
            serde_json::json!({"name": "run_with_secrets", "arguments": {
                "command": ["sh", "-c", "printf %s \"$TOKEN\""], "env": {"TOKEN": reference}}}),
            &|exec| {
                // The relay gets the value to inject, and returns it raw.
                assert_eq!(exec["env"][0][1], "jeton-secret-atlas-42");
                serde_json::json!({"t": "exec_result", "id": exec["id"], "ok": {
                    "code": 0, "stdout": "jeton-secret-atlas-42", "stderr": "",
                    "timed_out": false, "truncated": false}})
            },
        );
        let text = ran.to_string();
        assert!(!text.contains("jeton-secret-atlas-42"), "{text}");
        assert!(text.contains("concealed:TOKEN"), "{text}");
        assert_eq!(ui.asked.lock().unwrap().len(), 1);
        assert_eq!(ui.asked.lock().unwrap()[0].surface, "mcp");

        drop(r);
        host.stop();
        let report = fx.session.clone().audit_report(fx.data()).unwrap();
        assert!(
            report
                .entries
                .iter()
                .any(|e| e.action == "run_with_secrets")
        );
    }

    #[test]
    fn an_unpaired_ad_hoc_client_is_refused_without_a_prompt() {
        let fx = fixture();
        exposed(&fx);
        let ui = ScriptedUi::new(FfiDecision::AllowOnce, true);
        let host = start(&fx, ui.clone());
        let mut r = Relay::connect(
            &fx.mcp_socket(),
            serde_json::json!({"id": "adhoc:abcdef", "label": "outil-local", "signed": false,
                "hardened": false, "code": {"kind": "adhoc"}, "chain": []}),
        );
        initialize(&mut r);
        let listed = r.call(
            2,
            "tools/call",
            serde_json::json!({"name": "list_vaults", "arguments": {}}),
            &no_exec,
        );
        assert_eq!(listed["result"]["isError"], true, "{listed}");
        assert!(listed.to_string().contains("not paired"), "{listed}");
        assert!(ui.asked.lock().unwrap().is_empty());
        assert!(
            fx.session
                .clone()
                .paired_clients(fx.data())
                .unwrap()
                .is_empty()
        );
        host.stop();
    }

    #[test]
    fn a_refused_pairing_serves_nothing() {
        let fx = fixture();
        exposed(&fx);
        let ui = Arc::new(ScriptedUi {
            answer: Mutex::new(FfiDecision::AllowOnce),
            origin: Mutex::new(None),
            present: true,
            pair: false,
            asked: Mutex::new(Vec::new()),
            presence_checks: AtomicUsize::new(0),
        });
        let host = start(&fx, ui);
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        initialize(&mut r);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let listed = r.call(
            2,
            "tools/call",
            serde_json::json!({"name": "list_vaults", "arguments": {}}),
            &no_exec,
        );
        assert_eq!(listed["result"]["isError"], true, "{listed}");
        host.stop();
    }

    #[test]
    fn open_sessions_follow_the_settings_and_end_on_stop() {
        let fx = fixture();
        exposed(&fx);
        let ui = ScriptedUi::new(FfiDecision::AllowOnce, true);
        let host = start(&fx, ui);
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        initialize(&mut r);
        for _ in 0..200 {
            if !fx
                .session
                .clone()
                .paired_clients(fx.data())
                .unwrap()
                .is_empty()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let list = |r: &mut Relay, id| {
            r.call(
                id,
                "tools/call",
                serde_json::json!({"name": "list_vaults", "arguments": {}}),
                &no_exec,
            )
        };
        let before = list(&mut r, 2);
        assert_eq!(
            before["result"]["structuredContent"]["untrusted_vault_data"]
                .as_array()
                .map(Vec::len),
            Some(1),
            "{before}"
        );
        // The vault is no longer exposed: the open session sees it at once.
        fx.session
            .clone()
            .set_mcp_policy(fx.data(), Vec::new(), true)
            .unwrap();
        let after = list(&mut r, 3);
        assert_eq!(
            after["result"]["structuredContent"]["untrusted_vault_data"]
                .as_array()
                .map(Vec::len),
            Some(0),
            "{after}"
        );
        // Stopping the server ends the session.
        host.stop();
        let mut line = String::new();
        let n = r.input.read_line(&mut line).unwrap_or(0);
        assert_eq!(n, 0, "{line}");
        let report = fx.session.clone().audit_report(fx.data()).unwrap();
        for action in ["client_paired", "mcp_policy_set"] {
            assert!(
                report.entries.iter().any(|e| e.action == action),
                "{action}"
            );
        }
    }

    #[test]
    fn templates_never_touch_the_store_folder() {
        let fx = fixture();
        let reference = exposed(&fx);
        let _ = reference;
        let ui = ScriptedUi::new(FfiDecision::AllowOnce, true);
        let host = start(&fx, ui.clone());
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        initialize(&mut r);
        for _ in 0..200 {
            if !fx
                .session
                .clone()
                .paired_clients(fx.data())
                .unwrap()
                .is_empty()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let target = fx.dir.path().join("onepass.db");
        let filled = r.call(
            2,
            "tools/call",
            serde_json::json!({"name": "fill_template", "arguments": {
                "template_path": "/tmp/any.tpl", "output_path": target.display().to_string(),
                "overwrite": true}}),
            &|m| panic!("the relay must not be asked: {m}"),
        );
        assert_eq!(filled["result"]["isError"], true, "{filled}");
        assert!(filled.to_string().contains("data folder"), "{filled}");
        assert!(ui.asked.lock().unwrap().is_empty());
        host.stop();
    }
    // ---- the gate, while the app is locked

    const LOCKED: &str = "OnePass is locked on this Mac. Approve on your iPhone or unlock the app.";
    const NOT_PAIRED: &str =
        "This client is not paired with OnePass. Unlock OnePass on this Mac to pair it.";

    /// The app's side of the gate: records who asked, answers what the test
    /// sends (false after a while, as the app does after 60 s).
    struct GateUi {
        asked: Mutex<Vec<FfiMcpClient>>,
        answers: Mutex<std::sync::mpsc::Receiver<bool>>,
    }

    impl FfiGateUi for GateUi {
        fn locked_request(&self, client: FfiMcpClient) -> bool {
            self.asked.lock().unwrap().push(client);
            self.answers
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(20))
                .unwrap_or(false)
        }
    }

    fn gate_ui() -> (Arc<GateUi>, std::sync::mpsc::Sender<bool>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let ui = Arc::new(GateUi {
            asked: Mutex::new(Vec::new()),
            answers: Mutex::new(rx),
        });
        (ui, tx)
    }

    fn wait_asked(ui: &GateUi, n: usize) {
        for _ in 0..500 {
            if ui.asked.lock().unwrap().len() >= n {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the app was not asked {n} times");
    }

    fn init_params() -> serde_json::Value {
        serde_json::json!({"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}})
    }

    fn host_config(fx: &Fixture) -> FfiMcpHostConfig {
        FfiMcpHostConfig {
            data_dir: fx.data(),
            socket_path: fx.mcp_socket(),
            relay_path: "/unused".into(),
            protected_dirs: vec![fx.dir.path().display().to_string()],
        }
    }

    #[test]
    fn gate_refuses_unverified_peer() {
        let fx = fixture();
        let (ui, _answers) = gate_ui();
        // The relay the gate expects is /usr/bin/true: this test is not it.
        let gate = McpGate::start(
            fx.mcp_socket(),
            "/usr/bin/true".into(),
            fx.data(),
            ui.clone(),
        )
        .unwrap();
        assert!(gate.is_running());
        let mut s = UnixStream::connect(fx.mcp_socket()).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let hello = serde_json::json!({"t": "hello", "v": 1, "client": signed_client()});
        let _ = s.write_all(format!("{hello}\n").as_bytes());
        let mut buf = [0u8; 64];
        // Closed without a word.
        assert!(matches!(s.read(&mut buf), Ok(0) | Err(_)));
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(ui.asked.lock().unwrap().is_empty());
        gate.stop();
        assert!(!gate.is_running());
        assert!(!std::path::Path::new(&fx.mcp_socket()).exists());
    }

    /// Pairs the signed client through the real server (the owner did it
    /// before locking), and returns what that server answers to
    /// `initialize` and `tools/list`: the gate must answer the same.
    fn paired_signed(fx: &Fixture) -> (serde_json::Value, serde_json::Value) {
        let host = start(fx, ScriptedUi::new(FfiDecision::AllowOnce, true));
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        let init = r.call(1, "initialize", init_params(), &no_exec);
        for _ in 0..200 {
            if !fx
                .session
                .clone()
                .paired_clients(fx.data())
                .unwrap()
                .is_empty()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            fx.session.clone().paired_clients(fx.data()).unwrap().len(),
            1
        );
        let tools = r.call(2, "tools/list", serde_json::json!({}), &no_exec);
        drop(r);
        host.stop();
        (init["result"].clone(), tools["result"].clone())
    }

    fn start_gate(fx: &Fixture, ui: Arc<GateUi>) -> Arc<McpGate> {
        McpGate::start_any_relay_for_tests(fx.mcp_socket(), fx.data(), ui).unwrap()
    }

    fn list_vaults() -> serde_json::Value {
        serde_json::json!({"name": "list_vaults", "arguments": {}})
    }

    #[test]
    fn gate_answers_the_handshake_and_asks_on_the_first_tool_call() {
        let fx = fixture();
        exposed(&fx);
        let (server_init, server_tools) = paired_signed(&fx);
        let (gate_ui, answers) = gate_ui();
        let gate = start_gate(&fx, gate_ui.clone());
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());

        // The gate answers the handshake itself, as the server would, and
        // asks nobody: a client that never calls a tool prompts no phone.
        let init = r.call(1, "initialize", init_params(), &no_exec);
        assert_eq!(init["result"], server_init, "{init}");
        r.send(serde_json::json!({"t": "mcp", "line":
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string()}));
        let tools = r.call(2, "tools/list", serde_json::json!({}), &no_exec);
        assert_eq!(tools["result"], server_tools, "{tools}");
        let ping = r.call(3, "ping", serde_json::json!({}), &no_exec);
        assert!(ping.get("result").is_some(), "{ping}");
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(gate_ui.asked.lock().unwrap().is_empty());

        // The first tool call asks the app.
        r.request(4, "tools/call", list_vaults());
        wait_asked(&gate_ui, 1);
        {
            let asked = gate_ui.asked.lock().unwrap();
            assert_eq!(asked[0].id, "team:TEAMID0001:com.exemple.agent");
            assert_eq!(asked[0].label, "Agent Exemple");
            assert!(asked[0].signed);
        }

        // One asking connection per client: a second one's call is
        // answered at once.
        let mut second = Relay::connect(&fx.mcp_socket(), signed_client());
        let _ = second.call(1, "initialize", init_params(), &no_exec);
        second.request(2, "tools/call", list_vaults());
        let refused = second.reply();
        assert_eq!(refused["id"], 2, "{refused}");
        assert_eq!(refused["error"]["message"], LOCKED, "{refused}");
        assert!(second.closed());
        assert_eq!(gate_ui.asked.lock().unwrap().len(), 1);

        // The app unlocks: the server starts on the session and gets the
        // pending call, replayed on the handshake the gate answered.
        let ui = ScriptedUi::new(FfiDecision::AllowOnce, true);
        let host = gate
            .hand_over(fx.session.clone(), host_config(&fx), ui.clone())
            .unwrap();
        answers.send(true).unwrap();
        let listed = r.reply();
        assert_eq!(listed["id"], 4, "{listed}");
        assert_eq!(listed["result"]["isError"], false, "{listed}");
        assert_eq!(
            listed["result"]["structuredContent"]["untrusted_vault_data"]
                .as_array()
                .map(Vec::len),
            Some(1),
            "{listed}"
        );
        let again = r.call(5, "tools/call", list_vaults(), &no_exec);
        assert_eq!(again["result"]["isError"], false, "{again}");

        // Later connections go straight to the server.
        let mut third = Relay::connect(&fx.mcp_socket(), signed_client());
        initialize(&mut third);
        assert_eq!(gate_ui.asked.lock().unwrap().len(), 1);
        assert!(!gate.is_running());

        drop((r, third));
        host.stop();
        gate.stop();
        assert!(!std::path::Path::new(&fx.mcp_socket()).exists());
    }

    #[test]
    fn gate_hands_over_a_connection_that_never_called_a_tool() {
        let fx = fixture();
        exposed(&fx);
        paired_signed(&fx);
        let (gate_ui, _answers) = gate_ui();
        let gate = start_gate(&fx, gate_ui.clone());
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        let _ = r.call(1, "initialize", init_params(), &no_exec);

        // The owner unlocks the Mac: the connection still in its handshake
        // goes to the server, which serves its calls without a question.
        let host = gate
            .hand_over(
                fx.session.clone(),
                host_config(&fx),
                ScriptedUi::new(FfiDecision::AllowOnce, true),
            )
            .unwrap();
        drop(gate);
        let listed = r.call(2, "tools/call", list_vaults(), &no_exec);
        assert_eq!(listed["result"]["isError"], false, "{listed}");
        assert!(gate_ui.asked.lock().unwrap().is_empty());
        drop(r);
        host.stop();
    }

    #[test]
    fn gate_never_asks_for_an_unpaired_client() {
        let fx = fixture();
        exposed(&fx);
        let (gate_ui, _answers) = gate_ui();
        let gate = start_gate(&fx, gate_ui.clone());
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        let init = r.call(1, "initialize", init_params(), &no_exec);
        assert_eq!(init["result"]["serverInfo"]["name"], "onepass", "{init}");
        r.request(2, "tools/call", list_vaults());
        let refused = r.reply();
        assert_eq!(refused["id"], 2, "{refused}");
        assert_eq!(refused["error"]["message"], NOT_PAIRED, "{refused}");
        assert!(r.closed());
        assert!(gate_ui.asked.lock().unwrap().is_empty());
        gate.stop();
    }

    #[test]
    fn gate_answers_locked_error_on_refusal() {
        let fx = fixture();
        exposed(&fx);
        paired_signed(&fx);
        let (gate_ui, answers) = gate_ui();
        let gate = start_gate(&fx, gate_ui.clone());
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        let _ = r.call(1, "initialize", init_params(), &no_exec);
        r.request(7, "tools/call", list_vaults());
        wait_asked(&gate_ui, 1);
        answers.send(false).unwrap();
        let reply = r.reply();
        assert_eq!(reply["id"], 7, "{reply}");
        assert_eq!(reply["error"]["message"], LOCKED, "{reply}");
        assert!(!reply.to_string().contains("Jeton Atlas"));
        assert!(r.closed());

        // The hold is released: the same client is asked again.
        let mut again = Relay::connect(&fx.mcp_socket(), signed_client());
        let _ = again.call(1, "initialize", init_params(), &no_exec);
        again.request(2, "tools/call", list_vaults());
        wait_asked(&gate_ui, 2);
        answers.send(false).unwrap();
        assert_eq!(again.reply()["error"]["message"], LOCKED);

        // A client that leaves while held releases its hold at once, and the
        // app's late answer finds nobody to serve.
        let mut gone = Relay::connect(&fx.mcp_socket(), signed_client());
        let _ = gone.call(1, "initialize", init_params(), &no_exec);
        gone.request(2, "tools/call", list_vaults());
        wait_asked(&gate_ui, 3);
        drop(gone);
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut back = Relay::connect(&fx.mcp_socket(), signed_client());
        let _ = back.call(1, "initialize", init_params(), &no_exec);
        back.request(2, "tools/call", list_vaults());
        answers.send(true).unwrap();
        wait_asked(&gate_ui, 4);
        answers.send(false).unwrap();
        assert_eq!(back.reply()["error"]["message"], LOCKED);
        assert!(back.closed());
        gate.stop();
    }

    #[test]
    fn answer_origin_reaches_audit() {
        let fx = fixture();
        let reference = exposed(&fx);
        let ui = ScriptedUi::new(FfiDecision::AllowOnce, true);
        *ui.origin.lock().unwrap() = Some("phone:7f3a9c".into());
        let host = start(&fx, ui.clone());
        let mut r = Relay::connect(&fx.mcp_socket(), signed_client());
        initialize(&mut r);
        for _ in 0..200 {
            if !fx
                .session
                .clone()
                .paired_clients(fx.data())
                .unwrap()
                .is_empty()
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let ran = r.call(
            2,
            "tools/call",
            serde_json::json!({"name": "run_with_secrets", "arguments": {
                "command": ["true"], "env": {"TOKEN": reference}}}),
            &|exec| {
                serde_json::json!({"t": "exec_result", "id": exec["id"], "ok": {
                    "code": 0, "stdout": "", "stderr": "",
                    "timed_out": false, "truncated": false}})
            },
        );
        assert_eq!(ran["result"]["isError"], false, "{ran}");
        {
            let asked = ui.asked.lock().unwrap();
            assert_eq!(asked.len(), 1);
            // The app shows the guard's confirmation code.
            assert!(!asked[0].confirm_code.is_empty());
            assert!(!asked[0].strong_required);
        }
        drop(r);
        host.stop();

        let report = fx.session.clone().audit_report(fx.data()).unwrap();
        assert!(report.problem.is_none(), "{report:?}");
        let log = std::fs::read_to_string(fx.dir.path().join("dev").join("audit.log")).unwrap();
        let line = log
            .lines()
            .find(|l| l.contains("run_with_secrets"))
            .expect("run_with_secrets audited");
        assert!(line.contains(r#""approved_on":"phone:7f3a9c""#), "{line}");
        // The settings' audit view reads it too (its origin column).
        let entry = report
            .entries
            .iter()
            .find(|e| e.action == "run_with_secrets")
            .expect("run_with_secrets in the report");
        assert_eq!(entry.approved_on.as_deref(), Some("phone:7f3a9c"));
    }
}
