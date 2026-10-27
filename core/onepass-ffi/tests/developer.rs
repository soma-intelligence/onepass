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
    present: bool,
    pair: bool,
    asked: Mutex<Vec<FfiApprovalRequest>>,
    presence_checks: AtomicUsize,
}

impl ScriptedUi {
    fn new(answer: FfiDecision, present: bool) -> Arc<ScriptedUi> {
        Arc::new(ScriptedUi {
            answer: Mutex::new(answer),
            present,
            pair: true,
            asked: Mutex::new(Vec::new()),
            presence_checks: AtomicUsize::new(0),
        })
    }
}

impl FfiDeveloperUi for ScriptedUi {
    fn approve(&self, request: FfiApprovalRequest) -> FfiDecision {
        self.asked.lock().unwrap().push(request);
        *self.answer.lock().unwrap()
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
    assert!(
        id.starts_with("platform:") || id.starts_with("adhoc:"),
        "{id}"
    );
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
    assert!(report.problem.is_none() && report.entries.is_empty());
}
