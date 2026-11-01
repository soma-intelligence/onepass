//! Agent decisions (spec 6.2 to 6.4): approvals, grants, lock, session
//! binding, bookmarks, forwarding, peer uid and SSHSIG namespace.

mod common;

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::hmac;
use common::*;
use data_encoding::BASE64;
use onepass_guard::testing::ScriptedApprover;
use onepass_guard::{ApprovalRequest, Decision, Surface, Target};
use onepass_ssh_agent::keys::{AgentKey, KeyType, fingerprint_of_blob, verify_signature};
use onepass_ssh_agent::wire::{
    Request, Response, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512, SshWriter,
};
use onepass_ssh_agent::{Agent, AgentConfig, AgentGuards, ConnState, PeerInfo, Reply};
use tempfile::TempDir;
use zeroize::Zeroizing;

struct Fixture {
    agent: Agent<FakeSource>,
    source: FakeSource,
    approver: Arc<ScriptedApprover>,
    audit: SharedAudit,
    env: GuardEnv,
}

fn fixture_with(source: FakeSource, answers: Vec<Decision>, config: AgentConfig) -> Fixture {
    let approver = Arc::new(ScriptedApprover::new(answers));
    let audit = SharedAudit::default();
    let (guards, env) = guards(loose_limits());
    let agent = Agent::new(
        source.clone(),
        approver.clone(),
        Box::new(audit.clone()),
        config,
        guards,
    );
    Fixture {
        agent,
        source,
        approver,
        audit,
        env,
    }
}

fn fixture(answers: Vec<Decision>) -> Fixture {
    fixture_with(FakeSource::all(), answers, AgentConfig::default())
}

/// An open agent (the app's): no registry, grants in memory.
fn open_fixture_with(source: FakeSource, answers: Vec<Decision>, config: AgentConfig) -> Fixture {
    let approver = Arc::new(ScriptedApprover::new(answers));
    let audit = SharedAudit::default();
    let (_, env) = guards(loose_limits());
    let agent = Agent::new(
        source.clone(),
        approver.clone(),
        Box::new(audit.clone()),
        config,
        AgentGuards::open(),
    );
    Fixture {
        agent,
        source,
        approver,
        audit,
        env,
    }
}

fn open_fixture(answers: Vec<Decision>) -> Fixture {
    open_fixture_with(FakeSource::all(), answers, AgentConfig::default())
}

fn flags_for(t: KeyType) -> u32 {
    if t == KeyType::Rsa3072 {
        SSH_AGENT_RSA_SHA2_256
    } else {
        0
    }
}

fn sign_req(t: KeyType, data: &[u8]) -> Request {
    Request::Sign {
        key_blob: key(t).public_blob(),
        data: data.to_vec(),
        flags: flags_for(t),
    }
}

impl Fixture {
    fn handle(&mut self, conn: &mut ConnState, peer: &PeerInfo, req: Request) -> Reply {
        self.agent.handle(conn, peer, req)
    }

    /// Signs with key `t` as `exe` on a fresh connection.
    fn sign(&mut self, t: KeyType, exe: &str) -> Response {
        let mut conn = ConnState::default();
        self.handle(&mut conn, &peer(exe), sign_req(t, b"data to sign"))
            .response
    }

    fn asked(&self) -> usize {
        self.approver.calls().len()
    }

    fn last_call(&self) -> ApprovalRequest {
        self.approver.calls().pop().expect("an approval request")
    }
}

fn detail<'a>(req: &'a ApprovalRequest, label: &str) -> Option<&'a str> {
    req.details
        .iter()
        .find(|(l, _)| l == label)
        .map(|(_, v)| v.as_str())
}

fn is_signature(r: &Response) -> bool {
    matches!(r, Response::Signature(_))
}

/// `session-bind@openssh.com` contents for `host`, signed over `session_id`
/// by `signer` (the host key itself for a valid bind).
fn bind_request(host: &AgentKey, signer: &AgentKey, forwarding: bool) -> Request {
    let session_id = [9u8; 32];
    let sig = signer.sign(&session_id, 0).unwrap();
    let mut w = SshWriter::new();
    w.string(&host.public_blob())
        .string(&session_id)
        .string(&sig)
        .u8(u8::from(forwarding));
    Request::Extension {
        name: "session-bind@openssh.com".into(),
        contents: w.into_vec(),
    }
}

fn bind(f: &mut Fixture, conn: &mut ConnState, host: &AgentKey, forwarding: bool) {
    let r = f.handle(
        conn,
        &peer("/usr/bin/ssh"),
        bind_request(host, host, forwarding),
    );
    assert_eq!(
        r,
        Reply {
            response: Response::Success,
            close: false
        }
    );
}

fn known_hosts_line(names: &str, host: &AgentKey) -> String {
    format!("{names} {}\n", host.public_openssh(""))
}

fn hashed_name(name: &str) -> String {
    let salt = [3u8; 20];
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
    let tag = hmac::sign(&key, name.as_bytes());
    format!(
        "|1|{}|{}",
        BASE64.encode(&salt),
        BASE64.encode(tag.as_ref())
    )
}

#[test]
fn lists_identities_with_titles() {
    let mut f = fixture(vec![]);
    let r = f.handle(
        &mut ConnState::default(),
        &peer("/usr/bin/ssh-add"),
        Request::RequestIdentities,
    );
    let Response::Identities(ids) = r.response else {
        panic!("expected identities, got {:?}", r.response);
    };
    let expected: Vec<(Vec<u8>, String)> = TYPES
        .iter()
        .map(|&t| (key(t).public_blob(), title_of(t)))
        .collect();
    assert_eq!(ids, expected);
    assert!(!r.close);
    assert_eq!(f.asked(), 0);
}

#[test]
fn signs_each_algorithm_after_approval() {
    let mut f = fixture(vec![Decision::AllowOnce; TYPES.len() + 1]);
    let data = b"session data to sign";
    for (n, &t) in TYPES.iter().enumerate() {
        let blob = key(t).public_blob();
        let r = f.handle(
            &mut ConnState::default(),
            &peer("/usr/bin/ssh"),
            sign_req(t, data),
        );
        let Response::Signature(sig) = r.response else {
            panic!("{t:?}: expected a signature, got {:?}", r.response);
        };
        verify_signature(&blob, data, &sig).unwrap_or_else(|e| panic!("{t:?}: {e}"));
        assert_eq!(f.asked(), n + 1);
        let call = f.last_call();
        assert_eq!(call.surface, Surface::Ssh);
        assert_eq!(call.action, "ssh_sign");
        assert_eq!(call.client, "Test platform:com.apple.ssh");
        assert!(call.client_verified);
        assert_eq!(detail(&call, "client id"), Some("platform:com.apple.ssh"));
        assert_eq!(
            call.targets,
            vec![Target {
                vault: VAULT_NAME.into(),
                item: title_of(t),
                field: Some("private_key".into()),
            }]
        );
        assert_eq!(detail(&call, "key"), Some(title_of(t).as_str()));
        assert_eq!(
            detail(&call, "fingerprint"),
            Some(key(t).fingerprint().as_str())
        );
        assert_eq!(detail(&call, "process"), Some("/usr/bin/ssh (4242)"));
        assert_eq!(detail(&call, "forwarded"), Some("no"));
        assert_eq!(detail(&call, "destination"), None);
        assert_eq!(detail(&call, "namespace"), None);
        assert!(call.remember_allowed);
    }
    // RSA with SHA-512 too.
    let rsa = key(KeyType::Rsa3072);
    let r = f.handle(
        &mut ConnState::default(),
        &peer("/usr/bin/ssh"),
        Request::Sign {
            key_blob: rsa.public_blob(),
            data: data.to_vec(),
            flags: SSH_AGENT_RSA_SHA2_512,
        },
    );
    let Response::Signature(sig) = r.response else {
        panic!("expected an RSA SHA-512 signature");
    };
    assert!(sig.starts_with(b"\0\0\0\x0crsa-sha2-512"));
    verify_signature(&rsa.public_blob(), data, &sig).unwrap();

    let audit = f.audit.entries();
    assert_eq!(audit.len(), TYPES.len() + 1);
    for (e, &t) in audit.iter().zip(TYPES.iter()) {
        assert_eq!(e.surface, Surface::Ssh);
        assert_eq!(e.action, "ssh_sign");
        assert_eq!(e.client, "/usr/bin/ssh");
        assert_eq!(e.client_id.as_deref(), Some("platform:com.apple.ssh"));
        assert_eq!(
            e.client_label.as_deref(),
            Some("Test platform:com.apple.ssh")
        );
        assert_eq!(e.vault_id.as_deref(), Some(VAULT_ID));
        assert_eq!(e.item_id, Some(item_id_of(t)));
        assert_eq!(e.decision, "once");
        assert_eq!(e.outcome, "ok");
    }
}

#[test]
fn unknown_key_fails_without_asking() {
    let mut f = fixture(vec![Decision::AllowOnce]);
    let stranger = AgentKey::generate(KeyType::Ed25519).unwrap();
    let r = f.handle(
        &mut ConnState::default(),
        &peer("/usr/bin/ssh"),
        Request::Sign {
            key_blob: stranger.public_blob(),
            data: b"x".to_vec(),
            flags: 0,
        },
    );
    assert_eq!(r.response, Response::Failure);
    assert_eq!(f.asked(), 0);
    let audit = f.audit.entries();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].item_id, None);
    assert_eq!(audit[0].outcome, "refused");
}

#[test]
fn denial_fails() {
    let mut f = fixture(vec![Decision::Deny]);
    assert_eq!(f.sign(KeyType::Ed25519, "/usr/bin/ssh"), Response::Failure);
    assert_eq!(f.asked(), 1);
    let audit = f.audit.entries();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].item_id, Some(item_id_of(KeyType::Ed25519)));
    assert_eq!(audit[0].decision, "denied");
    assert_eq!(audit[0].outcome, "refused");
}

#[test]
fn confirm_each_use_never_remembered() {
    let mut f = fixture(vec![
        Decision::AllowFor(std::time::Duration::from_secs(300));
        3
    ]);
    f.source
        .edit(KeyType::Ed25519, |k| k.confirm_each_use = true);
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert!(!f.last_call().remember_allowed);
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 2);
    let audit = f.audit.entries();
    assert!(audit.iter().all(|e| e.decision == "once"));
}

#[test]
fn grant_is_per_key_and_client() {
    let mut f = fixture(vec![
        Decision::AllowFor(std::time::Duration::from_secs(300));
        4
    ]);
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 1);
    // Same key, same client: remembered.
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 1);
    // Same key, another client: asked again.
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/git")));
    assert_eq!(f.asked(), 2);
    // Another key, same client: asked again.
    assert!(is_signature(&f.sign(KeyType::EcdsaP256, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 3);
    let decisions: Vec<String> = f.audit.entries().into_iter().map(|e| e.decision).collect();
    assert_eq!(
        decisions,
        ["grant_5m", "remembered", "grant_5m", "grant_5m"]
    );

    // The same executable path under another identity (another binary
    // copied there) is another client: not paired, refused unasked.
    let mut conn = ConnState::default();
    let impostor = peer_with(
        "/usr/bin/ssh",
        Some(onepass_peer::ClientIdentity {
            code: onepass_peer::CodeIdentity::AdHoc {
                path: "/usr/bin/ssh".into(),
                cdhash: "ab".repeat(20),
                hardened: false,
            },
            pid: 4242,
            exe: Some("/usr/bin/ssh".into()),
            chain: Vec::new(),
        }),
    );
    let r = f.handle(&mut conn, &impostor, sign_req(KeyType::Ed25519, b"d"));
    assert_eq!(r.response, Response::Failure);
    assert_eq!(f.asked(), 3);
    // An unidentified client is refused too.
    let anonymous = peer_with("/usr/bin/ssh", None);
    let r = f.handle(&mut conn, &anonymous, sign_req(KeyType::Ed25519, b"d"));
    assert_eq!(r.response, Response::Failure);
    assert_eq!(f.asked(), 3);
}

/// Audit 2026-10-28: a client that execs `ssh` after connecting shows the
/// same executable path, but not the same code identity. The grant of the
/// real `ssh` must not cover it (open agent: a paired one refuses that
/// client outright, see `grant_is_per_key_and_client`).
#[test]
fn session_grant_is_keyed_by_code_not_path() {
    let mut f = open_fixture(vec![
        Decision::AllowFor(std::time::Duration::from_secs(300));
        2
    ]);
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 1);
    let impostor = PeerInfo {
        code: Some("adhoc:0badc0de".into()),
        identity: None,
        ..peer("/usr/bin/ssh")
    };
    let r = f.handle(
        &mut ConnState::default(),
        &impostor,
        sign_req(KeyType::Ed25519, b"d"),
    );
    assert!(is_signature(&r.response));
    assert_eq!(f.asked(), 2);
    assert!(
        f.last_call()
            .details
            .iter()
            .any(|(k, v)| k == "code" && v == "adhoc:0badc0de")
    );
}

/// A grant given for one destination does not sign for another, in both
/// modes.
#[test]
fn session_grant_is_per_destination() {
    for open in [false, true] {
        let answers = vec![Decision::AllowFor(std::time::Duration::from_secs(300)); 3];
        let f = if open {
            open_fixture(answers)
        } else {
            fixture(answers)
        };
        grant_per_destination(f);
    }
}

fn grant_per_destination(mut f: Fixture) {
    let one = AgentKey::generate(KeyType::Ed25519).unwrap();
    let two = AgentKey::generate(KeyType::Ed25519).unwrap();
    let ssh = peer("/usr/bin/ssh");
    let mut a = ConnState::default();
    bind(&mut f, &mut a, &one, false);
    assert!(is_signature(
        &f.handle(&mut a, &ssh, sign_req(KeyType::Ed25519, b"d"))
            .response
    ));
    assert_eq!(f.asked(), 1);
    let mut again = ConnState::default();
    bind(&mut f, &mut again, &one, false);
    assert!(is_signature(
        &f.handle(&mut again, &ssh, sign_req(KeyType::Ed25519, b"d"))
            .response
    ));
    assert_eq!(f.asked(), 1);
    let mut b = ConnState::default();
    bind(&mut f, &mut b, &two, false);
    assert!(is_signature(
        &f.handle(&mut b, &ssh, sign_req(KeyType::Ed25519, b"d"))
            .response
    ));
    assert_eq!(f.asked(), 2);
}

/// On macOS the kernel names the code of a socket peer: this test binary.
#[cfg(target_os = "macos")]
#[test]
fn peer_info_reads_the_code_identity() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let info = onepass_ssh_agent::server::peer_info(&a);
    assert!(info.code.is_some(), "{info:?}");
}

#[test]
fn grant_capped_by_remember_for() {
    let config = AgentConfig {
        remember_for: Duration::from_secs(60),
        ..AgentConfig::default()
    };
    let mut f = fixture_with(
        FakeSource::all(),
        vec![Decision::AllowFor(std::time::Duration::from_secs(300)); 2],
        config,
    );
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    f.env.advance(59);
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 1);
    f.env.advance(2);
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 2);
    let decisions: Vec<String> = f.audit.entries().into_iter().map(|e| e.decision).collect();
    assert_eq!(decisions[..2], ["grant", "remembered"]);
}

#[test]
fn lock_unlock() {
    let mut f = fixture(vec![
        Decision::AllowFor(std::time::Duration::from_secs(300));
        2
    ]);
    let mut conn = ConnState::default();
    let p = peer("/usr/bin/ssh");
    let pass = |s: &str| Zeroizing::new(s.as_bytes().to_vec());

    // A session grant before the lock.
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    // Unlock while unlocked fails.
    assert_eq!(
        f.handle(&mut conn, &p, Request::Unlock(pass("pw")))
            .response,
        Response::Failure
    );
    assert_eq!(
        f.handle(&mut conn, &p, Request::Lock(pass("pw"))).response,
        Response::Success
    );
    assert_eq!(
        f.handle(&mut conn, &p, Request::RequestIdentities).response,
        Response::Identities(vec![])
    );
    assert_eq!(f.sign(KeyType::Ed25519, "/usr/bin/ssh"), Response::Failure);
    assert_eq!(
        f.handle(&mut conn, &p, Request::Lock(pass("other")))
            .response,
        Response::Failure
    );
    assert_eq!(
        f.handle(&mut conn, &p, Request::Unlock(pass("wrong")))
            .response,
        Response::Failure
    );
    assert_eq!(
        f.handle(&mut conn, &p, Request::Unlock(pass("pw")))
            .response,
        Response::Success
    );
    let Response::Identities(ids) = f.handle(&mut conn, &p, Request::RequestIdentities).response
    else {
        panic!("expected identities");
    };
    assert_eq!(ids.len(), TYPES.len());
    // The lock cleared the grant: asked again.
    assert_eq!(f.asked(), 1);
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 2);
}

#[test]
fn session_bind_with_bad_signature_closes() {
    let mut f = fixture(vec![]);
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let impostor = AgentKey::generate(KeyType::Ed25519).unwrap();
    let mut conn = ConnState::default();
    let r = f.handle(
        &mut conn,
        &peer("/usr/bin/ssh"),
        bind_request(&host, &impostor, false),
    );
    assert_eq!(
        r,
        Reply {
            response: Response::Failure,
            close: true
        }
    );
    assert!(conn.bound.is_none());
    let audit = f.audit.entries();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "ssh_sign");
    assert_eq!(audit[0].item_id, None);
    assert_eq!(audit[0].outcome, "bind_bad_signature");

    // Malformed contents close too.
    let r = f.handle(
        &mut conn,
        &peer("/usr/bin/ssh"),
        Request::Extension {
            name: "session-bind@openssh.com".into(),
            contents: vec![0, 0, 0, 9],
        },
    );
    assert!(r.close);
    assert_eq!(r.response, Response::Failure);
}

#[test]
fn session_bind_ok_then_destination_in_prompt() {
    let dir = TempDir::new().unwrap();
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let both = dir.path().join("known_hosts");
    std::fs::write(
        &both,
        known_hosts_line("git.example.test", &host)
            + &known_hosts_line(&hashed_name("git.example.test"), &host),
    )
    .unwrap();
    let hashed_only = dir.path().join("known_hosts_hashed");
    std::fs::write(
        &hashed_only,
        known_hosts_line(&hashed_name("git.example.test"), &host),
    )
    .unwrap();

    for file in [both, hashed_only] {
        let source = FakeSource::all();
        source.edit(KeyType::Ed25519, |k| {
            k.hosts = vec!["git.example.test".into()]
        });
        let config = AgentConfig {
            known_hosts: vec![dir.path().join("missing"), file],
            ..AgentConfig::default()
        };
        let mut f = fixture_with(source, vec![Decision::AllowOnce], config);
        let mut conn = ConnState::default();
        bind(&mut f, &mut conn, &host, false);
        let bound = conn.bound.as_ref().unwrap();
        assert_eq!(bound.host_key, host.public_blob());
        assert!(!bound.forwarded);

        let r = f.handle(
            &mut conn,
            &peer("/usr/bin/ssh"),
            sign_req(KeyType::Ed25519, b"d"),
        );
        assert!(is_signature(&r.response));
        let call = f.last_call();
        let destination = detail(&call, "destination").unwrap();
        assert_eq!(
            destination,
            format!(
                "{} (git.example.test)",
                fingerprint_of_blob(&host.public_blob())
            )
        );
        assert_eq!(detail(&call, "warning"), None);
    }
}

#[test]
fn unbookmarked_destination_refused() {
    let dir = TempDir::new().unwrap();
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let file = dir.path().join("known_hosts");
    std::fs::write(&file, known_hosts_line("evil.example.test", &host)).unwrap();
    let source = FakeSource::all();
    source.edit(KeyType::Ed25519, |k| {
        k.hosts = vec!["git.example.test".into()]
    });
    let config = AgentConfig {
        known_hosts: vec![file],
        ..AgentConfig::default()
    };
    let mut f = fixture_with(source, vec![Decision::AllowOnce; 2], config);
    let mut conn = ConnState::default();
    bind(&mut f, &mut conn, &host, false);
    assert_eq!(
        f.handle(
            &mut conn,
            &peer("/usr/bin/ssh"),
            sign_req(KeyType::Ed25519, b"d")
        )
        .response,
        Response::Failure
    );
    assert_eq!(f.asked(), 0);
    let e = f.audit.entries().pop().unwrap();
    assert_eq!(e.outcome, "host_not_bound");
    assert_eq!(
        e.destination.as_deref(),
        Some(fingerprint_of_blob(&host.public_blob()).as_str())
    );

    // A key without bookmarks gets no warning.
    assert!(is_signature(
        &f.handle(
            &mut conn,
            &peer("/usr/bin/ssh"),
            sign_req(KeyType::EcdsaP256, b"d")
        )
        .response
    ));
    let call = f.last_call();
    assert!(detail(&call, "destination").is_some());
    assert_eq!(detail(&call, "warning"), None);
}

/// Open agent (the app's): a key whose bookmarks the destination does not
/// match is asked about with a warning, not refused.
#[test]
fn open_agent_warns_on_unbookmarked_destination() {
    let dir = TempDir::new().unwrap();
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let file = dir.path().join("known_hosts");
    std::fs::write(&file, known_hosts_line("evil.example.test", &host)).unwrap();
    let source = FakeSource::all();
    source.edit(KeyType::Ed25519, |k| {
        k.hosts = vec!["git.example.test".into()]
    });
    let config = AgentConfig {
        known_hosts: vec![file],
        ..AgentConfig::default()
    };
    let mut f = open_fixture_with(source, vec![Decision::AllowOnce], config);
    let mut conn = ConnState::default();
    bind(&mut f, &mut conn, &host, false);
    assert!(is_signature(
        &f.handle(
            &mut conn,
            &peer("/usr/bin/ssh"),
            sign_req(KeyType::Ed25519, b"d")
        )
        .response
    ));
    let call = f.last_call();
    assert_eq!(
        detail(&call, "destination"),
        Some(fingerprint_of_blob(&host.public_blob()).as_str())
    );
    assert!(detail(&call, "warning").is_some());
}

/// Open agent: any client of this user is asked (nothing is paired), by
/// its executable, unverified; one whose code cannot be read is never
/// remembered.
#[test]
fn open_agent_asks_every_client_and_never_remembers_unidentified_code() {
    let mut f = open_fixture(vec![
        Decision::AllowFor(std::time::Duration::from_secs(300));
        3
    ]);
    let stranger = peer_with("/opt/tool/bin/client", None);
    let r = f.handle(
        &mut ConnState::default(),
        &stranger,
        sign_req(KeyType::Ed25519, b"d"),
    );
    assert!(is_signature(&r.response));
    let call = f.last_call();
    assert_eq!(call.client, "/opt/tool/bin/client");
    assert!(!call.client_verified);
    assert!(!call.remember_allowed);
    assert_eq!(detail(&call, "code"), Some("unidentified"));
    let anonymous = PeerInfo {
        exe: None,
        ..stranger
    };
    let r = f.handle(
        &mut ConnState::default(),
        &anonymous,
        sign_req(KeyType::Ed25519, b"d"),
    );
    assert!(is_signature(&r.response));
    assert_eq!(f.last_call().client, "unknown process");
    assert_eq!(f.asked(), 2);
    // Identified code is remembered.
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert!(is_signature(&f.sign(KeyType::Ed25519, "/usr/bin/ssh")));
    assert_eq!(f.asked(), 3);
    let e = f.audit.entries().pop().unwrap();
    assert_eq!(e.decision, "remembered");
    assert_eq!(e.client_label, None);
}

#[test]
fn forwarded_session_refused_by_default_and_never_remembered_when_allowed() {
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();

    let mut f = fixture(vec![Decision::AllowOnce]);
    let mut conn = ConnState::default();
    bind(&mut f, &mut conn, &host, true);
    assert!(conn.bound.as_ref().unwrap().forwarded);
    let r = f.handle(
        &mut conn,
        &peer("/usr/bin/ssh"),
        sign_req(KeyType::Ed25519, b"d"),
    );
    assert_eq!(r.response, Response::Failure);
    assert_eq!(f.asked(), 0);
    assert_eq!(f.audit.entries()[0].outcome, "refused");

    let config = AgentConfig {
        allow_forwarded: true,
        ..AgentConfig::default()
    };
    let mut f = fixture_with(
        FakeSource::all(),
        vec![Decision::AllowFor(std::time::Duration::from_secs(300)); 2],
        config,
    );
    let mut conn = ConnState::default();
    bind(&mut f, &mut conn, &host, true);
    for n in 1..=2 {
        let r = f.handle(
            &mut conn,
            &peer("/usr/bin/ssh"),
            sign_req(KeyType::Ed25519, b"d"),
        );
        assert!(is_signature(&r.response));
        assert_eq!(f.asked(), n);
        let call = f.last_call();
        assert!(!call.remember_allowed);
        assert_eq!(detail(&call, "forwarded"), Some("yes"));
    }
}

#[test]
fn rebinding_keeps_forwarding_and_refuses_a_direct_connection() {
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let next_hop = AgentKey::generate(KeyType::Ed25519).unwrap();
    let mut f = fixture(vec![]);

    // A forwarded connection stays forwarded after a later non-forwarded
    // bind (the remote's own session-bind).
    let mut conn = ConnState::default();
    bind(&mut f, &mut conn, &host, true);
    bind(&mut f, &mut conn, &next_hop, false);
    let bound = conn.bound.as_ref().unwrap();
    assert!(bound.forwarded);
    assert_eq!(bound.host_key, next_hop.public_blob());

    // A direct connection cannot be bound again.
    let mut conn = ConnState::default();
    bind(&mut f, &mut conn, &host, false);
    let r = f.handle(
        &mut conn,
        &peer("/usr/bin/ssh"),
        bind_request(&next_hop, &next_hop, false),
    );
    assert_eq!(r.response, Response::Failure);
    assert_eq!(conn.bound.as_ref().unwrap().host_key, host.public_blob());
}

#[test]
fn other_uid_is_refused() {
    let mut f = fixture(vec![Decision::AllowOnce]);
    let stranger = PeerInfo {
        uid: Some(own_uid().wrapping_add(1)),
        ..peer("/usr/bin/ssh")
    };
    for req in [Request::RequestIdentities, sign_req(KeyType::Ed25519, b"d")] {
        let r = f.handle(&mut ConnState::default(), &stranger, req);
        assert_eq!(
            r,
            Reply {
                response: Response::Failure,
                close: true
            }
        );
    }
    assert_eq!(f.asked(), 0);
    // An unknown uid is refused like another uid.
    let unknown = PeerInfo {
        uid: None,
        ..peer("/usr/bin/ssh")
    };
    for req in [Request::RequestIdentities, sign_req(KeyType::Ed25519, b"d")] {
        let r = f.handle(&mut ConnState::default(), &unknown, req);
        assert_eq!(
            r,
            Reply {
                response: Response::Failure,
                close: true
            }
        );
    }
    assert_eq!(f.asked(), 0);
}

/// An audit log that cannot be appended to.
struct BrokenAudit;

impl onepass_guard::AuditSink for BrokenAudit {
    fn record(&mut self, _e: &onepass_guard::AuditEntry) -> Result<(), onepass_guard::GuardError> {
        Err(onepass_guard::GuardError::Tampered("test"))
    }
    fn ready(&mut self) -> Result<(), onepass_guard::GuardError> {
        Err(onepass_guard::GuardError::Tampered("test"))
    }
}

#[test]
fn sign_fails_closed_when_the_audit_log_is_unusable() {
    let approver = Arc::new(ScriptedApprover::new(vec![
        Decision::AllowFor(
            std::time::Duration::from_secs(300)
        );
        4
    ]));
    let (guards, _env) = guards(loose_limits());
    let agent = Agent::new(
        FakeSource::all(),
        approver.clone(),
        Box::new(BrokenAudit),
        AgentConfig::default(),
        guards,
    );
    let r = agent.handle(
        &mut ConnState::default(),
        &peer("/usr/bin/ssh"),
        sign_req(KeyType::Ed25519, b"d"),
    );
    assert_eq!(r.response, Response::Failure);
    assert!(approver.calls().is_empty());
    // Listing keys (no secret involved) still works.
    let r = agent.handle(
        &mut ConnState::default(),
        &peer("/usr/bin/ssh"),
        Request::RequestIdentities,
    );
    assert!(matches!(r.response, Response::Identities(_)));
}

#[test]
fn sshsig_namespace_shown() {
    let mut f = fixture(vec![Decision::AllowOnce]);
    let mut w = SshWriter::new();
    w.raw(b"SSHSIG")
        .string(b"git")
        .string(b"")
        .string(b"sha512")
        .string(&[5u8; 64]);
    let data = w.into_vec();
    let r = f.handle(
        &mut ConnState::default(),
        &peer("/usr/bin/ssh-keygen"),
        sign_req(KeyType::Ed25519, &data),
    );
    let Response::Signature(sig) = r.response else {
        panic!("expected a signature");
    };
    verify_signature(&key(KeyType::Ed25519).public_blob(), &data, &sig).unwrap();
    assert_eq!(detail(&f.last_call(), "namespace"), Some("git"));
}

#[test]
fn rsa_sha1_request_fails() {
    let mut f = fixture(vec![Decision::AllowOnce]);
    let r = f.handle(
        &mut ConnState::default(),
        &peer("/usr/bin/ssh"),
        Request::Sign {
            key_blob: key(KeyType::Rsa3072).public_blob(),
            data: b"d".to_vec(),
            flags: 0,
        },
    );
    assert_eq!(r.response, Response::Failure);
    assert_eq!(f.asked(), 0);
}

#[test]
fn other_requests_fail() {
    let mut f = fixture(vec![]);
    let p = peer("/usr/bin/ssh-add");
    for req in [
        Request::Unsupported(17),
        Request::Unsupported(19),
        Request::Extension {
            name: "query".into(),
            contents: vec![],
        },
    ] {
        let r = f.handle(&mut ConnState::default(), &p, req);
        assert_eq!(
            r,
            Reply {
                response: Response::Failure,
                close: false
            }
        );
    }
}
