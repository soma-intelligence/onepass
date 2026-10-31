//! Hardening of the agent (spec 2026-10-26 section 6): paired clients,
//! per-client key lists, host-bound keys with the `git` exception,
//! configurable confirmation, revocable grants, strong authentication,
//! rate limits and prompt coalescing.

mod common;

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::*;
use onepass_guard::testing::ScriptedApprover;
use onepass_guard::{ApprovalRequest, Approver, Decision, Limits, StrongOutcome};
use onepass_peer::{ClientIdentity, CodeIdentity};
use onepass_ssh_agent::keys::{AgentKey, KeyType, fingerprint_of_blob, verify_signature};
use onepass_ssh_agent::wire::{Request, Response, SSH_AGENT_RSA_SHA2_256, SshWriter};
use onepass_ssh_agent::{Agent, AgentConfig, AgentGuards, Confirm, ConnState, PeerInfo, Reply};
use tempfile::TempDir;

struct Fixture {
    agent: Agent<FakeSource>,
    source: FakeSource,
    approver: Arc<ScriptedApprover>,
    audit: SharedAudit,
    env: GuardEnv,
}

fn build(
    source: FakeSource,
    answers: Vec<Decision>,
    config: AgentConfig,
    limits: Limits,
    tweak: impl FnOnce(&mut AgentGuards),
) -> Fixture {
    let approver = Arc::new(ScriptedApprover::new(answers));
    let audit = SharedAudit::default();
    let (mut guards, env) = guards(limits);
    tweak(&mut guards);
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
    build(
        FakeSource::all(),
        answers,
        AgentConfig::default(),
        loose_limits(),
        |_| {},
    )
}

fn sign_req(t: KeyType, data: &[u8]) -> Request {
    Request::Sign {
        key_blob: key(t).public_blob(),
        data: data.to_vec(),
        flags: if t == KeyType::Rsa3072 {
            SSH_AGENT_RSA_SHA2_256
        } else {
            0
        },
    }
}

impl Fixture {
    fn handle(&self, conn: &mut ConnState, p: &PeerInfo, req: Request) -> Reply {
        self.agent.handle(conn, p, req)
    }

    fn sign_as(&self, p: &PeerInfo, t: KeyType) -> Response {
        self.handle(&mut ConnState::default(), p, sign_req(t, b"data"))
            .response
    }

    fn sign(&self, t: KeyType) -> Response {
        self.sign_as(&peer("/usr/bin/ssh"), t)
    }

    fn identities_of(&self, p: &PeerInfo) -> Vec<(Vec<u8>, String)> {
        match self
            .handle(&mut ConnState::default(), p, Request::RequestIdentities)
            .response
        {
            Response::Identities(ids) => ids,
            other => panic!("expected identities, got {other:?}"),
        }
    }

    fn asked(&self) -> usize {
        self.approver.calls().len()
    }

    fn outcomes(&self) -> Vec<String> {
        self.audit.entries().into_iter().map(|e| e.outcome).collect()
    }
}

fn is_signature(r: &Response) -> bool {
    matches!(r, Response::Signature(_))
}

fn team_identity(identifier: &str) -> ClientIdentity {
    ClientIdentity {
        code: CodeIdentity::Team {
            team_id: "TESTTEAM01".into(),
            identifier: identifier.into(),
        },
        pid: 5151,
        exe: Some("/opt/tool".into()),
        chain: Vec::new(),
    }
}

fn unsigned_identity(sha: char) -> ClientIdentity {
    ClientIdentity {
        code: CodeIdentity::Unsigned {
            path: "/home/u/bin/tool".into(),
            sha256: sha.to_string().repeat(64),
        },
        pid: 5152,
        exe: Some("/home/u/bin/tool".into()),
        chain: Vec::new(),
    }
}

fn bind_request(host: &AgentKey, forwarding: bool) -> Request {
    let session_id = [9u8; 32];
    let sig = host.sign(&session_id, 0).unwrap();
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

fn bound_conn(f: &Fixture, host: &AgentKey) -> ConnState {
    let mut conn = ConnState::default();
    let r = f.handle(&mut conn, &peer("/usr/bin/ssh"), bind_request(host, false));
    assert_eq!(r.response, Response::Success);
    conn
}

/// SSHSIG data to sign in `namespace`.
fn sshsig(namespace: &str) -> Vec<u8> {
    let mut w = SshWriter::new();
    w.raw(b"SSHSIG")
        .string(namespace.as_bytes())
        .string(b"")
        .string(b"sha512")
        .string(&[5u8; 64]);
    w.into_vec()
}

/// A `known_hosts` file naming `host` as `names`, and a config reading it.
fn known_hosts(dir: &TempDir, names: &str, host: &AgentKey) -> AgentConfig {
    let path = dir.path().join("known_hosts");
    std::fs::write(&path, format!("{names} {}\n", host.public_openssh(""))).unwrap();
    AgentConfig {
        known_hosts: vec![path],
        ..AgentConfig::default()
    }
}

fn bookmarked_source() -> FakeSource {
    let source = FakeSource::all();
    source.edit(KeyType::Ed25519, |k| {
        k.hosts = vec!["git.example.test".into()]
    });
    source
}

#[test]
fn unpaired_client_sees_no_keys_and_cannot_sign() {
    let f = fixture(vec![Decision::AllowOnce; 4]);
    let stranger = peer_with("/opt/tool", Some(team_identity("com.example.tool")));
    assert!(f.identities_of(&stranger).is_empty());
    assert_eq!(f.sign_as(&stranger, KeyType::Ed25519), Response::Failure);
    // Neither a bind nor a lock is served.
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let mut conn = ConnState::default();
    let r = f.handle(&mut conn, &stranger, bind_request(&host, false));
    assert_eq!(r.response, Response::Failure);
    assert!(conn.bound.is_none());
    let r = f.handle(
        &mut ConnState::default(),
        &stranger,
        Request::Lock(zeroize::Zeroizing::new(b"pw".to_vec())),
    );
    assert_eq!(r.response, Response::Failure);
    assert_eq!(f.asked(), 0);
    let entries = f.audit.entries();
    assert_eq!(entries.len(), 4);
    for e in &entries {
        assert_eq!(e.outcome, "not_paired");
        assert_eq!(e.client_id.as_deref(), Some("team:TESTTEAM01:com.example.tool"));
        assert_eq!(e.client_label, None);
        assert_eq!(e.item_id, None);
    }

    // The refusals keep coming, the log gets at most 6 per minute.
    for _ in 0..10 {
        assert_eq!(f.sign_as(&stranger, KeyType::Ed25519), Response::Failure);
    }
    assert_eq!(f.audit.entries().len(), 6);
    f.env.advance(61);
    assert_eq!(f.sign_as(&stranger, KeyType::Ed25519), Response::Failure);
    assert_eq!(f.audit.entries().len(), 7);

    // Paired later: served (the registry is read at every request).
    f.env.pair(&stranger.identity.as_ref().unwrap().code, None);
    assert_eq!(f.identities_of(&stranger).len(), TYPES.len());
    assert!(is_signature(&f.sign_as(&stranger, KeyType::Ed25519)));
    // Unpaired again: refused at the next request.
    f.env.unpair(&stranger.identity.as_ref().unwrap().code);
    assert!(f.identities_of(&stranger).is_empty());

    // An unidentified peer gets nothing either.
    let anonymous = peer_with("/usr/bin/ssh", None);
    assert!(f.identities_of(&anonymous).is_empty());
    assert_eq!(f.sign_as(&anonymous, KeyType::Ed25519), Response::Failure);

    // A registry that fails verification serves nobody.
    f.env.advance(61);
    f.env
        .registry_broken
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(f.identities_of(&peer("/usr/bin/ssh")).is_empty());
    assert_eq!(f.sign(KeyType::Ed25519), Response::Failure);
    assert_eq!(
        f.outcomes().last().map(String::as_str),
        Some("registry_unusable")
    );
    assert_eq!(f.asked(), 1);
}

#[test]
fn client_key_filter() {
    let f = fixture(vec![Decision::AllowOnce; 2]);
    let ed = key(KeyType::Ed25519).fingerprint();
    f.env
        .pair(&platform_identity("/usr/bin/ssh").code, Some(&[ed.as_str()][..]));
    let ssh = peer("/usr/bin/ssh");
    let ids = f.identities_of(&ssh);
    assert_eq!(
        ids,
        vec![(
            key(KeyType::Ed25519).public_blob(),
            title_of(KeyType::Ed25519)
        )]
    );
    // A key outside the client's list is refused without a prompt.
    assert_eq!(f.sign_as(&ssh, KeyType::EcdsaP256), Response::Failure);
    assert_eq!(f.asked(), 0);
    assert_eq!(f.outcomes(), ["refused"]);
    assert!(is_signature(&f.sign_as(&ssh, KeyType::Ed25519)));
    assert_eq!(f.asked(), 1);
    // Another client paired with every key sees them all.
    assert_eq!(f.identities_of(&peer("/usr/bin/ssh-add")).len(), TYPES.len());
    // An empty list means no key at all.
    f.env.pair(&platform_identity("/usr/bin/ssh").code, Some(&[][..]));
    assert!(f.identities_of(&ssh).is_empty());
    assert_eq!(f.sign_as(&ssh, KeyType::Ed25519), Response::Failure);
    assert_eq!(f.asked(), 1);
}

#[test]
fn key_with_hosts_refused_without_session_bind() {
    let f = build(
        bookmarked_source(),
        vec![Decision::AllowOnce; 2],
        AgentConfig::default(),
        loose_limits(),
        |_| {},
    );
    assert_eq!(f.sign(KeyType::Ed25519), Response::Failure);
    assert_eq!(f.asked(), 0);
    let e = f.audit.entries().pop().unwrap();
    assert_eq!(e.outcome, "host_not_bound");
    assert_eq!(e.item_id, Some(item_id_of(KeyType::Ed25519)));
    assert_eq!(e.destination, None);
    // A key without bookmarks signs anywhere, with approval.
    assert!(is_signature(&f.sign(KeyType::EcdsaP256)));
    assert_eq!(f.asked(), 1);
}

#[test]
fn key_with_hosts_refused_for_other_host() {
    let dir = TempDir::new().unwrap();
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let f = build(
        bookmarked_source(),
        vec![Decision::AllowOnce; 2],
        known_hosts(&dir, "evil.example.test", &host),
        loose_limits(),
        |_| {},
    );
    let mut conn = bound_conn(&f, &host);
    let r = f.handle(
        &mut conn,
        &peer("/usr/bin/ssh"),
        sign_req(KeyType::Ed25519, b"session"),
    );
    assert_eq!(r.response, Response::Failure);
    assert_eq!(f.asked(), 0);
    let e = f.audit.entries().pop().unwrap();
    assert_eq!(e.outcome, "host_not_bound");
    assert_eq!(
        e.destination,
        Some(fingerprint_of_blob(&host.public_blob()))
    );
    // A host key unknown to known_hosts is refused the same way.
    let stranger_host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let mut conn = bound_conn(&f, &stranger_host);
    let r = f.handle(
        &mut conn,
        &peer("/usr/bin/ssh"),
        sign_req(KeyType::Ed25519, b"session"),
    );
    assert_eq!(r.response, Response::Failure);
    assert_eq!(f.asked(), 0);
}

#[test]
fn key_with_hosts_signs_for_bookmarked_host() {
    let dir = TempDir::new().unwrap();
    let host = AgentKey::generate(KeyType::Ed25519).unwrap();
    let f = build(
        bookmarked_source(),
        vec![Decision::AllowOnce; 2],
        known_hosts(&dir, "git.example.test,10.0.0.7", &host),
        loose_limits(),
        |_| {},
    );
    let mut conn = bound_conn(&f, &host);
    let r = f.handle(
        &mut conn,
        &peer("/usr/bin/ssh"),
        sign_req(KeyType::Ed25519, b"session"),
    );
    let Response::Signature(sig) = r.response else {
        panic!("expected a signature, got {:?}", r.response);
    };
    verify_signature(&key(KeyType::Ed25519).public_blob(), b"session", &sig).unwrap();
    let e = f.audit.entries().pop().unwrap();
    assert_eq!(e.outcome, "ok");
    assert_eq!(
        e.destination,
        Some(format!(
            "{} (git.example.test)",
            fingerprint_of_blob(&host.public_blob())
        ))
    );
    assert_eq!(e.namespace, None);
}

#[test]
fn git_namespace_allowed_only_with_git_signing() {
    let f = build(
        bookmarked_source(),
        vec![Decision::AllowOnce; 3],
        AgentConfig::default(),
        loose_limits(),
        |_| {},
    );
    let keygen = peer("/usr/bin/ssh-keygen");
    let git = sshsig("git");
    let sign = |data: &[u8]| {
        f.handle(
            &mut ConnState::default(),
            &keygen,
            sign_req(KeyType::Ed25519, data),
        )
        .response
    };
    // Without git_signing: an unbound git signature is refused.
    assert_eq!(sign(&git), Response::Failure);
    assert_eq!(f.asked(), 0);
    assert_eq!(f.outcomes(), ["host_not_bound"]);

    f.source.edit(KeyType::Ed25519, |k| k.git_signing = true);
    let r = sign(&git);
    let Response::Signature(sig) = r else {
        panic!("expected a signature, got {r:?}");
    };
    verify_signature(&key(KeyType::Ed25519).public_blob(), &git, &sig).unwrap();
    assert_eq!(f.asked(), 1);
    let e = f.audit.entries().pop().unwrap();
    assert_eq!(e.outcome, "ok");
    assert_eq!(e.namespace.as_deref(), Some("git"));
    // Another namespace or plain data is still bound to the hosts.
    assert_eq!(sign(&sshsig("file")), Response::Failure);
    assert_eq!(sign(b"git"), Response::Failure);
    assert_eq!(f.asked(), 1);
    assert_eq!(
        f.outcomes(),
        ["host_not_bound", "ok", "host_not_bound", "host_not_bound"]
    );
}

#[test]
fn confirm_always_never_grants() {
    let config = AgentConfig {
        confirm: Confirm::Always,
        ..AgentConfig::default()
    };
    let f = build(
        FakeSource::all(),
        vec![Decision::AllowFor(Duration::from_secs(300)); 3],
        config,
        loose_limits(),
        |_| {},
    );
    for n in 1..=3 {
        assert!(is_signature(&f.sign(KeyType::Ed25519)));
        assert_eq!(f.asked(), n);
        assert!(!f.approver.calls().pop().unwrap().remember_allowed);
    }
    assert!(f.audit.entries().iter().all(|e| e.decision == "once"));
    assert!(!f.env.grants_path().exists(), "no grant may be written");

    // An item's confirm_each_use forces it under the session mode too.
    let f = fixture(vec![Decision::AllowFor(Duration::from_secs(300)); 2]);
    f.source
        .edit(KeyType::Ed25519, |k| k.confirm_each_use = true);
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    assert_eq!(f.asked(), 2);
    assert!(!f.env.grants_path().exists());
}

#[test]
fn expired_grant_prompts_again() {
    let f = fixture(vec![Decision::AllowFor(Duration::from_secs(300)); 3]);
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    // The grants file holds a digest, not the key or the client.
    let file = std::fs::read_to_string(f.env.grants_path()).unwrap();
    assert!(!file.contains(&key(KeyType::Ed25519).fingerprint()));
    f.env.advance(299);
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    assert_eq!(f.asked(), 1);
    f.env.advance(2);
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    assert_eq!(f.asked(), 2);
    let decisions: Vec<(String, String)> = f
        .audit
        .entries()
        .into_iter()
        .map(|e| (e.decision, e.outcome))
        .collect();
    let d = |a: &str, b: &str| (a.to_owned(), b.to_owned());
    assert_eq!(
        decisions,
        [
            d("grant_5m", "ok"),
            d("remembered", "ok"),
            d("policy", "grant_expired"),
            d("grant_5m", "ok"),
        ]
    );
    // A grant of one client does not cover another.
    assert!(is_signature(&f.sign_as(&peer("/usr/bin/git"), KeyType::Ed25519)));
    assert_eq!(f.asked(), 3);
}

#[test]
fn strong_mode_requires_strong_auth() {
    let config = AgentConfig {
        strong: true,
        ..AgentConfig::default()
    };
    let f = build(
        FakeSource::all(),
        vec![Decision::AllowFor(Duration::from_secs(300)); 10],
        config,
        Limits::ssh(),
        |_| {},
    );
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    assert_eq!((f.asked(), f.env.strong.calls()), (1, 1));
    // A grant spares the prompt, never strong authentication.
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    assert_eq!((f.asked(), f.env.strong.calls()), (1, 2));
    let reason = f.env.strong.reasons.lock().unwrap()[0].clone();
    assert!(reason.contains("Test platform:com.apple.ssh"), "{reason}");
    assert!(reason.contains(&title_of(KeyType::Ed25519)), "{reason}");

    // Unavailable refuses without counting as a denial.
    f.env.strong.set(StrongOutcome::Unavailable);
    for _ in 0..4 {
        assert_eq!(f.sign(KeyType::Ed25519), Response::Failure);
    }
    assert_eq!(
        f.outcomes().last().map(String::as_str),
        Some("strong_auth_failed")
    );
    // Denied counts: after three, the client cools down without a prompt
    // nor a strong authentication.
    f.env.strong.set(StrongOutcome::Denied);
    for _ in 0..3 {
        assert_eq!(f.sign(KeyType::EcdsaP256), Response::Failure);
    }
    let (asked, strong) = (f.asked(), f.env.strong.calls());
    assert_eq!(f.sign(KeyType::Ed25519), Response::Failure);
    assert_eq!((f.asked(), f.env.strong.calls()), (asked, strong));
    assert_eq!(
        f.outcomes().last().map(String::as_str),
        Some("client_cooling_down")
    );
    // Other clients are not affected.
    f.env.strong.set(StrongOutcome::Verified);
    assert!(is_signature(&f.sign_as(&peer("/usr/bin/git"), KeyType::Ed25519)));
}

#[test]
fn signature_rate_limit() {
    let f = build(
        FakeSource::all(),
        vec![Decision::AllowFor(Duration::from_secs(3600)); 1]
            .into_iter()
            .chain(vec![Decision::AllowOnce; 20])
            .collect(),
        AgentConfig::default(),
        Limits::ssh(),
        |_| {},
    );
    for _ in 0..60 {
        assert!(is_signature(&f.sign(KeyType::Ed25519)));
    }
    assert_eq!(f.asked(), 1);
    assert_eq!(f.sign(KeyType::Ed25519), Response::Failure);
    assert_eq!(
        f.outcomes().last().map(String::as_str),
        Some("rate_limited")
    );
    f.env.advance(60);
    assert!(is_signature(&f.sign(KeyType::Ed25519)));

    // Prompts: 6 a minute, the 7th is refused without a prompt.
    let g = peer("/usr/bin/git");
    for _ in 0..6 {
        assert!(is_signature(&f.sign_as(&g, KeyType::EcdsaP256)));
    }
    assert_eq!(f.asked(), 7);
    assert_eq!(f.sign_as(&g, KeyType::EcdsaP256), Response::Failure);
    assert_eq!(f.asked(), 7);
    assert_eq!(
        f.outcomes().last().map(String::as_str),
        Some("rate_limited")
    );
}

#[test]
fn three_denials_cool_the_client_down() {
    let f = build(
        FakeSource::all(),
        vec![Decision::Deny; 3]
            .into_iter()
            .chain([Decision::AllowOnce])
            .collect(),
        AgentConfig::default(),
        Limits::ssh(),
        |_| {},
    );
    for _ in 0..3 {
        assert_eq!(f.sign(KeyType::Ed25519), Response::Failure);
    }
    assert_eq!(f.sign(KeyType::Ed25519), Response::Failure);
    assert_eq!(f.asked(), 3);
    assert_eq!(
        f.outcomes().last().map(String::as_str),
        Some("client_cooling_down")
    );
    f.env.advance(600);
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
}

#[test]
fn replaced_unsigned_client_refused() {
    let f = fixture(vec![Decision::AllowOnce; 2]);
    let original = unsigned_identity('a');
    f.env.pair(&original.code, None);
    let paired = peer_with("/home/u/bin/tool", Some(original));
    assert!(is_signature(&f.sign_as(&paired, KeyType::Ed25519)));
    // The same path running other code (rebuilt, or replaced) is another
    // client: refused without a prompt.
    let replaced = peer_with("/home/u/bin/tool", Some(unsigned_identity('b')));
    assert!(f.identities_of(&replaced).is_empty());
    assert_eq!(f.sign_as(&replaced, KeyType::Ed25519), Response::Failure);
    assert_eq!(f.asked(), 1);
    let e = f.audit.entries().pop().unwrap();
    assert_eq!(e.outcome, "not_paired");
    assert_eq!(e.client_id, Some(format!("unsigned:{}", "b".repeat(64))));
    // Unsigned code is shown as unverified.
    assert!(!f.approver.calls()[0].client_verified);
}

#[test]
fn prompt_names_the_verified_client() {
    let f = fixture(vec![Decision::AllowOnce; 2]);
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    let call = f.approver.calls().pop().unwrap();
    assert!(call.client_verified);
    assert_eq!(call.client, "Test platform:com.apple.ssh");
    let adhoc = ClientIdentity {
        code: CodeIdentity::AdHoc {
            path: "/Users/u/bin/tool".into(),
            cdhash: "cd".repeat(20),
            hardened: false,
        },
        pid: 7,
        exe: Some("/Users/u/bin/tool".into()),
        chain: Vec::new(),
    };
    f.env.pair(&adhoc.code, None);
    assert!(is_signature(&f.sign_as(
        &peer_with("/Users/u/bin/tool", Some(adhoc)),
        KeyType::Ed25519
    )));
    let call = f.approver.calls().pop().unwrap();
    assert!(!call.client_verified);
    let detail = |l: &str| {
        call.details
            .iter()
            .find(|(k, _)| k == l)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(detail("client id"), Some(format!("adhoc:{}", "cd".repeat(20))));
    assert_eq!(detail("hardened runtime"), Some("no".into()));
}

#[test]
fn lost_control_channel_refuses_everything() {
    let f = build(
        FakeSource::all(),
        vec![Decision::AllowOnce],
        AgentConfig::default(),
        loose_limits(),
        |g| g.liveness = Some(Arc::new(|| false)),
    );
    for req in [Request::RequestIdentities, sign_req(KeyType::Ed25519, b"d")] {
        let r = f.handle(&mut ConnState::default(), &peer("/usr/bin/ssh"), req);
        assert_eq!(
            r,
            Reply {
                response: Response::Failure,
                close: true
            }
        );
    }
    assert_eq!(f.asked(), 0);
    assert!(!f.agent.control_alive());
}

/// Holds the first prompt until released, then answers `Deny`.
struct HeldApprover {
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
    calls: Mutex<Vec<ApprovalRequest>>,
}

impl Approver for HeldApprover {
    fn approve(&self, req: &ApprovalRequest) -> Decision {
        self.calls.lock().unwrap().push(req.clone());
        if let Some(tx) = self.entered.lock().unwrap().take() {
            tx.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
        }
        Decision::Deny
    }
}

#[test]
fn identical_requests_share_one_prompt() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let approver = Arc::new(HeldApprover {
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(release_rx),
        calls: Mutex::new(Vec::new()),
    });
    let audit = SharedAudit::default();
    let (guards, _env) = guards(loose_limits());
    let agent = Arc::new(Agent::new(
        FakeSource::all(),
        approver.clone(),
        Box::new(audit.clone()),
        AgentConfig::default(),
        guards,
    ));
    let spawn = |agent: Arc<Agent<FakeSource>>| {
        thread::spawn(move || {
            agent
                .handle(
                    &mut ConnState::default(),
                    &peer("/usr/bin/ssh"),
                    sign_req(KeyType::Ed25519, b"d"),
                )
                .response
        })
    };
    let first = spawn(agent.clone());
    entered_rx.recv().unwrap();
    // The prompt is shown and the agent is not blocked behind it.
    let ids = agent
        .handle(
            &mut ConnState::default(),
            &peer("/usr/bin/ssh-add"),
            Request::RequestIdentities,
        )
        .response;
    assert!(matches!(ids, Response::Identities(v) if v.len() == TYPES.len()));
    let second = spawn(agent.clone());
    let fp = key(KeyType::Ed25519).fingerprint();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while agent.waiting_for_prompt("platform:com.apple.ssh", &fp) == 0 {
        assert!(std::time::Instant::now() < deadline, "never waited");
        thread::sleep(Duration::from_millis(10));
    }
    release_tx.send(()).unwrap();
    assert_eq!(first.join().unwrap(), Response::Failure);
    assert_eq!(second.join().unwrap(), Response::Failure);
    assert_eq!(approver.calls.lock().unwrap().len(), 1);
    let mut decisions: Vec<String> = audit.entries().into_iter().map(|e| e.decision).collect();
    decisions.sort();
    assert_eq!(decisions, ["denied", "joined"]);
}

#[test]
fn lock_drops_grants() {
    let f = fixture(vec![Decision::AllowFor(Duration::from_secs(300)); 2]);
    let ssh = peer("/usr/bin/ssh");
    let pass = || zeroize::Zeroizing::new(b"pw".to_vec());
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    let mut conn = ConnState::default();
    assert_eq!(
        f.handle(&mut conn, &ssh, Request::Lock(pass())).response,
        Response::Success
    );
    assert_eq!(
        f.handle(&mut conn, &ssh, Request::Unlock(pass())).response,
        Response::Success
    );
    f.env.advance(1);
    assert!(is_signature(&f.sign(KeyType::Ed25519)));
    assert_eq!(f.asked(), 2);
}
