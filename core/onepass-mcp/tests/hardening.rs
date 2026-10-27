//! Hardening (spec 2026-10-26 sections 3.3, 4 and 7): paired clients,
//! client scopes, revocable grants, strong authentication, rate limits and
//! the approval fatigue guard.

mod common;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use onepass_core::Id;
use onepass_core::model::Item;
use onepass_core::reference::SecretRef;
use onepass_core::repo::Repository;
use onepass_core::store::MemoryStore;
use onepass_guard::testing::{FakeClock, ScriptedApprover};
use onepass_guard::{
    AuditEntry, Decision, GrantRequest, GrantStore, Limits, Revoke, StrongAuth, StrongOutcome,
    Surface,
};
use onepass_mcp::tools::McpTools;
use onepass_mcp::{
    ClientContext, ClientInfo, ClientScopes, McpGuards, Narrowing, Policy, PortError, RepoPort,
    Scope, ToolHost, ToolOutcome, VaultInfo, VaultPort,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Start of the fake wall clock.
const T0: i64 = 1_800_000_000;

/// A port over the shared fixture repository that counts the values read,
/// so two servers (two clients) can serve the same vaults.
#[derive(Clone)]
struct SharedPort {
    inner: Rc<RefCell<RepoPort<'static, MemoryStore>>>,
    resolved: Rc<RefCell<usize>>,
}

impl VaultPort for SharedPort {
    fn vaults(&mut self) -> Result<Vec<VaultInfo>, PortError> {
        self.inner.borrow_mut().vaults()
    }
    fn items(&mut self, vault_id: Id) -> Result<Vec<Item>, PortError> {
        self.inner.borrow_mut().items(vault_id)
    }
    fn resolve(&mut self, r: &SecretRef) -> Result<Zeroizing<String>, PortError> {
        *self.resolved.borrow_mut() += 1;
        self.inner.borrow_mut().resolve(r)
    }
    fn save_item(&mut self, vault_id: Id, item: Item) -> Result<(), PortError> {
        self.inner.borrow_mut().save_item(vault_id, item)
    }
}

/// Strong authentication with a fixed answer that records each reason.
struct Strong {
    outcome: StrongOutcome,
    reasons: Mutex<Vec<String>>,
}

impl Strong {
    fn new(outcome: StrongOutcome) -> Arc<Self> {
        Arc::new(Strong {
            outcome,
            reasons: Mutex::new(Vec::new()),
        })
    }
    fn reasons(&self) -> Vec<String> {
        self.reasons.lock().unwrap().clone()
    }
}

impl StrongAuth for Strong {
    fn verify(&self, reason: &str) -> StrongOutcome {
        self.reasons.lock().unwrap().push(reason.to_owned());
        self.outcome
    }
}

type HTools = McpTools<SharedPort>;

/// One server and everything a test drives around it.
struct H {
    tools: HTools,
    audit: SharedAudit,
    approver: Arc<ScriptedApprover>,
    strong: Arc<Strong>,
    clock: Arc<FakeClock>,
    grants: Arc<Mutex<GrantStore>>,
    port: SharedPort,
    data: Rc<DataDir>,
}

type Repo = Repository<MemoryStore>;
type PolicyFn = Box<dyn FnOnce(&Repo) -> Policy>;
type ScopesFn = Box<dyn FnOnce(&Repo) -> ClientScopes>;

struct Setup {
    policy: PolicyFn,
    /// `None`: the client is not paired.
    scopes: Option<ScopesFn>,
    answers: Vec<Decision>,
    strong: StrongOutcome,
    limits: Limits,
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            policy: Box::new(|_| Policy::default_for(&account_id())),
            scopes: Some(Box::new(all_scopes)),
            answers: Vec::new(),
            strong: StrongOutcome::Verified,
            limits: loose_limits(),
        }
    }
}

/// Every scope on every vault, in the policy.
fn open_policy(repo: &Repository<MemoryStore>) -> Policy {
    let mut p = Policy::default_for(&account_id());
    for v in repo.vaults().unwrap() {
        p.vaults
            .insert(v.id.to_string(), Scope::ALL.into_iter().collect());
    }
    p
}

fn build(s: Setup) -> H {
    let repo = repo();
    let policy = (s.policy)(repo);
    let data = Rc::new(DataDir::new());
    let c = client(CLIENT_ID);
    if let Some(scopes) = s.scopes {
        data.pair(&c, &scopes(repo), T0 - 100);
    }
    let port = SharedPort {
        inner: Rc::new(RefCell::new(RepoPort(repo))),
        resolved: Rc::new(RefCell::new(0)),
    };
    let clock = Arc::new(FakeClock::new(T0));
    let strong = Strong::new(s.strong);
    let approver = Arc::new(ScriptedApprover::new(s.answers));
    let (tools, audit, grants) = server(
        &data,
        port.clone(),
        policy,
        c,
        approver.clone(),
        strong.clone(),
        clock.clone(),
        s.limits,
    );
    H {
        tools,
        audit,
        approver,
        strong,
        clock,
        grants,
        port,
        data,
    }
}

/// A server over `port` for client `c`, with its audit sink and grants.
#[allow(clippy::too_many_arguments)]
fn server(
    data: &DataDir,
    port: SharedPort,
    policy: Policy,
    c: ClientContext,
    approver: Arc<ScriptedApprover>,
    strong: Arc<Strong>,
    clock: Arc<FakeClock>,
    limits: Limits,
) -> (HTools, SharedAudit, Arc<Mutex<GrantStore>>) {
    let guards: McpGuards = guards_in(data, c, strong, clock, limits);
    let grants = guards.grants.clone();
    let audit = SharedAudit::default();
    let tools = McpTools::new(
        port,
        policy,
        Narrowing::default(),
        approver,
        Box::new(audit.clone()),
        None,
        guards,
    );
    (tools, audit, grants)
}

fn hcall(t: &mut HTools, name: &str, args: Value) -> ToolOutcome {
    let info = ClientInfo {
        name: "declared-name".into(),
        version: "1".into(),
    };
    t.call(&info, name, args.as_object().unwrap())
}

fn vid(h: &H, name: &str) -> Id {
    vault(h.port.inner.borrow().0, name).id
}

fn names(scopes: &[Scope]) -> BTreeSet<Scope> {
    scopes.iter().copied().collect()
}

fn outcomes(audit: &SharedAudit) -> Vec<String> {
    audit.entries().into_iter().map(|e| e.outcome).collect()
}

fn decisions(audit: &SharedAudit) -> Vec<String> {
    audit.entries().into_iter().map(|e| e.decision).collect()
}

fn run_args(cmd: &[&str]) -> Value {
    json!({"command": cmd, "env": {"T": "onepass://Dev/GitHub/password"}})
}

fn witness(mark: &Path) -> Value {
    json!(["/usr/bin/touch", mark.to_str().unwrap()])
}

const NOT_PAIRED: &str = "client not paired: run onepass clients pair --surface mcp";

#[test]
fn unpaired_client_is_refused_everywhere() {
    let mut h = build(Setup {
        policy: Box::new(open_policy),
        scopes: None,
        answers: vec![Decision::AllowOnce; 10],
        ..Setup::default()
    });
    let tmp = tempfile::tempdir().unwrap();
    let mark = tmp.path().join("ran");
    let tpl = tmp.path().join("t.tpl");
    std::fs::write(&tpl, "x={{ onepass://Dev/GitHub/password }}").unwrap();
    let out = tmp.path().join("out");
    let calls = [
        ("list_vaults", json!({})),
        ("list_items", json!({})),
        ("search_items", json!({"query": "git"})),
        ("get_item", json!({"item": "GitHub"})),
        (
            "run_with_secrets",
            json!({"command": witness(&mark), "env": {"T": "onepass://Dev/GitHub/password"}}),
        ),
        (
            "fill_template",
            json!({"template_path": tpl.to_str().unwrap(), "output_path": out.to_str().unwrap()}),
        ),
        (
            "create_login",
            json!({"vault": "Dev", "title": "New", "username": "u"}),
        ),
        ("generate_password", json!({})),
        (
            "totp_code",
            json!({"reference": "onepass://Dev/GitHub/totp"}),
        ),
        (
            "reveal_secret",
            json!({"reference": "onepass://Dev/GitHub/password"}),
        ),
    ];
    for (tool, args) in calls {
        let m = refused(hcall(&mut h.tools, tool, args));
        assert_eq!(m, NOT_PAIRED, "{tool}");
    }
    assert!(h.approver.calls().is_empty());
    assert!(h.strong.reasons().is_empty());
    assert_eq!(*h.port.resolved.borrow(), 0);
    assert!(!mark.exists());
    assert!(!out.exists());
    // At most 6 refusals before pairing are audited per minute.
    let e = h.audit.entries();
    assert_eq!(e.len(), 6);
    for entry in &e {
        assert_eq!(entry.outcome, "not_paired");
        assert_eq!(entry.client_id.as_deref(), Some(CLIENT_ID));
        assert_eq!(entry.client_label.as_deref(), Some(CLIENT_LABEL));
        assert_eq!(entry.client, "declared-name");
    }

    h.clock.advance(Duration::from_secs(61));
    refused(hcall(&mut h.tools, "list_vaults", json!({})));
    assert_eq!(h.audit.entries().len(), 7);

    // Paired for another client id only: still refused.
    h.data
        .pair(&client("team:OTHER:x"), &ClientScopes::new(), T0);
    assert_eq!(
        refused(hcall(&mut h.tools, "list_vaults", json!({}))),
        NOT_PAIRED
    );
    // Arguments are still checked first.
    invalid(hcall(&mut h.tools, "get_item", json!({})));
}

#[test]
fn client_scopes_restrict_policy() {
    let mut h = build(Setup {
        policy: Box::new(open_policy),
        scopes: Some(Box::new(|repo| {
            ClientScopes::from([(
                vault(repo, "Dev").id.to_string(),
                names(&[Scope::Metadata, Scope::Use]),
            )])
        })),
        answers: vec![Decision::AllowOnce],
        ..Setup::default()
    });
    let v = ok(hcall(&mut h.tools, "list_vaults", json!({})));
    let list = v["untrusted_vault_data"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{v}");
    assert_eq!(list[0]["name"], "Dev");
    assert_eq!(list[0]["scopes"], json!(["metadata", "use"]));

    add_mail_h(&h);
    for (tool, scope, reference) in [
        ("reveal_secret", "reveal", "onepass://Dev/GitHub/password"),
        ("totp_code", "totp", "onepass://Dev/Mail/totp"),
    ] {
        let m = refused(hcall(&mut h.tools, tool, json!({"reference": reference})));
        assert_eq!(m, format!("scope '{scope}' not granted for this vault"));
    }
    let m = refused(hcall(
        &mut h.tools,
        "create_login",
        json!({"vault": "Dev", "title": "x", "username": "u"}),
    ));
    assert_eq!(m, "scope 'write' not granted for this vault");
    assert!(h.approver.calls().is_empty());
    assert!(h.strong.reasons().is_empty());
    assert_eq!(*h.port.resolved.borrow(), 0);

    // `use` is in both: allowed after the prompt.
    let v = ok(hcall(&mut h.tools, "run_with_secrets", run_args(&["true"])));
    assert_eq!(v["exit_code"], 0);
    assert_eq!(h.approver.calls().len(), 1);

    // The policy stays the ceiling: a client scope the policy refuses is
    // not granted.
    let mut h = build(Setup {
        scopes: Some(Box::new(all_scopes)),
        ..Setup::default()
    });
    let m = refused(hcall(
        &mut h.tools,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    assert_eq!(m, "scope 'reveal' not granted for this vault");
}

#[test]
fn vault_outside_client_scopes_reads_like_not_found() {
    let mut h = build(Setup {
        policy: Box::new(open_policy),
        scopes: Some(Box::new(|repo| {
            ClientScopes::from([(vault(repo, "Dev").id.to_string(), Scope::ALL.into())])
        })),
        answers: vec![Decision::AllowOnce; 4],
        ..Setup::default()
    });
    let shared = vid(&h, "Shared");
    {
        let repo = &mut *h.port.inner.borrow_mut().0;
        let v = vault(repo, "Shared");
        repo.save_item(&v, note(shared, "SharedNote")).unwrap();
    }
    let v = ok(hcall(&mut h.tools, "list_vaults", json!({})));
    assert!(!v.to_string().contains("Shared"), "{v}");
    let items = ok(hcall(
        &mut h.tools,
        "search_items",
        json!({"query": "note"}),
    ));
    assert!(!items.to_string().contains("SharedNote"), "{items}");

    let hidden = [
        ("list_items", json!({"vault": "Shared"})),
        ("get_item", json!({"vault": "Shared", "item": "SharedNote"})),
        (
            "get_item",
            json!({"vault": shared.to_string(), "item": "SharedNote"}),
        ),
        (
            "reveal_secret",
            json!({"reference": "onepass://Shared/SharedNote/content"}),
        ),
        (
            "run_with_secrets",
            json!({"command": ["true"], "env": {"X": "onepass://Shared/SharedNote/content"}}),
        ),
    ];
    for (tool, args) in hidden {
        assert_eq!(
            refused(hcall(&mut h.tools, tool, args)),
            "not found",
            "{tool}"
        );
    }
    // Exactly like a vault that does not exist.
    assert_eq!(
        refused(hcall(
            &mut h.tools,
            "list_items",
            json!({"vault": "Nowhere"})
        )),
        "not found"
    );
    let m = refused(hcall(
        &mut h.tools,
        "get_item",
        json!({"item": "SharedNote"}),
    ));
    assert_eq!(m, "not found");
    assert!(h.approver.calls().is_empty());
    assert_eq!(*h.port.resolved.borrow(), 0);
}

#[test]
fn grant_survives_across_tool_calls_until_expiry() {
    let mut h = build(Setup {
        answers: vec![Decision::AllowFor(Duration::from_secs(300))],
        ..Setup::default()
    });
    let args = run_args(&["/bin/echo", "hi"]);
    ok(hcall(&mut h.tools, "run_with_secrets", args.clone()));
    // Other calls in between do not touch the grant.
    ok(hcall(&mut h.tools, "list_items", json!({})));
    h.clock.advance(Duration::from_secs(299));
    ok(hcall(&mut h.tools, "run_with_secrets", args.clone()));
    assert_eq!(h.approver.calls().len(), 1);
    assert_eq!(decisions(&h.audit), ["grant_5m", "policy", "remembered"]);

    // The grant is in the signed file, bound to the client and the vault.
    let g = h.grants.lock().unwrap().list(&signer(), &*h.clock).unwrap();
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].client_id, CLIENT_ID);
    assert_eq!(g[0].surface, Surface::Mcp);
    assert_eq!(g[0].action, "run_with_secrets");
    assert_eq!(g[0].vault_id, Some(vid(&h, "Dev").to_string()));
    assert_eq!(g[0].expires_at - g[0].created_at, 300);
    // No request data on disk: the key is a digest.
    assert!(!g[0].key.contains("echo"), "{}", g[0].key);
    let text = std::fs::read_to_string(h.data.grants()).unwrap();
    assert!(!text.contains("echo") && !text.contains("onepass://"));

    // Past the end: asked again (the scripted approver denies now).
    h.clock.advance(Duration::from_secs(2));
    let m = refused(hcall(&mut h.tools, "run_with_secrets", args));
    assert_eq!(m, "denied by the user");
    assert_eq!(h.approver.calls().len(), 2);

    // A grant asked longer than 60 minutes is clamped.
    let mut h = build(Setup {
        answers: vec![Decision::AllowFor(Duration::from_secs(5 * 3600))],
        ..Setup::default()
    });
    ok(hcall(&mut h.tools, "run_with_secrets", run_args(&["true"])));
    let g = h.grants.lock().unwrap().list(&signer(), &*h.clock).unwrap();
    assert_eq!(g[0].expires_at - g[0].created_at, 3600);
    assert_eq!(decisions(&h.audit), ["grant_60m"]);
}

#[test]
fn expired_grant_replay_prompts_again() {
    let mut h = build(Setup {
        answers: vec![
            Decision::AllowFor(Duration::from_secs(300)),
            Decision::AllowOnce,
            Decision::AllowOnce,
        ],
        ..Setup::default()
    });
    let args = run_args(&["true"]);
    ok(hcall(&mut h.tools, "run_with_secrets", args.clone()));
    h.clock.advance(Duration::from_secs(301));
    ok(hcall(&mut h.tools, "run_with_secrets", args.clone()));
    assert_eq!(h.approver.calls().len(), 2);
    assert_eq!(
        outcomes(&h.audit),
        ["ok", "grant_expired", "ok"],
        "{:?}",
        h.audit.entries()
    );

    // Rolling the wall clock back does not revive it (monotonic deadline).
    h.clock.set_now_unix(T0 + 10);
    ok(hcall(&mut h.tools, "run_with_secrets", args));
    assert_eq!(h.approver.calls().len(), 3);
    assert_eq!(outcomes(&h.audit)[3], "grant_expired");
}

#[test]
fn revoked_grant_prompts_again() {
    let mut h = build(Setup {
        answers: vec![
            Decision::AllowFor(Duration::from_secs(900)),
            Decision::AllowOnce,
            Decision::AllowOnce,
        ],
        ..Setup::default()
    });
    let args = run_args(&["true"]);
    ok(hcall(&mut h.tools, "run_with_secrets", args.clone()));
    let before = std::fs::read(h.data.grants()).unwrap();

    // `onepass grants revoke --all` from another process.
    let mut other = GrantStore::open(h.data.grants(), &account_id());
    let out = other.revoke(&signer(), &*h.clock, Revoke::All).unwrap();
    assert_eq!(out.newly, 1);
    ok(hcall(&mut h.tools, "run_with_secrets", args.clone()));
    assert_eq!(h.approver.calls().len(), 2);
    assert_eq!(outcomes(&h.audit), ["ok", "grant_revoked", "ok"]);

    // The control channel pushes the revocation; the pre-revocation file
    // restored afterwards brings nothing back.
    h.grants.lock().unwrap().apply_revocations(
        &*h.clock,
        out.generation,
        &out.revoked,
        &[out.selector],
    );
    std::fs::write(h.data.grants(), before).unwrap();
    ok(hcall(&mut h.tools, "run_with_secrets", args));
    assert_eq!(h.approver.calls().len(), 3);
    assert!(!decisions(&h.audit).contains(&"remembered".to_owned()));
}

#[test]
fn grant_from_other_client_not_used() {
    let mut h = build(Setup {
        answers: vec![Decision::AllowFor(Duration::from_secs(300))],
        ..Setup::default()
    });
    let args = run_args(&["true"]);
    ok(hcall(&mut h.tools, "run_with_secrets", args.clone()));

    // A second client, paired with the same scopes, on the same vaults.
    let b = client("team:OTHERTEAM:com.example.other");
    let scopes = all_scopes(h.port.inner.borrow().0);
    h.data.pair(&b, &scopes, T0 - 50);
    let b_approver = Arc::new(ScriptedApprover::new(vec![Decision::AllowOnce]));
    let (mut tb, b_audit, _) = server(
        &h.data,
        h.port.clone(),
        Policy::default_for(&account_id()),
        b.clone(),
        b_approver.clone(),
        h.strong.clone(),
        h.clock.clone(),
        loose_limits(),
    );
    ok(hcall(&mut tb, "run_with_secrets", args.clone()));
    assert_eq!(b_approver.calls().len(), 1, "B is asked");
    assert_eq!(decisions(&b_audit), ["once"]);
    assert_eq!(
        b_audit.entries()[0].client_id.as_deref(),
        Some(b.client_id.as_str())
    );

    // A's grant copied to B (same key, B's id) is not B's request either:
    // the key is bound to the client.
    let a_grant = h
        .grants
        .lock()
        .unwrap()
        .list(&signer(), &*h.clock)
        .unwrap()
        .remove(0);
    GrantStore::open(h.data.grants(), &account_id())
        .add(
            &signer(),
            &*h.clock,
            GrantRequest {
                client_id: b.client_id.clone(),
                surface: Surface::Mcp,
                action: a_grant.action.clone(),
                key: a_grant.key.clone(),
                vault_id: a_grant.vault_id.clone(),
            },
            Duration::from_secs(300),
        )
        .unwrap();
    let m = refused(hcall(&mut tb, "run_with_secrets", args.clone()));
    assert_eq!(m, "denied by the user");
    assert_eq!(b_approver.calls().len(), 2);
    // A keeps its own grant.
    ok(hcall(&mut h.tools, "run_with_secrets", args));
    assert_eq!(h.approver.calls().len(), 1);
}

#[test]
fn reveal_requires_strong_auth() {
    for denied in [StrongOutcome::Denied, StrongOutcome::Unavailable] {
        let mut h = build(Setup {
            policy: Box::new(open_policy),
            answers: vec![Decision::AllowOnce; 2],
            strong: denied,
            ..Setup::default()
        });
        add_mail_h(&h);
        for (tool, reference) in [
            ("reveal_secret", "onepass://Dev/GitHub/password"),
            ("totp_code", "onepass://Dev/Mail/totp"),
        ] {
            let out = hcall(&mut h.tools, tool, json!({"reference": reference}));
            assert_eq!(refused(out), "strong authentication failed", "{tool}");
        }
        assert_eq!(*h.port.resolved.borrow(), 0, "no value read");
        assert_eq!(h.approver.calls().len(), 2, "the prompt comes first");
        let reasons = h.strong.reasons();
        assert_eq!(reasons.len(), 2);
        assert!(reasons[0].contains("reveal_secret"), "{reasons:?}");
        assert!(reasons[0].contains(CLIENT_LABEL), "{reasons:?}");
        assert!(reasons[0].contains("GitHub"), "{reasons:?}");
        assert!(!reasons.iter().any(|r| r.contains(GITHUB_PW)));
        assert_eq!(
            outcomes(&h.audit),
            ["strong_auth_failed", "strong_auth_failed"]
        );
    }

    // Verified: the value comes back.
    let mut h = build(Setup {
        policy: Box::new(open_policy),
        answers: vec![Decision::AllowOnce, Decision::Deny],
        ..Setup::default()
    });
    let v = ok(hcall(
        &mut h.tools,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    assert_eq!(v["untrusted_vault_data"]["value"], GITHUB_PW);
    assert_eq!(h.strong.reasons().len(), 1);
    // A denied prompt never reaches strong authentication.
    refused(hcall(
        &mut h.tools,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    assert_eq!(h.strong.reasons().len(), 1);
    // `run_with_secrets` does not ask for it.
    let mut h = build(Setup {
        answers: vec![Decision::AllowOnce],
        strong: StrongOutcome::Denied,
        ..Setup::default()
    });
    ok(hcall(&mut h.tools, "run_with_secrets", run_args(&["true"])));
    assert!(h.strong.reasons().is_empty());
}

/// Adds the `Mail` login (with a TOTP secret) to `Dev`.
fn add_mail_h(h: &H) {
    use onepass_core::model::{FieldValue, ItemType, new_item};
    let repo = &mut *h.port.inner.borrow_mut().0;
    let dev = vault(repo, "Dev");
    let mut item = new_item(ItemType::Login, dev.id, "Mail");
    item.field_mut("username").unwrap().value = FieldValue::Text("mail-user".into());
    item.field_mut("totp").unwrap().value = FieldValue::Otp(Zeroizing::new(MAIL_TOTP.into()));
    repo.save_item(&dev, item).unwrap();
}

#[test]
fn seventh_prompt_in_a_minute_refused_without_prompt() {
    let mut h = build(Setup {
        answers: vec![Decision::AllowOnce; 8],
        limits: Limits::mcp(),
        ..Setup::default()
    });
    for i in 0..6 {
        ok(hcall(
            &mut h.tools,
            "run_with_secrets",
            run_args(&["/bin/echo", &i.to_string()]),
        ));
    }
    let m = refused(hcall(
        &mut h.tools,
        "run_with_secrets",
        run_args(&["/bin/echo", "7"]),
    ));
    assert!(m.starts_with("rate limited"), "{m}");
    assert_eq!(h.approver.calls().len(), 6);
    assert_eq!(outcomes(&h.audit).last().unwrap(), "rate_limited");
    // Metadata tools are not prompts.
    ok(hcall(&mut h.tools, "list_items", json!({})));
    // A minute later, prompts again.
    h.clock.advance(Duration::from_secs(61));
    ok(hcall(
        &mut h.tools,
        "run_with_secrets",
        run_args(&["/bin/echo", "8"]),
    ));
    assert_eq!(h.approver.calls().len(), 7);
}

#[test]
fn secret_requests_are_rate_limited_even_with_a_grant() {
    let mut limits = Limits::mcp();
    limits.secret_per_min = 3;
    let mut h = build(Setup {
        answers: vec![Decision::AllowFor(Duration::from_secs(300))],
        limits,
        ..Setup::default()
    });
    let args = run_args(&["true"]);
    for _ in 0..3 {
        ok(hcall(&mut h.tools, "run_with_secrets", args.clone()));
    }
    let m = refused(hcall(&mut h.tools, "run_with_secrets", args));
    assert!(m.starts_with("rate limited"), "{m}");
    assert_eq!(h.approver.calls().len(), 1);
}

#[test]
fn three_denials_block_client() {
    let mut h = build(Setup {
        answers: vec![
            Decision::Deny,
            Decision::Deny,
            Decision::Deny,
            Decision::AllowOnce,
        ],
        limits: Limits::mcp(),
        ..Setup::default()
    });
    for i in 0..3 {
        let m = refused(hcall(
            &mut h.tools,
            "run_with_secrets",
            run_args(&["/bin/echo", &i.to_string()]),
        ));
        assert_eq!(m, "denied by the user");
    }
    let m = refused(hcall(&mut h.tools, "run_with_secrets", run_args(&["true"])));
    assert!(m.starts_with("client cooling down"), "{m}");
    assert_eq!(h.approver.calls().len(), 3);
    assert_eq!(outcomes(&h.audit).last().unwrap(), "client_cooling_down");
    // Still blocked just before the end of the 10 minutes.
    h.clock.advance(Duration::from_secs(599));
    refused(hcall(&mut h.tools, "run_with_secrets", run_args(&["true"])));
    assert_eq!(h.approver.calls().len(), 3);
    h.clock.advance(Duration::from_secs(1));
    ok(hcall(&mut h.tools, "run_with_secrets", run_args(&["true"])));
    assert_eq!(h.approver.calls().len(), 4);
}

#[test]
fn unpaired_after_start_refused_next_call() {
    let mut h = build(Setup::default());
    ok(hcall(&mut h.tools, "list_vaults", json!({})));
    let paired = std::fs::read(h.data.clients()).unwrap();
    h.data.unpair(CLIENT_ID);
    assert_eq!(
        refused(hcall(&mut h.tools, "list_vaults", json!({}))),
        NOT_PAIRED
    );
    // The older registry restored: refused (replay), never served.
    std::fs::write(h.data.clients(), &paired).unwrap();
    let m = refused(hcall(&mut h.tools, "list_vaults", json!({})));
    assert_eq!(m, "client registry failed verification");
    assert_eq!(outcomes(&h.audit).last().unwrap(), "registry_unusable");
    // Paired again (a newer registry): served.
    let scopes = all_scopes(h.port.inner.borrow().0);
    h.data.pair(&client(CLIENT_ID), &scopes, T0);
    ok(hcall(&mut h.tools, "list_vaults", json!({})));
    assert_eq!(
        outcomes(&h.audit),
        ["ok", "not_paired", "registry_unusable", "ok"]
    );
}

#[test]
fn lost_control_channel_refuses_every_call() {
    let repo = repo();
    let data = DataDir::new();
    let c = client(CLIENT_ID);
    data.pair(&c, &all_scopes(repo), 1);
    let approver = Arc::new(ScriptedApprover::new(vec![Decision::AllowOnce]));
    let mut guards = guards_in(
        &data,
        c,
        Strong::new(StrongOutcome::Verified),
        Arc::new(FakeClock::new(T0)),
        loose_limits(),
    );
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flag = alive.clone();
    guards.liveness = Some(Arc::new(move || {
        flag.load(std::sync::atomic::Ordering::SeqCst)
    }));
    let audit = SharedAudit::default();
    let mut t = McpTools::new(
        RepoPort(repo),
        Policy::default_for(&account_id()),
        Narrowing::default(),
        approver.clone(),
        Box::new(audit.clone()),
        None,
        guards,
    );
    ok(call(&mut t, "list_vaults", json!({})));
    alive.store(false, std::sync::atomic::Ordering::SeqCst);
    for (tool, args) in [
        ("list_vaults", json!({})),
        ("run_with_secrets", run_args(&["true"])),
    ] {
        assert_eq!(
            refused(call(&mut t, tool, args)),
            "server control channel lost; restart the server"
        );
    }
    assert!(approver.calls().is_empty());
}

#[test]
fn audit_entries_name_the_client() {
    let mut h = build(Setup {
        answers: vec![Decision::AllowOnce],
        ..Setup::default()
    });
    ok(hcall(&mut h.tools, "list_items", json!({})));
    ok(hcall(&mut h.tools, "run_with_secrets", run_args(&["true"])));
    let e: Vec<AuditEntry> = h.audit.entries();
    assert_eq!(e.len(), 2);
    for entry in e {
        assert_eq!(entry.client_id.as_deref(), Some(CLIENT_ID));
        assert_eq!(entry.client_label.as_deref(), Some(CLIENT_LABEL));
    }
    // The prompt names the verified client, not only the declared name.
    let req = &h.approver.calls()[0];
    assert!(req.client.contains(CLIENT_LABEL), "{}", req.client);
    assert!(req.client_verified);
}

#[test]
fn strong_auth_denials_count_toward_cooling_down() {
    let mut h = build(Setup {
        policy: Box::new(open_policy),
        answers: vec![Decision::AllowOnce; 4],
        strong: StrongOutcome::Denied,
        limits: Limits::mcp(),
        ..Setup::default()
    });
    let reveal = json!({"reference": "onepass://Dev/GitHub/password"});
    for _ in 0..3 {
        assert_eq!(
            refused(hcall(&mut h.tools, "reveal_secret", reveal.clone())),
            "strong authentication failed"
        );
    }
    let m = refused(hcall(&mut h.tools, "reveal_secret", reveal.clone()));
    assert!(m.starts_with("client cooling down"), "{m}");
    assert_eq!(h.approver.calls().len(), 3, "no fourth prompt");
    assert_eq!(h.strong.reasons().len(), 3);
    assert_eq!(*h.port.resolved.borrow(), 0);

    // `Unavailable` is not the user's denial: no cooling down.
    let mut h = build(Setup {
        policy: Box::new(open_policy),
        answers: vec![Decision::AllowOnce; 4],
        strong: StrongOutcome::Unavailable,
        limits: Limits::mcp(),
        ..Setup::default()
    });
    for _ in 0..4 {
        assert_eq!(
            refused(hcall(&mut h.tools, "reveal_secret", reveal.clone())),
            "strong authentication failed"
        );
    }
    assert_eq!(h.approver.calls().len(), 4);
}
