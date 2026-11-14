//! Key-use log: what the MCP secret tools record on the item (key-use
//! spec, MCP callers). One entry per field read or injected, the client
//! name taken from `initialize` and sanitized by the core, nothing for a
//! refused request, and a failed write never fails the tool.

mod common;

use std::sync::Arc;

use common::*;
use onepass_core::Id;
use onepass_core::model::Item;
use onepass_core::model::key_use::{KeyUse, KeyUseAction, KeyUseChannel, MAX_LABEL_CHARS};
use onepass_core::reference::SecretRef;
use onepass_core::store::MemoryStore;
use onepass_guard::Decision;
use onepass_guard::testing::ScriptedApprover;
use onepass_mcp::{
    BrowserError, BrowserFill, BrowserTarget, ClientInfo, FillKind, FillOutcome, McpTools,
    PageProbe, PortError, RepoPort, Scope, ToolHost, ToolOutcome, VaultInfo, VaultPort,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const CLIENT: &str = "Claude Code";

fn approver(answers: Vec<Decision>) -> Arc<ScriptedApprover> {
    Arc::new(ScriptedApprover::new(answers))
}

fn call_as(tools: &mut Tools, client: &str, name: &str, args: Value) -> ToolOutcome {
    let info = ClientInfo {
        name: client.into(),
        version: "1".into(),
    };
    tools.call(&info, name, args.as_object().unwrap())
}

fn call_claude(tools: &mut Tools, name: &str, args: Value) -> ToolOutcome {
    call_as(tools, CLIENT, name, args)
}

/// The key-use entries of the live item `title` in `Dev`.
fn uses(tools: &mut Tools, title: &str) -> Vec<KeyUse> {
    let repo = &mut *tools.port_mut().0;
    let v = vault(repo, "Dev");
    repo.items(&v)
        .unwrap()
        .into_iter()
        .find(|i| i.title == title && i.trashed_at.is_none())
        .unwrap()
        .key_use_trailer()
        .entries
}

/// The label of field `id` of the live item `title` in `Dev`.
fn label_of(tools: &mut Tools, title: &str, id: &str) -> String {
    let repo = &mut *tools.port_mut().0;
    let v = vault(repo, "Dev");
    let item: Item = repo
        .items(&v)
        .unwrap()
        .into_iter()
        .find(|i| i.title == title && i.trashed_at.is_none())
        .unwrap();
    item.field(id).unwrap().label.clone()
}

fn labels(entries: &[KeyUse]) -> Vec<String> {
    let mut l: Vec<String> = entries.iter().map(|e| e.field.clone()).collect();
    l.sort();
    l
}

#[test]
fn reveal_secret_records_revealed() {
    let (mut t, _) = tools_with_policy(
        |r| policy_with(r, &[("Dev", &[Scope::Reveal])]),
        approver(vec![Decision::AllowOnce]),
    );
    ok(call_claude(
        &mut t,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    let e = uses(&mut t, "GitHub");
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].channel, KeyUseChannel::Mcp);
    assert_eq!(e[0].action, KeyUseAction::Revealed);
    assert_eq!(e[0].client, CLIENT);
    assert_eq!(e[0].field, label_of(&mut t, "GitHub", "password"));
    assert_eq!(e[0].count, 1);
}

#[test]
fn run_with_secrets_records_one_entry_per_field() {
    let (mut t, _) = tools_with_policy(
        |r| policy_with(r, &[("Dev", &[Scope::Metadata, Scope::Use])]),
        approver(vec![Decision::AllowOnce]),
    );
    ok(call_claude(
        &mut t,
        "run_with_secrets",
        json!({
            "command": ["/bin/sh", "-c", "true"],
            "env": {
                "U": "onepass://Dev/GitHub/username",
                "P": "onepass://Dev/GitHub/password"
            }
        }),
    ));
    let e = uses(&mut t, "GitHub");
    assert_eq!(e.len(), 2, "{e:?}");
    assert!(e.iter().all(|x| x.action == KeyUseAction::Injected
        && x.channel == KeyUseChannel::Mcp
        && x.client == CLIENT));
    let mut want = vec![
        label_of(&mut t, "GitHub", "username"),
        label_of(&mut t, "GitHub", "password"),
    ];
    want.sort();
    assert_eq!(labels(&e), want);
}

#[test]
fn fill_template_records_injected() {
    let (mut t, _) = tools_with_policy(
        |r| policy_with(r, &[("Dev", &[Scope::Metadata, Scope::Use])]),
        approver(vec![Decision::AllowOnce]),
    );
    let dir = tempfile::tempdir().unwrap();
    let tpl = dir.path().join("tpl.txt");
    let out = dir.path().join("out.txt");
    std::fs::write(&tpl, "pw={{ onepass://Dev/GitHub/password }}\n").unwrap();
    ok(call_claude(
        &mut t,
        "fill_template",
        json!({"template_path": tpl, "output_path": out}),
    ));
    let e = uses(&mut t, "GitHub");
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].action, KeyUseAction::Injected);
    assert_eq!(e[0].client, CLIENT);
    assert_eq!(e[0].field, label_of(&mut t, "GitHub", "password"));
}

#[test]
fn totp_code_records_totp() {
    let (mut t, _) = tools_with_policy(
        |r| policy_with(r, &[("Dev", &[Scope::Metadata, Scope::Use, Scope::Totp])]),
        approver(vec![Decision::AllowOnce]),
    );
    add_mail(&mut t, false);
    ok(call_claude(
        &mut t,
        "totp_code",
        json!({"reference": "onepass://Dev/Mail/totp"}),
    ));
    let e = uses(&mut t, "Mail");
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].action, KeyUseAction::Totp);
    assert_eq!(e[0].channel, KeyUseChannel::Mcp);
    assert_eq!(e[0].client, CLIENT);
    assert_eq!(e[0].field, label_of(&mut t, "Mail", "totp"));
}

/// A browser that is always on github.com and fills both login fields.
struct GithubTab;

impl BrowserFill for GithubTab {
    fn probe(&self, _: &str, _: &BrowserTarget, _: &str) -> Result<PageProbe, BrowserError> {
        Ok(PageProbe {
            tab_title: "Sign in".into(),
            origin: "https://github.com".into(),
            handle: "tab".into(),
            request_id: 0,
        })
    }

    fn fill(
        &self,
        _: &str,
        _: &BrowserTarget,
        _: &PageProbe,
        _: &Item,
        _: Id,
        _: FillKind,
        _: bool,
        _: bool,
    ) -> Result<FillOutcome, BrowserError> {
        Ok(FillOutcome {
            filled: vec!["username".into(), "password".into()],
            submitted: false,
        })
    }
}

fn browser_tools(answers: Vec<Decision>) -> Tools {
    let (t, _) = tools_with_policy(
        |r| policy_with(r, &[("Dev", &[Scope::Metadata, Scope::Use, Scope::Fill])]),
        approver(answers),
    );
    t.with_browser(Box::new(GithubTab))
}

fn fill_args(t: &mut Tools) -> Value {
    let id = item_id(t, "Dev", "GitHub");
    json!({
        "item_id": id.to_string(),
        "url": "https://github.com/login",
        "kind": "login",
        "target": {"browser": "chrome"}
    })
}

#[test]
fn fill_in_browser_records_filled() {
    let mut t = browser_tools(vec![Decision::AllowOnce]);
    let args = fill_args(&mut t);
    ok(call_claude(&mut t, "fill_in_browser", args));
    let e = uses(&mut t, "GitHub");
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].action, KeyUseAction::Filled);
    assert_eq!(e[0].channel, KeyUseChannel::Mcp);
    assert_eq!(e[0].client, CLIENT);
    assert_eq!(e[0].field, "");
}

#[test]
fn denied_request_records_nothing() {
    // A scope refusal, then a user refusal, on reveal and on a fill.
    let (mut t, _) = tools_with_policy(
        |r| policy_with(r, &[("Dev", &[Scope::Metadata, Scope::Use])]),
        approver(vec![Decision::Deny]),
    );
    refused(call_claude(
        &mut t,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    assert!(uses(&mut t, "GitHub").is_empty());

    let (mut t, _) = tools_with_policy(
        |r| policy_with(r, &[("Dev", &[Scope::Reveal])]),
        approver(vec![Decision::Deny]),
    );
    refused(call_claude(
        &mut t,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    assert!(uses(&mut t, "GitHub").is_empty());

    let mut t = browser_tools(vec![Decision::Deny]);
    let args = fill_args(&mut t);
    refused(call_claude(&mut t, "fill_in_browser", args));
    assert!(uses(&mut t, "GitHub").is_empty());
}

/// A port whose key-use write always fails.
struct NoKeyUse(RepoPort<'static, MemoryStore>);

impl VaultPort for NoKeyUse {
    fn vaults(&mut self) -> Result<Vec<VaultInfo>, PortError> {
        self.0.vaults()
    }
    fn items(&mut self, vault_id: Id) -> Result<Vec<Item>, PortError> {
        self.0.items(vault_id)
    }
    fn resolve(&mut self, r: &SecretRef) -> Result<Zeroizing<String>, PortError> {
        self.0.resolve(r)
    }
    fn save_item(&mut self, vault_id: Id, item: Item) -> Result<(), PortError> {
        self.0.save_item(vault_id, item)
    }
    fn record_key_use(
        &mut self,
        _: Id,
        _: Id,
        _: KeyUseAction,
        _: &str,
        _: &str,
    ) -> Result<(), PortError> {
        Err(PortError::Other("disk full".into()))
    }
}

#[test]
fn record_failure_does_not_fail_reveal() {
    let repo = repo();
    let policy = policy_with(repo, &[("Dev", &[Scope::Reveal])]);
    let guards = default_guards(repo);
    let mut t = McpTools::new(
        NoKeyUse(RepoPort(repo)),
        policy,
        onepass_mcp::Narrowing::default(),
        approver(vec![Decision::AllowOnce]),
        Box::new(SharedAudit::default()),
        None,
        guards,
    );
    let info = ClientInfo {
        name: CLIENT.into(),
        version: "1".into(),
    };
    let args = json!({"reference": "onepass://Dev/GitHub/password"});
    let v = ok(t.call(&info, "reveal_secret", args.as_object().unwrap()));
    assert_eq!(v["untrusted_vault_data"]["value"], GITHUB_PW);
}

#[test]
fn hostile_client_name_is_sanitized() {
    let (mut t, _) = tools_with_policy(
        |r| policy_with(r, &[("Dev", &[Scope::Reveal])]),
        approver(vec![Decision::AllowOnce]),
    );
    let hostile = format!("\u{202E}{}", "x".repeat(5 * 1024));
    ok(call_as(
        &mut t,
        &hostile,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    let e = uses(&mut t, "GitHub");
    assert_eq!(e.len(), 1);
    assert!(e[0].client.chars().count() <= MAX_LABEL_CHARS);
    assert!(e[0].client.chars().count() <= 64);
    assert!(!e[0].client.contains('\u{202E}'));
    assert!(e[0].client.starts_with('x'));
}
