//! The server tells the agent that a human is being asked, with the
//! confirmation code, before it waits; the audit entry says where the
//! approval was given.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use onepass_guard::testing::ScriptedApprover;
use onepass_guard::{Answer, ApprovalRequest, Approver, CHALLENGE_ALPHABET, Decision};
use onepass_mcp::{Policy, Scope, Session, handle_line_notifying};
use serde_json::{Value, json};

const PENDING: &str = "Approve on your Mac or iPhone. Code: ";

fn default_policy() -> Policy {
    Policy::default_for(&account_id())
}

/// Every scope on the MCP vaults (reveal included).
fn everything(repo: &onepass_core::repo::Repository<onepass_core::store::MemoryStore>) -> Policy {
    let all: &[Scope] = &Scope::ALL;
    policy_with(repo, &[("Dev", all), ("Shared", all)])
}

/// Notices sent so far, shared with the approver.
type Sent = Arc<Mutex<Vec<String>>>;

/// Approves once, and records how many notices had been sent when it was
/// asked (it must be one: the agent is told before the wait) and the code
/// the guard put in the request.
struct Witness {
    sent: Sent,
    seen: Mutex<Vec<(usize, String)>>,
    answer: Answer,
}

impl Approver for Witness {
    fn approve(&self, req: &ApprovalRequest) -> Answer {
        let n = self.sent.lock().unwrap().len();
        self.seen
            .lock()
            .unwrap()
            .push((n, req.confirm_code.clone()));
        self.answer.clone()
    }
}

fn witness(sent: &Sent, answer: Answer) -> Arc<Witness> {
    Arc::new(Witness {
        sent: sent.clone(),
        seen: Mutex::new(Vec::new()),
        answer,
    })
}

/// Sends `request` (a JSON-RPC line) through the protocol after an
/// `initialize`; returns the reply and every notification it sent.
fn rpc(tools: &mut Tools, sent: &Sent, request: Value) -> Value {
    let mut session = Session::new();
    let init = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"test-agent","version":"1"}}});
    handle_line_notifying(&mut session, tools, &init.to_string(), &mut |_| {}).unwrap();
    let sink = sent.clone();
    let reply = handle_line_notifying(&mut session, tools, &request.to_string(), &mut |m| {
        sink.lock().unwrap().push(m)
    })
    .expect("reply");
    serde_json::from_str(&reply).unwrap()
}

fn reveal(token: Option<Value>) -> Value {
    let mut params = json!({
        "name": "reveal_secret",
        "arguments": {"reference": "onepass://Dev/GitHub/password"},
    });
    if let Some(t) = token {
        params["_meta"] = json!({"progressToken": t});
    }
    json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":params})
}

#[test]
fn mcp_sends_progress_with_token() {
    let sent = Sent::default();
    let w = witness(&sent, Answer::on(Decision::AllowOnce, "mac"));
    let (mut t, _) = tools_with_policy(everything, w.clone());
    let reply = rpc(&mut t, &sent, reveal(Some(json!("tok-1"))));
    assert_eq!(reply["result"]["isError"], false, "{reply}");

    let sent = sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let n: Value = serde_json::from_str(&sent[0]).unwrap();
    assert_eq!(n["jsonrpc"], "2.0");
    assert!(n.get("id").is_none(), "a notification has no id");
    assert_eq!(n["method"], "notifications/progress");
    assert_eq!(n["params"]["progressToken"], "tok-1");
    assert_eq!(n["params"]["progress"], 0);
    let (count, code) = w.seen.lock().unwrap()[0].clone();
    // Sent before the approver was asked, with the code it was shown.
    assert_eq!(count, 1);
    assert_eq!(code.chars().count(), 4);
    assert!(code.chars().all(|c| CHALLENGE_ALPHABET.contains(c)));
    assert_eq!(n["params"]["message"], format!("{PENDING}{code}"));

    // A numeric token is echoed as is.
    let sent2 = Sent::default();
    let w = witness(&sent2, Answer::new(Decision::AllowOnce));
    let (mut t, _) = tools_with_policy(everything, w);
    rpc(&mut t, &sent2, reveal(Some(json!(42))));
    let n: Value = serde_json::from_str(&sent2.lock().unwrap()[0]).unwrap();
    assert_eq!(n["params"]["progressToken"], 42);
}

#[test]
fn mcp_sends_log_message_without_token() {
    let sent = Sent::default();
    let w = witness(&sent, Answer::new(Decision::AllowOnce));
    let (mut t, _) = tools_with_policy(everything, w.clone());
    rpc(&mut t, &sent, reveal(None));

    let sent = sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let n: Value = serde_json::from_str(&sent[0]).unwrap();
    assert_eq!(n["method"], "notifications/message");
    assert_eq!(n["params"]["level"], "info");
    let (count, code) = w.seen.lock().unwrap()[0].clone();
    assert_eq!(count, 1);
    assert_eq!(n["params"]["data"], format!("{PENDING}{code}"));
    assert!(n["params"].get("progressToken").is_none());
}

/// A terminal-style approver: its code must stay between it and the user.
struct Terminal(Witness);

impl Approver for Terminal {
    fn approve(&self, req: &ApprovalRequest) -> Answer {
        self.0.approve(req)
    }
    fn code_is_public(&self) -> bool {
        false
    }
}

#[test]
fn a_terminal_approver_code_never_reaches_the_client() {
    for token in [Some(json!("t")), None] {
        let sent = Sent::default();
        let t_approver = Arc::new(Terminal(Witness {
            sent: sent.clone(),
            seen: Mutex::new(Vec::new()),
            answer: Answer::new(Decision::AllowOnce),
        }));
        let (mut t, _) = tools_with_policy(everything, t_approver.clone());
        let reply = rpc(&mut t, &sent, reveal(token));
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        let (count, code) = t_approver.0.seen.lock().unwrap()[0].clone();
        // Told before the wait, and the approver still got a code.
        assert_eq!(count, 1);
        assert_eq!(code.chars().count(), 4);
        let sent = sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert!(!sent[0].contains(&code), "{}", sent[0]);
        let n: Value = serde_json::from_str(&sent[0]).unwrap();
        let text = n["params"]["message"]
            .as_str()
            .or_else(|| n["params"]["data"].as_str())
            .unwrap();
        assert_eq!(text, "Approve in the terminal running onepass mcp.");
    }
}

#[test]
fn pending_notice_never_contains_values() {
    for token in [Some(json!("t")), None] {
        let sent = Sent::default();
        let w = witness(&sent, Answer::new(Decision::AllowOnce));
        let (mut t, _) = tools_with_policy(everything, w.clone());
        // Secret value, item and vault names, field: none may leak.
        let reply = rpc(&mut t, &sent, reveal(token));
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        let sent = sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        for leak in [
            GITHUB_PW,
            GITHUB_USER,
            GITHUB_NOTES,
            "GitHub",
            "Dev",
            "password",
            "reveal_secret",
            CLIENT_LABEL,
        ] {
            assert!(!sent[0].contains(leak), "{leak:?} in {}", sent[0]);
        }
        // Nothing but the fixed text and the code.
        let code = w.seen.lock().unwrap()[0].1.clone();
        assert!(sent[0].contains(&format!("{PENDING}{code}")));
        let n: Value = serde_json::from_str(&sent[0]).unwrap();
        let text = n["params"]["message"]
            .as_str()
            .or_else(|| n["params"]["data"].as_str())
            .unwrap();
        assert_eq!(text, format!("{PENDING}{code}"));
    }
}

#[test]
fn nothing_is_announced_when_nobody_is_asked() {
    // Metadata tools never prompt: no notice.
    let sent = Sent::default();
    let (mut t, _) = tools_with_audit(default_policy(), Arc::new(ScriptedApprover::new(vec![])));
    let reply = rpc(
        &mut t,
        &sent,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"list_vaults","arguments":{},"_meta":{"progressToken":"x"}}}),
    );
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert!(sent.lock().unwrap().is_empty());
}

#[test]
fn approved_on_reaches_the_audit_entry() {
    let sent = Sent::default();
    let w = witness(&sent, Answer::on(Decision::AllowOnce, "phone:p7"));
    let (mut t, audit) = tools_with_policy(everything, w);
    ok(call(
        &mut t,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    let e = audit.entries();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].approved_on.as_deref(), Some("phone:p7"));
    assert_eq!(e[0].decision, "once");

    // An approver that does not say leaves it out.
    let (mut t, audit) = tools_with_policy(
        everything,
        Arc::new(ScriptedApprover::new(vec![Decision::AllowOnce])),
    );
    ok(call(
        &mut t,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    assert_eq!(audit.entries()[0].approved_on, None);
}

#[test]
fn the_request_asks_for_strong_where_the_tool_needs_it() {
    let a = Arc::new(ScriptedApprover::new(vec![
        Decision::AllowOnce,
        Decision::AllowOnce,
    ]));
    let (mut t, _) = tools_with_policy(everything, a.clone());
    ok(call(
        &mut t,
        "reveal_secret",
        json!({"reference": "onepass://Dev/GitHub/password"}),
    ));
    ok(call(
        &mut t,
        "run_with_secrets",
        json!({"command": ["/bin/echo", "x"], "env": {"T": "onepass://Dev/GitHub/password"}}),
    ));
    let calls = a.calls();
    assert!(calls[0].strong_required);
    assert!(!calls[1].strong_required);
    assert!(!calls[0].confirm_code.is_empty() && !calls[1].confirm_code.is_empty());
}
