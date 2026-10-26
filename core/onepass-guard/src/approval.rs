//! User approvals for sensitive actions.

use crate::display::sanitize_for_display;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::time::Duration;

/// Which front end asks.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Surface {
    /// The MCP server.
    Mcp,
    /// The SSH agent.
    Ssh,
}

impl Surface {
    fn label(self) -> &'static str {
        match self {
            Surface::Mcp => "mcp",
            Surface::Ssh => "ssh",
        }
    }
}

/// An item (and optionally one of its fields) an action touches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Vault id or name.
    pub vault: String,
    /// Item id or title.
    pub item: String,
    /// Field, when the action targets one.
    pub field: Option<String>,
}

/// What the user is asked to approve. All text is untrusted and is sanitized
/// when displayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Requesting surface.
    pub surface: Surface,
    /// Client name as declared by the agent (untrusted).
    pub client: String,
    /// Action name.
    pub action: String,
    /// Non-secret detail lines (label, value).
    pub details: Vec<(String, String)>,
    /// Items the action touches.
    pub targets: Vec<Target>,
    /// Whether "allow for this session" may be offered.
    pub remember_allowed: bool,
}

/// The user's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Refuse.
    Deny,
    /// Allow this request only.
    AllowOnce,
    /// Allow this exact request for the rest of the session.
    AllowForSession,
}

/// Asks the user (or a stand-in) to approve a request.
pub trait Approver: Send + Sync {
    /// Returns the decision for `req`. Anything but an explicit yes is `Deny`.
    fn approve(&self, req: &ApprovalRequest) -> Decision;
}

/// Renders a request as terminal text. Every dynamic part is sanitized, so a
/// hostile title or client name cannot rewrite the prompt.
pub fn render_prompt(req: &ApprovalRequest) -> String {
    let s = sanitize_for_display;
    let mut out = String::new();
    out.push_str(&format!(
        "\nOnePass approval request ({})\n",
        req.surface.label()
    ));
    out.push_str(&format!(
        "  client: {} (declared, unverified)\n",
        s(&req.client)
    ));
    out.push_str(&format!("  action: {}\n", s(&req.action)));
    for (label, value) in &req.details {
        out.push_str(&format!("  {}: {}\n", s(label), s(value)));
    }
    for t in &req.targets {
        match &t.field {
            Some(f) => out.push_str(&format!(
                "  target: {} / {} / {}\n",
                s(&t.vault),
                s(&t.item),
                s(f)
            )),
            None => out.push_str(&format!("  target: {} / {}\n", s(&t.vault), s(&t.item))),
        }
    }
    out
}

/// Interprets one line typed at the prompt: `y` allows once, `s` allows for
/// the session (only when `remember_allowed`), anything else denies.
pub fn parse_answer(line: &str, remember_allowed: bool) -> Decision {
    match line.trim() {
        "y" | "Y" => Decision::AllowOnce,
        "s" | "S" if remember_allowed => Decision::AllowForSession,
        _ => Decision::Deny,
    }
}

/// Approver that talks to the user on `/dev/tty`.
pub struct TtyApprover {
    /// How long to wait for an answer before denying.
    pub timeout: Duration,
}

impl TtyApprover {
    /// Creates an approver with the default 60 s timeout.
    pub fn new() -> Self {
        TtyApprover {
            timeout: Duration::from_secs(60),
        }
    }
}

impl Default for TtyApprover {
    fn default() -> Self {
        Self::new()
    }
}

impl Approver for TtyApprover {
    fn approve(&self, req: &ApprovalRequest) -> Decision {
        let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
            return Decision::Deny;
        };
        let Ok(reader) = tty.try_clone() else {
            return Decision::Deny;
        };
        let choices = if req.remember_allowed {
            "[y] once, [s] session, anything else denies: "
        } else {
            "[y] once, anything else denies: "
        };
        let text = format!("{}{}", render_prompt(req), choices);
        if tty.write_all(text.as_bytes()).is_err() || tty.flush().is_err() {
            return Decision::Deny;
        }
        let (tx, rx) = mpsc::channel();
        // The reader thread may stay blocked after a timeout; it only holds
        // the terminal handle and ends with the process.
        std::thread::spawn(move || {
            let mut line = String::new();
            let ok = BufReader::new(reader).read_line(&mut line).is_ok();
            let _ = tx.send(if ok { line } else { String::new() });
        });
        match rx.recv_timeout(self.timeout) {
            Ok(line) => parse_answer(&line, req.remember_allowed),
            Err(_) => {
                let _ = tty.write_all(b"\ntimed out, denied\n");
                Decision::Deny
            }
        }
    }
}

/// Approver with a fixed answer, for end-to-end tests (debug builds only).
pub struct DevAutoApprover(pub Decision);

impl Approver for DevAutoApprover {
    fn approve(&self, _req: &ApprovalRequest) -> Decision {
        self.0
    }
}

/// Pure parser behind [`dev_auto_approver_from_env`]. `value` is the content
/// of `ONEPASS_DEV_AUTO_APPROVE`; `debug` says whether debug assertions are on.
pub fn parse_dev_auto_approve(
    value: Option<&str>,
    debug: bool,
) -> Result<Option<DevAutoApprover>, String> {
    let Some(v) = value else {
        return Ok(None);
    };
    if !debug {
        return Err("ONEPASS_DEV_AUTO_APPROVE is only accepted in debug builds".into());
    }
    match v {
        "once" => Ok(Some(DevAutoApprover(Decision::AllowOnce))),
        "session" => Ok(Some(DevAutoApprover(Decision::AllowForSession))),
        "deny" => Ok(Some(DevAutoApprover(Decision::Deny))),
        _ => Err("ONEPASS_DEV_AUTO_APPROVE must be once, session or deny".into()),
    }
}

/// Reads `ONEPASS_DEV_AUTO_APPROVE`: `None` when unset, `Err` on an unknown
/// value or in a release build.
pub fn dev_auto_approver_from_env() -> Result<Option<DevAutoApprover>, String> {
    let value = std::env::var("ONEPASS_DEV_AUTO_APPROVE").ok();
    parse_dev_auto_approve(value.as_deref(), cfg!(debug_assertions))
}

/// Helpers for tests of other crates.
pub mod testing {
    use super::*;
    use std::sync::Mutex;

    /// Approver that replays scripted answers in order, then denies, and
    /// records every request it receives.
    pub struct ScriptedApprover {
        state: Mutex<(VecDeque<Decision>, Vec<ApprovalRequest>)>,
    }

    impl ScriptedApprover {
        /// Creates an approver answering with `answers` in order.
        pub fn new(answers: Vec<Decision>) -> Self {
            ScriptedApprover {
                state: Mutex::new((answers.into(), Vec::new())),
            }
        }

        /// The requests seen so far.
        pub fn calls(&self) -> Vec<ApprovalRequest> {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .1
                .clone()
        }
    }

    impl Approver for ScriptedApprover {
        fn approve(&self, req: &ApprovalRequest) -> Decision {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.1.push(req.clone());
            st.0.pop_front().unwrap_or(Decision::Deny)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::ScriptedApprover;
    use super::*;

    fn req(remember_allowed: bool) -> ApprovalRequest {
        ApprovalRequest {
            surface: Surface::Mcp,
            client: "evil\x1b[2Jclient\r".into(),
            action: "run_with_secrets\x1b]0;x\x07".into(),
            details: vec![("command".into(), "sh -c 'echo \x1b[31mhi'".into())],
            targets: vec![Target {
                vault: "Work".into(),
                item: "Prod\x1b[1Adb".into(),
                field: Some("password".into()),
            }],
            remember_allowed,
        }
    }

    #[test]
    fn render_prompt_lists_everything_sanitized() {
        let text = render_prompt(&req(true));
        assert!(text.contains("run_with_secrets?]0;x?"));
        assert!(text.contains("evil?[2Jclient?"));
        assert!(text.contains("command"));
        assert!(text.contains("sh -c 'echo ?[31mhi'"));
        assert!(text.contains("Work"));
        assert!(text.contains("Prod?[1Adb"));
        assert!(text.contains("password"));
        assert!(!text.bytes().any(|b| b == 0x1b));
    }

    #[test]
    fn parse_answer_cases() {
        assert_eq!(parse_answer("y", true), Decision::AllowOnce);
        assert_eq!(parse_answer("Y\n", false), Decision::AllowOnce);
        assert_eq!(parse_answer("s", true), Decision::AllowForSession);
        assert_eq!(parse_answer("s", false), Decision::Deny);
        assert_eq!(parse_answer("", true), Decision::Deny);
        assert_eq!(parse_answer("yes please", true), Decision::Deny);
        assert_eq!(parse_answer("n", true), Decision::Deny);
    }

    #[test]
    fn scripted_approver_records_calls() {
        let a = ScriptedApprover::new(vec![Decision::AllowOnce, Decision::AllowForSession]);
        let r = req(true);
        assert_eq!(a.approve(&r), Decision::AllowOnce);
        assert_eq!(a.approve(&r), Decision::AllowForSession);
        assert_eq!(a.approve(&r), Decision::Deny);
        let calls = a.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0], r);
    }

    #[test]
    fn dev_auto_approver_parses_values() {
        assert!(parse_dev_auto_approve(None, true).unwrap().is_none());
        let d = |v: &str, debug| parse_dev_auto_approve(Some(v), debug);
        assert_eq!(d("deny", true).unwrap().unwrap().0, Decision::Deny);
        assert_eq!(d("once", true).unwrap().unwrap().0, Decision::AllowOnce);
        assert_eq!(
            d("session", true).unwrap().unwrap().0,
            Decision::AllowForSession
        );
        assert!(d("always", true).is_err());
        assert!(d("once", false).is_err());
        let approver = DevAutoApprover(Decision::AllowOnce);
        assert_eq!(approver.approve(&req(true)), Decision::AllowOnce);
    }
}
