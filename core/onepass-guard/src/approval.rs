//! User approvals for sensitive actions.

use crate::display::sanitize_for_display;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// Characters of the approval challenge: lowercase letters without `i`, `l`
/// and `o`, which are easy to misread.
pub const CHALLENGE_ALPHABET: &str = "abcdefghjkmnpqrstuvwxyz";

/// Draws a fresh 2-character challenge from [`CHALLENGE_ALPHABET`] with the
/// system random generator. `None` if the generator fails (the caller denies).
pub fn challenge_code() -> Option<String> {
    let alphabet = CHALLENGE_ALPHABET.as_bytes();
    let n = alphabet.len();
    // Rejection sampling keeps the draw uniform.
    let limit = (256 / n * n) as u8;
    let mut out = String::new();
    while out.len() < 2 {
        let mut b = [0u8; 1];
        aws_lc_rs::rand::fill(&mut b).ok()?;
        if b[0] < limit {
            out.push(alphabet[b[0] as usize % n] as char);
        }
    }
    Some(out)
}

/// Renders a request as terminal text, ending with the instruction to type
/// `code`. Every dynamic part is sanitized, so a hostile title or client name
/// cannot rewrite the prompt.
pub fn render_prompt(req: &ApprovalRequest, code: &str) -> String {
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
    let code = s(code);
    if req.remember_allowed {
        out.push_str(&format!(
            "type {code} to allow once, \"{code} s\" to allow for this session, anything else denies: "
        ));
    } else {
        out.push_str(&format!(
            "type {code} to allow once, anything else denies: "
        ));
    }
    out
}

/// Interprets one line typed at the prompt against the challenge `code`:
/// the code alone allows once, the code followed by ` s` allows for the
/// session (only when `remember_allowed`), anything else denies.
pub fn parse_answer(line: &str, code: &str, remember_allowed: bool) -> Decision {
    let answer = line.trim();
    if code.is_empty() {
        return Decision::Deny;
    }
    if answer == code {
        return Decision::AllowOnce;
    }
    if remember_allowed && answer.strip_suffix(" s") == Some(code) {
        return Decision::AllowForSession;
    }
    Decision::Deny
}

/// Longest answer line read from the terminal; a longer one denies.
const MAX_ANSWER: usize = 256;

/// Discards input queued on the terminal `f` (typeahead, or text injected
/// before the prompt was shown). Fails on a non-terminal.
fn flush_input(f: &File) -> std::io::Result<()> {
    // SAFETY: tcflush only reads the descriptor number, which `f` keeps open.
    if unsafe { libc::tcflush(f.as_raw_fd(), libc::TCIFLUSH) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Reads one line from `f`, waiting at most `timeout` in total. `None` on
/// timeout, end of input before a newline, an error or an over-long line.
fn read_line_with_timeout(f: &File, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    let mut line: Vec<u8> = Vec::new();
    let mut reader = f;
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        let mut pfd = libc::pollfd {
            fd: f.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = left.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        // SAFETY: `pfd` is a valid pollfd for the duration of the call.
        let r = unsafe { libc::poll(&mut pfd, 1, ms) };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        if r == 0 {
            if Instant::now() >= deadline {
                return None;
            }
            continue;
        }
        let mut buf = [0u8; 64];
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        for &b in &buf[..n] {
            if b == b'\n' {
                return String::from_utf8(line).ok();
            }
            line.push(b);
            if line.len() > MAX_ANSWER {
                return None;
            }
        }
    }
}

/// Approver that talks to the user on `/dev/tty`.
///
/// The terminal is opened only for the duration of one prompt: pending input
/// is flushed, the prompt (with a fresh 2-character challenge) is written, one
/// line is read with a timeout, and the terminal is closed. No reader is left
/// behind, so between prompts every keystroke goes to the program that shares
/// the terminal (for example the MCP client). Any error denies.
pub struct TtyApprover {
    /// How long to wait for an answer before denying.
    pub timeout: Duration,
    serial: Mutex<()>,
}

impl TtyApprover {
    /// Creates an approver with the default 60 s timeout.
    pub fn new() -> Self {
        TtyApprover {
            timeout: Duration::from_secs(60),
            serial: Mutex::new(()),
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
        // Holding the lock serializes concurrent prompts.
        let _guard = self.serial.lock().unwrap_or_else(|e| e.into_inner());
        let Some(code) = challenge_code() else {
            return Decision::Deny;
        };
        let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
            return Decision::Deny;
        };
        if flush_input(&tty).is_err() {
            return Decision::Deny;
        }
        let text = render_prompt(req, &code);
        if tty.write_all(text.as_bytes()).is_err() || tty.flush().is_err() {
            return Decision::Deny;
        }
        match read_line_with_timeout(&tty, self.timeout) {
            Some(line) => parse_answer(&line, &code, req.remember_allowed),
            None => {
                let _ = tty.write_all(b"\nno valid answer, denied\n");
                Decision::Deny
            }
        }
        // The terminal is closed when `tty` is dropped.
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
pub(crate) fn parse_dev_auto_approve(
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
        let text = render_prompt(&req(true), "ab");
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
    fn render_prompt_shows_the_challenge() {
        let text = render_prompt(&req(true), "kq");
        assert!(text.contains("type kq to allow once"));
        assert!(text.contains("kq s"));
        let text = render_prompt(&req(false), "kq");
        assert!(text.contains("type kq to allow once"));
        assert!(!text.contains("kq s"));
    }

    #[test]
    fn parse_answer_cases() {
        assert_eq!(parse_answer("kq", "kq", true), Decision::AllowOnce);
        assert_eq!(parse_answer(" kq \n", "kq", false), Decision::AllowOnce);
        assert_eq!(parse_answer("kq s", "kq", true), Decision::AllowForSession);
        assert_eq!(parse_answer("kq s\n", "kq", false), Decision::Deny);
        // The old fixed answers and a wrong code all deny.
        assert_eq!(parse_answer("y", "kq", true), Decision::Deny);
        assert_eq!(parse_answer("s", "kq", true), Decision::Deny);
        assert_eq!(parse_answer("ab", "kq", true), Decision::Deny);
        assert_eq!(parse_answer("ab s", "kq", true), Decision::Deny);
        assert_eq!(parse_answer("KQ", "kq", true), Decision::Deny);
        assert_eq!(parse_answer("", "kq", true), Decision::Deny);
        assert_eq!(parse_answer("kqs", "kq", true), Decision::Deny);
        assert_eq!(parse_answer("kq  s", "kq", true), Decision::Deny);
        // An empty expected code never matches.
        assert_eq!(parse_answer("", "", true), Decision::Deny);
    }

    #[test]
    fn challenge_codes_use_the_alphabet_and_vary() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let c = challenge_code().expect("random source");
            assert_eq!(c.chars().count(), 2);
            assert!(c.chars().all(|ch| CHALLENGE_ALPHABET.contains(ch)));
            seen.insert(c);
        }
        assert!(seen.len() > 50);
        assert!(!CHALLENGE_ALPHABET.contains(['i', 'l', 'o']));
    }

    #[test]
    fn read_line_with_timeout_reads_one_line() {
        use std::os::unix::net::UnixStream;
        let (mut w, r) = UnixStream::pair().unwrap();
        w.write_all(b"kq s\nnext\n").unwrap();
        let file = File::from(std::os::fd::OwnedFd::from(r));
        assert_eq!(
            read_line_with_timeout(&file, Duration::from_secs(5)).as_deref(),
            Some("kq s")
        );
    }

    #[test]
    fn read_line_with_timeout_times_out_and_bounds_length() {
        use std::os::unix::net::UnixStream;
        let (_w, r) = UnixStream::pair().unwrap();
        let file = File::from(std::os::fd::OwnedFd::from(r));
        let start = std::time::Instant::now();
        assert_eq!(
            read_line_with_timeout(&file, Duration::from_millis(200)),
            None
        );
        assert!(start.elapsed() >= Duration::from_millis(150));

        let (mut w, r) = UnixStream::pair().unwrap();
        w.write_all(&[b'a'; 4096]).unwrap();
        let file = File::from(std::os::fd::OwnedFd::from(r));
        assert_eq!(read_line_with_timeout(&file, Duration::from_secs(5)), None);

        // End of input without a newline denies.
        let (mut w, r) = UnixStream::pair().unwrap();
        w.write_all(b"kq").unwrap();
        drop(w);
        let file = File::from(std::os::fd::OwnedFd::from(r));
        assert_eq!(read_line_with_timeout(&file, Duration::from_secs(5)), None);
    }

    #[test]
    fn pending_input_is_flushed_before_reading() {
        // On a terminal, typeahead (or TIOCSTI injection before the prompt)
        // is discarded by tcflush; on a non-terminal the flush fails and the
        // approver must deny (fail closed).
        use std::os::unix::net::UnixStream;
        let (_w, r) = UnixStream::pair().unwrap();
        let file = File::from(std::os::fd::OwnedFd::from(r));
        assert!(flush_input(&file).is_err());
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
