//! User approvals for sensitive actions.

// The terminal handling calls libc on our own `/dev/tty` descriptor
// (tcflush, fcntl); each block has its SAFETY comment.
#![allow(unsafe_code)]

use crate::display::sanitize_for_display;
use crate::grants::{DEFAULT_GRANT_TTL, MAX_GRANT_TTL};
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
    /// Client name as declared by the agent (untrusted), or a label of a
    /// verified client when `client_verified`.
    pub client: String,
    /// True when `client` names a verified, paired client identity; false
    /// shows it as declared and unverified.
    pub client_verified: bool,
    /// Action name.
    pub action: String,
    /// Non-secret detail lines (label, value).
    pub details: Vec<(String, String)>,
    /// Items the action touches.
    pub targets: Vec<Target>,
    /// Whether "allow for a few minutes" (a grant) may be offered.
    pub remember_allowed: bool,
}

/// The user's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Refuse.
    Deny,
    /// Allow this request only.
    AllowOnce,
    /// Allow this exact request again for the given duration (one of
    /// [`GRANT_CHOICES`], at most 60 minutes).
    AllowFor(Duration),
}

/// Durations offered at the prompt: answer suffix and duration. `s` is the
/// default grant (5 minutes), `s60` the ceiling.
pub const GRANT_CHOICES: [(&str, Duration); 3] = [
    ("s", DEFAULT_GRANT_TTL),
    ("s15", Duration::from_secs(15 * 60)),
    ("s60", MAX_GRANT_TTL),
];

/// Audit label of a decision: `denied`, `once`, or `grant_<n>m` for a grant
/// of one of the [`GRANT_CHOICES`] durations (`grant` for any other).
pub fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Deny => "denied",
        Decision::AllowOnce => "once",
        Decision::AllowFor(d) => match d.as_secs() {
            300 => "grant_5m",
            900 => "grant_15m",
            3600 => "grant_60m",
            _ => "grant",
        },
    }
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
    if req.client_verified {
        out.push_str(&format!("  client: {}\n", s(&req.client)));
    } else {
        out.push_str(&format!(
            "  client: {} (declared, unverified)\n",
            s(&req.client)
        ));
    }
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
        out.push_str(&format!("type {code} to allow once"));
        for (suffix, d) in GRANT_CHOICES {
            out.push_str(&format!(
                ", \"{code} {suffix}\" for {} min",
                d.as_secs() / 60
            ));
        }
        out.push_str(", anything else denies: ");
    } else {
        out.push_str(&format!(
            "type {code} to allow once, anything else denies: "
        ));
    }
    out
}

/// Interprets one line typed at the prompt against the challenge `code`:
/// the code alone allows once; the code followed by a space and one of the
/// [`GRANT_CHOICES`] suffixes (`s` 5 min, `s15`, `s60`) allows for that
/// duration (only when `remember_allowed`); anything else denies.
pub fn parse_answer(line: &str, code: &str, remember_allowed: bool) -> Decision {
    let answer = line.trim();
    if code.is_empty() {
        return Decision::Deny;
    }
    if answer == code {
        return Decision::AllowOnce;
    }
    if !remember_allowed {
        return Decision::Deny;
    }
    let Some(suffix) = answer
        .strip_prefix(code)
        .and_then(|rest| rest.strip_prefix(' '))
    else {
        return Decision::Deny;
    };
    GRANT_CHOICES
        .iter()
        .find(|(s, _)| *s == suffix)
        .map_or(Decision::Deny, |&(_, d)| Decision::AllowFor(d))
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

/// Pause between two non-blocking reads while no answer is available.
const READ_POLL: Duration = Duration::from_millis(20);

/// Reads one line (ended by `\n` or `\r`, so raw-mode terminals work too)
/// from `f`, waiting at most `timeout` in total. `None` on timeout, end of
/// input before the end of line, any error or an over-long line.
///
/// `f` is switched to non-blocking mode and polled by reading: `poll(2)` is
/// not usable here, since on macOS it answers `POLLNVAL` at once for
/// `/dev/tty`. The mode is not restored: `f` is always our own open of
/// `/dev/tty` (its own open file description, never the client's
/// descriptors) and is closed right after the prompt.
fn read_line_with_timeout(f: &File, timeout: Duration) -> Option<String> {
    let fd = f.as_raw_fd();
    // SAFETY: fcntl only reads and sets the status flags of `fd`, which `f`
    // keeps open for the duration of the calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return None;
    }
    let deadline = Instant::now() + timeout;
    let mut line: Vec<u8> = Vec::new();
    let mut reader = f;
    loop {
        let mut buf = [0u8; 64];
        match reader.read(&mut buf) {
            Ok(0) => return None,
            Ok(n) => {
                for &b in &buf[..n] {
                    if b == b'\n' || b == b'\r' {
                        return String::from_utf8(line).ok();
                    }
                    line.push(b);
                    if line.len() > MAX_ANSWER {
                        return None;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let left = deadline.checked_duration_since(Instant::now())?;
                std::thread::sleep(left.min(READ_POLL));
                if Instant::now() >= deadline {
                    return None;
                }
            }
            Err(_) => return None,
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
        prompt_on(&mut tty, req, &code, self.timeout)
        // The terminal is closed when `tty` is dropped.
    }
}

/// One approval prompt on the terminal `tty`: flush pending input, write the
/// prompt for `code`, read one answer within `timeout`. Any error denies.
fn prompt_on(tty: &mut File, req: &ApprovalRequest, code: &str, timeout: Duration) -> Decision {
    if flush_input(tty).is_err() {
        return Decision::Deny;
    }
    let text = render_prompt(req, code);
    if tty.write_all(text.as_bytes()).is_err() || tty.flush().is_err() {
        return Decision::Deny;
    }
    match read_line_with_timeout(tty, timeout) {
        Some(line) => parse_answer(&line, code, req.remember_allowed),
        None => {
            let _ = tty.write_all(b"\nno valid answer, denied\n");
            Decision::Deny
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
        "session" => Ok(Some(DevAutoApprover(Decision::AllowFor(
            GRANT_CHOICES[0].1,
        )))),
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
    use std::os::fd::FromRawFd;

    fn req(remember_allowed: bool) -> ApprovalRequest {
        ApprovalRequest {
            surface: Surface::Mcp,
            client_verified: false,
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
    fn verified_client_is_not_shown_as_declared() {
        let mut r = req(false);
        assert!(render_prompt(&r, "ab").contains("(declared, unverified)"));
        r.client_verified = true;
        r.client = "Example Agent (declared: x)".into();
        let text = render_prompt(&r, "ab");
        assert!(
            text.contains("  client: Example Agent (declared: x)\n"),
            "{text}"
        );
        assert!(!text.contains("unverified"), "{text}");
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
        assert!(text.contains("\"kq s\" for 5 min"));
        assert!(text.contains("\"kq s15\" for 15 min"));
        assert!(text.contains("\"kq s60\" for 60 min"));
        let text = render_prompt(&req(false), "kq");
        assert!(text.contains("type kq to allow once"));
        assert!(!text.contains("kq s"));
        assert!(!text.contains("min"));
    }

    #[test]
    fn parse_answer_cases() {
        assert_eq!(parse_answer("kq", "kq", true), Decision::AllowOnce);
        assert_eq!(parse_answer(" kq \n", "kq", false), Decision::AllowOnce);
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
    fn grant_choices_follow_the_grant_limits_and_have_labels() {
        assert_eq!(GRANT_CHOICES[0].1, DEFAULT_GRANT_TTL);
        assert_eq!(GRANT_CHOICES[2].1, MAX_GRANT_TTL);
        let labels: Vec<_> = GRANT_CHOICES
            .iter()
            .map(|(_, d)| decision_label(&Decision::AllowFor(*d)))
            .collect();
        assert_eq!(labels, ["grant_5m", "grant_15m", "grant_60m"]);
        assert_eq!(decision_label(&Decision::Deny), "denied");
        assert_eq!(decision_label(&Decision::AllowOnce), "once");
        assert_eq!(
            decision_label(&Decision::AllowFor(Duration::from_secs(1))),
            "grant"
        );
    }

    #[test]
    fn parse_answer_durations() {
        let min = |m: u64| Decision::AllowFor(Duration::from_secs(m * 60));
        assert_eq!(parse_answer("kq s", "kq", true), min(5));
        assert_eq!(parse_answer(" kq s\r\n", "kq", true), min(5));
        assert_eq!(parse_answer("kq s15", "kq", true), min(15));
        assert_eq!(parse_answer("kq s60", "kq", true), min(60));
        // Only the offered durations; never beyond the 60 min ceiling.
        for other in [
            "kq s5", "kq s0", "kq s30", "kq s61", "kq s120", "kq S15", "kq s 15", "kq s015",
            "kq s60s", "kq s-1", "kq 15", "kq s1e9",
        ] {
            assert_eq!(parse_answer(other, "kq", true), Decision::Deny, "{other:?}");
        }
        // No duration when remembering is not offered.
        for line in ["kq s", "kq s15", "kq s60"] {
            assert_eq!(parse_answer(line, "kq", false), Decision::Deny);
        }
        // A wrong code with a duration denies.
        assert_eq!(parse_answer("ab s15", "kq", true), Decision::Deny);
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

    /// A pseudo-terminal: (master, slave).
    fn pty() -> (File, File) {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        // SAFETY: both out pointers are valid; name, termios and winsize may
        // be null.
        let r = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(r, 0, "openpty failed");
        // SAFETY: openpty returned two fresh descriptors that we now own.
        unsafe {
            (
                File::from(std::os::fd::OwnedFd::from_raw_fd(master)),
                File::from(std::os::fd::OwnedFd::from_raw_fd(slave)),
            )
        }
    }

    /// Env var that turns [`tty_child_helper`] into the child side.
    const CHILD_ENV: &str = "ONEPASS_GUARD_TTY_CHILD_TIMEOUT_MS";

    /// Child side of the pty tests (a no-op in a normal run): opens
    /// `/dev/tty`, whose controlling terminal the parent set to a pty, runs
    /// one prompt for code `kq` and prints the decision.
    #[test]
    fn tty_child_helper() {
        let Ok(ms) = std::env::var(CHILD_ENV) else {
            return;
        };
        let timeout = Duration::from_millis(ms.parse().unwrap());
        let mut tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .unwrap();
        let d = prompt_on(&mut tty, &req(true), "kq", timeout);
        // On its own line: libtest may have printed `test ... ` already.
        println!("\ndecision={d:?}");
    }

    /// Runs [`tty_child_helper`] in a child process whose controlling
    /// terminal is the slave of a fresh pty. `answer` is written to the
    /// master after 300 ms, if any. Returns the decision printed by the
    /// child, or `None` if it did not exit within `limit`, and the time it
    /// took.
    fn prompt_in_child(
        timeout: Duration,
        answer: Option<&'static [u8]>,
        limit: Duration,
    ) -> (Option<String>, Duration) {
        use std::os::unix::process::CommandExt;
        let (master, slave) = pty();
        drain(&master);
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "approval::tests::tty_child_helper",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, timeout.as_millis().to_string())
        .stdin(std::process::Stdio::from(slave))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let start = Instant::now();
        let mut child = cmd.spawn().unwrap();
        if let Some(a) = answer {
            let mut w = master.try_clone().unwrap();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                let _ = w.write_all(a);
            });
        }
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break Some(st);
            }
            if start.elapsed() > limit {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let elapsed = start.elapsed();
        let Some(status) = status else {
            return (None, elapsed);
        };
        assert!(status.success(), "child failed: {status:?}");
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        let decision = out
            .lines()
            .find_map(|l| l.split_once("decision=").map(|(_, d)| d))
            .map(|d| d.split_whitespace().next().unwrap_or("").to_owned());
        (decision, elapsed)
    }

    /// Reads the master side in the background so prompt writes never fill
    /// the pty buffer.
    fn drain(master: &File) {
        let mut m = master.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while matches!(m.read(&mut buf), Ok(n) if n > 0) {}
        });
    }

    #[test]
    fn tty_prompt_times_out_on_a_real_terminal() {
        let timeout = Duration::from_millis(1000);
        // Process start-up is part of the limit: allow it on top.
        let (d, elapsed) =
            prompt_in_child(timeout, None, timeout + Duration::from_secs(1) + STARTUP);
        assert_eq!(d.as_deref(), Some("Deny"), "no decision after {elapsed:?}");
        assert!(elapsed >= Duration::from_millis(900));
    }

    #[test]
    fn tty_prompt_reads_the_code_ended_by_cr() {
        let (d, _) = prompt_in_child(
            Duration::from_secs(10),
            Some(b"kq\r"),
            Duration::from_secs(10) + STARTUP,
        );
        assert_eq!(d.as_deref(), Some("AllowOnce"));
    }

    /// Allowance for starting the child test process.
    const STARTUP: Duration = Duration::from_secs(2);

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
        let five = Decision::AllowFor(Duration::from_secs(300));
        let a = ScriptedApprover::new(vec![Decision::AllowOnce, five]);
        let r = req(true);
        assert_eq!(a.approve(&r), Decision::AllowOnce);
        assert_eq!(a.approve(&r), five);
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
            Decision::AllowFor(Duration::from_secs(5 * 60))
        );
        assert!(d("always", true).is_err());
        assert!(d("once", false).is_err());
        let approver = DevAutoApprover(Decision::AllowOnce);
        assert_eq!(approver.approve(&req(true)), Decision::AllowOnce);
    }
}
