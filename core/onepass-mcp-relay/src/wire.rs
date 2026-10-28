//! Messages between the relay and the app (app design spec section 4.2):
//! one JSON object per line, both ways, over the app's Unix socket. Every
//! message names its kind in `"t"`.
//!
//! Relay to app ([`RelayToApp`]):
//!
//! - `{"t":"hello","v":1,"client":{"id":..,"label":..,"signed":b,"hardened":b|null,"code":{..},"chain":[..]}}`,
//!   or `{"t":"hello","v":1,"client":null,"error":".."}` when the client
//!   could not be identified. Always the first line.
//! - `{"t":"mcp","line":".."}`: one JSON-RPC line read from the client,
//!   without its newline.
//! - `{"t":"exec_result","id":n,"ok":{"code":n|null,"stdout":"..","stderr":"..","timed_out":b,"truncated":b}}`
//!   or `{"t":"exec_result","id":n,"err":".."}`: the raw output of an
//!   `exec` (the app masks it).
//! - `{"t":"file_result","id":n,"ok":".."|null}` or
//!   `{"t":"file_result","id":n,"err":".."}`: the template text of a
//!   `read_template`, `null` for `check_output` and `write_output`, or the
//!   refusal message.
//!
//! App to relay ([`AppToRelay`]):
//!
//! - `{"t":"mcp","line":".."}`: one JSON-RPC line for the client.
//! - `{"t":"exec","id":n,"argv":[..],"env":[[name,value]..],"files":[[name,value]..],"cwd":".."|null,"timeout_secs":n}`:
//!   [`onepass_mcp::Workspace::run`].
//! - `{"t":"read_template","id":n,"path":"..","forbidden":".."|null}`:
//!   [`onepass_mcp::Workspace::read_template`].
//! - `{"t":"check_output","id":n,"path":"..","overwrite":b,"forbidden":".."|null}`:
//!   [`onepass_mcp::Workspace::check_output`].
//! - `{"t":"write_output","id":n,"path":"..","content":"..","overwrite":b,"forbidden":".."|null}`:
//!   [`onepass_mcp::Workspace::write_output`].
//!
//! `id` pairs a request with its result; requests run concurrently, so
//! results may come back in any order. `forbidden` is the data directory.
//! An unknown `"t"`, a missing field or a line over [`MAX_WIRE_LINE`] is a
//! protocol error: the reader closes the connection.
//!
//! Secret values (injected variables and files, template text, outputs,
//! MCP lines that may carry a revealed value) are held in [`Zeroizing`]
//! strings, and lines are encoded and read into zeroized buffers. The
//! `Debug` of a message shows its kind and id only.

use onepass_mcp::runner::{RunOutput, RunRequest};
use onepass_mcp::{ClientContext, MAX_LINE};
use onepass_peer::{ClientIdentity, CodeIdentity};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// Version announced in `hello`.
pub const VERSION: u32 = 1;

/// Longest line on the socket, in bytes (excluding the newline): a payload
/// of [`MAX_LINE`] bytes (an MCP line, a template) grows at most sixfold
/// once escaped as a JSON string (`\u0000`), plus the envelope.
pub const MAX_WIRE_LINE: usize = 6 * MAX_LINE + 64 * 1024;

/// The MCP client as the relay identified it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// Stable client id ([`CodeIdentity::client_id`]).
    pub id: String,
    /// Label shown to the user.
    pub label: String,
    /// True for a platform or team identity.
    pub signed: bool,
    /// Ad hoc code only: whether it runs with the hardened runtime.
    pub hardened: Option<bool>,
    /// The code identity as JSON (see [`code_json`]).
    pub code: Value,
    /// Client ids from the relay's parent up to the client.
    pub chain: Vec<String>,
}

impl ClientHello {
    /// The hello of the client `id`.
    pub fn from_identity(id: &ClientIdentity) -> Self {
        ClientHello {
            id: id.code.client_id(),
            label: client_label(&id.code),
            signed: id.code.is_signed(),
            hardened: match id.code {
                CodeIdentity::AdHoc { hardened, .. } => Some(hardened),
                _ => None,
            },
            code: code_json(&id.code),
            chain: id.chain.clone(),
        }
    }

    /// The client context of the MCP tools for this client.
    pub fn context(&self) -> ClientContext {
        ClientContext {
            client_id: self.id.clone(),
            label: self.label.clone(),
            signed: self.signed,
            hardened: self.hardened,
        }
    }
}

/// Label of a client: the signing identifier (with the team for a team
/// identity), else the executable's file name and how it is pinned.
pub fn client_label(code: &CodeIdentity) -> String {
    let file = |p: &Path| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.to_string_lossy().into_owned())
    };
    match code {
        CodeIdentity::Platform { identifier } => identifier.clone(),
        CodeIdentity::Team {
            team_id,
            identifier,
        } => format!("{identifier} ({team_id})"),
        CodeIdentity::AdHoc { path, .. } => format!("{} (ad hoc)", file(path)),
        CodeIdentity::Unsigned { path, .. } => format!("{} (unsigned)", file(path)),
    }
}

/// A code identity as JSON, `kind` first: `platform` (`identifier`),
/// `team` (`team_id`, `identifier`), `adhoc` (`path`, `cdhash`,
/// `hardened`) or `unsigned` (`path`, `sha256`).
pub fn code_json(code: &CodeIdentity) -> Value {
    match code {
        CodeIdentity::Platform { identifier } => {
            json!({"kind": "platform", "identifier": identifier})
        }
        CodeIdentity::Team {
            team_id,
            identifier,
        } => json!({"kind": "team", "team_id": team_id, "identifier": identifier}),
        CodeIdentity::AdHoc {
            path,
            cdhash,
            hardened,
        } => json!({
            "kind": "adhoc",
            "path": path.to_string_lossy(),
            "cdhash": cdhash,
            "hardened": hardened,
        }),
        CodeIdentity::Unsigned { path, sha256 } => json!({
            "kind": "unsigned",
            "path": path.to_string_lossy(),
            "sha256": sha256,
        }),
    }
}

/// The outcome of a request: `"ok"` with its value, or `"err"` with a
/// message free of secret values.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reply<T> {
    /// Done.
    Ok(T),
    /// Refused or failed: the message the agent gets.
    Err(String),
}

/// The raw output of a command, as [`RunOutput`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutput {
    /// Exit code, `None` when killed by a signal.
    pub code: Option<i32>,
    /// Standard output, unmasked.
    pub stdout: Zeroizing<String>,
    /// Standard error, unmasked.
    pub stderr: Zeroizing<String>,
    /// The command was killed at the timeout.
    pub timed_out: bool,
    /// One of the streams was cut.
    pub truncated: bool,
}

impl From<RunOutput> for ExecOutput {
    fn from(o: RunOutput) -> Self {
        ExecOutput {
            code: o.code,
            stdout: o.stdout,
            stderr: o.stderr,
            timed_out: o.timed_out,
            truncated: o.truncated,
        }
    }
}

impl From<ExecOutput> for RunOutput {
    fn from(o: ExecOutput) -> Self {
        RunOutput {
            code: o.code,
            stdout: o.stdout,
            stderr: o.stderr,
            timed_out: o.timed_out,
            truncated: o.truncated,
        }
    }
}

/// A message from the relay to the app.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum RelayToApp {
    /// First line: who the client is.
    Hello {
        /// Protocol version, [`VERSION`].
        v: u32,
        /// The client, `None` when it could not be identified.
        client: Option<ClientHello>,
        /// Why the client could not be identified.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// One JSON-RPC line from the client.
    Mcp {
        /// The line, without its newline.
        line: Zeroizing<String>,
    },
    /// Result of an `exec`.
    ExecResult {
        /// The request's id.
        id: u64,
        /// The output, or why the command could not run.
        #[serde(flatten)]
        result: Reply<ExecOutput>,
    },
    /// Result of a file request: the template text, or `None`.
    FileResult {
        /// The request's id.
        id: u64,
        /// The template text (`read_template`), `None` otherwise, or the
        /// refusal.
        #[serde(flatten)]
        result: Reply<Option<Zeroizing<String>>>,
    },
}

/// A message from the app to the relay.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum AppToRelay {
    /// One JSON-RPC line for the client.
    Mcp {
        /// The line, without its newline.
        line: Zeroizing<String>,
    },
    /// Run a command ([`RunRequest`]).
    Exec {
        /// Request id, echoed in the result.
        id: u64,
        /// Program and arguments, run without a shell.
        argv: Vec<String>,
        /// Variables to inject, name and secret value.
        env: Vec<(String, Zeroizing<String>)>,
        /// Secret files, variable name and content.
        files: Vec<(String, Zeroizing<String>)>,
        /// Working directory, the relay's own when `None`.
        cwd: Option<String>,
        /// Timeout, in seconds.
        timeout_secs: u64,
    },
    /// Read a template.
    ReadTemplate {
        /// Request id, echoed in the result.
        id: u64,
        /// Template path, as the agent gave it.
        path: String,
        /// The data directory.
        forbidden: Option<String>,
    },
    /// Check where an output may go.
    CheckOutput {
        /// Request id, echoed in the result.
        id: u64,
        /// Output path, as the agent gave it.
        path: String,
        /// Whether an existing file may be replaced.
        overwrite: bool,
        /// The data directory.
        forbidden: Option<String>,
    },
    /// Check again, then write an output with mode `0600`.
    WriteOutput {
        /// Request id, echoed in the result.
        id: u64,
        /// Output path, as the agent gave it.
        path: String,
        /// The rendered template.
        content: Zeroizing<String>,
        /// Whether an existing file may be replaced.
        overwrite: bool,
        /// The data directory.
        forbidden: Option<String>,
    },
}

impl AppToRelay {
    /// The `exec` message of `req` (the timeout rounded up to a second).
    pub fn exec(id: u64, req: &RunRequest) -> Self {
        let secs = req.timeout.as_secs() + u64::from(req.timeout.subsec_nanos() > 0);
        AppToRelay::Exec {
            id,
            argv: req.argv.clone(),
            env: req.env.clone(),
            files: req.files.clone(),
            cwd: req.cwd.as_ref().map(|p| p.to_string_lossy().into_owned()),
            timeout_secs: secs,
        }
    }
}

/// The [`RunRequest`] of an `exec` message's fields.
pub fn run_request(
    argv: Vec<String>,
    env: Vec<(String, Zeroizing<String>)>,
    files: Vec<(String, Zeroizing<String>)>,
    cwd: Option<String>,
    timeout_secs: u64,
) -> RunRequest {
    RunRequest {
        argv,
        env,
        files,
        cwd: cwd.map(Into::into),
        timeout: Duration::from_secs(timeout_secs),
    }
}

impl fmt::Debug for RelayToApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayToApp::Hello { v, client, error } => f
                .debug_struct("Hello")
                .field("v", v)
                .field("client", client)
                .field("error", error)
                .finish(),
            RelayToApp::Mcp { line } => f.debug_struct("Mcp").field("len", &line.len()).finish(),
            RelayToApp::ExecResult { id, result } => f
                .debug_struct("ExecResult")
                .field("id", id)
                .field("ok", &matches!(result, Reply::Ok(_)))
                .finish(),
            RelayToApp::FileResult { id, result } => f
                .debug_struct("FileResult")
                .field("id", id)
                .field("ok", &matches!(result, Reply::Ok(_)))
                .finish(),
        }
    }
}

impl fmt::Debug for AppToRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, id) = match self {
            AppToRelay::Mcp { line } => {
                return f.debug_struct("Mcp").field("len", &line.len()).finish();
            }
            AppToRelay::Exec { id, .. } => ("Exec", id),
            AppToRelay::ReadTemplate { id, .. } => ("ReadTemplate", id),
            AppToRelay::CheckOutput { id, .. } => ("CheckOutput", id),
            AppToRelay::WriteOutput { id, .. } => ("WriteOutput", id),
        };
        f.debug_struct(kind).field("id", id).finish()
    }
}

/// Why a line could not be encoded or decoded. Never holds message
/// content.
#[derive(Debug)]
pub enum WireError {
    /// Over [`MAX_WIRE_LINE`] bytes.
    TooLong,
    /// Not a known message (bad JSON, unknown `"t"`, missing field).
    Malformed,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WireError::TooLong => "message too long",
            WireError::Malformed => "malformed message",
        })
    }
}

impl std::error::Error for WireError {}

/// Appends `data` to `buf`, moving to a larger buffer when needed so the
/// old one is zeroized rather than left behind by a reallocation.
fn extend_zeroizing(buf: &mut Zeroizing<Vec<u8>>, data: &[u8]) {
    let need = buf.len() + data.len();
    if need > buf.capacity() {
        let mut bigger = Zeroizing::new(Vec::with_capacity(need.max(2 * buf.capacity())));
        bigger.extend_from_slice(buf);
        std::mem::swap(buf, &mut bigger);
    }
    buf.extend_from_slice(data);
}

/// A writer into a zeroized buffer that refuses to grow past `max` bytes.
struct BoundedWriter {
    buf: Zeroizing<Vec<u8>>,
    max: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len() + data.len() > self.max {
            return Err(io::Error::other("too long"));
        }
        extend_zeroizing(&mut self.buf, data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `msg` as one line, newline included, in a zeroized buffer.
pub fn encode<T: Serialize>(msg: &T) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let mut w = BoundedWriter {
        buf: Zeroizing::new(Vec::with_capacity(256)),
        max: MAX_WIRE_LINE,
    };
    serde_json::to_writer(&mut w, msg).map_err(|e| {
        if e.is_io() {
            WireError::TooLong
        } else {
            WireError::Malformed
        }
    })?;
    extend_zeroizing(&mut w.buf, b"\n");
    Ok(w.buf)
}

/// The message on `line` (without its newline).
pub fn decode<T: DeserializeOwned>(line: &[u8]) -> Result<T, WireError> {
    if line.len() > MAX_WIRE_LINE {
        return Err(WireError::TooLong);
    }
    serde_json::from_slice(line).map_err(|_| WireError::Malformed)
}

/// One line read by a [`LineReader`].
pub enum Line {
    /// A line, without its newline (the last one may lack it).
    Complete(Zeroizing<Vec<u8>>),
    /// A line over the limit, read and dropped.
    TooLong,
}

/// Reads bounded lines from an unbuffered reader into zeroized buffers.
pub struct LineReader<R> {
    inner: R,
    max: usize,
    buf: Zeroizing<Vec<u8>>,
    pos: usize,
    filled: usize,
}

impl<R: Read> LineReader<R> {
    /// Lines of at most `max` bytes from `inner`.
    pub fn new(inner: R, max: usize) -> Self {
        LineReader {
            inner,
            max,
            buf: Zeroizing::new(vec![0; 64 * 1024]),
            pos: 0,
            filled: 0,
        }
    }

    /// The next line, `None` at the end of the input.
    pub fn next_line(&mut self) -> io::Result<Option<Line>> {
        let mut line = Zeroizing::new(Vec::new());
        let mut started = false;
        let mut too_long = false;
        loop {
            if self.pos == self.filled {
                let n = loop {
                    match self.inner.read(&mut self.buf[..]) {
                        Ok(n) => break n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                };
                if n == 0 {
                    return Ok(match (started, too_long) {
                        (false, _) => None,
                        (true, true) => Some(Line::TooLong),
                        (true, false) => Some(Line::Complete(line)),
                    });
                }
                self.pos = 0;
                self.filled = n;
            }
            started = true;
            let avail = &self.buf[self.pos..self.filled];
            let (part, end) = match avail.iter().position(|&b| b == b'\n') {
                Some(i) => (&avail[..i], Some(i + 1)),
                None => (avail, None),
            };
            if !too_long {
                if line.len() + part.len() > self.max {
                    too_long = true;
                    line.zeroize();
                } else {
                    extend_zeroizing(&mut line, part);
                }
            }
            match end {
                Some(skip) => {
                    self.pos += skip;
                    return Ok(Some(if too_long {
                        Line::TooLong
                    } else {
                        Line::Complete(line)
                    }));
                }
                None => self.pos = self.filled,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    fn round_trip<T>(msg: &T, expected: Value)
    where
        T: Serialize + DeserializeOwned + PartialEq + fmt::Debug,
    {
        let line = encode(msg).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        let body = &line[..line.len() - 1];
        assert!(!body.contains(&b'\n'));
        let as_json: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(as_json, expected);
        let back: T = decode(body).unwrap();
        assert!(back == *msg, "{back:?} != {msg:?}");
    }

    fn hello_client() -> ClientHello {
        ClientHello::from_identity(&ClientIdentity {
            code: CodeIdentity::Team {
                team_id: "TEAM123".into(),
                identifier: "com.example.agent".into(),
            },
            pid: 42,
            exe: None,
            chain: vec![
                "platform:com.apple.zsh".into(),
                "team:TEAM123:com.example.agent".into(),
            ],
        })
    }

    #[test]
    fn hello_round_trips() {
        round_trip(
            &RelayToApp::Hello {
                v: VERSION,
                client: Some(hello_client()),
                error: None,
            },
            json!({"t": "hello", "v": 1, "client": {
                "id": "team:TEAM123:com.example.agent",
                "label": "com.example.agent (TEAM123)",
                "signed": true,
                "hardened": null,
                "code": {"kind": "team", "team_id": "TEAM123", "identifier": "com.example.agent"},
                "chain": ["platform:com.apple.zsh", "team:TEAM123:com.example.agent"],
            }}),
        );
        round_trip(
            &RelayToApp::Hello {
                v: VERSION,
                client: None,
                error: Some("the client process is gone".into()),
            },
            json!({"t": "hello", "v": 1, "client": null, "error": "the client process is gone"}),
        );
    }

    #[test]
    fn identity_rules() {
        let adhoc = ClientIdentity {
            code: CodeIdentity::AdHoc {
                path: PathBuf::from("/usr/local/bin/agent"),
                cdhash: "ab12".into(),
                hardened: false,
            },
            pid: 7,
            exe: None,
            chain: vec!["adhoc:ab12".into()],
        };
        let h = ClientHello::from_identity(&adhoc);
        assert_eq!(h.id, "adhoc:ab12");
        assert_eq!(h.label, "agent (ad hoc)");
        assert!(!h.signed);
        assert_eq!(h.hardened, Some(false));
        assert_eq!(
            h.code,
            json!({"kind": "adhoc", "path": "/usr/local/bin/agent", "cdhash": "ab12", "hardened": false})
        );
        let c = h.context();
        assert_eq!(c.client_id, "adhoc:ab12");
        assert_eq!(c.label, "agent (ad hoc)");
        assert_eq!(c.hardened, Some(false));
        let platform = CodeIdentity::Platform {
            identifier: "com.apple.Terminal".into(),
        };
        assert_eq!(client_label(&platform), "com.apple.Terminal");
        let unsigned = CodeIdentity::Unsigned {
            path: PathBuf::from("/opt/agent"),
            sha256: "ff".into(),
        };
        assert_eq!(client_label(&unsigned), "agent (unsigned)");
        assert_eq!(
            code_json(&unsigned),
            json!({"kind": "unsigned", "path": "/opt/agent", "sha256": "ff"})
        );
    }

    #[test]
    fn relay_messages_round_trip() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        round_trip(
            &RelayToApp::Mcp { line: z(line) },
            json!({"t": "mcp", "line": line}),
        );
        round_trip(
            &RelayToApp::ExecResult {
                id: 3,
                result: Reply::Ok(ExecOutput {
                    code: Some(0),
                    stdout: z("out"),
                    stderr: z("err"),
                    timed_out: false,
                    truncated: true,
                }),
            },
            json!({"t": "exec_result", "id": 3, "ok": {
                "code": 0, "stdout": "out", "stderr": "err", "timed_out": false, "truncated": true,
            }}),
        );
        round_trip(
            &RelayToApp::ExecResult {
                id: 4,
                result: Reply::Ok(ExecOutput {
                    code: None,
                    stdout: z(""),
                    stderr: z(""),
                    timed_out: true,
                    truncated: false,
                }),
            },
            json!({"t": "exec_result", "id": 4, "ok": {
                "code": null, "stdout": "", "stderr": "", "timed_out": true, "truncated": false,
            }}),
        );
        round_trip(
            &RelayToApp::ExecResult {
                id: 5,
                result: Reply::Err("command could not be started: entity not found".into()),
            },
            json!({"t": "exec_result", "id": 5, "err": "command could not be started: entity not found"}),
        );
        round_trip(
            &RelayToApp::FileResult {
                id: 6,
                result: Reply::Ok(Some(z("A={{ onepass://V/I/f }}"))),
            },
            json!({"t": "file_result", "id": 6, "ok": "A={{ onepass://V/I/f }}"}),
        );
        round_trip(
            &RelayToApp::FileResult {
                id: 7,
                result: Reply::Ok(None),
            },
            json!({"t": "file_result", "id": 7, "ok": null}),
        );
        round_trip(
            &RelayToApp::FileResult {
                id: 8,
                result: Reply::Err("output path is inside the data directory".into()),
            },
            json!({"t": "file_result", "id": 8, "err": "output path is inside the data directory"}),
        );
    }

    #[test]
    fn app_messages_round_trip() {
        round_trip(
            &AppToRelay::Mcp { line: z("{}") },
            json!({"t": "mcp", "line": "{}"}),
        );
        round_trip(
            &AppToRelay::Exec {
                id: 1,
                argv: vec!["sh".into(), "-c".into(), "true".into()],
                env: vec![("TOKEN".into(), z("v1"))],
                files: vec![("KEY".into(), z("v2"))],
                cwd: Some("/tmp".into()),
                timeout_secs: 60,
            },
            json!({"t": "exec", "id": 1, "argv": ["sh", "-c", "true"],
                "env": [["TOKEN", "v1"]], "files": [["KEY", "v2"]], "cwd": "/tmp", "timeout_secs": 60}),
        );
        round_trip(
            &AppToRelay::ReadTemplate {
                id: 2,
                path: "/in.tpl".into(),
                forbidden: None,
            },
            json!({"t": "read_template", "id": 2, "path": "/in.tpl", "forbidden": null}),
        );
        round_trip(
            &AppToRelay::CheckOutput {
                id: 3,
                path: "/out".into(),
                overwrite: false,
                forbidden: Some("/data".into()),
            },
            json!({"t": "check_output", "id": 3, "path": "/out", "overwrite": false, "forbidden": "/data"}),
        );
        round_trip(
            &AppToRelay::WriteOutput {
                id: 4,
                path: "/out".into(),
                content: z("A=s3cret\n"),
                overwrite: true,
                forbidden: Some("/data".into()),
            },
            json!({"t": "write_output", "id": 4, "path": "/out", "content": "A=s3cret\n",
                "overwrite": true, "forbidden": "/data"}),
        );
    }

    #[test]
    fn exec_from_and_to_a_run_request() {
        let req = RunRequest {
            argv: vec!["x".into()],
            env: vec![("A".into(), z("1"))],
            files: Vec::new(),
            cwd: Some(PathBuf::from("/w")),
            timeout: Duration::from_millis(1500),
        };
        let AppToRelay::Exec {
            argv,
            env,
            files,
            cwd,
            timeout_secs,
            ..
        } = AppToRelay::exec(9, &req)
        else {
            panic!("not an exec");
        };
        assert_eq!(timeout_secs, 2);
        let back = run_request(argv, env, files, cwd, timeout_secs);
        assert_eq!(back.argv, req.argv);
        assert_eq!(back.env, req.env);
        assert_eq!(back.cwd, req.cwd);
        assert_eq!(back.timeout, Duration::from_secs(2));
    }

    #[test]
    fn unknown_kind_and_bad_fields_are_refused() {
        for bad in [
            r#"{"t":"shell","cmd":"rm -rf /"}"#,
            r#"{"line":"x"}"#,
            r#"{"t":"exec","id":1}"#,
            r#"{"t":"file_result","id":1}"#,
            "not json",
        ] {
            assert!(
                matches!(
                    decode::<AppToRelay>(bad.as_bytes()),
                    Err(WireError::Malformed)
                ) && matches!(
                    decode::<RelayToApp>(bad.as_bytes()),
                    Err(WireError::Malformed)
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn oversize_lines_are_refused() {
        let big = "x".repeat(MAX_WIRE_LINE);
        let msg = AppToRelay::WriteOutput {
            id: 1,
            path: "/o".into(),
            content: Zeroizing::new(big),
            overwrite: false,
            forbidden: None,
        };
        assert!(matches!(encode(&msg), Err(WireError::TooLong)));
        let line = vec![b' '; MAX_WIRE_LINE + 1];
        assert!(matches!(
            decode::<AppToRelay>(&line),
            Err(WireError::TooLong)
        ));
        // A payload of MAX_LINE control characters still fits once escaped.
        let worst = "\u{1}".repeat(MAX_LINE);
        let line = encode(&RelayToApp::Mcp { line: z(&worst) }).unwrap();
        assert!(line.len() <= MAX_WIRE_LINE);
    }

    #[test]
    fn debug_shows_no_value() {
        let msg = AppToRelay::Exec {
            id: 5,
            argv: vec!["x".into()],
            env: vec![("T".into(), z("very-secret"))],
            files: Vec::new(),
            cwd: None,
            timeout_secs: 1,
        };
        let d = format!("{msg:?}");
        assert!(!d.contains("very-secret"), "{d}");
        assert_eq!(d, "Exec { id: 5 }");
        let r = RelayToApp::FileResult {
            id: 2,
            result: Reply::Ok(Some(z("very-secret"))),
        };
        assert!(!format!("{r:?}").contains("very-secret"));
    }

    #[test]
    fn line_reader_bounds_lines() {
        let input: &[u8] = b"one\n\ntoo long line\nlast";
        let mut r = LineReader::new(input, 8);
        let mut got = Vec::new();
        while let Some(l) = r.next_line().unwrap() {
            got.push(match l {
                Line::Complete(b) => String::from_utf8(b.to_vec()).unwrap(),
                Line::TooLong => "<too long>".into(),
            });
        }
        assert_eq!(got, ["one", "", "<too long>", "last"]);
    }

    #[test]
    fn line_reader_spans_chunks() {
        let mut input = vec![b'a'; 200_000];
        input.push(b'\n');
        input.extend_from_slice(b"b\n");
        let mut r = LineReader::new(&input[..], 300_000);
        let Some(Line::Complete(first)) = r.next_line().unwrap() else {
            panic!("no first line");
        };
        assert_eq!(first.len(), 200_000);
        let Some(Line::Complete(second)) = r.next_line().unwrap() else {
            panic!("no second line");
        };
        assert_eq!(&second[..], b"b");
        assert!(r.next_line().unwrap().is_none());
    }
}
