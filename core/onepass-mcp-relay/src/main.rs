//! `onepass-mcp --socket <path>`: the stdio MCP server that MCP clients
//! launch, a relay to the OnePass app (see the library's [`wire`] module
//! for the messages).
//!
//! The main thread reads the app's messages: `mcp` lines go to stdout,
//! requests run each on its own thread (a long command never blocks the
//! relaying) with [`LocalWorkspace`], so the checks are those of the CLI.
//! Another thread turns stdin lines into `mcp` messages and, at the end of
//! stdin, shuts down the socket's write half. Replies share one writer
//! behind a mutex. Stdout carries MCP lines only; errors go to stderr, one
//! line, never with a value.
//!
//! [`wire`]: onepass_mcp_relay::wire
#![deny(unsafe_code)]
// The relay itself is Unix only until the named pipe of milestone X3;
// `install` and `uninstall` work everywhere.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use onepass_mcp::{LocalWorkspace, MAX_LINE, Workspace};
use onepass_mcp_relay::install;
use onepass_mcp_relay::wire::{
    AppToRelay, ClientHello, Line, LineReader, MAX_WIRE_LINE, RelayToApp, Reply, VERSION, decode,
    encode, run_request,
};
use serde_json::json;
use std::ffi::OsString;
use std::io::{self, Write};
use std::net::Shutdown;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zeroize::Zeroizing;

const USAGE: &str = "usage: onepass-mcp --socket <path>\n       onepass-mcp install|uninstall --client <claude-code|claude-desktop|codex|cursor> [--dry-run] [--force] [--with-docs] [--home <dir>] [--socket <path>]";

/// `EX_USAGE` of sysexits.h.
const EXIT_USAGE: u8 = 64;
/// `EX_UNAVAILABLE` of sysexits.h.
#[cfg(not(unix))]
const EXIT_UNAVAILABLE: u8 = 69;

/// The socket path of `--socket <path>` or `--socket=<path>`, the only
/// arguments accepted.
fn socket_arg(args: &[OsString]) -> Option<PathBuf> {
    match args {
        [flag, path] if flag == "--socket" && !path.is_empty() => Some(PathBuf::from(path)),
        [one] => one
            .to_str()
            .and_then(|s| s.strip_prefix("--socket="))
            .filter(|p| !p.is_empty())
            .map(PathBuf::from),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // Anything else is the relay itself, which MCP clients launch with
    // `--socket`; the two subcommands configure those clients.
    let action = match args.first().and_then(|a| a.to_str()) {
        Some("install") => Some(install::Action::Install),
        Some("uninstall") => Some(install::Action::Uninstall),
        _ => None,
    };
    if let Some(action) = action {
        return match install::run(action, &args[1..], &mut io::stdout()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(install::Error::Usage(m)) => {
                eprintln!("onepass-mcp: {m}");
                ExitCode::from(EXIT_USAGE)
            }
            Err(install::Error::Failed(m)) => {
                eprintln!("onepass-mcp: {m}");
                ExitCode::FAILURE
            }
        };
    }
    let Some(socket) = socket_arg(&args) else {
        eprintln!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };
    // Identify the client before connecting: on Linux this hashes the
    // client's executable, which can take seconds for a large binary on a
    // busy machine, and the app waits only a few seconds for the hello.
    let hello = hello();
    #[cfg(not(unix))]
    {
        // The app's socket is a named pipe on Windows (milestone X3).
        let _ = (socket, hello);
        eprintln!("onepass-mcp: the relay is not available on this system yet");
        ExitCode::from(EXIT_UNAVAILABLE)
    }
    #[cfg(unix)]
    {
        match relay(socket, hello) {
            Ok(()) => ExitCode::SUCCESS,
            Err(m) => {
                eprintln!("onepass-mcp: {m}");
                ExitCode::FAILURE
            }
        }
    }
}

/// The write half of the socket, shared by every thread that answers.
#[cfg(unix)]
struct Writer(Mutex<UnixStream>);

#[cfg(unix)]
impl Writer {
    fn lock(&self) -> std::sync::MutexGuard<'_, UnixStream> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sends one encoded line.
    fn send_line(&self, line: &[u8]) -> io::Result<()> {
        self.lock().write_all(line)
    }

    /// Sends `msg`.
    fn send(&self, msg: &RelayToApp) -> io::Result<()> {
        let line = encode(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.send_line(&line)
    }

    /// No more messages from the client.
    fn shutdown(&self) {
        let _ = self.lock().shutdown(Shutdown::Write);
    }
}

/// The first message: who the MCP client is, or why it is unknown.
fn hello() -> RelayToApp {
    match onepass_peer::identify_mcp_parent() {
        Ok(id) => RelayToApp::Hello {
            v: VERSION,
            client: Some(ClientHello::from_identity(&id)),
            error: None,
        },
        Err(e) => RelayToApp::Hello {
            v: VERSION,
            client: None,
            error: Some(e.to_string()),
        },
    }
}

/// How often a relay without the app tries the socket again.
#[cfg(unix)]
const RETRY: Duration = Duration::from_secs(2);

/// What a tool call gets while the app is away.
const AWAY: &str = "OnePass is locked or not running. Unlock it, then try again.";

/// The two fields of a JSON-RPC line the relay looks at. The others are
/// skipped unread, so a tool's arguments or result are never copied.
#[derive(serde::Deserialize)]
struct Head {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    method: Option<String>,
}

fn head(line: &str) -> Option<Head> {
    serde_json::from_str(line).ok()
}

/// What the main loop hears from the client and from the app.
#[cfg(unix)]
enum Event {
    /// A client line, valid UTF-8 and within `MAX_LINE`.
    Client(Zeroizing<String>),
    /// The end of stdin.
    ClientEnd,
    /// A message of connection `gen`.
    App(u64, AppToRelay),
    /// Connection `gen` closed or failed (the app locked, quit or relaunched).
    AppGone(u64),
    /// Connection `gen` broke the protocol: the relay ends.
    AppBroken(u64, String),
}

/// The live connection to the app.
#[cfg(unix)]
struct Conn {
    generation: u64,
    writer: Arc<Writer>,
    /// The client's requests sent on it and not answered yet, with whether
    /// each is a tool call.
    pending: Vec<(serde_json::Value, bool)>,
    /// The id of the replayed `initialize`, whose reply the client already had.
    swallow: Option<serde_json::Value>,
}

/// The relay's state across connections. The app stops its MCP server on
/// every lock and closes the socket: the relay keeps the client, answers
/// for the app while it is away, then connects again, replays the client's
/// `initialize` and tells the client the tools changed.
#[cfg(unix)]
struct Session {
    socket: PathBuf,
    hello: RelayToApp,
    events: Sender<Event>,
    conn: Option<Conn>,
    generation: u64,
    /// The client's `initialize` and `notifications/initialized` lines: no
    /// vault data, replayed to every new connection.
    initialize: Option<(Zeroizing<String>, serde_json::Value)>,
    initialized: Option<Zeroizing<String>>,
    /// The client finished its handshake once: a new connection then means
    /// the tools may have changed.
    handshake_done: bool,
    client_ended: bool,
    told_away: bool,
    workers: Vec<JoinHandle<()>>,
}

#[cfg(unix)]
impl Session {
    /// Connects when the app listens; false while it does not.
    fn connect(&mut self) -> bool {
        let Ok(stream) = UnixStream::connect(&self.socket) else {
            if !self.told_away {
                self.told_away = true;
                eprintln!(
                    "onepass-mcp: OnePass is not running or the MCP server is off in its settings, waiting for it"
                );
            }
            return false;
        };
        let Ok(write_half) = stream.try_clone() else {
            return false;
        };
        let writer = Arc::new(Writer(Mutex::new(write_half)));
        if writer.send(&self.hello).is_err() {
            return false;
        }
        self.generation += 1;
        let generation = self.generation;
        let events = self.events.clone();
        thread::spawn(move || read_app(stream, generation, &events));
        let mut conn = Conn {
            generation,
            writer,
            pending: Vec::new(),
            swallow: None,
        };
        if let Some((line, id)) = &self.initialize {
            let replay = |l: &Zeroizing<String>| RelayToApp::Mcp { line: l.clone() };
            if conn.writer.send(&replay(line)).is_err() {
                return false;
            }
            conn.swallow = Some(id.clone());
            if let Some(note) = &self.initialized
                && conn.writer.send(&replay(note)).is_err()
            {
                return false;
            }
        }
        self.conn = Some(conn);
        self.told_away = false;
        if self.handshake_done {
            eprintln!("onepass-mcp: connected to OnePass again");
            let changed = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
            let _ = to_stdout(&changed.to_string());
        }
        true
    }

    /// A line from the client: to the app, or answered here while it is away.
    fn client(&mut self, line: Zeroizing<String>) -> io::Result<()> {
        let head = head(&line);
        let method = head.as_ref().and_then(|h| h.method.as_deref());
        let id = head.as_ref().and_then(|h| h.id.clone());
        match (method, &id) {
            (Some("initialize"), Some(id)) => self.initialize = Some((line.clone(), id.clone())),
            (Some("notifications/initialized"), None) => {
                self.initialized = Some(line.clone());
                self.handshake_done = true;
            }
            _ => {}
        }
        if let Some(conn) = &mut self.conn {
            if let (Some(m), Some(id)) = (method, &id) {
                conn.pending.push((id.clone(), m == "tools/call"));
            }
            // A failed write means the app went away: its reader reports
            // it, and the request is answered with the pending ones.
            let _ = conn.writer.send(&RelayToApp::Mcp { line });
            return Ok(());
        }
        match (method, id) {
            (Some(m), Some(id)) => away_reply(m, &id, &line),
            // Notifications wait for the app (initialized is replayed).
            _ => Ok(()),
        }
    }

    /// A message of the app on the live connection.
    fn app(&mut self, msg: AppToRelay) -> io::Result<()> {
        let Some(conn) = &mut self.conn else {
            return Ok(());
        };
        if let AppToRelay::Mcp { line } = msg {
            let id = head(&line).and_then(|h| h.id);
            if let Some(id) = &id {
                if conn.swallow.as_ref() == Some(id) {
                    conn.swallow = None;
                    return Ok(());
                }
                conn.pending.retain(|(p, _)| p != id);
            }
            let first_reply = id.is_some()
                && self.initialize.as_ref().map(|(_, i)| i) == id.as_ref()
                && !self.handshake_done;
            if first_reply {
                return to_stdout(&with_list_changed(&line));
            }
            return to_stdout(&line);
        }
        self.workers.retain(|w| !w.is_finished());
        let writer = conn.writer.clone();
        self.workers
            .push(thread::spawn(move || answer(&writer, msg)));
        Ok(())
    }

    /// The live connection closed: every request still waiting is answered.
    fn app_gone(&mut self) -> io::Result<()> {
        let Some(conn) = self.conn.take() else {
            return Ok(());
        };
        if !self.client_ended {
            eprintln!(
                "onepass-mcp: OnePass closed the connection (locked or quit), waiting for it"
            );
        }
        for (id, tool) in conn.pending {
            if tool {
                to_stdout(&tool_error(&id).to_string())?;
            } else {
                to_stdout(&rpc_error(&id).to_string())?;
            }
        }
        Ok(())
    }

    fn is_current(&self, generation: u64) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|c| c.generation == generation)
    }
}

/// The app's reply to the first `initialize`, with `tools.listChanged` on
/// so the client refetches the tools after a reconnection. A line that is
/// not the expected shape goes out unchanged.
fn with_list_changed(line: &str) -> String {
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.to_owned();
    };
    let Some(caps) = v
        .get_mut("result")
        .and_then(|r| r.get_mut("capabilities"))
        .and_then(|c| c.as_object_mut())
    else {
        return line.to_owned();
    };
    let tools = caps.entry("tools").or_insert_with(|| json!({}));
    if let Some(t) = tools.as_object_mut() {
        t.insert("listChanged".into(), json!(true));
    }
    v.to_string()
}

fn tool_error(id: &serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {
        "content": [{"type": "text", "text": AWAY}],
        "isError": true,
    }})
}

fn rpc_error(id: &serde_json::Value) -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": AWAY}})
}

/// The relay's own answer to a request while the app is away: the
/// handshake, ping and an empty tool list work, a tool call says why it
/// cannot run, anything else is an error.
fn away_reply(method: &str, id: &serde_json::Value, line: &str) -> io::Result<()> {
    let reply = match method {
        "initialize" => {
            let asked = serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| v["params"]["protocolVersion"].as_str().map(str::to_owned))
                .unwrap_or_else(|| "2025-06-18".to_owned());
            json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": asked,
                "capabilities": {"logging": {}, "tools": {"listChanged": true}},
                "serverInfo": {"name": "onepass", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "OnePass vault access. OnePass is locked or not running: its tools appear once it is unlocked.",
            }})
        }
        "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        "tools/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}}),
        "tools/call" => tool_error(id),
        _ => rpc_error(id),
    };
    to_stdout(&reply.to_string())
}

/// Reads connection `generation` until it ends.
#[cfg(unix)]
fn read_app(stream: UnixStream, generation: u64, events: &Sender<Event>) {
    let mut reader = LineReader::new(stream, MAX_WIRE_LINE);
    let event = loop {
        let line = match reader.next_line() {
            Ok(Some(Line::Complete(line))) => line,
            Ok(Some(Line::TooLong)) => {
                break Event::AppBroken(generation, "message too long from OnePass".into());
            }
            Ok(None) | Err(_) => break Event::AppGone(generation),
        };
        match decode::<AppToRelay>(&line) {
            Ok(AppToRelay::Mcp { line }) if line.contains('\n') => {
                break Event::AppBroken(generation, "malformed message from OnePass".into());
            }
            Ok(msg) => {
                if events.send(Event::App(generation, msg)).is_err() {
                    return;
                }
            }
            Err(e) => break Event::AppBroken(generation, format!("{e} from OnePass")),
        }
    };
    let _ = events.send(event);
}

/// Relays until the client ends, across the app's locks and relaunches.
#[cfg(unix)]
fn relay(socket: PathBuf, hello: RelayToApp) -> Result<(), String> {
    let (events, inbox) = channel();
    {
        let events = events.clone();
        thread::spawn(move || pump_stdin(&events));
    }
    let mut s = Session {
        socket,
        hello,
        events,
        conn: None,
        generation: 0,
        initialize: None,
        initialized: None,
        handshake_done: false,
        client_ended: false,
        told_away: false,
        workers: Vec::new(),
    };
    s.connect();
    let result = loop {
        let wait = if s.conn.is_some() || s.client_ended {
            Duration::from_secs(3600)
        } else {
            RETRY
        };
        let event = match inbox.recv_timeout(wait) {
            Ok(e) => e,
            Err(RecvTimeoutError::Timeout) => {
                if s.conn.is_none() && !s.client_ended {
                    s.connect();
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break Ok(()),
        };
        let step = match event {
            Event::Client(line) => s.client(line),
            Event::ClientEnd => {
                s.client_ended = true;
                match &s.conn {
                    // The app closes once it has the end: then the relay ends.
                    Some(c) => {
                        c.writer.shutdown();
                        Ok(())
                    }
                    None => break Ok(()),
                }
            }
            Event::App(g, msg) if s.is_current(g) => s.app(msg),
            Event::AppGone(g) if s.is_current(g) => {
                if let Err(e) = s.app_gone() {
                    Err(e)
                } else if s.client_ended {
                    break Ok(());
                } else {
                    // A relaunched app may already listen.
                    s.connect();
                    Ok(())
                }
            }
            Event::AppBroken(g, m) if s.is_current(g) => break Err(m),
            // A message of an older connection.
            _ => Ok(()),
        };
        if step.is_err() {
            // The client is gone (stdout closed).
            break Ok(());
        }
    };
    // A command still running keeps its injected values: let it end (its
    // timeout bounds the wait) rather than orphan it.
    for w in s.workers {
        let _ = w.join();
    }
    result
}

/// Writes one MCP line to stdout and flushes.
fn to_stdout(line: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()
}

/// Hands stdin lines to the main loop until the end of stdin. A line too
/// long or not UTF-8 gets the server's parse error on stdout, as `onepass
/// mcp` would answer.
#[cfg(unix)]
fn pump_stdin(events: &Sender<Event>) {
    let mut input = LineReader::new(io::stdin(), MAX_LINE);
    loop {
        let error = match input.next_line() {
            Ok(Some(Line::Complete(bytes))) => match std::str::from_utf8(&bytes) {
                Ok(line) => {
                    if events
                        .send(Event::Client(Zeroizing::new(line.to_owned())))
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                Err(_) => "invalid UTF-8",
            },
            Ok(Some(Line::TooLong)) => "line too long",
            Ok(None) | Err(_) => break,
        };
        let reply =
            json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": error}});
        if to_stdout(&reply.to_string()).is_err() {
            break;
        }
    }
    let _ = events.send(Event::ClientEnd);
}

/// Runs one request of the app and sends its result.
#[cfg(unix)]
fn answer(writer: &Writer, msg: AppToRelay) {
    let Some((id, reply)) = run(msg) else {
        return;
    };
    // Cannot happen within the limits (outputs and templates are bounded),
    // but the app must never wait for a result that will not come.
    if writer.send(&reply).is_err() {
        let refused = match reply {
            RelayToApp::ExecResult { .. } => RelayToApp::ExecResult {
                id,
                result: Reply::Err("result too large to relay".into()),
            },
            _ => RelayToApp::FileResult {
                id,
                result: Reply::Err("result too large to relay".into()),
            },
        };
        let _ = writer.send(&refused);
    }
}

/// The data directory of a request.
fn forbidden(f: &Option<String>) -> Option<&Path> {
    f.as_deref().map(Path::new)
}

/// The result of a request, with its id (`None` for an `mcp` line).
fn run(msg: AppToRelay) -> Option<(u64, RelayToApp)> {
    let w = LocalWorkspace;
    let file = |id, r: Result<Option<Zeroizing<String>>, onepass_mcp::WorkspaceRefusal>| {
        let result = match r {
            Ok(v) => Reply::Ok(v),
            Err(e) => Reply::Err(e.message().to_owned()),
        };
        Some((id, RelayToApp::FileResult { id, result }))
    };
    match msg {
        AppToRelay::Mcp { .. } => None,
        AppToRelay::Exec {
            id,
            argv,
            env,
            files,
            cwd,
            timeout_secs,
        } => {
            let req = run_request(argv, env, files, cwd, timeout_secs);
            let result = match w.run(&req) {
                Ok(out) => Reply::Ok(out.into()),
                Err(e) => Reply::Err(e.message().to_owned()),
            };
            Some((id, RelayToApp::ExecResult { id, result }))
        }
        AppToRelay::ReadTemplate {
            id,
            path,
            forbidden: f,
        } => file(
            id,
            w.read_template(Path::new(&path), forbidden(&f)).map(Some),
        ),
        AppToRelay::CheckOutput {
            id,
            path,
            overwrite,
            forbidden: f,
        } => file(
            id,
            w.check_output(Path::new(&path), overwrite, forbidden(&f))
                .map(|()| None),
        ),
        AppToRelay::WriteOutput {
            id,
            path,
            content,
            overwrite,
            forbidden: f,
        } => file(
            id,
            w.write_output(Path::new(&path), &content, overwrite, forbidden(&f))
                .map(|()| None),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    #[test]
    fn socket_arg_accepts_only_the_socket() {
        assert_eq!(
            socket_arg(&args(&["--socket", "/s.sock"])),
            Some(PathBuf::from("/s.sock"))
        );
        assert_eq!(
            socket_arg(&args(&["--socket=/s.sock"])),
            Some(PathBuf::from("/s.sock"))
        );
        for bad in [
            &[][..],
            &["--socket"][..],
            &["--socket", ""][..],
            &["--socket="][..],
            &["/s.sock"][..],
            &["--socket", "/s", "extra"][..],
            &["--other", "/s"][..],
        ] {
            assert_eq!(socket_arg(&args(bad)), None, "{bad:?}");
        }
    }
}
