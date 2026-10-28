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

use onepass_mcp::{LocalWorkspace, MAX_LINE, Workspace};
use onepass_mcp_relay::wire::{
    AppToRelay, ClientHello, Line, LineReader, MAX_WIRE_LINE, RelayToApp, Reply, VERSION, decode,
    encode, run_request,
};
use serde_json::json;
use std::ffi::OsString;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use zeroize::Zeroizing;

const USAGE: &str = "usage: onepass-mcp --socket <path>";

/// `EX_USAGE` of sysexits.h.
const EXIT_USAGE: u8 = 64;
/// `EX_UNAVAILABLE` of sysexits.h.
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
    let Some(socket) = socket_arg(&args) else {
        eprintln!("{USAGE}");
        return ExitCode::from(EXIT_USAGE);
    };
    let Ok(stream) = UnixStream::connect(&socket) else {
        eprintln!("onepass-mcp: OnePass is not running or the MCP server is off in its settings");
        return ExitCode::from(EXIT_UNAVAILABLE);
    };
    match relay(stream) {
        Ok(()) => ExitCode::SUCCESS,
        Err(m) => {
            eprintln!("onepass-mcp: {m}");
            ExitCode::FAILURE
        }
    }
}

/// The write half of the socket, shared by every thread that answers.
struct Writer(Mutex<UnixStream>);

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

/// Relays until the app closes the socket.
fn relay(stream: UnixStream) -> Result<(), String> {
    let lost = |_| "connection to OnePass lost".to_owned();
    let writer = Arc::new(Writer(Mutex::new(stream.try_clone().map_err(lost)?)));
    let hello = match onepass_peer::identify_mcp_parent() {
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
    };
    writer.send(&hello).map_err(lost)?;
    {
        let writer = writer.clone();
        thread::spawn(move || pump_stdin(&writer));
    }

    let mut reader = LineReader::new(stream, MAX_WIRE_LINE);
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let result = loop {
        let line = match reader.next_line() {
            Ok(None) => break Ok(()),
            Ok(Some(Line::Complete(line))) => line,
            Ok(Some(Line::TooLong)) => break Err("message too long from OnePass".to_owned()),
            Err(e) => break Err(lost(e)),
        };
        let msg = match decode::<AppToRelay>(&line) {
            Ok(msg) => msg,
            Err(e) => break Err(format!("{e} from OnePass")),
        };
        if let AppToRelay::Mcp { line } = msg {
            if line.contains('\n') {
                break Err("malformed message from OnePass".to_owned());
            }
            if to_stdout(&line).is_err() {
                // The client is gone.
                break Ok(());
            }
            continue;
        }
        workers.retain(|w| !w.is_finished());
        let writer = writer.clone();
        workers.push(thread::spawn(move || answer(&writer, msg)));
    };
    // A command still running keeps its injected values: let it end (its
    // timeout bounds the wait) rather than orphan it.
    for w in workers {
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

/// Copies stdin lines to the app until the end of stdin, then shuts down
/// the write half. A line too long or not UTF-8 gets the server's parse
/// error on stdout, as `onepass mcp` would answer.
fn pump_stdin(writer: &Writer) {
    let mut input = LineReader::new(io::stdin(), MAX_LINE);
    loop {
        let error = match input.next_line() {
            Ok(Some(Line::Complete(bytes))) => match std::str::from_utf8(&bytes) {
                Ok(line) => {
                    let msg = RelayToApp::Mcp {
                        line: Zeroizing::new(line.to_owned()),
                    };
                    if writer.send(&msg).is_err() {
                        break;
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
    writer.shutdown();
}

/// Runs one request of the app and sends its result.
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
