//! `onepass ssh-agent`: the SSH agent in the foreground (spec sections 6
//! and 7).
//!
//! It unlocks once (password on `/dev/tty`), then every key listing and
//! every key load is its own lock cycle through [`LongSession::with_repo`],
//! so the rest of the CLI stays usable while it runs. Signatures go
//! through the approver (as for `onepass mcp`) and into the signed audit
//! log `<data-dir>/audit.log`. `SIGINT` and `SIGTERM` stop the accept loop
//! and remove the socket.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use clap::Args;
use onepass_core::repo::Repository;
use onepass_core::store::SqliteStore;
use onepass_guard::{Approver, AuditLog, SignedAuditSink, TtyApprover, dev_auto_approver_from_env};
use onepass_ssh_agent::keys::AgentKey;
use onepass_ssh_agent::{
    Agent, AgentConfig, KeyInfo, KeySource, bind_socket, load_key_of, serve, ssh_keys_of,
};

use super::ssh_key::AGENT_SOCKET;
use crate::session::{CliError, Ctx, LongSession, TRAVEL_CHANGED, stored};
use crate::signer::SyncSigner;

const AUDIT_FILE: &str = "audit.log";
/// How often the signal flag is looked at.
const SIGNAL_POLL: Duration = Duration::from_millis(50);

#[derive(Args)]
pub struct SshAgentArgs {
    /// Socket path (default: <data-dir>/ssh-agent.sock).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Serve forwarded connections too (approval at every signature).
    #[arg(long)]
    allow_forwarded: bool,
    /// known_hosts file used to name bound destinations, read only,
    /// repeatable (default: ~/.ssh/known_hosts if it exists).
    #[arg(long = "known-hosts")]
    known_hosts: Vec<PathBuf>,
}

/// Set by the `SIGINT` and `SIGTERM` handlers, and nothing else.
static SIGNALED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    SIGNALED.store(true, Ordering::SeqCst);
}

/// Routes `SIGINT` and `SIGTERM` to [`on_signal`]. The standard library
/// has no signal API, hence `libc::signal`; the handler only stores to an
/// atomic, which is async-signal-safe.
fn install_signal_handlers() -> Result<(), CliError> {
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `handler` is a valid `extern "C" fn(c_int)` that lives for
        // the whole program and only performs an atomic store to a static,
        // an async-signal-safe operation. `sig` is a valid catchable signal.
        let previous = unsafe { libc::signal(sig, handler) };
        if previous == libc::SIG_ERR {
            return Err(CliError::usage("cannot install the signal handlers"));
        }
        // Started with the signal ignored (`nohup`, a background job of a
        // non-interactive shell): keep it ignored.
        if previous == libc::SIG_IGN {
            // SAFETY: restores the disposition the process started with;
            // `SIG_IGN` is a valid disposition for a catchable signal.
            unsafe { libc::signal(sig, libc::SIG_IGN) };
        }
    }
    Ok(())
}

/// [`KeySource`] of the agent: each call is its own lock cycle on the
/// shared session. The flag is raised when the session refused a request
/// because Travel Mode changed: the agent then stops.
struct SessionKeys(Arc<Mutex<LongSession>>, Arc<AtomicBool>);

impl SessionKeys {
    fn with<T>(
        &self,
        f: impl FnOnce(&mut Repository<SqliteStore>) -> Result<T, CliError>,
    ) -> Result<T, String> {
        let mut session = self
            .0
            .lock()
            .map_err(|_| "session unavailable".to_owned())?;
        let result = session.with_repo(f).map_err(|e| e.msg);
        if session.travel_changed() {
            self.1.store(true, Ordering::SeqCst);
        }
        result
    }
}

impl KeySource for SessionKeys {
    fn list(&mut self) -> Result<Vec<KeyInfo>, String> {
        self.with(|repo| stored(ssh_keys_of(repo)))
    }

    fn load(&mut self, item_id: &str) -> Result<AgentKey, String> {
        self.with(|repo| Ok(load_key_of(repo, item_id)))?
    }
}

/// `s` as one POSIX shell word: single quotes, embedded ones as `'\''`.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `$HOME/.ssh/known_hosts` if it exists. It is only ever read.
fn default_known_hosts() -> Vec<PathBuf> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".ssh").join("known_hosts"))
        .filter(|p| p.is_file())
        .into_iter()
        .collect()
}

pub fn run(ctx: &Ctx, args: SshAgentArgs) -> Result<(), CliError> {
    // Checked before prompting: a bad dev switch must not cost a password.
    let approver: Arc<dyn Approver> = match dev_auto_approver_from_env().map_err(CliError::usage)? {
        Some(a) => Arc::new(a),
        None => Arc::new(TtyApprover::new()),
    };
    let socket = std::path::absolute(
        args.socket
            .unwrap_or_else(|| ctx.data_dir.join(AGENT_SOCKET)),
    )?;
    let known_hosts = if args.known_hosts.is_empty() {
        default_known_hosts()
    } else {
        args.known_hosts
    };
    let session = Arc::new(Mutex::new(LongSession::open(ctx)?));
    let travel_changed = Arc::new(AtomicBool::new(false));
    let log = AuditLog::open(&ctx.data_dir.join(AUDIT_FILE))
        .map_err(|e| CliError::usage(format!("cannot open the audit log: {e}")))?;
    let sink = SignedAuditSink {
        log,
        signer: SyncSigner(session.clone()),
    };
    let agent = Agent::new(
        SessionKeys(session, travel_changed.clone()),
        approver,
        Box::new(sink),
        AgentConfig {
            allow_forwarded: args.allow_forwarded,
            known_hosts,
            ..AgentConfig::default()
        },
    );
    install_signal_handlers()?;
    let listener = bind_socket(&socket)
        .map_err(|e| CliError::usage(format!("cannot listen on {}: {e}", socket.display())))?;
    eprintln!(
        "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
        shell_quote(&socket.display().to_string())
    );
    let stop = Arc::new(AtomicBool::new(false));
    // `serve` watches an `Arc` flag; the handlers can only set a static.
    let watcher = {
        let stop = stop.clone();
        let travel_changed = travel_changed.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if SIGNALED.load(Ordering::SeqCst) || travel_changed.load(Ordering::SeqCst) {
                    stop.store(true, Ordering::SeqCst);
                }
                thread::sleep(SIGNAL_POLL);
            }
        })
    };
    let served = serve(listener, Arc::new(Mutex::new(agent)), stop.clone());
    stop.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    let removed = match std::fs::remove_file(&socket) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(CliError::from(e)),
        _ => Ok(()),
    };
    served.map_err(|e| CliError::usage(format!("agent stopped on error: {e}")))?;
    removed?;
    if travel_changed.load(Ordering::SeqCst) {
        return Err(CliError::usage(TRAVEL_CHANGED));
    }
    eprintln!("onepass ssh-agent: stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_paths_are_one_shell_word() {
        assert_eq!(shell_quote("/a b/s"), "'/a b/s'");
        assert_eq!(shell_quote("/it's;rm"), "'/it'\\''s;rm'");
    }
}
