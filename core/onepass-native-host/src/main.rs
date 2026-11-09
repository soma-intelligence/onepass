//! Development native messaging host of OnePass.
//!
//! `onepass-native-host [--config <path>] [<caller-origin-or-manifest> [<extension-id>]]`
//! serves one browser connection over stdio. `onepass-native-host approve
//! <code> [--config <path>]` approves a pending pairing (`file` mode).
//! `onepass-native-host prepare [--config <path>]` builds the fixture
//! vault cache ahead of the first connection. `onepass-native-host sign-in
//! <item-id> <url> [--config <path>]` records an open and sign in in
//! `data_dir`, as the app does when the user taps a login's website.

mod config;
mod fixture;
mod host;
mod log;
mod pairings;
mod vault;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::thread;

use std::str::FromStr;

use onepass_bridge::framing::write_frame;
use onepass_bridge::host::{Conn, Frame, Limits, spawn_reader};
use onepass_bridge::pending::PendingStore;
use onepass_bridge::service::VaultAccess;

use crate::config::{Approval, Config, HostError, Reprompt, Source, Unlock, extension_id};
use crate::host::{APPROVED_FILE, DevApprover};
use crate::log::{FileAudit, Log, ensure_dir, now};
use crate::pairings::{Pairings, write_atomic};

const FIXTURE_CACHE: &str = "fixture-cache.bin";
/// "Bring the app forward": the one plain message of the extension, on a
/// connection of its own, and the reply. The same bytes as
/// `onepass_relay::open_app` (the tests compare them): the relay opens the
/// app, this host has none and only says it did, so that the extension goes
/// on as with the app (its bridge `unlock` follows).
const OPEN_APP_REQUEST: &[u8] = br#"{"onepass":1,"op":"open_app"}"#;
const OPEN_APP_REPLY: &[u8] = br#"{"ok":true}"#;

struct Args {
    config: Option<PathBuf>,
    /// `approve <code>`.
    approve: Option<String>,
    /// `prepare`.
    prepare: bool,
    /// `sign-in <item-id> <url>`.
    sign_in: Option<(String, String)>,
    /// Caller arguments given by the browser.
    positional: Vec<String>,
}

fn parse_args(raw: Vec<String>) -> Result<Args, HostError> {
    let mut config = None;
    let mut positional = Vec::new();
    let mut it = raw.into_iter();
    while let Some(a) = it.next() {
        if a == "--config" {
            config = Some(PathBuf::from(
                it.next()
                    .ok_or_else(|| HostError::new("--config needs a path"))?,
            ));
        } else if let Some(p) = a.strip_prefix("--config=") {
            config = Some(PathBuf::from(p));
        } else if a.starts_with("--") {
            // Browser flags such as --parent-window: not ours.
        } else {
            positional.push(a);
        }
    }
    let approve = if positional.first().map(String::as_str) == Some("approve") {
        let code = positional
            .get(1)
            .cloned()
            .ok_or_else(|| HostError::new("usage: onepass-native-host approve <code>"))?;
        Some(code)
    } else {
        None
    };
    let prepare = positional.first().map(String::as_str) == Some("prepare");
    let sign_in = if positional.first().map(String::as_str) == Some("sign-in") {
        match (positional.get(1), positional.get(2)) {
            (Some(id), Some(url)) => Some((id.clone(), url.clone())),
            _ => {
                return Err(HostError::new(
                    "usage: onepass-native-host sign-in <item-id> <url>",
                ));
            }
        }
    } else {
        None
    };
    Ok(Args {
        config,
        approve,
        prepare,
        sign_in,
        positional,
    })
}

/// `approve <code>`: write `<data_dir>/pairing-approved` (0600).
fn approve(cfg: &Config, code: &str) -> Result<(), HostError> {
    ensure_dir(&cfg.data_dir)
        .map_err(|e| HostError::new(format!("data directory: {}", e.kind())))?;
    write_atomic(&cfg.data_dir.join(APPROVED_FILE), code.trim().as_bytes())
        .map_err(|e| HostError::new(format!("cannot write {APPROVED_FILE}: {}", e.kind())))
}

/// `sign-in <item-id> <url>`: record a pending sign-in in `data_dir`.
fn sign_in(cfg: &Config, item_id: &str, url: &str) -> Result<(), HostError> {
    let id = onepass_core::Id::from_str(item_id.trim())
        .map_err(|_| HostError::new("sign-in: bad item id"))?;
    PendingStore::new(cfg.data_dir.clone())
        .record(id, url, now())
        .map(|_| ())
        .map_err(|e| HostError::new(format!("sign-in: {e}")))
}

/// `prepare`: build the fixture vault cache now, so that the first
/// connection reopens it instead of signing the fixture account while the
/// extension's first request waits. Nothing to do for the dev source.
fn prepare(cfg: &Config) -> Result<(), HostError> {
    check_build(cfg, !cfg!(debug_assertions))?;
    match &cfg.source {
        Source::Fixture { path } => {
            ensure_dir(&cfg.data_dir)
                .map_err(|e| HostError::new(format!("data directory: {}", e.kind())))?;
            fixture::load_fixture_cached(path, &cfg.data_dir.join(FIXTURE_CACHE)).map(|_| ())
        }
        Source::Dev { .. } => Ok(()),
    }
}

/// The frames of a connection whose first one was already read: `first`,
/// then the rest of `frames`, as `spawn_reader` would have given them.
fn replay(first: Frame, frames: Receiver<Frame>) -> Receiver<Frame> {
    let (tx, rx) = sync_channel(1);
    thread::spawn(move || {
        let more = matches!(first, Ok(Some(_)));
        if tx.send(first).is_err() || !more {
            return;
        }
        for f in frames {
            if tx.send(f).is_err() {
                return;
            }
        }
    });
    rx
}

/// Serve the connection, the vault loading on its own thread meanwhile.
fn serve<V, F>(conn: &mut Conn<'_, std::io::Stdout>, load: F)
where
    V: VaultAccess + Send + 'static,
    F: FnOnce() -> Result<V, HostError> + Send + 'static,
{
    let loading = thread::spawn(load);
    conn.serve(move || {
        loading
            .join()
            .unwrap_or_else(|_| Err(HostError::new("vault loading failed")))
            .map_err(|e| e.to_string())
    });
}

/// Settings a release build refuses: the fixture source, and pairing
/// approval `auto`, which approves without any code comparison so that
/// any local process could pair with the host.
fn check_build(cfg: &Config, release: bool) -> Result<(), HostError> {
    if matches!(cfg.source, Source::Fixture { .. }) && release {
        return Err(HostError::new(
            "the fixture source is refused in a release build",
        ));
    }
    if cfg.approval == Approval::Auto && release {
        return Err(HostError::new(
            "automatic pairing approval is refused in a release build",
        ));
    }
    Ok(())
}

fn run_host(cfg: &Config, positional: &[String]) -> Result<(), HostError> {
    check_build(cfg, !cfg!(debug_assertions))?;
    let log = Log::open(&cfg.data_dir);
    log.line("DEV MODE: OnePass development native messaging host, not for real secrets");
    let mut pairings = Pairings::load(&cfg.data_dir)?;
    let mut approver = DevApprover::new(cfg.approval, &cfg.data_dir, log.clone());
    let extension_id = extension_id(positional);
    let allowed = extension_id.as_deref().is_some_and(|id| cfg.is_allowed(id));
    let clock = now;
    let limits = Limits::default();
    // The first frame decides: the plain `open_app` message, or a bridge
    // connection (the frame then goes to the loop below, unchanged).
    let frames = spawn_reader(std::io::stdin());
    let first: Frame = match frames.recv_timeout(limits.step) {
        Ok(f) => f,
        Err(RecvTimeoutError::Disconnected) => Ok(None),
        Err(RecvTimeoutError::Timeout) => {
            log.line("handshake step timed out");
            log.line("connection closed");
            return Ok(());
        }
    };
    if allowed && matches!(&first, Ok(Some(f)) if f == OPEN_APP_REQUEST) {
        log.line("open_app: no app to bring forward, answered as done");
        return write_frame(&mut std::io::stdout().lock(), OPEN_APP_REPLY)
            .map_err(|_| HostError::new("cannot answer open_app"));
    }
    let mut conn = Conn {
        allowed,
        // The development host proves nothing about its caller: never a
        // pairing without the configured approval.
        vouched: None,
        extension_id: extension_id.unwrap_or_default(),
        journal: &log,
        clock: &clock,
        limits,
        pairings: &mut pairings,
        approver: &mut approver,
        audit: Some(Box::new(FileAudit::new(&cfg.data_dir))),
        // No agent fills through the development host.
        agent: None,
        rx: replay(first, frames),
        out: std::io::stdout(),
    };
    let unlocked = cfg.unlocked;
    let allow_reprompt = cfg.reprompt == Reprompt::Allow;
    // Lab hook: `unlock` waits for an approval file in the data directory.
    let deferred = (cfg.unlock == Unlock::File).then(|| cfg.data_dir.clone());
    match (&cfg.source, allowed) {
        // A caller that is refused never gets the vault loaded.
        (_, false) => conn.serve(|| Err::<fixture::FixtureVault, _>("refused".to_owned())),
        (Source::Fixture { path }, true) => {
            let path = path.clone();
            let cache = cfg.data_dir.join(FIXTURE_CACHE);
            let pending_dir = cfg.data_dir.clone();
            serve(&mut conn, move || {
                let mut v = fixture::load_fixture_cached(&path, &cache)?;
                v.set_locked(!unlocked);
                v.set_allow_reprompt(allow_reprompt);
                if let Some(dir) = &deferred {
                    v.set_deferred_unlock(dir);
                }
                v.set_pending_dir(pending_dir);
                Ok(v)
            });
        }
        (Source::Dev { path }, true) => {
            let dir = path.clone().unwrap_or_else(|| cfg.data_dir.clone());
            let vlog = log.clone();
            let pending_dir = cfg.data_dir.clone();
            serve(&mut conn, move || {
                let mut v = vault::load_dev(dir, unlocked, &vlog);
                v.set_allow_reprompt(allow_reprompt);
                if let Some(dir) = &deferred {
                    v.set_deferred_unlock(dir);
                }
                v.set_pending_dir(pending_dir);
                Ok(v)
            });
        }
    }
    log.line("connection closed");
    Ok(())
}

fn main() -> ExitCode {
    let result = parse_args(std::env::args().skip(1).collect()).and_then(|args| {
        let cfg = Config::load(&Config::locate(args.config)?)?;
        if let Some((id, url)) = &args.sign_in {
            return sign_in(&cfg, id, url);
        }
        match args.approve {
            Some(code) => approve(&cfg, &code),
            None if args.prepare => prepare(&cfg),
            None => run_host(&cfg, &args.positional),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Never `eprintln!`: it panics when stderr is closed.
            let _ = writeln!(std::io::stderr(), "onepass-native-host: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn args_for_each_mode() {
        let a = parse_args(args(&["--config", "/c.json", "chrome-extension://x/"])).unwrap();
        assert_eq!(a.config, Some(PathBuf::from("/c.json")));
        assert_eq!(a.approve, None);
        assert_eq!(a.positional, args(&["chrome-extension://x/"]));

        let a = parse_args(args(&["approve", "123 456", "--config=/c.json"])).unwrap();
        assert_eq!(a.approve.as_deref(), Some("123 456"));
        assert_eq!(a.config, Some(PathBuf::from("/c.json")));

        let a = parse_args(args(&["chrome-extension://x/", "--parent-window=0"])).unwrap();
        assert_eq!(a.positional, args(&["chrome-extension://x/"]));

        assert!(parse_args(args(&["approve"])).is_err());
        let a = parse_args(args(&["sign-in", "id", "https://atlas-cloud.test"])).unwrap();
        assert_eq!(
            a.sign_in,
            Some(("id".to_owned(), "https://atlas-cloud.test".to_owned()))
        );
        assert!(parse_args(args(&["sign-in", "id"])).is_err());
        assert!(parse_args(args(&["--config"])).is_err());

        let a = parse_args(args(&["prepare", "--config", "/c.json"])).unwrap();
        assert!(a.prepare);
        assert_eq!(a.approve, None);
        assert!(
            !parse_args(args(&["chrome-extension://x/"]))
                .unwrap()
                .prepare
        );
    }

    #[test]
    fn prepare_builds_the_fixture_cache_once() {
        // The first connection of a fresh data directory otherwise builds
        // the fixture vault (one SLH-DSA signature, seconds of CPU in a
        // debug build) while the extension's first request waits.
        let dir = std::env::temp_dir().join(format!("onepass-prepare-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/e2e.json");
        let json = format!(
            r#"{{"data_dir":{},"allowed_extensions":["x"],"source":{{"kind":"fixture","path":{}}},"approval":"auto"}}"#,
            serde_json::to_string(&dir).unwrap(),
            serde_json::to_string(&fixture).unwrap()
        );
        let cfg = Config::parse(json.as_bytes()).unwrap();
        prepare(&cfg).unwrap();
        let cache = dir.join(FIXTURE_CACHE);
        let first = std::fs::read(&cache).unwrap();
        // A second run reopens the cache instead of rebuilding it.
        prepare(&cfg).unwrap();
        assert_eq!(std::fs::read(&cache).unwrap(), first);
        // Nothing to prepare for the dev source.
        assert!(prepare(&config(DEV, "auto")).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn config(source: &str, approval: &str) -> Config {
        let json = format!(
            r#"{{"data_dir":"/d","allowed_extensions":["x"],"source":{source},"approval":"{approval}"}}"#
        );
        Config::parse(json.as_bytes()).unwrap()
    }

    const DEV: &str = r#"{"kind":"dev"}"#;
    const FIXTURE: &str = r#"{"kind":"fixture","path":"/f.json"}"#;

    #[test]
    fn release_build_refuses_auto_approval() {
        // Approving a pairing without any code comparison lets any local
        // process pair with the host: test builds only.
        assert!(check_build(&config(DEV, "auto"), true).is_err());
        assert!(check_build(&config(DEV, "auto"), false).is_ok());
        assert!(check_build(&config(DEV, "file"), true).is_ok());
    }

    #[test]
    fn release_build_refuses_fixture_source() {
        assert!(check_build(&config(FIXTURE, "file"), true).is_err());
        assert!(check_build(&config(FIXTURE, "file"), false).is_ok());
        assert!(check_build(&config(FIXTURE, "auto"), false).is_ok());
    }
}
