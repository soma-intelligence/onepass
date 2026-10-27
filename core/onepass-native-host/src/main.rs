//! Development native messaging host of OnePass.
//!
//! `onepass-native-host [--config <path>] [<caller-origin-or-manifest> [<extension-id>]]`
//! serves one browser connection over stdio. `onepass-native-host approve
//! <code> [--config <path>]` approves a pending pairing (`file` mode).

mod config;
mod fixture;
mod host;
mod log;
mod pairings;
mod vault;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;

use onepass_bridge::service::VaultAccess;

use crate::config::{Approval, Config, HostError, Reprompt, Source, extension_id};
use crate::host::{APPROVED_FILE, Conn, Limits, spawn_reader};
use crate::log::{Log, ensure_dir, now};
use crate::pairings::{Pairings, write_atomic};

const FIXTURE_CACHE: &str = "fixture-cache.bin";

struct Args {
    config: Option<PathBuf>,
    /// `approve <code>`.
    approve: Option<String>,
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
    Ok(Args {
        config,
        approve,
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
    let pairings = Pairings::load(&cfg.data_dir)?;
    let extension_id = extension_id(positional);
    let allowed = extension_id.as_deref().is_some_and(|id| cfg.is_allowed(id));
    let clock = now;
    let mut conn = Conn {
        cfg,
        extension_id,
        log: &log,
        clock: &clock,
        limits: Limits::default(),
        pairings,
        rx: spawn_reader(std::io::stdin()),
        out: std::io::stdout(),
    };
    let unlocked = cfg.unlocked;
    let allow_reprompt = cfg.reprompt == Reprompt::Allow;
    match (&cfg.source, allowed) {
        // A caller that is refused never gets the vault loaded.
        (_, false) => conn.serve(|| Err::<fixture::FixtureVault, _>(HostError::new("refused"))),
        (Source::Fixture { path }, true) => {
            let path = path.clone();
            let cache = cfg.data_dir.join(FIXTURE_CACHE);
            serve(&mut conn, move || {
                let mut v = fixture::load_fixture_cached(&path, &cache)?;
                v.set_locked(!unlocked);
                v.set_allow_reprompt(allow_reprompt);
                Ok(v)
            });
        }
        (Source::Dev { path }, true) => {
            let dir = path.clone().unwrap_or_else(|| cfg.data_dir.clone());
            let vlog = log.clone();
            serve(&mut conn, move || {
                let mut v = vault::load_dev(dir, unlocked, &vlog);
                v.set_allow_reprompt(allow_reprompt);
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
        match args.approve {
            Some(code) => approve(&cfg, &code),
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
        assert!(parse_args(args(&["--config"])).is_err());
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
