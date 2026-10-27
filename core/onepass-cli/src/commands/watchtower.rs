//! `onepass watchtower`: password and site checks over the account.
//!
//! Online, the breach ranges and the site catalogs are fetched with `curl`
//! (spec ruling 8): only the 5 hex character prefix of a password hash ever
//! leaves the machine. `--offline` runs no command at all and uses only the
//! files given. The report holds titles, field ids, counts and dates, never
//! a field value.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Args;
use onepass_core::watchtower::{
    BreachCatalog, Check, Detail, DirRangeSource, Finding, Options, PwnedStatus, RangeSource,
    Report, SiteDirectory, Sources, analyze,
};
use onepass_core::{Error, Id};
use serde_json::json;
use time::{Date, OffsetDateTime};

use super::display::clean;
use super::exec::{CommandRunner, runner};
use super::vault::{all, find_vault};
use crate::session::{CliError, Ctx, stored, with_session};

const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
const TWOFA_URL: &str = "https://api.2fa.directory/v4/all.json";
const PASSKEYS_URL: &str = "https://passkeys-api.2fa.directory/v1/all.json";
const BREACHES_URL: &str = "https://haveibeenpwned.com/api/v3/breaches";

/// Largest catalog file read (spec 3.4).
const MAX_CATALOG: u64 = 16 * 1024 * 1024;
const PREFIX_LEN: usize = 5;

#[derive(Args)]
pub struct WatchtowerArgs {
    /// Analyze this vault only (default: every vault).
    #[arg(long)]
    vault: Option<String>,
    /// Run no network command: only the files given are used.
    #[arg(long)]
    offline: bool,
    /// Directory of `<PREFIX>.txt` range files (PwnedPasswordsDownloader).
    #[arg(long)]
    hibp_dir: Option<PathBuf>,
    /// 2fa.directory v4 `all.json`.
    #[arg(long)]
    sites: Option<PathBuf>,
    /// passkeys-api v1 `all.json`.
    #[arg(long)]
    passkeys: Option<PathBuf>,
    /// HIBP `breaches` document.
    #[arg(long)]
    breaches: Option<PathBuf>,
}

/// Absolute path of `curl`, so that `PATH` cannot substitute another
/// program.
const CURL: &str = "/usr/bin/curl";

/// `curl` arguments fetching `url`, with the HIBP padding header or not.
fn curl_args(url: &str, padding: bool) -> Vec<&str> {
    let mut args = vec!["-sS", "--fail", "--max-time", "15"];
    if padding {
        args.extend(["-H", "Add-Padding: true"]);
    }
    args.extend(["-H", "User-Agent: onepass-cli", url]);
    args
}

/// Body of `url` fetched by `curl` through `runner`.
fn fetch<R: CommandRunner + ?Sized>(
    runner: &mut R,
    url: &str,
    padding: bool,
) -> Result<Vec<u8>, CliError> {
    runner.run(CURL, &curl_args(url, padding))
}

/// HIBP range source over `curl`. The prefix is checked (5 upper-case hex
/// characters) before any command runs, so nothing else can reach the
/// command line.
pub struct CurlRangeSource<'a, R: CommandRunner + ?Sized> {
    runner: &'a mut R,
}

impl<'a, R: CommandRunner + ?Sized> CurlRangeSource<'a, R> {
    pub fn new(runner: &'a mut R) -> Self {
        CurlRangeSource { runner }
    }
}

fn valid_prefix(prefix: &str) -> bool {
    prefix.len() == PREFIX_LEN
        && prefix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

impl<R: CommandRunner + ?Sized> RangeSource for CurlRangeSource<'_, R> {
    fn range(&mut self, prefix: &str) -> onepass_core::Result<Vec<u8>> {
        if !valid_prefix(prefix) {
            return Err(Error::InvalidFormat("range prefix"));
        }
        let url = format!("{RANGE_URL}{prefix}");
        fetch(&mut *self.runner, &url, true)
            .map_err(|_| Error::Store("range download failed".into()))
    }
}

/// A command runner (object lifetime fixed so reborrows stay short).
type Runner<'a> = &'a mut (dyn CommandRunner + 'static);

/// The site catalogs of an analysis.
struct Catalogs {
    sites: Option<SiteDirectory>,
    breaches: Option<BreachCatalog>,
}

/// A catalog file, refused over 16 MiB.
fn read_catalog(path: &Path) -> Result<Vec<u8>, CliError> {
    let unreadable = || CliError::usage(format!("cannot read {}", path.display()));
    let meta = fs::metadata(path).map_err(|_| unreadable())?;
    if !meta.is_file() {
        return Err(unreadable());
    }
    if meta.len() > MAX_CATALOG {
        return Err(CliError::usage(format!(
            "{} is too large (over 16 MiB)",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| unreadable())?
        .take(MAX_CATALOG + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > MAX_CATALOG {
        return Err(CliError::usage(format!(
            "{} is too large (over 16 MiB)",
            path.display()
        )));
    }
    Ok(bytes)
}

/// One catalog document: the file when given (a bad file is an error),
/// else a download when online (a failure leaves the source absent, noted
/// on stderr), else nothing.
fn catalog<T>(
    file: Option<&Path>,
    url: &str,
    what: &str,
    runner: Option<Runner<'_>>,
    parse: impl Fn(&[u8]) -> onepass_core::Result<T>,
) -> Result<Option<T>, CliError> {
    if let Some(path) = file {
        let bytes = read_catalog(path)?;
        return parse(&bytes)
            .map(Some)
            .map_err(|_| CliError::usage(format!("{} is not a valid {what}", path.display())));
    }
    let Some(runner) = runner else {
        return Ok(None);
    };
    match fetch(runner, url, false).ok().and_then(|b| parse(&b).ok()) {
        Some(v) => Ok(Some(v)),
        None => {
            eprintln!("note: {what} unavailable, its checks are skipped");
            Ok(None)
        }
    }
}

fn load_catalogs(a: &WatchtowerArgs, mut runner: Option<Runner<'_>>) -> Result<Catalogs, CliError> {
    let twofa = catalog(
        a.sites.as_deref(),
        TWOFA_URL,
        "2FA directory",
        runner.as_deref_mut(),
        SiteDirectory::from_2fa_directory,
    )?;
    let passkeys = catalog(
        a.passkeys.as_deref(),
        PASSKEYS_URL,
        "passkey directory",
        runner.as_deref_mut(),
        |b| {
            let mut d = SiteDirectory::default();
            d.add_passkeys_directory(b)?;
            Ok(b.to_vec())
        },
    )?;
    let sites = match (twofa, passkeys) {
        (None, None) => None,
        (dir, keys) => {
            let mut dir = dir.unwrap_or_default();
            if let Some(keys) = keys {
                dir.add_passkeys_directory(&keys)?;
            }
            Some(dir)
        }
    };
    let breaches = catalog(
        a.breaches.as_deref(),
        BREACHES_URL,
        "breach catalog",
        runner,
        BreachCatalog::from_hibp,
    )?;
    Ok(Catalogs { sites, breaches })
}

pub fn run(ctx: &Ctx, a: WatchtowerArgs) -> Result<(), CliError> {
    // Online only: `--offline` never builds a runner.
    let mut runner: Option<Box<dyn CommandRunner>> = if a.offline { None } else { Some(runner()?) };
    let catalogs = load_catalogs(&a, runner.as_deref_mut())?;

    // Items are read under the lock; the range lookups run after it.
    let (items, names) = with_session(ctx, |repo| {
        let vaults = all(repo)?;
        let chosen: Vec<usize> = match a.vault.as_deref() {
            Some(v) => vec![find_vault(&vaults, v)?],
            None => (0..vaults.len()).collect(),
        };
        let mut items = Vec::new();
        let mut names = HashMap::new();
        for i in chosen {
            let Some(v) = vaults.get(i) else { continue };
            names.insert(v.id, v.meta.name.clone());
            items.extend(stored(repo.items(v))?);
        }
        Ok((items, names))
    })?;

    let opts = Options::new(OffsetDateTime::now_utc().date());
    let mut dir_source;
    let mut curl_source;
    let pwned: Option<&mut dyn RangeSource> = match (&a.hibp_dir, runner.as_deref_mut()) {
        (Some(d), _) => {
            dir_source = DirRangeSource::new(d);
            Some(&mut dir_source)
        }
        (None, Some(r)) => {
            curl_source = CurlRangeSource::new(r);
            Some(&mut curl_source)
        }
        (None, None) => None,
    };
    let report = analyze(
        &items,
        &opts,
        Sources {
            pwned,
            sites: catalogs.sites.as_ref(),
            breaches: catalogs.breaches.as_ref(),
        },
    );
    let titles: HashMap<Id, String> = items.iter().map(|i| (i.id, i.title.clone())).collect();
    drop(items);
    print(ctx, &report, &names, &titles)
}

fn pwned_name(s: &PwnedStatus) -> &'static str {
    match s {
        PwnedStatus::Checked => "checked",
        PwnedStatus::Partial { .. } => "partial",
        PwnedStatus::Unavailable => "unavailable",
        PwnedStatus::Disabled => "disabled",
    }
}

fn date_text(d: Date) -> String {
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// Human text of a finding detail; empty when there is nothing to add.
fn detail_text(d: &Detail) -> String {
    match d {
        Detail::None => String::new(),
        Detail::Pwned { count } => format!("seen {count} times"),
        Detail::Reused { group, members } => format!("group {group} ({members} items)"),
        Detail::Weak { score } => format!("zxcvbn score {score}"),
        Detail::Expiry { on } => format!("on {}", date_text(*on)),
        Detail::Breach { name, date } => format!("{name} on {}", date_text(*date)),
        Detail::Dependents { items } => format!("{} dependent items", items.len()),
        Detail::KeyBits { algorithm, bits } => format!("{algorithm} {bits} bits"),
        Detail::Age { days } => format!("{days} days"),
        Detail::Duplicate { other } => format!("duplicate of {other}"),
        Detail::Site { documentation } => match documentation {
            Some(url) => format!("documentation: {url}"),
            None => String::new(),
        },
    }
}

fn print(
    ctx: &Ctx,
    report: &Report,
    names: &HashMap<Id, String>,
    titles: &HashMap<Id, String>,
) -> Result<(), CliError> {
    let vault_name = |id: &Id| names.get(id).cloned().unwrap_or_else(|| id.to_string());
    let title = |id: &Id| titles.get(id).cloned().unwrap_or_default();
    if let PwnedStatus::Partial { failed_prefixes } = report.pwned {
        eprintln!("note: breach lookup incomplete ({failed_prefixes} ranges failed)");
    } else if report.pwned == PwnedStatus::Unavailable {
        eprintln!("note: breach lookup unavailable");
    }
    if ctx.json {
        let vaults: Vec<_> = report
            .vaults
            .iter()
            .map(|v| {
                json!({
                    "id": v.vault_id.to_string(),
                    "name": vault_name(&v.vault_id),
                    "score": v.score,
                    "items": v.items,
                })
            })
            .collect();
        let findings = report
            .findings
            .iter()
            .map(|f| finding_json(f, &title(&f.item_id), &vault_name(&f.vault_id)))
            .collect::<Result<Vec<_>, CliError>>()?;
        crate::out!(
            "{}",
            json!({
                "score": report.score,
                "vaults": vaults,
                "findings": findings,
                "pwned": pwned_name(&report.pwned),
                "sites_checked": report.sites_checked,
                "breaches_checked": report.breaches_checked,
            })
        );
        return Ok(());
    }
    // Text mode: titles, vault names, field ids and catalog names are
    // untrusted, so every line goes through `clean`.
    crate::out!("Score: {}/100", report.score);
    for v in &report.vaults {
        crate::out!(
            "  {}: {}/100 ({} items)",
            clean(&vault_name(&v.vault_id)),
            v.score,
            v.items
        );
    }
    for check in Check::ALL {
        let of_check: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.check == check)
            .collect();
        if of_check.is_empty() {
            continue;
        }
        crate::out!("{} ({})", check.id(), of_check.len());
        for f in of_check {
            let mut line = format!("  - {} [{}]", title(&f.item_id), vault_name(&f.vault_id));
            for part in [
                f.field_id.clone().unwrap_or_default(),
                detail_text(&f.detail),
            ] {
                if !part.is_empty() {
                    line.push(' ');
                    line.push_str(&part);
                }
            }
            crate::out!("{}", clean(&line));
        }
    }
    Ok(())
}

fn finding_json(f: &Finding, title: &str, vault: &str) -> Result<serde_json::Value, CliError> {
    let detail =
        serde_json::to_value(&f.detail).map_err(|_| CliError::usage("cannot encode the report"))?;
    Ok(json!({
        "item_id": f.item_id.to_string(),
        "title": title,
        "vault": vault,
        "check": f.check.id(),
        "severity": f.severity,
        "field": f.field_id,
        "detail": detail,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records every command and answers with a fixed body.
    struct Recorder {
        calls: Vec<(String, Vec<String>)>,
        body: Vec<u8>,
    }

    impl CommandRunner for Recorder {
        fn run(&mut self, program: &str, args: &[&str]) -> Result<Vec<u8>, CliError> {
            self.calls.push((
                program.to_owned(),
                args.iter().map(|a| (*a).to_owned()).collect(),
            ));
            Ok(self.body.clone())
        }
    }

    #[test]
    fn curl_range_uses_exact_arguments() {
        let mut r = Recorder {
            calls: Vec::new(),
            body: b"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n".to_vec(),
        };
        let body = CurlRangeSource::new(&mut r).range("21BD1").unwrap();
        assert!(body.starts_with(b"0018A"));
        assert_eq!(r.calls.len(), 1);
        let (program, args) = &r.calls[0];
        assert_eq!(program, "/usr/bin/curl");
        assert_eq!(
            args,
            &[
                "-sS",
                "--fail",
                "--max-time",
                "15",
                "-H",
                "Add-Padding: true",
                "-H",
                "User-Agent: onepass-cli",
                "https://api.pwnedpasswords.com/range/21BD1",
            ]
        );
    }

    #[test]
    fn bad_prefixes_run_nothing() {
        let mut r = Recorder {
            calls: Vec::new(),
            body: Vec::new(),
        };
        let mut src = CurlRangeSource::new(&mut r);
        for bad in ["21bd1", "21BD", "21BD1F", "21BDG", "../x", "21BD1 ", ""] {
            assert!(src.range(bad).is_err(), "{bad:?}");
        }
        assert!(r.calls.is_empty());
    }

    #[test]
    fn catalogs_use_no_padding_header() {
        let mut r = Recorder {
            calls: Vec::new(),
            body: b"[]".to_vec(),
        };
        let got = catalog(
            None,
            BREACHES_URL,
            "breach catalog",
            Some(&mut r),
            BreachCatalog::from_hibp,
        )
        .unwrap();
        assert!(got.is_some());
        assert_eq!(
            r.calls[0].1,
            [
                "-sS",
                "--fail",
                "--max-time",
                "15",
                "-H",
                "User-Agent: onepass-cli",
                BREACHES_URL
            ]
        );
        // Offline (no runner) and no file: absent, nothing run.
        let none = catalog(
            None,
            BREACHES_URL,
            "breach catalog",
            None,
            BreachCatalog::from_hibp,
        )
        .unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn details_read_as_text() {
        let d = Date::from_calendar_date(2027, time::Month::March, 4).unwrap();
        assert_eq!(detail_text(&Detail::Pwned { count: 3 }), "seen 3 times");
        assert_eq!(
            detail_text(&Detail::Reused {
                group: 1,
                members: 2
            }),
            "group 1 (2 items)"
        );
        assert_eq!(detail_text(&Detail::Weak { score: 1 }), "zxcvbn score 1");
        assert_eq!(detail_text(&Detail::Expiry { on: d }), "on 2027-03-04");
        assert_eq!(
            detail_text(&Detail::Breach {
                name: "Leak".into(),
                date: d
            }),
            "Leak on 2027-03-04"
        );
        assert_eq!(
            detail_text(&Detail::Dependents {
                items: vec![Id::new(), Id::new()]
            }),
            "2 dependent items"
        );
        assert_eq!(
            detail_text(&Detail::KeyBits {
                algorithm: "RSA".into(),
                bits: 2048
            }),
            "RSA 2048 bits"
        );
        assert_eq!(detail_text(&Detail::Age { days: 400 }), "400 days");
        let other = Id::new();
        assert_eq!(
            detail_text(&Detail::Duplicate { other }),
            format!("duplicate of {other}")
        );
        assert_eq!(
            detail_text(&Detail::Site {
                documentation: Some("https://example.com/2fa".into())
            }),
            "documentation: https://example.com/2fa"
        );
        assert_eq!(
            detail_text(&Detail::Site {
                documentation: None
            }),
            ""
        );
        assert_eq!(detail_text(&Detail::None), "");
    }
}
