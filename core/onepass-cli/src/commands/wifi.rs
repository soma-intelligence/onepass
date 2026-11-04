//! `onepass wifi`: the vault's Wi-Fi networks on Windows and Linux,
//! without a button (docs/wifi-windows-linux.md).
//!
//! - `sync` writes the networks the vault selects (`onepass_core::wifi`)
//!   into the system as per-user profiles joined automatically, and
//!   removes the ones OnePass added that left the vault. Idempotent: the
//!   state file (`onepass_wifi::state`, no secret) says what was applied.
//! - `import` saves the system's personal networks into the vault as
//!   Router items, skipping SSIDs the vault already has.
//! - `watch` does both on its own: sync when the store changes, import
//!   when a new network is saved in the system. Installed once as a login
//!   item by `install-agent`.
//!
//! A network the system already had before OnePass (same SSID, not added
//! by OnePass) is never overwritten or removed. Reports hold counts and
//! SSIDs, never a key.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Read as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use clap::{Args, Subcommand};
use onepass_core::import::text::{WifiNetwork, router_item};
use onepass_core::model::{FieldValue, Item, ItemType};
use onepass_core::repo::Repository;
use onepass_core::store::SqliteStore;
use onepass_core::vault::Vault;
use onepass_core::wifi::{self as model, Network, Security};
use onepass_wifi::state::{AppliedEntry, State};
use onepass_wifi::{Auth, Backend, OsNetwork, Read};
use serde_json::json;
use zeroize::Zeroizing;

use super::vault::{all, find_vault};
use crate::session::{
    CliError, Ctx, INSECURE_FILE_KEY_OPTION, Session, env_secrets_allowed, harden, lock, stored,
    with_session,
};

/// Debug builds: a JSON file standing in for the system (tests).
const FAKE_ENV: &str = "ONEPASS_DEV_WIFI_FAKE";

#[derive(Subcommand)]
pub enum WifiCmd {
    /// Write the vault's networks into the system (WPA2/WPA3 personal),
    /// remove the ones OnePass added that left the vault. Idempotent.
    Sync,
    /// Save the system's personal networks into the vault.
    Import(ImportArgs),
    /// Keep the system and the vault in step: sync when the vault changes,
    /// import a network as soon as the system saves it. Runs until
    /// stopped; `install-agent` starts it at every login.
    Watch(WatchArgs),
    /// Start `wifi watch` at every login (Linux: systemd user unit,
    /// Windows: the user's Run key), and now. No administrator.
    InstallAgent,
    /// Stop and remove the login item.
    UninstallAgent,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Target vault (default: Personnel, or the only vault).
    #[arg(long)]
    vault: Option<String>,
    /// Report what would be imported, write nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
pub struct WatchArgs {
    /// Seconds between two looks at the system and the store.
    #[arg(long, default_value_t = 15, hide = true)]
    interval: u64,
    /// One round, then exit (tests).
    #[arg(long, hide = true)]
    once: bool,
}

pub fn run(ctx: &Ctx, cmd: WifiCmd) -> Result<(), CliError> {
    match cmd {
        WifiCmd::Sync => sync(ctx),
        WifiCmd::Import(a) => import_cmd(ctx, a),
        WifiCmd::Watch(a) => watch(ctx, a),
        WifiCmd::InstallAgent => install_agent(ctx),
        WifiCmd::UninstallAgent => {
            onepass_wifi::agent::uninstall().map_err(wifi_err)?;
            crate::out!("Wi-Fi agent removed");
            Ok(())
        }
    }
}

fn wifi_err(e: onepass_wifi::WifiError) -> CliError {
    CliError::usage(e.0)
}

/// The system's Wi-Fi profiles: NetworkManager on Linux, `netsh` on
/// Windows, the fake file in a debug build that names one.
fn backend() -> Result<Box<dyn Backend>, CliError> {
    if cfg!(debug_assertions)
        && let Some(path) = std::env::var_os(FAKE_ENV)
    {
        return Ok(Box::new(onepass_wifi::fake::FileBackend(PathBuf::from(
            path,
        ))));
    }
    system_backend()
}

#[cfg(target_os = "linux")]
fn system_backend() -> Result<Box<dyn Backend>, CliError> {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| CliError::usage("USER is not set"))?;
    Ok(Box::new(
        onepass_wifi::linux::NetworkManager::connect(&user).map_err(wifi_err)?,
    ))
}

#[cfg(windows)]
fn system_backend() -> Result<Box<dyn Backend>, CliError> {
    Ok(Box::new(onepass_wifi::windows::Netsh::system()))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn system_backend() -> Result<Box<dyn Backend>, CliError> {
    Err(CliError::usage(
        "onepass wifi runs on Windows and Linux; on a Mac the OnePass app writes the networks",
    ))
}

/// Whether the system listing shows `os_ref` exactly (see
/// `onepass_wifi::windows::Netsh::listing_is_exact`).
fn listing_exact(os_ref: &str) -> bool {
    !cfg!(windows) || os_ref.is_ascii()
}

fn state_path() -> Result<PathBuf, CliError> {
    onepass_wifi::state::default_path().map_err(wifi_err)
}

fn load_state() -> Result<State, CliError> {
    State::load(&state_path()?).map_err(wifi_err)
}

fn save_state(state: &State) -> Result<(), CliError> {
    state.save(&state_path()?).map_err(wifi_err)
}

/// What a round did: counts and codes only.
#[derive(Default)]
struct Report {
    added: u32,
    updated: u32,
    removed: u32,
    unchanged: u32,
    /// Vault networks the system already had before OnePass: left alone.
    kept_system: u32,
    failed: u32,
    skipped: BTreeMap<&'static str, u32>,
    imported: u32,
    import_skipped: BTreeMap<&'static str, u32>,
}

impl Report {
    fn changed(&self) -> bool {
        self.added + self.updated + self.removed + self.imported + self.failed > 0
    }

    fn json(&self) -> serde_json::Value {
        json!({
            "added": self.added,
            "updated": self.updated,
            "removed": self.removed,
            "unchanged": self.unchanged,
            "kept_system": self.kept_system,
            "failed": self.failed,
            "skipped": self.skipped,
            "imported": self.imported,
            "import_skipped": self.import_skipped,
        })
    }

    fn print(&self, ctx: &Ctx, sync: bool, import: bool) -> Result<(), CliError> {
        if ctx.json {
            crate::out!("{}", self.json());
            return Ok(());
        }
        if sync {
            crate::out!(
                "Wi-Fi: {} added, {} updated, {} removed, {} unchanged",
                self.added,
                self.updated,
                self.removed,
                self.unchanged
            );
            if self.kept_system > 0 {
                crate::out!("Already in the system, left as is: {}", self.kept_system);
            }
            for (code, n) in &self.skipped {
                crate::out!("Not applied: {code} x {n}");
            }
        }
        if import || self.imported > 0 {
            crate::out!("Imported into the vault: {}", self.imported);
            for (code, n) in &self.import_skipped {
                crate::out!("Not imported: {code} x {n}");
            }
        }
        if self.failed > 0 {
            crate::out!("Failed: {}", self.failed);
        }
        Ok(())
    }
}

/// Every vault and every item of the account.
fn everything(repo: &mut Repository<SqliteStore>) -> Result<(Vec<Vault>, Vec<Item>), CliError> {
    let vaults = all(repo)?;
    let mut items = Vec::new();
    for v in &vaults {
        items.extend(stored(repo.items(v))?);
    }
    Ok((vaults, items))
}

fn to_os(n: &Network) -> OsNetwork {
    OsNetwork {
        ssid: n.ssid.clone(),
        psk: n.psk.clone(),
        auth: match n.security {
            Security::Wpa2Personal => Auth::Wpa2Psk,
            Security::Wpa3Personal => Auth::Wpa3Sae,
        },
        hidden: n.hidden,
    }
}

/// Bring the system in line with the vault (see the module doc).
fn apply(
    repo: &mut Repository<SqliteStore>,
    backend: &mut dyn Backend,
    state: &mut State,
    report: &mut Report,
) -> Result<(), CliError> {
    let (_, items) = everything(repo)?;
    let selection = model::select(&items);
    report.skipped = selection.skipped_codes();
    let profiles = backend.list().map_err(wifi_err)?;
    let present: BTreeSet<String> = profiles.iter().map(|p| p.os_ref.clone()).collect();
    // A profile of ours the user deleted in the system comes back: the
    // vault decides.
    state
        .applied
        .retain(|_, a| present.contains(&a.os_ref) || !listing_exact(&a.os_ref));
    let ours: BTreeSet<String> = state.applied.values().map(|a| a.os_ref.clone()).collect();
    let foreign: BTreeSet<String> = profiles
        .iter()
        .filter(|p| !ours.contains(&p.os_ref))
        .map(|p| p.ssid.clone())
        .collect();
    let mut desired: Vec<Network> = Vec::new();
    for n in selection.networks {
        if !state.applied.contains_key(&n.ssid) && foreign.contains(&n.ssid) {
            report.kept_system += 1;
        } else {
            desired.push(n);
        }
    }
    let applied: BTreeMap<String, model::Applied> = state
        .applied
        .iter()
        .map(|(ssid, a)| {
            (
                ssid.clone(),
                model::Applied {
                    os_ref: a.os_ref.clone(),
                    fingerprint: a.fingerprint.clone(),
                },
            )
        })
        .collect();
    let plan = model::diff(&desired, &applied);
    report.unchanged = u32::try_from(plan.unchanged).unwrap_or(u32::MAX);
    for n in plan.add {
        match backend.add(&to_os(n)) {
            Ok(os_ref) => {
                state.applied.insert(
                    n.ssid.clone(),
                    AppliedEntry {
                        os_ref,
                        fingerprint: n.fingerprint(),
                    },
                );
                report.added += 1;
            }
            Err(e) => {
                eprintln!("wifi: {e}");
                report.failed += 1;
            }
        }
    }
    for (n, os_ref) in plan.update {
        match backend.update(&os_ref, &to_os(n)) {
            Ok(os_ref) => {
                state.applied.insert(
                    n.ssid.clone(),
                    AppliedEntry {
                        os_ref,
                        fingerprint: n.fingerprint(),
                    },
                );
                report.updated += 1;
            }
            Err(e) => {
                eprintln!("wifi: {e}");
                report.failed += 1;
            }
        }
    }
    for (ssid, os_ref) in plan.remove {
        match backend.remove(&os_ref) {
            Ok(()) => {
                state.applied.remove(&ssid);
                report.removed += 1;
            }
            Err(_) if !present.contains(&os_ref) => {
                state.applied.remove(&ssid);
                report.removed += 1;
            }
            Err(e) => {
                eprintln!("wifi: {e}");
                report.failed += 1;
            }
        }
    }
    Ok(())
}

/// Which system profiles an import looks at.
enum Which<'a> {
    All,
    Only(&'a BTreeSet<String>),
}

/// SSIDs of every Router item, trash included (a network the user deleted
/// from the vault is not brought back by `import`).
fn vault_ssids(items: &[Item]) -> BTreeSet<String> {
    items
        .iter()
        .filter(|i| i.item_type == ItemType::Router)
        .filter_map(|i| match &i.field("ssid")?.value {
            FieldValue::Text(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        })
        .collect()
}

/// The vault imports go to: `--vault`, else Personnel, else the only
/// vault, else the first.
fn import_vault(vaults: &[Vault], wanted: Option<&str>) -> Result<usize, CliError> {
    if vaults.is_empty() {
        return Err(CliError::usage("the account has no vault"));
    }
    match wanted {
        Some(v) => find_vault(vaults, v),
        None => Ok(find_vault(vaults, "Personnel").unwrap_or(0)),
    }
}

/// Save the system's personal networks into the vault (see the module
/// doc). Returns the references of the profiles looked at.
fn import(
    repo: &mut Repository<SqliteStore>,
    backend: &mut dyn Backend,
    state: &State,
    which: Which<'_>,
    vault: Option<&str>,
    dry_run: bool,
    report: &mut Report,
) -> Result<BTreeSet<String>, CliError> {
    let (vaults, items) = everything(repo)?;
    let mut known = vault_ssids(&items);
    let ours: BTreeSet<&str> = state.applied.values().map(|a| a.os_ref.as_str()).collect();
    let mut looked = BTreeSet::new();
    let mut skipped: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut skip = |code: &'static str| *skipped.entry(code).or_default() += 1;
    for p in backend.list().map_err(wifi_err)? {
        if ours.contains(p.os_ref.as_str()) {
            continue;
        }
        if let Which::Only(set) = which
            && !set.contains(&p.os_ref)
        {
            continue;
        }
        looked.insert(p.os_ref.clone());
        if known.contains(&p.ssid) {
            skip("already_in_vault");
            continue;
        }
        let net = match backend.read(&p) {
            Ok(Read::Personal(n)) => n,
            Ok(Read::NotPersonal) => {
                skip("not_personal");
                continue;
            }
            Ok(Read::Unavailable) | Err(_) => {
                skip("password_unavailable");
                continue;
            }
        };
        if !model::valid_psk(&net.psk) {
            skip("bad_password");
            continue;
        }
        // The vault keys by the SSID of the profile's content.
        if known.contains(&net.ssid) {
            skip("already_in_vault");
            continue;
        }
        let security = match net.auth {
            Auth::Wpa2Psk => "WPA2",
            Auth::Wpa3Sae => "WPA3",
        };
        let item = router_item(&WifiNetwork {
            ssid: net.ssid.clone(),
            password: Some(net.psk.clone()),
            security: security.to_owned(),
            hidden: net.hidden,
        });
        known.insert(net.ssid.clone());
        report.imported += 1;
        if dry_run {
            continue;
        }
        let vi = import_vault(&vaults, vault)?;
        let target = vaults
            .get(vi)
            .ok_or_else(|| CliError::usage("the account has no vault"))?;
        let mut item = item;
        item.vault_id = target.id;
        stored(repo.save_item(target, item))?;
    }
    for (code, n) in skipped {
        *report.import_skipped.entry(code).or_default() += n;
    }
    Ok(looked)
}

fn sync(ctx: &Ctx) -> Result<(), CliError> {
    let mut backend = backend()?;
    let mut state = load_state()?;
    let mut report = Report::default();
    let result = with_session(ctx, |repo| {
        // Networks `watch` saw while locked: their keys stay in the system.
        if !state.pending.is_empty() {
            let pending = state.pending.clone();
            import(
                repo,
                backend.as_mut(),
                &state,
                Which::Only(&pending),
                None,
                false,
                &mut report,
            )?;
            state.pending.clear();
        }
        apply(repo, backend.as_mut(), &mut state, &mut report)
    });
    // What was applied is recorded even when a later step failed.
    save_state(&state)?;
    result?;
    report.print(ctx, true, false)
}

fn import_cmd(ctx: &Ctx, a: ImportArgs) -> Result<(), CliError> {
    let mut backend = backend()?;
    let mut state = load_state()?;
    let mut report = Report::default();
    let looked = with_session(ctx, |repo| {
        import(
            repo,
            backend.as_mut(),
            &state,
            Which::All,
            a.vault.as_deref(),
            a.dry_run,
            &mut report,
        )
    })?;
    if !a.dry_run {
        state.seen.extend(looked);
        save_state(&state)?;
    }
    report.print(ctx, false, true)
}

/// Like `with_session`, with a password already read (the watch keeps it
/// for its whole run): lock, unlock, run, save the device state.
fn with_password<T>(
    ctx: &Ctx,
    password: &str,
    f: impl FnOnce(&mut Repository<SqliteStore>) -> Result<T, CliError>,
) -> Result<T, CliError> {
    if !ctx.has_account() {
        return Err(crate::session::no_account(ctx));
    }
    let _lock = lock(ctx)?;
    let mut session = Session::open(ctx, password)?;
    let result = f(&mut session.repo);
    let saved = harden(ctx).and_then(|()| session.persist());
    let v = result?;
    saved.map(|()| v)
}

/// Modification times of the store and its WAL: moves when any command
/// (or a sync) writes the vault.
fn store_stamp(ctx: &Ctx) -> Vec<Option<SystemTime>> {
    let base = ctx.store_path();
    ["", "-wal"]
        .iter()
        .map(|s| {
            let mut p = base.clone().into_os_string();
            p.push(s);
            std::fs::metadata(PathBuf::from(p))
                .and_then(|m| m.modified())
                .ok()
        })
        .collect()
}

/// A graphical password prompt for the login agent on Linux (zenity or
/// kdialog, absolute paths), when a display is there. The password comes
/// back through a pipe, never a command line.
fn graphical_password() -> Option<Zeroizing<String>> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return None;
    }
    let text = "Mot de passe OnePass, pour garder le Wi-Fi a jour";
    let candidates: [(&str, Vec<&str>); 2] = [
        (
            "/usr/bin/zenity",
            vec!["--password", "--title=OnePass Wi-Fi"],
        ),
        (
            "/usr/bin/kdialog",
            vec!["--title", "OnePass Wi-Fi", "--password", text],
        ),
    ];
    for (program, args) in candidates {
        if !std::path::Path::new(program).is_file() {
            continue;
        }
        let Ok(mut child) = Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        let mut out = Zeroizing::new(Vec::new());
        if let Some(mut s) = child.stdout.take() {
            let _ = (&mut s).take(4096).read_to_end(&mut out);
        }
        let ok = child.wait().map(|s| s.success()).unwrap_or(false);
        if !ok {
            return None;
        }
        let text = Zeroizing::new(String::from_utf8_lossy(&out).into_owned());
        let p = text.trim_end_matches(['\n', '\r']);
        return (!p.is_empty()).then(|| Zeroizing::new(p.to_owned()));
    }
    None
}

/// The password of the watch: the environment in tests, the terminal when
/// there is one, else a graphical prompt; `None` runs the watch locked.
fn watch_password(attempt: u32) -> Result<Option<Zeroizing<String>>, CliError> {
    if env_secrets_allowed()?
        && let Ok(p) = std::env::var("ONEPASS_PASSWORD")
    {
        return Ok(Some(Zeroizing::new(p)));
    }
    if std::io::stdin().is_terminal() {
        let prompt = if attempt == 0 {
            "Password (OnePass Wi-Fi): "
        } else {
            "Wrong password, again: "
        };
        return Ok(Some(Zeroizing::new(rpassword::prompt_password(prompt)?)));
    }
    Ok(graphical_password())
}

fn watch(ctx: &Ctx, a: WatchArgs) -> Result<(), CliError> {
    if !ctx.has_account() {
        return Err(crate::session::no_account(ctx));
    }
    let mut backend = backend()?;
    let interval = Duration::from_secs(a.interval.max(1));
    // Unlock once and check the password; three tries, then locked.
    let mut password: Option<Zeroizing<String>> = None;
    for attempt in 0..3 {
        let Some(p) = watch_password(attempt)? else {
            break;
        };
        match with_password(ctx, &p, |_| Ok(())) {
            Ok(()) => {
                password = Some(p);
                break;
            }
            Err(e) if e.code == 2 => continue,
            Err(e) => return Err(e),
        }
    }
    if password.is_none() {
        eprintln!(
            "wifi: running locked: new networks are noted and imported at the next unlock \
             (onepass wifi sync)"
        );
    }
    let mut stamp: Option<Vec<Option<SystemTime>>> = None;
    loop {
        if let Err(e) = watch_round(ctx, backend.as_mut(), &mut password, &mut stamp) {
            eprintln!("wifi: {}", e.msg);
        }
        if a.once {
            return Ok(());
        }
        std::thread::sleep(interval);
    }
}

/// One look at the system and the store; a round with nothing new does
/// not unlock.
fn watch_round(
    ctx: &Ctx,
    backend: &mut dyn Backend,
    password: &mut Option<Zeroizing<String>>,
    stamp: &mut Option<Vec<Option<SystemTime>>>,
) -> Result<(), CliError> {
    let profiles = backend.list().map_err(wifi_err)?;
    let mut state = load_state()?;
    let ours: BTreeSet<&str> = state.applied.values().map(|a| a.os_ref.as_str()).collect();
    let new: BTreeSet<String> = profiles
        .iter()
        .filter(|p| !ours.contains(p.os_ref.as_str()) && !state.seen.contains(&p.os_ref))
        .map(|p| p.os_ref.clone())
        .collect();
    let now = store_stamp(ctx);
    let store_moved = stamp.as_ref() != Some(&now);
    let Some(pw) = password.as_ref() else {
        if !new.is_empty() {
            state.pending.extend(new.iter().cloned());
            state.seen.extend(new);
            save_state(&state)?;
        }
        *stamp = Some(now);
        return Ok(());
    };
    if new.is_empty() && !store_moved && state.pending.is_empty() {
        return Ok(());
    }
    let mut wanted = state.pending.clone();
    wanted.extend(new.iter().cloned());
    let mut report = Report::default();
    let result = with_password(ctx, pw, |repo| {
        import(
            repo,
            backend,
            &state,
            Which::Only(&wanted),
            None,
            false,
            &mut report,
        )?;
        apply(repo, backend, &mut state, &mut report)
    });
    match &result {
        Ok(()) => {
            state.pending.clear();
            state.seen.extend(wanted);
        }
        // The account password changed elsewhere: go on locked.
        Err(e) if e.code == 2 => {
            *password = None;
            state.pending.extend(new.iter().cloned());
            state.seen.extend(new);
        }
        Err(_) => {}
    }
    save_state(&state)?;
    *stamp = Some(store_stamp(ctx));
    result?;
    if report.changed() {
        report.print(ctx, true, false)?;
    }
    Ok(())
}

fn install_agent(ctx: &Ctx) -> Result<(), CliError> {
    if !ctx.has_account() {
        return Err(crate::session::no_account(ctx));
    }
    let exe = std::env::current_exe()
        .map_err(|_| CliError::usage("cannot find the onepass executable"))?;
    let mut args = vec!["--data-dir".to_owned(), ctx.data_dir.display().to_string()];
    if ctx.insecure_file_key {
        args.push(INSECURE_FILE_KEY_OPTION.to_owned());
    }
    args.extend(["wifi".to_owned(), "watch".to_owned()]);
    let at = onepass_wifi::agent::install(&exe, &args).map_err(wifi_err)?;
    crate::out!("Wi-Fi agent installed: {at}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use onepass_core::Id;

    #[test]
    fn vault_ssids_include_trash_and_skip_other_types() {
        let mut r = router_item(&WifiNetwork {
            ssid: "Home".into(),
            password: Some(Zeroizing::new("12345678".into())),
            security: "WPA2".into(),
            hidden: false,
        });
        r.trashed_at = Some(time::OffsetDateTime::UNIX_EPOCH);
        let login = onepass_core::model::new_item(ItemType::Login, Id([0; 16]), "Home2");
        let set = vault_ssids(&[r, login]);
        assert_eq!(set.into_iter().collect::<Vec<_>>(), ["Home"]);
    }

    #[test]
    fn to_os_maps_security() {
        let n = Network {
            item_id: Id([0; 16]),
            ssid: "S".into(),
            psk: Zeroizing::new("12345678".into()),
            security: Security::Wpa3Personal,
            hidden: true,
            updated_ns: 0,
        };
        let o = to_os(&n);
        assert_eq!(o.auth, Auth::Wpa3Sae);
        assert!(o.hidden);
    }
}
