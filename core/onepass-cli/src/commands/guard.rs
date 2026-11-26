//! `onepass guard`: the Guarded Kit of the account (spec 2026-11-20).
//!
//! With the guard on, the password and the Secret Key no longer open the
//! account alone: a new device also asks two of the three realms, which
//! count wrong passwords (10 tries per realm). This device keeps the guard
//! `G` in the secret store, so its own unlocks stay offline.

use clap::{Args, Subcommand};
use onepass_core::guarded_kit::{self, GuardState};

use crate::session::{self, CliError, Ctx, HttpRealms, Session, stored, with_password_session};

#[derive(Subcommand)]
pub enum GuardCmd {
    /// Turn the guard on: a new guard registered at every realm, then the
    /// keys sealed under it. Prints nothing secret; no new kit is needed.
    Enable,
    /// Show whether the guard is on, and ask the realms for the wrong
    /// passwords they counted.
    Status,
    /// Register the guard again: after a realm list change, a realm that
    /// lost it, or (default) with a new guard so an old copy stops working.
    Rotate(RotateArgs),
    /// Turn the guard off: the keys back under the password and Secret Key
    /// alone, the guard deleted at the realms.
    Disable,
}

#[derive(Args)]
pub struct RotateArgs {
    /// Keep the same guard under a new version (realm list change).
    #[arg(long)]
    same_guard: bool,
}

pub fn run(ctx: &Ctx, cmd: GuardCmd) -> Result<(), CliError> {
    let pinned = guarded_kit::pinned_realms();
    match cmd {
        GuardCmd::Status => with_password_session(ctx, |s, _| status(ctx, s, &pinned)),
        GuardCmd::Enable => with_password_session(ctx, |s, password| {
            let key = s.secret_key()?;
            let realms = HttpRealms::new()?;
            let (_auk, g) = stored(s.repo.enable_guard(password, &key, &realms, &pinned))?;
            keep(ctx, s, &g);
            report(ctx, "on")
        }),
        GuardCmd::Rotate(a) => with_password_session(ctx, |s, password| {
            let key = s.secret_key()?;
            let realms = HttpRealms::new()?;
            let (_auk, g) =
                stored(
                    s.repo
                        .renew_guard(password, &key, &realms, &pinned, !a.same_guard),
                )?;
            keep(ctx, s, &g);
            report(ctx, "rotated")
        }),
        GuardCmd::Disable => with_password_session(ctx, |s, password| {
            let key = s.secret_key()?;
            let realms = HttpRealms::new()?;
            stored(s.repo.disable_guard(password, &key, &realms, &pinned))?;
            session::forget_guard(ctx, s.repo.account_id());
            report(ctx, "off")
        }),
    }
}

/// Keep `G` for the guard version now in the account parameters.
fn keep(ctx: &Ctx, s: &Session, g: &guarded_kit::GuardSecret) {
    if let GuardState::On { version, .. } = s.repo.guard_state(&guarded_kit::pinned_realms()) {
        session::keep_guard(ctx, s.repo.account_id(), version, g);
    }
}

fn report(ctx: &Ctx, what: &str) -> Result<(), CliError> {
    if ctx.json {
        line(format_args!("{}", serde_json::json!({ "guard": what })))
    } else {
        line(format_args!("Guarded Kit: {what}"))
    }
}

fn status(ctx: &Ctx, s: &Session, pinned: &[guarded_kit::RealmInfo]) -> Result<(), CliError> {
    let GuardState::On {
        version,
        threshold,
        realms,
        realm_set_current,
    } = s.repo.guard_state(pinned)
    else {
        return if ctx.json {
            line(format_args!("{}", serde_json::json!({ "guard": "off" })))
        } else {
            line(format_args!("Guarded Kit: off"))
        };
    };
    let health = HttpRealms::new().and_then(|t| stored(s.repo.guard_health(&t, pinned)));
    let (answered, failures, renew) = match &health {
        Ok(h) => (
            h.realms.iter().filter(|r| r.status.is_some()).count(),
            h.failures.clone(),
            h.needs_renewal,
        ),
        Err(_) => (0, Vec::new(), false),
    };
    if ctx.json {
        return line(format_args!(
            "{}",
            serde_json::json!({
                "guard": "on",
                "version": version,
                "threshold": threshold,
                "realms": realms,
                "realm_set_current": realm_set_current,
                "realms_answered": answered,
                "failures": failures,
                "needs_renewal": renew || !realm_set_current,
            })
        ));
    }
    line(format_args!(
        "Guarded Kit: on (version {version}, {threshold} of {realms} realms)"
    ))?;
    line(format_args!("Realms answering: {answered} of {realms}"))?;
    if failures.is_empty() {
        line(format_args!("Wrong passwords counted: none"))?;
    } else {
        line(format_args!(
            "Wrong passwords counted: {} (unix times, newest first: {})",
            failures.len(),
            failures
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))?;
    }
    if renew || !realm_set_current {
        line(format_args!(
            "Run `onepass guard rotate --same-guard`: a realm lost the guard or the realm list changed"
        ))?;
    }
    Ok(())
}

fn line(args: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    Ok(session::write_line(args)?)
}
