use std::fs;

use onepass_core::crypto::SecretKey;
use onepass_core::repo::Repository;
use onepass_core::store::SqliteStore;

use crate::session::{self, CliError, Ctx, Session};

fn exists(ctx: &Ctx) -> Result<(), CliError> {
    if ctx.device_path().exists() || ctx.store_path().exists() {
        return Err(CliError::usage(format!(
            "an account already exists in {}",
            ctx.data_dir.display()
        )));
    }
    Ok(())
}

/// Remove what `build` created: the account did not exist before.
fn remove_account(ctx: &Ctx) {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = ctx.store_path().into_os_string();
        p.push(suffix);
        let _ = fs::remove_file(p);
    }
    let _ = fs::remove_file(ctx.device_path());
}

/// `onepass account create`: new account, Secret Key shown once. If the
/// key cannot be shown (stdout closed or failing), the account is removed
/// again and the command fails: an account nobody saw the key of would be
/// lost with the device.
pub fn create(ctx: &Ctx) -> Result<(), CliError> {
    // Checked early to fail before the prompt, and again under the lock.
    exists(ctx)?;
    let kdf = session::kdf_params()?;
    let password = session::read_password("New password: ")?;
    if password.is_empty() {
        return Err(CliError::usage("the password must not be empty"));
    }
    if !session::env_secrets_allowed()? {
        let again = session::read_password("Repeat the password: ")?;
        if *again != *password {
            return Err(CliError::usage("the passwords differ"));
        }
    }
    session::ensure_dir(&ctx.data_dir)?;
    let _lock = session::lock(ctx)?;
    exists(ctx)?;
    let result = build(ctx, &password, kdf);
    if result.is_err() {
        remove_account(ctx);
    }
    let key = result?;
    // Still under the lock: the account becomes usable only once its key
    // was shown.
    let shown = if ctx.json {
        session::write_line(format_args!(
            "{}",
            serde_json::json!({ "secret_key": *key })
        ))
    } else {
        eprintln!("Write the Secret Key down now: it is shown only once.");
        session::write_line(format_args!("Secret Key: {}", *key))
    };
    if let Err(e) = shown {
        remove_account(ctx);
        return Err(CliError::usage(format!(
            "cannot show the Secret Key (i/o error: {}): the account was not created",
            e.kind()
        )));
    }
    Ok(())
}

fn build(
    ctx: &Ctx,
    password: &str,
    kdf: onepass_core::crypto::KdfParams,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let store = SqliteStore::open(&ctx.store_path())?;
    session::harden(ctx)?;
    let (repo, key) = Repository::create_account(store, password, kdf)?;
    let key_text = zeroize::Zeroizing::new(key.to_display());
    Session::created(ctx, repo, &key).persist()?;
    Ok(key_text)
}

/// Test-only source of the current Secret Key (`read_secret`).
const SECRET_KEY_ENV: &str = "ONEPASS_SECRET_KEY";
/// Test-only source of the new password (`read_secret`).
const NEW_PASSWORD_ENV: &str = "ONEPASS_NEW_PASSWORD";

/// `onepass account rotate-keys [--change-password]`: rotate every key of
/// the account (spec 2026-10-28). The current password and Secret Key are
/// asked for (the Secret Key is typed, as proof, not taken from
/// `device.bin`). The new Secret Key is drawn and shown before anything is
/// written, so a crash after the write never leaves an account nobody has
/// the key of; on failure nothing changed and the old key stays valid. The
/// new key then replaces the old one in `device.bin`.
pub fn rotate_keys(ctx: &Ctx, change_password: bool) -> Result<(), CliError> {
    if !ctx.has_account() {
        return Err(CliError::usage(format!(
            "no account in {}; run `onepass account create` first",
            ctx.data_dir.display()
        )));
    }
    let password = session::read_password("Password: ")?;
    let current_key = session::read_secret("Current Secret Key: ", SECRET_KEY_ENV)?;
    let current_key = SecretKey::parse(&current_key)?;
    let new_password = if change_password {
        let p = session::read_secret("New password: ", NEW_PASSWORD_ENV)?;
        if p.is_empty() {
            return Err(CliError::usage("the password must not be empty"));
        }
        if !session::env_secrets_allowed()? {
            let again = session::read_secret("Repeat the new password: ", NEW_PASSWORD_ENV)?;
            if *again != *p {
                return Err(CliError::usage("the passwords differ"));
            }
        }
        Some(p)
    } else {
        None
    };
    let _lock = session::lock(ctx)?;
    let open = Session::open(ctx, &password)?;
    let mut repo = open.repo;
    let new_key = SecretKey::generate()?;
    let shown = if ctx.json {
        session::write_line(format_args!(
            "{}",
            serde_json::json!({ "secret_key": *zeroize::Zeroizing::new(new_key.to_display()) })
        ))
    } else {
        eprintln!("Write the new Secret Key down now: it is shown only once.");
        eprintln!("The old Secret Key and its Emergency Kit stop working.");
        session::write_line(format_args!(
            "New Secret Key: {}",
            *zeroize::Zeroizing::new(new_key.to_display())
        ))
    };
    if let Err(e) = shown {
        return Err(CliError::usage(format!(
            "cannot show the new Secret Key (i/o error: {}): nothing was changed",
            e.kind()
        )));
    }
    repo.rotate_keys(
        &password,
        &current_key,
        &new_key,
        new_password.as_deref().map(String::as_str),
    )
    .inspect_err(|_| eprintln!("The keys did not change: the old Secret Key stays valid."))?;
    session::harden(ctx)?;
    Session::created(ctx, repo, &new_key).persist()
}
