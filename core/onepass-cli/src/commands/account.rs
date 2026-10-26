use std::fs;

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

/// `onepass account create`: new account, Secret Key shown once.
pub fn create(ctx: &Ctx) -> Result<(), CliError> {
    // Checked early to fail before the prompt, and again under the lock.
    exists(ctx)?;
    let kdf = session::kdf_params()?;
    let password = session::read_password("New password: ")?;
    if password.is_empty() {
        return Err(CliError::usage("the password must not be empty"));
    }
    if std::env::var("ONEPASS_DEV_ALLOW_ENV_PASSWORD").as_deref() != Ok("1") {
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
        // Leave nothing half made behind: the account did not exist before.
        for suffix in ["", "-wal", "-shm"] {
            let mut p = ctx.store_path().into_os_string();
            p.push(suffix);
            let _ = fs::remove_file(p);
        }
        let _ = fs::remove_file(ctx.device_path());
    }
    let key = result?;
    if ctx.json {
        crate::out!("{}", serde_json::json!({ "secret_key": *key }));
    } else {
        crate::out!("Secret Key: {}", *key);
        eprintln!("Write the Secret Key down now: it is shown only once.");
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
