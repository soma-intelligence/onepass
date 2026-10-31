use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Args;
use onepass_core::crypto::SecretKey;
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::RotationReason;
use onepass_core::repo::{Repository, RotateRequest};
use onepass_core::store::{RecordStore, SqliteStore};
use onepass_core::trust::TrustLevel;
use onepass_core::{Error, Id};
use zeroize::Zeroizing;

use crate::session::{self, CliError, Ctx, DEVICE_NAME, DeviceKeyBlob, NotMe, Session};

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
fn remove_account(ctx: &Ctx, account: Option<Id>) {
    if let Some(account) = account {
        session::forget_key(ctx, account);
    }
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
        remove_account(ctx, None);
    }
    let (key, account) = result?;
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
        remove_account(ctx, Some(account));
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
) -> Result<(zeroize::Zeroizing<String>, Id), CliError> {
    let store = SqliteStore::open(&ctx.store_path())?;
    session::harden(ctx)?;
    let fast = session::fast_kdf_requested().as_deref() == Some("1");
    // Key rotation v2 (spec 6.2, 5.1): the device keys come first, the
    // genesis of the account is signed with them in the same write, and
    // `device.bin` keeps them (no Secure Enclave in the CLI).
    let device = DeviceKeyBlob::generate()?;
    let keys = device.keys()?;
    let (repo, key) = Repository::create_account_v2(
        store,
        password,
        kdf,
        &keys,
        DEVICE_NAME,
        DeviceKind::Other,
        DeviceMode::Personal,
    )
    .map_err(|e| session::account_kdf_error(e, fast))?;
    let key_text = zeroize::Zeroizing::new(key.to_display());
    let account = repo.account_id();
    // Stores the Secret Key (or refuses without a store); on a failure
    // after that, the entry goes with the account.
    let session = Session::create(ctx, repo, &key, device)?;
    if let Err(e) = session.persist() {
        session::forget_key(ctx, account);
        return Err(e);
    }
    Ok((key_text, account))
}

/// One device of the roster, as the commands show it.
struct Row {
    id: Id,
    name: String,
    kind: DeviceKind,
    tofu: bool,
    this: bool,
}

/// The roster of the device (spec 5.3): who this device trusts, sorted by id.
fn roster<S: RecordStore>(repo: &Repository<S>) -> Result<Vec<Row>, CliError> {
    let Some(t) = session::stored(repo.store().trust_state())? else {
        return Ok(Vec::new());
    };
    Ok(t.roster
        .iter()
        .map(|e| Row {
            id: e.device_id,
            name: e.name.clone(),
            kind: e.kind,
            tofu: t.levels.get(&e.device_id) == Some(&TrustLevel::Tofu),
            this: e.device_id == t.me.device_id,
        })
        .collect())
}

/// `onepass account devices`: the devices this device trusts.
pub fn devices(ctx: &Ctx) -> Result<(), CliError> {
    let rows = session::with_session(ctx, |repo| roster(repo))?;
    if ctx.json {
        let list: Vec<_> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "name": r.name,
                    "kind": format!("{:?}", r.kind).to_lowercase(),
                    "verified": !r.tofu,
                    "this_device": r.this,
                })
            })
            .collect();
        return session::write_line(format_args!("{}", serde_json::Value::Array(list)))
            .map_err(session::stdout_error);
    }
    for r in &rows {
        crate::out!(
            "{}  {}  {}  {}{}",
            r.id,
            r.name,
            format!("{:?}", r.kind).to_lowercase(),
            if r.tofu { "unverified" } else { "verified" },
            if r.this { "  (this device)" } else { "" }
        );
    }
    Ok(())
}

/// What `rotate-keys` and `remove-device` share.
#[derive(Args)]
pub struct RotateArgs {
    /// An unverified device (legacy, trusted on first use) that keeps the
    /// account: it gets the new Secret Key. Repeat for several. Without it,
    /// the unverified devices are asked about on a terminal, and none is
    /// kept when there is no terminal.
    #[arg(long = "keep-tofu", value_name = "DEVICE_ID")]
    keep_tofu: Vec<String>,
    /// Where to write the new Emergency Kit (default: a new file in the
    /// data directory). The file is created with mode 0600 and never
    /// overwritten.
    #[arg(long, value_name = "FILE")]
    kit_path: Option<PathBuf>,
}

/// `onepass account remove-device`.
#[derive(Args)]
pub struct RemoveArgs {
    /// The device to remove (see `onepass account devices`).
    id: String,
    #[command(flatten)]
    rotate: RotateArgs,
}

fn parse_ids(texts: &[String]) -> Result<Vec<Id>, CliError> {
    texts
        .iter()
        .map(|t| Id::from_str(t).map_err(|_| CliError::usage(format!("not a device id: {t}"))))
        .collect()
}

/// The unverified devices to keep (spec 15 step 5, `RotateRequest::
/// keep_tofu`): the user confirms each one, none is kept silently.
fn confirm_tofu(rows: &[Row], flags: &[Id], removing: &[Id]) -> Result<Vec<Id>, CliError> {
    let tofu: Vec<&Row> = rows
        .iter()
        .filter(|r| r.tofu && !r.this && !removing.contains(&r.id))
        .collect();
    for id in flags {
        if !tofu.iter().any(|r| r.id == *id) {
            return Err(CliError::usage(format!(
                "--keep-tofu {id}: not an unverified device of this account"
            )));
        }
    }
    let mut keep = flags.to_vec();
    if flags.is_empty() && !tofu.is_empty() {
        if std::io::stdin().is_terminal() {
            let mut lines = std::io::stdin().lock().lines();
            for r in &tofu {
                eprint!(
                    "Keep {} ({}), not verified since the update? It gets the new Secret Key. [y/N] ",
                    r.name, r.id
                );
                std::io::stderr().flush()?;
                let answer = lines.next().transpose()?.unwrap_or_default();
                if matches!(answer.trim(), "y" | "Y" | "yes") {
                    keep.push(r.id);
                }
            }
        } else {
            eprintln!(
                "No terminal to ask on: no unverified device is kept (pass --keep-tofu <id> to keep one)."
            );
        }
    }
    for r in &tofu {
        if !keep.contains(&r.id) {
            eprintln!(
                "{} ({}) will not get the new Secret Key: it has to be paired again.",
                r.name, r.id
            );
        }
    }
    Ok(keep)
}

/// The text of an Emergency Kit file: what is needed to open the account
/// from a new device, apart from the master password, which is never kept.
fn kit_text(account: Id, key: &SecretKey) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "OnePass Emergency Kit (development CLI)\n\
         \n\
         Account ID: {account}\n\
         Secret Key: {}\n\
         Master password: write it here by hand; this file never holds it.\n\
         \n\
         This kit replaces every earlier one: the account keys changed, and an older\n\
         kit no longer opens the account. Keep it somewhere safe and offline.\n",
        key.to_display()
    ))
}

/// Write the kit, created with 0600 and never over an existing file.
fn write_kit(
    ctx: &Ctx,
    account: Id,
    key: &SecretKey,
    path: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    let path = path.unwrap_or_else(|| {
        ctx.data_dir.join(format!(
            "emergency-kit-{account}-{}.txt",
            session::now_unix()
        ))
    });
    let path = std::path::absolute(&path)?;
    let text = kit_text(account, key);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    Ok(path)
}

/// `onepass account rotate-keys`.
pub fn rotate_keys(ctx: &Ctx, args: RotateArgs) -> Result<(), CliError> {
    rotate(ctx, Vec::new(), RotationReason::Rotate, args)
}

/// `onepass account remove-device <id>`: a rotation with reason `Revoke`
/// (spec 10.8; the account-signed list revocation of milestone 2b is
/// refused on a v2 device, `Repository::revoke_device`).
pub fn remove_device(ctx: &Ctx, args: RemoveArgs) -> Result<(), CliError> {
    let id = Id::from_str(&args.id)
        .map_err(|_| CliError::usage(format!("not a device id: {}", args.id)))?;
    rotate(ctx, vec![id], RotationReason::Revoke, args.rotate)
}

/// A rotation of every key of the account (spec 7.1), with `revoke` removed
/// from the roster. The new Secret Key is drawn here and kept pending before
/// the call (K6); the rotation code goes to stdout, the Secret Key only
/// into the Emergency Kit file.
fn rotate(
    ctx: &Ctx,
    revoke: Vec<Id>,
    reason: RotationReason,
    args: RotateArgs,
) -> Result<(), CliError> {
    if !ctx.has_account() {
        return Err(session::no_account(ctx));
    }
    let flags = parse_ids(&args.keep_tofu)?;
    let password = session::read_password("Password: ")?;
    let _lock = session::lock(ctx)?;
    // The keys change under a running server: it must stop first.
    let _servers = session::exclude_servers(ctx)?;
    let mut session = Session::open(ctx, &password)?;
    let rows = roster(&session.repo)?;
    for id in &revoke {
        match rows.iter().find(|r| r.id == *id) {
            None => {
                return Err(CliError::usage(format!(
                    "{id} is not a device of this account (see `onepass account devices`)"
                )));
            }
            Some(r) if r.this => {
                return Err(CliError::usage(
                    "this device cannot remove itself: remove it from another device",
                ));
            }
            Some(_) => {}
        }
    }
    let keep = confirm_tofu(&rows, &flags, &revoke)?;
    let keys = session.device_keys()?;
    let current = session.secret_key()?;
    let new_key = SecretKey::generate()?;
    session.stage_pending(ctx, &new_key)?;
    let committed = session.repo.rotate(RotateRequest {
        revoke,
        new_password: None,
        password: &password,
        secret_key: &current,
        new_secret_key: &new_key,
        device_keys: &keys,
        reason,
        keep_tofu: &keep,
    });
    let outcome = match committed {
        Ok(o) => o,
        Err(e) => {
            // Nothing was written: the key drawn for it is void.
            let _ = session.discard_pending(ctx);
            let _ = session.persist();
            return Err(refusal(e));
        }
    };
    // From here the account uses the new keys (K12): whatever fails next,
    // the new Secret Key stays pending in the secret store (or the file)
    // and the next command finishes the move.
    let account = session.repo.account_id();
    let kit = write_kit(ctx, account, &new_key, args.kit_path);
    let promoted = session.promote_pending(ctx);
    let saved = session::harden(ctx).and_then(|()| session.persist());
    let code = format!("{:06}", outcome.code);
    drop(outcome.auk);
    let kit = kit?;
    promoted?;
    saved?;
    if ctx.json {
        session::write_line(format_args!(
            "{}",
            serde_json::json!({
                "rotation_code": code,
                "emergency_kit": kit.display().to_string(),
            })
        ))
        .map_err(session::stdout_error)?;
    } else {
        crate::out!("Rotation code: {code}");
        crate::out!("Emergency Kit: {}", kit.display());
        eprintln!(
            "Save the Emergency Kit now: it holds the new Secret Key, and every earlier kit \
             stopped opening the account. Your other devices ask you to confirm this rotation \
             with the master password; the code above is the one they show."
        );
    }
    Ok(())
}

/// The error of a refused rotation, with the words of this CLI.
fn refusal(e: Error) -> CliError {
    match &e {
        Error::Validation(v) if v.field == "device" && v.reason == "not current" => {
            CliError::usage(format!(
                "this device is not up to date with the account's keys. {}",
                session::FOLLOW_HINT
            ))
        }
        _ => session::stored(Err::<(), _>(e)).unwrap_err(),
    }
}

/// `onepass account not-me`: "Ce n'etait pas moi".
pub fn not_me(ctx: &Ctx) -> Result<(), CliError> {
    if !ctx.has_account() {
        return Err(session::no_account(ctx));
    }
    let password = session::read_password("Password: ")?;
    let _lock = session::lock(ctx)?;
    match session::answer_not_me(ctx, &password)? {
        NotMe::Prompt => {
            crate::out!(
                "Rejected: that rotation is ignored and its signer is no longer trusted here."
            );
        }
        NotMe::Locked => {
            crate::out!(
                "This device is unlocked again and will not erase itself. The device that \
                 rotated the keys is no longer trusted here: remove it with \
                 `onepass account remove-device`."
            );
        }
    }
    Ok(())
}
