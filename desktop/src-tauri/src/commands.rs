//! The IPC commands, the whole surface the web view can reach. Each one is
//! declared in build.rs and allowed in capabilities/main.json. No generic
//! command (read a file, run a process) exists.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use onepass_ffi::{
    FfiDeviceKind, FfiDeviceMode, FfiFieldType, FfiItem, FfiMatchRule, FfiPasswordRecipe,
    FfiStoreState, FfiUrl, OnePassError, Session,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

use crate::device::SoftwareHalf;
use crate::secrets::DeviceSecrets;
use crate::state::{AppState, CLIPBOARD_CLEAR_SECS, now};
use crate::view::{self, ItemView, SummaryView, UiResult, VaultView};

fn session(state: &AppState) -> UiResult<Arc<Session>> {
    state.touch();
    state.session().ok_or_else(|| OnePassError::Locked.into())
}

// ---- account -------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// "empty", "locked", "unlocked", "missing" (the pinned account is gone)
    /// or "noDeviceFile" (an account without this device's secrets).
    pub state: &'static str,
    pub account_id: Option<String>,
    /// How `device.bin` is sealed ("dpapi" for now, "tpm" later).
    pub protection: &'static str,
    pub auto_lock_minutes: i64,
    /// "fr" or "en": the Windows display language, as the iPhone app
    /// follows the system's.
    pub language: &'static str,
}

#[tauri::command]
pub fn status(state: State<'_, AppState>) -> UiResult<Status> {
    let protection = state.sealer.name();
    let auto_lock_minutes = crate::state::AUTO_LOCK_SECS / 60;
    let store = onepass_ffi::store_state(state.db_path())?;
    let mk = |s, account_id| Status {
        state: s,
        account_id,
        protection,
        auto_lock_minutes,
        language: crate::state::language(),
    };
    Ok(match store {
        FfiStoreState::Empty => mk("empty", None),
        FfiStoreState::Account => {
            if let Some(s) = state.session() {
                mk("unlocked", Some(s.account_id()))
            } else {
                match state.load_secrets()? {
                    Some(d) => mk("locked", Some(d.account_id.clone())),
                    None => mk("noDeviceFile", None),
                }
            }
        }
        _ => mk("missing", None),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Created {
    pub account_id: String,
    /// Shown once, for the Emergency Kit. Kept sealed in `device.bin`.
    pub secret_key: String,
}

fn device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "PC".into())
}

fn device_kind() -> FfiDeviceKind {
    if cfg!(windows) {
        FfiDeviceKind::Windows
    } else {
        FfiDeviceKind::Linux
    }
}

/// A new account on this device, with device keys (rotation v2) and the
/// default Argon2id parameters. Undone if `device.bin` cannot be written.
#[tauri::command]
pub fn create_account(state: State<'_, AppState>, password: String) -> UiResult<Created> {
    let password = Zeroizing::new(password);
    if password.chars().count() < 10 {
        return Err(view::UiError {
            code: "WeakPassword".into(),
            detail: "at least 10 characters".into(),
        });
    }
    if onepass_ffi::store_state(state.db_path())? != FfiStoreState::Empty {
        return Err("an account already exists on this PC".into());
    }
    let rng_seed = Zeroizing::new(onepass_ffi::new_device_rng_seed()?);
    onepass_ffi::set_device_rng_seed(rng_seed.to_vec())?;
    let classical = Zeroizing::new(onepass_ffi::generate_classical_device_keys()?);
    let pq = SoftwareHalf::generate()?;
    let created = onepass_ffi::create_account_v2(
        state.db_path(),
        password.to_string(),
        None,
        classical.to_vec(),
        SoftwareHalf::open(&pq)?,
        device_name(),
        device_kind(),
        FfiDeviceMode::Personal,
    )?;
    let secrets = DeviceSecrets {
        account_id: created.account_id.clone(),
        secret_key: Zeroizing::new(created.secret_key.clone()),
        classical,
        pq,
        rng_seed,
    };
    if let Err(e) = state.save_secrets(&secrets) {
        created.session.lock();
        let _ = onepass_ffi::reset_store(state.db_path());
        return Err(e.into());
    }
    state.set_session(created.session);
    Ok(Created {
        account_id: created.account_id,
        secret_key: created.secret_key,
    })
}

#[tauri::command]
pub fn unlock(state: State<'_, AppState>, password: String) -> UiResult<()> {
    let password = Zeroizing::new(password);
    let secrets = state
        .load_secrets()?
        .ok_or("this PC has no device file for the account")?;
    let unlocked = onepass_ffi::unlock_with_password(
        state.db_path(),
        password.to_string(),
        secrets.secret_key.to_string(),
    )?;
    // The AUK would serve a Windows Hello unlock (spec 6.3, milestone X3):
    // not kept until then.
    drop(Zeroizing::new(unlocked.auk));
    state.set_session(unlocked.session);
    Ok(())
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>) {
    state.lock();
}

// ---- vaults and items -------------------------------------------------------------

#[tauri::command]
pub fn vaults(state: State<'_, AppState>) -> UiResult<Vec<VaultView>> {
    Ok(session(&state)?
        .vaults()?
        .into_iter()
        .map(VaultView::from)
        .collect())
}

#[tauri::command]
pub fn items(state: State<'_, AppState>) -> UiResult<Vec<SummaryView>> {
    Ok(session(&state)?
        .item_summaries()?
        .into_iter()
        .map(SummaryView::from)
        .collect())
}

#[tauri::command]
pub fn item(state: State<'_, AppState>, vault_id: String, item_id: String) -> UiResult<ItemView> {
    Ok(ItemView::from(&session(&state)?.item(vault_id, item_id)?))
}

#[derive(Serialize)]
pub struct TypeInfo {
    pub key: &'static str,
    pub label: String,
}

#[tauri::command]
pub fn item_types() -> Vec<TypeInfo> {
    onepass_ffi::item_types()
        .into_iter()
        .map(|t| TypeInfo {
            key: view::type_key(t.item_type),
            label: t.label,
        })
        .collect()
}

/// An empty item of `item_type`, not stored until `save_item`.
#[tauri::command]
pub fn new_item(
    state: State<'_, AppState>,
    vault_id: String,
    item_type: String,
    title: String,
) -> UiResult<ItemView> {
    let t = view::type_from_key(&item_type).ok_or("unknown item type")?;
    // Not stored: an empty item fails the core's validation (required
    // fields). `save_item` with `newType` stores it once filled in.
    let s = session(&state)?;
    Ok(ItemView::from(&s.new_item(vault_id, t, title)?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemEdit {
    pub vault_id: String,
    pub item_id: String,
    pub title: String,
    pub notes: String,
    /// The primary website, for the types that have one.
    pub url: Option<String>,
    /// New text values by field id. Absent fields keep their value, so an
    /// unrevealed secret is never overwritten by an empty one.
    pub fields: HashMap<String, Zeroizing<String>>,
    /// The tags, when the editor sends them.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Set for an item `new_item` made and nothing stored yet: its type.
    #[serde(default)]
    pub new_type: Option<String>,
}

fn apply_edit(item: &mut FfiItem, edit: ItemEdit) -> UiResult<()> {
    item.title = edit.title;
    item.notes = edit.notes;
    if let Some(tags) = edit.tags {
        item.tags = tags;
    }
    if let Some(url) = edit.url {
        item.urls.retain(|u| !u.primary);
        if !url.trim().is_empty() {
            item.urls.insert(
                0,
                FfiUrl {
                    label: String::new(),
                    url: url.trim().to_owned(),
                    rule: FfiMatchRule::Domain,
                    primary: true,
                },
            );
        }
    }
    let mut fields = edit.fields;
    for field in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        if let Some(text) = fields.remove(&field.id) {
            field.value = view::text_value(field.kind, text.to_string())
                .ok_or("this field is not editable as text yet")?;
        }
    }
    if !fields.is_empty() {
        return Err("unknown field".into());
    }
    Ok(())
}

#[tauri::command]
pub fn save_item(state: State<'_, AppState>, edit: ItemEdit) -> UiResult<ItemView> {
    let s = session(&state)?;
    let mut item = match &edit.new_type {
        Some(t) => {
            let t = view::type_from_key(t).ok_or("unknown item type")?;
            s.new_item(edit.vault_id.clone(), t, edit.title.clone())?
        }
        None => s.item(edit.vault_id.clone(), edit.item_id.clone())?,
    };
    apply_edit(&mut item, edit)?;
    if let Some(e) = onepass_ffi::validate_item(item.clone()) {
        return Err(e.into());
    }
    Ok(ItemView::from(&s.save_item(item)?))
}

#[tauri::command]
pub fn trash_item(state: State<'_, AppState>, vault_id: String, item_id: String) -> UiResult<()> {
    Ok(session(&state)?.trash_item(vault_id, item_id)?)
}

#[tauri::command]
pub fn set_favorite(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    favorite: bool,
) -> UiResult<()> {
    Ok(session(&state)?.set_favorite(vault_id, item_id, favorite)?)
}

// ---- secrets on demand --------------------------------------------------------------

fn field_value(
    state: &AppState,
    vault_id: String,
    item_id: String,
    field_id: &str,
) -> UiResult<(FfiFieldType, Zeroizing<String>)> {
    let item = session(state)?.item(vault_id, item_id)?;
    let field = item
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find(|f| f.id == field_id)
        .ok_or(OnePassError::NotFound)?;
    let text = view::display(&field.value).ok_or(OnePassError::NotFound)?;
    Ok((field.kind, Zeroizing::new(text)))
}

/// The value of one field, when the user asks to see it.
#[tauri::command]
pub fn reveal_field(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    field_id: String,
) -> UiResult<String> {
    Ok(field_value(&state, vault_id, item_id, &field_id)?
        .1
        .to_string())
}

/// Copies a field without its value crossing the IPC; an OTP field copies
/// its current code. Cleared after 90 s if the clipboard still holds it.
#[tauri::command]
pub fn copy_field(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    field_id: String,
) -> UiResult<u64> {
    let (kind, text) = field_value(&state, vault_id, item_id, &field_id)?;
    let text = if kind == FfiFieldType::Otp {
        let code = onepass_ffi::totp_now(text.to_string(), u64::try_from(now()).unwrap_or(0))?;
        Zeroizing::new(code.code)
    } else {
        text
    };
    let mut clipboard = arboard::Clipboard::new().map_err(|e| format!("clipboard: {e}"))?;
    set_clipboard(&mut clipboard, &text)?;
    let copied = text.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECS));
        if let Ok(mut c) = arboard::Clipboard::new() {
            // Only our own value is cleared: a later copy by the user stays.
            if c.get_text()
                .is_ok_and(|t| Zeroizing::new(t).as_str() == copied.as_str())
            {
                let _ = c.clear();
            }
        }
    });
    Ok(CLIPBOARD_CLEAR_SECS)
}

/// Copies a generated or past password (not a field of an item): same
/// rules as `copy_field` (out of the clipboard history, cleared after 90 s).
#[tauri::command]
pub fn copy_secret(text: String) -> UiResult<u64> {
    let text = Zeroizing::new(text);
    let mut clipboard = arboard::Clipboard::new().map_err(|e| format!("clipboard: {e}"))?;
    set_clipboard(&mut clipboard, &text)?;
    let copied = text.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECS));
        let Ok(mut c) = arboard::Clipboard::new() else {
            return;
        };
        if c.get_text()
            .is_ok_and(|t| Zeroizing::new(t).as_str() == copied.as_str())
        {
            let _ = c.clear();
        }
    });
    Ok(CLIPBOARD_CLEAR_SECS)
}

#[cfg(windows)]
fn set_clipboard(c: &mut arboard::Clipboard, text: &str) -> UiResult<()> {
    use arboard::SetExtWindows;
    // Out of Win+V history and of the cloud clipboard.
    c.set()
        .exclude_from_history()
        .exclude_from_cloud()
        .text(text)
        .map_err(|e| format!("clipboard: {e}").into())
}

#[cfg(not(windows))]
fn set_clipboard(c: &mut arboard::Clipboard, text: &str) -> UiResult<()> {
    c.set_text(text)
        .map_err(|e| format!("clipboard: {e}").into())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Totp {
    pub code: String,
    pub remaining: u32,
    pub period: u32,
}

#[tauri::command]
pub fn totp(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    field_id: String,
) -> UiResult<Totp> {
    let (kind, secret) = field_value(&state, vault_id, item_id, &field_id)?;
    if kind != FfiFieldType::Otp {
        return Err(OnePassError::NotFound.into());
    }
    let c = onepass_ffi::totp_now(secret.to_string(), u64::try_from(now()).unwrap_or(0))?;
    Ok(Totp {
        code: c.code,
        remaining: c.remaining,
        period: c.period,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Recipe {
    Characters {
        length: u32,
        digits: bool,
        symbols: bool,
    },
    Words {
        count: u32,
        french: bool,
        #[serde(default = "yes")]
        capitalize: bool,
    },
    Pin {
        length: u32,
    },
}

fn yes() -> bool {
    true
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Generated {
    pub password: String,
    pub bits: f64,
}

#[tauri::command]
pub fn generate_password(recipe: Recipe) -> UiResult<Generated> {
    let r = match recipe {
        Recipe::Characters {
            length,
            digits,
            symbols,
        } => FfiPasswordRecipe::Characters {
            length,
            digits,
            symbols,
            avoid_ambiguous: false,
        },
        Recipe::Words {
            count,
            french,
            capitalize,
        } => FfiPasswordRecipe::Words {
            count,
            separator: "-".into(),
            french,
            capitalize,
        },
        Recipe::Pin { length } => FfiPasswordRecipe::Pin { length },
    };
    Ok(Generated {
        bits: onepass_ffi::password_entropy_bits(r.clone()),
        password: onepass_ffi::generate_password(r)?,
    })
}

// ---- iPhone parity: Watchtower, archive, trash, vaults, history, account ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckView {
    pub check: String,
    pub item_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchtowerView {
    pub score: u8,
    pub items_analyzed: u32,
    pub checks: Vec<CheckView>,
    /// Counts by strength level, 0 (too short) to 4 (excellent).
    pub strength: Vec<u32>,
    /// "checked", "partial", "unavailable" or "disabled".
    pub pwned: &'static str,
    pub sites_checked: bool,
}

/// The local Watchtower report: no network lookup on Windows yet (breaches
/// off, no 2FA or passkey catalog), item ids only, never a value.
#[tauri::command]
pub fn watchtower(state: State<'_, AppState>) -> UiResult<WatchtowerView> {
    let r = session(&state)?.watchtower_report(onepass_ffi::watchtower::FfiWatchtowerOptions {
        expiry_warning_days: 30,
        old_password_days: 365,
        ranges: None,
        twofa_directory: None,
        passkeys_directory: None,
        excluded_vault_ids: vec![],
        breach_catalog: None,
    })?;
    Ok(WatchtowerView {
        score: r.score,
        items_analyzed: r.items_analyzed,
        checks: r
            .checks
            .into_iter()
            .map(|c| CheckView {
                check: c.check,
                item_ids: c.item_ids,
            })
            .collect(),
        strength: r.strength,
        pwned: match r.pwned {
            onepass_ffi::watchtower::FfiPwnedStatus::Checked => "checked",
            onepass_ffi::watchtower::FfiPwnedStatus::Partial { .. } => "partial",
            onepass_ffi::watchtower::FfiPwnedStatus::Unavailable => "unavailable",
            onepass_ffi::watchtower::FfiPwnedStatus::Disabled => "disabled",
        },
        sites_checked: r.sites_checked,
    })
}

#[tauri::command]
pub fn set_archived(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    archived: bool,
) -> UiResult<()> {
    let s = session(&state)?;
    if archived {
        s.archive_item(vault_id, item_id)?;
    } else {
        s.unarchive_item(vault_id, item_id)?;
    }
    Ok(())
}

#[tauri::command]
pub fn restore_item(state: State<'_, AppState>, vault_id: String, item_id: String) -> UiResult<()> {
    Ok(session(&state)?.restore_item(vault_id, item_id)?)
}

/// Deletes an item for good (from Supprimés récemment).
#[tauri::command]
pub fn delete_item(state: State<'_, AppState>, vault_id: String, item_id: String) -> UiResult<()> {
    Ok(session(&state)?.delete_item(vault_id, item_id)?)
}

#[tauri::command]
pub fn move_item(
    state: State<'_, AppState>,
    item_id: String,
    from_vault: String,
    to_vault: String,
) -> UiResult<()> {
    Ok(session(&state)?.move_item(item_id, from_vault, to_vault)?)
}

/// A copy of an item in the same vault, its title followed by `suffix`.
#[tauri::command]
pub fn duplicate_item(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    suffix: String,
) -> UiResult<ItemView> {
    let s = session(&state)?;
    let item = s.item(vault_id.clone(), item_id)?;
    let fresh = s.new_item(vault_id, item.item_type, format!("{}{suffix}", item.title))?;
    let copy = FfiItem {
        id: fresh.id,
        title: fresh.title,
        favorite: false,
        archived: false,
        trashed_at: None,
        created_at: fresh.created_at,
        updated_at: fresh.updated_at,
        password_history_count: 0,
        attachment_count: 0,
        attachments: vec![],
        ..item
    };
    Ok(ItemView::from(&s.save_item(copy)?))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryView {
    pub index: usize,
    pub replaced_at: i64,
}

/// The dates of the passwords an item replaced; a value comes through
/// `history_value`, one at a time, when asked.
#[tauri::command]
pub fn password_history(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
) -> UiResult<Vec<HistoryView>> {
    Ok(session(&state)?
        .password_history(vault_id, item_id)?
        .into_iter()
        .enumerate()
        .map(|(index, e)| HistoryView {
            index,
            replaced_at: e.replaced_at,
        })
        .collect())
}

#[tauri::command]
pub fn history_value(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    index: usize,
) -> UiResult<String> {
    let all = session(&state)?.password_history(vault_id, item_id)?;
    Ok(all
        .into_iter()
        .nth(index)
        .ok_or(OnePassError::NotFound)?
        .value)
}

#[tauri::command]
pub fn save_vault(
    state: State<'_, AppState>,
    vault_id: Option<String>,
    name: String,
    color: String,
) -> UiResult<VaultView> {
    let s = session(&state)?;
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err("a vault needs a name".into());
    }
    let v = match vault_id {
        Some(id) => {
            let current = s
                .vaults()?
                .into_iter()
                .find(|v| v.id == id)
                .ok_or(OnePassError::NotFound)?;
            s.update_vault(
                id,
                onepass_ffi::FfiVaultMeta {
                    name,
                    color,
                    ..current.meta
                },
            )?
        }
        None => s.create_vault(onepass_ffi::FfiVaultMeta {
            name,
            icon: "lock".into(),
            color,
            travel_safe: false,
            mcp_access: false,
        })?,
    };
    Ok(VaultView::from(v))
}

#[tauri::command]
pub fn delete_vault(state: State<'_, AppState>, vault_id: String) -> UiResult<()> {
    Ok(session(&state)?.delete_vault(vault_id)?)
}

/// A new master password; the Secret Key stays (read from device.bin).
#[tauri::command]
pub fn change_password(state: State<'_, AppState>, current: String, new: String) -> UiResult<()> {
    let current = Zeroizing::new(current);
    let new = Zeroizing::new(new);
    if new.chars().count() < 10 || onepass_ffi::password_strength_bits(new.to_string()) < 60.0 {
        return Err(view::UiError {
            code: "WeakPassword".into(),
            detail: "not strong enough".into(),
        });
    }
    let s = session(&state)?;
    let secrets = state
        .load_secrets()?
        .ok_or("this PC has no device file for the account")?;
    let auk = s.change_password(
        current.to_string(),
        secrets.secret_key.to_string(),
        new.to_string(),
    )?;
    drop(Zeroizing::new(auk));
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    pub account_id: String,
    pub name: String,
    pub devices: Vec<DeviceView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub name: String,
    pub added_at: i64,
    pub this_device: bool,
}

#[tauri::command]
pub fn account(state: State<'_, AppState>) -> UiResult<AccountView> {
    let s = session(&state)?;
    let me = s.this_device_id();
    Ok(AccountView {
        account_id: s.account_id(),
        name: s.profile()?.map(|p| p.name).unwrap_or_default(),
        devices: s
            .devices()?
            .into_iter()
            .map(|d| DeviceView {
                this_device: me.as_deref() == Some(d.id.as_str()),
                name: d.name,
                added_at: d.added_at,
            })
            .collect(),
    })
}

#[tauri::command]
pub fn set_profile_name(state: State<'_, AppState>, name: String) -> UiResult<()> {
    session(&state)?.set_profile(name.trim().to_owned(), vec![])?;
    Ok(())
}

/// Strength of a password being typed (onboarding, editor), in bits.
#[tauri::command]
pub fn strength(password: String) -> f64 {
    onepass_ffi::password_strength_bits(Zeroizing::new(password).to_string())
}

// ---- websites ---------------------------------------------------------------------

/// Opens an item's website in the default browser: http and https only
/// (shell.rs), anything else is refused before Windows sees it.
#[tauri::command]
pub fn open_url(url: String) -> UiResult<()> {
    Ok(crate::shell::open_web(&url)?)
}
