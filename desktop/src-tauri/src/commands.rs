//! The IPC commands, the whole surface the web view can reach. Each one is
//! declared in build.rs and allowed in capabilities/main.json. No generic
//! command (read a file, run a process) exists.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use onepass_ffi::{
    FfiDeviceKind, FfiDeviceMode, FfiFieldType, FfiItem, FfiMatchRule,
    FfiPasswordRecipe, FfiStoreState, FfiUrl, OnePassError, Session,
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
    // Saved at once so the editor works on a stored item.
    let s = session(&state)?;
    let item = s.new_item(vault_id, t, title)?;
    Ok(ItemView::from(&s.save_item(item)?))
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
}

fn apply_edit(item: &mut FfiItem, edit: ItemEdit) -> UiResult<()> {
    item.title = edit.title;
    item.notes = edit.notes;
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
    let mut item = s.item(edit.vault_id.clone(), edit.item_id.clone())?;
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
    Ok(field_value(&state, vault_id, item_id, &field_id)?.1.to_string())
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
            if c.get_text().is_ok_and(|t| Zeroizing::new(t).as_str() == copied.as_str()) {
                let _ = c.clear();
            }
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
    c.set_text(text).map_err(|e| format!("clipboard: {e}").into())
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
    },
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
        Recipe::Words { count, french } => FfiPasswordRecipe::Words {
            count,
            separator: "-".into(),
            french,
            capitalize: true,
        },
    };
    Ok(Generated {
        bits: onepass_ffi::password_entropy_bits(r.clone()),
        password: onepass_ffi::generate_password(r)?,
    })
}
