//! The IPC commands, the whole surface the web view can reach. Each one is
//! declared in build.rs and allowed in capabilities/main.json. No generic
//! command (read a file, run a process) exists.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use onepass_ffi::{
    FfiDeviceKind, FfiDeviceMode, FfiField, FfiFieldType, FfiFieldValue, FfiItem, FfiMatchRule,
    FfiPasswordRecipe, FfiSection, FfiStoreState, FfiUrl, OnePassError, Session,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

use crate::device::SoftwareHalf;
use crate::secrets::DeviceSecrets;
use crate::state::{AppState, CLIPBOARD_CLEAR_SECS, now};
use crate::view::{self, FieldInput, ItemView, SummaryView, UiResult, VaultView};

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
    /// The primary website, for the types that have one (older editor).
    #[serde(default)]
    pub url: Option<String>,
    /// Every website, the first one primary. Replaces `url` when present.
    #[serde(default)]
    pub urls: Option<Vec<UrlEdit>>,
    /// New values of template fields by id. Absent fields keep their value,
    /// so an unrevealed secret is never overwritten by an empty one.
    #[serde(default)]
    pub fields: HashMap<String, FieldInput>,
    /// The custom fields (section `custom`), in order, when the editor sends
    /// them: the ones left out are removed.
    #[serde(default)]
    pub custom: Option<Vec<CustomEdit>>,
    /// The tags, when the editor sends them.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Travel Mode marks (hidden in travel, extra protection in travel).
    #[serde(default)]
    pub travel_hidden: Option<bool>,
    #[serde(default)]
    pub travel_guard: Option<bool>,
    /// Set for an item `new_item` made and nothing stored yet: its type.
    #[serde(default)]
    pub new_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlEdit {
    #[serde(default)]
    pub label: String,
    pub url: String,
    /// "domain", "exactHost", "exactUrl" or "never".
    #[serde(default)]
    pub rule: Option<String>,
}

/// A custom field: an existing one (`id`) or a new one of `kind`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomEdit {
    #[serde(default)]
    pub id: Option<String>,
    pub label: String,
    pub kind: String,
    /// `None` keeps the stored value (an unrevealed secret).
    #[serde(default)]
    pub value: Option<FieldInput>,
}

/// The section of the fields the user adds, as the Apple apps name it.
pub const CUSTOM_SECTION: &str = "custom";
const CUSTOM_SECTION_LABEL: &str = "Champs perso";
const CUSTOM_PREFIX: &str = "custom_";

/// The kinds a custom field can have here: the Apple apps' list without
/// "Lieu" (no map to pick a place on Windows yet).
fn custom_kind(key: &str) -> Option<FfiFieldType> {
    Some(match key {
        "text" => FfiFieldType::Text,
        "concealed" => FfiFieldType::Concealed,
        "password" => FfiFieldType::Password,
        "date" => FfiFieldType::Date,
        "url" => FfiFieldType::Url,
        "email" => FfiFieldType::Email,
        "phone" => FfiFieldType::Phone,
        _ => return None,
    })
}

/// The label of a custom field left blank, in the app's language.
fn default_label(kind: FfiFieldType) -> &'static str {
    let fr = crate::state::language() == "fr";
    match (kind, fr) {
        (FfiFieldType::Concealed, true) => "Champ masqué",
        (FfiFieldType::Concealed, false) => "Hidden field",
        (FfiFieldType::Password, true) => "Mot de passe",
        (FfiFieldType::Password, false) => "Password",
        (FfiFieldType::Date, _) => "Date",
        (FfiFieldType::Url, true) => "Site web",
        (FfiFieldType::Url, false) => "Website",
        (FfiFieldType::Email, _) => "Email",
        (FfiFieldType::Phone, true) => "Téléphone",
        (FfiFieldType::Phone, false) => "Phone",
        (_, true) => "Texte",
        (_, false) => "Text",
    }
}

fn custom_number(id: &str) -> Option<u32> {
    id.strip_prefix(CUSTOM_PREFIX)?.parse().ok()
}

fn apply_custom(item: &mut FfiItem, custom: Vec<CustomEdit>) -> UiResult<()> {
    let mut old: Vec<FfiField> = match item.sections.iter().position(|s| s.id == CUSTOM_SECTION) {
        Some(i) => std::mem::take(&mut item.sections[i].fields),
        None => vec![],
    };
    // Ids are never reused within the item.
    let mut next = item
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .chain(old.iter())
        .filter_map(|f| custom_number(&f.id))
        .max()
        .unwrap_or(0);
    let mut fields = Vec::with_capacity(custom.len());
    for c in custom {
        let mut field = match c.id {
            Some(id) => {
                let i = old
                    .iter()
                    .position(|f| f.id == id)
                    .ok_or(OnePassError::NotFound)?;
                old.remove(i)
            }
            None => {
                let kind = custom_kind(&c.kind).ok_or("unknown field kind")?;
                next += 1;
                FfiField {
                    id: format!("{CUSTOM_PREFIX}{next}"),
                    label: String::new(),
                    kind,
                    value: FfiFieldValue::Empty,
                    required: false,
                    repeatable: false,
                    autofill: false,
                }
            }
        };
        let label = c.label.trim();
        field.label = if label.is_empty() {
            default_label(field.kind).to_owned()
        } else {
            label.to_owned()
        };
        if let Some(input) = c.value {
            field.value =
                view::input_value(field.kind, input).ok_or("this value does not fit the field")?;
        }
        fields.push(field);
    }
    match item.sections.iter().position(|s| s.id == CUSTOM_SECTION) {
        Some(i) if fields.is_empty() => {
            item.sections.remove(i);
        }
        Some(i) => item.sections[i].fields = fields,
        None if fields.is_empty() => {}
        None => item.sections.push(FfiSection {
            id: CUSTOM_SECTION.into(),
            label: CUSTOM_SECTION_LABEL.into(),
            fields,
        }),
    }
    Ok(())
}

fn apply_edit(item: &mut FfiItem, edit: ItemEdit) -> UiResult<()> {
    item.title = edit.title;
    item.notes = edit.notes;
    if let Some(tags) = edit.tags {
        // Trimmed, no blank, no case-insensitive duplicate (as on the Mac).
        let mut kept: Vec<String> = vec![];
        for tag in tags {
            let tag = tag.trim();
            if !tag.is_empty() && !kept.iter().any(|k| k.to_lowercase() == tag.to_lowercase()) {
                kept.push(tag.to_owned());
            }
        }
        item.tags = kept;
    }
    if let Some(urls) = edit.urls {
        // The match rule of a website survives when its address is kept.
        let before = std::mem::take(&mut item.urls);
        for u in urls {
            let url = u.url.trim();
            if url.is_empty() {
                continue;
            }
            let rule = match u.rule.as_deref().and_then(view::rule_from_key) {
                Some(r) => r,
                None => before
                    .iter()
                    .find(|b| b.url == url)
                    .map_or(FfiMatchRule::Domain, |b| b.rule),
            };
            let primary = item.urls.is_empty();
            item.urls.push(FfiUrl {
                label: u.label.trim().to_owned(),
                url: url.to_owned(),
                rule,
                primary,
            });
        }
    } else if let Some(url) = edit.url {
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
    if let Some(v) = edit.travel_hidden {
        item.travel_hidden = v;
    }
    if let Some(v) = edit.travel_guard {
        item.travel_guard = v;
    }
    let mut fields = edit.fields;
    for field in item
        .sections
        .iter_mut()
        .filter(|s| s.id != CUSTOM_SECTION)
        .flat_map(|s| s.fields.iter_mut())
    {
        if let Some(input) = fields.remove(&field.id) {
            field.value =
                view::input_value(field.kind, input).ok_or("this value does not fit the field")?;
        }
    }
    if !fields.is_empty() {
        return Err("unknown field".into());
    }
    if let Some(custom) = edit.custom {
        apply_custom(item, custom)?;
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

// ---- attachments ------------------------------------------------------------------

/// The largest file the core attaches (onepass-core attachment.rs).
const MAX_ATTACHMENT: u64 = 20 * 1024 * 1024;
/// The most files an item holds (same file).
const MAX_ATTACHMENTS: usize = 32;

fn fr() -> bool {
    crate::state::language() == "fr"
}

/// Asks for a file and attaches it to a stored item. `None` when the user
/// cancels the dialog. The path and the bytes stay in the backend.
#[tauri::command]
pub async fn add_attachment(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
) -> UiResult<Option<ItemView>> {
    let s = session(&state)?;
    let item = s.item(vault_id.clone(), item_id.clone())?;
    if item.attachments.len() >= MAX_ATTACHMENTS {
        return Err(view::UiError {
            code: "TooMany".into(),
            detail: "too many attachments".into(),
        });
    }
    let title = if fr() {
        "Ajouter un fichier"
    } else {
        "Add a File"
    };
    let Some(path) = crate::dialog::pick_file(&window, title, &[]).await else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(crate::dialog::read_limited(&path, MAX_ATTACHMENT)?);
    let name = crate::dialog::file_name(&path);
    let mime = crate::dialog::mime_for(&name).to_owned();
    let stored = s.add_attachment(vault_id, item_id, name, mime, bytes.to_vec())?;
    Ok(Some(ItemView::from(&stored)))
}

#[tauri::command]
pub fn remove_attachment(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    attachment_id: String,
) -> UiResult<ItemView> {
    let s = session(&state)?;
    Ok(ItemView::from(&s.remove_attachment(
        vault_id,
        item_id,
        attachment_id,
    )?))
}

fn attachment(
    state: &AppState,
    vault_id: String,
    item_id: String,
    attachment_id: &str,
) -> UiResult<(String, Zeroizing<Vec<u8>>)> {
    let s = session(state)?;
    let item = s.item(vault_id.clone(), item_id.clone())?;
    let name = item
        .attachments
        .iter()
        .find(|a| a.id == attachment_id)
        .ok_or(OnePassError::NotFound)?
        .name
        .clone();
    let bytes = Zeroizing::new(s.attachment_data(vault_id, item_id, attachment_id.to_owned())?);
    Ok((name, bytes))
}

/// Opens an attachment in the app Windows associates with its type: written
/// to a private temporary folder, deleted 10 minutes later and at lock. A
/// program or a script is refused (export it instead).
#[tauri::command]
pub fn open_attachment(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    attachment_id: String,
) -> UiResult<()> {
    let (name, bytes) = attachment(&state, vault_id, item_id, &attachment_id)?;
    if !crate::shell::opens_safely(&name) {
        return Err(view::UiError {
            code: "NoPreview".into(),
            detail: "this kind of file does not open from OnePass".into(),
        });
    }
    let dir = crate::state::opened_dir().join(format!(
        "{:x}",
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("write: {e}"))?;
    let path = dir.join(crate::shell::safe_file_name(&name));
    std::fs::write(&path, bytes.as_slice()).map_err(|e| format!("write: {e}"))?;
    let cleanup = dir.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(10 * 60));
        let _ = std::fs::remove_dir_all(cleanup);
    });
    Ok(crate::shell::open_file(&path)?)
}

/// Saves a copy of an attachment where the user chooses. False on cancel.
#[tauri::command]
pub async fn export_attachment(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    attachment_id: String,
) -> UiResult<bool> {
    let (name, bytes) = attachment(&state, vault_id, item_id, &attachment_id)?;
    let title = if fr() { "Exporter" } else { "Export" };
    let safe = crate::shell::safe_file_name(&name);
    let Some(path) = crate::dialog::save_file(&window, title, &safe, &[]).await else {
        return Ok(false);
    };
    std::fs::write(&path, bytes.as_slice()).map_err(|e| format!("write: {e}"))?;
    Ok(true)
}
