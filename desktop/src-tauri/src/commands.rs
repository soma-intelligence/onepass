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

pub(crate) fn session(state: &AppState) -> UiResult<Arc<Session>> {
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
    /// Windows Hello can unlock now (an enrollment is on file).
    pub hello_enrolled: bool,
    /// "Déverrouiller avec Windows Hello" is on.
    pub hello_wanted: bool,
    /// Why the last Hello attempt fell back to the password: "expired",
    /// "rebooted" or "invalidated".
    pub hello_dropped: Option<&'static str>,
    /// Days before the master password is asked again.
    pub hello_days_left: Option<i64>,
    /// "Icônes des sites" is on.
    pub site_icons: bool,
}

#[tauri::command]
pub fn status(state: State<'_, AppState>) -> UiResult<Status> {
    let protection = state.sealer.name();
    let auto_lock_minutes = crate::state::AUTO_LOCK_SECS / 60;
    let store = onepass_ffi::store_state(state.db_path())?;
    let enrolled = crate::hello::is_enrolled(&state.hello_path());
    let dropped = *state
        .hello_dropped
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mk = |s, account_id| Status {
        state: s,
        account_id,
        protection,
        auto_lock_minutes,
        language: crate::state::language(),
        hello_enrolled: enrolled,
        hello_wanted: state.prefs().hello,
        site_icons: state.prefs().site_icons,
        hello_dropped: dropped.map(crate::hello::Dropped::key),
        hello_days_left: if enrolled {
            crate::hello::days_left(state.sealer.as_ref(), &state.hello_path())
        } else {
            None
        },
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

pub(crate) fn device_name() -> String {
    // Debug builds: the end-to-end test names its instances on one PC.
    #[cfg(debug_assertions)]
    if let Ok(n) = std::env::var("ONEPASS_DEVICE_NAME") {
        return n;
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "PC".into())
}

pub(crate) fn device_kind() -> FfiDeviceKind {
    if cfg!(windows) {
        FfiDeviceKind::Windows
    } else {
        FfiDeviceKind::Linux
    }
}

/// A new account on this device, with device keys (rotation v2) and the
/// default Argon2id parameters. Undone if `device.bin` cannot be written.
#[tauri::command]
pub fn create_account(
    state: State<'_, AppState>,
    password: String,
    sync: Option<crate::sync_cmds::ChoiceInput>,
) -> UiResult<Created> {
    // "Où est rangé mon coffre ?": checked before anything is created.
    let server = sync.map(crate::sync_cmds::server_of).transpose()?;
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
    // The mailbox is made in the background (spec D.2, 3): the account is
    // usable at once, on this PC; the setup resumes until it is done.
    if let Some(server) = server {
        crate::sync::set_backend(&state, &crate::sync::Backend::Pending { server })?;
        state.sync.reset();
    }
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
    let auk = Zeroizing::new(unlocked.auk);
    state.set_session(unlocked.session);
    // A password unlock restarts the 14 days of Windows Hello (as the Apple
    // apps re-wrap the AUK): kept only while the setting is on.
    if state.prefs().hello {
        let _ = crate::hello::enroll(
            state.sealer.as_ref(),
            &state.hello_path(),
            &secrets.account_id,
            &auk,
        );
    }
    *state
        .hello_dropped
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
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
    /// The list of breached sites was at hand.
    pub breach_catalog: bool,
    /// "Vérifier les fuites" is on.
    pub check_breaches: bool,
    /// Ranges still missing (not downloaded, or offline pass).
    pub missing_prefixes: u32,
}

/// The Watchtower report, item ids only, never a value. With breach checks
/// on, the offline pass (`online` false) uses what is already held; the
/// online pass downloads the catalogs and the HIBP ranges the core asks for
/// (5-character prefixes only), then runs again with them.
#[tauri::command]
pub async fn watchtower(state: State<'_, AppState>, online: bool) -> UiResult<WatchtowerView> {
    let s = session(&state)?;
    let on = state.prefs().check_breaches;
    let data = state.data_dir();
    let network = on && online;
    let catalogs = blocking(move || crate::breach::catalogs(&data, network)).await?;
    let has_catalog = catalogs.breaches.is_some();
    let options = |ranges| onepass_ffi::watchtower::FfiWatchtowerOptions {
        expiry_warning_days: 30,
        old_password_days: 365,
        ranges,
        excluded_vault_ids: vec![],
        breach_catalog: catalogs.breaches.clone(),
        site_pack: Some(crate::breach::SITE_PACK.to_vec()),
    };
    let first_options = options(on.then(|| state.ranges.held()));
    let s1 = s.clone();
    let mut r = blocking(move || s1.watchtower_report(first_options)).await??;
    if network && !r.missing_prefixes.is_empty() {
        let missing = r.missing_prefixes.clone();
        let ranges = state.ranges.clone();
        let held = blocking(move || {
            ranges.fetch(&missing);
            ranges.held()
        })
        .await?;
        let second_options = options(Some(held));
        r = blocking(move || s.watchtower_report(second_options)).await??;
    }
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
        breach_catalog: has_catalog,
        check_breaches: on,
        missing_prefixes: u32::try_from(r.missing_prefixes.len()).unwrap_or(u32::MAX),
    })
}

/// "Vérifier les fuites" on or off.
#[tauri::command]
pub fn set_check_breaches(state: State<'_, AppState>, on: bool) -> UiResult<()> {
    if !on {
        state.ranges.clear();
    }
    Ok(state.update_prefs(|p| p.check_breaches = on)?)
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
    let auk = Zeroizing::new(s.change_password(
        current.to_string(),
        secrets.secret_key.to_string(),
        new.to_string(),
    )?);
    // Windows Hello now needs the new unlock key, or nothing.
    if crate::hello::is_enrolled(&state.hello_path())
        && crate::hello::enroll(
            state.sealer.as_ref(),
            &state.hello_path(),
            &secrets.account_id,
            &auk,
        )
        .is_err()
    {
        crate::hello::remove(&state.hello_path());
    }
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
    pub id: String,
    pub name: String,
    /// "windows", "phone", "mac"... (pairing::kind_key).
    pub kind: &'static str,
    /// "personal", "shared" or "public".
    pub mode: &'static str,
    pub added_at: i64,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
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
                kind: crate::pairing::kind_key(d.kind),
                mode: match d.mode {
                    FfiDeviceMode::Personal => "personal",
                    FfiDeviceMode::Shared => "shared",
                    FfiDeviceMode::Public => "public",
                },
                revoked: d.revoked,
                revoked_at: d.revoked_at,
                id: d.id,
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

// ---- Windows Hello ------------------------------------------------------------------

fn hwnd(window: &tauri::WebviewWindow) -> UiResult<isize> {
    #[cfg(windows)]
    {
        Ok(window.hwnd().map_err(|e| format!("window: {e}"))?.0 as isize)
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        Err("Windows Hello is a Windows feature".into())
    }
}

/// Runs blocking work (Argon2id, a WinRT wait, a network fetch) off the
/// event loop's thread.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> UiResult<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("task: {e}").into())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloStatus {
    /// "available", "notConfigured" or "unavailable".
    pub availability: &'static str,
    pub wanted: bool,
    pub enrolled: bool,
    pub days_left: Option<i64>,
}

#[tauri::command]
pub async fn hello_status(state: State<'_, AppState>) -> UiResult<HelloStatus> {
    let availability = match blocking(crate::hello::availability).await? {
        crate::hello::Availability::Available => "available",
        crate::hello::Availability::NotConfigured => "notConfigured",
        crate::hello::Availability::Unavailable => "unavailable",
    };
    let path = state.hello_path();
    Ok(HelloStatus {
        availability,
        wanted: state.prefs().hello,
        enrolled: crate::hello::is_enrolled(&path),
        days_left: crate::hello::days_left(state.sealer.as_ref(), &path),
    })
}

fn not_confirmed() -> view::UiError {
    view::UiError {
        code: "HelloNotConfirmed".into(),
        detail: "Windows Hello did not confirm".into(),
    }
}

/// Turns Windows Hello on: the master password is checked (without opening
/// a session), then Windows Hello confirms, then the AUK is sealed.
#[tauri::command]
pub async fn enable_hello(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    password: String,
) -> UiResult<()> {
    let password = Zeroizing::new(password);
    session(&state)?;
    let secrets = state
        .load_secrets()?
        .ok_or("this PC has no device file for the account")?;
    let db = state.db_path();
    let key = secrets.secret_key.clone();
    let auk = Zeroizing::new(
        blocking(move || onepass_ffi::verify_password(db, password.to_string(), key.to_string()))
            .await??,
    );
    let message = if fr() {
        "Activer le déverrouillage avec Windows Hello"
    } else {
        "Turn on unlocking with Windows Hello"
    };
    let h = hwnd(&window)?;
    if blocking(move || crate::hello::verify(h, message)).await? != crate::hello::Verdict::Verified
    {
        return Err(not_confirmed());
    }
    crate::hello::enroll(
        state.sealer.as_ref(),
        &state.hello_path(),
        &secrets.account_id,
        &auk,
    )?;
    state.update_prefs(|p| p.hello = true)?;
    Ok(())
}

#[tauri::command]
pub fn disable_hello(state: State<'_, AppState>) -> UiResult<()> {
    crate::hello::remove(&state.hello_path());
    state.update_prefs(|p| p.hello = false)?;
    Ok(())
}

fn hello_dropped(state: &AppState, reason: Option<crate::hello::Dropped>) -> view::UiError {
    *state
        .hello_dropped
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = reason;
    view::UiError {
        code: "HelloDropped".into(),
        detail: "master password needed".into(),
    }
}

/// Unlocks with Windows Hello. "HelloDropped" (the reason is in `status`)
/// when the master password is due; "HelloNotConfirmed" when the user
/// cancels or is not recognized (the enrollment stays).
#[tauri::command]
pub async fn unlock_with_hello(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
) -> UiResult<()> {
    let secrets = state
        .load_secrets()?
        .ok_or("this PC has no device file for the account")?;
    let path = state.hello_path();
    // Checked before asking: no Hello prompt for a key that would be refused.
    if let Err(reason) = crate::hello::take_auk(state.sealer.as_ref(), &path, &secrets.account_id) {
        return Err(hello_dropped(&state, reason));
    }
    let message = if fr() {
        "Déverrouiller OnePass"
    } else {
        "Unlock OnePass"
    };
    let h = hwnd(&window)?;
    if blocking(move || crate::hello::verify(h, message)).await? != crate::hello::Verdict::Verified
    {
        return Err(not_confirmed());
    }
    let auk = crate::hello::take_auk(state.sealer.as_ref(), &path, &secrets.account_id)
        .map_err(|reason| hello_dropped(&state, reason))?;
    let db = state.db_path();
    match blocking(move || onepass_ffi::unlock_with_auk(db, auk.to_vec())).await? {
        Ok(session) => {
            state.set_session(session);
            Ok(())
        }
        Err(e @ (OnePassError::WrongPassword | OnePassError::Crypto)) => {
            // The key no longer opens the vault (password changed elsewhere).
            crate::hello::remove(&path);
            let _ = hello_dropped(&state, Some(crate::hello::Dropped::Invalidated));
            Err(e.into())
        }
        Err(e) => Err(e.into()),
    }
}

// ---- backup, restore, import, plaintext export ----------------------------------------

/// The largest file read for a restore or an import (the Apple apps' limit).
const MAX_IMPORT: u64 = 256 * 1024 * 1024;

/// Checks the master password without opening a session (Argon2id, off the
/// event loop's thread). `WrongPassword` when it is not the right one.
pub(crate) async fn confirm_password(
    state: &AppState,
    password: Zeroizing<String>,
) -> UiResult<()> {
    session(state)?;
    let secrets = state
        .load_secrets()?
        .ok_or("this PC has no device file for the account")?;
    let db = state.db_path();
    let key = secrets.secret_key.clone();
    let auk =
        blocking(move || onepass_ffi::verify_password(db, password.to_string(), key.to_string()))
            .await??;
    drop(Zeroizing::new(auk));
    Ok(())
}

fn today() -> String {
    let d = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// A folder another service copies to its servers (OneDrive, Dropbox,
/// Google Drive, iCloud Drive): the Apple apps warn before saving there.
fn synced_folder(path: &std::path::Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    let roots = ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|r| r.to_lowercase());
    roots
        .into_iter()
        .any(|r| !r.is_empty() && p.starts_with(&r))
        || [
            "\\dropbox\\",
            "\\google drive\\",
            "\\icloud drive\\",
            "\\iclouddrive\\",
        ]
        .iter()
        .any(|m| p.contains(m))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Saved {
    /// False when the user cancelled the save dialog.
    pub saved: bool,
    /// The chosen folder syncs to a cloud: nothing written yet, the file
    /// waits for `save_pending` (or `discard_pending`).
    pub cloud: bool,
    pub file_name: String,
}

/// Asks where to save `bytes`; writes them unless the folder syncs to a
/// cloud, in which case they wait in memory for the user's answer.
async fn save_export(
    window: &tauri::WebviewWindow,
    state: &AppState,
    title: &str,
    name: &str,
    filter: crate::dialog::Filter<'_>,
    bytes: Zeroizing<Vec<u8>>,
) -> UiResult<Saved> {
    let Some(path) = crate::dialog::save_file(window, title, name, &[filter]).await else {
        return Ok(Saved {
            saved: false,
            cloud: false,
            file_name: String::new(),
        });
    };
    let file_name = crate::dialog::file_name(&path);
    if synced_folder(&path) {
        *state
            .pending_export
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((path, bytes));
        return Ok(Saved {
            saved: false,
            cloud: true,
            file_name,
        });
    }
    std::fs::write(&path, bytes.as_slice()).map_err(|e| format!("write: {e}"))?;
    Ok(Saved {
        saved: true,
        cloud: false,
        file_name,
    })
}

/// "Enregistrer quand même" after the cloud warning.
#[tauri::command]
pub fn save_pending(state: State<'_, AppState>) -> UiResult<bool> {
    let pending = state
        .pending_export
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some((path, bytes)) = pending else {
        return Ok(false);
    };
    std::fs::write(&path, bytes.as_slice()).map_err(|e| format!("write: {e}"))?;
    Ok(true)
}

#[tauri::command]
pub fn discard_pending(state: State<'_, AppState>) {
    state
        .pending_export
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
}

/// "Sauvegarde chiffrée": the master password, a passphrase, then where to
/// save the `.onepass` archive (every vault, trash and archive included).
#[tauri::command]
pub async fn export_backup(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    password: String,
    passphrase: String,
) -> UiResult<Saved> {
    let passphrase = Zeroizing::new(passphrase.into_bytes());
    confirm_password(&state, Zeroizing::new(password)).await?;
    let s = session(&state)?;
    let bytes =
        Zeroizing::new(blocking(move || s.export_encrypted_backup(passphrase.to_vec())).await??);
    let name = if fr() {
        format!("OnePass sauvegarde {}.onepass", today())
    } else {
        format!("OnePass backup {}.onepass", today())
    };
    let title = if fr() {
        "Sauvegarde chiffrée"
    } else {
        "Encrypted Backup"
    };
    save_export(
        &window,
        &state,
        title,
        &name,
        ("OnePass", &["onepass"]),
        bytes,
    )
    .await
}

/// "Export CSV non chiffré": the master password, the vaults (none: all).
#[tauri::command]
pub async fn export_csv(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
    password: String,
    vault_ids: Vec<String>,
) -> UiResult<Saved> {
    confirm_password(&state, Zeroizing::new(password)).await?;
    let s = session(&state)?;
    let bytes = Zeroizing::new(s.export_plaintext_csv(vault_ids)?);
    let name = if fr() {
        format!("OnePass export non chiffré {}.csv", today())
    } else {
        format!("OnePass unencrypted export {}.csv", today())
    };
    let title = if fr() {
        "Export non chiffré"
    } else {
        "Unencrypted Export"
    };
    save_export(&window, &state, title, &name, ("CSV", &["csv"]), bytes).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveView {
    pub file_name: String,
    /// "backup" (signed by its account) or "export" (passphrase only).
    pub kind: &'static str,
    pub created_at: i64,
    pub newer_version: bool,
    pub has_passphrase: bool,
    pub signed: bool,
    pub for_this_account: bool,
}

fn kind_key(k: onepass_ffi::FfiArchiveKind) -> &'static str {
    match k {
        onepass_ffi::FfiArchiveKind::Backup => "backup",
        onepass_ffi::FfiArchiveKind::Export => "export",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeCount {
    pub item_type: &'static str,
    pub count: u32,
}

fn counts(v: Vec<onepass_ffi::FfiImportTypeCount>) -> Vec<TypeCount> {
    v.into_iter()
        .map(|c| TypeCount {
            item_type: view::type_key(c.item_type),
            count: c.count,
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreView {
    pub kind: &'static str,
    pub created_at: i64,
    pub vaults_created: u32,
    pub items: u32,
    pub by_type: Vec<TypeCount>,
    pub skipped: u32,
    pub signature_verified: bool,
    /// Restored, but the restore epoch could not be recorded.
    pub epoch_missing: bool,
}

impl From<onepass_ffi::FfiRestoreSummary> for RestoreView {
    fn from(r: onepass_ffi::FfiRestoreSummary) -> Self {
        RestoreView {
            kind: kind_key(r.kind),
            created_at: r.created_at,
            vaults_created: r.vaults_created,
            items: r.items,
            by_type: counts(r.by_type),
            skipped: r.skipped,
            signature_verified: r.signature_verified,
            epoch_missing: r.epoch.is_none(),
        }
    }
}

/// Asks for a file and keeps its bytes here (never sent to the web view).
async fn pick_into_pending(
    window: &tauri::WebviewWindow,
    state: &AppState,
    title: &str,
    filters: &[crate::dialog::Filter<'_>],
) -> UiResult<Option<String>> {
    let Some(path) = crate::dialog::pick_file(window, title, filters).await else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(crate::dialog::read_limited(&path, MAX_IMPORT)?);
    let name = crate::dialog::file_name(&path);
    *state
        .pending_import
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((name.clone(), bytes));
    Ok(Some(name))
}

fn pending_bytes(state: &AppState) -> UiResult<(String, Zeroizing<Vec<u8>>)> {
    state
        .pending_import
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(|(n, b)| (n.clone(), b.clone()))
        .ok_or_else(|| "choose a file first".into())
}

fn archive_view(state: &AppState) -> UiResult<ArchiveView> {
    let (file_name, bytes) = pending_bytes(state)?;
    let info = session(state)?.archive_info(bytes.to_vec())?;
    Ok(ArchiveView {
        file_name,
        kind: kind_key(info.kind),
        created_at: info.created_at,
        newer_version: info.newer_version,
        has_passphrase: info.has_passphrase,
        signed: info.signed,
        for_this_account: info.for_this_account,
    })
}

/// "Choisir une sauvegarde…": reads a `.onepass` file and its clear header.
#[tauri::command]
pub async fn pick_backup(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
) -> UiResult<Option<ArchiveView>> {
    session(&state)?;
    let title = if fr() {
        "Restaurer une sauvegarde"
    } else {
        "Restore a Backup"
    };
    if pick_into_pending(&window, &state, title, &[("OnePass", &["onepass"])])
        .await?
        .is_none()
    {
        return Ok(None);
    }
    Ok(Some(archive_view(&state)?))
}

/// The header of the file `pick_import` read when it turned out to be a
/// OnePass archive.
#[tauri::command]
pub fn pending_archive(state: State<'_, AppState>) -> UiResult<ArchiveView> {
    archive_view(&state)
}

#[tauri::command]
pub async fn preview_restore(
    state: State<'_, AppState>,
    passphrase: Option<String>,
) -> UiResult<RestoreView> {
    let (_, bytes) = pending_bytes(&state)?;
    let s = session(&state)?;
    let p = passphrase.map(|p| Zeroizing::new(p.into_bytes()));
    let r = blocking(move || s.preview_restore(bytes.to_vec(), p.map(|p| p.to_vec()))).await??;
    Ok(r.into())
}

#[tauri::command]
pub async fn restore_backup(
    state: State<'_, AppState>,
    passphrase: Option<String>,
) -> UiResult<RestoreView> {
    let (_, bytes) = pending_bytes(&state)?;
    let s = session(&state)?;
    let p = passphrase.map(|p| Zeroizing::new(p.into_bytes()));
    let r = blocking(move || s.restore_archive(bytes.to_vec(), p.map(|p| p.to_vec()))).await??;
    clear_pending(&state);
    Ok(r.into())
}

fn clear_pending(state: &AppState) {
    state
        .pending_import
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
}

/// Forgets the file read for a restore or an import.
#[tauri::command]
pub fn forget_file(state: State<'_, AppState>) {
    clear_pending(&state);
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedImport {
    pub file_name: String,
    /// The format the content looks like (`detect_import_format`), if any.
    pub format: Option<String>,
}

/// "Importer…": reads a file exported by another manager or a browser.
#[tauri::command]
pub async fn pick_import(
    window: tauri::WebviewWindow,
    state: State<'_, AppState>,
) -> UiResult<Option<PickedImport>> {
    session(&state)?;
    let title = if fr() { "Importer" } else { "Import" };
    let Some(file_name) = pick_into_pending(&window, &state, title, &[]).await? else {
        return Ok(None);
    };
    let (_, bytes) = pending_bytes(&state)?;
    let format = onepass_ffi::detect_import_format(file_name.clone(), bytes.to_vec());
    Ok(Some(PickedImport { file_name, format }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WarningCount {
    pub code: String,
    pub count: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateView {
    pub index: u32,
    pub incoming: SummaryView,
    pub existing: SummaryView,
    pub differences: Vec<&'static str>,
    pub exact: bool,
    /// "merge", "skip" or "import".
    pub suggested: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportView {
    pub format: String,
    pub items: u32,
    pub by_type: Vec<TypeCount>,
    pub warnings: Vec<WarningCount>,
    pub skipped: u32,
    pub updated: u32,
    pub added: u32,
    pub fixed: u32,
    pub converted: u32,
    pub archived_duplicates: u32,
    pub unchanged: u32,
    pub duplicates: Vec<DuplicateView>,
    pub merged: u32,
    pub skipped_duplicates: u32,
    pub separate: u32,
}

pub fn aspect_key(a: onepass_ffi::FfiDuplicateAspect) -> &'static str {
    use onepass_ffi::FfiDuplicateAspect as A;
    match a {
        A::Title => "title",
        A::Username => "username",
        A::Password => "password",
        A::Websites => "websites",
        A::Totp => "totp",
        A::Passkeys => "passkeys",
        A::Notes => "notes",
        A::Fields => "fields",
        A::Attachments => "attachments",
        A::Tags => "tags",
    }
}

fn choice_key(c: onepass_ffi::FfiImportChoice) -> &'static str {
    match c {
        onepass_ffi::FfiImportChoice::Merge => "merge",
        onepass_ffi::FfiImportChoice::Skip => "skip",
        onepass_ffi::FfiImportChoice::Import => "import",
    }
}

impl From<onepass_ffi::FfiImportSummary> for ImportView {
    fn from(s: onepass_ffi::FfiImportSummary) -> Self {
        ImportView {
            format: s.format,
            items: s.items,
            by_type: counts(s.by_type),
            warnings: s
                .warnings
                .into_iter()
                .map(|w| WarningCount {
                    code: w.code,
                    count: w.count,
                })
                .collect(),
            skipped: s.skipped,
            updated: s.updated,
            added: s.added,
            fixed: s.fixed,
            converted: s.converted,
            archived_duplicates: s.archived_duplicates,
            unchanged: s.unchanged,
            duplicates: s
                .duplicates
                .into_iter()
                .map(|d| DuplicateView {
                    index: d.index,
                    incoming: SummaryView::from(d.incoming),
                    existing: SummaryView::from(d.existing),
                    differences: d.differences.into_iter().map(aspect_key).collect(),
                    exact: d.exact,
                    suggested: choice_key(d.suggested),
                })
                .collect(),
            merged: s.merged,
            skipped_duplicates: s.skipped_duplicates,
            separate: s.separate,
        }
    }
}

/// What the file would bring into `vault_id`, nothing written.
#[tauri::command]
pub async fn preview_import(
    state: State<'_, AppState>,
    format: String,
    vault_id: String,
) -> UiResult<ImportView> {
    let (_, bytes) = pending_bytes(&state)?;
    let s = session(&state)?;
    let r = blocking(move || s.preview_import_into(format, bytes.to_vec(), vault_id)).await??;
    Ok(r.into())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub index: u32,
    /// "merge", "skip" or "import".
    pub choice: String,
}

#[tauri::command]
pub async fn import_items(
    state: State<'_, AppState>,
    format: String,
    vault_id: String,
    decisions: Vec<Decision>,
) -> UiResult<ImportView> {
    let (_, bytes) = pending_bytes(&state)?;
    let s = session(&state)?;
    let decisions = decisions
        .into_iter()
        .map(|d| {
            let choice = match d.choice.as_str() {
                "merge" => onepass_ffi::FfiImportChoice::Merge,
                "skip" => onepass_ffi::FfiImportChoice::Skip,
                "import" => onepass_ffi::FfiImportChoice::Import,
                _ => return Err(view::UiError::from("unknown choice")),
            };
            Ok(onepass_ffi::FfiImportDecision {
                index: d.index,
                choice,
            })
        })
        .collect::<UiResult<Vec<_>>>()?;
    let r = blocking(move || s.import_items(format, bytes.to_vec(), vault_id, decisions)).await??;
    clear_pending(&state);
    Ok(r.into())
}

// ---- timeline -----------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub kind: String,
    pub at: i64,
    /// A field label, a website host, a vault name, a file name: never a value.
    pub detail: String,
}

/// What happened to an item, newest first.
#[tauri::command]
pub fn item_timeline(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
) -> UiResult<Vec<TimelineEvent>> {
    Ok(session(&state)?
        .item_timeline(vault_id, item_id)?
        .into_iter()
        .map(|e| TimelineEvent {
            kind: e.kind,
            at: e.at,
            detail: e.detail,
        })
        .collect())
}

// ---- Travel Mode -------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TravelVault {
    pub vault_id: String,
    pub name: String,
    pub leaves: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TravelItem {
    pub item_id: String,
    pub title: String,
    pub vault_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TravelView {
    pub active: bool,
    pub exiting: bool,
    pub entered_at: Option<i64>,
    pub hidden_count: u32,
    pub hidden_item_count: u32,
    pub vaults: Vec<TravelVault>,
    pub hidden: Vec<TravelItem>,
    pub guarded: Vec<TravelItem>,
}

fn travel_view(s: &Session) -> UiResult<TravelView> {
    let st = s.travel_status()?;
    let items = |v: Vec<onepass_ffi::FfiTravelItemEntry>| {
        v.into_iter()
            .map(|e| TravelItem {
                item_id: e.item_id,
                title: e.title,
                vault_name: e.vault_name,
            })
            .collect()
    };
    let plan = s.travel_item_plan()?;
    Ok(TravelView {
        active: st.active,
        exiting: st.exiting,
        entered_at: st.entered_at,
        hidden_count: st.hidden_count,
        hidden_item_count: st.hidden_item_count,
        vaults: s
            .travel_plan()?
            .into_iter()
            .map(|e| TravelVault {
                vault_id: e.vault_id,
                name: e.name,
                leaves: e.leaves,
            })
            .collect(),
        hidden: items(plan.hidden),
        guarded: items(plan.guarded),
    })
}

#[tauri::command]
pub fn travel_status(state: State<'_, AppState>) -> UiResult<TravelView> {
    travel_view(&*session(&state)?)
}

/// "Sûr en voyage" on a vault (it stays on the device in Travel Mode).
#[tauri::command]
pub fn set_vault_travel_safe(
    state: State<'_, AppState>,
    vault_id: String,
    safe: bool,
) -> UiResult<TravelView> {
    let s = session(&state)?;
    let current = s
        .vaults()?
        .into_iter()
        .find(|v| v.id == vault_id)
        .ok_or(OnePassError::NotFound)?;
    s.update_vault(
        vault_id,
        onepass_ffi::FfiVaultMeta {
            travel_safe: safe,
            ..current.meta
        },
    )?;
    travel_view(&s)
}

/// Takes the vaults that are not safe for travel off this device. The core
/// refuses while a change of a leaving vault is not synced: the server copy
/// is what comes back, so a vault never synced must not leave. A round runs
/// first, so a change just made is pushed.
#[tauri::command]
pub async fn enter_travel(app: tauri::AppHandle) -> UiResult<TravelView> {
    blocking(move || {
        let state = tauri::Manager::state::<AppState>(&app);
        let s = session(&state)?;
        state.sync.sync_now_blocking(Duration::from_secs(60));
        s.enter_travel()?;
        travel_view(&s)
    })
    .await?
}

/// The store meta key of the private mailbox cursor (`onepass_sync::CURSOR_KEY`).
const MAILBOX_CURSOR_KEY: &str = "mailbox.cursor";

/// Brings the vaults back (TravelSettings.exit): the sync fetches from
/// scratch (the cursor is forgotten), then the core checks what came back
/// against the manifests this device saw last.
#[tauri::command]
pub async fn exit_travel(app: tauri::AppHandle) -> UiResult<TravelView> {
    blocking(move || {
        let state = tauri::Manager::state::<AppState>(&app);
        let s = session(&state)?;
        if !s.travel_status()?.exiting {
            s.begin_travel_exit()?;
        }
        {
            let mut store =
                onepass_core::sync::SyncStore::open(std::path::Path::new(&state.db_path()))
                    .map_err(|_| OnePassError::Store)?;
            store
                .set_meta(MAILBOX_CURSOR_KEY, &[])
                .map_err(|_| OnePassError::Store)?;
        }
        state.sync.sync_now_blocking(Duration::from_secs(120));
        s.finish_travel_exit()?;
        travel_view(&s)
    })
    .await?
}

// ---- duplicates ---------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateCopy {
    pub summary: SummaryView,
    pub vault_name: String,
    pub writable: bool,
    pub differences: Vec<&'static str>,
    pub has_totp: bool,
    pub attachment_count: u32,
    pub field_count: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateGroup {
    pub id: String,
    /// "sure" (one copy only adds details) or "review" (the copies disagree).
    pub confidence: &'static str,
    pub signals: Vec<&'static str>,
    pub domain: Option<String>,
    /// The suggested primary first.
    pub copies: Vec<DuplicateCopy>,
    /// The labels of the lines that differ (never a value).
    pub conflicts: Vec<String>,
}

fn signal_key(s: onepass_ffi::FfiDuplicateSignal) -> &'static str {
    use onepass_ffi::FfiDuplicateSignal as S;
    match s {
        S::SameTotp => "sameTotp",
        S::SameCardNumber => "sameCard",
        S::SameDocumentNumber => "sameDocument",
        S::SameLogin => "sameLogin",
        S::SameTitleAndUsername => "sameTitle",
    }
}

#[tauri::command]
pub fn duplicate_groups(state: State<'_, AppState>) -> UiResult<Vec<DuplicateGroup>> {
    Ok(session(&state)?
        .duplicate_groups(vec![])?
        .into_iter()
        .map(|g| DuplicateGroup {
            id: g.id,
            confidence: match g.confidence {
                onepass_ffi::FfiDuplicateConfidence::Sure => "sure",
                onepass_ffi::FfiDuplicateConfidence::Review => "review",
            },
            signals: g.signals.into_iter().map(signal_key).collect(),
            domain: g.domain,
            copies: g
                .copies
                .into_iter()
                .map(|c| DuplicateCopy {
                    summary: SummaryView::from(c.summary),
                    vault_name: c.vault_name,
                    writable: c.writable,
                    differences: c.differences.into_iter().map(aspect_key).collect(),
                    has_totp: c.has_totp,
                    attachment_count: c.attachment_count,
                    field_count: c.field_count,
                })
                .collect(),
            conflicts: g
                .rows
                .into_iter()
                .filter(|r| r.kind == onepass_ffi::FfiDuplicateRowKind::Conflict)
                .map(|r| r.label)
                .collect(),
        })
        .collect())
}

fn group_keys(
    s: &Session,
    group_id: &str,
) -> UiResult<(FfiItemKeyPair, Vec<onepass_ffi::FfiItemKey>)> {
    let g = s
        .duplicate_groups(vec![])?
        .into_iter()
        .find(|g| g.id == group_id)
        .ok_or(OnePassError::NotFound)?;
    let mut copies = g.copies.into_iter();
    let first = copies.next().ok_or(OnePassError::NotFound)?;
    let primary = FfiItemKeyPair {
        key: onepass_ffi::FfiItemKey {
            vault_id: first.summary.vault_id.clone(),
            item_id: first.summary.id.clone(),
        },
        title: first.summary.title,
    };
    let others = copies
        .filter(|c| c.writable)
        .map(|c| onepass_ffi::FfiItemKey {
            vault_id: c.summary.vault_id,
            item_id: c.summary.id,
        })
        .collect();
    Ok((primary, others))
}

struct FfiItemKeyPair {
    key: onepass_ffi::FfiItemKey,
    title: String,
}

fn merged_note(title: &str) -> String {
    if fr() {
        format!("Fusionné dans « {title} »")
    } else {
        format!("Merged into \u{201c}{title}\u{201d}")
    }
}

/// Merges a group into its suggested primary with the core's choices for
/// each difference (the other password goes to the history); the other
/// copies are archived intact.
#[tauri::command]
pub fn merge_duplicates(state: State<'_, AppState>, group_id: String) -> UiResult<()> {
    let s = session(&state)?;
    let (primary, others) = group_keys(&s, &group_id)?;
    s.merge_duplicates(primary.key, others, merged_note(&primary.title))?;
    Ok(())
}

/// "Fusionner la sélection": the sure groups chosen.
#[tauri::command]
pub fn merge_sure_duplicates(state: State<'_, AppState>, group_ids: Vec<String>) -> UiResult<u32> {
    let s = session(&state)?;
    let merged = s.merge_sure_duplicates(group_ids, vec![], merged_note("{title}"))?;
    Ok(u32::try_from(merged.len()).unwrap_or(u32::MAX))
}

/// "Archiver les autres", "Supprimer les autres" (restorable) or "Pas des
/// doublons" for a group.
#[tauri::command]
pub fn resolve_duplicates(
    state: State<'_, AppState>,
    group_id: String,
    action: String,
) -> UiResult<()> {
    let s = session(&state)?;
    let (primary, others) = group_keys(&s, &group_id)?;
    match action.as_str() {
        "archive" => s.archive_duplicates(others)?,
        "trash" => s.trash_duplicates(others)?,
        "dismiss" => {
            let mut all = vec![primary.key];
            all.extend(others);
            s.dismiss_duplicates(all)?;
        }
        _ => return Err("unknown action".into()),
    }
    Ok(())
}

// ---- Wi-Fi --------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrView {
    pub ssid: String,
    /// Modules, row by row, `width` per row.
    pub modules: Vec<bool>,
    pub width: usize,
}

/// `\ ; , : "` are escaped in a WIFI: payload.
fn wifi_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The "join this network" QR code of a Wi-Fi router item (the Mac's
/// WifiQRCard). It holds the password: drawn only when the user shows it.
#[tauri::command]
pub fn wifi_qr(state: State<'_, AppState>, vault_id: String, item_id: String) -> UiResult<QrView> {
    let item = session(&state)?.item(vault_id, item_id)?;
    let text = |id: &str| -> Zeroizing<String> {
        Zeroizing::new(
            item.sections
                .iter()
                .flat_map(|s| s.fields.iter())
                .find(|f| f.id == id)
                .and_then(|f| view::display(&f.value))
                .unwrap_or_default(),
        )
    };
    let ssid = text("ssid");
    if ssid.is_empty() {
        return Err(OnePassError::NotFound.into());
    }
    let password = text("wifi_password");
    let security = text("security").to_uppercase();
    let hidden = matches!(
        text("hidden").to_lowercase().as_str(),
        "oui" | "yes" | "true"
    );
    let kind = if password.is_empty() || security.contains("OUVERT") || security.contains("OPEN") {
        "nopass"
    } else if security.contains("WEP") {
        "WEP"
    } else {
        "WPA"
    };
    let mut payload = Zeroizing::new(format!("WIFI:T:{kind};S:{};", wifi_escape(&ssid)));
    if kind != "nopass" {
        payload.push_str(&format!("P:{};", wifi_escape(&password)));
    }
    if hidden {
        payload.push_str("H:true;");
    }
    payload.push(';');
    let code = qrcode::QrCode::with_error_correction_level(payload.as_bytes(), qrcode::EcLevel::H)
        .map_err(|_| "this network does not fit a QR code")?;
    let width = code.width();
    let modules = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    Ok(QrView {
        ssid: ssid.to_string(),
        modules,
        width,
    })
}

// ---- site icons ---------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IconQuery {
    pub id: String,
    #[serde(default)]
    pub url: Option<String>,
    pub title: String,
}

/// The icon pack's icon for each item (by website, then by title), when
/// the "Icônes des sites" setting is on. Items without one are left out.
#[tauri::command]
pub fn site_icons(state: State<'_, AppState>, items: Vec<IconQuery>) -> HashMap<String, usize> {
    let Some(pack) = crate::iconpack::pack().filter(|_| state.prefs().site_icons) else {
        return HashMap::new();
    };
    items
        .into_iter()
        .filter_map(|q| {
            let by_url = q
                .url
                .as_deref()
                .and_then(crate::iconpack::host_of)
                .and_then(|h| pack.for_host(&h));
            by_url
                .or_else(|| pack.for_title(&q.title))
                .map(|i| (q.id, i))
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IconImage {
    /// A data: URL of the WebP image (the CSP allows data: images).
    pub src: String,
    /// A mark to draw in the text color.
    pub mono: bool,
}

#[tauri::command]
pub fn icon_image(index: usize) -> UiResult<IconImage> {
    use base64::Engine;
    let (bytes, mono) = crate::iconpack::pack()
        .and_then(|p| p.image(index))
        .ok_or(OnePassError::NotFound)?;
    Ok(IconImage {
        src: format!(
            "data:image/webp;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        ),
        mono,
    })
}

#[tauri::command]
pub fn set_site_icons(state: State<'_, AppState>, on: bool) -> UiResult<()> {
    Ok(state.update_prefs(|p| p.site_icons = on)?)
}
