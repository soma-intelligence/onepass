//! The IPC commands of sync, the Emergency Kit restore, the device list and
//! pairing (sync.rs, pairing.rs). Each one is declared in build.rs, allowed
//! in capabilities/main.json and in the isolation script.

use std::time::Duration;

use onepass_ffi::{FfiCredentialRole, FfiDeviceMode, FfiRoundStatus, MailboxSync, OnePassError};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::commands::{blocking, confirm_password, device_kind, device_name, session};
use crate::device::SoftwareHalf;
use crate::pairing::{self, PairView};
use crate::secrets::DeviceSecrets;
use crate::state::{AppState, now};
use crate::sync::{self, Backend, Home, Server, SyncView};
use crate::view::{UiError, UiResult};

fn ui(code: &str) -> UiError {
    UiError {
        code: code.into(),
        detail: code.into(),
    }
}

/// Where a vault is kept, as the UI picks it ("Où est rangé mon coffre ?").
#[derive(Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ChoiceInput {
    Hosted,
    #[serde(rename_all = "camelCase")]
    SelfHost {
        url: String,
        ca_pem: Option<String>,
    },
}

/// The server of a choice; a self-host URL must pass `valid_url` (`BadUrl`).
pub fn server_of(c: ChoiceInput) -> UiResult<Server> {
    match c {
        ChoiceInput::Hosted => Ok(sync::hosted()),
        ChoiceInput::SelfHost { url, ca_pem } => {
            let url = url.trim().to_owned();
            if !sync::valid_url(&url) {
                return Err(ui("BadUrl"));
            }
            let ca_pem = ca_pem
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty());
            Ok(Server {
                base_url: url,
                ca_pem,
            })
        }
    }
}

// ---- sync -------------------------------------------------------------------------

#[tauri::command]
pub fn sync_status(state: State<'_, AppState>) -> SyncView {
    let v = state.sync.view();
    if v.backend.is_empty() {
        // The sync thread has not spoken yet.
        return match sync::backend(&state) {
            Backend::Local => SyncView {
                backend: "local",
                state: "off",
                ..SyncView::default()
            },
            Backend::Pending { server } => SyncView {
                backend: "pending",
                server: Some(sync::server_name(&server.base_url)),
                state: "syncing",
                ..SyncView::default()
            },
            Backend::Mailbox { home } => SyncView {
                backend: "mailbox",
                server: Some(sync::server_name(&home.base_url)),
                state: "syncing",
                ..SyncView::default()
            },
        };
    }
    v
}

/// "Synchroniser maintenant": returns once the round ran.
#[tauri::command]
pub async fn sync_now(app: AppHandle) -> UiResult<SyncView> {
    blocking(move || {
        let state = app.state::<AppState>();
        state.sync.sync_now_blocking(Duration::from_secs(120));
        state.sync.view()
    })
    .await
}

/// "Tester": the server answers `GET /v1/config`.
#[tauri::command]
pub async fn check_server(url: String, ca_pem: Option<String>) -> UiResult<bool> {
    let server = server_of(ChoiceInput::SelfHost { url, ca_pem })?;
    blocking(move || onepass_ffi::mailbox_server_check(server.endpoint()).is_ok()).await
}

/// Turns sync on for an account kept on this PC only: the mailbox setup
/// runs (and resumes) in the background, as for a new account.
#[tauri::command]
pub fn enable_sync(state: State<'_, AppState>, choice: ChoiceInput) -> UiResult<SyncView> {
    session(&state)?;
    if !matches!(sync::backend(&state), Backend::Local) {
        return Err("sync is already on".into());
    }
    let server = server_of(choice)?;
    sync::set_backend(&state, &Backend::Pending { server })?;
    state.sync.reset();
    Ok(sync_status(state))
}

// ---- Emergency Kit restore (MailboxRestore.swift) ---------------------------------------

/// "Restaurer avec mon Emergency Kit": the account of `secret_key` is
/// looked up by its locator (the kit's server first, then the Cleon
/// server), fetched with the recovery credential, unlocked with
/// `password`, then this PC gets its own credential. A wrong password
/// leaves nothing granted and an empty store. Errors: `BadKey`,
/// `NotFound`, `Offline`, `WrongPassword`, `RestoreFetch`.
#[tauri::command]
pub async fn restore_kit(
    app: AppHandle,
    secret_key: String,
    password: String,
    server: Option<ChoiceInput>,
) -> UiResult<()> {
    let secret_key = Zeroizing::new(secret_key);
    let password = Zeroizing::new(password);
    let kit_server = match server {
        Some(c @ ChoiceInput::SelfHost { .. }) => Some(server_of(c)?),
        _ => None,
    };
    let key = Zeroizing::new(
        onepass_ffi::normalize_secret_key(secret_key.to_string()).map_err(|_| ui("BadKey"))?,
    );
    blocking(move || restore_blocking(&app, &key, &password, kit_server)).await?
}

fn restore_blocking(
    app: &AppHandle,
    key: &str,
    password: &str,
    kit_server: Option<Server>,
) -> UiResult<()> {
    let state = app.state::<AppState>();
    if onepass_ffi::store_state(state.db_path())? != onepass_ffi::FfiStoreState::Empty {
        return Err("an account already exists on this PC".into());
    }
    let locator = onepass_ffi::mailbox_locator(key.to_owned()).map_err(|_| ui("BadKey"))?;
    let mut servers: Vec<Server> = kit_server.into_iter().collect();
    let hosted = sync::hosted();
    if !servers.iter().any(|s| s.base_url == hosted.base_url) {
        servers.push(hosted);
    }
    let mut unreachable = false;
    let mut found = None;
    'servers: for s in servers {
        let ids = match onepass_ffi::mailbox_locate(s.endpoint(), locator.clone()) {
            Ok(ids) => ids,
            Err(OnePassError::MailboxUnavailable { reason }) if reason.contains("not found") => {
                continue;
            }
            Err(_) => {
                unreachable = true;
                continue;
            }
        };
        // Oldest first: the account's first mailbox is the one its home
        // names. One that no longer answers is skipped (spec D.4).
        for id in ids {
            let home = Home {
                base_url: s.base_url.clone(),
                mailbox_id: id.clone(),
                ca_pem: s.ca_pem.clone(),
            };
            let recovery = onepass_ffi::mailbox_recovery_credential(key.to_owned(), id.clone())?;
            let Ok(client) =
                MailboxSync::open(state.db_path(), home.endpoint(), id, recovery.seed.clone())
            else {
                continue;
            };
            let mut fetched = client.run_round(None, now());
            for _ in 0..8 {
                if !fetched.rerun {
                    break;
                }
                fetched = client.run_round(None, now());
            }
            match fetched.status {
                FfiRoundStatus::Idle
                | FfiRoundStatus::WaitingForServer
                | FfiRoundStatus::Unsettled => {
                    if onepass_ffi::store_state(state.db_path())?
                        == onepass_ffi::FfiStoreState::Account
                    {
                        found = Some((home, client));
                        break 'servers;
                    }
                }
                FfiRoundStatus::Offline => unreachable = true,
                _ => {}
            }
            let _ = onepass_ffi::reset_store(state.db_path());
        }
    }
    let Some((home, recovery_client)) = found else {
        return Err(ui(if unreachable { "Offline" } else { "NotFound" }));
    };
    // The account is here: the master password opens it, with new device keys.
    let undo = |state: &AppState| {
        let _ = onepass_ffi::reset_store(state.db_path());
    };
    let rng_seed = Zeroizing::new(onepass_ffi::new_device_rng_seed()?);
    onepass_ffi::set_device_rng_seed(rng_seed.to_vec())?;
    let classical = Zeroizing::new(onepass_ffi::generate_classical_device_keys()?);
    let pq = SoftwareHalf::generate()?;
    let session = match onepass_ffi::restore_from_kit(
        state.db_path(),
        password.to_owned(),
        key.to_owned(),
        classical.to_vec(),
        SoftwareHalf::open(&pq)?,
        device_name(),
        device_kind(),
        FfiDeviceMode::Personal,
    ) {
        Ok(s) => s,
        Err(e) => {
            undo(&state);
            return Err(e.into());
        }
    };
    let secrets = DeviceSecrets {
        account_id: session.account_id(),
        secret_key: Zeroizing::new(key.to_owned()),
        classical,
        pq,
        rng_seed,
    };
    if let Err(e) = state.save_secrets(&secrets) {
        session.lock();
        undo(&state);
        return Err(e.into());
    }
    // This PC's own credential, granted by the recovery one.
    let device = onepass_ffi::mailbox_generate_credential()?;
    let seed = Zeroizing::new(device.seed.clone());
    recovery_client.grant(
        device.public_key.clone(),
        FfiCredentialRole::Manage,
        Vec::new(),
    )?;
    sync::store_seed(&state, &home.mailbox_id, &seed)?;
    sync::set_backend(&state, &Backend::Mailbox { home })?;
    state.set_session(session);
    // The rebase of what the recovery fetch staged, signed by this PC.
    state.sync.reset();
    state.sync.sync_now_blocking(Duration::from_secs(60));
    Ok(())
}

// ---- the device list -----------------------------------------------------------------

#[tauri::command]
pub fn rename_device(state: State<'_, AppState>, id: String, name: String) -> UiResult<()> {
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err(ui("EmptyName"));
    }
    session(&state)?.rename_device(id, name)?;
    Ok(())
}

/// "Retirer l'appareil": fresh presence (the master password), then the
/// device is marked revoked in the signed list; it erases its Cleon data
/// when it sees the list.
#[tauri::command]
pub async fn revoke_device(
    state: State<'_, AppState>,
    id: String,
    password: String,
) -> UiResult<()> {
    confirm_password(&state, Zeroizing::new(password)).await?;
    session(&state)?.revoke_device(id)?;
    state.sync.changed();
    Ok(())
}

// ---- pairing ----------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairState {
    pub active: bool,
    pub view: Option<PairView>,
}

#[tauri::command]
pub fn pair_state(state: State<'_, AppState>) -> PairState {
    let view = state
        .pairing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(pairing::Pairing::view);
    PairState {
        active: view.is_some(),
        view,
    }
}

/// "Ajouter un appareil": this PC shows a code.
#[tauri::command]
pub fn pair_host_start(app: AppHandle, state: State<'_, AppState>) -> UiResult<()> {
    session(&state)?;
    pairing::start_host(&app);
    Ok(())
}

/// The user typed the 6 digits the new device shows, and the master
/// password. `SasMismatch` when the digits differ.
#[tauri::command]
pub async fn pair_host_approve(
    state: State<'_, AppState>,
    sas: String,
    password: String,
) -> UiResult<()> {
    {
        let p = state
            .pairing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let p = p
            .as_ref()
            .filter(|p| p.role == "host")
            .ok_or("no pairing")?;
        if !p.sas_matches(&sas) {
            return Err(ui("SasMismatch"));
        }
    }
    confirm_password(&state, Zeroizing::new(password)).await?;
    let p = state
        .pairing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    p.as_ref().ok_or("no pairing")?.approve();
    Ok(())
}

/// "Ajouter cet appareil": join the device that shows `code` (`XXXX-XXXX`
/// or the QR text) through `server`. `BadCode` when it does not parse.
#[tauri::command]
pub fn pair_join_start(
    app: AppHandle,
    state: State<'_, AppState>,
    code: String,
    server: ChoiceInput,
) -> UiResult<()> {
    if onepass_ffi::store_state(state.db_path())? != onepass_ffi::FfiStoreState::Empty {
        return Err("an account already exists on this PC".into());
    }
    let code = code.trim().to_owned();
    if onepass_ffi::pairing_rendezvous_service_name(code.clone()).is_err() {
        return Err(ui("BadCode"));
    }
    let server = server_of(server)?;
    pairing::start_join(&app, code, server);
    Ok(())
}

#[tauri::command]
pub fn pair_join_confirm(state: State<'_, AppState>) -> UiResult<()> {
    let p = state
        .pairing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    p.as_ref().ok_or("no pairing")?.confirm();
    Ok(())
}

#[tauri::command]
pub fn pair_join_password(state: State<'_, AppState>, password: String) -> UiResult<()> {
    let p = state
        .pairing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    p.as_ref()
        .ok_or("no pairing")?
        .password(Zeroizing::new(password));
    Ok(())
}

/// "Annuler" or "Ils sont différents": nothing is granted.
#[tauri::command]
pub fn pair_cancel(state: State<'_, AppState>) {
    if let Some(p) = state
        .pairing
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        p.cancel();
    }
}

// ---- the kit's QR code, from an image ------------------------------------------------

/// What a kit's QR code gives: its Secret Key and, for a self-hosted
/// account, its server (`EmergencyKit.parseKit`).
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KitScan {
    pub secret_key: String,
    pub server: Option<String>,
}

/// `onepass-kit:1:<key>` or `onepass-kit:2:<account id>:<key>`, then
/// `;<server URL>` for a self-hosted account. A server that is not a valid
/// URL is dropped (the key still counts).
pub fn parse_kit(text: &str) -> Option<KitScan> {
    let text = text.trim();
    let (kit, server) = match text.split_once(';') {
        Some((k, s)) => (k, Some(s.trim().to_owned()).filter(|s| sync::valid_url(s))),
        None => (text, None),
    };
    let lower = kit.to_ascii_lowercase();
    let body = if lower.starts_with("onepass-kit:1:") {
        &kit["onepass-kit:1:".len()..]
    } else if lower.starts_with("onepass-kit:2:") {
        let (id, key) = kit["onepass-kit:2:".len()..].split_once(':')?;
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        key
    } else {
        return None;
    };
    let secret_key = onepass_ffi::normalize_secret_key(body.to_owned()).ok()?;
    Some(KitScan { secret_key, server })
}

/// "Lire le QR code du kit…": an image of the Emergency Kit (a scan, a
/// screenshot of its PDF) picked in the open dialog, decoded here.
/// `None` on cancel; `NoKit` when no kit code is found in it.
#[tauri::command]
pub async fn read_kit_image(window: tauri::WebviewWindow) -> UiResult<Option<KitScan>> {
    let title = if crate::state::language() == "fr" {
        "Image de l'Emergency Kit"
    } else {
        "Emergency Kit Image"
    };
    let Some(path) = crate::dialog::pick_file(
        &window,
        title,
        &[("Images", &["png", "jpg", "jpeg", "bmp", "gif", "webp"])],
    )
    .await
    else {
        return Ok(None);
    };
    blocking(move || -> UiResult<Option<KitScan>> {
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        if meta.len() > 40 * 1024 * 1024 {
            return Err(ui("NoKit"));
        }
        let img = image::open(&path).map_err(|_| ui("NoKit"))?.to_luma8();
        let mut prepared = rqrr::PreparedImage::prepare(img);
        for grid in prepared.detect_grids() {
            if let Ok((_, text)) = grid.decode()
                && let Some(scan) = parse_kit(&text)
            {
                return Ok(Some(scan));
            }
        }
        Err(ui("NoKit"))
    })
    .await?
}

// ---- devices restored with the Emergency Kit (spec 7.5) ------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KitDevices {
    /// This device was restored with the kit and no other device trusts it yet.
    pub awaiting_trust: bool,
    /// Devices restored with the kit asking this one to trust them.
    pub asking: Vec<KitDevice>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KitDevice {
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    pub name_in_use: bool,
    pub rotated: bool,
}

#[tauri::command]
pub fn kit_devices(state: State<'_, AppState>) -> UiResult<KitDevices> {
    let s = session(&state)?;
    Ok(KitDevices {
        awaiting_trust: s.awaiting_pin().unwrap_or(false),
        asking: s
            .kit_restored_devices()?
            .into_iter()
            .map(|d| KitDevice {
                kind: pairing::kind_key(d.kind),
                id: d.id,
                name: d.name,
                name_in_use: d.name_in_use,
                rotated: d.rotated,
            })
            .collect(),
    })
}

/// "Faire confiance" (after the master password) or "Refuser".
#[tauri::command]
pub async fn answer_kit_device(
    state: State<'_, AppState>,
    id: String,
    trust: bool,
    password: String,
) -> UiResult<()> {
    let s = session(&state)?;
    if trust {
        confirm_password(&state, Zeroizing::new(password)).await?;
        let secrets = state.load_secrets()?.ok_or("device")?;
        s.accept_kit_restored(
            id,
            secrets.classical.to_vec(),
            SoftwareHalf::open(&secrets.pq)?,
        )?;
    } else {
        s.reject_kit_restored(id)?;
    }
    state.sync.changed();
    Ok(())
}

/// "Je n'ai plus d'autre appareil", on a kit-restored device, after the
/// master password.
#[tauri::command]
pub async fn claim_only_device(state: State<'_, AppState>, password: String) -> UiResult<()> {
    confirm_password(&state, Zeroizing::new(password)).await?;
    session(&state)?.claim_only_device()?;
    state.sync.changed();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kit_payloads() {
        let key = onepass_ffi::generate_secret_key().unwrap();
        let bare: String = key.chars().filter(|c| *c != '-').collect();
        let v1 = parse_kit(&format!("onepass-kit:1:{bare}")).unwrap();
        assert_eq!(v1.secret_key, key);
        assert_eq!(v1.server, None);
        let v2 = parse_kit(&format!(
            "onepass-kit:2:{}:{bare};https://sync.example.org/functions/v1/mailbox",
            "ab".repeat(16)
        ))
        .unwrap();
        assert_eq!(v2.secret_key, key);
        assert_eq!(
            v2.server.as_deref(),
            Some("https://sync.example.org/functions/v1/mailbox")
        );
        assert_eq!(
            parse_kit(&format!("onepass-kit:1:{bare};http://x"))
                .unwrap()
                .server,
            None
        );
        assert!(parse_kit("onepass-kit:2:zz:ABC").is_none());
        assert!(parse_kit("WIFI:T:WPA;S:x;;").is_none());
    }
}

#[cfg(test)]
mod image_tests {
    use super::*;

    /// A kit QR drawn into a picture is found and read back.
    #[test]
    fn kit_qr_in_an_image() {
        let key = onepass_ffi::generate_secret_key().unwrap();
        let bare: String = key.chars().filter(|c| *c != '-').collect();
        let code = qrcode::QrCode::with_error_correction_level(
            format!("onepass-kit:1:{bare}").as_bytes(),
            qrcode::EcLevel::M,
        )
        .unwrap();
        let (w, scale, quiet) = (code.width() as u32, 6, 4);
        let side = (w + 2 * quiet) * scale;
        let colors = code.to_colors();
        let img = image::GrayImage::from_fn(side + 40, side + 40, |x, y| {
            let (x, y) = (x.wrapping_sub(20) / scale, y.wrapping_sub(20) / scale);
            let inside = (quiet..quiet + w).contains(&x) && (quiet..quiet + w).contains(&y);
            let dark =
                inside && colors[((y - quiet) * w + (x - quiet)) as usize] == qrcode::Color::Dark;
            image::Luma([if dark { 0 } else { 255 }])
        });
        let mut prepared = rqrr::PreparedImage::prepare(img);
        let grids = prepared.detect_grids();
        let (_, text) = grids[0].decode().unwrap();
        assert_eq!(parse_kit(&text).unwrap().secret_key, key);
    }
}
