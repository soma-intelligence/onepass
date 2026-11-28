//! The IPC commands of contacts, shared vaults, item sends, the family and
//! organizer-assisted recovery (sharing plan 4; `VaultSession+Sharing`,
//! `+Family` and `+Recovery` of the Apple apps). These calls write the
//! core's records and queue its share actions; the zone round (zones.rs)
//! carries them, so each write is followed by a round (`sync::WRITES`).
//! Every name shown is the contact book's local name, every role the
//! core's. Each command is declared in build.rs, allowed in
//! capabilities/main.json and in the isolation script.

use std::sync::Arc;
use std::time::Duration;

use onepass_ffi::{
    FfiAdoptionProof, FfiContactLevel, FfiFamilyRole, FfiRecoveryStatus, FfiRole, OnePassError,
    Session,
};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::commands::{blocking, session};
use crate::contacts::{self, ContactView, InviteView};
use crate::device::SoftwareHalf;
use crate::state::{AppState, now};
use crate::view::{UiError, UiResult};

fn ui(code: &str) -> UiError {
    UiError {
        code: code.into(),
        detail: code.into(),
    }
}

fn role_key(r: FfiRole) -> &'static str {
    match r {
        FfiRole::Read => "read",
        FfiRole::Write => "write",
        FfiRole::Manage => "manage",
    }
}

fn parse_role(s: &str) -> UiResult<FfiRole> {
    match s {
        "read" => Ok(FfiRole::Read),
        "write" => Ok(FfiRole::Write),
        "manage" => Ok(FfiRole::Manage),
        _ => Err(ui("BadRole")),
    }
}

fn level_key(l: FfiContactLevel) -> &'static str {
    match l {
        FfiContactLevel::Link => "link",
        FfiContactLevel::Verified => "verified",
    }
}

fn family_role_key(r: FfiFamilyRole) -> &'static str {
    match r {
        FfiFamilyRole::Member => "member",
        FfiFamilyRole::Organizer => "organizer",
    }
}

fn parse_family_role(s: &str) -> UiResult<FfiFamilyRole> {
    match s {
        "member" => Ok(FfiFamilyRole::Member),
        "organizer" => Ok(FfiFamilyRole::Organizer),
        _ => Err(ui("BadRole")),
    }
}

// ---- the snapshot ------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    pub account_id: String,
    /// Empty for this account and for an account not in the book.
    pub name: String,
    pub role: &'static str,
    pub owner: bool,
    pub level: &'static str,
    pub keys_changed: bool,
    pub key_pending: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharedVaultView {
    pub vault_id: String,
    pub name: String,
    pub role: &'static str,
    pub owner: bool,
    pub generation: u32,
    pub members: Vec<MemberView>,
    pub identity_pending: bool,
    /// Members that have not confirmed this account's new keys (spec 12.4).
    pub not_confirmed: u32,
    /// The server refuses this vault's credential: kept read-only (13.8).
    pub refused: bool,
    /// Its mailbox is full.
    pub full: bool,
}

fn shared_view(s: onepass_ffi::FfiSharedVault, not_confirmed: u32) -> SharedVaultView {
    SharedVaultView {
        role: role_key(s.role),
        owner: s.owner,
        generation: s.generation,
        members: s
            .members
            .into_iter()
            .map(|m| MemberView {
                account_id: m.account_id,
                name: m.name_local,
                role: role_key(m.role),
                owner: m.owner,
                level: level_key(m.level),
                keys_changed: m.keys_changed,
                key_pending: m.key_pending,
            })
            .collect(),
        identity_pending: s.identity_pending,
        not_confirmed,
        refused: false,
        full: false,
        vault_id: s.vault_id,
        name: s.name,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareInviteView {
    pub id: String,
    pub vault_name_hint: Option<String>,
    pub from_name: String,
    pub role: &'static str,
    pub server_host: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityChangeView {
    pub account_id: String,
    pub name: String,
    pub child: String,
    pub rotator_name: Option<String>,
    pub revoked_names: Vec<String>,
    pub issued_at: i64,
    pub vaults: Vec<String>,
    /// "code" (every vault this account manages with them gives Read),
    /// "inPerson" or "forked" (`identityChangeOffer`).
    pub offer: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FamilyMemberView {
    pub account_id: String,
    pub name: String,
    pub role: &'static str,
    pub level: &'static str,
    pub keys_changed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FamilyView {
    pub family_id: String,
    pub members: Vec<FamilyMemberView>,
    pub vaults: Vec<String>,
    pub i_am_organizer: bool,
    pub needs_second_organizer: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FamilyInviteView {
    pub id: String,
    pub from_name: String,
    pub role: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentView {
    pub enrollment_id: String,
    pub organizer_name: String,
    pub delay_secs: u32,
    pub created_at: i64,
    pub valid: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelperView {
    pub member: String,
    pub name: String,
    pub enrollment_id: String,
    pub delay_secs: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedItemView {
    pub send_id: String,
    pub from_name: String,
    pub title: String,
    pub kind: &'static str,
    pub expires_at: i64,
}

/// What the sharing screens show (`SharingSnapshot`). A part that cannot be
/// read is left empty: display only.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SharingView {
    /// The account syncs through a mailbox: zones can be made.
    pub zones_ready: bool,
    pub contacts: Vec<ContactView>,
    pub shared_vaults: Vec<SharedVaultView>,
    pub share_invites: Vec<ShareInviteView>,
    pub identity_changes: Vec<IdentityChangeView>,
    pub family: Option<FamilyView>,
    pub family_invites: Vec<FamilyInviteView>,
    pub recovery_enrollment: Option<EnrollmentView>,
    pub helpers: Vec<HelperView>,
    pub received_items: Vec<ReceivedItemView>,
    pub seen_by_former_members: Vec<String>,
}

fn snapshot(state: &AppState, s: &Session) -> SharingView {
    let t = now();
    let zone_view = state.sync.zones.view();
    let shared = s.shared_vaults().unwrap_or_default();
    let changes = s.refresh_member_identities(t).unwrap_or_default();
    let shared_vaults: Vec<SharedVaultView> = shared
        .iter()
        .cloned()
        .map(|v| {
            let n = if v.role == FfiRole::Manage {
                s.members_not_confirmed(v.vault_id.clone())
                    .map(|m| u32::try_from(m.len()).unwrap_or(u32::MAX))
                    .unwrap_or(0)
            } else {
                0
            };
            let mut view = shared_view(v, n);
            view.refused = zone_view.refused_vaults.contains(&view.vault_id);
            view.full = zone_view.full_vaults.contains(&view.vault_id);
            view
        })
        .collect();
    let identity_changes = changes
        .into_iter()
        .map(|c| {
            let roles: Vec<FfiRole> = shared
                .iter()
                .filter(|v| c.vaults.contains(&v.vault_id))
                .filter_map(|v| {
                    v.members
                        .iter()
                        .find(|m| m.account_id == c.account_id)
                        .map(|m| m.role)
                })
                .collect();
            let offer = if c.forked {
                "forked"
            } else if roles.iter().any(|r| *r != FfiRole::Read) {
                "inPerson"
            } else {
                "code"
            };
            IdentityChangeView {
                account_id: c.account_id,
                name: c.name_local,
                child: c.child,
                rotator_name: c.rotator_name,
                revoked_names: c.revoked_names,
                issued_at: c.issued_at,
                vaults: c.vaults,
                offer,
            }
        })
        .collect();
    SharingView {
        zones_ready: state.sync.zones.client().is_some(),
        contacts: s
            .contacts()
            .unwrap_or_default()
            .into_iter()
            .map(ContactView::from)
            .filter(|c| c.state != "removed")
            .collect(),
        shared_vaults,
        share_invites: s
            .share_invites()
            .unwrap_or_default()
            .into_iter()
            .map(|i| ShareInviteView {
                id: i.id,
                vault_name_hint: i.vault_name_hint,
                from_name: i.from_name_local,
                role: role_key(i.role),
                server_host: i.server_host,
            })
            .collect(),
        identity_changes,
        family: s.family().ok().flatten().map(|f| FamilyView {
            family_id: f.family_id,
            members: f
                .members
                .into_iter()
                .map(|m| FamilyMemberView {
                    account_id: m.account_id,
                    name: m.name_local,
                    role: family_role_key(m.role),
                    level: level_key(m.level),
                    keys_changed: m.keys_changed,
                })
                .collect(),
            vaults: f.vaults,
            i_am_organizer: f.i_am_organizer,
            needs_second_organizer: f.needs_second_organizer,
        }),
        family_invites: s
            .family_invites()
            .unwrap_or_default()
            .into_iter()
            .map(|i| FamilyInviteView {
                id: i.id,
                from_name: i.from_name_local,
                role: family_role_key(i.role),
            })
            .collect(),
        recovery_enrollment: s
            .recovery_enrollment()
            .ok()
            .flatten()
            .map(|e| EnrollmentView {
                enrollment_id: e.enrollment_id,
                organizer_name: e.organizer_name_local,
                delay_secs: e.delay_secs,
                created_at: e.created_at,
                valid: e.valid,
            }),
        helpers: s
            .recovery_enrollments_for_me()
            .unwrap_or_default()
            .into_iter()
            .map(|h| HelperView {
                member: h.member,
                name: h.name_local,
                enrollment_id: h.enrollment_id,
                delay_secs: h.delay_secs,
            })
            .collect(),
        received_items: s
            .received_items(t)
            .unwrap_or_default()
            .into_iter()
            .map(|r| ReceivedItemView {
                send_id: r.send_id,
                from_name: r.from_name_local,
                title: r.title,
                kind: crate::view::type_key(r.kind),
                expires_at: r.expires_at,
            })
            .collect(),
        seen_by_former_members: s
            .seen_by_former_members()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.item_id)
            .collect(),
    }
}

#[tauri::command]
pub fn sharing_state(state: State<'_, AppState>) -> UiResult<SharingView> {
    let s = session(&state)?;
    Ok(snapshot(&state, &s))
}

// ---- recovery requests (shown locked too) --------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryAlertView {
    pub enrollment_id: String,
    pub organizer_name: String,
    pub release_after: i64,
}

/// The recovery requests for this account, read without unlocking.
#[tauri::command]
pub fn recovery_alerts(state: State<'_, AppState>) -> Vec<RecoveryAlertView> {
    if onepass_ffi::store_state(state.db_path()).ok() != Some(onepass_ffi::FfiStoreState::Account) {
        return Vec::new();
    }
    onepass_ffi::recovery_alerts(state.db_path())
        .unwrap_or_default()
        .into_iter()
        .map(|a| RecoveryAlertView {
            enrollment_id: a.enrollment_id,
            organizer_name: a.organizer_name_local,
            release_after: a.release_after,
        })
        .collect()
}

/// "Annuler la récupération": signed by this PC's keys, no password, so a
/// locked PC can stop a recovery it did not ask for.
#[tauri::command]
pub fn cancel_recovery(state: State<'_, AppState>, enrollment_id: String) -> UiResult<()> {
    let secrets = state.load_secrets()?.ok_or("device")?;
    onepass_ffi::cancel_recovery(
        state.db_path(),
        enrollment_id,
        secrets.classical.to_vec(),
        SoftwareHalf::open(&secrets.pq)?,
        now(),
    )?;
    state.sync.changed();
    Ok(())
}

// ---- contacts -------------------------------------------------------------------------------

fn need_zones(state: &AppState) -> UiResult<()> {
    if state.sync.zones.client().is_none() {
        return Err(ui("NoSync"));
    }
    Ok(())
}

/// "Créer un lien".
#[tauri::command]
pub fn contact_invite_create(app: AppHandle, state: State<'_, AppState>) -> UiResult<InviteView> {
    let s = session(&state)?;
    need_zones(&state)?;
    contacts::start_inviter(&app, s);
    contact_invite_state(state)
}

/// A link received from a contact, pasted here.
#[tauri::command]
pub fn contact_invite_open(
    app: AppHandle,
    state: State<'_, AppState>,
    link: String,
) -> UiResult<InviteView> {
    let s = session(&state)?;
    need_zones(&state)?;
    if !link.trim().starts_with("onepass://contact") {
        return Err(ui("BadLink"));
    }
    contacts::start_invitee(&app, s, link);
    contact_invite_state(state)
}

#[tauri::command]
pub fn contact_invite_state(state: State<'_, AppState>) -> UiResult<InviteView> {
    Ok(state
        .invite
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(contacts::InviteFlow::view)
        .unwrap_or_default())
}

#[tauri::command]
pub fn contact_invite_cancel(state: State<'_, AppState>) {
    if let Some(f) = state
        .invite
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        f.cancel();
    }
}

#[tauri::command]
pub fn rename_contact(
    state: State<'_, AppState>,
    account_id: String,
    name: String,
) -> UiResult<()> {
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err(ui("EmptyName"));
    }
    session(&state)?.rename_contact(account_id, name)?;
    Ok(())
}

/// Remove a contact: its shares are revoked by the next zone round.
#[tauri::command]
pub fn remove_contact(state: State<'_, AppState>, account_id: String) -> UiResult<()> {
    session(&state)?.remove_contact(account_id, now())?;
    Ok(())
}

/// "Les numéros sont identiques": a Link contact becomes Verified.
#[tauri::command]
pub fn confirm_safety_number(
    state: State<'_, AppState>,
    account_id: String,
    shown: String,
) -> UiResult<ContactView> {
    Ok(session(&state)?
        .confirm_safety_number(account_id, shown, now())?
        .into())
}

// ---- shared vaults -----------------------------------------------------------------------------

/// "Partager" (ShareVaultSheet): a personal vault is shared first, a round
/// makes its mailbox, then the contact is invited with `role`.
#[tauri::command]
pub async fn add_vault_member(
    app: AppHandle,
    vault_id: String,
    contact: String,
    role: String,
) -> UiResult<()> {
    let role = parse_role(&role)?;
    blocking(move || -> UiResult<()> {
        let state = app.state::<AppState>();
        let s = session(&state)?;
        need_zones(&state)?;
        let shared = s.shared_vaults()?.iter().any(|v| v.vault_id == vault_id);
        if !shared {
            s.share_vault(vault_id.clone(), now())?;
            // The vault's mailbox is made by the zone round (spec 13.3).
            state.sync.sync_now_blocking(Duration::from_secs(60));
        }
        s.add_member(vault_id, contact, role, now())?;
        state.sync.changed();
        Ok(())
    })
    .await?
}

#[tauri::command]
pub fn set_member_role(
    state: State<'_, AppState>,
    vault_id: String,
    account_id: String,
    role: String,
) -> UiResult<()> {
    session(&state)?.set_role(vault_id, account_id, parse_role(&role)?, now())?;
    Ok(())
}

/// "Retirer": with a new key; how many items they could read (spec 9.3).
#[tauri::command]
pub fn remove_member(
    state: State<'_, AppState>,
    vault_id: String,
    account_id: String,
) -> UiResult<u32> {
    Ok(session(&state)?
        .remove_member(vault_id, account_id, now())?
        .seen_items)
}

#[tauri::command]
pub fn leave_shared_vault(state: State<'_, AppState>, vault_id: String) -> UiResult<()> {
    session(&state)?.leave_shared_vault(vault_id, now())?;
    Ok(())
}

#[tauri::command]
pub fn stop_sharing(state: State<'_, AppState>, vault_id: String) -> UiResult<()> {
    session(&state)?.stop_sharing(vault_id, now())?;
    Ok(())
}

#[tauri::command]
pub fn accept_share_invite(state: State<'_, AppState>, invite_id: String) -> UiResult<String> {
    Ok(session(&state)?
        .accept_share_invite(invite_id, now())?
        .vault_id)
}

#[tauri::command]
pub fn decline_share_invite(state: State<'_, AppState>, invite_id: String) -> UiResult<()> {
    session(&state)?.decline_share_invite(invite_id)?;
    Ok(())
}

/// A reader's new keys, confirmed with the 6-digit code shown on their device.
#[tauri::command]
pub fn adopt_member_identity(
    state: State<'_, AppState>,
    account_id: String,
    child: String,
    code: String,
) -> UiResult<()> {
    let code: u32 = code.trim().parse().map_err(|_| ui("BadCode"))?;
    session(&state)?.adopt_member_identity(
        account_id,
        child,
        FfiAdoptionProof::Code { code },
        now(),
    )?;
    Ok(())
}

// ---- item sends ----------------------------------------------------------------------------------

/// Send a copy of an item to a contact, kept `days` days (30 at most).
#[tauri::command]
pub fn send_item(
    state: State<'_, AppState>,
    vault_id: String,
    item_id: String,
    to: String,
    days: u32,
) -> UiResult<()> {
    let t = now();
    let until = t + i64::from(days.clamp(1, 30)) * 86_400;
    session(&state)?.send_item(vault_id, item_id, to, until, t)?;
    Ok(())
}

#[tauri::command]
pub fn accept_received_item(
    state: State<'_, AppState>,
    send_id: String,
    into: String,
) -> UiResult<String> {
    Ok(session(&state)?
        .accept_received_item(send_id, into, now())?
        .id)
}

#[tauri::command]
pub fn decline_received_item(state: State<'_, AppState>, send_id: String) -> UiResult<()> {
    session(&state)?.decline_received_item(send_id)?;
    Ok(())
}

// ---- the family ----------------------------------------------------------------------------------

/// "Créer une famille": its mailboxes are made by the next round, run now so
/// the organizer can invite at once.
#[tauri::command]
pub async fn create_family(app: AppHandle, vault_name: String) -> UiResult<()> {
    blocking(move || -> UiResult<()> {
        let state = app.state::<AppState>();
        need_zones(&state)?;
        session(&state)?.create_family(vault_name, now())?;
        state.sync.sync_now_blocking(Duration::from_secs(60));
        Ok(())
    })
    .await?
}

#[tauri::command]
pub async fn invite_to_family(app: AppHandle, contact: String, role: String) -> UiResult<()> {
    let role = parse_family_role(&role)?;
    blocking(move || -> UiResult<()> {
        let state = app.state::<AppState>();
        let s = session(&state)?;
        match s.invite_to_family(contact.clone(), role, now()) {
            // The family zone is made by a round that has not run yet.
            Err(OnePassError::Validation { field, .. }) if field == "zone" => {
                state.sync.sync_now_blocking(Duration::from_secs(60));
                s.invite_to_family(contact, role, now())?;
            }
            other => {
                other?;
            }
        }
        state.sync.changed();
        Ok(())
    })
    .await?
}

#[tauri::command]
pub fn accept_family_invite(state: State<'_, AppState>, invite_id: String) -> UiResult<()> {
    session(&state)?.accept_family_invite(invite_id, now())?;
    Ok(())
}

#[tauri::command]
pub fn remove_from_family(state: State<'_, AppState>, account_id: String) -> UiResult<()> {
    session(&state)?.remove_from_family(account_id, now())?;
    Ok(())
}

#[tauri::command]
pub fn leave_family(state: State<'_, AppState>) -> UiResult<()> {
    session(&state)?.leave_family(now())?;
    Ok(())
}

#[tauri::command]
pub fn set_family_role(
    state: State<'_, AppState>,
    account_id: String,
    role: String,
) -> UiResult<()> {
    session(&state)?.set_family_role(account_id, parse_family_role(&role)?, now())?;
    Ok(())
}

#[tauri::command]
pub fn add_family_vault(state: State<'_, AppState>, vault_id: String) -> UiResult<()> {
    session(&state)?.add_family_vault(vault_id, now())?;
    Ok(())
}

// ---- organizer-assisted recovery -----------------------------------------------------------------

/// The typed password and this PC's Secret Key, as the core takes them.
fn credentials(state: &AppState, password: String) -> UiResult<(String, String, Arc<Session>)> {
    let s = session(state)?;
    let secrets = state.load_secrets()?.ok_or("device")?;
    Ok((password, secrets.secret_key.to_string(), s))
}

/// "Activer" (RecoveryEnrollView): `organizer` helps after `days` days.
#[tauri::command]
pub async fn enroll_recovery(
    app: AppHandle,
    organizer: String,
    days: u32,
    password: String,
) -> UiResult<()> {
    let password = Zeroizing::new(password);
    blocking(move || -> UiResult<()> {
        let state = app.state::<AppState>();
        let (pw, sk, s) = credentials(&state, password.to_string())?;
        let (pw, sk) = (Zeroizing::new(pw), Zeroizing::new(sk));
        s.enroll_recovery(
            organizer,
            days.clamp(1, 7) * 86_400,
            pw.to_string(),
            sk.to_string(),
            now(),
        )?;
        state.sync.changed();
        Ok(())
    })
    .await?
}

#[tauri::command]
pub async fn disable_recovery(app: AppHandle, password: String) -> UiResult<()> {
    let password = Zeroizing::new(password);
    blocking(move || -> UiResult<()> {
        let state = app.state::<AppState>();
        let (pw, sk, s) = credentials(&state, password.to_string())?;
        let (pw, sk) = (Zeroizing::new(pw), Zeroizing::new(sk));
        s.disable_recovery(pw.to_string(), sk.to_string())?;
        state.sync.changed();
        Ok(())
    })
    .await?
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RecoveryStatusView {
    #[serde(rename_all = "camelCase")]
    Waiting {
        release_after: i64,
    },
    Ready,
    #[serde(rename_all = "camelCase")]
    Cancelled {
        at: i64,
    },
    Replaced,
    NotEnrolled,
}

impl From<FfiRecoveryStatus> for RecoveryStatusView {
    fn from(s: FfiRecoveryStatus) -> Self {
        match s {
            FfiRecoveryStatus::Waiting { release_after } => {
                RecoveryStatusView::Waiting { release_after }
            }
            FfiRecoveryStatus::Ready => RecoveryStatusView::Ready,
            FfiRecoveryStatus::Cancelled { at } => RecoveryStatusView::Cancelled { at },
            FfiRecoveryStatus::Replaced => RecoveryStatusView::Replaced,
            FfiRecoveryStatus::NotEnrolled => RecoveryStatusView::NotEnrolled,
        }
    }
}

/// "Demander la récupération" (organizer side): the delay starts now.
#[tauri::command]
pub async fn request_recovery(
    app: AppHandle,
    member: String,
    password: String,
) -> UiResult<RecoveryStatusView> {
    let password = Zeroizing::new(password);
    blocking(move || -> UiResult<RecoveryStatusView> {
        let state = app.state::<AppState>();
        let (pw, sk, s) = credentials(&state, password.to_string())?;
        let (pw, sk) = (Zeroizing::new(pw), Zeroizing::new(sk));
        let status = s.request_recovery(member, pw.to_string(), sk.to_string(), now())?;
        state.sync.changed();
        Ok(status.into())
    })
    .await?
}

#[tauri::command]
pub fn recovery_status(state: State<'_, AppState>, member: String) -> UiResult<RecoveryStatusView> {
    match session(&state)?.recovery_status(member, now()) {
        Ok(s) => Ok(s.into()),
        Err(OnePassError::NotFound) => Ok(RecoveryStatusView::NotEnrolled),
        Err(e) => Err(e.into()),
    }
}
