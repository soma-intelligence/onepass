//! The family, organizer-assisted recovery and item sends for the apps
//! (sharing plan 4, Task 4; spec 11 and 14.2).
//!
//! Like the shared vaults, these calls write the core's records and queue
//! its share actions; the zone round carries them. Every call takes the
//! app's clock `now`, as the rest of the sharing surface does.

use std::sync::{Arc, Mutex};

use onepass_core::contact::ContactResponder;
use onepass_core::crypto::SecretKey;
use onepass_core::family::FamilyRole;
use onepass_core::repo::RecoverRequest;
use onepass_core::repo::family::{FamilyInfo, FamilyInviteView, FamilyMemberView};
use onepass_core::repo::recovery::{
    self as core_recovery, HelperView, RecoveryAlert, RecoveryEnrollmentView, RecoveryStatus,
};
use onepass_core::repo::send::ReceivedItem;
use zeroize::Zeroizing;

use crate::contacts::{FfiContactInitiator, FfiContactLevel, lock};
use crate::convert::{id_hex, item_to_ffi, parse_id};
use crate::devices::{FfiDeviceKind, FfiDeviceMode};
use crate::error::OnePassError;
use crate::rotation::{FfiPqDeviceHalf, device_keys};
use crate::session::{Session, find_vault};
use crate::types::{FfiItem, FfiItemType};

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiFamilyRole {
    Member,
    Organizer,
}

impl From<FamilyRole> for FfiFamilyRole {
    fn from(r: FamilyRole) -> FfiFamilyRole {
        match r {
            FamilyRole::Member => FfiFamilyRole::Member,
            FamilyRole::Organizer => FfiFamilyRole::Organizer,
        }
    }
}

impl From<FfiFamilyRole> for FamilyRole {
    fn from(r: FfiFamilyRole) -> FamilyRole {
        match r {
            FfiFamilyRole::Member => FamilyRole::Member,
            FfiFamilyRole::Organizer => FamilyRole::Organizer,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiFamilyMember {
    pub account_id: String,
    pub name_local: String,
    pub role: FfiFamilyRole,
    pub level: FfiContactLevel,
    /// The member's account rotated since it joined: its identity waits
    /// for a confirmation.
    pub keys_changed: bool,
}

impl From<&FamilyMemberView> for FfiFamilyMember {
    fn from(m: &FamilyMemberView) -> FfiFamilyMember {
        FfiFamilyMember {
            account_id: id_hex(m.account_id),
            name_local: m.name_local.clone(),
            role: m.role.into(),
            level: m.level.into(),
            keys_changed: m.keys_changed,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiFamily {
    pub family_id: String,
    pub members: Vec<FfiFamilyMember>,
    /// The family's shared vaults (the first one is made with the family).
    pub vaults: Vec<String>,
    pub i_am_organizer: bool,
    /// One organizer only: the app reminds the family (decision 13).
    pub needs_second_organizer: bool,
}

impl From<&FamilyInfo> for FfiFamily {
    fn from(f: &FamilyInfo) -> FfiFamily {
        FfiFamily {
            family_id: id_hex(f.family_id),
            members: f.members.iter().map(FfiFamilyMember::from).collect(),
            vaults: f.vaults.iter().copied().map(id_hex).collect(),
            i_am_organizer: f.i_am_organizer,
            needs_second_organizer: f.needs_second_organizer,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiFamilyInvite {
    pub id: String,
    pub from_name_local: String,
    pub role: FfiFamilyRole,
}

impl From<&FamilyInviteView> for FfiFamilyInvite {
    fn from(v: &FamilyInviteView) -> FfiFamilyInvite {
        FfiFamilyInvite {
            id: id_hex(v.id),
            from_name_local: v.from_name_local.clone(),
            role: v.role.into(),
        }
    }
}

/// My enrollment, as the member's screen shows it.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiRecoveryEnrollment {
    pub enrollment_id: String,
    pub organizer_name_local: String,
    pub delay_secs: u32,
    pub created_at: i64,
    /// False once my identity or the organizer's changed: enroll again.
    pub valid: bool,
}

impl From<&RecoveryEnrollmentView> for FfiRecoveryEnrollment {
    fn from(e: &RecoveryEnrollmentView) -> FfiRecoveryEnrollment {
        FfiRecoveryEnrollment {
            enrollment_id: id_hex(e.enrollment_id),
            organizer_name_local: e.organizer_name_local.clone(),
            delay_secs: e.delay_secs,
            created_at: e.created_at,
            valid: e.valid,
        }
    }
}

/// A member who chose me to help (organizer side).
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiHelper {
    pub member: String,
    pub name_local: String,
    pub enrollment_id: String,
    pub delay_secs: u32,
}

impl From<&HelperView> for FfiHelper {
    fn from(h: &HelperView) -> FfiHelper {
        FfiHelper {
            member: id_hex(h.member),
            name_local: h.name_local.clone(),
            enrollment_id: id_hex(h.enrollment_id),
            delay_secs: h.delay_secs,
        }
    }
}

/// Where a recovery stands on the organizer's side; the delay runs on the
/// organizer's clock.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiRecoveryStatus {
    Waiting {
        release_after: i64,
    },
    Ready,
    /// A device of the member cancelled, at its own time `at`.
    Cancelled {
        at: i64,
    },
    /// The member enrolled again since the request: the request is void.
    Replaced,
    NotEnrolled,
}

impl From<RecoveryStatus> for FfiRecoveryStatus {
    fn from(s: RecoveryStatus) -> FfiRecoveryStatus {
        match s {
            RecoveryStatus::Waiting { release_after } => {
                FfiRecoveryStatus::Waiting { release_after }
            }
            RecoveryStatus::Ready => FfiRecoveryStatus::Ready,
            RecoveryStatus::Cancelled { at } => FfiRecoveryStatus::Cancelled { at },
            RecoveryStatus::Replaced => FfiRecoveryStatus::Replaced,
            RecoveryStatus::NotEnrolled => FfiRecoveryStatus::NotEnrolled,
        }
    }
}

/// A recovery request shown on the member's devices, locked or not.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiRecoveryAlert {
    pub enrollment_id: String,
    pub organizer_name_local: String,
    pub release_after: i64,
}

impl From<&RecoveryAlert> for FfiRecoveryAlert {
    fn from(a: &RecoveryAlert) -> FfiRecoveryAlert {
        FfiRecoveryAlert {
            enrollment_id: id_hex(a.enrollment_id),
            organizer_name_local: a.organizer_name_local.clone(),
            release_after: a.release_after,
        }
    }
}

/// A copy of an item a contact sent, waiting for an answer.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct FfiReceivedItem {
    pub send_id: String,
    pub from_name_local: String,
    pub title: String,
    pub kind: FfiItemType,
    pub expires_at: i64,
}

impl From<&ReceivedItem> for FfiReceivedItem {
    fn from(r: &ReceivedItem) -> FfiReceivedItem {
        FfiReceivedItem {
            send_id: id_hex(r.send_id),
            from_name_local: r.from_name_local.clone(),
            title: r.title.clone(),
            kind: r.kind.into(),
            expires_at: r.expires_at,
        }
    }
}

fn secret(secret_key: &str) -> Result<SecretKey, OnePassError> {
    Ok(SecretKey::parse(&Zeroizing::new(secret_key.to_owned()))?)
}

fn family_of(f: &FamilyInfo) -> FfiFamily {
    FfiFamily::from(f)
}

#[uniffi::export]
impl Session {
    // ---- Family -------------------------------------------------------------

    /// Create the family, this account its organizer, with its first
    /// shared vault `vault_name`. Its mailboxes are made by the next round.
    pub fn create_family(&self, vault_name: String, now: i64) -> Result<FfiFamily, OnePassError> {
        self.with(|repo| Ok(family_of(&repo.create_family(&vault_name, now)?)))
    }

    /// The family this account belongs to, if any.
    pub fn family(&self) -> Result<Option<FfiFamily>, OnePassError> {
        self.with(|repo| Ok(repo.family()?.as_ref().map(family_of)))
    }

    /// Invite contact `contact` (organizer only). An organizer needs a
    /// verified contact (`ContactNotVerified`).
    pub fn invite_to_family(
        &self,
        contact: String,
        role: FfiFamilyRole,
        now: i64,
    ) -> Result<FfiFamily, OnePassError> {
        let contact = parse_id(&contact)?;
        self.with(|repo| {
            Ok(family_of(&repo.invite_to_family(
                contact,
                role.into(),
                now,
            )?))
        })
    }

    /// The family invitations waiting in the contact zones.
    pub fn family_invites(&self) -> Result<Vec<FfiFamilyInvite>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .family_invites()?
                .iter()
                .map(FfiFamilyInvite::from)
                .collect())
        })
    }

    pub fn accept_family_invite(
        &self,
        invite_id: String,
        now: i64,
    ) -> Result<FfiFamily, OnePassError> {
        let id = parse_id(&invite_id)?;
        self.with(|repo| Ok(family_of(&repo.accept_family_invite(id, now)?)))
    }

    /// Remove `account_id` from the family (organizer only).
    pub fn remove_from_family(
        &self,
        account_id: String,
        now: i64,
    ) -> Result<FfiFamily, OnePassError> {
        let id = parse_id(&account_id)?;
        self.with(|repo| Ok(family_of(&repo.remove_from_family(id, now)?)))
    }

    pub fn leave_family(&self, now: i64) -> Result<(), OnePassError> {
        self.with(|repo| Ok(repo.leave_family(now)?))
    }

    /// Make a member organizer or member again (organizer only).
    pub fn set_family_role(
        &self,
        account_id: String,
        role: FfiFamilyRole,
        now: i64,
    ) -> Result<FfiFamily, OnePassError> {
        let id = parse_id(&account_id)?;
        self.with(|repo| Ok(family_of(&repo.set_family_role(id, role.into(), now)?)))
    }

    /// Give one of my vaults to the family.
    pub fn add_family_vault(&self, vault_id: String, now: i64) -> Result<FfiFamily, OnePassError> {
        let id = parse_id(&vault_id)?;
        self.with(|repo| {
            let vault = find_vault(repo, id)?;
            Ok(family_of(&repo.add_family_vault(&vault, now)?))
        })
    }

    // ---- Recovery, member side ------------------------------------------------

    /// Choose `organizer` to help recover this account after `delay_secs`
    /// (24 hours to 7 days). The password and Secret Key are checked.
    pub fn enroll_recovery(
        &self,
        organizer: String,
        delay_secs: u32,
        password: String,
        secret_key: String,
        now: i64,
    ) -> Result<FfiRecoveryEnrollment, OnePassError> {
        let organizer = parse_id(&organizer)?;
        let password = Zeroizing::new(password);
        let sk = secret(&secret_key)?;
        self.with(|repo| {
            repo.enroll_recovery(organizer, delay_secs, &password, &sk, now)?;
            repo.recovery_enrollment()?
                .as_ref()
                .map(FfiRecoveryEnrollment::from)
                .ok_or(OnePassError::NotFound)
        })
    }

    pub fn recovery_enrollment(&self) -> Result<Option<FfiRecoveryEnrollment>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .recovery_enrollment()?
                .as_ref()
                .map(FfiRecoveryEnrollment::from))
        })
    }

    pub fn disable_recovery(
        &self,
        password: String,
        secret_key: String,
    ) -> Result<(), OnePassError> {
        let password = Zeroizing::new(password);
        let sk = secret(&secret_key)?;
        self.with(|repo| Ok(repo.disable_recovery(&password, &sk)?))
    }

    // ---- Recovery, organizer side ---------------------------------------------

    /// The members who chose me to help.
    pub fn recovery_enrollments_for_me(&self) -> Result<Vec<FfiHelper>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .recovery_enrollments_for_me()?
                .iter()
                .map(FfiHelper::from)
                .collect())
        })
    }

    /// Start `member`'s recovery: the delay starts now, on this clock. The
    /// member's devices show the request and can cancel it.
    pub fn request_recovery(
        &self,
        member: String,
        password: String,
        secret_key: String,
        now: i64,
    ) -> Result<FfiRecoveryStatus, OnePassError> {
        let member = parse_id(&member)?;
        let password = Zeroizing::new(password);
        let sk = secret(&secret_key)?;
        self.with(|repo| Ok(repo.request_recovery(member, &password, &sk, now)?.into()))
    }

    pub fn recovery_status(
        &self,
        member: String,
        now: i64,
    ) -> Result<FfiRecoveryStatus, OnePassError> {
        let member = parse_id(&member)?;
        self.with(|repo| Ok(repo.recovery_status(member, now)?.into()))
    }

    /// Face to face with the member's new device, once the SAS is confirmed
    /// (`FfiContactInitiator::confirm_sas_for_recovery`) and the delay is
    /// over: the frame to hand to that device. Refused before `Ready`.
    pub fn release_recovery_share(
        &self,
        member: String,
        initiator: Arc<FfiContactInitiator>,
        now: i64,
    ) -> Result<Vec<u8>, OnePassError> {
        let member = parse_id(&member)?;
        self.with(|repo| {
            let mut init = lock(&initiator.inner);
            Ok(repo.release_recovery_share(member, &mut init, now)?)
        })
    }

    // ---- Sends ----------------------------------------------------------------

    /// Send a copy of an item to a contact, kept until `expires_at` (at
    /// most 30 days). Returns the send id.
    pub fn send_item(
        &self,
        vault_id: String,
        item_id: String,
        to: String,
        expires_at: i64,
        now: i64,
    ) -> Result<String, OnePassError> {
        let (vault_id, item_id, to) = (parse_id(&vault_id)?, parse_id(&item_id)?, parse_id(&to)?);
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            Ok(id_hex(
                repo.send_item(&vault, item_id, to, expires_at, now)?,
            ))
        })
    }

    pub fn received_items(&self, now: i64) -> Result<Vec<FfiReceivedItem>, OnePassError> {
        self.with(|repo| {
            Ok(repo
                .received_items(now)?
                .iter()
                .map(FfiReceivedItem::from)
                .collect())
        })
    }

    /// Keep a received copy as a new item of vault `into`.
    pub fn accept_received_item(
        &self,
        send_id: String,
        into: String,
        now: i64,
    ) -> Result<FfiItem, OnePassError> {
        let (send_id, into) = (parse_id(&send_id)?, parse_id(&into)?);
        self.with(|repo| {
            let vault = find_vault(repo, into)?;
            Ok(item_to_ffi(
                &repo.accept_received_item(send_id, &vault, now)?,
            ))
        })
    }

    pub fn decline_received_item(&self, send_id: String) -> Result<(), OnePassError> {
        let id = parse_id(&send_id)?;
        self.with(|repo| Ok(repo.decline_received_item(id)?))
    }

    /// Delete my sends past their date; returns how many went.
    pub fn purge_expired_sends(&self, now: i64) -> Result<u32, OnePassError> {
        self.with(|repo| Ok(repo.purge_expired_sends(now)?))
    }
}

// ---- Without a session ----------------------------------------------------------

/// The recovery requests for this account, read from the store without
/// unlocking: a locked device must show them.
#[uniffi::export]
pub fn recovery_alerts(db_path: String) -> Result<Vec<FfiRecoveryAlert>, OnePassError> {
    let store = crate::open_store(&db_path)?;
    Ok(core_recovery::recovery_alerts(&store)?
        .iter()
        .map(FfiRecoveryAlert::from)
        .collect())
}

/// "Annuler" on a member device: a cancel signed by this device's keys,
/// with no password, so a locked device can stop a recovery it did not ask
/// for.
#[uniffi::export]
pub fn cancel_recovery(
    db_path: String,
    enrollment_id: String,
    classical: Vec<u8>,
    pq: Arc<dyn FfiPqDeviceHalf>,
    now: i64,
) -> Result<(), OnePassError> {
    let eid = parse_id(&enrollment_id)?;
    let classical = Zeroizing::new(classical);
    let keys = device_keys(&classical, pq)?;
    let mut store = crate::open_store(&db_path)?;
    Ok(core_recovery::cancel_recovery(&mut store, eid, &keys, now)?)
}

/// The member's new device in an organizer-assisted recovery: it shows the
/// QR, reads the SAS, then takes the organizer's frame.
#[derive(uniffi::Object)]
pub struct FfiRecoveryResponder {
    inner: Mutex<ContactResponder>,
}

#[derive(uniffi::Record)]
pub struct FfiRecoveryStart {
    pub responder: Arc<FfiRecoveryResponder>,
    pub qr: String,
    pub hello: Vec<u8>,
}

/// Start the recovery session on the member's new device.
#[uniffi::export]
pub fn recovery_responder_start(now: i64) -> Result<FfiRecoveryStart, OnePassError> {
    let (responder, qr, hello) = ContactResponder::new_for_recovery(now)?;
    Ok(FfiRecoveryStart {
        responder: Arc::new(FfiRecoveryResponder {
            inner: Mutex::new(responder),
        }),
        qr: qr.to_text(),
        hello,
    })
}

#[uniffi::export]
impl FfiRecoveryResponder {
    /// The organizer's KeyExchange: the SAS to show.
    pub fn on_key_exchange(&self, kx: Vec<u8>, now: i64) -> Result<String, OnePassError> {
        Ok(lock(&self.inner).on_key_exchange(&kx, now)?)
    }

    /// Take the organizer's frame and recover the account in `db_path` (its
    /// private base fetched, nothing unlocked): a rotation with reason
    /// Recover, the new password and Secret Key, this device's new keys.
    /// `kit_secret_key` is the Emergency Kit's Secret Key, needed only when
    /// the account syncs through the mailbox. The app stores
    /// `new_secret_key` as pending before the call.
    #[allow(clippy::too_many_arguments)]
    pub fn recover(
        &self,
        db_path: String,
        frame: Vec<u8>,
        kit_secret_key: Option<String>,
        new_password: String,
        new_secret_key: String,
        classical: Vec<u8>,
        pq: Arc<dyn FfiPqDeviceHalf>,
        device_name: String,
        kind: FfiDeviceKind,
        mode: FfiDeviceMode,
        now: i64,
    ) -> Result<Arc<Session>, OnePassError> {
        let new_password = Zeroizing::new(new_password);
        let classical = Zeroizing::new(classical);
        let kit = kit_secret_key.as_deref().map(secret).transpose()?;
        let new_sk = secret(&new_secret_key)?;
        let keys = device_keys(&classical, pq)?;
        let store = crate::open_store(&db_path)?;
        let device = store.device_state()?;
        let mut session = lock(&self.inner);
        let (mut repo, _) = core_recovery::recover_with_share(
            store,
            &mut session,
            &frame,
            kit.as_ref(),
            RecoverRequest {
                keyset_record: &[],
                new_password: &new_password,
                new_secret_key: &new_sk,
                device_keys: &keys,
                device_name: &device_name,
                kind: kind.into(),
                mode: mode.into(),
                device,
            },
            now,
        )?;
        repo.persist_device_state()?;
        Session::new(repo)
    }
}
