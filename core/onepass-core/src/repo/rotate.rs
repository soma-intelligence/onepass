//! Key rotation v2 on the rotating device (spec 7.1, steps 1 to 6).
//!
//! `Repository::rotate` checks every precondition, then builds the whole
//! rotation in memory: a new Secret Key (from the caller, K6), a new
//! identity with its signing and KEM keys and params at epoch 1
//! (`Account::rotate_keys`), the roster without the revoked and excluded
//! devices, one Secret Key delivery per remaining device, every live vault
//! under a new vault key with every listed item resealed at version + 1 and
//! the next manifest signed by the new key, both signed lists (and the
//! contact book, when there is one) at seq 1, and the rotation record signed by this device's key and by the new identity.
//! Account records of the new identity live under its identity id (spec
//! 6.6). Then everything goes in one local transaction with the new trust
//! state (`Rotating { phase: 1 }`, K5). Nothing is written before it, and
//! nothing after it can fail the call (K12).
//!
//! The old item records stay until phase 3 confirms the new content on the
//! server (R23): nothing is deleted here. Pushing the phases is the sync
//! layer's job (`SyncStore::push_rotation_phase`); the transaction hands it
//! the re-sealed vaults and the blob ids of the records the loaded
//! manifests list (`RotationPush`), and resets the chain state for the new
//! identity.
//!
//! Secret Key delivery (spec 6.5): the envelope is
//! `wrap_key_labeled(recipient kem_pub, "onepass/rotation/secret-key/v1",
//! context, new Secret Key)`. Spec 6.5 names the lineage hash `h` in the
//! context, but `h` covers the body, and the body holds the SHA-256 of
//! every envelope: the context would depend on itself. The context is
//! therefore `postcard((account_id, parent, recipient_id))`, the parent
//! lineage hash; the envelope stays bound to this rotation through its
//! hash in the signed body, checked before any decapsulation
//! (`open_key_delivery`), and the record id keeps `h`.

use std::collections::{BTreeMap, BTreeSet};

use aws_lc_rs::digest::{SHA256, digest};

use super::kit::{KitRestore, kit_unpinned, restore_prelude};
use super::pairing::{insert_sorted, same_keys, stored_intros};
use super::replay::meta_hash;
use super::{DeviceState, Repository, pin, seen};
use crate::account::{Account, Auk, RotatedAccount};
use crate::approvers::ApproverEntry;
use crate::chain::{ChainState, Seen};
use crate::contact::ContactEntry;
use crate::crypto::kem::wrap_key_labeled;
use crate::crypto::{SecretKey, SymmetricKey};
use crate::device_keys::DeviceKeys;
use crate::devices::{DeviceEntry, DeviceKind, DeviceMode, now};
use crate::lineage::{
    LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationBody, RotationReason, check_rotation,
    delivery_id, identity_id, rotation_code, sign_rotation,
};
use crate::lists::{AccountList, ListBody, sign};
use crate::manifest::{SeenManifest, sign_manifest};
use crate::share::{
    MemberLineageRecord, MemberRef, PendingIdentity, RekeyReason, RekeyRequest, ShareState,
    SignedZoneAccess, ZONE_ACCESS_KIND, wrap_member_key,
};
use crate::store::{
    Record, RecordKind, RecordStore, RotationPush, VaultEvent, Zone, account_record_id,
};
use crate::synchome::{SYNC_HOME_DOMAIN, SignedSyncHome, SyncBackend, SyncHomeBody};
use crate::trust::{DeviceLineageState, LineageHead, RetiredIdentity, TrustLevel, TrustState};
use crate::vault::Vault;
use crate::vaultlist::VaultListEntry;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// `wrap_key_labeled` label of a Secret Key delivery (spec 6.1).
pub const SECRET_KEY_DELIVERY_LABEL: &[u8] = b"onepass/rotation/secret-key/v1";

/// The context of a delivery envelope: `postcard((account_id, parent,
/// recipient_id))` (see the module doc for why the parent hash).
pub fn delivery_context(account_id: Id, parent: &[u8; 32], recipient: Id) -> Vec<u8> {
    postcard::to_allocvec(&(account_id, parent, recipient)).expect("delivery context encodes")
}

/// Open the Secret Key delivery `envelope` of `recipient` under the
/// rotation `body`, with the recipient's device keys. The envelope's
/// SHA-256 must be the one the body lists for `recipient` before anything
/// is decapsulated (`Integrity(Signature)` otherwise); a device the body
/// does not list is `Validation`. The body must already be verified.
pub fn open_key_delivery(
    keys: &DeviceKeys,
    body: &RotationBody,
    recipient: Id,
    envelope: &[u8],
) -> Result<SecretKey> {
    let (_, hash) = body
        .deliveries
        .iter()
        .find(|(id, _)| *id == recipient)
        .ok_or_else(|| refused("delivery", "not a recipient"))?;
    if sha256(envelope) != *hash {
        return Err(IntegrityError::Signature.into());
    }
    let context = delivery_context(body.account_id, &body.parent, recipient);
    let key = keys.unwrap_key_labeled(SECRET_KEY_DELIVERY_LABEL, &context, envelope)?;
    Ok(SecretKey(*key.expose()))
}

/// What `Repository::rotate` needs from the app.
pub struct RotateRequest<'a> {
    /// Devices to revoke: each in the roster, never this device.
    pub revoke: Vec<Id>,
    /// The new master password, `None` to keep `password`.
    pub new_password: Option<&'a str>,
    /// The current master password.
    pub password: &'a str,
    /// The current Secret Key.
    pub secret_key: &'a SecretKey,
    /// The new Secret Key, drawn by the caller and stored as pending
    /// before the call (K6). Must differ from `secret_key` (K11).
    pub new_secret_key: &'a SecretKey,
    /// This device's keys (they must be the ones the trust state pins).
    pub device_keys: &'a DeviceKeys,
    pub reason: RotationReason,
    /// Spec 15 step 5 (Task 14 review I2): the `Tofu` roster devices the
    /// user confirmed to keep (the screen lists every one, none is kept
    /// silently). Any other `Tofu` device gets no delivery and leaves the
    /// new roster: it re-pairs. Each must be a `Tofu` roster device, not
    /// revoked by this request (`Validation("device")`).
    pub keep_tofu: &'a [Id],
}

/// A committed rotation. `Debug` never prints the AUK.
#[derive(Debug)]
pub struct RotationOutcome {
    /// The new Account Unlock Key, to enroll biometrics again.
    pub auk: Auk,
    /// The 6-digit rotation code shown to the user (spec 6.3).
    pub code: u32,
    /// The lineage hash of the new head.
    pub head: [u8; 32],
}

/// What `recover_rotate` needs from the app (sharing plan 3 Task 3).
pub struct RecoverRequest<'a> {
    /// The keyset opened by the recovery key, in clear
    /// (`Account::recovery_keyset`).
    pub keyset_record: &'a [u8],
    /// The new master password.
    pub new_password: &'a str,
    /// The new Secret Key, drawn by the caller and stored as pending
    /// before the call (K6).
    pub new_secret_key: &'a SecretKey,
    /// The device keys the app just created for this device.
    pub device_keys: &'a DeviceKeys,
    pub device_name: &'a str,
    pub kind: DeviceKind,
    pub mode: DeviceMode,
    /// The device state the app saved (default on a new device).
    pub device: DeviceState,
}

/// Organizer-assisted recovery, the last step (sharing spec 11.5 step 5,
/// plan 3 rulings B-3 and B-4): from the keyset the recovery slot gave,
/// pin the head that introduces its identity through the identity's
/// signature (as an Emergency Kit restore does, spec rotation 7.5 step 3),
/// publish this device's self-intro signed by its key and by that
/// identity, then rotate with reason `Recover`: a new identity, Secret Key
/// and password, every live vault re-sealed (spec 7.1), the roster this
/// device alone, every other device of the roster revoked. The old
/// devices see the rotation as valid through the self-intro and go to
/// quarantine (or `Orphaned`); they come back by pairing from this device.
///
/// Two local transactions (ruled): the restore (trust state, self-intro),
/// then the rotation. Cut between them, the device is a kit-restored
/// device nobody pinned; calling again restores again (a new device id)
/// and rotates. The phases of the rotation are pushed by the sync layer
/// as for any rotation.
///
/// Refused: what an Emergency Kit restore refuses (a bad name or mode,
/// a device that is neither new, locked nor a cut recovery, an identity
/// introduced by no verified record, a keyset whose identity has a newer
/// child: `OutdatedKit`); an account with no lineage:
/// `Validation("lineage")`; a keyset that does not match its params:
/// `Integrity(Signature)`; own writes left to replay:
/// `Validation("device")`.
pub fn recover_rotate<S: RecordStore>(
    store: S,
    mut req: RecoverRequest<'_>,
    now: i64,
) -> Result<(Repository<S>, RotationOutcome)> {
    // Only the device fields of a kit restore are read past the prelude.
    let unused = SecretKey([0; 32]);
    let kit = KitRestore {
        password: "",
        secret_key: &unused,
        device_keys: req.device_keys,
        name: req.device_name,
        kind: req.kind,
        mode: req.mode,
        device: std::mem::take(&mut req.device),
    };
    let (existing, account_id, records) = restore_prelude(&store, &kit, true)?;
    if records.is_empty() {
        return Err(refused("lineage", "none"));
    }
    let mut params_record = None;
    let account = Account::open_recovered(req.keyset_record, |identity| {
        let generation = records
            .iter()
            .filter(|r| r.identity_pub() == identity)
            .map(LineageRecord::generation)
            .min()
            .ok_or(IntegrityError::Signature)?;
        let id = account_record_id(account_id, (generation > 0).then_some(identity));
        let rec = store
            .get(RecordKind::AccountParams, id)?
            .ok_or(Error::NotFound)?;
        params_record = Some(rec.clone());
        Ok(rec.data)
    })?;
    let params = params_record.ok_or(Error::NotFound)?;
    if account.params.account_id != account_id {
        return Err(IntegrityError::WrongContext.into());
    }
    let mut repo =
        Repository::restore_opened(store, existing, records, account, params.clone(), &kit)?;
    let outcome = repo.recover_rotation(&req, &params.data, now)?;
    Ok((repo, outcome))
}

/// What `rotate_with` makes a rotation of, its preconditions checked.
struct RotationPlan<'a> {
    revoked: BTreeSet<Id>,
    /// The master password of the new identity (new or kept).
    password: &'a str,
    new_secret_key: &'a SecretKey,
    device_keys: &'a DeviceKeys,
    reason: RotationReason,
    keep_tofu: &'a [Id],
    /// The `issued_at` of the record and the date of the list changes.
    at: i64,
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, b).as_ref());
    out
}

fn next_version(r: &Record) -> Result<u64> {
    r.version.checked_add(1).ok_or(Error::Conflict)
}

/// The first list of a new identity: seq 1, signed by its key, under its
/// identity id `id` (spec 7.1 step 4).
fn first_list<E: AccountList>(
    account: &Account,
    id: Id,
    entries: Vec<E>,
) -> Result<(Record, Seen)> {
    let body = ListBody::next(None, account.params.account_id, entries)?;
    let seen = body.seen();
    let signed = sign(account, E::DOMAIN, body)?;
    Ok((
        Record {
            id,
            kind: E::KIND,
            version: 1,
            data: signed.encode(),
        },
        seen,
    ))
}

/// The first `SyncHome` of a new identity: seq 1, no previous one.
fn first_home(account: &Account, id: Id, backend: SyncBackend, at: i64) -> Result<(Record, Seen)> {
    let body = SyncHomeBody::next(None, account.params.account_id, backend, at)?;
    let seen = body.seen();
    let sig = account
        .keyset()
        .signing
        .sign(SYNC_HOME_DOMAIN, &body.encode())?;
    let signed = SignedSyncHome { body, sig };
    Ok((
        Record {
            id,
            kind: RecordKind::SyncHome,
            version: 1,
            data: signed.encode(),
        },
        seen,
    ))
}

/// One vault rotated in memory.
struct RotatedVault {
    id: Id,
    from: SeenManifest,
    head: SeenManifest,
}

/// Zoned rows and share states a rotation writes next to its own rows.
type ShareWrites = (Vec<(Zone, Record, Option<u64>)>, Vec<ShareState>);

impl<S: RecordStore> Repository<S> {
    /// The removals this device made that its head's roster lacks (spec
    /// 8.5 step 5): devices in `revoked` (monotone, every removal this
    /// device made or adopted) that the roster still lists, after a switch
    /// to a winner that did not revoke them. Sorted. Empty without a trust
    /// state.
    pub fn uncovered_removals(&self) -> Result<Vec<Id>> {
        let Some(trust) = self.store.trust_state()? else {
            return Ok(Vec::new());
        };
        Ok(trust
            .roster
            .iter()
            .map(|e| e.device_id)
            .filter(|id| *id != trust.me.device_id && trust.revoked.contains(id))
            .collect())
    }

    /// Re-apply the uncovered removals (`uncovered_removals`) as a `Reapply`
    /// child of the head (spec 8.5 step 5), with the preconditions and the
    /// single transaction of `rotate`; `password` and `secret_key` are the
    /// current ones (after a switch: the ones just followed), `new_secret_key`
    /// is drawn and stored as pending by the caller (K6). `Ok(None)` when
    /// the head already covers every removal: nothing is written (no
    /// livelock, G6). Same user step as the switch (no prompt of its own).
    pub fn reapply(
        &mut self,
        password: &str,
        secret_key: &SecretKey,
        new_secret_key: &SecretKey,
        device_keys: &DeviceKeys,
    ) -> Result<Option<RotationOutcome>> {
        let revoke = self.uncovered_removals()?;
        if revoke.is_empty() {
            return Ok(None);
        }
        // A re-apply removes again what this device removed; it drops no
        // `Tofu` device the winner kept (not an F1 rotation, spec 15 step 5).
        let keep: Vec<Id> = match self.store.trust_state()? {
            Some(t) => t
                .roster
                .iter()
                .map(|e| e.device_id)
                .filter(|id| {
                    t.levels.get(id) == Some(&TrustLevel::Tofu)
                        && *id != t.me.device_id
                        && !revoke.contains(id)
                })
                .collect(),
            None => Vec::new(),
        };
        self.rotate(RotateRequest {
            revoke,
            new_password: None,
            password,
            secret_key,
            new_secret_key,
            device_keys,
            reason: RotationReason::Reapply,
            keep_tofu: &keep,
        })
        .map(Some)
    }

    /// Rotate every key of the account into a signed lineage record (spec
    /// 7.1). See the module doc.
    ///
    /// Refused, with nothing written:
    /// - Travel Mode on (K8): `Validation("travel mode")`;
    /// - no trust state (a legacy device), a state other than `Current`,
    ///   or `device_keys` other than the pinned ones: `Validation("device")`;
    /// - a device to revoke that is this one or not in the roster, a
    ///   `Revoke` without one, `RotateWithPassword` without a new password:
    ///   `Validation`;
    /// - a new Secret Key equal to the current one (K11): `Validation`;
    /// - a live vault that does not load through the verified path, among
    ///   them `VaultMissing` (R22): that error;
    /// - a wrong password or Secret Key: `WrongPassword` (this also
    ///   establishes the current Secret Key of a session opened with the
    ///   Account Unlock Key alone);
    /// - account records changed since this session opened: `Conflict`;
    /// - the commit itself failing: its error.
    ///
    /// The caller runs a full sync first (spec 7.1): the core cannot tell.
    /// Once committed the call returns `Ok` (K12), and the session goes on
    /// under the new keys, pinned to the new identity.
    pub fn rotate(&mut self, req: RotateRequest<'_>) -> Result<RotationOutcome> {
        // Preconditions that need no derivation, cheapest first.
        if self.travelling() {
            return Err(refused("travel mode", "active"));
        }
        let account_id = self.account.params.account_id;
        let trust = self
            .store
            .trust_state()?
            .ok_or_else(|| refused("device", "no device keys"))?;
        if trust.account_id != account_id {
            return Err(IntegrityError::WrongContext.into());
        }
        if trust.state != DeviceLineageState::Current {
            return Err(refused("device", "not current"));
        }
        // Spec 10.4: own writes of an identity left are replayed before
        // this device makes keys of its own.
        if !trust.own_writes.replay.is_empty() {
            return Err(refused("device", "own writes to replay"));
        }
        let me = trust.me.device_id;
        if req.device_keys.public(me)? != trust.me {
            return Err(refused("device", "other device keys"));
        }
        // Task 15 (concern 1): the one pin check, keys compared.
        super::kit::check_pinned(&trust)?;
        if trust.identity_pub != self.account.params.identity_pub {
            return Err(IntegrityError::WrongContext.into());
        }
        let revoked: BTreeSet<Id> = req.revoke.iter().copied().collect();
        if revoked.contains(&me) {
            return Err(refused("device", "this device"));
        }
        if revoked
            .iter()
            .any(|id| !trust.roster.iter().any(|e| e.device_id == *id))
        {
            return Err(refused("device", "not in the roster"));
        }
        // Spec 15 step 5: a kept `Tofu` device is one the user confirmed.
        for id in req.keep_tofu {
            if trust.levels.get(id) != Some(&TrustLevel::Tofu)
                || revoked.contains(id)
                || !trust.roster.iter().any(|e| e.device_id == *id)
            {
                return Err(refused("device", "not a kept tofu device"));
            }
        }
        match req.reason {
            RotationReason::Revoke if revoked.is_empty() => {
                return Err(refused("revoke", "no device"));
            }
            RotationReason::RotateWithPassword if req.new_password.is_none() => {
                return Err(refused("password", "missing"));
            }
            _ => {}
        }
        if req.new_secret_key.same_as(req.secret_key) {
            return Err(refused("secret key", "unchanged"));
        }
        let plan = RotationPlan {
            revoked,
            password: req.new_password.unwrap_or(req.password),
            new_secret_key: req.new_secret_key,
            device_keys: req.device_keys,
            reason: req.reason,
            keep_tofu: req.keep_tofu,
            at: now(),
        };
        let (password, secret_key) = (req.password, req.secret_key);
        self.rotate_with(&trust, trust.clone(), plan, move |repo, t| {
            // The current password and Secret Key, with every unlock check, on
            // the records of the current identity (spec 6.6). This also gives
            // the account the current Secret Key (`rotate_keys` compares, K11).
            let current_id = account_record_id(
                account_id,
                (t.head.generation > 0).then_some(&t.identity_pub),
            );
            let params = repo
                .store
                .get(RecordKind::AccountParams, current_id)?
                .ok_or(Error::NotFound)?;
            let keyset = repo
                .store
                .get(RecordKind::Keyset, current_id)?
                .ok_or(Error::NotFound)?;
            let (stored, _) = Account::unlock_exporting_auk_at(
                password,
                secret_key,
                &params.data,
                &keyset.data,
                repo.device.pinned.as_ref(),
                repo.account.params.epoch,
            )?;
            Ok(stored)
        })
    }

    /// The `Recover` rotation of `recover_rotate`, on the device it just
    /// restored: this device pinned in memory from its own self-intro (as
    /// `claim_only_device` would, but not stored), every other roster
    /// device revoked.
    fn recover_rotation(
        &mut self,
        req: &RecoverRequest<'_>,
        params: &[u8],
        now: i64,
    ) -> Result<RotationOutcome> {
        if self.travelling() {
            return Err(refused("travel mode", "active"));
        }
        let trust = self
            .store
            .trust_state()?
            .ok_or_else(|| refused("device", "no device keys"))?;
        if trust.state != DeviceLineageState::Current || !kit_unpinned(&trust) {
            return Err(refused("device", "not current"));
        }
        if !trust.own_writes.replay.is_empty() {
            return Err(refused("device", "own writes to replay"));
        }
        let me = trust.me.device_id;
        if req.device_keys.public(me)? != trust.me {
            return Err(refused("device", "other device keys"));
        }
        let entry = stored_intros(&self.store)?
            .into_iter()
            .find(|i| {
                i.identity_sig.is_some()
                    && i.body.head == trust.head.hash
                    && i.body.introducer == me
                    && same_keys(&i.body.entry, &trust.me)
            })
            .map(|i| i.body.entry)
            .ok_or(Error::NotFound)?;
        let mut work = trust.clone();
        let revoked: BTreeSet<Id> = work.roster.iter().map(|e| e.device_id).collect();
        insert_sorted(&mut work.roster, entry);
        work.levels.insert(me, TrustLevel::Verified);
        let plan = RotationPlan {
            revoked,
            password: req.new_password,
            new_secret_key: req.new_secret_key,
            device_keys: req.device_keys,
            reason: RotationReason::Recover,
            keep_tofu: &[],
            at: now,
        };
        let keyset = req.keyset_record;
        self.rotate_with(&trust, work, plan, move |_, _| {
            Account::open_recovered(keyset, |_| Ok(params.to_vec()))
        })
    }

    /// Steps 1 to 6 of `rotate` (spec 7.1) from `work`, the trust state the
    /// rotation is made from (the stored one, `stored_trust`, or for a
    /// recovery that state with this device pinned in memory), once the
    /// preconditions of `plan` hold. `unlock` gives the current account
    /// with its keys. The transaction is conditional on `stored_trust`.
    fn rotate_with(
        &mut self,
        stored_trust: &TrustState,
        work: TrustState,
        plan: RotationPlan<'_>,
        unlock: impl FnOnce(&Self, &TrustState) -> Result<Account>,
    ) -> Result<RotationOutcome> {
        let account_id = self.account.params.account_id;
        let me = work.me.device_id;
        let revoked = &plan.revoked;
        let generation = work
            .head
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidFormat("lineage generation"))?;

        // R22: every live vault loads through the verified path.
        let vaults = self.personal_vaults()?;
        let mut loaded = Vec::with_capacity(vaults.len());
        for vault in vaults {
            let l = self.load(&vault)?;
            loaded.push((vault, l));
        }
        let devices = self.read_list::<DeviceEntry>()?;
        let vault_list = self.read_list::<VaultListEntry>()?;
        let book = self.read_list::<ContactEntry>()?;
        let approvers = self.read_list::<ApproverEntry>()?;
        // Where the account syncs (mailbox spec 4.13): the new identity
        // opens its own chain on the same backend.
        let home = self.sync_home()?;

        // The current keys (the caller's unlock: the password and Secret Key
        // with every check, or a recovered keyset).
        let stored = unlock(self, &work)?;
        if stored.params != self.account.params {
            // Changed since this session opened: the vault keys loaded
            // above were opened with the session's keys.
            return Err(Error::Conflict);
        }

        // Step 1: the new identity, params and keyset.
        let floor = self
            .device
            .pinned
            .as_ref()
            .map_or_else(|| stored.params.kdf.clone(), |p| p.kdf_floor.clone());
        let RotatedAccount {
            account,
            params_record,
            keyset_record,
            identity_pub,
            auk,
        } = stored.rotate_keys(plan.password, plan.new_secret_key, &floor)?;
        let new_id = identity_id(&identity_pub);
        let params_hash = sha256(&params_record);
        let keyset_hash = sha256(&keyset_record);
        let mut writes = vec![
            (
                Record {
                    id: new_id,
                    kind: RecordKind::AccountParams,
                    version: 1,
                    data: params_record,
                },
                None,
            ),
            (
                Record {
                    id: new_id,
                    kind: RecordKind::Keyset,
                    version: 1,
                    data: keyset_record,
                },
                None,
            ),
        ];

        // Step 2: the roster and one delivery per member except this one.
        let tofu = |id: &Id| work.levels.get(id) == Some(&TrustLevel::Tofu) && *id != me;
        let roster: Vec<RosterEntry> = work
            .roster
            .iter()
            .filter(|e| {
                !revoked.contains(&e.device_id)
                    && !work.excluded.contains(&e.device_id)
                    && !work.revoked.contains(&e.device_id)
                    && (!tofu(&e.device_id) || plan.keep_tofu.contains(&e.device_id))
            })
            .cloned()
            .collect();
        let secret = SymmetricKey::from_bytes(plan.new_secret_key.0);
        let mut envelopes = Vec::new();
        for e in roster.iter().filter(|e| e.device_id != me) {
            let context = delivery_context(account_id, &work.head.hash, e.device_id);
            let envelope =
                wrap_key_labeled(&e.kem_pub, &secret, SECRET_KEY_DELIVERY_LABEL, &context)?;
            envelopes.push((e.device_id, envelope));
        }
        let deliveries = envelopes
            .iter()
            .map(|(id, env)| (*id, sha256(env)))
            .collect();

        // Step 3: every live vault under a new key, every listed item
        // (live, archived, trashed) resealed at version + 1. The records
        // the loaded manifests list are the only ones phase 3 deletes
        // (R23).
        let mut collect = Vec::new();
        let mut rotated = Vec::with_capacity(loaded.len());
        // What this device re-sealed, for its own-write log (Task 11).
        let mut resealed: BTreeMap<(Id, Id), [u8; 32]> = BTreeMap::new();
        let mut metas: BTreeMap<Id, [u8; 32]> = BTreeMap::new();
        for (vault, l) in &loaded {
            let key_rec = self
                .store
                .get(RecordKind::VaultKey, vault.id)?
                .ok_or(IntegrityError::VaultMissing)?;
            let meta_rec = self
                .store
                .get(RecordKind::VaultMeta, vault.id)?
                .ok_or(Error::InvalidFormat("vault meta"))?;
            let (fresh, envelope, meta_blob) =
                Vault::create_with_id(&account, vault.id, vault.meta.clone())?;
            let r = self.reseal_vault(vault, &fresh, l)?;
            collect.extend(r.collect);
            resealed.extend(r.hashes.into_iter().map(|(i, h)| ((vault.id, i), h)));
            writes.extend(r.items.into_iter().map(|rec| (rec, None)));
            writes.extend(r.attachments.into_iter().map(|(moved, v)| (moved, Some(v))));
            let m = r.manifest.with_meta(&fresh.meta);
            let sm = sign_manifest(&fresh, &account.keyset().signing, &m)?;
            writes.push((
                Record {
                    id: vault.id,
                    kind: RecordKind::Manifest,
                    version: m.seq,
                    data: postcard::to_allocvec(&sm)
                        .map_err(|_| Error::InvalidFormat("manifest"))?,
                },
                Some(l.manifest.seq),
            ));
            metas.insert(vault.id, meta_hash(&meta_blob));
            writes.push((
                Record {
                    id: vault.id,
                    kind: RecordKind::VaultMeta,
                    version: next_version(&meta_rec)?,
                    data: meta_blob,
                },
                Some(meta_rec.version),
            ));
            writes.push((
                Record {
                    id: vault.id,
                    kind: RecordKind::VaultKey,
                    version: next_version(&key_rec)?,
                    data: envelope,
                },
                Some(key_rec.version),
            ));
            rotated.push(RotatedVault {
                id: vault.id,
                from: seen(&l.manifest),
                head: seen(&m),
            });
        }

        // Step 4: the lists (and the contact book, if any) at seq 1 under
        // the identity id, signed by the new key; the device list marks the
        // revoked devices.
        let at = plan.at;
        let mut device_entries = devices.map(|d| d.body.entries).unwrap_or_default();
        for e in &mut device_entries {
            if revoked.contains(&e.device_id) {
                e.revoked_at.get_or_insert(at);
            }
        }
        // A recovery (sharing plan 3 Task 3): the recovering device was
        // never listed (a kit-restored device signs no list); the new
        // identity's list names it, from its self-intro entry.
        if plan.reason == RotationReason::Recover
            && !device_entries.iter().any(|e| e.device_id == me)
            && let Some(e) = work.roster.iter().find(|e| e.device_id == me)
        {
            device_entries.push(DeviceEntry {
                device_id: me,
                name: e.name.clone(),
                kind: e.kind,
                mode: e.mode,
                added_at: at,
                added_by: None,
                revoked_at: None,
            });
        }
        let vault_entries = match vault_list {
            Some(v) => v.body.entries,
            None => rotated
                .iter()
                .map(|v| VaultListEntry {
                    vault_id: v.id,
                    created_at: at,
                    deleted_at: None,
                })
                .collect(),
        };
        let (device_rec, device_seen) = first_list(&account, new_id, device_entries)?;
        let (vault_rec, vault_seen) = first_list(&account, new_id, vault_entries)?;
        writes.push((device_rec, None));
        writes.push((vault_rec, None));
        let book_seen = match book {
            Some(b) => {
                let (rec, seen) = first_list(&account, new_id, b.body.entries)?;
                writes.push((rec, None));
                Some(seen)
            }
            None => None,
        };
        // The home: seq 1 under the new identity, same backend, signed by
        // the new key (a new identity opens a new chain). Phase 1, before
        // the lineage record that announces the rotation.
        let home_seen = match home {
            Some(h) => {
                let (rec, seen) = first_home(&account, new_id, h.backend, at)?;
                writes.push((rec, None));
                Some(seen)
            }
            None => None,
        };
        // The approver list follows (agent-ready spec 4): without it the
        // other devices' approval keys would be gone until each one enrolls
        // again. A revoked device's entries are retired.
        let approver_seen = match approvers {
            Some(a) => {
                let mut entries = a.body.entries;
                for e in &mut entries {
                    if revoked.contains(&e.device_id) {
                        e.retired_at.get_or_insert(at);
                    }
                }
                let (rec, seen) = first_list(&account, new_id, entries)?;
                writes.push((rec, None));
                Some(seen)
            }
            None => None,
        };

        // Step 5: the rotation record, signed by this device and by the new
        // identity.
        let from_heads: BTreeMap<Id, SeenManifest> =
            rotated.iter().map(|v| (v.id, v.from.clone())).collect();
        let body = RotationBody {
            format: LINEAGE_FORMAT,
            account_id,
            generation,
            parent: work.head.hash,
            rotator: me,
            reason: plan.reason,
            revoked: revoked.iter().copied().collect(),
            roster: roster.clone(),
            identity_pub: identity_pub.clone(),
            params_hash,
            keyset_hash,
            deliveries,
            from_heads,
            issued_at: at,
        };
        check_rotation(&body)?;
        let record = LineageRecord::Rotation(sign_rotation(
            body,
            plan.device_keys,
            &account.keyset().identity,
        )?);
        let head = record.hash();
        for (recipient, envelope) in envelopes {
            writes.push((
                Record {
                    id: delivery_id(&head, recipient),
                    kind: RecordKind::KeyDelivery,
                    version: generation,
                    data: envelope,
                },
                None,
            ));
        }
        writes.push((
            Record {
                id: record.record_id(),
                kind: RecordKind::Lineage,
                version: generation,
                data: record.encode(),
            },
            None,
        ));

        // Sharing plan 2 Task 13 (spec 12.2 step 3 bis): in each shared
        // vault I belong to, an envelope of the current generation for the
        // new identity, my new lineage record in every shared and contact
        // zone, a rekey request when devices are revoked, the share state
        // marked `identity_pending`; every zone access signed again under
        // the new identity, its seed wrapped for the new KEM key. All in the
        // rotation's transaction.
        let (zoned, shares) = self.rotation_share_writes(
            &account,
            new_id,
            &record,
            matches!(
                plan.reason,
                RotationReason::Revoke | RotationReason::Recover
            ),
            at,
            &mut writes,
        )?;

        // The trust state of the new head.
        let mut next: TrustState = work.clone();
        next.head = LineageHead {
            generation,
            hash: head,
        };
        next.identity_pub = identity_pub;
        next.levels
            .retain(|id, _| roster.iter().any(|e| e.device_id == *id));
        next.roster = roster;
        next.add_revoked(&revoked.iter().copied().collect::<Vec<_>>());
        next.retired.push(RetiredIdentity {
            identity_id: identity_id(&self.account.params.identity_pub),
            sign_pub: self.account.params.signing_pub.clone(),
            identity_pub: self.account.params.identity_pub.clone(),
            generation: work.head.generation,
        });
        next.state = DeviceLineageState::Rotating { phase: 1 };
        // The new head is this device's own: every write it made so far is
        // in the content it re-sealed. Task 11 (spec 8.5, G4): should this
        // rotation lose to a sibling, those writes are replayed on the
        // winner, so each intent now names the record this device re-sealed
        // (`wrote`), based on the manifest the rotation was made from: a
        // later rotation made from this head reflects it.
        let froms: BTreeMap<Id, SeenManifest> =
            rotated.iter().map(|v| (v.id, v.from.clone())).collect();
        next.own_writes.entries = std::mem::take(&mut next.own_writes.entries)
            .into_iter()
            .filter_map(|mut w| {
                let from = froms.get(&w.vault)?;
                w.based_on = from.clone();
                if w.item == w.vault {
                    w.wrote = Some(*metas.get(&w.vault)?);
                } else if w.wrote.is_some() {
                    // Not in the content re-sealed: a later change of
                    // another device replaced it there.
                    w.wrote = Some(*resealed.get(&(w.vault, w.item))?);
                }
                Some(w)
            })
            .collect();

        // The chain state of the new identity: its params epoch and its
        // lists start again (spec 6.6, 10.2); it replaces the stored one in
        // the same transaction, so no reopen pins the left identity's.
        let chain = ChainState {
            sync_home: home_seen,
            params_epoch: account.params.epoch,
            device_list: Some(device_seen),
            vault_list: Some(vault_seen),
            approver_list: approver_seen,
            device_id: self.chain.device_id,
            contact_book: book_seen,
        };
        // Spec 6.8 (O6): this device's acknowledgment of the head it pins,
        // in the same transaction (display only).
        writes.push((
            crate::lineage::ack::ack_record(&next, plan.device_keys, at)?,
            None,
        ));
        collect.sort();
        collect.dedup();
        let push = RotationPush {
            vaults: rotated.iter().map(|v| v.id).collect(),
            collect,
        };

        // Step 6: one local transaction, nothing deleted (R23), conditional
        // on the trust state read above: a follow or a rejection saved
        // meanwhile (another connection) is a `Conflict`, nothing written.
        self.store.put_rotation(
            writes,
            chain.clone(),
            stored_trust,
            &next,
            &push,
            zoned,
            &shares,
        )?;

        // Committed: from here on nothing may fail (K12), or a caller
        // following the contract would discard the new Secret Key of an
        // account that already uses it. The session moves to the new
        // identity; restore epochs and list pins start again with it.
        let mut pinned = pin(&account);
        if let Some(old) = &self.device.pinned {
            pinned.kdf_floor = old.kdf_floor.clone();
            pinned.raise_floor(&account.params.kdf);
        }
        self.device.pinned = Some(pinned);
        self.device.epoch = 0;
        self.epoch_rewound = true;
        if let Ok(mut cache) = self.epoch_cache.lock() {
            *cache = None;
        }
        self.chain = chain;
        self.lists_forced = true;
        self.records_id = new_id;
        self.replace_last_seen(rotated.iter().map(|v| (v.id, v.head.clone())).collect());
        self.account = account;
        for v in &rotated {
            // Kept copies were signed by the old key (best effort: the next
            // load redoes it).
            let _ = self.store.vault_event(v.id, VaultEvent::Clean);
        }
        Ok(RotationOutcome {
            auk,
            code: rotation_code(&head),
            head,
        })
    }
}

impl<S: RecordStore> Repository<S> {
    /// The shared side of a rotation (sharing plan 2 Task 13): what goes
    /// in the shared and contact zones, the share states to write, and the
    /// zone accesses signed again (added to `writes`). Read with the
    /// identity being left, written for `account`, the new one.
    fn rotation_share_writes(
        &self,
        account: &Account,
        new_id: Id,
        record: &LineageRecord,
        revoke: bool,
        at: i64,
        writes: &mut Vec<(Record, Option<u64>)>,
    ) -> Result<ShareWrites> {
        let old = self.me();
        let new = MemberRef {
            account_id: old.account_id,
            identity_id: new_id,
        };
        // The whole chain (a reader follows it from the genesis it pinned)
        // and the new identity's params (its keys, bound by `params_hash`).
        let mut published: Vec<MemberLineageRecord> = Vec::new();
        for r in self.store.list(RecordKind::Lineage)? {
            if let Ok(l) = LineageRecord::decode(&r.data)
                && l.account_id() == old.account_id
            {
                published.push(MemberLineageRecord::Lineage(l));
            }
        }
        published.push(MemberLineageRecord::Lineage(record.clone()));
        if let Some((p, _)) = writes
            .iter()
            .find(|(r, _)| r.kind == RecordKind::AccountParams && r.id == new_id)
        {
            published.push(MemberLineageRecord::Params(p.data.clone()));
        }
        let published: Vec<(Id, Vec<u8>)> = published
            .into_iter()
            .map(|m| (m.id(), m.encode()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .collect();
        let head = record.hash();
        let mut zoned = Vec::new();
        let mut shares = Vec::new();
        let publish = |zone: Zone, zoned: &mut Vec<(Zone, Record, Option<u64>)>| -> Result<()> {
            for (id, data) in &published {
                if self
                    .store
                    .get_in(zone, RecordKind::MemberLineage, *id)?
                    .is_none()
                {
                    zoned.push((
                        zone,
                        Record {
                            kind: RecordKind::MemberLineage,
                            id: *id,
                            version: 1,
                            data: data.clone(),
                        },
                        None,
                    ));
                }
            }
            Ok(())
        };
        for mut state in self.store.share_states()? {
            if state
                .head
                .member(old.account_id)
                .is_none_or(|m| m.identity_id != old.identity_id)
            {
                continue;
            }
            // A vault I cannot open (refused, never keyed) gets nothing.
            let Ok(vault) = self.open_shared(state.vault_id) else {
                continue;
            };
            let zone = state.zone;
            let g = state.head.generation;
            let mk = wrap_member_key(&account.params.kem_pub, vault.key(), vault.id, g, &new)?;
            zoned.push((
                zone,
                Record {
                    kind: RecordKind::MemberKey,
                    id: mk.id(),
                    version: 1,
                    data: mk.encode(),
                },
                self.store
                    .get_in(zone, RecordKind::MemberKey, mk.id())?
                    .map(|r| r.version),
            ));
            publish(zone, &mut zoned)?;
            if revoke {
                let req = RekeyRequest::sign(
                    vault.id,
                    Some(head),
                    RekeyReason::MemberRotation,
                    g,
                    old,
                    &self.account.keyset().signing,
                )?;
                zoned.push((
                    zone,
                    Record {
                        kind: RecordKind::RekeyRequest,
                        id: req.id(),
                        version: 1,
                        data: req.encode(),
                    },
                    self.store
                        .get_in(zone, RecordKind::RekeyRequest, req.id())?
                        .map(|r| r.version),
                ));
            }
            state.identity_pending = Some(PendingIdentity {
                new_identity: new,
                since: at,
            });
            shares.push(state);
        }
        for zone in self.contact_zones()? {
            publish(zone, &mut zoned)?;
        }
        for access in self.zone_accesses()? {
            let Some((_, seed)) = self.zone_access(access.target)? else {
                continue;
            };
            let id = access.target.record_id()?;
            let expected = self.store.get(ZONE_ACCESS_KIND, id)?.map(|r| r.version);
            let signed = SignedZoneAccess::seal(
                account.params.account_id,
                &account.params.kem_pub,
                &account.keyset().signing,
                access.target,
                access.home,
                &seed,
            )?;
            let version = expected.map_or(Ok(1), |v| {
                v.checked_add(1)
                    .ok_or(Error::InvalidFormat("zone access version"))
            })?;
            writes.push((
                Record {
                    kind: ZONE_ACCESS_KIND,
                    id,
                    version,
                    data: signed.encode(),
                },
                expected,
            ));
        }
        Ok((zoned, shares))
    }
}
