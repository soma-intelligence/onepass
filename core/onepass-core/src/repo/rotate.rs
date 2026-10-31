//! Key rotation v2 on the rotating device (spec 7.1, steps 1 to 6).
//!
//! `Repository::rotate` checks every precondition, then builds the whole
//! rotation in memory: a new Secret Key (from the caller, K6), a new
//! identity with its signing and KEM keys and params at epoch 1
//! (`Account::rotate_keys`), the roster without the revoked and excluded
//! devices, one Secret Key delivery per remaining device, every live vault
//! under a new vault key with every listed item resealed at version + 1 and
//! the next manifest signed by the new key, both signed lists at seq 1, and
//! the rotation record signed by this device's key and by the new identity.
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

use super::replay::meta_hash;
use super::{Repository, entry, pin, seen};
use crate::account::{Account, Auk, RotatedAccount};
use crate::chain::{ChainState, Seen};
use crate::crypto::kem::wrap_key_labeled;
use crate::crypto::{SecretKey, SymmetricKey};
use crate::device_keys::DeviceKeys;
use crate::devices::{DeviceEntry, now};
use crate::lineage::{
    LINEAGE_FORMAT, LineageRecord, RosterEntry, RotationBody, RotationReason, check_rotation,
    delivery_id, identity_id, rotation_code, sign_rotation,
};
use crate::lists::{AccountList, ListBody, sign};
use crate::manifest::{Manifest, SeenManifest, record_hash, sign_manifest};
use crate::store::{Record, RecordKind, RecordStore, RotationPush, VaultEvent, account_record_id};
use crate::trust::{DeviceLineageState, LineageHead, RetiredIdentity, TrustLevel, TrustState};
use crate::vault::{ItemRecord, Vault};
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

/// The stored record of an item: `vault_id || postcard(ItemRecord)` under a
/// fresh blob id (see the layout in `repo`).
fn item_record(vault_id: Id, rec: &ItemRecord) -> Result<Record> {
    let mut data = vault_id.0.to_vec();
    data.extend(postcard::to_allocvec(rec).map_err(|_| Error::InvalidFormat("item record"))?);
    Ok(Record {
        id: Id::new(),
        kind: RecordKind::Item,
        version: rec.version,
        data,
    })
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

/// One vault rotated in memory.
struct RotatedVault {
    id: Id,
    from: SeenManifest,
    head: SeenManifest,
}

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
        if !self.travel_parked.is_empty() {
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
        if !trust
            .roster
            .iter()
            .any(|e| e.device_id == me && e.sign_pub == trust.me.sign_pub)
        {
            return Err(refused("device", "not in the roster"));
        }
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
        let generation = trust
            .head
            .generation
            .checked_add(1)
            .ok_or(Error::InvalidFormat("lineage generation"))?;

        // R22: every live vault loads through the verified path.
        let vaults = self.vaults()?;
        let mut loaded = Vec::with_capacity(vaults.len());
        for vault in vaults {
            let l = self.load(&vault)?;
            loaded.push((vault, l));
        }
        let devices = self.read_list::<DeviceEntry>()?;
        let vault_list = self.read_list::<VaultListEntry>()?;

        // The current password and Secret Key, with every unlock check, on
        // the records of the current identity (spec 6.6). This also gives
        // the account the current Secret Key (`rotate_keys` compares, K11).
        let current_id = account_record_id(
            account_id,
            (trust.head.generation > 0).then_some(&trust.identity_pub),
        );
        let params = self
            .store
            .get(RecordKind::AccountParams, current_id)?
            .ok_or(Error::NotFound)?;
        let keyset = self
            .store
            .get(RecordKind::Keyset, current_id)?
            .ok_or(Error::NotFound)?;
        let (stored, _) = Account::unlock_exporting_auk_at(
            req.password,
            req.secret_key,
            &params.data,
            &keyset.data,
            self.device.pinned.as_ref(),
            self.account.params.epoch,
        )?;
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
        } = stored.rotate_keys(
            req.new_password.unwrap_or(req.password),
            req.new_secret_key,
            &floor,
        )?;
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
        let tofu = |id: &Id| trust.levels.get(id) == Some(&TrustLevel::Tofu) && *id != me;
        let roster: Vec<RosterEntry> = trust
            .roster
            .iter()
            .filter(|e| {
                !revoked.contains(&e.device_id)
                    && !trust.excluded.contains(&e.device_id)
                    && !trust.revoked.contains(&e.device_id)
                    && (!tofu(&e.device_id) || req.keep_tofu.contains(&e.device_id))
            })
            .cloned()
            .collect();
        let secret = SymmetricKey::from_bytes(req.new_secret_key.0);
        let mut envelopes = Vec::new();
        for e in roster.iter().filter(|e| e.device_id != me) {
            let context = delivery_context(account_id, &trust.head.hash, e.device_id);
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
            let mut entries = Vec::with_capacity(l.records.len());
            for (blob, rec) in &l.records {
                collect.push(*blob);
                let item = vault.open_item(rec)?;
                let version = rec
                    .version
                    .checked_add(1)
                    .ok_or(Error::InvalidFormat("item version"))?;
                let sealed = fresh.reseal_item(&item, version)?;
                resealed.insert((vault.id, item.id), record_hash(&sealed));
                entries.push(entry(&sealed));
                writes.push((item_record(vault.id, &sealed)?, None));
            }
            // Spec 6.7: prev_hash and seq follow the manifest loaded.
            let m = Manifest::next(Some(&l.manifest), vault.id, entries)?.with_meta(&fresh.meta);
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

        // Step 4: both lists at seq 1 under the identity id, signed by the
        // new key; the device list marks the revoked devices.
        let at = now();
        let mut device_entries = devices.map(|d| d.body.entries).unwrap_or_default();
        for e in &mut device_entries {
            if revoked.contains(&e.device_id) {
                e.revoked_at.get_or_insert(at);
            }
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

        // Step 5: the rotation record, signed by this device and by the new
        // identity.
        let from_heads: BTreeMap<Id, SeenManifest> =
            rotated.iter().map(|v| (v.id, v.from.clone())).collect();
        let body = RotationBody {
            format: LINEAGE_FORMAT,
            account_id,
            generation,
            parent: trust.head.hash,
            rotator: me,
            reason: req.reason,
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
            req.device_keys,
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

        // The trust state of the new head.
        let mut next: TrustState = trust.clone();
        next.head = LineageHead {
            generation,
            hash: head,
        };
        next.identity_pub = identity_pub;
        next.levels
            .retain(|id, _| roster.iter().any(|e| e.device_id == *id));
        next.roster = roster;
        next.add_revoked(&req.revoke);
        next.retired.push(RetiredIdentity {
            identity_id: identity_id(&self.account.params.identity_pub),
            sign_pub: self.account.params.signing_pub.clone(),
            identity_pub: self.account.params.identity_pub.clone(),
            generation: trust.head.generation,
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
            params_epoch: account.params.epoch,
            device_list: Some(device_seen),
            vault_list: Some(vault_seen),
            device_id: self.chain.device_id,
        };
        collect.sort();
        collect.dedup();
        let push = RotationPush {
            vaults: rotated.iter().map(|v| v.id).collect(),
            collect,
        };

        // Step 6: one local transaction, nothing deleted (R23), conditional
        // on the trust state read above: a follow or a rejection saved
        // meanwhile (another connection) is a `Conflict`, nothing written.
        self.store
            .put_rotation(writes, chain.clone(), &trust, &next, &push)?;

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
