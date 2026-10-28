//! Key rotation (finding F1, spec `2026-10-28-key-rotation-design.md`).
//!
//! A rotation replaces every secret of the account in one conditional
//! write: a new Secret Key and keyset (KEM, signing and identity keys,
//! `Account::rotate`), v2 params at the next epoch signed by the new
//! identity, a new key for every vault with every listed item re-sealed
//! under a fresh item key (version + 1, new blob id), the next manifest of
//! each vault signed by the new signing key, both signed lists signed again
//! (a revoked device marked in the same list), and a restore epoch
//! (`EpochReason::KeyRotation`) whose heads are the new manifests. The old
//! item records and the ignored leftovers are deleted in the same write.
//!
//! Whoever kept the old Secret Key, keyset or vault keys reads nothing
//! written after it, and nothing signed with the old keys is accepted
//! again. A device that saw the rotation pins the new identity and the new
//! params epoch: the old pair is refused (`ParamsRollback`, or
//! `ParamsUnsigned` where the epoch is not kept). Another trusted device
//! follows with the new Secret Key only (`unlock_after_rotation`).

use std::collections::BTreeMap;

use aws_lc_rs::digest::{SHA256, digest};
use time::OffsetDateTime;

use super::{DeviceState, Repository, account_records, entry, epoch_floor, pin, seen};
use crate::account::{Account, AccountParams, Auk, Rekeyed, identity_changed};
use crate::crypto::SecretKey;
use crate::devices::{DeviceEntry, invalid, now, revoked};
use crate::epoch::{EpochReason, RestoreEpoch, SignedRestoreEpoch};
use crate::lists::{ListBody, list_record};
use crate::manifest::{Manifest, sign_manifest};
use crate::store::{Record, RecordKind, RecordStore, VaultEvent};
use crate::sync::SyncStore;
use crate::vault::{ItemRecord, Vault};
use crate::vaultlist::VaultListEntry;
use crate::{Error, Id, IntegrityError, Result};

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

fn next_version(r: &Record) -> Result<u64> {
    r.version.checked_add(1).ok_or(Error::Conflict)
}

impl<S: RecordStore> Repository<S> {
    /// Rotate every key of the account (spec 2026-10-28): see the module
    /// doc. `current` and `secret_key` are checked first by opening the
    /// stored params and keyset with every unlock check (a wrong one is
    /// `Error::WrongPassword`, nothing written). The new keyset is sealed
    /// under `new_password`, or `current` when `None`, and
    /// `new_secret_key`, which the caller drew (`SecretKey::generate`) and
    /// stored as pending before this call (ruling K6). Returns the new
    /// Account Unlock Key.
    ///
    /// Every vault must load cleanly (`vaults`, then the strict `load`):
    /// their errors come first, and nothing is written. Refused while the
    /// Travel Mode parks vaults (`InvalidFormat("travel mode active")`), on
    /// a device the list marks revoked (`Validation("device")`), and when
    /// the session's params are no longer the stored ones (`Conflict`:
    /// unlock again). Any write by another writer since the records were
    /// read is `Error::Conflict` and nothing is written.
    ///
    /// With a `SyncStore` the device state is saved by the next
    /// `persist_device_state`, which the caller runs right after.
    pub fn rotate_keys(
        &mut self,
        current: &str,
        secret_key: &SecretKey,
        new_secret_key: &SecretKey,
        new_password: Option<&str>,
    ) -> Result<Auk> {
        self.rotate(current, secret_key, new_secret_key, new_password, None)
    }

    /// Revoke a device and rotate every key in the same write (ruling K7):
    /// `rotate_keys` with the device marked revoked in the device list
    /// signed by the new key. This device cannot revoke itself
    /// (`Validation("device")`); an id the list does not hold is
    /// `NotFound`; a device already revoked stays so (the keys still
    /// rotate).
    pub fn revoke_device_rotating(
        &mut self,
        id: Id,
        password: &str,
        secret_key: &SecretKey,
        new_secret_key: &SecretKey,
    ) -> Result<Auk> {
        self.rotate(password, secret_key, new_secret_key, None, Some(id))
    }

    fn rotate(
        &mut self,
        current: &str,
        secret_key: &SecretKey,
        new_secret_key: &SecretKey,
        new_password: Option<&str>,
        revoke: Option<Id>,
    ) -> Result<Auk> {
        if !self.travel_parked.is_empty() {
            return Err(Error::InvalidFormat("travel mode active"));
        }
        // A "rotation" to the key already in use proves nothing to the
        // other devices (ruling K11).
        if new_secret_key.same_as(secret_key) {
            return Err(invalid("secret key", "unchanged"));
        }
        let account_id = self.account.params.account_id;

        // The lists, up to date (migration, registration), and the device
        // to revoke.
        let stored_epoch = self.sync_epoch()?.map(|e| e.epoch);
        self.maintain_lists(None)?;
        let devices = self.read_list::<DeviceEntry>()?;
        let vault_list = self.read_list::<VaultListEntry>()?;
        let mut device_entries = devices
            .as_ref()
            .map(|d| d.body.entries.clone())
            .unwrap_or_default();
        let me = self.chain.device_id;
        if device_entries
            .iter()
            .any(|e| Some(e.device_id) == me && e.revoked_at.is_some())
        {
            return Err(revoked());
        }
        if let Some(id) = revoke {
            if me == Some(id) {
                return Err(invalid("device", "this device"));
            }
            let e = device_entries
                .iter_mut()
                .find(|e| e.device_id == id)
                .ok_or(Error::NotFound)?;
            e.revoked_at.get_or_insert_with(now);
        }

        // The current password and Secret Key, with every unlock check.
        let (params, keyset) = account_records(&self.store)?;
        if params.id != account_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let (stored, _) = Account::unlock_exporting_auk_at(
            current,
            secret_key,
            &params.data,
            &keyset.data,
            self.device.pinned.as_ref(),
            self.chain.params_epoch,
        )?;
        if stored.params != self.account.params {
            // Changed by another device since this session opened: the
            // vault keys below were opened with the session's keys.
            return Err(Error::Conflict);
        }
        let Rekeyed {
            account,
            auk,
            params_record,
            keyset_record,
        } = stored.rotate(new_secret_key, new_password.unwrap_or(current))?;

        let mut writes = vec![
            (
                Record {
                    id: account_id,
                    kind: RecordKind::Keyset,
                    version: next_version(&keyset)?,
                    data: keyset_record,
                },
                Some(keyset.version),
            ),
            (
                Record {
                    id: account_id,
                    kind: RecordKind::AccountParams,
                    version: next_version(&params)?,
                    data: params_record,
                },
                Some(params.version),
            ),
        ];
        let mut deletes = Vec::new();

        // Every vault: a new key, every listed item re-sealed, the next
        // manifest above the new epoch's seq floor.
        let epoch = self
            .device
            .epoch
            .max(stored_epoch.unwrap_or(0))
            .checked_add(1)
            .ok_or(Error::InvalidFormat("restore epoch"))?;
        let floor = epoch_floor(epoch)?;
        let mut heads = BTreeMap::new();
        for vault in self.vaults()? {
            let loaded = self.load(&vault)?;
            let key_rec = self
                .store
                .get(RecordKind::VaultKey, vault.id)?
                .ok_or(Error::NotFound)?;
            let meta_rec = self
                .store
                .get(RecordKind::VaultMeta, vault.id)?
                .ok_or(Error::InvalidFormat("vault meta"))?;
            let (fresh, envelope, meta_blob) =
                Vault::create_with_id(&account, vault.id, vault.meta.clone())?;
            let mut entries = Vec::with_capacity(loaded.records.len());
            for (blob, rec) in &loaded.records {
                let item = vault.open_item(rec)?;
                let version = rec
                    .version
                    .checked_add(1)
                    .ok_or(Error::InvalidFormat("item version"))?;
                let sealed = fresh.reseal_item(&item, version)?;
                entries.push(entry(&sealed));
                writes.push((item_record(vault.id, &sealed)?, None));
                deletes.push((RecordKind::Item, *blob));
            }
            deletes.extend(
                loaded
                    .ignored
                    .iter()
                    .map(|(blob, _)| (RecordKind::Item, *blob)),
            );
            let mut m = Manifest::next(Some(&loaded.manifest), vault.id, entries)?;
            m.seq = m.seq.max(floor);
            let sm = sign_manifest(&fresh, &account.keyset().signing, &m)?;
            writes.push((
                Record {
                    id: vault.id,
                    kind: RecordKind::Manifest,
                    version: m.seq,
                    data: postcard::to_allocvec(&sm)
                        .map_err(|_| Error::InvalidFormat("manifest"))?,
                },
                Some(loaded.manifest.seq),
            ));
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
            heads.insert(vault.id, seen(&m));
        }

        // Both lists signed again by the new key, at their next seq.
        let mut device_seen = None;
        if let Some(d) = &devices {
            let body = ListBody::next(Some(&d.body), account_id, device_entries)?;
            device_seen = Some(body.seen());
            writes.push((list_record(&account, body)?, Some(d.version)));
        }
        let mut vault_seen = None;
        if let Some(v) = &vault_list {
            let body = ListBody::next(Some(&v.body), account_id, v.body.entries.clone())?;
            vault_seen = Some(body.seen());
            writes.push((list_record(&account, body)?, Some(v.version)));
        }

        // The restore epoch of the rotation, signed by the new key.
        let issued = RestoreEpoch {
            account_id,
            epoch,
            issued_at: OffsetDateTime::now_utc().unix_timestamp(),
            heads: heads.clone(),
            reason: EpochReason::KeyRotation,
        };
        let data = SignedRestoreEpoch::sign(issued, &account.keyset().signing)?.encode();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest(&SHA256, &data).as_ref());
        writes.push((
            Record {
                id: account_id,
                kind: RecordKind::RestoreEpoch,
                version: epoch,
                data,
            },
            stored_epoch,
        ));

        // One write, all or nothing.
        self.store.put_all_if_version_and_delete(writes, deletes)?;

        // The session moves to the new account: pin the new identity (the
        // KDF floor only goes up), the params epoch, the lists, the epoch
        // and its heads.
        let mut pinned = pin(&account);
        if let Some(old) = &self.device.pinned {
            pinned.kdf_floor = old.kdf_floor.clone();
            pinned.raise_floor(&account.params.kdf);
        }
        self.device.pinned = Some(pinned);
        self.chain.accept_params_epoch(account.params.epoch);
        if let Some(s) = device_seen {
            self.chain.device_list = Some(s);
        }
        if let Some(s) = vault_seen {
            self.chain.vault_list = Some(s);
        }
        self.account = account;
        self.auk = Some(Auk::from_bytes(*auk.as_bytes()));
        self.device.epoch = epoch;
        self.replace_last_seen(heads);
        // The write is committed: from here on nothing may fail, or a
        // caller following the contract would discard the new Secret Key of
        // an account that already uses it (ruling K12). Both steps below
        // are bookkeeping the next session redoes: the epoch mark is set
        // again by `sync_epoch`, a kept copy signed by the old key fails its
        // check and is replaced.
        let _ = self.store.set_restore_epoch_mark(epoch, hash);
        let vaults: Vec<Id> = self.device.last_seen.keys().copied().collect();
        for v in vaults {
            // The kept copies were signed by the old key: drop them.
            let _ = self.store.vault_event(v, VaultEvent::Clean);
        }
        Ok(auk)
    }

    /// Unlock on a trusted device after the keys were rotated on another
    /// one (spec 2026-10-28, section 5), with the new Secret Key the user
    /// just supplied (typed from the new Emergency Kit, or received by
    /// pairing). The pinned identity may change, under the rules of
    /// `Account::unlock_rotated_at` (same account, epoch above the pinned
    /// one, keyset opening under `password` and `secret_key`); the KDF
    /// floor, the lists seen and the device id are kept. The normal unlock
    /// functions never follow a new identity (ruling K9).
    ///
    /// `previous` is the Secret Key the device held until now (Keychain,
    /// `device.bin`): a new identity sealed under it is refused
    /// (`Validation("secret key")`, ruling K11), since the revoked device
    /// knows it too. On a device that pinned nothing, this is
    /// `unlock_exporting_auk`.
    pub fn unlock_after_rotation(
        store: S,
        password: &str,
        secret_key: &SecretKey,
        previous: &SecretKey,
        mut device: DeviceState,
    ) -> Result<(Repository<S>, Auk)> {
        let Some(pinned) = device.pinned.clone() else {
            return Self::unlock_exporting_auk(store, password, secret_key, device);
        };
        let (params, keyset) = account_records(&store)?;
        let chain = store.chain_state()?;
        let (account, auk, pin) = Account::unlock_rotated_at(
            password,
            secret_key,
            previous,
            &params.data,
            &keyset.data,
            &pinned,
            chain.params_epoch,
        )?;
        device.pinned = Some(pin);
        Ok((
            Self::finish_unlock(store, account, &params, device, chain, &auk)?,
            auk,
        ))
    }

    /// Whether the account in `store` is the one `device` pinned, signed by
    /// another identity than the pinned one at an epoch above the store's
    /// pinned params epoch (`account::identity_changed`), without any
    /// unlock: the keys were rotated on another device, and the app asks
    /// for the new Secret Key (`unlock_after_rotation`). `false` without a
    /// pin or an account.
    pub fn keys_rotated(store: &S, device: &DeviceState) -> Result<bool> {
        let Some(pinned) = &device.pinned else {
            return Ok(false);
        };
        let params = match account_records(store) {
            Ok((params, _)) => params,
            Err(Error::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };
        identity_changed(&params.data, pinned, store.chain_state()?.params_epoch)
    }
}

impl Repository<SyncStore> {
    /// A rotation of this session whose params the server overtook before
    /// they landed (another device changed the password, or the server
    /// served params of an epoch at least theirs): sign the same keys
    /// again at the server's epoch plus one and reseal the keyset under the
    /// same Account Unlock Key, in place of the pending pair (ruling K10).
    /// Run by `rebase`. Returns whether it did.
    ///
    /// Only for the pair this session wrote (same identity as the session's
    /// account); it needs the session's Account Unlock Key
    /// (`InvalidFormat("rotation pending: unlock with the password")`
    /// without one).
    pub(crate) fn reissue_rotation(&mut self) -> Result<bool> {
        let Some((id, server_epoch)) = self.store.rotation_blocked()? else {
            return Ok(false);
        };
        if id != self.account.params.account_id {
            return Ok(false);
        }
        let (params, keyset) = account_records(&self.store)?;
        let pending = AccountParams::decode(&params.data)?;
        if pending.identity_pub != self.account.params.identity_pub {
            return Ok(false);
        }
        let auk = self.auk.as_ref().ok_or(Error::InvalidFormat(
            "rotation pending: unlock with the password",
        ))?;
        let epoch = server_epoch
            .max(pending.epoch)
            .checked_add(1)
            .ok_or(Error::InvalidFormat("account params"))?;
        let (reissued, params_record, keyset_record) = self.account.reissue(epoch, auk)?;
        self.store.put_all_if_version(vec![
            (
                Record {
                    id,
                    kind: RecordKind::Keyset,
                    version: next_version(&keyset)?,
                    data: keyset_record,
                },
                Some(keyset.version),
            ),
            (
                Record {
                    id,
                    kind: RecordKind::AccountParams,
                    version: next_version(&params)?,
                    data: params_record,
                },
                Some(params.version),
            ),
        ])?;
        self.account.params = reissued;
        self.chain.accept_params_epoch(epoch);
        self.persist_device_state()?;
        Ok(true)
    }
}
