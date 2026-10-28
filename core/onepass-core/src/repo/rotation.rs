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

use super::{
    DeviceState, Repository, account_records, entry, epoch_floor, pin, seen, split_item_record,
};
use crate::account::{Account, AccountParams, Auk, Rekeyed, identity_changed};
use crate::crypto::key::hkdf32;
use crate::crypto::{IdentityVerifyingKey, SecretKey};
use crate::devices::{DeviceEntry, invalid, now, revoked};
use crate::epoch::{EpochReason, RestoreEpoch, SignedRestoreEpoch};
use crate::lists::{ListBody, list_record};
use crate::manifest::{
    Manifest, SeenManifest, SignedManifest, record_hash, sign_manifest, verify_manifest,
};
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

/// Most a waiting rotation's params epoch may be signed again above its
/// own (ruling K14): a server that serves signed params far above it gets
/// an alert, not a signature at the epoch it picked.
pub(crate) const MAX_REISSUE_LEAP: u64 = 16;

/// The epoch a waiting rotation is signed again at, above the server's
/// `server` epoch: refused (`ParamsEpochJump`) more than
/// `MAX_REISSUE_LEAP` above the rotation's own `pending` epoch.
pub(crate) fn reissue_epoch(pending: u64, server: u64) -> Result<u64> {
    if server > pending.saturating_add(MAX_REISSUE_LEAP) {
        return Err(IntegrityError::ParamsEpochJump.into());
    }
    server
        .max(pending)
        .checked_add(1)
        .ok_or(IntegrityError::ParamsEpochJump.into())
}

/// The fingerprint a device keeps of a Secret Key it used (ruling K15):
/// HKDF-SHA256 keyed by the key itself, salted by the account id, so the
/// stored value is no oracle for anything.
pub(crate) fn key_fingerprint(account_id: Id, key: &SecretKey) -> Result<[u8; 32]> {
    Ok(*hkdf32(&account_id.0, &key.0, &[b"onepass/known-secret-key/v1"])?.expose())
}

/// SHA-256 of an identity public key's postcard encoding.
pub(crate) fn identity_fingerprint(identity: &IdentityVerifyingKey) -> [u8; 32] {
    let bytes = postcard::to_allocvec(identity).unwrap_or_default();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, &bytes).as_ref());
    out
}

/// Remember that this device used `key` with `account` (best effort: a
/// failure only loses the memory, never the unlock).
pub(crate) fn remember_key<S: RecordStore>(
    store: &mut S,
    account_id: Id,
    identity: &IdentityVerifyingKey,
    key: &SecretKey,
) {
    if let Ok(fp) = key_fingerprint(account_id, key) {
        let _ = store.remember_secret_key(fp, identity_fingerprint(identity));
    }
}

/// Whether `store` remembers `key` used with another identity than
/// `identity`.
fn known_elsewhere<S: RecordStore>(
    store: &S,
    account_id: Id,
    key: &SecretKey,
    identity: &IdentityVerifyingKey,
) -> bool {
    let (Ok(fp), Ok(known)) = (key_fingerprint(account_id, key), store.known_secret_keys()) else {
        // Fail closed: what cannot be checked is treated as known.
        return true;
    };
    let id = identity_fingerprint(identity);
    known.iter().any(|(k, i)| *k == fp && *i != id)
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
        let old_identity = self.account.params.identity_pub.clone();

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
        remember_key(&mut self.store, account_id, &old_identity, secret_key);
        let new_identity = self.account.params.identity_pub.clone();
        remember_key(&mut self.store, account_id, &new_identity, new_secret_key);
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
    /// A new identity offered with a Secret Key this device already used
    /// under another identity is refused (`Validation("secret key")`,
    /// rulings K11 and K15), whatever order the app tries keys in: the
    /// revoked device knows the password and the old key too. The device
    /// remembers every key it unlocked or rotated with
    /// (`RecordStore::known_secret_keys`; a store that keeps none, as the
    /// CLI's, checks nothing). On a device that pinned nothing, this is
    /// `unlock_exporting_auk`.
    pub fn unlock_after_rotation(
        mut store: S,
        password: &str,
        secret_key: &SecretKey,
        mut device: DeviceState,
    ) -> Result<(Repository<S>, Auk)> {
        let Some(pinned) = device.pinned.clone() else {
            return Self::unlock_exporting_auk(store, password, secret_key, device);
        };
        let (params, keyset) = account_records(&store)?;
        let chain = store.chain_state()?;
        let known = |identity: &IdentityVerifyingKey| {
            known_elsewhere(&store, pinned.account_id, secret_key, identity)
        };
        let (account, auk, pin) = Account::unlock_rotated_at(
            password,
            secret_key,
            &known,
            &params.data,
            &keyset.data,
            &pinned,
            chain.params_epoch,
        )?;
        remember_key(
            &mut store,
            account.params.account_id,
            &account.params.identity_pub,
            secret_key,
        );
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
        let epoch = reissue_epoch(pending.epoch, server_epoch)?;
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
        // Verified params of another identity at an epoch at least the
        // rotation's: a password change made elsewhere, now overtaken.
        self.store.note_password_change_overtaken()?;
        self.persist_device_state()?;
        Ok(true)
    }

    /// While this device's rotation is not whole on the server
    /// (`SyncStore::rotation_marked`), resolve every held vault whose
    /// server manifest the session's signing key did not sign (a write made
    /// with the old keys reached the server first): this device's rotated
    /// copy wins, the item records the server holds for that vault outside
    /// the local manifest are deleted, and the local manifest is made to
    /// build on the server's, so key, meta, manifest and items go out
    /// together (ruling K13). The concurrent write is lost; a manifest the
    /// new key signed is left to the normal rebase.
    pub(crate) fn resolve_rotated_vaults(&mut self) -> Result<()> {
        for v in self.store.vaults_needing_rebase()? {
            let Some(base) = self.store.base_record(RecordKind::Manifest, v)? else {
                continue;
            };
            let vault = self.open_vault(v)?;
            let signing = &self.account.params.signing_pub;
            let foreign = SignedManifest::decode(&base.data)
                .and_then(|sm| verify_manifest(&vault, signing, &sm, None))
                .is_err();
            if !foreign {
                continue;
            }
            let ours = self
                .store
                .get(RecordKind::Manifest, v)?
                .ok_or(IntegrityError::ManifestMissingItem)?;
            let m = verify_manifest(&vault, signing, &SignedManifest::decode(&ours.data)?, None)?;
            for r in self.store.list(RecordKind::Item)? {
                let (prefix, body) = split_item_record(&r.data)?;
                if prefix != v {
                    continue;
                }
                let listed = ItemRecord::decode(body).is_ok_and(|rec| {
                    m.entries.iter().any(|e| {
                        e.item_id == rec.item_id
                            && e.version == rec.version
                            && e.record_hash == record_hash(&rec)
                    })
                });
                if !listed {
                    self.store.delete(RecordKind::Item, r.id)?;
                }
            }
            self.store.rebuild_ancestors_on_base(&[v])?;
        }
        Ok(())
    }

    /// Issue the rotation's restore epoch again when a rebase would have
    /// dropped it (the server took another epoch, or vaults were rebased
    /// and renumbered): same reason, the current heads of its vaults, at
    /// the next number above it and the server's (capped as for the params,
    /// ruling K14), signed by the session's key, built on the server's
    /// record (ruling K13).
    pub(crate) fn reissue_rotation_epoch(&mut self) -> Result<()> {
        let Some(pending) = self.store.pending_rotation_epoch()? else {
            return Ok(());
        };
        let current = pending.epoch.epoch;
        let server = self.store.server_epoch_number()?.unwrap_or(0);
        let epoch = reissue_epoch(current, server)?;
        let heads: BTreeMap<Id, SeenManifest> = pending
            .epoch
            .heads
            .keys()
            .filter_map(|v| self.device.last_seen.get(v).map(|s| (*v, s.clone())))
            .collect();
        let account_id = self.account.params.account_id;
        let issued = RestoreEpoch {
            account_id,
            epoch,
            issued_at: OffsetDateTime::now_utc().unix_timestamp(),
            heads: heads.clone(),
            reason: EpochReason::KeyRotation,
        };
        let data = SignedRestoreEpoch::sign(issued, &self.account.keyset().signing)?.encode();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest(&SHA256, &data).as_ref());
        self.store.put_if_version(
            Record {
                id: account_id,
                kind: RecordKind::RestoreEpoch,
                version: epoch,
                data,
            },
            Some(current),
        )?;
        self.store
            .rebuild_ancestor_on_base(RecordKind::RestoreEpoch, account_id)?;
        self.device.epoch = epoch;
        self.replace_last_seen(heads);
        self.store.set_restore_epoch_mark(epoch, hash)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reissue_epoch_is_capped_above_the_rotation() {
        assert_eq!(reissue_epoch(2, 1).unwrap(), 3);
        assert_eq!(reissue_epoch(2, 2).unwrap(), 3);
        assert_eq!(
            reissue_epoch(2, 2 + MAX_REISSUE_LEAP).unwrap(),
            3 + MAX_REISSUE_LEAP
        );
        let jump = Error::Integrity(IntegrityError::ParamsEpochJump);
        for server in [3 + MAX_REISSUE_LEAP, u64::MAX - 1, u64::MAX] {
            assert_eq!(reissue_epoch(2, server).unwrap_err(), jump);
        }
        assert_eq!(reissue_epoch(u64::MAX, u64::MAX).unwrap_err(), jump);
    }

    #[test]
    fn key_fingerprints_depend_on_the_key_and_the_account() {
        let (a, b) = (
            SecretKey::generate().unwrap(),
            SecretKey::generate().unwrap(),
        );
        let (x, y) = (Id::new(), Id::new());
        let fp = key_fingerprint(x, &a).unwrap();
        assert_eq!(fp, key_fingerprint(x, &a).unwrap());
        assert_ne!(fp, key_fingerprint(x, &b).unwrap());
        assert_ne!(fp, key_fingerprint(y, &a).unwrap());
        assert_ne!(&fp, &a.0);
    }
}
