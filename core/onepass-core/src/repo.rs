//! Repository: ties the account, its vaults, items and manifests to a
//! record store, and verifies everything it reads back from it.
//!
//! Layout in the store:
//! - account params (`AccountParams`) and keyset (`Keyset`), id = account id;
//! - vault key envelope (`VaultKey`) and sealed meta (`VaultMeta`), id = vault id;
//! - signed manifest (`Manifest`), id = vault id, version = seq,
//!   data = `postcard(SignedManifest)`;
//! - item records (`Item`), id = a fresh blob id per written version,
//!   version = item version, data = `vault_id (16 bytes) || postcard(ItemRecord)`;
//! - signed device list (`DeviceList`) and vault list (`VaultList`), id =
//!   account id, version = seq (see `lists`, `devices`, `vaultlist`).
//!
//! - restore epoch (`RestoreEpoch`), id = account id, version = epoch,
//!   data = `postcard(SignedRestoreEpoch)` (see `crate::epoch`).
//!
//! Item versions get their own blob ids so that writing a new version never
//! overwrites the one the current manifest lists. Writes go record first,
//! manifest second, cleanup last: nothing is deleted before the manifest
//! write succeeds. The manifest write is conditional on the stored manifest
//! still being the one loaded (`put_if_version` on the seq): two writers
//! racing on one vault, on different items or on the same one, cannot both
//! win; the loser gets `Error::Conflict`, deletes the record it just wrote
//! (only that one), and the winner's state stays readable. This holds in
//! the core alone, without the CLI lock.
//!
//! A crash before the manifest leaves an interrupted write, which loading
//! ignores: a record that opens under the vault key and carries exactly the
//! next version of a listed item, or version 1 of an item the manifest does
//! not list. Any other record that does not match the manifest is reported,
//! as `check_records` does, except the leftovers below.
//!
//! Beside the exact current record (same version and hash) of a listed
//! item, two leftovers are ignored: an older version (a crash after the
//! manifest but before the old record is deleted) and the same version with
//! another hash (a race loser stopped before deleting its record). Served
//! instead of the current record, both stay errors.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use aws_lc_rs::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::account::{Account, Auk, NewAccount, PinnedAccount, Rekeyed};
use crate::chain::ChainState;
use crate::devices::{DeviceEntry, now, self_entry};
use crate::lists::{ListBody, list_record};
use crate::vaultlist::VaultListEntry;
use zeroize::Zeroizing;

use crate::crypto::{Aad, BlobKind, KdfParams, SecretKey, seal};
use crate::epoch::{EpochReason, RestoreEpoch, SignedRestoreEpoch};
use crate::manifest::{
    Manifest, ManifestEntry, SeenManifest, SignedManifest, check_records, manifest_hash,
    record_hash, sign_manifest, verify_manifest,
};
use crate::model::Item;
use crate::model::events::EventKind;
use crate::model::usage::SiteUsage;
use crate::store::{Record, RecordKind, RecordStore, VaultEvent};
use crate::vault::{ItemRecord, Vault, VaultMeta};
use crate::{Error, Id, IntegrityError, Result};

mod local;
pub mod travel;

/// What a device keeps between sessions: the account pinned at first
/// unlock, the last manifest accepted for each vault, and the restore epoch
/// it last accepted (0 before any).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceState {
    pub pinned: Option<PinnedAccount>,
    pub last_seen: BTreeMap<Id, SeenManifest>,
    pub epoch: u64,
}

/// Header of the versioned `DeviceState` encoding, followed by the version.
const DEVICE_STATE_MAGIC: &[u8; 3] = b"ODS";

/// The version 1 layout (headerless postcard), still read and migrated.
///
/// Its first byte is the postcard tag of `pinned: Option<_>`, always 0 or 1,
/// never `b'O'` (0x4F): a version 1 encoding cannot be taken for the header.
#[derive(Deserialize)]
struct DeviceStateV1 {
    pinned: Option<PinnedAccount>,
    last_seen: BTreeMap<Id, SeenManifest>,
}

/// The version 2 body, borrowed for encoding.
#[derive(Serialize)]
struct DeviceStateV2Ref<'a> {
    pinned: &'a Option<PinnedAccount>,
    last_seen: &'a BTreeMap<Id, SeenManifest>,
    epoch: u64,
}

#[derive(Deserialize)]
struct DeviceStateV2 {
    pinned: Option<PinnedAccount>,
    last_seen: BTreeMap<Id, SeenManifest>,
    epoch: u64,
}

fn decode_whole<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    match postcard::take_from_bytes::<T>(bytes) {
        Ok((value, [])) => Ok(value),
        _ => Err(Error::InvalidFormat("device state")),
    }
}

impl DeviceState {
    /// Versioned encoding, for the device to persist between sessions:
    /// `b"ODS" || DEVICE_STATE_VERSION || postcard { pinned, last_seen, epoch }`.
    pub fn encode(&self) -> Vec<u8> {
        let body = DeviceStateV2Ref {
            pinned: &self.pinned,
            last_seen: &self.last_seen,
            epoch: self.epoch,
        };
        let mut out = DEVICE_STATE_MAGIC.to_vec();
        out.push(crate::format::DEVICE_STATE_VERSION);
        // Plain data (options, maps of ids and hashes): encoding cannot fail.
        postcard::to_extend(&body, out).expect("device state encodes")
    }

    /// Decode what `encode` wrote, or the headerless version 1 encoding
    /// (migrated with `epoch = 0`): the whole buffer, trailing bytes refused
    /// (`InvalidFormat("device state")`). A version newer than this build's
    /// is `InvalidFormat("device state from a newer version")`.
    pub fn decode(bytes: &[u8]) -> Result<DeviceState> {
        let Some(rest) = bytes.strip_prefix(DEVICE_STATE_MAGIC) else {
            let v1: DeviceStateV1 = decode_whole(bytes)?;
            return Ok(DeviceState {
                pinned: v1.pinned,
                last_seen: v1.last_seen,
                epoch: 0,
            });
        };
        match rest.split_first() {
            Some((&crate::format::DEVICE_STATE_VERSION, body)) => {
                let v2: DeviceStateV2 = decode_whole(body)?;
                Ok(DeviceState {
                    pinned: v2.pinned,
                    last_seen: v2.last_seen,
                    epoch: v2.epoch,
                })
            }
            Some((&v, _)) if v > crate::format::DEVICE_STATE_VERSION => {
                Err(Error::InvalidFormat("device state from a newer version"))
            }
            _ => Err(Error::InvalidFormat("device state")),
        }
    }
}

/// An unlocked account over a record store it does not trust.
pub struct Repository<S: RecordStore> {
    pub(crate) store: S,
    pub(crate) account: Account,
    pub(crate) device: DeviceState,
    /// Vaults whose `last_seen` entry was removed or replaced on purpose
    /// (Travel Mode parks them, a restore epoch replaces the map with its
    /// heads) since the device state was last persisted: a merging
    /// persist (`Repository<SyncStore>::persist_device_state`) must not take
    /// the stored entry back for them.
    pub(crate) dropped: BTreeSet<Id>,
    /// The accepted restore epoch was taken back on purpose (a pending
    /// epoch that could not ship was dropped) since the device state was
    /// last persisted: a merging persist keeps the in-memory epoch instead
    /// of the larger of it and the stored one.
    pub(crate) epoch_rewound: bool,
    /// The last restore epoch record verified, keyed by its version and
    /// data, so that a read does not verify the same signature again.
    epoch_cache: Mutex<Option<(u64, Vec<u8>, StoredEpoch)>>,
    /// The pinned chain state (`chain`): read from the store at unlock,
    /// persisted with the device state by a `SyncStore`.
    pub(crate) chain: ChainState,
    /// Vaults parked by the Travel Mode (`enter_travel`, `resume_travel`):
    /// absent on purpose, so `vaults()` does not expect them although the
    /// vault list does. In memory only.
    pub(crate) travel_parked: BTreeSet<Id>,
    /// The lists seen in `chain` were set back on purpose since the state
    /// was last persisted (a list rebase renumbered them, or the owner took
    /// the server's lists): a merging persist keeps the in-memory ones
    /// instead of refusing a fork with the stored ones.
    pub(crate) lists_forced: bool,
}

/// A restore epoch record, verified, and the SHA-256 of its data.
#[derive(Clone)]
struct StoredEpoch {
    epoch: RestoreEpoch,
    hash: [u8; 32],
}

/// What a vault is loaded for (`Repository::served`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    Read,
    /// A write follows: the copy served must also be the visible one.
    Write,
    /// The owner keeps this device's copy (`KeepThisDevice`), even over a
    /// server manifest that forks from it.
    Keep,
}

/// A vault's verified copy rebuilt from the visible rows and the rows the
/// store kept (`RecordStore::kept_rows`).
pub(crate) struct LocalCopy {
    /// The manifest record.
    record: Record,
    loaded: Loaded,
    /// Listed records that only the kept rows still hold.
    restore: Vec<Record>,
    /// Visible item records of the vault the manifest does not list (each
    /// opens under the vault key).
    unlisted: Vec<Id>,
}

/// The verified content of a vault.
pub(crate) struct Loaded {
    pub(crate) manifest: Manifest,
    /// Records matching the manifest, sorted by item id, with their blob ids.
    records: Vec<(Id, ItemRecord)>,
    /// Records ignored on load, interrupted writes and stale leftovers:
    /// `(blob id, item id)`. Deleted when that item is written next.
    ignored: Vec<(Id, Id)>,
}

impl Loaded {
    pub(crate) fn listed(&self, item_id: Id) -> Option<&(Id, ItemRecord)> {
        self.records.iter().find(|(_, r)| r.item_id == item_id)
    }

    fn next_version(&self, item_id: Id) -> Result<u64> {
        match self.listed(item_id) {
            Some((_, r)) => r
                .version
                .checked_add(1)
                .ok_or(Error::InvalidFormat("item version")),
            None => Ok(1),
        }
    }

    fn ignored_of(&self, item_id: Id) -> impl Iterator<Item = Id> + '_ {
        self.ignored
            .iter()
            .filter(move |(_, i)| *i == item_id)
            .map(|(blob, _)| *blob)
    }

    /// The manifest entries without `item_id`.
    fn entries_without(&self, item_id: Id) -> Vec<ManifestEntry> {
        self.manifest
            .entries
            .iter()
            .filter(|e| e.item_id != item_id)
            .cloned()
            .collect()
    }
}

fn pin(account: &Account) -> PinnedAccount {
    PinnedAccount {
        account_id: account.params.account_id,
        identity_pub: account.params.identity_pub.clone(),
        kdf_floor: account.params.kdf.clone(),
    }
}

pub(crate) fn seen(m: &Manifest) -> SeenManifest {
    SeenManifest {
        seq: m.seq,
        hash: manifest_hash(m),
    }
}

fn entry(rec: &ItemRecord) -> ManifestEntry {
    ManifestEntry {
        item_id: rec.item_id,
        version: rec.version,
        record_hash: record_hash(rec),
    }
}

/// Split a stored item record into its vault id prefix and its
/// `ItemRecord` body (see the layout above). Shorter than the 16-byte
/// prefix is `InvalidFormat("item record")`. The body is not decoded.
pub fn split_item_record(data: &[u8]) -> Result<(Id, &[u8])> {
    let (prefix, body) = data
        .split_at_checked(16)
        .ok_or(Error::InvalidFormat("item record"))?;
    let mut id = [0u8; 16];
    id.copy_from_slice(prefix);
    Ok((Id(id), body))
}

/// The single account's params and keyset records (`NotFound` if there is
/// none, `InvalidFormat("account params")` if there are several).
fn account_records<S: RecordStore>(store: &S) -> Result<(Record, Record)> {
    let mut found = store.list(RecordKind::AccountParams)?;
    let params = match found.len() {
        0 => return Err(Error::NotFound),
        1 => found.remove(0),
        _ => return Err(Error::InvalidFormat("account params")),
    };
    let keyset = store
        .get(RecordKind::Keyset, params.id)?
        .ok_or(Error::NotFound)?;
    Ok((params, keyset))
}

/// Manifests re-signed by epoch `e` start at seq `e * 2^32`, above every
/// seq written before it (fewer than 2^32 writes per vault and epoch): a
/// manifest from before the epoch can never pass for a later one, even
/// across a gap that `verify_manifest` cannot chain.
const EPOCH_SEQ_STRIDE: u64 = 1 << 32;

fn epoch_floor(epoch: u64) -> Result<u64> {
    epoch
        .checked_mul(EPOCH_SEQ_STRIDE)
        .ok_or(Error::InvalidFormat("restore epoch"))
}

/// The epoch rules against the epoch this device accepted
/// (`device_epoch`, 0 for none): whether `stored` is newer and must be
/// applied. No record while the device accepted one, or an older one, is
/// `EpochRollback`.
fn newer_epoch(device_epoch: u64, stored: Option<&RestoreEpoch>) -> Result<bool> {
    match stored {
        None if device_epoch == 0 => Ok(false),
        None => Err(IntegrityError::EpochRollback.into()),
        Some(e) if e.epoch > device_epoch => Ok(true),
        Some(e) if e.epoch == device_epoch => Ok(false),
        Some(_) => Err(IntegrityError::EpochRollback.into()),
    }
}

fn personal() -> VaultMeta {
    VaultMeta {
        name: "Personnel".into(),
        icon: "person".into(),
        color: "blue".into(),
        travel_safe: false,
        mcp_access: false,
    }
}

impl<S: RecordStore> Repository<S> {
    /// Create an account in an empty store, in one write
    /// (`RecordStore::put_all_if_version_with_chain`, with the chain state
    /// where the store keeps one): params, keyset, the device list with this
    /// device (named `devices::DEFAULT_DEVICE_NAME` until
    /// `register_this_device`; empty on a store that does not persist the
    /// chain state, see `devices`), the vault list, and the "Personnel"
    /// vault.
    /// The device pins the new account.
    pub fn create_account(
        store: S,
        password: &str,
        kdf: KdfParams,
    ) -> Result<(Repository<S>, SecretKey)> {
        if !store.list(RecordKind::AccountParams)?.is_empty() {
            return Err(Error::InvalidFormat("store already holds an account"));
        }
        let NewAccount {
            account,
            secret_key,
            params_record,
            keyset_record,
        } = Account::create_with_params(password, kdf)?;
        let id = account.params.account_id;
        // Only a store that keeps the chain state can hold this device's id
        // (see `devices`): elsewhere the device list starts empty.
        let device_id = store.persists_chain().then(Id::new);
        let at = now();
        let (vault, envelope, meta_blob) = Vault::create(&account, personal())?;
        let device = DeviceState {
            pinned: Some(pin(&account)),
            last_seen: BTreeMap::new(),
            epoch: 0,
        };
        let chain = ChainState {
            params_epoch: account.params.epoch,
            device_id,
            ..ChainState::default()
        };
        let mut repo = Repository {
            store,
            account,
            device,
            dropped: BTreeSet::new(),
            epoch_rewound: false,
            epoch_cache: Mutex::new(None),
            chain,
            travel_parked: BTreeSet::new(),
            lists_forced: false,
        };
        let (manifest, seen) = repo.manifest_record(&vault, None, vec![])?;
        let me = device_id.map(|d| self_entry(d, None, at));
        let devices = ListBody::next(None, id, me.into_iter().collect())?;
        let vaults = ListBody::next(
            None,
            id,
            vec![VaultListEntry {
                vault_id: vault.id,
                created_at: at,
                deleted_at: None,
            }],
        )?;
        repo.chain.device_list = Some(devices.seen());
        repo.chain.vault_list = Some(vaults.seen());
        let record = |kind, id, data| Record {
            id,
            kind,
            version: 1,
            data,
        };
        let writes = vec![
            record(RecordKind::AccountParams, id, params_record),
            record(RecordKind::Keyset, id, keyset_record),
            list_record::<DeviceEntry>(&repo.account, devices)?,
            list_record::<VaultListEntry>(&repo.account, vaults)?,
            manifest,
            record(RecordKind::VaultMeta, vault.id, meta_blob),
            record(RecordKind::VaultKey, vault.id, envelope),
        ];
        let writes = writes.into_iter().map(|r| (r, None)).collect();
        repo.store
            .put_all_if_version_with_chain(writes, &repo.chain)?;
        repo.device.last_seen.insert(vault.id, seen);
        Ok((repo, secret_key))
    }

    /// Unlock the single account of the store (`NotFound` if there is none,
    /// `InvalidFormat("account params")` if there are several). On a device
    /// that pinned nothing yet, the account is pinned now (trust on first
    /// use); otherwise `Account::unlock` checks it against the pin, and the
    /// pinned KDF floor is raised to the parameters just accepted.
    ///
    /// The params epoch is checked against the store's chain state
    /// (`RecordStore::chain_state`): an older epoch is
    /// `IntegrityError::ParamsRollback`, before any derivation. The epoch
    /// accepted is pinned (it only goes up).
    pub fn unlock(
        store: S,
        password: &str,
        secret_key: &SecretKey,
        device: DeviceState,
    ) -> Result<Repository<S>> {
        Ok(Self::unlock_exporting_auk(store, password, secret_key, device)?.0)
    }

    /// Like `unlock`, and also hand back the Account Unlock Key.
    pub fn unlock_exporting_auk(
        store: S,
        password: &str,
        secret_key: &SecretKey,
        device: DeviceState,
    ) -> Result<(Repository<S>, Auk)> {
        let (params, keyset) = account_records(&store)?;
        let chain = store.chain_state()?;
        let (account, auk) = Account::unlock_exporting_auk_at(
            password,
            secret_key,
            &params.data,
            &keyset.data,
            device.pinned.as_ref(),
            chain.params_epoch,
        )?;
        Ok((
            Self::finish_unlock(store, account, &params, device, chain)?,
            auk,
        ))
    }

    /// Like `unlock`, from an Account Unlock Key kept from an earlier one.
    pub fn unlock_with_auk(store: S, auk: &Auk, device: DeviceState) -> Result<Repository<S>> {
        let (params, keyset) = account_records(&store)?;
        let chain = store.chain_state()?;
        let account = Account::unlock_with_auk_at(
            auk,
            &params.data,
            &keyset.data,
            device.pinned.as_ref(),
            chain.params_epoch,
        )?;
        Self::finish_unlock(store, account, &params, device, chain)
    }

    fn finish_unlock(
        store: S,
        account: Account,
        params: &Record,
        mut device: DeviceState,
        mut chain: ChainState,
    ) -> Result<Repository<S>> {
        if account.params.account_id != params.id {
            return Err(IntegrityError::WrongContext.into());
        }
        match &mut device.pinned {
            None => device.pinned = Some(pin(&account)),
            Some(p) => p.raise_floor(&account.params.kdf),
        }
        chain.accept_params_epoch(account.params.epoch);
        Ok(Repository {
            store,
            account,
            device,
            dropped: BTreeSet::new(),
            epoch_rewound: false,
            epoch_cache: Mutex::new(None),
            chain,
            travel_parked: BTreeSet::new(),
            lists_forced: false,
        })
    }

    /// Change the master password (spec 2b, 3.3). The current password and
    /// the Secret Key are checked by opening the stored params and keyset
    /// with every unlock check (pin, pinned epoch, floors): a wrong one is
    /// `Error::WrongPassword` and nothing is written. Then the same keys get
    /// v2 params at the stored epoch plus one (fresh salt, costs at least the
    /// current ones and the floor) and a keyset resealed at that epoch under
    /// the new Account Unlock Key, which is returned (to enroll biometrics
    /// again).
    ///
    /// The keyset and the params are written together
    /// (`RecordStore::put_all_if_version`, one transaction in a persistent
    /// store), each conditional on the version just read: a lost race is
    /// `Error::Conflict`, and on any error the previous pair stays as it
    /// was. Then the new epoch is pinned and the session goes on with the
    /// new params (same keys: vault keys, manifests and pending writes of
    /// other devices stay valid). With a `SyncStore` the chain state is
    /// saved by the next `persist_device_state`, which the caller runs right
    /// after.
    pub fn change_password(
        &mut self,
        current: &str,
        secret_key: &SecretKey,
        new: &str,
    ) -> Result<Auk> {
        let (params, keyset) = account_records(&self.store)?;
        if params.id != self.account.params.account_id {
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
        let Rekeyed {
            account,
            auk,
            params_record,
            keyset_record,
        } = stored.rekey(secret_key, new)?;
        let id = params.id;
        let next = |r: &Record| r.version.checked_add(1).ok_or(Error::Conflict);
        // Both records in one atomic write: a conflict, a store failure or
        // a crash leaves the previous pair as it was.
        self.store.put_all_if_version(vec![
            (
                Record {
                    id,
                    kind: RecordKind::Keyset,
                    version: next(&keyset)?,
                    data: keyset_record,
                },
                Some(keyset.version),
            ),
            (
                Record {
                    id,
                    kind: RecordKind::AccountParams,
                    version: next(&params)?,
                    data: params_record,
                },
                Some(params.version),
            ),
        ])?;
        if let Some(p) = &mut self.device.pinned {
            p.raise_floor(&account.params.kdf);
        }
        self.chain.accept_params_epoch(account.params.epoch);
        self.account = account;
        Ok(auk)
    }

    /// The pinned chain state, to persist with the device state.
    pub fn chain(&self) -> &ChainState {
        &self.chain
    }

    /// The underlying record store, for the sync layer.
    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// The state to persist on the device after each session.
    pub fn device_state(&self) -> &DeviceState {
        &self.device
    }

    /// The unlocked account keys, to sign and wrap backups.
    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Every vault of the account, sorted by id. A vault is returned only
    /// when its key envelope opens, its meta opens under that key, and its
    /// signed manifest verifies under the account signing key and opens
    /// with that key: the envelope itself is not authenticated (anyone can
    /// wrap a key to the account's public KEM key), the manifest signature
    /// is what authenticates the vault key. History against the last
    /// manifest seen is checked by `items` and the writes, not here.
    ///
    /// Errors: a key envelope without its meta record is
    /// `InvalidFormat("vault meta")`; a vault without a manifest is
    /// `ManifestMissingItem`; a vault this device already read
    /// (`DeviceState::last_seen`) whose key record is gone is
    /// `VaultMissing`.
    ///
    /// The signed vault list (`vaultlist`), when there is one, is verified
    /// against the one last accepted (`VaultListRollback`), and every live
    /// vault it lists must be present, even one this device never read
    /// (`VaultMissing`). A vault it marks deleted is neither expected nor
    /// returned. A valid vault it does not list is returned (adopted into
    /// the list later). No list yet (an account from before the list) means
    /// no list check. A vault parked by the Travel Mode (`enter_travel`, or
    /// `resume_travel` in a later session) is not expected either: a
    /// session that forgets `resume_travel` gets `VaultMissing`.
    ///
    /// The restore epoch is checked first (`sync_epoch`), without being
    /// applied (this takes `&self`): a newer epoch's heads stand for the
    /// vaults already read; its errors come before any vault's. A head of a
    /// vault the vault list marks deleted is not expected either: the
    /// deletion wins over an epoch that still named the vault (issued
    /// before it reached the issuing device).
    pub fn vaults(&self) -> Result<Vec<Vault>> {
        let stored = self.stored_epoch()?;
        let newer = self.epoch_rule(stored.as_ref())?;
        let known = match &stored {
            Some(s) if newer => &s.epoch.heads,
            _ => &self.device.last_seen,
        };
        let list = self.read_list::<VaultListEntry>()?;
        let entries: &[VaultListEntry] = list.as_ref().map_or(&[], |l| &l.body.entries);
        let out = self.open_listed_vaults(entries)?;
        let expected = known.keys().copied().chain(
            entries
                .iter()
                .filter(|e| e.deleted_at.is_none())
                .map(|e| e.vault_id),
        );
        for id in expected {
            let parked = self.travel_parked.contains(&id);
            if !listed_deleted(entries, id) && !parked && !out.iter().any(|v| v.id == id) {
                return Err(IntegrityError::VaultMissing.into());
            }
        }
        Ok(out)
    }

    /// Every vault whose key, meta and manifest open (see `vaults`), sorted
    /// by id, without the epoch and `VaultMissing` checks. The vault list is
    /// still verified, and the vaults it marks deleted are left out.
    pub(crate) fn open_vaults(&self) -> Result<Vec<Vault>> {
        let list = self.read_list::<VaultListEntry>()?;
        self.open_listed_vaults(list.as_ref().map_or(&[], |l| &l.body.entries))
    }

    /// `open_vaults` over the vault list `entries`, already verified.
    fn open_listed_vaults(&self, entries: &[VaultListEntry]) -> Result<Vec<Vault>> {
        let mut out = Vec::new();
        for key in self.store.list(RecordKind::VaultKey)? {
            if listed_deleted(entries, key.id) {
                continue;
            }
            let meta = self
                .store
                .get(RecordKind::VaultMeta, key.id)?
                .ok_or(Error::InvalidFormat("vault meta"))?;
            let vault = Vault::open(&self.account, key.id, &key.data, &meta.data)?;
            self.read_manifest(&vault, None)?;
            out.push(vault);
        }
        out.sort_by_key(|v| v.id);
        Ok(out)
    }

    /// The epoch this device accepted last, `None` before any.
    pub fn restore_epoch(&self) -> Option<u64> {
        (self.device.epoch > 0).then_some(self.device.epoch)
    }

    /// The account's restore epoch record, decoded and verified under the
    /// pinned account's signing key, or `None` if there is none. A record
    /// whose version is not its epoch is `EpochRollback`. The verification
    /// of the same record (version and data) is cached.
    fn stored_epoch(&self) -> Result<Option<StoredEpoch>> {
        let id = self.account.params.account_id;
        let Some(rec) = self.store.get(RecordKind::RestoreEpoch, id)? else {
            return Ok(None);
        };
        let mut cache = self
            .epoch_cache
            .lock()
            .map_err(|_| Error::Store("epoch cache".into()))?;
        if let Some((version, data, stored)) = cache.as_ref()
            && *version == rec.version
            && *data == rec.data
        {
            return Ok(Some(stored.clone()));
        }
        let signed = SignedRestoreEpoch::decode(&rec.data)?;
        let epoch = signed.verify(id, &self.account.params.signing_pub)?;
        if rec.version != epoch.epoch {
            return Err(IntegrityError::EpochRollback.into());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest(&SHA256, &rec.data).as_ref());
        let stored = StoredEpoch {
            epoch: signed.epoch,
            hash,
        };
        *cache = Some((rec.version, rec.data, stored.clone()));
        Ok(Some(stored))
    }

    /// `newer_epoch`, plus the fork check: a record with the very epoch
    /// this device accepted, but not the record it accepted (its hash,
    /// kept by the store as `restore_epoch_mark`), is `EpochRollback`.
    /// Stores that keep no mark skip that check.
    fn epoch_rule(&self, stored: Option<&StoredEpoch>) -> Result<bool> {
        let newer = newer_epoch(self.device.epoch, stored.map(|s| &s.epoch))?;
        if let Some(s) = stored
            && !newer
            && let Some((epoch, hash)) = self.store.restore_epoch_mark()?
            && epoch == s.epoch.epoch
            && hash != s.hash
        {
            return Err(IntegrityError::EpochRollback.into());
        }
        Ok(newer)
    }

    /// The restore epoch rules, the one place they are applied (before
    /// `items`, every write and the rebase; `vaults` checks them without
    /// applying):
    /// 1. no record and no epoch accepted: nothing changes;
    /// 2. a valid record newer than the epoch accepted: `last_seen` is
    ///    replaced by its heads (vaults outside them are forgotten) and its
    ///    epoch is accepted; the usual checks follow;
    /// 3. the same epoch: nothing changes, unless it is another record
    ///    than the one accepted (a fork, see `epoch_rule`);
    /// 4. an older epoch, or none while one was accepted, is
    ///    `EpochRollback`; a bad signature `Signature`; another account
    ///    `EpochRollback`; an undecodable record `InvalidFormat`.
    ///
    /// The record accepted is remembered by the store
    /// (`set_restore_epoch_mark`). Returns the stored epoch, verified.
    pub(crate) fn sync_epoch(&mut self) -> Result<Option<RestoreEpoch>> {
        let stored = self.stored_epoch()?;
        let newer = self.epoch_rule(stored.as_ref())?;
        let Some(s) = stored else {
            return Ok(None);
        };
        if newer {
            self.replace_last_seen(s.epoch.heads.clone());
            // A head of a vault the vault list marks deleted is not
            // remembered: the deletion wins (see `vaults`).
            self.forget_deleted_vaults();
            self.device.epoch = s.epoch.epoch;
            for vault in s.epoch.heads.keys() {
                self.store.vault_event(*vault, VaultEvent::EpochAccepted)?;
            }
        }
        if self.store.restore_epoch_mark()? != Some((s.epoch.epoch, s.hash)) {
            self.store.set_restore_epoch_mark(s.epoch.epoch, s.hash)?;
        }
        Ok(Some(s.epoch))
    }

    /// Mark that the account was deliberately set back (a restore, or a
    /// choice after an alert), so that the other devices accept its current
    /// state instead of reporting a rollback.
    ///
    /// The epoch is `max(epoch accepted, epoch stored) + 1`. Every vault is
    /// loaded and checked like `items`, then its manifest is signed again,
    /// same entries, at `seq = max(seq + 1, epoch * 2^32)`: no manifest
    /// from before the epoch can follow it. Those manifests are the heads.
    /// The signed epoch record is written last, conditionally on the stored
    /// one (`put_if_version`): another device's epoch written meanwhile is
    /// `Error::Conflict` (sync, then retry). The device then accepts the
    /// epoch and its heads.
    ///
    /// Strict: the stored epoch and every vault must pass the usual checks.
    /// Over a sync store, an epoch whose heads cannot all reach the server
    /// (a vault held for rebase) is dropped by the rebase with
    /// `Error::Conflict`, to be issued again; see also
    /// `issue_restore_epoch_from_local`.
    ///
    /// Errors: those of `sync_epoch`, `vaults`, the loads and the writes.
    /// The manifests already re-signed when a later step fails are valid
    /// successors and stay.
    pub fn issue_restore_epoch(&mut self, reason: EpochReason) -> Result<RestoreEpoch> {
        let stored = self.sync_epoch()?.map(|e| e.epoch);
        let vaults = self.vaults()?;
        self.issue_epoch(reason, stored, vaults, false)
    }

    /// The epoch number stored, its signature verified, without the epoch
    /// rules (`sync_epoch`): for the owner's explicit choice of the
    /// server's state (`issue_restore_epoch_take_server`).
    pub(crate) fn stored_epoch_number(&self) -> Result<Option<u64>> {
        Ok(self.stored_epoch()?.map(|s| s.epoch.epoch))
    }

    /// `issue_restore_epoch` over `vaults`, `stored` being the epoch the
    /// record holds now. `local`: each head is the copy this device serves
    /// (`served` with `Use::Keep`) instead of the strictly loaded one.
    pub(crate) fn issue_epoch(
        &mut self,
        reason: EpochReason,
        stored: Option<u64>,
        vaults: Vec<Vault>,
        local: bool,
    ) -> Result<RestoreEpoch> {
        let epoch = self
            .device
            .epoch
            .max(stored.unwrap_or(0))
            .checked_add(1)
            .ok_or(Error::InvalidFormat("restore epoch"))?;
        let floor = epoch_floor(epoch)?;
        let mut heads = BTreeMap::new();
        for vault in vaults {
            let loaded = if local {
                self.served(&vault, Use::Keep)?
            } else {
                self.load(&vault)?
            };
            for (_, r) in &loaded.records {
                vault.open_item(r)?;
            }
            let prev = &loaded.manifest;
            let mut m = Manifest::next(Some(prev), vault.id, prev.entries.clone())?;
            m.seq = m.seq.max(floor);
            let head = self.store_manifest(&vault, &m, Some(prev.seq))?;
            self.device.last_seen.insert(vault.id, head.clone());
            heads.insert(vault.id, head);
        }
        let account_id = self.account.params.account_id;
        let issued = RestoreEpoch {
            account_id,
            epoch,
            issued_at: OffsetDateTime::now_utc().unix_timestamp(),
            heads,
            reason,
        };
        let data =
            SignedRestoreEpoch::sign(issued.clone(), &self.account.keyset().signing)?.encode();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest(&SHA256, &data).as_ref());
        self.store.put_if_version(
            Record {
                id: account_id,
                kind: RecordKind::RestoreEpoch,
                version: epoch,
                data,
            },
            stored,
        )?;
        self.device.epoch = epoch;
        self.replace_last_seen(issued.heads.clone());
        self.store.set_restore_epoch_mark(epoch, hash)?;
        Ok(issued)
    }

    /// Replace `last_seen` wholesale (an epoch's heads). Every vault of the
    /// old or the new map joins `dropped`, so that a merging persist takes
    /// the new map as is: a vault outside the heads stays forgotten, and no
    /// stored entry from before the epoch comes back.
    pub(crate) fn replace_last_seen(&mut self, heads: BTreeMap<Id, SeenManifest>) {
        self.dropped.extend(self.device.last_seen.keys().copied());
        self.dropped.extend(heads.keys().copied());
        self.device.last_seen = heads;
    }

    /// Create a vault with an empty signed manifest (seq 1), so that a
    /// vault without a manifest is always a storage fault. Manifest, meta,
    /// key envelope and, when the account has a vault list, the next list
    /// with the new vault go in one write
    /// (`RecordStore::put_all_if_version`, the key after the manifest and
    /// meta); the device remembers the manifest once it is written. On an
    /// account without a vault list (from before it), the lists are first
    /// brought up to date (`devices`, migration), so the new vault is
    /// listed too; if the vaults do not verify, no list is created and the
    /// vault waits for adoption. A list changed by
    /// another writer meanwhile is `Error::Conflict`, and nothing is written.
    pub fn create_vault(&mut self, meta: VaultMeta) -> Result<Vault> {
        self.sync_epoch()?;
        if self.read_list::<VaultListEntry>()?.is_none() {
            // An account from before the lists: migrate on this first write.
            self.maintain_lists(None)?;
        }
        let list = self.read_list::<VaultListEntry>()?;
        let (vault, envelope, meta_blob) = Vault::create(&self.account, meta)?;
        let (manifest, seen) = self.manifest_record(&vault, None, vec![])?;
        let mut writes = vec![(manifest, None)];
        for (kind, data) in [
            (RecordKind::VaultMeta, meta_blob),
            (RecordKind::VaultKey, envelope),
        ] {
            let r = Record {
                id: vault.id,
                kind,
                version: 1,
                data,
            };
            writes.push((r, None));
        }
        let mut list_body = None;
        if let Some(list) = &list {
            let mut entries = list.body.entries.clone();
            entries.push(VaultListEntry {
                vault_id: vault.id,
                created_at: now(),
                deleted_at: None,
            });
            let (rec, expected, body) = self.list_write(Some(list), entries)?;
            writes.push((rec, expected));
            list_body = Some(body);
        }
        self.store.put_all_if_version(writes)?;
        if let Some(body) = list_body {
            self.chain.vault_list = Some(body.seen());
        }
        self.device.last_seen.insert(vault.id, seen);
        Ok(vault)
    }

    /// Delete a vault (spec 4.5, ruling B8). Refused while it holds a live
    /// or archived item (`InvalidFormat("vault not empty")`: the user
    /// empties it first), and for the last live vault of the account
    /// (`InvalidFormat("last vault")`). A vault that is not among `vaults()`
    /// (already deleted, or never there) is `NotFound`; `vaults()` and the
    /// verified load of the vault report their own faults first.
    ///
    /// Otherwise, in one write (`RecordStore::put_all_if_version_and_delete`):
    /// the next vault list with the vault marked deleted, then the deletion
    /// of its key, meta and manifest and of every item record of the vault
    /// (the trashed items are purged with it, ignored leftovers too). The
    /// list goes first: on a store where the write is not atomic, a cut
    /// leaves rows of a vault the list marks deleted, which `vaults()` no
    /// longer returns or expects. The vault leaves `last_seen`. A list
    /// changed by another writer meanwhile is `Error::Conflict`, and nothing
    /// is written. On an account without a vault list (from before it), the
    /// lists are first brought up to date.
    pub fn delete_vault(&mut self, vault: &Vault) -> Result<()> {
        if self.read_list::<VaultListEntry>()?.is_none() {
            self.maintain_lists(None)?;
        }
        if !self.vaults()?.iter().any(|v| v.id == vault.id) {
            return Err(Error::NotFound);
        }
        let list = self.read_list::<VaultListEntry>()?.ok_or(Error::NotFound)?;
        let others_live = list
            .body
            .entries
            .iter()
            .any(|e| e.vault_id != vault.id && e.deleted_at.is_none());
        if !others_live {
            return Err(Error::InvalidFormat("last vault"));
        }
        let loaded = self.load(vault)?;
        for (_, rec) in &loaded.records {
            if vault.open_item(rec)?.trashed_at.is_none() {
                return Err(Error::InvalidFormat("vault not empty"));
            }
        }

        let at = now();
        let mut entries = list.body.entries.clone();
        match entries.iter_mut().find(|e| e.vault_id == vault.id) {
            Some(e) => e.deleted_at = Some(at),
            None => entries.push(VaultListEntry {
                vault_id: vault.id,
                created_at: at,
                deleted_at: Some(at),
            }),
        }
        let (rec, expected, body) = self.list_write(Some(&list), entries)?;
        let mut deletes: Vec<(RecordKind, Id)> = [
            RecordKind::VaultKey,
            RecordKind::VaultMeta,
            RecordKind::Manifest,
        ]
        .into_iter()
        .map(|kind| (kind, vault.id))
        .collect();
        for r in self.store.list(RecordKind::Item)? {
            if split_item_record(&r.data).is_ok_and(|(prefix, _)| prefix == vault.id) {
                deletes.push((RecordKind::Item, r.id));
            }
        }
        self.store
            .put_all_if_version_and_delete(vec![(rec, expected)], deletes)?;
        self.chain.vault_list = Some(body.seen());
        self.forget_vault(vault.id);
        Ok(())
    }

    /// Forget the last manifest seen of every vault the signed vault list
    /// marks deleted: a vault deleted (here or elsewhere) is no longer
    /// remembered. Best effort: a list that does not verify changes nothing
    /// here, `vaults()` reports it.
    pub(crate) fn forget_deleted_vaults(&mut self) {
        if let Ok(Some(list)) = self.read_list::<VaultListEntry>() {
            for e in list.body.entries.iter().filter(|e| e.deleted_at.is_some()) {
                self.forget_vault(e.vault_id);
            }
        }
    }

    /// Remove `vault` from `last_seen` on purpose: it joins `dropped`, so
    /// that a merging persist does not take the stored entry back (a
    /// deleted vault stays forgotten, even if another process on the file
    /// still remembers it).
    pub(crate) fn forget_vault(&mut self, vault: Id) {
        self.device.last_seen.remove(&vault);
        self.dropped.insert(vault);
    }

    /// Replace the display settings of a vault (name, icon, color, flags).
    /// `vault` is the state the caller read: if the stored meta is no longer
    /// the same, another writer got there first and the result is
    /// `Error::Conflict`. The write itself is conditional on the version of
    /// the stored `VaultMeta` record, so two racing updates cannot both win.
    pub fn update_vault_meta(&mut self, vault: &Vault, meta: VaultMeta) -> Result<Vault> {
        self.sync_epoch()?;
        let key = self
            .store
            .get(RecordKind::VaultKey, vault.id)?
            .ok_or(Error::NotFound)?;
        let current = self
            .store
            .get(RecordKind::VaultMeta, vault.id)?
            .ok_or(Error::InvalidFormat("vault meta"))?;
        let stored = Vault::open(&self.account, vault.id, &key.data, &current.data)?;
        if stored.meta != vault.meta {
            return Err(Error::Conflict);
        }
        let plain = Zeroizing::new(
            postcard::to_allocvec(&meta).map_err(|_| Error::InvalidFormat("vault meta"))?,
        );
        // Same context as `Vault::create`: blob id and vault id are the
        // vault id, schema 1. Reopening below proves they agree.
        let aad = Aad {
            blob_id: vault.id,
            vault_id: Some(vault.id),
            schema: 1,
        };
        let blob = seal(vault.key(), BlobKind::VaultMeta, &aad, &plain)?;
        let updated = Vault::open(&self.account, vault.id, &key.data, &blob)?;
        let version = current.version.checked_add(1).ok_or(Error::Conflict)?;
        self.store.put_if_version(
            Record {
                id: vault.id,
                kind: RecordKind::VaultMeta,
                version,
                data: blob,
            },
            Some(current.version),
        )?;
        Ok(updated)
    }

    /// The items of a vault, sorted by id, after verifying the manifest
    /// against the last one seen and the records against the manifest. The
    /// manifest is then remembered as the last one seen.
    pub fn items(&mut self, vault: &Vault) -> Result<Vec<Item>> {
        self.sync_epoch()?;
        let loaded = self.served(vault, Use::Read)?;
        let items = loaded
            .records
            .iter()
            .map(|(_, r)| vault.open_item(r))
            .collect::<Result<Vec<_>>>()?;
        self.device
            .last_seen
            .insert(vault.id, seen(&loaded.manifest));
        Ok(items)
    }

    /// Store a new version of the item (or its first one), then the
    /// manifest that lists it, then delete the previous record and the
    /// ignored leftovers of this item. Nothing is deleted before the
    /// manifest write succeeds: an ignored record may be another writer's
    /// write in flight. A lost race (`Conflict`) deletes only the record
    /// this call wrote.
    pub fn save_item(&mut self, vault: &Vault, item: Item) -> Result<()> {
        self.sync_epoch()?;
        let loaded = self.served(vault, Use::Write)?;
        let rec = vault.seal_item(&item, loaded.next_version(item.id)?)?;
        let old = loaded.listed(item.id).map(|(blob, _)| *blob);
        let written = self.put_item(vault.id, &rec)?;
        let mut entries = loaded.entries_without(item.id);
        entries.push(entry(&rec));
        self.commit_manifest(vault, &loaded.manifest, entries, Some(written))?;
        self.delete_ignored(&loaded, item.id)?;
        if let Some(blob) = old {
            self.store.delete(RecordKind::Item, blob)?;
        }
        Ok(())
    }

    /// Remember a fill of `u.site` by this item (`Item::note_usage`). The
    /// item is saved only when the memory changed enough to be worth a
    /// write (`true`), with its `updated_at` unchanged: a usage write never
    /// beats a real edit from another device. The write is forced when
    /// `force` (the caller saw another item, maybe in another vault, use
    /// the site later) or when another live item of this vault used the
    /// site after this item's entry, so this item becomes the last used
    /// there again (A, B, then A within the hour). Archived, trashed and
    /// unreadable items are skipped for that check.
    pub fn record_usage(
        &mut self,
        vault: &Vault,
        item_id: Id,
        u: SiteUsage,
        now: OffsetDateTime,
        force: bool,
    ) -> Result<bool> {
        self.sync_epoch()?;
        let loaded = self.served(vault, Use::Write)?;
        let (_, rec) = loaded.listed(item_id).ok_or(Error::NotFound)?;
        let mut item = vault.open_item(rec)?;
        let force = force
            || item.site_last_at(&u.site).is_some_and(|own| {
                loaded
                    .records
                    .iter()
                    .filter(|(_, r)| r.item_id != item_id)
                    .filter_map(|(_, r)| vault.open_item(r).ok())
                    .filter(|other| !other.archived && other.trashed_at.is_none())
                    .filter_map(|other| other.site_last_at(&u.site))
                    .any(|at| at > own)
            });
        if !item.note_usage_with(u, now, force) {
            return Ok(false);
        }
        self.save_item(vault, item)?;
        Ok(true)
    }

    /// Forget `site` in every item of every vault this device opens (spec
    /// 7, erase by site), leaving a tombstone in each so other devices'
    /// copies do not bring it back. The vaults come from `vaults` (epoch and
    /// `VaultMissing` checks: an alert there fails the whole call, nothing
    /// written). Then best effort, vault by vault and item by item: a vault
    /// that cannot be read or an item that cannot be written (an alert, a
    /// lost race) does not stop the others, but the call still returns the
    /// first such error once every vault was tried, so a caller never shows
    /// a partial forget as done. Returns how many items were rewritten, each
    /// with its `updated_at` unchanged.
    pub fn forget_site_usage(&mut self, site: &str) -> Result<usize> {
        self.forget_site_usage_in(site, |_| true)
    }

    /// `forget_site_usage` over the vaults `keep` accepts only (an app
    /// leaves out the vaults it hides from the extension).
    pub fn forget_site_usage_in(
        &mut self,
        site: &str,
        keep: impl Fn(&Vault) -> bool,
    ) -> Result<usize> {
        let now = OffsetDateTime::now_utc();
        let mut rewritten = 0;
        let mut first_err: Option<Error> = None;
        for vault in self.vaults()?.into_iter().filter(|v| keep(v)) {
            let items = match self.items(&vault) {
                Ok(items) => items,
                Err(e) => {
                    first_err.get_or_insert(e);
                    continue;
                }
            };
            for mut item in items {
                if item.forget_site_usage(site, now) {
                    match self.save_item(&vault, item) {
                        Ok(()) => rewritten += 1,
                        Err(e) => {
                            first_err.get_or_insert(e);
                        }
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(rewritten),
        }
    }

    /// Remove an item for good: manifest without it first, then its record
    /// and its ignored leftovers.
    pub fn delete_item(&mut self, vault: &Vault, item_id: Id) -> Result<()> {
        self.sync_epoch()?;
        let loaded = self.served(vault, Use::Write)?;
        let (blob, _) = *loaded.listed(item_id).ok_or(Error::NotFound)?;
        let entries = loaded.entries_without(item_id);
        self.commit_manifest(vault, &loaded.manifest, entries, None)?;
        self.delete_ignored(&loaded, item_id)?;
        self.store.delete(RecordKind::Item, blob)
    }

    /// Put the item in the trash: a new version with `trashed_at` set.
    pub fn trash_item(&mut self, vault: &Vault, item_id: Id) -> Result<()> {
        self.update(vault, item_id, |item, now| {
            item.trashed_at = Some(now);
            item.record(now, EventKind::Trashed);
        })
    }

    /// Archive the item: a new version with `archived` set.
    pub fn archive_item(&mut self, vault: &Vault, item_id: Id) -> Result<()> {
        self.update(vault, item_id, |item, now| {
            if !item.archived {
                item.record(now, EventKind::Archived);
            }
            item.archived = true;
        })
    }

    /// Move an item to another vault: the record re-sealed for `to`
    /// (version 1 there, or the next one if `to` already lists it), the
    /// manifest of `to`, the manifest of `from`, then the old records. A
    /// crash or a lost race (`Conflict`) between the two manifests leaves
    /// the item in both vaults, both loadable; moving it again replaces the
    /// copy in `to` and heals it. A lost race on the manifest of `to`
    /// deletes the moved record and changes nothing.
    pub fn move_item(&mut self, item_id: Id, from: &Vault, to: &Vault) -> Result<()> {
        if from.id == to.id {
            return Err(Error::InvalidFormat("move to the same vault"));
        }
        self.sync_epoch()?;
        let src = self.served(from, Use::Write)?;
        let (blob, rec) = src.listed(item_id).ok_or(Error::NotFound)?.clone();
        let dst = self.served(to, Use::Write)?;
        let moved = from.move_item(to, &rec, dst.next_version(item_id)?)?;
        let replaced = dst.listed(item_id).map(|(b, _)| *b);
        let written = self.put_item(to.id, &moved)?;
        let mut entries = dst.entries_without(item_id);
        entries.push(entry(&moved));
        self.commit_manifest(to, &dst.manifest, entries, Some(written))?;
        self.delete_ignored(&dst, item_id)?;
        let entries = src.entries_without(item_id);
        self.commit_manifest(from, &src.manifest, entries, None)?;
        self.delete_ignored(&src, item_id)?;
        self.store.delete(RecordKind::Item, blob)?;
        if let Some(b) = replaced {
            self.store.delete(RecordKind::Item, b)?;
        }
        Ok(())
    }

    /// Open the listed item, apply `change` with the current time, bump
    /// `updated_at` and save it as a new version.
    fn update(
        &mut self,
        vault: &Vault,
        item_id: Id,
        change: impl FnOnce(&mut Item, OffsetDateTime),
    ) -> Result<()> {
        self.sync_epoch()?;
        let loaded = self.served(vault, Use::Write)?;
        let (_, rec) = loaded.listed(item_id).ok_or(Error::NotFound)?;
        let mut item = vault.open_item(rec)?;
        let now = OffsetDateTime::now_utc();
        change(&mut item, now);
        item.updated_at = now;
        self.save_item(vault, item)
    }

    /// The vault as this device serves it (`items` and the writes).
    ///
    /// The visible state (`load`) first. If it fails a check and the store
    /// keeps the device's copy (`RecordStore::kept_rows`), the copy last
    /// verified is served instead, when it still verifies against the last
    /// manifest seen (`verify_manifest`) and every record it lists is
    /// there: the server went back to an older state or serves an
    /// incomplete one (`VaultEvent::Behind`, see
    /// `crate::sync::VaultSyncHealth`). The store then makes that copy the
    /// visible one again for a write, or when the server is behind it (so
    /// that the next push restores the server's copy).
    ///
    /// A visible manifest that forks from the copy (same seq, other hash,
    /// or the next seq not built on it) is an alert: the copy is still
    /// served for reading (the owner can export it), never written over the
    /// fork (`ManifestRollback`), except to keep it (`Use::Keep`). No
    /// verified copy (a vault this device never read, or a copy that fails
    /// too) is an alert and the visible state's error.
    pub(crate) fn served(&mut self, vault: &Vault, use_: Use) -> Result<Loaded> {
        let cause = match self.load(vault) {
            Ok(loaded) => {
                self.store.vault_event(vault.id, VaultEvent::Clean)?;
                return Ok(loaded);
            }
            Err(Error::Integrity(e)) => e,
            Err(e) => return Err(e),
        };
        let Some(kept) = self.store.kept_rows(vault.id)? else {
            return Err(cause.into());
        };
        let copy = match self.local_copy(vault, &kept) {
            Ok(copy) => copy,
            Err(Error::Integrity(_)) => {
                let alert = VaultEvent::Alert { seq: 0, cause };
                self.store.vault_event(vault.id, alert)?;
                return Err(cause.into());
            }
            Err(e) => return Err(e),
        };
        let seq = copy.loaded.manifest.seq;
        if self.forks_from(vault, &copy)? {
            let cause = IntegrityError::ManifestRollback;
            self.store
                .vault_event(vault.id, VaultEvent::Alert { seq, cause })?;
            match use_ {
                Use::Read => return Ok(copy.loaded),
                Use::Write => return Err(cause.into()),
                Use::Keep => {}
            }
        } else {
            self.store
                .vault_event(vault.id, VaultEvent::Behind { seq, cause })?;
        }
        self.store.keep_local_copy(
            vault.id,
            &copy.record,
            &copy.restore,
            &copy.unlisted,
            use_ != Use::Read,
        )?;
        Ok(copy.loaded)
    }

    /// The device's verified copy of the vault: the newest manifest among
    /// the visible one and the kept one that verifies against the last
    /// manifest seen and finds every record it lists (visible rows first,
    /// then kept ones). Another visible record of the vault must open under
    /// the vault key (`ManifestUnexpectedItem` otherwise). No last manifest
    /// seen: no copy (`ManifestRollback`).
    pub(crate) fn local_copy(&self, vault: &Vault, kept: &[Record]) -> Result<LocalCopy> {
        let last = self
            .device
            .last_seen
            .get(&vault.id)
            .ok_or(IntegrityError::ManifestRollback)?;
        let of_vault = |r: &Record| {
            split_item_record(&r.data)
                .ok()
                .filter(|(prefix, _)| *prefix == vault.id)
                .map(|(_, body)| ItemRecord::decode(body).ok())
        };
        let mut visible = Vec::new();
        for r in self.store.list(RecordKind::Item)? {
            if let Some(item) = of_vault(&r) {
                visible.push((r, item));
            }
        }
        let held: Vec<(Record, ItemRecord)> = kept
            .iter()
            .filter(|r| r.kind == RecordKind::Item && !visible.iter().any(|(v, _)| v.id == r.id))
            .filter_map(|r| Some((r.clone(), of_vault(r)??)))
            .collect();
        let mut candidates: Vec<Record> = Vec::new();
        let manifests = self
            .store
            .get(RecordKind::Manifest, vault.id)?
            .into_iter()
            .chain(
                kept.iter()
                    .filter(|r| r.kind == RecordKind::Manifest && r.id == vault.id)
                    .cloned(),
            );
        for r in manifests {
            if !candidates.contains(&r) {
                candidates.push(r);
            }
        }
        candidates.sort_by_key(|r| std::cmp::Reverse(r.version));
        let mut first = None;
        for record in candidates {
            match self.copy_from(vault, record, last, &visible, &held) {
                Ok(copy) => return Ok(copy),
                Err(Error::Integrity(e)) => {
                    first.get_or_insert(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(first.unwrap_or(IntegrityError::ManifestMissingItem).into())
    }

    fn copy_from(
        &self,
        vault: &Vault,
        record: Record,
        last: &SeenManifest,
        visible: &[(Record, Option<ItemRecord>)],
        held: &[(Record, ItemRecord)],
    ) -> Result<LocalCopy> {
        let sm = SignedManifest::decode(&record.data)?;
        let manifest = verify_manifest(vault, &self.account.params.signing_pub, &sm, Some(last))?;
        let exact = |e: &ManifestEntry, i: &ItemRecord| {
            i.item_id == e.item_id && i.version == e.version && record_hash(i) == e.record_hash
        };
        let mut records = Vec::new();
        let mut restore = Vec::new();
        let mut used = BTreeSet::new();
        for e in &manifest.entries {
            let found = visible
                .iter()
                .find(|(r, i)| !used.contains(&r.id) && i.as_ref().is_some_and(|i| exact(e, i)));
            if let Some((r, Some(i))) = found {
                used.insert(r.id);
                records.push((r.id, i.clone()));
            } else if let Some((r, i)) = held.iter().find(|(_, i)| exact(e, i)) {
                restore.push(r.clone());
                records.push((r.id, i.clone()));
            } else {
                return Err(IntegrityError::ManifestMissingItem.into());
            }
        }
        let mut unlisted = Vec::new();
        for (r, i) in visible.iter().filter(|(r, _)| !used.contains(&r.id)) {
            let opens = i.as_ref().is_some_and(|i| vault.open_item(i).is_ok());
            if !opens {
                return Err(IntegrityError::ManifestUnexpectedItem.into());
            }
            unlisted.push(r.id);
        }
        records.sort_by_key(|(_, r)| r.item_id);
        Ok(LocalCopy {
            record,
            loaded: Loaded {
                manifest,
                records,
                ignored: Vec::new(),
            },
            restore,
            unlisted,
        })
    }

    /// Whether the visible manifest forks from the copy: the same seq with
    /// another hash, or the next seq not built on it. An older one is the
    /// server behind, a later one cannot be told apart (no chain).
    fn forks_from(&self, vault: &Vault, copy: &LocalCopy) -> Result<bool> {
        let Some(visible) = self.store.get(RecordKind::Manifest, vault.id)? else {
            return Ok(false);
        };
        if visible.data == copy.record.data {
            return Ok(false);
        }
        let Ok(sm) = SignedManifest::decode(&visible.data) else {
            return Ok(false);
        };
        let Ok(m) = verify_manifest(vault, &self.account.params.signing_pub, &sm, None) else {
            return Ok(false);
        };
        let ours = &copy.loaded.manifest;
        let hash = manifest_hash(ours);
        Ok((m.seq == ours.seq && manifest_hash(&m) != hash)
            || (Some(m.seq) == ours.seq.checked_add(1) && m.prev_hash != hash))
    }

    /// Load and verify the manifest and item records of a vault.
    ///
    /// Errors: no manifest record is `ManifestMissingItem` (the vault was
    /// created with one, so the store dropped it); an undecodable manifest
    /// record is `InvalidFormat("manifest")`; an item record shorter than
    /// the 16 byte vault prefix is `InvalidFormat("item record")`; a record
    /// with this vault's prefix that does not decode is
    /// `ManifestUnexpectedItem`. Then `verify_manifest` and `check_records`.
    pub(crate) fn load(&self, vault: &Vault) -> Result<Loaded> {
        let manifest = self.read_manifest(vault, self.device.last_seen.get(&vault.id))?;

        let mut records = Vec::new();
        let mut ignored = Vec::new();
        for r in self.store.list(RecordKind::Item)? {
            let (prefix, body) = split_item_record(&r.data)?;
            if prefix != vault.id {
                continue;
            }
            let item =
                ItemRecord::decode(body).map_err(|_| IntegrityError::ManifestUnexpectedItem)?;
            if interrupted_write(vault, &manifest, &item) {
                ignored.push((r.id, item.item_id));
            } else {
                records.push((r.id, item));
            }
        }
        // Leftovers ignored only beside the exact current record of a listed
        // item: an older version (cleanup cut short) or the same version
        // with other content (the record of a writer that lost a race on
        // this item and stopped before deleting it).
        let current: Vec<Id> = manifest
            .entries
            .iter()
            .filter(|e| {
                records.iter().any(|(_, r)| {
                    r.item_id == e.item_id
                        && r.version == e.version
                        && record_hash(r) == e.record_hash
                })
            })
            .map(|e| e.item_id)
            .collect();
        let (stale, mut records): (Vec<_>, Vec<_>) = records
            .into_iter()
            .partition(|(_, r)| current.contains(&r.item_id) && is_leftover(&manifest, r));
        ignored.extend(stale.iter().map(|(blob, r)| (*blob, r.item_id)));
        records.sort_by_key(|(_, r)| r.item_id);
        let plain: Vec<ItemRecord> = records.iter().map(|(_, r)| r.clone()).collect();
        check_records(&manifest, &plain)?;
        Ok(Loaded {
            manifest,
            records,
            ignored,
        })
    }

    /// The vault's manifest record, decoded and verified (`verify_manifest`).
    /// No record is `ManifestMissingItem`, an undecodable one
    /// `InvalidFormat("manifest")`.
    fn read_manifest(&self, vault: &Vault, last_seen: Option<&SeenManifest>) -> Result<Manifest> {
        let rec = self
            .store
            .get(RecordKind::Manifest, vault.id)?
            .ok_or(IntegrityError::ManifestMissingItem)?;
        let sm = SignedManifest::decode(&rec.data)?;
        verify_manifest(vault, &self.account.params.signing_pub, &sm, last_seen)
    }

    fn delete_ignored(&mut self, loaded: &Loaded, item_id: Id) -> Result<()> {
        for blob in loaded.ignored_of(item_id) {
            self.store.delete(RecordKind::Item, blob)?;
        }
        Ok(())
    }

    /// Store an item record under a fresh blob id, returned.
    fn put_item(&mut self, vault_id: Id, rec: &ItemRecord) -> Result<Id> {
        let mut data = vault_id.0.to_vec();
        data.extend(postcard::to_allocvec(rec).map_err(|_| Error::InvalidFormat("item record"))?);
        let id = Id::new();
        self.store.put(Record {
            id,
            kind: RecordKind::Item,
            version: rec.version,
            data,
        })?;
        Ok(id)
    }

    /// `write_manifest`; on a lost race, delete `written` (the record this
    /// write put just before, if any) and return `Conflict`. Other errors
    /// keep the record: the manifest may have been written after all.
    fn commit_manifest(
        &mut self,
        vault: &Vault,
        prev: &Manifest,
        entries: Vec<ManifestEntry>,
        written: Option<Id>,
    ) -> Result<()> {
        match self.write_manifest(vault, prev, entries) {
            Err(Error::Conflict) => {
                if let Some(blob) = written {
                    // Best effort: if this fails too, the record is a
                    // leftover that loading ignores beside the winner's.
                    let _ = self.store.delete(RecordKind::Item, blob);
                }
                Err(Error::Conflict)
            }
            other => other,
        }
    }

    /// Sign and store the manifest following `prev` with `entries`, and
    /// remember it as the last one seen.
    fn write_manifest(
        &mut self,
        vault: &Vault,
        prev: &Manifest,
        entries: Vec<ManifestEntry>,
    ) -> Result<()> {
        let seen = self.put_manifest(vault, Some(prev), entries)?;
        self.device.last_seen.insert(vault.id, seen);
        Ok(())
    }

    /// Sign and store the manifest following `prev` (or the first one),
    /// only if the stored manifest is still `prev` (or there is none): the
    /// record version is the seq. A lost race is `Error::Conflict`, and the
    /// item record already written stays an ignored interrupted write.
    fn put_manifest(
        &mut self,
        vault: &Vault,
        prev: Option<&Manifest>,
        entries: Vec<ManifestEntry>,
    ) -> Result<SeenManifest> {
        let (rec, seen) = self.manifest_record(vault, prev, entries)?;
        self.store.put_if_version(rec, prev.map(|p| p.seq))?;
        Ok(seen)
    }

    /// The signed record of the manifest following `prev` (or the first
    /// one), not written.
    fn manifest_record(
        &self,
        vault: &Vault,
        prev: Option<&Manifest>,
        entries: Vec<ManifestEntry>,
    ) -> Result<(Record, SeenManifest)> {
        let m = Manifest::next(prev, vault.id, entries)?;
        Ok((self.signed_manifest(vault, &m)?, seen(&m)))
    }

    /// The signed record of `m` (record version = its seq), not written.
    fn signed_manifest(&self, vault: &Vault, m: &Manifest) -> Result<Record> {
        let sm = sign_manifest(vault, &self.account.keyset().signing, m)?;
        let data = postcard::to_allocvec(&sm).map_err(|_| Error::InvalidFormat("manifest"))?;
        Ok(Record {
            id: vault.id,
            kind: RecordKind::Manifest,
            version: m.seq,
            data,
        })
    }

    /// Sign and store `m` (record version = its seq), only if the stored
    /// manifest has seq `expected` (`None`: there is none). A lost race is
    /// `Error::Conflict`.
    fn store_manifest(
        &mut self,
        vault: &Vault,
        m: &Manifest,
        expected: Option<u64>,
    ) -> Result<SeenManifest> {
        let rec = self.signed_manifest(vault, m)?;
        self.store.put_if_version(rec, expected)?;
        Ok(seen(m))
    }
}

/// Whether the vault list `entries` marks `vault` deleted.
fn listed_deleted(entries: &[VaultListEntry], vault: Id) -> bool {
    entries
        .iter()
        .any(|e| e.vault_id == vault && e.deleted_at.is_some())
}

/// Beside the exact current record of its item: an older version, or the
/// same version with another hash. The exact current record served twice is
/// not a leftover (`check_records` refuses it).
fn is_leftover(m: &Manifest, rec: &ItemRecord) -> bool {
    match m.entries.binary_search_by_key(&rec.item_id, |e| e.item_id) {
        Ok(i) => {
            let e = &m.entries[i];
            e.version > rec.version
                || (e.version == rec.version && e.record_hash != record_hash(rec))
        }
        Err(_) => false,
    }
}

/// The version the manifest lists for this item, if any.
fn entry_version(m: &Manifest, item_id: Id) -> Option<u64> {
    m.entries
        .binary_search_by_key(&item_id, |e| e.item_id)
        .ok()
        .map(|i| m.entries[i].version)
}

/// A record left by a write that stopped before its manifest: exactly the
/// next version of a listed item, or version 1 of an unlisted one, and it
/// opens under this vault's key (so the store cannot fake one).
fn interrupted_write(vault: &Vault, m: &Manifest, rec: &ItemRecord) -> bool {
    let expected = match entry_version(m, rec.item_id) {
        Some(v) => v.checked_add(1),
        None => Some(1),
    };
    expected == Some(rec.version) && vault.open_item(rec).is_ok()
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::account::NewAccount;
    use crate::crypto::random_array;
    use crate::model::{FieldValue, ItemType, new_item};
    use crate::store::{MemoryStore, Record, RecordKind, SqliteStore};
    use crate::vault::ItemRecord;
    use crate::{Error, IntegrityError};

    fn kdf() -> KdfParams {
        KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: random_array().unwrap(),
        }
    }

    /// One account shared by the tests that do not test creation itself.
    fn shared() -> &'static NewAccount {
        static N: OnceLock<NewAccount> = OnceLock::new();
        N.get_or_init(|| Account::create_with_params("pw", kdf()).unwrap())
    }

    /// Write the shared account into `store`, unlock it on a new device and
    /// give it one vault.
    fn fresh<S: RecordStore>(mut store: S) -> (Repository<S>, Vault) {
        let n = shared();
        let id = n.account.params.account_id;
        for (kind, data) in [
            (RecordKind::AccountParams, &n.params_record),
            (RecordKind::Keyset, &n.keyset_record),
        ] {
            store
                .put(Record {
                    id,
                    kind,
                    version: 1,
                    data: data.clone(),
                })
                .unwrap();
        }
        let mut repo =
            Repository::unlock(store, "pw", &n.secret_key, DeviceState::default()).unwrap();
        let v = repo.create_vault(meta("A")).unwrap();
        (repo, v)
    }

    fn meta(name: &str) -> VaultMeta {
        VaultMeta {
            name: name.into(),
            icon: "key".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        }
    }

    fn login(v: &Vault, user: &str) -> Item {
        let mut item = new_item(ItemType::Login, v.id, "Example");
        item.field_mut("username").unwrap().value = FieldValue::Text(user.into());
        item
    }

    fn user(item: &Item) -> String {
        item.subtitle()
    }

    #[test]
    fn usage_a_b_a_within_the_hour_rewrites_a() {
        use crate::fill_plan::context::FieldRole;
        use crate::fill_plan::intent::Intent;
        use crate::model::usage::{StepKind, form_shape_hash};
        let (mut repo, v) = fresh(MemoryStore::new());
        let (a, b) = (login(&v, "alice"), login(&v, "bob"));
        repo.save_item(&v, a.clone()).unwrap();
        repo.save_item(&v, b.clone()).unwrap();
        let t0 = OffsetDateTime::now_utc();
        let u = |at: OffsetDateTime| SiteUsage {
            site: "a.com".into(),
            form_shape_hash: form_shape_hash(&[FieldRole::Username]),
            intent: Intent::Login,
            step_seq: vec![StepKind::Fill],
            count: 1,
            last_at: at,
        };
        let min = time::Duration::minutes;
        let (t10, t20) = (t0 + min(10), t0 + min(20));
        assert!(repo.record_usage(&v, a.id, u(t0), t0, false).unwrap());
        assert!(repo.record_usage(&v, b.id, u(t10), t10, false).unwrap());
        // B used the site after A's entry: A is rewritten within the hour.
        assert!(repo.record_usage(&v, a.id, u(t20), t20, false).unwrap());
        let items = repo.items(&v).unwrap();
        let last = |id: Id| items.iter().find(|i| i.id == id).unwrap().usage[0].last_at;
        assert_eq!(last(a.id), t20);
        assert_eq!(last(b.id), t10);
        // A is now the newest: a repeat within the hour writes nothing.
        let t25 = t0 + min(25);
        assert!(!repo.record_usage(&v, a.id, u(t25), t25, false).unwrap());
        // Unless the caller saw a newer use elsewhere (another vault).
        let t30 = t0 + min(30);
        assert!(repo.record_usage(&v, a.id, u(t30), t30, true).unwrap());
    }

    #[test]
    fn usage_force_scan_skips_archived_and_trashed() {
        use crate::fill_plan::context::FieldRole;
        use crate::fill_plan::intent::Intent;
        use crate::model::usage::{StepKind, form_shape_hash};
        let (mut repo, v) = fresh(MemoryStore::new());
        let (a, b) = (login(&v, "alice"), login(&v, "bob"));
        repo.save_item(&v, a.clone()).unwrap();
        repo.save_item(&v, b.clone()).unwrap();
        let t0 = OffsetDateTime::now_utc();
        let min = time::Duration::minutes;
        let u = |at: OffsetDateTime| SiteUsage {
            site: "a.com".into(),
            form_shape_hash: form_shape_hash(&[FieldRole::Username]),
            intent: Intent::Login,
            step_seq: vec![StepKind::Fill],
            count: 1,
            last_at: at,
        };
        assert!(repo.record_usage(&v, a.id, u(t0), t0, false).unwrap());
        assert!(
            repo.record_usage(&v, b.id, u(t0 + min(10)), t0 + min(10), false)
                .unwrap()
        );
        repo.archive_item(&v, b.id).unwrap();
        assert!(
            !repo
                .record_usage(&v, a.id, u(t0 + min(20)), t0 + min(20), false)
                .unwrap()
        );
        repo.trash_item(&v, b.id).unwrap();
        assert!(
            !repo
                .record_usage(&v, a.id, u(t0 + min(21)), t0 + min(21), false)
                .unwrap()
        );
    }

    #[test]
    fn usage_writes_only_when_worth_it_and_forgets_by_site() {
        use crate::fill_plan::context::FieldRole;
        use crate::fill_plan::intent::Intent;
        use crate::model::usage::{StepKind, form_shape_hash};
        let (mut repo, v) = fresh(MemoryStore::new());
        let item = login(&v, "alice");
        repo.save_item(&v, item.clone()).unwrap();
        let now = OffsetDateTime::now_utc();
        let u = |site: &str| SiteUsage {
            site: site.into(),
            form_shape_hash: form_shape_hash(&[FieldRole::Username]),
            intent: Intent::Login,
            step_seq: vec![StepKind::Fill],
            count: 1,
            last_at: now,
        };
        let version = |repo: &mut Repository<MemoryStore>| {
            repo.load(&v).unwrap().listed(item.id).unwrap().1.version
        };
        assert!(
            repo.record_usage(&v, item.id, u("a.com"), now, false)
                .unwrap()
        );
        assert!(
            repo.record_usage(&v, item.id, u("b.com"), now, false)
                .unwrap()
        );
        let written = version(&mut repo);
        // Same site, same shape, within the hour: no write.
        assert!(
            !repo
                .record_usage(&v, item.id, u("a.com"), now, false)
                .unwrap()
        );
        assert_eq!(version(&mut repo), written);
        let stored = repo.items(&v).unwrap().remove(0);
        assert_eq!(stored.updated_at, item.updated_at);
        assert_eq!(stored.usage.len(), 2);

        // A vault left out keeps its memory.
        assert_eq!(repo.forget_site_usage_in("a.com", |_| false).unwrap(), 0);
        assert_eq!(repo.items(&v).unwrap()[0].usage.len(), 2);
        assert_eq!(repo.forget_site_usage("a.com").unwrap(), 1);
        assert_eq!(repo.forget_site_usage("a.com").unwrap(), 0);
        let stored = repo.items(&v).unwrap().remove(0);
        assert_eq!(stored.usage.len(), 1);
        assert_eq!(stored.usage[0].site, "b.com");
        assert_eq!(stored.updated_at, item.updated_at);
    }

    #[test]
    fn forget_by_site_skips_a_failing_vault_and_reports_it() {
        use crate::fill_plan::context::FieldRole;
        use crate::fill_plan::intent::Intent;
        use crate::model::usage::{StepKind, form_shape_hash};
        let (mut repo, v) = fresh(MemoryStore::new());
        let w = repo.create_vault(meta("B")).unwrap();
        let now = OffsetDateTime::now_utc();
        let u = SiteUsage {
            site: "a.com".into(),
            form_shape_hash: form_shape_hash(&[FieldRole::Username]),
            intent: Intent::Login,
            step_seq: vec![StepKind::Fill],
            count: 1,
            last_at: now,
        };
        for vault in [&v, &w] {
            let item = login(vault, "alice");
            repo.save_item(vault, item.clone()).unwrap();
            assert!(
                repo.record_usage(vault, item.id, u.clone(), now, false)
                    .unwrap()
            );
        }
        // The store serves an older manifest of `w`: an alert there.
        let old = repo.store.get(RecordKind::Manifest, w.id).unwrap().unwrap();
        repo.save_item(&w, login(&w, "bob")).unwrap();
        let current = repo.store.get(RecordKind::Manifest, w.id).unwrap().unwrap();
        repo.store.put(old).unwrap();
        assert_eq!(integrity(repo.items(&w)), IntegrityError::ManifestRollback);

        // The other vault still forgets; the call still says it failed.
        assert_eq!(
            integrity(repo.forget_site_usage("a.com")),
            IntegrityError::ManifestRollback
        );
        assert!(repo.items(&v).unwrap()[0].usage.is_empty());
        repo.store.put(current).unwrap();
        assert!(repo.items(&w).unwrap().iter().any(|i| !i.usage.is_empty()));

        // A vault the store hides is an alert for the whole call.
        let key = repo.store.get(RecordKind::VaultKey, w.id).unwrap().unwrap();
        repo.store.delete(RecordKind::VaultKey, w.id).unwrap();
        assert_eq!(
            integrity(repo.forget_site_usage("a.com")),
            IntegrityError::VaultMissing
        );
        repo.store.put(key).unwrap();
        assert_eq!(repo.forget_site_usage("a.com").unwrap(), 1);
    }

    /// Store an item record by hand, as an interrupted write would leave it.
    fn put_raw<S: RecordStore>(repo: &mut Repository<S>, vault_id: Id, rec: &ItemRecord) -> Id {
        let mut data = vault_id.0.to_vec();
        data.extend(postcard::to_allocvec(rec).unwrap());
        let id = Id::new();
        repo.store
            .put(Record {
                id,
                kind: RecordKind::Item,
                version: rec.version,
                data,
            })
            .unwrap();
        id
    }

    fn integrity<T: std::fmt::Debug>(r: Result<T>) -> IntegrityError {
        match r {
            Err(Error::Integrity(e)) => e,
            other => panic!("expected an integrity error, got {other:?}"),
        }
    }

    #[test]
    fn account_accessor_returns_unlocked_account() {
        let (repo, _sk) =
            Repository::create_account(MemoryStore::new(), "pass word", kdf()).unwrap();
        assert_eq!(
            repo.account().params.account_id,
            repo.device_state().pinned.clone().unwrap().account_id
        );
    }

    #[test]
    fn create_save_reload() {
        let (mut repo, sk) =
            Repository::create_account(MemoryStore::new(), "pass word", kdf()).unwrap();
        let pinned = repo.device_state().pinned.clone().unwrap();
        assert_eq!(pinned.account_id, repo.account.params.account_id);
        let vaults = repo.vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].meta.name, "Personnel");
        assert_eq!(repo.items(&vaults[0]).unwrap(), vec![]);

        let item = login(&vaults[0], "alice");
        repo.save_item(&vaults[0], item.clone()).unwrap();
        let device = repo.device_state().clone();

        let mut again = Repository::unlock(repo.store, "pass word", &sk, device).unwrap();
        let vaults = again.vaults().unwrap();
        assert_eq!(again.items(&vaults[0]).unwrap(), vec![item]);
        assert_eq!(again.device_state().pinned, Some(pinned));
        assert!(matches!(
            Repository::unlock(again.store, "wrong", &sk, DeviceState::default()),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn interrupted_write_keeps_last_consistent_version() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let item = login(&v, "v1");
        repo.save_item(&v, item.clone()).unwrap();

        // Next version of the item, record written, manifest never written.
        let rec = v.seal_item(&login_as(&item, "v2"), 2).unwrap();
        put_raw(&mut repo, v.id, &rec);
        // A new item, record written, manifest never written.
        let other = login(&v, "new");
        put_raw(&mut repo, v.id, &v.seal_item(&other, 1).unwrap());

        assert_eq!(repo.items(&v).unwrap(), vec![item.clone()]);

        // The next save goes through and clears the leftovers.
        repo.save_item(&v, login_as(&item, "v3")).unwrap();
        let items = repo.items(&v).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(user(&items[0]), "v3");
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 2);
    }

    fn login_as(item: &Item, name: &str) -> Item {
        let mut out = item.clone();
        out.field_mut("username").unwrap().value = FieldValue::Text(name.into());
        out
    }

    #[test]
    fn stale_older_version_is_ignored_only_beside_the_current_one() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let item = login(&v, "v1");
        repo.save_item(&v, item.clone()).unwrap();
        let v1 = repo.store.list(RecordKind::Item).unwrap().pop().unwrap();
        repo.save_item(&v, login_as(&item, "v2")).unwrap();
        let current = repo.store.list(RecordKind::Item).unwrap().pop().unwrap();
        // A crash between the manifest write and the delete of v1.
        repo.store.put(v1).unwrap();
        let items = repo.items(&v).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(user(&items[0]), "v2");

        // The old version served instead of the current one stays an error.
        repo.store.delete(RecordKind::Item, current.id).unwrap();
        assert_eq!(
            integrity(repo.items(&v)),
            IntegrityError::ManifestItemMismatch
        );

        // Back to current plus stale: the next save clears the stale record.
        repo.store.put(current).unwrap();
        repo.save_item(&v, login_as(&item, "v3")).unwrap();
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 1);
        assert_eq!(user(&repo.items(&v).unwrap()[0]), "v3");
    }

    #[test]
    fn records_that_are_not_interrupted_writes_stay_errors() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let item = login(&v, "v1");
        repo.save_item(&v, item.clone()).unwrap();

        // Two versions ahead: not an interrupted write.
        let rec = v.seal_item(&login_as(&item, "v3"), 3).unwrap();
        let stray = put_raw(&mut repo, v.id, &rec);
        assert_eq!(
            integrity(repo.items(&v)),
            IntegrityError::ManifestUnexpectedItem
        );
        repo.store.delete(RecordKind::Item, stray).unwrap();
        assert_eq!(repo.items(&v).unwrap(), vec![item.clone()]);

        // Version + 1, but sealed for another vault: injected, not pending.
        let w = repo.create_vault(meta("B")).unwrap();
        let mut foreign = login_as(&item, "x");
        foreign.vault_id = w.id;
        let rec = w.seal_item(&foreign, 2).unwrap();
        assert_eq!(rec.item_id, item.id);
        put_raw(&mut repo, v.id, &rec);
        assert_eq!(
            integrity(repo.items(&v)),
            IntegrityError::ManifestUnexpectedItem
        );
    }

    #[test]
    fn missing_or_old_manifest_is_refused() {
        let (mut repo, v) = fresh(MemoryStore::new());
        repo.save_item(&v, login(&v, "a")).unwrap();
        let old = repo.store.get(RecordKind::Manifest, v.id).unwrap().unwrap();
        repo.save_item(&v, login(&v, "b")).unwrap();
        assert_eq!(repo.items(&v).unwrap().len(), 2);
        let seen = repo.device_state().last_seen[&v.id].clone();
        assert_eq!(seen.seq, 3);

        let current = repo.store.get(RecordKind::Manifest, v.id).unwrap().unwrap();
        repo.store.put(old).unwrap();
        assert_eq!(integrity(repo.items(&v)), IntegrityError::ManifestRollback);

        repo.store.delete(RecordKind::Manifest, v.id).unwrap();
        assert_eq!(
            integrity(repo.items(&v)),
            IntegrityError::ManifestMissingItem
        );

        let mut bad = current.clone();
        bad.data.truncate(bad.data.len() - 1);
        repo.store.put(bad).unwrap();
        assert_eq!(repo.items(&v), Err(Error::InvalidFormat("manifest")));

        repo.store.put(current).unwrap();
        assert_eq!(repo.items(&v).unwrap().len(), 2);
    }

    #[test]
    fn delete_trash_archive() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let (a, b, c) = (login(&v, "a"), login(&v, "b"), login(&v, "c"));
        for i in [&a, &b, &c] {
            repo.save_item(&v, i.clone()).unwrap();
        }
        repo.delete_item(&v, a.id).unwrap();
        repo.trash_item(&v, b.id).unwrap();
        repo.archive_item(&v, c.id).unwrap();
        let items = repo.items(&v).unwrap();
        assert_eq!(items.len(), 2);
        let get = |id| items.iter().find(|i| i.id == id).unwrap();
        assert!(get(b.id).trashed_at.is_some());
        assert!(!get(b.id).archived);
        assert!(get(c.id).archived);
        assert!(get(c.id).trashed_at.is_none());
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 2);
        assert_eq!(repo.delete_item(&v, a.id), Err(Error::NotFound));
    }

    #[test]
    fn item_record_decoders_are_strict() {
        assert_eq!(
            split_item_record(&[0; 15]).unwrap_err(),
            Error::InvalidFormat("item record")
        );
        let (repo, v) = fresh(MemoryStore::new());
        let rec = v.seal_item(&login(&v, "a"), 1).unwrap();
        let mut data = v.id.0.to_vec();
        data.extend(postcard::to_allocvec(&rec).unwrap());
        let (prefix, body) = split_item_record(&data).unwrap();
        assert_eq!(prefix, v.id);
        assert_eq!(ItemRecord::decode(body).unwrap(), rec);
        data.push(0);
        assert_eq!(
            ItemRecord::decode(&data[16..]).unwrap_err(),
            Error::InvalidFormat("item record")
        );
        drop(repo);
    }

    #[test]
    fn unlock_ratchets_the_pinned_kdf_floor() {
        let (repo, _) = fresh(MemoryStore::new());
        let mut device = repo.device_state().clone();
        let accepted = repo.account.params.kdf.clone();
        // A pin from before the params were strengthened.
        device.pinned.as_mut().unwrap().kdf_floor.m_kib = accepted.m_kib / 2;
        let repo = Repository::unlock(repo.store, "pw", &shared().secret_key, device).unwrap();
        assert_eq!(
            repo.device_state().pinned.as_ref().unwrap().kdf_floor,
            accepted
        );
    }

    #[test]
    fn unlock_requires_exactly_one_account() {
        let n = shared();
        assert!(matches!(
            Repository::unlock(
                MemoryStore::new(),
                "pw",
                &n.secret_key,
                DeviceState::default()
            ),
            Err(Error::NotFound)
        ));
        let (repo, _) = fresh(MemoryStore::new());
        let mut store = repo.store;
        let mut twin = store
            .list(RecordKind::AccountParams)
            .unwrap()
            .pop()
            .unwrap();
        twin.id = Id::new();
        store.put(twin).unwrap();
        assert!(matches!(
            Repository::unlock(store, "pw", &n.secret_key, DeviceState::default()),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn sqlite_store_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onepass.sqlite");
        let (mut repo, v) = fresh(SqliteStore::open(&path).unwrap());
        let item = login(&v, "alice");
        repo.save_item(&v, item.clone()).unwrap();
        let device = repo.device_state().clone();
        drop(repo);

        let store = SqliteStore::open(&path).unwrap();
        let mut repo = Repository::unlock(store, "pw", &shared().secret_key, device).unwrap();
        let vaults = repo.vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(repo.items(&vaults[0]).unwrap(), vec![item]);
    }

    /// A store that runs `hook` once, just before the first write of a
    /// record of kind `on`, and can refuse writes of one record.
    struct Hooked<S> {
        inner: S,
        on: RecordKind,
        /// Only for this record id, when set.
        on_id: Option<Id>,
        hook: Option<Box<dyn FnOnce()>>,
        refuse: Option<(RecordKind, Id)>,
        refuse_kind: Option<RecordKind>,
    }

    impl<S> Hooked<S> {
        fn new(inner: S) -> Hooked<S> {
            Hooked {
                inner,
                on: RecordKind::Item,
                on_id: None,
                hook: None,
                refuse: None,
                refuse_kind: None,
            }
        }

        fn before_put(&mut self, r: &Record) -> Result<()> {
            if self.refuse == Some((r.kind, r.id)) || self.refuse_kind == Some(r.kind) {
                return Err(Error::Store("cut".into()));
            }
            if r.kind == self.on
                && self.on_id.is_none_or(|id| id == r.id)
                && let Some(hook) = self.hook.take()
            {
                hook();
            }
            Ok(())
        }
    }

    impl<S: RecordStore> RecordStore for Hooked<S> {
        fn put(&mut self, r: Record) -> Result<()> {
            self.before_put(&r)?;
            self.inner.put(r)
        }

        fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
            self.before_put(&r)?;
            self.inner.put_if_version(r, expected)
        }

        fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
            self.inner.get(kind, id)
        }

        fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
            self.inner.list(kind)
        }

        fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
            self.inner.delete(kind, id)
        }
    }

    #[test]
    fn lost_race_is_a_conflict_not_a_silent_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onepass.sqlite");
        let (repo, v) = fresh(SqliteStore::open(&path).unwrap());
        let device = repo.device_state().clone();
        drop(repo);
        let open = |device: DeviceState| {
            let store = SqliteStore::open(&path).unwrap();
            Repository::unlock(store, "pw", &shared().secret_key, device).unwrap()
        };

        // Writer 1 saves `first` while writer 2 is between its load and its
        // manifest write.
        let first = login(&v, "first");
        let mut writer1 = open(device.clone());
        let (first_c, v1) = (first.clone(), vault_of(&writer1, v.id));
        let mut store2 = Hooked::new(SqliteStore::open(&path).unwrap());
        store2.hook = Some(Box::new(move || writer1.save_item(&v1, first_c).unwrap()));
        let mut writer2 =
            Repository::unlock(store2, "pw", &shared().secret_key, device.clone()).unwrap();
        let v2 = vault_of(&writer2, v.id);
        let second = login(&v, "second");
        assert_eq!(writer2.save_item(&v2, second.clone()), Err(Error::Conflict));

        // Only the winner is listed, and loading still works.
        let mut reader = open(device);
        let ids: Vec<Id> = reader.items(&v).unwrap().iter().map(|i| i.id).collect();
        assert_eq!(ids, vec![first.id]);
        // The loser retries and gets through.
        let mut writer2 = open(reader.device_state().clone());
        writer2.save_item(&v, second.clone()).unwrap();
        assert_eq!(writer2.items(&v).unwrap().len(), 2);
    }

    #[test]
    fn vaults_requires_a_verified_manifest_and_every_known_vault() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let w = repo.create_vault(meta("B")).unwrap();
        assert_eq!(repo.vaults().unwrap().len(), 2);

        // A listed vault without its manifest.
        let m = repo.store.get(RecordKind::Manifest, w.id).unwrap().unwrap();
        repo.store.delete(RecordKind::Manifest, w.id).unwrap();
        assert_eq!(
            integrity(repo.vaults()),
            IntegrityError::ManifestMissingItem
        );
        // The manifest of another vault served for this one.
        let mut other = repo.store.get(RecordKind::Manifest, v.id).unwrap().unwrap();
        other.id = w.id;
        repo.store.put(other).unwrap();
        assert_eq!(integrity(repo.vaults()), IntegrityError::Commitment);
        repo.store.put(m).unwrap();

        // A vault this device saw, hidden by the store.
        let key = repo.store.get(RecordKind::VaultKey, w.id).unwrap().unwrap();
        repo.store.delete(RecordKind::VaultKey, w.id).unwrap();
        assert_eq!(integrity(repo.vaults()), IntegrityError::VaultMissing);
        // A device that never saw it tells too: the signed vault list
        // lists it.
        repo.device.last_seen.remove(&w.id);
        assert_eq!(integrity(repo.vaults()), IntegrityError::VaultMissing);
        repo.store.put(key).unwrap();
        assert_eq!(repo.vaults().unwrap().len(), 2);
    }

    #[test]
    fn interrupted_create_vault_is_not_remembered() {
        let (repo, _) = fresh(MemoryStore::new());
        let device = repo.device_state().clone();
        let mut store = Hooked::new(repo.store);
        store.refuse_kind = Some(RecordKind::VaultKey);
        let mut repo = Repository::unlock(store, "pw", &shared().secret_key, device).unwrap();
        let seen = repo.device_state().last_seen.clone();
        assert!(matches!(repo.create_vault(meta("B")), Err(Error::Store(_))));
        // Manifest written, key never: the vault is not listed, and the
        // device does not remember it, so this is not a hidden vault.
        assert_eq!(repo.device_state().last_seen, seen);
        repo.store.refuse_kind = None;
        assert_eq!(repo.vaults().unwrap().len(), 1);
    }

    #[test]
    fn move_cut_between_the_two_manifests_leaves_the_item_in_both() {
        let (repo, a) = fresh(MemoryStore::new());
        let device = repo.device_state().clone();
        let mut repo =
            Repository::unlock(Hooked::new(repo.store), "pw", &shared().secret_key, device)
                .unwrap();
        let b = repo.create_vault(meta("B")).unwrap();
        let item = login(&a, "alice");
        repo.save_item(&a, item.clone()).unwrap();

        // The manifest of `to` is written, the one of `from` is not.
        repo.store.refuse = Some((RecordKind::Manifest, a.id));
        assert!(matches!(
            repo.move_item(item.id, &a, &b),
            Err(Error::Store(_))
        ));
        repo.store.refuse = None;
        let mut in_b = item.clone();
        in_b.vault_id = b.id;
        // Duplicated, never lost: both vaults load and list the item.
        assert_eq!(repo.items(&a).unwrap(), vec![item.clone()]);
        assert_eq!(no_events(repo.items(&b).unwrap()), vec![in_b.clone()]);

        // Moving again heals it: the copy in `b` is replaced, `a` drops it.
        repo.move_item(item.id, &a, &b).unwrap();
        assert_eq!(repo.items(&a).unwrap(), vec![]);
        assert_eq!(no_events(repo.items(&b).unwrap()), vec![in_b]);
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 1);
    }

    /// A store that stops before its first write of a `kind` record: it
    /// says so on `arrived`, then waits for `go`. For races between threads.
    struct Gated<S> {
        inner: S,
        kind: RecordKind,
        gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    }

    impl<S> Gated<S> {
        fn before_put(&mut self, r: &Record) {
            if r.kind == self.kind
                && let Some((arrived, go)) = self.gate.take()
            {
                arrived.send(()).unwrap();
                go.recv().unwrap();
            }
        }
    }

    impl<S: RecordStore> RecordStore for Gated<S> {
        fn put(&mut self, r: Record) -> Result<()> {
            self.before_put(&r);
            self.inner.put(r)
        }

        fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()> {
            self.before_put(&r);
            self.inner.put_if_version(r, expected)
        }

        fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>> {
            self.inner.get(kind, id)
        }

        fn list(&self, kind: RecordKind) -> Result<Vec<Record>> {
            self.inner.list(kind)
        }

        fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()> {
            self.inner.delete(kind, id)
        }
    }

    /// How the loser of a same-item race touches the item.
    #[derive(Clone, Copy)]
    enum Loser {
        Edit,
        Delete,
        /// Move the item out of the vault the winner writes to.
        MoveOut,
    }

    /// Two writers on one item over one SQLite file. The winner edits the
    /// item, writes its record and stops just before its manifest. The
    /// loser then loads (the winner's record looks like an interrupted
    /// write), runs up to its own manifest write, lets the winner commit,
    /// and writes its manifest last. Returns the loser's result, a fresh
    /// reader over the file, the vaults and the winner's item.
    fn same_item_race(
        loser: Loser,
    ) -> (
        Result<()>,
        Repository<SqliteStore>,
        Vault,
        Vault,
        Item,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onepass.sqlite");
        let (mut repo, a) = fresh(SqliteStore::open(&path).unwrap());
        let b = repo.create_vault(meta("B")).unwrap();
        let item = login(&a, "v1");
        repo.save_item(&a, item.clone()).unwrap();
        let device = repo.device_state().clone();
        drop(repo);
        fn on<S: RecordStore>(store: S, device: &DeviceState) -> Repository<S> {
            Repository::unlock(store, "pw", &shared().secret_key, device.clone()).unwrap()
        }

        let (arrived_tx, arrived) = std::sync::mpsc::channel();
        let (go, go_rx) = std::sync::mpsc::channel();
        let winner_store = Gated {
            inner: SqliteStore::open(&path).unwrap(),
            kind: RecordKind::Manifest,
            gate: Some((arrived_tx, go_rx)),
        };
        let mut winner = on(winner_store, &device);
        let (wa, winner_item) = (vault_of(&winner, a.id), login_as(&item, "winner"));
        let edit = winner_item.clone();
        let winner = std::thread::spawn(move || winner.save_item(&wa, edit));
        arrived.recv().unwrap();

        // The loser lets the winner commit right before its manifest write.
        let mut store = Hooked::new(SqliteStore::open(&path).unwrap());
        store.on = RecordKind::Manifest;
        if let Loser::MoveOut = loser {
            store.on_id = Some(a.id);
        }
        let done = std::sync::Arc::new(std::sync::Mutex::new(None));
        let done_in = std::sync::Arc::clone(&done);
        store.hook = Some(Box::new(move || {
            go.send(()).unwrap();
            *done_in.lock().unwrap() = Some(winner.join().unwrap());
        }));
        let mut l = on(store, &device);
        let (la, lb) = (vault_of(&l, a.id), vault_of(&l, b.id));
        let result = match loser {
            Loser::Edit => l.save_item(&la, login_as(&item, "loser")),
            Loser::Delete => l.delete_item(&la, item.id),
            Loser::MoveOut => l.move_item(item.id, &la, &lb),
        };
        assert_eq!(
            done.lock().unwrap().take(),
            Some(Ok(())),
            "the winner commits"
        );
        let reader = on(SqliteStore::open(&path).unwrap(), &device);
        (result, reader, a, b, winner_item, dir)
    }

    #[test]
    fn same_item_race_edit_leaves_the_winner_readable() {
        let (result, mut reader, a, _, winner, _dir) = same_item_race(Loser::Edit);
        assert_eq!(result, Err(Error::Conflict));
        assert_eq!(reader.items(&a).unwrap(), vec![winner.clone()]);
        // The loser cleaned up: only the winner's record is left.
        assert_eq!(reader.store.list(RecordKind::Item).unwrap().len(), 1);
    }

    #[test]
    fn same_item_race_delete_leaves_the_winner_readable() {
        let (result, mut reader, a, _, winner, _dir) = same_item_race(Loser::Delete);
        assert_eq!(result, Err(Error::Conflict));
        assert_eq!(reader.items(&a).unwrap(), vec![winner]);
        assert_eq!(reader.store.list(RecordKind::Item).unwrap().len(), 1);
    }

    #[test]
    fn same_item_race_move_duplicates_and_heals() {
        let (result, mut reader, a, b, winner, _dir) = same_item_race(Loser::MoveOut);
        // The target manifest went through, the source one lost the race:
        // the item is in both vaults, as after a crash between the two.
        assert_eq!(result, Err(Error::Conflict));
        assert_eq!(reader.items(&a).unwrap(), vec![winner.clone()]);
        assert_eq!(reader.items(&b).unwrap().len(), 1);
        // Moving again heals it, with the winner's content.
        reader.move_item(winner.id, &a, &b).unwrap();
        let mut moved = winner;
        moved.vault_id = b.id;
        assert_eq!(reader.items(&a).unwrap(), vec![]);
        assert_eq!(no_events(reader.items(&b).unwrap()), vec![moved]);
        assert_eq!(reader.store.list(RecordKind::Item).unwrap().len(), 1);
    }

    #[test]
    fn lost_race_on_the_target_vault_leaves_no_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("onepass.sqlite");
        let (mut repo, a) = fresh(SqliteStore::open(&path).unwrap());
        let b = repo.create_vault(meta("B")).unwrap();
        let item = login(&a, "mover");
        repo.save_item(&a, item.clone()).unwrap();
        let device = repo.device_state().clone();
        drop(repo);
        let open = |device: DeviceState| {
            Repository::unlock(
                SqliteStore::open(&path).unwrap(),
                "pw",
                &shared().secret_key,
                device,
            )
            .unwrap()
        };
        // Another writer adds an item to `b` right before the move's
        // first manifest write (the one of `b`).
        let mut other = open(device.clone());
        let vb = vault_of(&other, b.id);
        let extra = login(&b, "extra");
        let extra_c = extra.clone();
        let mut store = Hooked::new(SqliteStore::open(&path).unwrap());
        store.on = RecordKind::Manifest;
        store.on_id = Some(b.id);
        store.hook = Some(Box::new(move || other.save_item(&vb, extra_c).unwrap()));
        let mut mover =
            Repository::unlock(store, "pw", &shared().secret_key, device.clone()).unwrap();
        let (ma, mb) = (vault_of(&mover, a.id), vault_of(&mover, b.id));
        assert_eq!(mover.move_item(item.id, &ma, &mb), Err(Error::Conflict));
        // Nothing moved, the moved record is gone, both vaults load.
        let mut reader = open(device);
        assert_eq!(reader.items(&a).unwrap(), vec![item]);
        assert_eq!(reader.items(&b).unwrap(), vec![extra]);
        assert_eq!(reader.store.list(RecordKind::Item).unwrap().len(), 2);
    }

    #[test]
    fn loser_record_left_by_a_crash_is_ignored_beside_the_current_one() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let item = login(&v, "v1");
        repo.save_item(&v, item.clone()).unwrap();
        repo.save_item(&v, login_as(&item, "winner")).unwrap();
        // A loser that crashed before deleting its record: same item, same
        // version as listed, other content.
        let leftover = put_raw(
            &mut repo,
            v.id,
            &v.seal_item(&login_as(&item, "loser"), 2).unwrap(),
        );
        let items = repo.items(&v).unwrap();
        assert_eq!(user(&items[0]), "winner");
        // Served alone, in place of the current record, it stays an error.
        let current = repo
            .store
            .list(RecordKind::Item)
            .unwrap()
            .into_iter()
            .find(|r| r.id != leftover)
            .unwrap();
        repo.store.delete(RecordKind::Item, current.id).unwrap();
        assert_eq!(
            integrity(repo.items(&v)),
            IntegrityError::ManifestItemMismatch
        );
        repo.store.put(current).unwrap();
        // The next save clears it.
        repo.save_item(&v, login_as(&item, "v3")).unwrap();
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 1);
    }

    /// Items without their timeline: a move records one event (its time is
    /// the clock's).
    fn no_events(mut items: Vec<Item>) -> Vec<Item> {
        for i in &mut items {
            i.events
                .retain(|e| !matches!(e.kind, EventKind::Moved { .. }));
        }
        items
    }

    fn vault_of<S: RecordStore>(repo: &Repository<S>, id: Id) -> Vault {
        repo.vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.id == id)
            .unwrap()
    }

    #[test]
    fn move_item_between_vaults() {
        let (mut repo, a) = fresh(MemoryStore::new());
        let b = repo.create_vault(meta("B")).unwrap();
        let item = login(&a, "alice");
        let stay = login(&a, "bob");
        repo.save_item(&a, item.clone()).unwrap();
        repo.save_item(&a, stay.clone()).unwrap();

        repo.move_item(item.id, &a, &b).unwrap();
        assert_eq!(repo.items(&a).unwrap(), vec![stay]);
        let mut expected = item.clone();
        expected.vault_id = b.id;
        assert_eq!(no_events(repo.items(&b).unwrap()), vec![expected]);
        assert_eq!(repo.store.list(RecordKind::Item).unwrap().len(), 2);
        assert_eq!(repo.move_item(item.id, &a, &b), Err(Error::NotFound));
    }

    #[test]
    fn update_vault_meta_roundtrips() {
        let (mut repo, v) = fresh(MemoryStore::new());
        let updated = repo.update_vault_meta(&v, meta("B")).unwrap();
        assert_eq!(updated.id, v.id);
        assert_eq!(updated.meta.name, "B");
        let listed = repo.vaults().unwrap();
        let names: Vec<_> = listed
            .iter()
            .filter(|x| x.id == v.id)
            .map(|x| x.meta.name.clone())
            .collect();
        assert_eq!(names, vec!["B".to_string()]);
        // The vault still opens its items.
        assert_eq!(repo.items(&updated).unwrap(), vec![]);
    }

    #[test]
    fn update_vault_meta_conflicts_on_stale_version() {
        let (mut repo, v) = fresh(MemoryStore::new());
        repo.update_vault_meta(&v, meta("B")).unwrap();
        assert!(matches!(
            repo.update_vault_meta(&v, meta("C")),
            Err(Error::Conflict)
        ));
        let listed = repo.vaults().unwrap();
        assert!(listed.iter().any(|x| x.meta.name == "B"));
    }

    #[test]
    fn unlock_exporting_auk_then_unlock_with_auk() {
        let (repo, sk) = Repository::create_account(MemoryStore::new(), "pw", kdf()).unwrap();
        let device = repo.device_state().clone();
        let (repo, auk) =
            Repository::unlock_exporting_auk(repo.store, "pw", &sk, device.clone()).unwrap();
        let again = Repository::unlock_with_auk(repo.store, &auk, device).unwrap();
        assert_eq!(again.vaults().unwrap().len(), 1);
        assert!(again.store().list(RecordKind::Keyset).unwrap().len() == 1);
    }

    #[test]
    fn device_state_roundtrips() {
        let (mut repo, v) = fresh(MemoryStore::new());
        repo.items(&v).unwrap();
        let device = repo.device_state().clone();
        assert!(device.pinned.is_some() && !device.last_seen.is_empty());
        assert_eq!(DeviceState::decode(&device.encode()).unwrap(), device);
        let empty = DeviceState::default();
        assert_eq!(DeviceState::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn device_state_rejects_trailing_bytes() {
        let mut bytes = DeviceState::default().encode();
        bytes.push(0);
        assert_eq!(
            DeviceState::decode(&bytes),
            Err(Error::InvalidFormat("device state"))
        );
        assert_eq!(
            DeviceState::decode(&[0xFF, 0xFF]),
            Err(Error::InvalidFormat("device state"))
        );
    }

    /// The version 1 layout of `DeviceState` (headerless postcard), copied
    /// here so the legacy bytes stay pinned whatever the struct becomes.
    #[derive(Serialize)]
    struct DeviceStateV1 {
        pinned: Option<PinnedAccount>,
        last_seen: BTreeMap<Id, SeenManifest>,
    }

    fn fixed_last_seen() -> BTreeMap<Id, SeenManifest> {
        BTreeMap::from([(
            Id([1; 16]),
            SeenManifest {
                seq: 7,
                hash: [0xab; 32],
            },
        )])
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Version 1 bytes of `{ pinned: None, last_seen: { [1; 16]: (7, [0xab; 32]) } }`.
    const LEGACY_V1_HEX: &str = concat!(
        "00",
        "01",
        "01010101010101010101010101010101",
        "07",
        "abababababababababababababababababababababababababababababababab",
    );

    #[test]
    fn legacy_device_state_migrates() {
        let v1 = DeviceStateV1 {
            pinned: None,
            last_seen: fixed_last_seen(),
        };
        let bytes = postcard::to_allocvec(&v1).unwrap();
        assert_eq!(to_hex(&bytes), LEGACY_V1_HEX);
        let migrated = DeviceState::decode(&from_hex(LEGACY_V1_HEX)).unwrap();
        assert_eq!(
            migrated,
            DeviceState {
                pinned: None,
                last_seen: fixed_last_seen(),
                epoch: 0,
            }
        );
        // With a pinned account too.
        let (mut repo, v) = fresh(MemoryStore::new());
        repo.items(&v).unwrap();
        let device = repo.device_state().clone();
        let v1 = DeviceStateV1 {
            pinned: device.pinned.clone(),
            last_seen: device.last_seen.clone(),
        };
        let mut bytes = postcard::to_allocvec(&v1).unwrap();
        let migrated = DeviceState::decode(&bytes).unwrap();
        assert_eq!(migrated.pinned, device.pinned);
        assert_eq!(migrated.last_seen, device.last_seen);
        assert_eq!(migrated.epoch, 0);
        // Trailing bytes after a legacy encoding stay refused.
        bytes.push(0);
        assert_eq!(
            DeviceState::decode(&bytes),
            Err(Error::InvalidFormat("device state"))
        );
    }

    /// A version 1 encoding starts with the `Option` tag of `pinned`, 0 or
    /// 1, so it can never be taken for the `b"ODS"` header (0x4F first).
    #[test]
    fn legacy_device_state_never_looks_like_header() {
        let (repo, _) = fresh(MemoryStore::new());
        for pinned in [None, repo.device_state().pinned.clone()] {
            let bytes = postcard::to_allocvec(&DeviceStateV1 {
                pinned,
                last_seen: fixed_last_seen(),
            })
            .unwrap();
            assert!(bytes[0] == 0 || bytes[0] == 1);
            assert_ne!(bytes[0], b'O');
        }
    }

    #[test]
    fn device_state_v2_roundtrip() {
        let (mut repo, v) = fresh(MemoryStore::new());
        repo.items(&v).unwrap();
        let mut device = repo.device_state().clone();
        device.epoch = 5;
        let mut bytes = device.encode();
        assert_eq!(&bytes[..4], b"ODS\x02");
        assert_eq!(&bytes[..3], b"ODS");
        assert_eq!(bytes[3], crate::format::DEVICE_STATE_VERSION);
        assert_eq!(DeviceState::decode(&bytes).unwrap(), device);
        let empty = DeviceState::default();
        assert_eq!(DeviceState::decode(&empty.encode()).unwrap(), empty);
        bytes.push(0);
        assert_eq!(
            DeviceState::decode(&bytes),
            Err(Error::InvalidFormat("device state"))
        );
    }

    #[test]
    fn future_device_state_refused() {
        let body = &DeviceState::default().encode()[4..];
        for newer in [3u8, 0xFF] {
            let mut bytes = b"ODS".to_vec();
            bytes.push(newer);
            bytes.extend_from_slice(body);
            assert_eq!(
                DeviceState::decode(&bytes),
                Err(Error::InvalidFormat("device state from a newer version"))
            );
        }
        for bad in [0u8, 1] {
            let mut bytes = b"ODS".to_vec();
            bytes.push(bad);
            bytes.extend_from_slice(body);
            assert_eq!(
                DeviceState::decode(&bytes),
                Err(Error::InvalidFormat("device state"))
            );
        }
        assert_eq!(
            DeviceState::decode(b"ODS"),
            Err(Error::InvalidFormat("device state"))
        );
    }

    #[test]
    fn change_password_new_works_old_fails() {
        let (repo, sk) = Repository::create_account(MemoryStore::new(), "ancien", kdf()).unwrap();
        let device = repo.device_state().clone();
        let (mut repo, old_auk) =
            Repository::unlock_exporting_auk(repo.store, "ancien", &sk, device).unwrap();
        let v = repo.vaults().unwrap().remove(0);
        let item = login(&v, "camille.durand@exemple.fr");
        repo.save_item(&v, item.clone()).unwrap();
        let before = repo.account().params.clone();

        let new_auk = repo.change_password("ancien", &sk, "nouveau").unwrap();
        let after = repo.account().params.clone();
        assert_eq!(after.epoch, before.epoch + 1);
        assert_eq!(repo.chain().params_epoch, after.epoch);
        assert_ne!(after.kdf.salt, before.kdf.salt);
        assert!(after.kdf.is_at_least(&before.kdf));
        // Same keys: the session and the vault keep working.
        assert_eq!(after.kem_pub, before.kem_pub);
        assert_eq!(after.signing_pub, before.signing_pub);
        assert_eq!(repo.items(&v).unwrap(), vec![item.clone()]);
        assert_eq!(
            repo.device_state().pinned.as_ref().unwrap().kdf_floor.salt,
            after.kdf.salt
        );
        let device = repo.device_state().clone();
        let store = repo.store;

        assert_eq!(
            Repository::unlock(store.clone(), "ancien", &sk, device.clone()).err(),
            Some(Error::WrongPassword)
        );
        assert_eq!(
            Repository::unlock_with_auk(store.clone(), &old_auk, device.clone()).err(),
            Some(Error::WrongPassword)
        );
        let mut again =
            Repository::unlock_with_auk(store.clone(), &new_auk, device.clone()).unwrap();
        assert_eq!(again.items(&v).unwrap(), vec![item.clone()]);
        let (mut again, auk) =
            Repository::unlock_exporting_auk(store, "nouveau", &sk, device).unwrap();
        assert_eq!(auk.as_bytes(), new_auk.as_bytes());
        assert_eq!(again.account().params, after);
        assert_eq!(again.items(&v).unwrap(), vec![item]);
    }

    #[test]
    fn change_password_rejects_wrong_current() {
        let (mut repo, sk) =
            Repository::create_account(MemoryStore::new(), "ancien", kdf()).unwrap();
        let params_before = repo.store.list(RecordKind::AccountParams).unwrap();
        let keyset_before = repo.store.list(RecordKind::Keyset).unwrap();
        assert_eq!(
            repo.change_password("faux", &sk, "nouveau").unwrap_err(),
            Error::WrongPassword
        );
        let other = SecretKey::generate().unwrap();
        assert_eq!(
            repo.change_password("ancien", &other, "nouveau")
                .unwrap_err(),
            Error::WrongPassword
        );
        // Nothing written, nothing pinned.
        assert_eq!(
            repo.store.list(RecordKind::AccountParams).unwrap(),
            params_before
        );
        assert_eq!(repo.store.list(RecordKind::Keyset).unwrap(), keyset_before);
        assert_eq!(repo.chain().params_epoch, 1);
        assert_eq!(repo.account().params.epoch, 1);
    }

    #[test]
    fn create_account_pins_epoch_one() {
        let (repo, _) = Repository::create_account(MemoryStore::new(), "pw", kdf()).unwrap();
        assert_eq!(repo.account().params.epoch, 1);
        assert_eq!(repo.chain().params_epoch, 1);
    }
}
