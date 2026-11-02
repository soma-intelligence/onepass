//! Record storage. A store keeps opaque records and is not trusted: the
//! `Repository` verifies everything it reads back.

mod memory;
mod sqlite;
mod zone;

pub use memory::MemoryStore;
pub use sqlite::SqliteStore;
pub use zone::Zone;

use crate::chain::ChainState;
use crate::crypto::IdentityVerifyingKey;
use crate::share::ShareState;
use crate::trust::TrustState;
use crate::{Error, Id, IntegrityError, Result};

/// What a record holds. The numeric codes are the on-disk encoding: append
/// only, never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    AccountParams,
    Keyset,
    VaultKey,
    VaultMeta,
    Item,
    Manifest,
    /// The account's signed restore epoch (one record per identity, id =
    /// `account_record_id`).
    RestoreEpoch,
    /// The signed device list, id = `account_record_id`, version = its seq.
    DeviceList,
    /// The signed vault list, id = `account_record_id`, version = its seq.
    VaultList,
    /// A lineage record (genesis or rotation), id = `h[..16]`, version =
    /// its generation. Immutable: written once, never deleted by a client,
    /// remote deletions refused (spec 6.3).
    Lineage,
    /// A signed device intro, immutable (spec 6.4).
    DeviceIntro,
    /// A Secret Key delivery envelope, immutable (spec 6.5).
    KeyDelivery,
    /// The signed approver list, id = account id, version = its seq.
    ApproverList,
    /// The signed contact book (spec 19.1).
    ContactBook,
    /// A family or share membership record (spec 19.1).
    Membership,
    /// A member's public key record, written once (spec 19.1).
    MemberKey,
    /// A member's lineage record, written once (spec 19.1).
    MemberLineage,
    /// A request to rekey a share (spec 19.1).
    RekeyRequest,
    /// A family record (spec 19.1).
    Family,
    /// A recovery slot (spec 19.1).
    RecoverySlot,
    /// A recovery half (spec 19.1).
    RecoveryHalf,
    /// A recovery message (spec 19.1).
    RecoveryMessage,
    /// A sent item (spec 19.1).
    ItemSend,
    /// A share invitation (spec 19.1).
    ShareInvite,
    /// One chunk of an encrypted attachment (`crate::attachment`), id =
    /// `attachment::chunk_id`, data = `vault_id (16 bytes) ||
    /// postcard(AttachmentChunk)`, like an item record.
    Attachment,
    /// A signed follow acknowledgment (spec 6.8, O6), id = `ack_id(head,
    /// device_id)`, version = the head's generation. Immutable, display
    /// only.
    DeviceAck,
    /// Where the account syncs (`crate::synchome`), signed and chained like
    /// the lists: id = `account_record_id`, version = its seq. A deletion
    /// from the server is ignored, like a list's.
    SyncHome,
}

impl RecordKind {
    pub fn code(self) -> u8 {
        match self {
            Self::AccountParams => 1,
            Self::Keyset => 2,
            Self::VaultKey => 3,
            Self::VaultMeta => 4,
            Self::Item => 5,
            Self::Manifest => 6,
            Self::RestoreEpoch => 7,
            Self::DeviceList => 8,
            Self::VaultList => 9,
            Self::Lineage => 10,
            Self::DeviceIntro => 11,
            Self::KeyDelivery => 12,
            Self::ApproverList => 13,
            Self::ContactBook => 14,
            Self::Membership => 15,
            Self::MemberKey => 16,
            Self::MemberLineage => 17,
            Self::RekeyRequest => 18,
            Self::Family => 19,
            Self::RecoverySlot => 20,
            Self::RecoveryHalf => 21,
            Self::RecoveryMessage => 22,
            Self::ItemSend => 23,
            Self::ShareInvite => 24,
            Self::Attachment => 25,
            Self::DeviceAck => 26,
            Self::SyncHome => 27,
        }
    }

    pub fn from_code(code: u8) -> Result<RecordKind> {
        Ok(match code {
            1 => Self::AccountParams,
            2 => Self::Keyset,
            3 => Self::VaultKey,
            4 => Self::VaultMeta,
            5 => Self::Item,
            6 => Self::Manifest,
            7 => Self::RestoreEpoch,
            8 => Self::DeviceList,
            9 => Self::VaultList,
            10 => Self::Lineage,
            11 => Self::DeviceIntro,
            12 => Self::KeyDelivery,
            13 => Self::ApproverList,
            14 => Self::ContactBook,
            15 => Self::Membership,
            16 => Self::MemberKey,
            17 => Self::MemberLineage,
            18 => Self::RekeyRequest,
            19 => Self::Family,
            20 => Self::RecoverySlot,
            21 => Self::RecoveryHalf,
            22 => Self::RecoveryMessage,
            23 => Self::ItemSend,
            24 => Self::ShareInvite,
            25 => Self::Attachment,
            26 => Self::DeviceAck,
            27 => Self::SyncHome,
            _ => return Err(Error::InvalidFormat("record kind")),
        })
    }
}

impl RecordKind {
    /// The kinds whose data starts with the id of their vault (16 bytes):
    /// item records and attachment chunks.
    pub fn is_vault_prefixed(self) -> bool {
        matches!(self, Self::Item | Self::Attachment)
    }

    /// The kinds written once and never replaced or deleted (spec 6.3 to
    /// 6.5): a second write under the same key is a conflict, and a
    /// deletion coming from the server is refused.
    pub fn is_immutable(self) -> bool {
        matches!(
            self,
            Self::Lineage
                | Self::DeviceIntro
                | Self::KeyDelivery
                | Self::MemberKey
                | Self::MemberLineage
                | Self::DeviceAck
        )
    }

    /// The kinds whose deletion coming from the server is refused and
    /// logged by `commit_remote` (spec 13.2): the immutable chain records
    /// plus memberships and families, which only a signed change retires.
    pub fn server_deletion_refused(self) -> bool {
        matches!(
            self,
            Self::Lineage
                | Self::DeviceIntro
                | Self::KeyDelivery
                | Self::Membership
                | Self::Family
                | Self::MemberLineage
                | Self::DeviceAck
        )
    }
}

/// The id of the account records (`AccountParams`, `Keyset`, `RestoreEpoch`,
/// `DeviceList`, `VaultList`) of an identity: the account id for generation
/// 0 (`None`), `identity_id` of the identity key from generation 1 (spec
/// 6.6).
pub fn account_record_id(account_id: Id, identity: Option<&IdentityVerifyingKey>) -> Id {
    identity.map_or(account_id, crate::lineage::identity_id)
}

/// A stored record. Only `id`, `kind` and the opaque `version` are in clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: Id,
    pub kind: RecordKind,
    pub version: u64,
    pub data: Vec<u8>,
}

/// What a trust write requires of the stored trust state, checked inside
/// its transaction (`Error::Conflict` otherwise).
#[derive(Debug, Clone, Copy)]
pub(crate) enum TrustGuard<'a> {
    /// Anything, or nothing.
    Any,
    /// Exactly this one, byte for byte.
    Is(&'a TrustState),
    /// None at all (the first trust write).
    Absent,
}

impl TrustGuard<'_> {
    /// Whether the stored encoding passes.
    pub(crate) fn admits(&self, stored: Option<&[u8]>) -> bool {
        match self {
            TrustGuard::Any => true,
            TrustGuard::Is(t) => stored == Some(t.encode().as_slice()),
            TrustGuard::Absent => stored.is_none(),
        }
    }
}

/// Prefixes of the device-local metadata keys the repository may read and
/// write through `RecordStore::local_meta` and its siblings: never synced,
/// never a key the store uses itself (chain, trust, sync state).
pub const LOCAL_META_PREFIXES: &[&str] = &["contact_invite."];

/// `key` under one of `LOCAL_META_PREFIXES`, else `Validation`.
pub fn check_local_meta_key(key: &str) -> Result<()> {
    if LOCAL_META_PREFIXES
        .iter()
        .any(|p| key.len() > p.len() && key.starts_with(p))
    {
        Ok(())
    } else {
        Err(Error::Validation(crate::ValidationError {
            field: "meta".into(),
            reason: "not a local meta key",
        }))
    }
}

/// A `local_meta_keys` prefix: one of `LOCAL_META_PREFIXES` or longer
/// under it, else `Validation` (store-internal key names stay unlisted).
pub fn check_local_meta_prefix(prefix: &str) -> Result<()> {
    if LOCAL_META_PREFIXES.iter().any(|p| prefix.starts_with(p)) {
        Ok(())
    } else {
        Err(Error::Validation(crate::ValidationError {
            field: "meta".into(),
            reason: "not a local meta prefix",
        }))
    }
}

fn zones_unsupported() -> Error {
    Error::Store("zones unsupported".into())
}

fn local_meta_unsupported() -> Error {
    Error::Store("local meta unsupported".into())
}

/// A key-value store of records, keyed by `(kind, id)`. `put` replaces the
/// record with the same key; `delete` of a missing record is not an error.
pub trait RecordStore {
    /// `get` in `zone` (sharing spec 13.2). The default holds the private
    /// zone only: any other zone is `Store("zones unsupported")`.
    fn get_in(&self, zone: Zone, kind: RecordKind, id: Id) -> Result<Option<Record>> {
        match zone {
            Zone::Private => self.get(kind, id),
            _ => Err(zones_unsupported()),
        }
    }

    /// `list` in `zone`. Same default as `get_in`.
    fn list_in(&self, zone: Zone, kind: RecordKind) -> Result<Vec<Record>> {
        match zone {
            Zone::Private => self.list(kind),
            _ => Err(zones_unsupported()),
        }
    }

    /// Writes (each conditional on the version the caller read, as
    /// `put_all_if_version`) and deletions in any zones, the trust state
    /// when given, and the local state of shared vaults, all or nothing
    /// (`Conflict` on a version mismatch, nothing written in any zone).
    /// The default holds the private zone only.
    fn put_all_zoned(
        &mut self,
        writes: Vec<(Zone, Record, Option<u64>)>,
        deletes: Vec<(Zone, RecordKind, Id)>,
        trust: Option<&TrustState>,
        shares: &[ShareState],
    ) -> Result<()> {
        if writes.iter().any(|(z, _, _)| z.is_shared())
            || deletes.iter().any(|(z, _, _)| z.is_shared())
            || !shares.is_empty()
        {
            return Err(zones_unsupported());
        }
        let writes = writes.into_iter().map(|(_, r, v)| (r, v)).collect();
        let deletes = deletes.into_iter().map(|(_, k, id)| (k, id)).collect();
        match trust {
            Some(t) => self.put_all_if_version_with_trust(writes, deletes, None, t),
            None => self.put_all_if_version_and_delete(writes, deletes),
        }
    }

    /// The local pinned state of shared vault `vault`, never synced. The
    /// default holds none.
    fn share_state(&self, vault: Id) -> Result<Option<ShareState>> {
        let _ = vault;
        Ok(None)
    }

    /// Every shared vault's local state, by vault id.
    fn share_states(&self) -> Result<Vec<ShareState>> {
        Ok(Vec::new())
    }

    /// The shared zones this store holds records of (the private zone is
    /// not listed). The default holds none.
    fn zones(&self) -> Result<Vec<Zone>> {
        Ok(Vec::new())
    }

    /// Forget everything of shared `zone` on this device (pending writes
    /// included, and the local state of the vault of a `Vault` zone),
    /// pushing nothing. The default holds no shared zone.
    fn drop_zone(&mut self, zone: Zone) -> Result<()> {
        let _ = zone;
        Err(zones_unsupported())
    }

    fn put(&mut self, r: Record) -> Result<()>;
    /// Write `r` only if the stored record with its key has version
    /// `expected` (`None`: only if there is no such record), atomically.
    /// Otherwise nothing is written and the error is `Error::Conflict`.
    fn put_if_version(&mut self, r: Record, expected: Option<u64>) -> Result<()>;
    fn get(&self, kind: RecordKind, id: Id) -> Result<Option<Record>>;
    fn list(&self, kind: RecordKind) -> Result<Vec<Record>>;
    fn delete(&mut self, kind: RecordKind, id: Id) -> Result<()>;

    /// Remove this device's copy of a record, and only that: the Travel
    /// Mode takes a vault off the device without deleting it anywhere
    /// else. The default is `delete`, which is the same thing for a store
    /// that has no remote; a store that pushes deletions to a server
    /// (`crate::sync::SyncStore`) overrides it so nothing is pushed.
    fn evict(&mut self, kind: RecordKind, id: Id) -> Result<()> {
        self.delete(kind, id)
    }

    /// `evict` every record, all or nothing: on a failure the records
    /// already evicted are put back (best effort over every record; a
    /// failed put back is returned instead of the first error, so the
    /// caller never takes a partial undo for a clean one). A persistent
    /// store overrides it with one transaction.
    fn evict_all(&mut self, records: &[Record]) -> Result<()> {
        for (n, r) in records.iter().enumerate() {
            if let Err(e) = self.evict(r.kind, r.id) {
                let mut undo = Ok(());
                for d in records[..n].iter().rev() {
                    if let Err(e2) = self.put(d.clone()) {
                        undo = undo.and(Err(e2));
                    }
                }
                undo?;
                return Err(e);
            }
        }
        Ok(())
    }

    /// The restore epoch this device accepted or issued last, with the
    /// SHA-256 of its record data, if the store keeps it (device-local, not
    /// synced). Used to tell two different epochs with the same number
    /// apart (a fork). The default keeps nothing: the check is then skipped.
    fn restore_epoch_mark(&self) -> Result<Option<(u64, [u8; 32])>> {
        Ok(None)
    }

    /// Remember the mark of `restore_epoch_mark`. The default drops it.
    fn set_restore_epoch_mark(&mut self, _epoch: u64, _hash: [u8; 32]) -> Result<()> {
        Ok(())
    }

    /// The rows of `vault` (its manifest, its item records) that the
    /// server replaced or removed since the vault last loaded cleanly, for
    /// a store that keeps the device's own copy when the server falls
    /// behind (`crate::sync::SyncStore`). `None` (the default): the store
    /// keeps no such copy, and a vault that fails its checks is an error.
    fn kept_rows(&self, _vault: Id) -> Result<Option<Vec<Record>>> {
        Ok(None)
    }

    /// Make the device's verified copy of `vault` the visible one again,
    /// as pending writes: `manifest` (if it is not already the visible
    /// one), the item records `restore` it lists that only the kept rows
    /// still hold, and deletions of the vault's visible item records it
    /// does not list (`unlisted`). Done for a `write`, or when the server
    /// went back to an older manifest (so that the next push restores the
    /// server's copy); otherwise nothing is written. Only called when
    /// `kept_rows` is `Some`. The default refuses.
    fn keep_local_copy(
        &mut self,
        _vault: Id,
        _manifest: &Record,
        _restore: &[Record],
        _unlisted: &[Id],
        _write: bool,
    ) -> Result<()> {
        Err(Error::Store("no local copy".into()))
    }

    /// What the repository learned about a vault's server state, for the
    /// sync health (`crate::sync::VaultSyncHealth`). The default ignores it.
    fn vault_event(&mut self, _vault: Id, _event: VaultEvent) -> Result<()> {
        Ok(())
    }

    /// Write every record only if the stored record with its key has the
    /// version paired with it (`None`: no such record), all or nothing:
    /// on a conflict nothing is written (`Error::Conflict`). The default
    /// checks every version, then puts in order, which is atomic only for a
    /// store whose `put` cannot fail (in memory); a persistent store
    /// overrides it with one transaction (`SqliteStore`, `SyncStore`).
    fn put_all_if_version(&mut self, writes: Vec<(Record, Option<u64>)>) -> Result<()> {
        for (r, expected) in &writes {
            if self.get(r.kind, r.id)?.map(|c| c.version) != *expected {
                return Err(Error::Conflict);
            }
        }
        for (r, _) in writes {
            self.put(r)?;
        }
        Ok(())
    }

    /// `put_all_if_version`, then delete every `(kind, id)` of `deletes` in
    /// order, all or nothing where the store can: on a conflict nothing is
    /// written or deleted (`Error::Conflict`). The default writes then
    /// deletes, which is atomic only for a store whose `put` and `delete`
    /// cannot fail (in memory); a persistent store overrides it with one
    /// transaction (`SqliteStore`, `SyncStore`). A deletion the store
    /// refuses (a signed list record) fails the whole call there.
    fn put_all_if_version_and_delete(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
    ) -> Result<()> {
        self.put_all_if_version(writes)?;
        for (kind, id) in deletes {
            self.delete(kind, id)?;
        }
        Ok(())
    }

    /// Device-local metadata under `key` (see `LOCAL_META_PREFIXES`; any
    /// other key is `Validation`). A store that keeps none refuses.
    fn local_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _ = key;
        Err(local_meta_unsupported())
    }

    /// The local metadata keys that start with `prefix`, sorted. A prefix
    /// outside `LOCAL_META_PREFIXES` is `Validation` (see
    /// `check_local_meta_prefix`). A store that keeps none refuses.
    fn local_meta_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let _ = prefix;
        Err(local_meta_unsupported())
    }

    /// Set (`Some`) or remove (`None`) the local metadata under `key`. A
    /// store that keeps none refuses.
    fn set_local_meta(&mut self, key: &str, value: Option<&[u8]>) -> Result<()> {
        let _ = (key, value);
        Err(local_meta_unsupported())
    }

    /// `put_all_if_version`, and remove the local metadata under `key`,
    /// which must hold exactly `expected`, all or nothing: a version
    /// mismatch, or `key` missing or holding anything else, writes and
    /// removes nothing (`Error::Conflict`). What a one-time token needs:
    /// two callers racing on one key never both succeed. A store that
    /// keeps no local metadata refuses.
    fn put_all_if_version_taking_meta(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        key: &str,
        expected: &[u8],
    ) -> Result<()> {
        let _ = (writes, key, expected);
        Err(local_meta_unsupported())
    }

    /// The pinned chain state this store keeps for the device, read by the
    /// `Repository` unlock functions. `SyncStore` and `SqliteStore` persist
    /// one (meta key `chain`); other stores give the default, so each
    /// session pins on first use.
    fn chain_state(&self) -> Result<ChainState> {
        Ok(ChainState::default())
    }

    /// Whether `chain_state` gives back, in a later session, the chain state
    /// saved with `put_all_if_version_with_chain` (`SyncStore` and
    /// `SqliteStore`). A device registers itself in the device list only on
    /// such a store: its id must outlive the session.
    fn persists_chain(&self) -> bool {
        false
    }

    /// `put_all_if_version`, and on a store that persists the chain state,
    /// save `chain` in the same transaction (all or nothing). Other stores
    /// only write the records.
    fn put_all_if_version_with_chain(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: &ChainState,
    ) -> Result<()> {
        let _ = chain;
        self.put_all_if_version(writes)
    }

    /// The local trust state of this device (key rotation v2, spec 5.3), if
    /// one was saved. A store that keeps none refuses.
    fn trust_state(&self) -> Result<Option<TrustState>> {
        Err(Error::Store("trust state unsupported".into()))
    }

    /// A counter that changes whenever a row of the kinds a rotation prompt
    /// depends on (account params, keysets, lineage, intro and delivery
    /// records) is written or removed, local or fetched, on any connection
    /// (Task 19 carried item 6; `SyncStore`: SQLite triggers). `None`: the
    /// store keeps none, and the caller digests the rows themselves.
    fn lineage_stamp(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    /// `put_all_if_version_and_delete`, and the trust state (and `chain`,
    /// on a store that persists it) in the same transaction: all or nothing.
    /// A store that keeps no trust state refuses and writes nothing.
    fn put_all_if_version_with_trust(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
        chain: Option<ChainState>,
        trust: &TrustState,
    ) -> Result<()> {
        let _ = (writes, deletes, chain, trust);
        Err(Error::Store("trust state unsupported".into()))
    }

    /// The first trust state of this device (key rotation v2, spec 6.2,
    /// 15: a genesis at creation, or the migration of a legacy device),
    /// with `writes` (each conditional on its version), all or nothing,
    /// only while no trust state is stored (`Error::Conflict` otherwise:
    /// two migrations racing on one device never both write). `chain` is
    /// merged with the stored chain state, never replaces it (the device
    /// id and the lists accepted stay). A store that keeps no trust state
    /// refuses and writes nothing.
    fn put_first_trust(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: Option<ChainState>,
        trust: &TrustState,
    ) -> Result<()> {
        let _ = (writes, chain, trust);
        Err(Error::Store("trust state unsupported".into()))
    }

    /// `put_all_if_version_with_trust`, conditional on the stored trust
    /// state too: it is written only if the stored one is still `expected`
    /// (the one the caller read before deciding), byte for byte. Otherwise
    /// nothing is written and the error is `Error::Conflict`. Two writers
    /// of the trust state (a rotation, a follow, a rejection) can then
    /// never overwrite each other's decision. A store that keeps no trust
    /// state refuses and writes nothing.
    fn put_with_trust_cas(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        deletes: Vec<(RecordKind, Id)>,
        chain: Option<ChainState>,
        expected: &TrustState,
        trust: &TrustState,
    ) -> Result<()> {
        let _ = (writes, deletes, chain, expected, trust);
        Err(Error::Store("trust state unsupported".into()))
    }

    /// Erase everything this store holds for the device, in one
    /// transaction: every record, pending write and sync state, the trust
    /// state, the chain state and the device state. Only if the stored trust
    /// state is still `expected` (`Error::Conflict` otherwise, nothing
    /// erased). Irreversible: its only caller is the quarantine of key
    /// rotation v2 (`crate::repo::follow::quarantine_tick` 7 days after a
    /// valid lineage record revoked this device, or the user's "Effacer cet
    /// appareil", spec 8.4, R8, O1). A store that keeps no trust state
    /// refuses and erases nothing.
    fn erase_device(&mut self, expected: &TrustState) -> Result<()> {
        let _ = expected;
        Err(Error::Store("trust state unsupported".into()))
    }

    /// The local transaction of a rotation (spec 7.1 step 6): the writes,
    /// the chain state of the new identity (it replaces the stored one) and
    /// the trust state in state `Rotating { phase: 1 }`, conditional on the
    /// stored trust state being `expected` (`put_with_trust_cas`), plus
    /// what the push phases need (`rotation`), all or nothing. The default
    /// is `put_with_trust_cas` (a store that pushes nothing has no phases
    /// to drive).
    fn put_rotation(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: ChainState,
        expected: &TrustState,
        trust: &TrustState,
        rotation: &RotationPush,
    ) -> Result<()> {
        let _ = rotation;
        self.put_with_trust_cas(writes, Vec::new(), Some(chain), expected, trust)
    }

    /// Whether this device holds a write of `(kind, id)` it has not pushed
    /// yet (a store that pushes, `crate::sync::SyncStore`). The default
    /// pushes nothing: `false`.
    fn is_pending_write(&self, kind: RecordKind, id: Id) -> Result<bool> {
        let _ = (kind, id);
        Ok(false)
    }

    /// The vault key and vault meta rows of `vault` that a fetch replaced
    /// with other bytes, as this device held them before (key rotation v2,
    /// spec 9 and 10.4): a device that has not followed a rotation yet
    /// still reads its own copy of a vault the rotation re-sealed, and the
    /// replay of its own writes opens them with the retired keys. The
    /// default keeps none.
    fn retained_rows(&self, vault: Id) -> Result<Vec<Record>> {
        let _ = vault;
        Ok(Vec::new())
    }

    /// The own writes of `vault` were replayed under the identity this
    /// device follows now (`crate::repo::replay`): drop the vault's pending
    /// writes made under the identity it left (manifest, item records and
    /// tombstones, vault key and meta), their ancestor, the kept rows and
    /// the retained rows. The default keeps nothing, so it has nothing to
    /// drop.
    fn settle_replayed(&mut self, vault: Id) -> Result<()> {
        let _ = vault;
        Ok(())
    }

    /// Drop the retained rows of `vault` (`retained_rows`) and nothing
    /// else. The default keeps none.
    fn drop_retained(&mut self, vault: Id) -> Result<()> {
        let _ = vault;
        Ok(())
    }

    /// The local transaction of a follow (spec 7.2 step 3, Task 11): the
    /// `writes` (each conditional on its version: the device's
    /// acknowledgment of the new head, spec 6.8), the
    /// chain state and trust state of the new head, conditional on the
    /// stored trust state being `expected` (`put_with_trust_cas`), the
    /// retained rows of the own copies a switch keeps (`put_retained`), the
    /// pending rows `drop_pending` dropped without a deletion being queued
    /// (the phase-1 records of a rotation that lost before they went out),
    /// and what a rotation being pushed needed forgotten, all or nothing.
    ///
    /// The default is for a store that pushes nothing: it keeps no pending
    /// rows and no rotation push to forget. A row of `drop_pending` it
    /// reports pending (`is_pending_write`) would be left behind, so the
    /// default refuses then (`Error::Store`), nothing written: a store
    /// with pending rows implements this. Otherwise it writes the trust
    /// state (`put_with_trust_cas`), then the retained rows.
    fn put_follow(
        &mut self,
        writes: Vec<(Record, Option<u64>)>,
        chain: ChainState,
        expected: &TrustState,
        trust: &TrustState,
        retained: Vec<Record>,
        drop_pending: Vec<(RecordKind, Id)>,
    ) -> Result<()> {
        for (kind, id) in drop_pending {
            if self.is_pending_write(kind, id)? {
                return Err(Error::Store("pending rows to drop unsupported".into()));
            }
        }
        self.put_with_trust_cas(writes, Vec::new(), Some(chain), expected, trust)?;
        if retained.is_empty() {
            return Ok(());
        }
        self.put_retained(retained)
    }

    /// Replace retained rows (`retained_rows`) with `rows`, each a vault
    /// key or vault meta row, by kind and id, and drop this device's
    /// pending writes of those rows (key rotation v2, Task 11: a device
    /// following a switch keeps its own copy of a vault, its vault key
    /// wrapped again for the identity it follows, until its own writes are
    /// replayed; the key and meta it wrote under the identity it left move
    /// there and no longer hide the followed identity's). The default keeps
    /// none, so it writes nothing.
    fn put_retained(&mut self, rows: Vec<Record>) -> Result<()> {
        let _ = rows;
        Ok(())
    }

    /// Queue the server deletion of these item records, which this device
    /// holds as server rows and no device needs any more (R21: the content
    /// of a rotation that lost, Task 19 carried item 5). A store with a
    /// push queue sends each as a deletion until it is confirmed or the
    /// row is gone; nothing is deleted locally before. The default keeps
    /// no queue.
    fn collect_foreign_items(&mut self, ids: Vec<Id>) -> Result<()> {
        let _ = ids;
        Ok(())
    }

    /// Open a batch: every write until `batch_commit` or `batch_rollback`
    /// lands in one transaction where the store can. The default writes as
    /// it goes (no undo).
    fn batch_begin(&mut self) -> Result<()> {
        Ok(())
    }

    fn batch_commit(&mut self) -> Result<()> {
        Ok(())
    }

    fn batch_rollback(&mut self) -> Result<()> {
        Ok(())
    }
}

/// What the push phases of a rotation need beyond its records (spec 7.1):
/// the vaults it re-sealed (the `from_heads` keys, whose single-slot
/// records phase 2 overwrites, R21) and the blob ids of the item records
/// the `from_heads` manifests list (the only records phase 3 deletes,
/// R23). Kept by the store until the rotation is pushed.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RotationPush {
    pub vaults: Vec<Id>,
    pub collect: Vec<Id>,
}

const ROTATION_PUSH_VERSION: u8 = 1;

impl RotationPush {
    /// A version byte, then postcard; both lists sorted and unique.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![ROTATION_PUSH_VERSION];
        // Plain data (lists of ids): cannot fail.
        out.extend(postcard::to_allocvec(self).expect("rotation push encodes"));
        out
    }

    /// Decode what `encode` wrote: the whole buffer, a known version,
    /// sorted unique lists (`InvalidFormat("rotation push")`).
    pub fn decode(bytes: &[u8]) -> Result<RotationPush> {
        let bad = Error::InvalidFormat("rotation push");
        let Some((&ROTATION_PUSH_VERSION, body)) = bytes.split_first() else {
            return Err(bad);
        };
        let Ok((push, [])) = postcard::take_from_bytes::<RotationPush>(body) else {
            return Err(bad);
        };
        let sorted = |v: &[Id]| v.windows(2).all(|w| w[0] < w[1]);
        if !sorted(&push.vaults) || !sorted(&push.collect) {
            return Err(bad);
        }
        Ok(push)
    }
}

/// What the repository reports to the store about one vault
/// (`RecordStore::vault_event`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultEvent {
    /// The visible copy loaded and passed every check.
    Clean,
    /// The server's state failed the checks (`cause`); the device serves
    /// its own verified copy, manifest seq `seq`, instead.
    Behind { seq: u64, cause: IntegrityError },
    /// The rebase verified and adopted the server's newer state.
    CaughtUp,
    /// Nothing safe to serve or merge: no verified local copy, or a server
    /// manifest that forks from it (`seq`: the local copy's, 0 for none).
    Alert { seq: u64, cause: IntegrityError },
    /// A newer restore epoch with this vault among its heads was accepted:
    /// the owner took a safe exit (maybe on another device), so an alert
    /// from a fork now clears like one from staying behind, once the
    /// server serves the head cleanly.
    EpochAccepted,
}

/// Shared behavior checks, run against every store.
#[cfg(test)]
pub(crate) fn exercise(store: &mut dyn RecordStore) {
    let a = Id::new();
    let b = Id::new();
    let rec = |id, kind, version, data: &[u8]| Record {
        id,
        kind,
        version,
        data: data.to_vec(),
    };
    assert_eq!(store.get(RecordKind::Item, a).unwrap(), None);
    store.put(rec(a, RecordKind::Item, 1, b"one")).unwrap();
    store.put(rec(b, RecordKind::Item, 7, b"two")).unwrap();
    // Same id, other kind: a distinct record.
    store.put(rec(a, RecordKind::Manifest, 3, b"m")).unwrap();
    assert_eq!(
        store.get(RecordKind::Item, a).unwrap(),
        Some(rec(a, RecordKind::Item, 1, b"one"))
    );
    // Replace.
    store.put(rec(a, RecordKind::Item, 2, b"uno")).unwrap();
    let mut items = store.list(RecordKind::Item).unwrap();
    items.sort_by_key(|r| r.id);
    assert_eq!(
        items,
        vec![
            rec(a, RecordKind::Item, 2, b"uno"),
            rec(b, RecordKind::Item, 7, b"two")
        ]
    );
    assert_eq!(store.list(RecordKind::Keyset).unwrap(), vec![]);
    store.delete(RecordKind::Item, a).unwrap();
    store.delete(RecordKind::Item, a).unwrap();
    assert_eq!(store.get(RecordKind::Item, a).unwrap(), None);
    assert!(store.get(RecordKind::Manifest, a).unwrap().is_some());
    assert_eq!(store.list(RecordKind::Item).unwrap().len(), 1);

    // Conditional writes.
    let c = Id::new();
    store
        .put_if_version(rec(c, RecordKind::Manifest, 1, b"m1"), None)
        .unwrap();
    assert_eq!(
        store.put_if_version(rec(c, RecordKind::Manifest, 1, b"x"), None),
        Err(Error::Conflict)
    );
    store
        .put_if_version(rec(c, RecordKind::Manifest, 2, b"m2"), Some(1))
        .unwrap();
    assert_eq!(
        store.put_if_version(rec(c, RecordKind::Manifest, 2, b"y"), Some(1)),
        Err(Error::Conflict)
    );
    assert_eq!(
        store.put_if_version(rec(Id::new(), RecordKind::Manifest, 2, b"z"), Some(1)),
        Err(Error::Conflict)
    );
    assert_eq!(
        store.get(RecordKind::Manifest, c).unwrap(),
        Some(rec(c, RecordKind::Manifest, 2, b"m2"))
    );
    // Same id, other kind: not the same record.
    store
        .put_if_version(rec(c, RecordKind::Item, 9, b"i"), None)
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(kind: RecordKind, id: Id, version: u64, data: &[u8]) -> Record {
        Record {
            id,
            kind,
            version,
            data: data.to_vec(),
        }
    }

    #[test]
    fn lineage_put_twice_refused() {
        for kind in [
            RecordKind::Lineage,
            RecordKind::DeviceIntro,
            RecordKind::KeyDelivery,
            RecordKind::DeviceAck,
        ] {
            assert!(kind.is_immutable());
            let mut s = MemoryStore::default();
            let id = Id::new();
            s.put_if_version(rec(kind, id, 1, b"one"), None).unwrap();
            assert_eq!(
                s.put_if_version(rec(kind, id, 1, b"other"), None),
                Err(Error::Conflict)
            );
            assert_eq!(s.get(kind, id).unwrap().unwrap().data, b"one");
        }
        assert!(!RecordKind::AccountParams.is_immutable());
    }

    #[test]
    fn generation_zero_ids_unchanged() {
        let a = Id::new();
        assert_eq!(account_record_id(a, None), a);
        let k = crate::crypto::IdentityKey::generate()
            .unwrap()
            .verifying_key();
        assert_eq!(
            account_record_id(a, Some(&k)),
            crate::lineage::identity_id(&k)
        );
        assert_ne!(account_record_id(a, Some(&k)), a);
    }

    #[test]
    fn kind_codes_roundtrip() {
        for kind in [
            RecordKind::AccountParams,
            RecordKind::Keyset,
            RecordKind::VaultKey,
            RecordKind::VaultMeta,
            RecordKind::Item,
            RecordKind::Manifest,
            RecordKind::RestoreEpoch,
            RecordKind::DeviceList,
            RecordKind::VaultList,
            RecordKind::Lineage,
            RecordKind::DeviceIntro,
            RecordKind::KeyDelivery,
            RecordKind::ApproverList,
            RecordKind::ContactBook,
            RecordKind::Membership,
            RecordKind::MemberKey,
            RecordKind::MemberLineage,
            RecordKind::RekeyRequest,
            RecordKind::Family,
            RecordKind::RecoverySlot,
            RecordKind::RecoveryHalf,
            RecordKind::RecoveryMessage,
            RecordKind::ItemSend,
            RecordKind::ShareInvite,
            RecordKind::Attachment,
            RecordKind::DeviceAck,
            RecordKind::SyncHome,
        ] {
            assert_eq!(RecordKind::from_code(kind.code()).unwrap(), kind);
        }
        for (kind, code) in [
            (RecordKind::ContactBook, 14),
            (RecordKind::Membership, 15),
            (RecordKind::MemberKey, 16),
            (RecordKind::MemberLineage, 17),
            (RecordKind::RekeyRequest, 18),
            (RecordKind::Family, 19),
            (RecordKind::RecoverySlot, 20),
            (RecordKind::RecoveryHalf, 21),
            (RecordKind::RecoveryMessage, 22),
            (RecordKind::ItemSend, 23),
            (RecordKind::ShareInvite, 24),
        ] {
            assert_eq!(kind.code(), code);
        }
        assert!(RecordKind::MemberKey.is_immutable());
        assert!(RecordKind::MemberLineage.is_immutable());
        assert!(!RecordKind::Membership.is_immutable());
        assert_eq!(RecordKind::Lineage.code(), 10);
        assert_eq!(RecordKind::DeviceIntro.code(), 11);
        assert_eq!(RecordKind::KeyDelivery.code(), 12);
        // Frozen codes: the on-disk and CloudKit encoding.
        assert_eq!(RecordKind::RestoreEpoch.code(), 7);
        assert_eq!(RecordKind::DeviceList.code(), 8);
        assert_eq!(RecordKind::VaultList.code(), 9);
        assert_eq!(RecordKind::ApproverList.code(), 13);
        assert_eq!(RecordKind::Attachment.code(), 25);
        assert_eq!(RecordKind::SyncHome.code(), 27);
        assert_eq!(RecordKind::from_code(27).unwrap(), RecordKind::SyncHome);
        assert!(!RecordKind::SyncHome.is_immutable());
        assert!(RecordKind::Attachment.is_vault_prefixed());
        // Spec 6.8 (O6): code 13 went to the approver lists, the ack takes 26.
        assert_eq!(RecordKind::DeviceAck.code(), 26);
        assert!(RecordKind::DeviceAck.server_deletion_refused());
        assert_eq!(
            RecordKind::from_code(u8::MAX).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
        assert_eq!(
            RecordKind::from_code(0).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
        assert_eq!(
            RecordKind::from_code(u8::MAX).unwrap_err(),
            Error::InvalidFormat("record kind")
        );
    }
}
