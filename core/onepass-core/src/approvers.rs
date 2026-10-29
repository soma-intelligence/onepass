//! The signed approver list (agent-ready spec 4): the public approval keys
//! of the account's devices, so that a Mac can send a signed request to the
//! iPhone and the iPhone can check who asked.
//!
//! It is a third signed, chained, monotone list (`lists`), beside the device
//! list and the vault list, signed by the account key under its own domain.
//! An entry holds a device's hybrid signing key (ML-DSA-87 + Ed25519), its
//! hybrid KEM key (ML-KEM-1024 + X25519) and its role. The private keys stay
//! on their device and never reach this module.
//!
//! An entry counts only while its `device_id` is in the device list and not
//! revoked there, and while it is not retired: revoking a device voids its
//! keys with no other write. Enrolling a device again retires its entry and
//! adds a new one.
//!
//! The list is never created lazily: it is born with the first
//! `register_this_approver`. Rolling it back is the device list's error
//! (`IntegrityError::DeviceListRollback`).

use aws_lc_rs::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use crate::chain::{ChainState, Seen};
use crate::crypto::HybridVerifyingKey;
use crate::crypto::kem::HybridKemPublic;
use crate::devices::{DeviceEntry, earliest, now};
use crate::lists::{AccountList, MonotoneEntry};
use crate::repo::Repository;
use crate::store::{RecordKind, RecordStore};
use crate::{Error, Id, Result, ValidationError};

/// What kind of device an approval key belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ApproverRole {
    Mac,
    Phone,
}

/// One approval key pair (public halves) of a device. Dates are Unix
/// seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverEntry {
    pub device_id: Id,
    pub sign_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
    pub role: ApproverRole,
    pub added_at: i64,
    pub retired_at: Option<i64>,
}

impl ApproverEntry {
    /// The fields no date moves, as one comparable value: the larger of two
    /// versions of an entry gives them to the merge.
    fn fixed(&self) -> (ApproverRole, &[u8], [u8; 32]) {
        (self.role, &self.kem_pub.mlkem, self.kem_pub.x25519)
    }

    fn with_monotone_of(&self, other: &Self) -> Self {
        ApproverEntry {
            added_at: self.added_at.min(other.added_at),
            retired_at: earliest(self.retired_at, other.retired_at),
            ..self.clone()
        }
    }

    fn is_active(&self) -> bool {
        self.retired_at.is_none()
    }
}

impl MonotoneEntry for ApproverEntry {
    /// A device holds several entries over time (one per key it enrolled),
    /// so the key of an entry is a hash of the device and its signing key,
    /// not the device id alone.
    fn id(&self) -> Id {
        let mut input = Vec::with_capacity(16 + self.sign_pub.mldsa.len() + 32);
        input.extend_from_slice(&self.device_id.0);
        input.extend_from_slice(&self.sign_pub.mldsa);
        input.extend_from_slice(&self.sign_pub.ed25519);
        let hash = digest(&SHA256, &input);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_ref()[..16]);
        Id(id)
    }

    /// Retirement wins, the earliest dates are kept; the other fields come
    /// from the larger of the two, so the merge is commutative.
    fn merge(&self, other: &Self) -> Self {
        if self.fixed() >= other.fixed() {
            self.with_monotone_of(other)
        } else {
            other.with_monotone_of(self)
        }
    }
}

impl AccountList for ApproverEntry {
    const KIND: RecordKind = RecordKind::ApproverList;
    const DOMAIN: &'static [u8] = crate::lists::APPROVER_LIST_DOMAIN;

    fn seen(chain: &ChainState) -> Option<Seen> {
        chain.approver_list
    }

    fn set_seen(chain: &mut ChainState, seen: Seen) {
        chain.approver_list = Some(seen);
    }
}

fn invalid(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

impl<S: RecordStore> Repository<S> {
    /// The approvers of the account that count: entries whose device is
    /// listed and not revoked and that are not retired, sorted by entry
    /// key. Brings the device and vault lists up to date first, and pins
    /// the approver list read as accepted (an older one replayed is
    /// `DeviceListRollback`). No list yet is no approver.
    pub fn approvers(&mut self) -> Result<Vec<ApproverEntry>> {
        self.maintain_lists(None)?;
        let devices = self.read_list::<DeviceEntry>()?;
        let Some(list) = self.read_list::<ApproverEntry>()? else {
            return Ok(Vec::new());
        };
        self.chain.approver_list = Some(list.body.seen());
        let live = |id: Id| {
            devices
                .as_ref()
                .and_then(|d| d.body.entry(id))
                .is_some_and(|d| d.revoked_at.is_none())
        };
        Ok(list
            .body
            .entries
            .into_iter()
            .filter(|e| e.is_active() && live(e.device_id))
            .collect())
    }

    /// Enroll this device's approval keys: its active entries are retired
    /// and the new one is added, in one list write. The same entry again
    /// writes nothing. Refused without a device id
    /// (`Validation("device")`: a store that keeps no chain state, or a
    /// device that never registered), on a revoked device
    /// (`Validation("device")`), for a key already retired
    /// (`Validation("approver key")`) and for a key already enrolled with
    /// other halves (`Validation("approver key")`).
    pub fn register_this_approver(
        &mut self,
        sign_pub: HybridVerifyingKey,
        kem_pub: HybridKemPublic,
        role: ApproverRole,
    ) -> Result<()> {
        let device_id = self.approver_device()?;
        let wanted = ApproverEntry {
            device_id,
            sign_pub,
            kem_pub,
            role,
            added_at: now(),
            retired_at: None,
        };
        let current = self.read_list::<ApproverEntry>()?;
        let mut entries = current
            .as_ref()
            .map(|c| c.body.entries.clone())
            .unwrap_or_default();
        let key = wanted.id();
        if let Some(same) = entries.iter().find(|e| e.id() == key) {
            return if same.retired_at.is_some() {
                Err(invalid("approver key", "retired"))
            } else if same.fixed() == wanted.fixed() {
                Ok(())
            } else {
                Err(invalid("approver key", "already enrolled"))
            };
        }
        let at = wanted.added_at;
        for e in entries
            .iter_mut()
            .filter(|e| e.device_id == device_id && e.is_active())
        {
            e.retired_at = Some(at);
        }
        entries.push(wanted);
        self.write_list(current.as_ref(), entries)
    }

    /// Retire this device's approval keys (it stops approving). Nothing to
    /// retire writes nothing. Refused like `register_this_approver` without
    /// a device id or on a revoked device.
    pub fn retire_this_approver(&mut self) -> Result<()> {
        let device_id = self.approver_device()?;
        let Some(current) = self.read_list::<ApproverEntry>()? else {
            return Ok(());
        };
        let at = now();
        let mut entries = current.body.entries.clone();
        let mut changed = false;
        for e in entries
            .iter_mut()
            .filter(|e| e.device_id == device_id && e.is_active())
        {
            e.retired_at = Some(at);
            changed = true;
        }
        if !changed {
            return Ok(());
        }
        self.write_list(Some(&current), entries)
    }

    /// This device's id after bringing the lists up to date, for an
    /// approver edit: none (no chain state kept, not registered) and
    /// revoked are `Validation("device")`.
    fn approver_device(&mut self) -> Result<Id> {
        self.maintain_lists(None)?;
        let id = self
            .chain
            .device_id
            .ok_or_else(|| invalid("device", "unregistered"))?;
        let revoked = self
            .read_list::<DeviceEntry>()?
            .and_then(|d| d.body.entry(id).map(|e| e.revoked_at.is_some()))
            .unwrap_or(false);
        if revoked {
            return Err(invalid("device", "revoked"));
        }
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntegrityError;
    use crate::crypto::{HybridKemSecret, HybridSigningKey, KdfParams, random_array};
    use crate::devices::{DeviceKind, DeviceMode};
    use crate::store::{Record, RecordKind, RecordStore};
    use crate::sync::SyncStore;

    fn repo() -> Repository<SyncStore> {
        let kdf = KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: random_array().unwrap(),
        };
        let store = SyncStore::open_in_memory().unwrap();
        Repository::create_account(store, "pw", kdf).unwrap().0
    }

    fn keys() -> (HybridVerifyingKey, HybridKemPublic) {
        (
            HybridSigningKey::generate()
                .unwrap()
                .verifying_key()
                .unwrap(),
            HybridKemSecret::generate().unwrap().public().unwrap(),
        )
    }

    fn entry(n: u8, retired_at: Option<i64>) -> ApproverEntry {
        let (sign_pub, kem_pub) = keys();
        ApproverEntry {
            device_id: Id([n; 16]),
            sign_pub,
            kem_pub,
            role: ApproverRole::Phone,
            added_at: 100,
            retired_at,
        }
    }

    fn stored(repo: &Repository<SyncStore>) -> Record {
        let id = repo.account().params.account_id;
        repo.store
            .get(RecordKind::ApproverList, id)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn register_then_list() {
        let mut repo = repo();
        assert_eq!(repo.approvers().unwrap(), vec![]);
        let (sign_pub, kem_pub) = keys();
        repo.register_this_approver(sign_pub.clone(), kem_pub.clone(), ApproverRole::Mac)
            .unwrap();
        let list = repo.approvers().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(Some(list[0].device_id), repo.this_device_id());
        assert_eq!(list[0].sign_pub, sign_pub);
        assert_eq!(list[0].kem_pub, kem_pub);
        assert_eq!(list[0].role, ApproverRole::Mac);
        assert_eq!(list[0].retired_at, None);
        assert_eq!(stored(&repo).version, 1);
    }

    #[test]
    fn register_needs_a_device_id() {
        use crate::store::MemoryStore;
        let kdf = KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: random_array().unwrap(),
        };
        let (mut repo, _) = Repository::create_account(MemoryStore::new(), "pw", kdf).unwrap();
        let (s, k) = keys();
        assert_eq!(
            repo.register_this_approver(s, k, ApproverRole::Mac),
            Err(invalid("device", "unregistered"))
        );
        assert_eq!(repo.approvers().unwrap(), vec![]);
    }

    #[test]
    fn reregister_retires_old_entry() {
        let mut repo = repo();
        let (s1, k1) = keys();
        repo.register_this_approver(s1.clone(), k1, ApproverRole::Phone)
            .unwrap();
        let (s2, k2) = keys();
        repo.register_this_approver(s2.clone(), k2, ApproverRole::Phone)
            .unwrap();
        let active = repo.approvers().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].sign_pub, s2);
        // The old entry is kept, retired.
        let all = repo
            .read_list::<ApproverEntry>()
            .unwrap()
            .unwrap()
            .body
            .entries;
        assert_eq!(all.len(), 2);
        let old = all.iter().find(|e| e.sign_pub == s1).unwrap();
        assert!(old.retired_at.is_some());
        assert_eq!(stored(&repo).version, 2);
    }

    #[test]
    fn reregister_same_key_is_refused_once_retired() {
        let mut repo = repo();
        let (s1, k1) = keys();
        repo.register_this_approver(s1.clone(), k1.clone(), ApproverRole::Phone)
            .unwrap();
        // Same entry again: nothing to write.
        repo.register_this_approver(s1.clone(), k1.clone(), ApproverRole::Phone)
            .unwrap();
        assert_eq!(stored(&repo).version, 1);
        repo.retire_this_approver().unwrap();
        assert_eq!(
            repo.register_this_approver(s1, k1, ApproverRole::Phone),
            Err(invalid("approver key", "retired"))
        );
    }

    #[test]
    fn revoked_device_entry_ignored() {
        let mut repo = repo();
        let (s, k) = keys();
        repo.register_this_approver(s, k, ApproverRole::Mac)
            .unwrap();
        // A second device registers an approver through the list directly.
        let other = entry(9, None);
        repo.add_device(DeviceEntry {
            device_id: other.device_id,
            name: "iPhone".into(),
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            added_at: 100,
            added_by: None,
            revoked_at: None,
        })
        .unwrap();
        let current = repo.read_list::<ApproverEntry>().unwrap().unwrap();
        let mut entries = current.body.entries.clone();
        entries.push(other.clone());
        repo.write_list(Some(&current), entries).unwrap();
        assert_eq!(repo.approvers().unwrap().len(), 2);
        repo.revoke_device(other.device_id).unwrap();
        let active = repo.approvers().unwrap();
        assert_eq!(active.len(), 1);
        assert_ne!(active[0].device_id, other.device_id);
    }

    #[test]
    fn unlisted_device_entry_ignored() {
        let mut repo = repo();
        let (s, k) = keys();
        repo.register_this_approver(s, k, ApproverRole::Mac)
            .unwrap();
        let stranger = entry(7, None);
        let current = repo.read_list::<ApproverEntry>().unwrap().unwrap();
        let mut entries = current.body.entries.clone();
        entries.push(stranger);
        repo.write_list(Some(&current), entries).unwrap();
        assert_eq!(repo.approvers().unwrap().len(), 1);
    }

    #[test]
    fn retired_entry_ignored() {
        let mut repo = repo();
        let (s, k) = keys();
        repo.register_this_approver(s, k, ApproverRole::Mac)
            .unwrap();
        assert_eq!(repo.approvers().unwrap().len(), 1);
        repo.retire_this_approver().unwrap();
        assert_eq!(repo.approvers().unwrap(), vec![]);
        // Retiring again changes nothing.
        let version = stored(&repo).version;
        repo.retire_this_approver().unwrap();
        assert_eq!(stored(&repo).version, version);
    }

    #[test]
    fn older_list_replayed_is_rollback() {
        let mut repo = repo();
        let (s, k) = keys();
        repo.register_this_approver(s, k, ApproverRole::Mac)
            .unwrap();
        let old = stored(&repo);
        let (s, k) = keys();
        repo.register_this_approver(s, k, ApproverRole::Mac)
            .unwrap();
        assert_eq!(repo.approvers().unwrap().len(), 1);
        repo.store.put(old).unwrap();
        assert_eq!(
            repo.approvers().unwrap_err(),
            Error::Integrity(IntegrityError::DeviceListRollback)
        );
    }

    #[test]
    fn merge_is_commutative_and_retire_wins() {
        let a = entry(1, Some(500));
        let b = ApproverEntry {
            retired_at: Some(300),
            added_at: 50,
            ..a.clone()
        };
        let c = ApproverEntry {
            retired_at: None,
            ..a.clone()
        };
        for (x, y) in [(&a, &b), (&a, &c), (&b, &c)] {
            assert_eq!(x.merge(y), y.merge(x));
            assert!(x.merge(y).retired_at.is_some());
        }
        let ab = a.merge(&b);
        assert_eq!(ab.retired_at, Some(300));
        assert_eq!(ab.added_at, 50);
        assert_eq!(a.merge(&b).merge(&c), a.merge(&b.merge(&c)));
        assert_eq!(a.merge(&a), a);
    }
}
