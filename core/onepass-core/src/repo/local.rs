//! Local-only signatures and device state merge, for long-running servers
//! (MCP server, SSH agent, Travel Mode) that sign their own state and share
//! the device state file with other processes.

use super::{DeviceState, Repository};
use crate::crypto::sign::HybridSignature;
use crate::store::RecordStore;
use crate::{Error, Id, IntegrityError, Result};

/// Prefix of every local signature domain, so a local signature can never
/// be replayed as a signature of another part of the format (manifests...).
const LOCAL_PREFIX: &[u8] = b"local:";

fn local_domain(domain: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(LOCAL_PREFIX.len() + domain.len());
    d.extend_from_slice(LOCAL_PREFIX);
    d.extend_from_slice(domain);
    d
}

impl<S: RecordStore> Repository<S> {
    /// The id of the unlocked account.
    pub fn account_id(&self) -> Id {
        self.account.params.account_id
    }

    /// Sign `msg` with the account signing key under the domain
    /// `b"local:" || domain`.
    pub fn sign_local(&self, domain: &[u8], msg: &[u8]) -> Result<HybridSignature> {
        self.account
            .keyset()
            .signing
            .sign(&local_domain(domain), msg)
    }

    /// Verify a signature made by `sign_local` under the same `domain`.
    pub fn verify_local(&self, domain: &[u8], msg: &[u8], sig: &HybridSignature) -> Result<()> {
        self.account
            .params
            .signing_pub
            .verify(&local_domain(domain), msg, sig)
    }

    /// Merge a device state read from disk into the in-memory one.
    ///
    /// Per vault the higher `seq` wins; the same `seq` with another hash is
    /// a fork (`ManifestRollback`); a lower `seq` is ignored; unknown vaults
    /// are added. A pinned account of another account (id or identity key)
    /// is refused (`WrongContext`). The KDF floor only goes up. Everything
    /// is validated before anything is modified.
    pub fn adopt_device_state(&mut self, other: &DeviceState) -> Result<()> {
        if let Some(p) = &other.pinned
            && (p.account_id != self.account.params.account_id
                || p.identity_pub != self.account.params.identity_pub)
        {
            return Err(Error::Integrity(IntegrityError::WrongContext));
        }
        let mut take = Vec::new();
        for (id, theirs) in &other.last_seen {
            match self.device.last_seen.get(id) {
                None => take.push((*id, theirs.clone())),
                Some(mine) if theirs.seq > mine.seq => take.push((*id, theirs.clone())),
                Some(mine) if theirs.seq == mine.seq && theirs.hash != mine.hash => {
                    return Err(Error::Integrity(IntegrityError::ManifestRollback));
                }
                Some(_) => {}
            }
        }
        for (id, seen) in take {
            self.device.last_seen.insert(id, seen);
        }
        if let Some(theirs) = &other.pinned {
            match &mut self.device.pinned {
                None => self.device.pinned = Some(theirs.clone()),
                Some(mine) => {
                    let salt = mine.kdf_floor.salt;
                    let before = (mine.kdf_floor.m_kib, mine.kdf_floor.t, mine.kdf_floor.p);
                    mine.raise_floor(&theirs.kdf_floor);
                    let after = (mine.kdf_floor.m_kib, mine.kdf_floor.t, mine.kdf_floor.p);
                    if before == after {
                        mine.kdf_floor.salt = salt;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::account::{Account, NewAccount};
    use crate::crypto::{KdfParams, random_array};
    use crate::manifest::SeenManifest;
    use crate::store::{MemoryStore, Record, RecordKind};

    fn shared() -> &'static NewAccount {
        static N: OnceLock<NewAccount> = OnceLock::new();
        N.get_or_init(|| {
            let kdf = KdfParams {
                m_kib: 8192,
                t: 1,
                p: 1,
                salt: random_array().unwrap(),
            };
            Account::create_with_params("pw", kdf).unwrap()
        })
    }

    fn repo() -> Repository<MemoryStore> {
        let n = shared();
        let id = n.account.params.account_id;
        let mut store = MemoryStore::new();
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
        Repository::unlock(store, "pw", &n.secret_key, DeviceState::default()).unwrap()
    }

    fn seen(seq: u64, b: u8) -> SeenManifest {
        SeenManifest { seq, hash: [b; 32] }
    }

    fn with_seen(repo: &Repository<MemoryStore>, v: Id, s: SeenManifest) -> DeviceState {
        let mut d = repo.device_state().clone();
        d.last_seen.insert(v, s);
        d
    }

    #[test]
    fn local_signature_roundtrip() {
        let r = repo();
        assert_eq!(r.account_id(), shared().account.params.account_id);
        let m = b"message";
        let sig = r.sign_local(b"x", m).unwrap();
        r.verify_local(b"x", m, &sig).unwrap();
    }

    #[test]
    fn local_signature_is_domain_separated() {
        let r = repo();
        let m = b"message";
        let sig = r.sign_local(b"a", m).unwrap();
        assert!(r.verify_local(b"b", m, &sig).is_err());
        let sig = r.sign_local(b"manifest", m).unwrap();
        assert!(
            shared()
                .account
                .params
                .signing_pub
                .verify(b"manifest", m, &sig)
                .is_err()
        );
    }

    #[test]
    fn adopt_takes_higher_seq() {
        let mut r = repo();
        let v = Id::new();
        r.device.last_seen.insert(v, seen(1, 1));
        let disk = with_seen(&r, v, seen(3, 3));
        r.adopt_device_state(&disk).unwrap();
        assert_eq!(r.device_state().last_seen[&v], seen(3, 3));
    }

    #[test]
    fn adopt_ignores_lower_seq() {
        let mut r = repo();
        let v = Id::new();
        r.device.last_seen.insert(v, seen(5, 5));
        let disk = with_seen(&r, v, seen(2, 2));
        r.adopt_device_state(&disk).unwrap();
        assert_eq!(r.device_state().last_seen[&v], seen(5, 5));
    }

    #[test]
    fn adopt_refuses_fork() {
        let mut r = repo();
        let v = Id::new();
        let w = Id::new();
        r.device.last_seen.insert(v, seen(4, 1));
        let before = r.device_state().clone();
        let mut disk = with_seen(&r, v, seen(4, 2));
        disk.last_seen.insert(w, seen(1, 1));
        let err = r.adopt_device_state(&disk).unwrap_err();
        assert!(matches!(
            err,
            Error::Integrity(IntegrityError::ManifestRollback)
        ));
        assert_eq!(r.device_state(), &before);
    }

    #[test]
    fn adopt_refuses_other_account() {
        let mut r = repo();
        let before = r.device_state().clone();
        let mut disk = before.clone();
        disk.pinned.as_mut().unwrap().account_id = Id::new();
        disk.last_seen.insert(Id::new(), seen(1, 1));
        let err = r.adopt_device_state(&disk).unwrap_err();
        assert!(matches!(
            err,
            Error::Integrity(IntegrityError::WrongContext)
        ));
        assert_eq!(r.device_state(), &before);
    }

    #[test]
    fn adopt_keeps_max_kdf_floor() {
        let mut r = repo();
        let mine = r.device_state().pinned.clone().unwrap();
        let mut stronger = mine.clone();
        stronger.raise_floor(&KdfParams {
            m_kib: mine.kdf_floor.m_kib * 2,
            t: mine.kdf_floor.t + 1,
            p: mine.kdf_floor.p,
            salt: [9; 32],
        });
        let mut disk = r.device_state().clone();
        disk.pinned = Some(stronger.clone());
        r.adopt_device_state(&disk).unwrap();
        assert_eq!(r.device_state().pinned, Some(stronger.clone()));

        let mut weaker = mine.clone();
        weaker.kdf_floor.m_kib = 1;
        weaker.kdf_floor.t = 1;
        weaker.kdf_floor.salt = [3; 32];
        disk.pinned = Some(weaker);
        r.adopt_device_state(&disk).unwrap();
        assert_eq!(r.device_state().pinned, Some(stronger));
    }

    #[test]
    fn adopt_adds_unknown_vault() {
        let mut r = repo();
        let v = Id::new();
        let disk = with_seen(&r, v, seen(2, 7));
        r.adopt_device_state(&disk).unwrap();
        assert_eq!(r.device_state().last_seen[&v], seen(2, 7));
    }
}
