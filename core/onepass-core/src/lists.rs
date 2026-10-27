//! Signed, chained, monotone lists (milestone 2b, spec 4.1 and 4.2): the
//! device list (`devices`) and the vault list (`vaultlist`).
//!
//! A list is one record per account (id = account id, version = `seq`)
//! holding `postcard(Wire{body, sig})`, where `body` is the postcard of a
//! `ListBody{account_id, seq, prev_hash, entries}` and `sig` the hybrid
//! signature of the account signing key over it, under the list's domain.
//! The content is in clear: no secret, but the server can read it.
//!
//! Chaining is the manifests' one: `seq` grows, `prev_hash` is the SHA-256 of
//! the previous body, and the device remembers the last body accepted as a
//! `Seen{seq, hash}` (in `ChainState`). An older `seq`, or the same one with
//! another hash, or the next one that does not point at the remembered body,
//! is a rollback.
//!
//! Entries are a monotone set keyed by id: an entry never leaves, it only
//! moves forward (revoked, deleted). `merge` is their commutative union;
//! `rebase_entries` is the three-way merge a device runs when the server list
//! moved on while a local list waited to be sent.

use std::collections::BTreeMap;

use aws_lc_rs::digest::{SHA256, digest};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::chain::{ChainState, Seen};
use crate::crypto::{HybridSignature, HybridVerifyingKey};
use crate::devices::DeviceEntry;
use crate::repo::Repository;
use crate::store::{Record, RecordKind, RecordStore};
use crate::vaultlist::VaultListEntry;
use crate::{Error, Id, IntegrityError, Result};

/// Signature domain of the device list.
pub const DEVICE_LIST_DOMAIN: &[u8] = b"device-list";
/// Signature domain of the vault list.
pub const VAULT_LIST_DOMAIN: &[u8] = b"vault-list";

const BAD: Error = Error::InvalidFormat("signed list");

/// An entry of a monotone list.
pub trait MonotoneEntry: Clone + PartialEq + Serialize + DeserializeOwned {
    /// The key of the entry in its list.
    fn id(&self) -> Id;

    /// The union of two versions of one entry (same id): commutative,
    /// associative and idempotent, and never undoes a forward step
    /// (revocation, deletion), the earliest date being kept.
    fn merge(&self, other: &Self) -> Self;

    /// Like `merge`, but the fields an edit can change (a device name) are
    /// `self`'s: for an entry the local device changed and the other side
    /// did not. Defaults to `merge` for an entry with no such field.
    fn merge_preferring(&self, other: &Self) -> Self {
        self.merge(other)
    }
}

/// The signed content of a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListBody<E> {
    pub account_id: Id,
    pub seq: u64,
    /// SHA-256 of the previous body, zeros for the first one.
    pub prev_hash: [u8; 32],
    /// Sorted by id, no duplicates.
    pub entries: Vec<E>,
}

impl<E: MonotoneEntry> ListBody<E> {
    /// The body following `prev` (or the first one, seq 1) with `entries`,
    /// sorted by id. Duplicates are kept, and refused by `sign`.
    ///
    /// Errors: a `prev` at `u64::MAX` has no next seq,
    /// `InvalidFormat("signed list")`.
    pub fn next(prev: Option<&ListBody<E>>, account_id: Id, mut entries: Vec<E>) -> Result<Self> {
        entries.sort_by_key(MonotoneEntry::id);
        let (seq, prev_hash) = match prev {
            Some(p) => (p.seq.checked_add(1).ok_or(BAD)?, p.hash()),
            None => (1, [0u8; 32]),
        };
        Ok(ListBody {
            account_id,
            seq,
            prev_hash,
            entries,
        })
    }

    /// `postcard(self)`: the signed bytes.
    pub fn encode(&self) -> Vec<u8> {
        // Ids, integers, hashes, strings and enums: cannot fail.
        postcard::to_allocvec(self).expect("list body encodes")
    }

    /// SHA-256 of the encoded body: the next body's `prev_hash`.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.encode())
    }

    /// What a device remembers of this body once accepted.
    pub fn seen(&self) -> Seen {
        Seen {
            seq: self.seq,
            hash: self.hash(),
        }
    }

    /// The entry with this id.
    pub fn entry(&self, id: Id) -> Option<&E> {
        self.entries
            .binary_search_by_key(&id, MonotoneEntry::id)
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Seq at least 1, entries strictly sorted by id.
    fn well_formed(&self) -> bool {
        self.seq >= 1 && self.entries.windows(2).all(|w| w[0].id() < w[1].id())
    }
}

/// A list body and the account's signature over its encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedList<E> {
    pub body: ListBody<E>,
    pub sig: HybridSignature,
}

/// The stored form: the body as the exact bytes signed.
#[derive(Serialize, Deserialize)]
struct Wire {
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
    sig: HybridSignature,
}

impl<E: MonotoneEntry> SignedList<E> {
    /// The record data: `postcard(Wire{postcard(body), sig})`.
    pub fn encode(&self) -> Vec<u8> {
        let wire = Wire {
            body: self.body.encode(),
            sig: self.sig.clone(),
        };
        postcard::to_allocvec(&wire).expect("signed list encodes")
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, bytes).as_ref());
    out
}

/// The rollback error of the list signed under `domain`.
fn rollback(domain: &[u8]) -> Error {
    if domain == DEVICE_LIST_DOMAIN {
        IntegrityError::DeviceListRollback.into()
    } else {
        IntegrityError::VaultListRollback.into()
    }
}

/// Sign `body` with the account signing key under `domain`. Refuses what
/// `verify` would refuse: another account (`WrongContext`), seq 0 or
/// unsorted or duplicate entries (`InvalidFormat("signed list")`).
pub fn sign<E: MonotoneEntry>(
    account: &Account,
    domain: &[u8],
    body: ListBody<E>,
) -> Result<SignedList<E>> {
    if body.account_id != account.params.account_id {
        return Err(IntegrityError::WrongContext.into());
    }
    if !body.well_formed() {
        return Err(BAD);
    }
    let sig = account.keyset().signing.sign(domain, &body.encode())?;
    Ok(SignedList { body, sig })
}

/// Verify a stored list, which may come from a hostile store. In order: the
/// record decodes as a whole and its body is canonical (re-encodes to the
/// same bytes), otherwise `InvalidFormat("signed list")`; the signature
/// under `domain` (`Signature`); seq at least 1 and entries strictly sorted
/// (`InvalidFormat("signed list")`); then the history against `seen`, as for
/// manifests: an older seq, the same seq with another hash, or the next seq
/// that does not chain to `seen` is `DeviceListRollback` (domain
/// `DEVICE_LIST_DOMAIN`) or `VaultListRollback` (any other domain); a larger
/// gap cannot be chained and is accepted. The account id is the caller's to
/// check.
pub fn verify<E: MonotoneEntry>(
    signing_pub: &HybridVerifyingKey,
    domain: &[u8],
    bytes: &[u8],
    seen: Option<&Seen>,
) -> Result<ListBody<E>> {
    let wire: Wire = match postcard::take_from_bytes(bytes) {
        Ok((w, [])) => w,
        _ => return Err(BAD),
    };
    let body: ListBody<E> = match postcard::take_from_bytes(&wire.body) {
        Ok((b, [])) => b,
        _ => return Err(BAD),
    };
    if body.encode() != wire.body {
        return Err(BAD);
    }
    signing_pub.verify(domain, &wire.body, &wire.sig)?;
    if !body.well_formed() {
        return Err(BAD);
    }
    if let Some(last) = seen {
        let hash = sha256(&wire.body);
        let consistent = if body.seq < last.seq {
            false
        } else if body.seq == last.seq {
            hash == last.hash
        } else if body.seq - last.seq == 1 {
            body.prev_hash == last.hash
        } else {
            true
        };
        if !consistent {
            return Err(rollback(domain));
        }
    }
    Ok(body)
}

/// The union of two entry sets, by id, sorted: an entry on both sides is
/// `MonotoneEntry::merge`d. Commutative.
pub fn merge<E: MonotoneEntry>(local: &[E], remote: &[E]) -> Vec<E> {
    let mut out: BTreeMap<Id, E> = BTreeMap::new();
    for e in local.iter().chain(remote) {
        let merged = match out.get(&e.id()) {
            Some(prev) => prev.merge(e),
            None => e.clone(),
        };
        out.insert(e.id(), merged);
    }
    out.into_values().collect()
}

/// The entries of a local list rebuilt over the server's (spec 4.2): the
/// union of both, where an entry the local side changed since `ancestor`
/// (the list it was built on) keeps its edits and one it did not change
/// takes the server's (`merge_preferring`). Without an ancestor (a local
/// list created before any server list) entries on both sides are plainly
/// merged. Forward steps (revocation, deletion) always survive.
pub(crate) fn rebase_entries<E: MonotoneEntry>(
    ancestor: Option<&[E]>,
    local: &[E],
    remote: &[E],
) -> Vec<E> {
    let find = |set: &[E], id: Id| set.iter().find(|e| e.id() == id).cloned();
    let mut out = merge(local, remote);
    for e in &mut out {
        let id = e.id();
        let (Some(l), Some(r)) = (find(local, id), find(remote, id)) else {
            continue;
        };
        let Some(ancestor) = ancestor else {
            continue;
        };
        let base = find(ancestor, id);
        let local_changed = base.as_ref() != Some(&l);
        *e = if local_changed {
            l.merge_preferring(&r)
        } else {
            r.merge_preferring(&l)
        };
    }
    out
}

/// One of the account's two lists: its record kind, signature domain and
/// slot in the chain state.
pub(crate) trait AccountList: MonotoneEntry {
    const KIND: RecordKind;
    const DOMAIN: &'static [u8];
    fn seen(chain: &ChainState) -> Option<Seen>;
    fn set_seen(chain: &mut ChainState, seen: Seen);
}

/// A list as read from the store: the stored record version (the
/// conditional write expects it) and the verified body.
pub(crate) struct Stored<E> {
    pub(crate) version: u64,
    pub(crate) body: ListBody<E>,
}

/// The record of a list body, signed: id = account id, version = seq.
pub(crate) fn list_record<E: AccountList>(account: &Account, body: ListBody<E>) -> Result<Record> {
    let id = body.account_id;
    let version = body.seq;
    let signed = sign(account, E::DOMAIN, body)?;
    Ok(Record {
        id,
        kind: E::KIND,
        version,
        data: signed.encode(),
    })
}

/// Verify a stored list record of `account` against `seen`: `verify`, then
/// the record id and the body's account id must be the account's
/// (`WrongContext`).
pub(crate) fn open_record<E: AccountList>(
    account: &Account,
    rec: &Record,
    seen: Option<&Seen>,
) -> Result<ListBody<E>> {
    let body: ListBody<E> = verify(&account.params.signing_pub, E::DOMAIN, &rec.data, seen)?;
    let id = account.params.account_id;
    if rec.id != id || body.account_id != id {
        return Err(IntegrityError::WrongContext.into());
    }
    Ok(body)
}

impl<S: RecordStore> Repository<S> {
    /// The account's list of this kind, verified against the one this
    /// device last accepted (`ChainState`). No record is `None` when none
    /// was ever accepted (an account from before the lists: migration
    /// creates it), and a rollback when one was.
    pub(crate) fn read_list<E: AccountList>(&self) -> Result<Option<Stored<E>>> {
        let seen = E::seen(&self.chain);
        match self.store.get(E::KIND, self.account.params.account_id)? {
            Some(rec) => Ok(Some(Stored {
                version: rec.version,
                body: open_record(&self.account, &rec, seen.as_ref())?,
            })),
            None if seen.is_some() => Err(rollback(E::DOMAIN)),
            None => Ok(None),
        }
    }

    /// Take the stored lists like a first use: each is verified (signature,
    /// account) without the check against the one last accepted, and
    /// becomes the accepted one (`None` when there is none). For the
    /// owner's explicit choice of the server's state
    /// (`issue_restore_epoch_take_server`), after the pending lists were
    /// dropped; the next persist keeps these pins (`lists_forced`).
    pub(crate) fn take_server_lists(&mut self) -> Result<()> {
        let id = self.account.params.account_id;
        let device_list = match self.store.get(RecordKind::DeviceList, id)? {
            Some(rec) => Some(open_record::<DeviceEntry>(&self.account, &rec, None)?.seen()),
            None => None,
        };
        let vault_list = match self.store.get(RecordKind::VaultList, id)? {
            Some(rec) => Some(open_record::<VaultListEntry>(&self.account, &rec, None)?.seen()),
            None => None,
        };
        self.chain.device_list = device_list;
        self.chain.vault_list = vault_list;
        self.lists_forced = true;
        Ok(())
    }

    /// The signed record of the list following `current` (or the first
    /// one) with `entries`, and the version the write must expect.
    pub(crate) fn list_write<E: AccountList>(
        &self,
        current: Option<&Stored<E>>,
        entries: Vec<E>,
    ) -> Result<(Record, Option<u64>, ListBody<E>)> {
        let body = ListBody::next(
            current.map(|c| &c.body),
            self.account.params.account_id,
            entries,
        )?;
        let rec = list_record(&self.account, body.clone())?;
        Ok((rec, current.map(|c| c.version), body))
    }

    /// Write the list following `current` with `entries` (conditional on
    /// `current`'s version: a lost race is `Error::Conflict`) and remember it
    /// as accepted.
    pub(crate) fn write_list<E: AccountList>(
        &mut self,
        current: Option<&Stored<E>>,
        entries: Vec<E>,
    ) -> Result<()> {
        let (rec, expected, body) = self.list_write(current, entries)?;
        self.store.put_if_version(rec, expected)?;
        E::set_seen(&mut self.chain, body.seen());
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::account::NewAccount;
    use crate::crypto::{KdfParams, random_array};

    pub(crate) fn shared() -> &'static NewAccount {
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

    /// A test entry: a counter that only goes up, and a label edits change.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct E {
        id: Id,
        level: u8,
        label: String,
    }

    impl MonotoneEntry for E {
        fn id(&self) -> Id {
            self.id
        }
        fn merge(&self, other: &Self) -> Self {
            let label = self.label.clone().max(other.label.clone());
            E {
                id: self.id,
                level: self.level.max(other.level),
                label,
            }
        }
        fn merge_preferring(&self, other: &Self) -> Self {
            E {
                label: self.label.clone(),
                ..self.merge(other)
            }
        }
    }

    fn e(n: u8, level: u8, label: &str) -> E {
        E {
            id: Id([n; 16]),
            level,
            label: label.into(),
        }
    }

    fn signed(prev: Option<&ListBody<E>>, entries: Vec<E>) -> SignedList<E> {
        let a = &shared().account;
        let body = ListBody::next(prev, a.params.account_id, entries).unwrap();
        sign(a, VAULT_LIST_DOMAIN, body).unwrap()
    }

    fn check(bytes: &[u8], seen: Option<&Seen>) -> Result<ListBody<E>> {
        verify(
            &shared().account.params.signing_pub,
            VAULT_LIST_DOMAIN,
            bytes,
            seen,
        )
    }

    #[test]
    fn list_sign_verify_and_chain() {
        let first = signed(None, vec![e(2, 0, "b"), e(1, 0, "a")]);
        assert_eq!(first.body.seq, 1);
        assert_eq!(first.body.prev_hash, [0; 32]);
        // Sorted by id.
        assert_eq!(first.body.entries[0].id, Id([1; 16]));
        let body = check(&first.encode(), None).unwrap();
        assert_eq!(body, first.body);
        // The same list again is consistent with itself.
        check(&first.encode(), Some(&first.body.seen())).unwrap();

        let second = signed(Some(&first.body), vec![e(1, 1, "a")]);
        assert_eq!(second.body.seq, 2);
        assert_eq!(second.body.prev_hash, first.body.hash());
        check(&second.encode(), Some(&first.body.seen())).unwrap();
        // A larger gap cannot be chained and is accepted.
        let third = signed(Some(&second.body), vec![]);
        check(&third.encode(), Some(&first.body.seen())).unwrap();

        // Another domain, another account, a flipped byte: refused.
        let wrong_domain = verify::<E>(
            &shared().account.params.signing_pub,
            DEVICE_LIST_DOMAIN,
            &first.encode(),
            None,
        );
        assert_eq!(
            wrong_domain,
            Err(Error::Integrity(IntegrityError::Signature))
        );
        let mut bytes = first.encode();
        let n = bytes.len();
        bytes[n - 1] ^= 1;
        assert!(check(&bytes, None).is_err());
        // Trailing bytes.
        let mut bytes = first.encode();
        bytes.push(0);
        assert_eq!(check(&bytes, None), Err(BAD));
        // Signing refuses duplicates and another account.
        let a = &shared().account;
        let dup =
            ListBody::next(None, a.params.account_id, vec![e(1, 0, "a"), e(1, 1, "a")]).unwrap();
        assert_eq!(sign(a, VAULT_LIST_DOMAIN, dup).unwrap_err(), BAD);
        let other = ListBody::<E>::next(None, Id::new(), vec![]).unwrap();
        assert_eq!(
            sign(a, VAULT_LIST_DOMAIN, other).unwrap_err(),
            Error::Integrity(IntegrityError::WrongContext)
        );
    }

    #[test]
    fn list_rollback_and_fork_refused() {
        let first = signed(None, vec![e(1, 0, "a")]);
        let second = signed(Some(&first.body), vec![e(1, 1, "a")]);
        let seen = second.body.seen();
        // Older.
        assert_eq!(
            check(&first.encode(), Some(&seen)),
            Err(IntegrityError::VaultListRollback.into())
        );
        // Same seq, other content: a fork.
        let fork = signed(Some(&first.body), vec![e(1, 2, "a")]);
        assert_eq!(fork.body.seq, seen.seq);
        assert_eq!(
            check(&fork.encode(), Some(&seen)),
            Err(IntegrityError::VaultListRollback.into())
        );
        // The next seq built on another list.
        let elsewhere = signed(Some(&fork.body), vec![]);
        assert_eq!(
            check(&elsewhere.encode(), Some(&seen)),
            Err(IntegrityError::VaultListRollback.into())
        );
        // The device list has its own error.
        let a = &shared().account;
        let body = ListBody::next(None, a.params.account_id, vec![e(1, 0, "a")]).unwrap();
        let devices = sign(a, DEVICE_LIST_DOMAIN, body).unwrap();
        let later = sign(
            a,
            DEVICE_LIST_DOMAIN,
            ListBody::next(Some(&devices.body), a.params.account_id, vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify::<E>(
                &a.params.signing_pub,
                DEVICE_LIST_DOMAIN,
                &devices.encode(),
                Some(&later.body.seen())
            ),
            Err(IntegrityError::DeviceListRollback.into())
        );
    }

    #[test]
    fn merge_is_commutative_and_monotone() {
        let x = vec![e(1, 0, "a"), e(2, 3, "b"), e(4, 1, "z")];
        let y = vec![e(2, 1, "c"), e(3, 0, "d"), e(4, 2, "y")];
        let xy = merge(&x, &y);
        assert_eq!(xy, merge(&y, &x));
        assert_eq!(merge(&xy, &x), xy);
        assert_eq!(
            xy,
            vec![e(1, 0, "a"), e(2, 3, "c"), e(3, 0, "d"), e(4, 2, "z")]
        );
        // Nothing leaves, nothing goes back.
        for side in [&x, &y] {
            for old in side.iter() {
                let new = xy.iter().find(|n| n.id == old.id).unwrap();
                assert!(new.level >= old.level);
            }
        }
    }

    #[test]
    fn rebase_keeps_the_side_that_edited() {
        let ancestor = vec![e(1, 0, "old"), e(2, 0, "old")];
        // Local renamed 1; the server renamed 2 and moved 1 forward.
        let local = vec![e(1, 0, "a-local"), e(2, 0, "old"), e(5, 0, "new")];
        let remote = vec![e(1, 4, "old"), e(2, 0, "b-remote"), e(6, 0, "theirs")];
        let out = rebase_entries(Some(&ancestor), &local, &remote);
        assert_eq!(
            out,
            vec![
                e(1, 4, "a-local"),
                e(2, 0, "b-remote"),
                e(5, 0, "new"),
                e(6, 0, "theirs")
            ]
        );
        // Without an ancestor: the plain merge.
        assert_eq!(
            rebase_entries(None, &local, &remote),
            merge(&local, &remote)
        );
    }
}
