//! The signed contact book (sharing spec 5.4, S6, founder decision 8).
//!
//! One more signed, chained, monotone list of the account, cast in the
//! mould of the device and vault lists (`crate::lists`): kind
//! `RecordKind::ContactBook`, signed by the signing key of the account's
//! current identity under `CONTACT_BOOK_DOMAIN` (plan ruling A-7), record
//! id = the identity's record id (rotation spec 6.6), version = seq, last
//! accepted body pinned in `ChainState::contact_book`. It syncs between the
//! account's devices: a contact verified on one is usable on the others
//! without verifying again (S6). A book signed by a left identity no longer
//! verifies once this account rotated (spec 5.4): `Repository::rotate`
//! copies the book to the new identity at seq 1.
//!
//! An entry is keyed by the contact's account id. Its name is local: it
//! starts as the card's name the user accepted when pinning, and only
//! `rename_contact` changes it; no card or server ever does (spec 5.4).
//!
//! A removed contact can be added again, by a fresh `Verified` pin only:
//! the entry's `incarnation` goes up by one. A removal belongs to its
//! incarnation and never reaches a later one.
//!
//! Merge (`MonotoneEntry::merge`), in this order:
//! - two geneses for one account id: the older entry stays whole (earliest
//!   `verified_at`, then the smaller encoding), with its own state; the
//!   other side's incarnation and removal do not count (a forged genesis
//!   never wins by raising its counter, and never removes the kept
//!   entry). Never a silent replacement: the book raises
//!   `ContactAlert::ContactBookConflict`;
//! - the higher incarnation wins whole (head, keys, verification, state);
//! - within one incarnation `Removed` wins, the earliest date kept;
//! - the pinned head of the higher generation brings its identity and
//!   keys, and its verification (level, date, device, transcript); at equal
//!   head `Verified` wins over `Link`, the earliest `verified_at` of the
//!   winning level. Two heads of one generation (a fork the book should
//!   never hold: `pin_contact` refuses another head, `refresh_contact`
//!   never moves it) go to the smaller hash, deterministically; the
//!   confirmation path (spec 12.3 points 3 and 4, a later task) must alert
//!   instead of writing such a pair;
//! - at equal head `KeysChanged` wins over `Active` (the earliest sighting);
//!   an entry at an older head brings no state;
//! - `name_local`: the larger, or `self`'s in `merge_preferring`.
//!
//! Within one genesis the merge is commutative, associative and idempotent.
//! Across two geneses it stays commutative and idempotent, and keeps the
//! older of the two versions it compares: a book holds one version per id,
//! and only a forged genesis brings a second one (the alert).

use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use super::SignedContactCard;
use super::card::check_name;
use super::lineage::{ForeignLineage, ForeignPin, LegacyIntros, follow_foreign};
use crate::chain::{ChainState, Seen};
use crate::crypto::{HybridKemPublic, HybridVerifyingKey, IdentityVerifyingKey};
use crate::lineage::{LineageRecord, SignedIntro, verify_genesis};
use crate::lists::{AccountList, MonotoneEntry, Stored};
use crate::repo::Repository;
use crate::store::{RecordKind, RecordStore};
use crate::trust::LineageHead;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// Signature domain of the contact book (plan ruling A-7: spec 19.1 names
/// none; to add to its table).
pub const CONTACT_BOOK_DOMAIN: &[u8] = b"onepass/contact-book/v1";

/// How a contact was verified. `Verified > Link`. Founder decision 1: a
/// `Link` contact may only be given Read; Modify, Manage and recovery need
/// `Verified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContactLevel {
    /// A remote invitation, no comparison of fingerprints.
    Link,
    /// In person (QR) or by a compared safety number.
    Verified,
}

/// Where a contact stands. Dates are Unix seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactState {
    Active,
    /// A valid rotation of the contact's account was seen past the pinned
    /// head, first at `seen_at`: `child` is the valid child of the pinned
    /// head, or with a fork (two valid children of the pinned head or of a
    /// valid descendant) the smallest sibling. The old identity is no
    /// longer used (spec 12.3 point 1); the new one only after the explicit
    /// confirmation (spec 12.3, a later task).
    KeysChanged {
        child: [u8; 32],
        seen_at: i64,
    },
    /// Removed by the owner: this incarnation is never active again.
    Removed {
        at: i64,
    },
}

/// One contact of the book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactEntry {
    pub account_id: Id,
    /// Lineage hash of the contact's genesis.
    pub genesis: [u8; 32],
    /// The last head of the contact's lineage this account confirmed.
    pub pinned_head: LineageHead,
    /// The identity of `pinned_head`.
    pub identity_pub: IdentityVerifyingKey,
    pub sign_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
    pub level: ContactLevel,
    pub verified_at: i64,
    /// The device of this account that verified.
    pub verified_on: Id,
    /// Evidence only: the face-to-face transcript hash is
    /// `SHA-256(QR text || Hello)`, which commits to neither the key
    /// exchange nor the cards (the SAS over K is what binds the session),
    /// and is the same on both sides even under a swapped key exchange.
    pub transcript_hash: [u8; 32],
    /// The name the owner chose: never the card's, never the server's.
    pub name_local: String,
    pub state: ContactState,
    /// 0 at the first pin, one more at each re-add after a removal.
    pub incarnation: u64,
}

/// What the book could not merge on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactAlert {
    /// Two entries of one account id under two geneses: `kept` stays,
    /// `refused` was not taken (spec 5.4).
    ContactBookConflict {
        account_id: Id,
        kept: [u8; 32],
        refused: [u8; 32],
    },
}

impl ContactEntry {
    /// The pin `follow_foreign` starts from.
    pub fn pin(&self) -> ForeignPin {
        ForeignPin {
            account_id: self.account_id,
            genesis: self.genesis,
            head: self.pinned_head,
            identity_pub: self.identity_pub.clone(),
        }
    }

    /// Active and at least at level `need`.
    pub fn usable_for(&self, need: ContactLevel) -> bool {
        self.state == ContactState::Active && self.level >= need
    }

    fn bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("contact entry encodes")
    }

    /// The age order across geneses: the smaller is the older.
    fn age(&self) -> (i64, Vec<u8>) {
        (self.verified_at, self.bytes())
    }

    /// The order of the head and its verification: the larger wins. A
    /// higher incarnation first, then a higher generation, then (a fork)
    /// the smaller hash; at equal
    /// head the higher level, then the earliest date, device and
    /// transcript, then the smaller encoding of the keys, so that the order
    /// is total.
    #[allow(clippy::type_complexity)]
    fn rank(
        &self,
    ) -> (
        u64,
        u64,
        Reverse<[u8; 32]>,
        ContactLevel,
        Reverse<i64>,
        Reverse<Id>,
        Reverse<[u8; 32]>,
        Reverse<Vec<u8>>,
    ) {
        let keys = postcard::to_allocvec(&(&self.identity_pub, &self.sign_pub, &self.kem_pub))
            .expect("contact keys encode");
        (
            self.incarnation,
            self.pinned_head.generation,
            Reverse(self.pinned_head.hash),
            self.level,
            Reverse(self.verified_at),
            Reverse(self.verified_on),
            Reverse(self.transcript_hash),
            Reverse(keys),
        )
    }
}

/// What `plan_pin` decided: the entry, and the book to write (the current
/// one, the next entries) when it changes.
pub(super) type PinPlan = (
    ContactEntry,
    Option<(Option<Stored<ContactEntry>>, Vec<ContactEntry>)>,
);

/// The earliest removal among the sides of `incarnation`.
fn removal(a: &ContactEntry, b: &ContactEntry, incarnation: u64) -> Option<ContactState> {
    [a, b]
        .iter()
        .filter(|e| e.incarnation == incarnation)
        .filter_map(|e| match e.state {
            ContactState::Removed { at } => Some(at),
            _ => None,
        })
        .min()
        .map(|at| ContactState::Removed { at })
}

/// The state of a merge won by `win`: among the sides of its incarnation,
/// the earliest removal, otherwise the states of the sides at its head,
/// `KeysChanged` (the earliest sighting, then the smaller child) over
/// `Active`.
fn merged_state(a: &ContactEntry, b: &ContactEntry, win: &ContactEntry) -> ContactState {
    if let Some(removed) = removal(a, b, win.incarnation) {
        return removed;
    }
    [a, b]
        .iter()
        .filter(|e| e.incarnation == win.incarnation && e.pinned_head == win.pinned_head)
        .filter_map(|e| match e.state {
            ContactState::KeysChanged { child, seen_at } => Some((seen_at, child)),
            _ => None,
        })
        .min()
        .map_or(ContactState::Active, |(seen_at, child)| {
            ContactState::KeysChanged { child, seen_at }
        })
}

impl MonotoneEntry for ContactEntry {
    fn id(&self) -> Id {
        self.account_id
    }

    /// See the module doc.
    fn merge(&self, other: &Self) -> Self {
        if self.genesis != other.genesis {
            let (kept, _) = older(self, other);
            return kept.clone();
        }
        let win = if self.rank() >= other.rank() {
            self
        } else {
            other
        };
        ContactEntry {
            account_id: self.account_id,
            genesis: self.genesis,
            pinned_head: win.pinned_head,
            identity_pub: win.identity_pub.clone(),
            sign_pub: win.sign_pub.clone(),
            kem_pub: win.kem_pub.clone(),
            level: win.level,
            verified_at: win.verified_at,
            verified_on: win.verified_on,
            transcript_hash: win.transcript_hash,
            name_local: self.name_local.clone().max(other.name_local.clone()),
            state: merged_state(self, other, win),
            incarnation: win.incarnation,
        }
    }

    /// `merge`, keeping `self`'s local name.
    fn merge_preferring(&self, other: &Self) -> Self {
        ContactEntry {
            name_local: self.name_local.clone(),
            ..self.merge(other)
        }
    }
}

/// The older of two entries of different geneses, then the other.
fn older<'a>(a: &'a ContactEntry, b: &'a ContactEntry) -> (&'a ContactEntry, &'a ContactEntry) {
    if a.age() <= b.age() { (a, b) } else { (b, a) }
}

impl AccountList for ContactEntry {
    const KIND: RecordKind = RecordKind::ContactBook;
    const DOMAIN: &'static [u8] = CONTACT_BOOK_DOMAIN;

    fn seen(chain: &ChainState) -> Option<Seen> {
        chain.contact_book
    }

    fn set_seen(chain: &mut ChainState, seen: Seen) {
        chain.contact_book = Some(seen);
    }

    /// An id on both sides under two geneses (spec 5.4).
    fn conflicts(local: &[Self], remote: &[Self]) -> Vec<ContactAlert> {
        let mut out = Vec::new();
        for l in local {
            if let Some(r) = remote.iter().find(|r| r.account_id == l.account_id)
                && r.genesis != l.genesis
            {
                let (kept, refused) = older(l, r);
                out.push(ContactAlert::ContactBookConflict {
                    account_id: l.account_id,
                    kept: kept.genesis,
                    refused: refused.genesis,
                });
            }
        }
        out
    }
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// The card's lineage, followed from its own genesis (`follow_foreign`),
/// must lead to `card.head` under `card.identity_pub`, the genesis
/// carrying both its signatures: `Integrity(Signature)` otherwise.
pub(super) fn check_card_lineage(card: &SignedContactCard) -> Result<()> {
    let c = &card.card;
    let bad = || Error::Integrity(IntegrityError::Signature);
    let Some(LineageRecord::Genesis(g)) = c.lineage.first() else {
        return Err(bad());
    };
    verify_genesis(g).map_err(|_| bad())?;
    let pin = ForeignPin {
        account_id: c.account_id,
        genesis: c.genesis,
        head: LineageHead {
            generation: 0,
            hash: c.genesis,
        },
        identity_pub: g.body.identity_pub.clone(),
    };
    let ok = match follow_foreign(&pin, &c.lineage, &c.intros, &c.legacy()) {
        ForeignLineage::Same => c.head == pin.head && c.identity_pub == pin.identity_pub,
        ForeignLineage::Advanced {
            head, identity_pub, ..
        } => head == c.head && identity_pub == c.identity_pub,
        _ => false,
    };
    if ok { Ok(()) } else { Err(bad()) }
}

impl<S: RecordStore> Repository<S> {
    /// Every contact of the book, sorted by account id, removed ones
    /// included. The book read is remembered as accepted.
    pub fn contacts(&mut self) -> Result<Vec<ContactEntry>> {
        Ok(self
            .read_book()?
            .map(|b| b.body.entries)
            .unwrap_or_default())
    }

    /// The contact of this account id, removed or not.
    pub fn contact(&mut self, account_id: Id) -> Result<Option<ContactEntry>> {
        Ok(self
            .read_book()?
            .and_then(|b| b.body.entry(account_id).cloned()))
    }

    /// The alerts the book raised in this session, oldest first.
    pub fn contact_alerts(&self) -> &[ContactAlert] {
        &self.contact_alerts
    }

    /// Pin `card` in the book at `level`, after a verification whose
    /// transcript hashes to `transcript_hash` (the verification flows, later
    /// tasks). The card's name becomes the local name of a new contact, as
    /// the suggestion the user accepted.
    ///
    /// Refused, with nothing written: a card of this account
    /// (`Validation`); a card that breaks the card rules (`InvalidFormat`);
    /// a card whose signatures or lineage do not hold (`Integrity`, see
    /// `SignedContactCard::keys` and `check_card_lineage`); a contact
    /// already in the book under another genesis (`Validation`, and
    /// `ContactBookConflict` raised), or removed and pinned again at `Link`,
    /// or pinned at another head (moving the pin is the confirmation path's
    /// job, spec 12.3): `Validation`. Then this device needs an id: when it
    /// has none it is registered in the device list first (as `devices`
    /// does), and a device without one even so is `Validation("device")`.
    ///
    /// A removed contact pinned again at `Verified` comes back `Active` at
    /// the next incarnation, at the card's head, its local name kept. A
    /// contact pinned at the same head is merged (a higher level wins, the
    /// local name and a `KeysChanged` state stay). A lost race is
    /// `Conflict`.
    ///
    /// The verification flows pin through `pin_with` (zone.rs), which
    /// adds the contact zone's access in the same transaction; this form
    /// stays for the integration tests only.
    #[cfg(all(feature = "dev-fast-kdf", debug_assertions))]
    pub(crate) fn pin_contact(
        &mut self,
        card: &SignedContactCard,
        level: ContactLevel,
        transcript_hash: [u8; 32],
        now: i64,
    ) -> Result<ContactEntry> {
        let (entry, write) = self.plan_pin(card, level, transcript_hash, now)?;
        if let Some((current, entries)) = write {
            self.write_list(current.as_ref(), entries)?;
        }
        Ok(entry)
    }

    /// `pin_contact` up to the write: the entry, and the book to write
    /// (the current one, the next entries) when it changes.
    pub(super) fn plan_pin(
        &mut self,
        card: &SignedContactCard,
        level: ContactLevel,
        transcript_hash: [u8; 32],
        now: i64,
    ) -> Result<PinPlan> {
        if card.card.account_id == self.account.params.account_id {
            return Err(refused("contact", "own account"));
        }
        let card = SignedContactCard::decode(&card.encode())?;
        let keys = card.keys()?;
        check_card_lineage(&card)?;
        let c = &card.card;
        let current = self.read_book()?;
        let mut entries = current
            .as_ref()
            .map(|b| b.body.entries.clone())
            .unwrap_or_default();
        let at = entries.iter().position(|e| e.account_id == c.account_id);
        let mut incarnation = 0;
        let mut name_local = c.name.clone();
        if let Some(i) = at {
            let old = &entries[i];
            if old.genesis != c.genesis {
                self.contact_alerts.push(ContactAlert::ContactBookConflict {
                    account_id: old.account_id,
                    kept: old.genesis,
                    refused: c.genesis,
                });
                return Err(refused("contact", "another genesis"));
            }
            if matches!(old.state, ContactState::Removed { .. }) {
                if level != ContactLevel::Verified {
                    return Err(refused("contact", "removed"));
                }
                incarnation = old.incarnation.checked_add(1).ok_or(Error::Conflict)?;
                name_local = old.name_local.clone();
            } else if old.pinned_head != c.head {
                return Err(refused("contact", "another head"));
            }
        }
        let verified_on = self.this_device()?;
        let fresh = ContactEntry {
            account_id: c.account_id,
            genesis: c.genesis,
            pinned_head: c.head,
            identity_pub: c.identity_pub.clone(),
            sign_pub: keys.sign_pub,
            kem_pub: keys.kem_pub,
            level,
            verified_at: now,
            verified_on,
            transcript_hash,
            name_local,
            state: ContactState::Active,
            incarnation,
        };
        let entry = match at {
            None => {
                entries.push(fresh.clone());
                fresh
            }
            Some(i) => {
                let merged = entries[i].merge_preferring(&fresh);
                if merged == entries[i] {
                    return Ok((merged, None));
                }
                entries[i] = merged.clone();
                merged
            }
        };
        Ok((entry, Some((current, entries))))
    }

    /// `pin_contact` for the integration tests: the verification flows are
    /// later tasks.
    #[cfg(all(feature = "dev-fast-kdf", debug_assertions))]
    #[doc(hidden)]
    pub fn test_pin_contact(
        &mut self,
        card: &SignedContactCard,
        level: ContactLevel,
        transcript_hash: [u8; 32],
        now: i64,
    ) -> Result<ContactEntry> {
        self.pin_contact(card, level, transcript_hash, now)
    }

    /// Mark contact `account_id` `KeysChanged` for the integration tests
    /// (a lineage rotation of the contact is a later task's fixture).
    #[cfg(all(feature = "dev-fast-kdf", debug_assertions))]
    #[doc(hidden)]
    pub fn test_mark_keys_changed(&mut self, account_id: Id, now: i64) -> Result<()> {
        self.edit_contact(account_id, |e| {
            e.state = ContactState::KeysChanged {
                child: e.pinned_head.hash,
                seen_at: now,
            };
            Ok(())
        })
    }

    /// Set the local name of a contact. A name that breaks the card name
    /// rules, or a removed contact, is `Validation`; an unknown one
    /// `NotFound`.
    pub fn rename_contact(&mut self, account_id: Id, name: &str) -> Result<()> {
        check_name(name).map_err(|_| refused("name", "not a contact name"))?;
        self.edit_contact(account_id, |e| {
            if matches!(e.state, ContactState::Removed { .. }) {
                return Err(refused("contact", "removed"));
            }
            e.name_local = name.to_owned();
            Ok(())
        })
    }

    /// Remove a contact: its current incarnation for good (the first
    /// removal date stays); only a `Verified` pin brings it back. An
    /// unknown one is `NotFound`.
    pub fn remove_contact(&mut self, account_id: Id, now: i64) -> Result<()> {
        self.edit_contact(account_id, |e| {
            if !matches!(e.state, ContactState::Removed { .. }) {
                e.state = ContactState::Removed { at: now };
            }
            Ok(())
        })
    }

    /// Follow the contact's lineage from its pinned head (`follow_foreign`,
    /// with no legacy intros: a rotation only a legacy device could sign
    /// reads `Same`, failing safe). A valid rotation retires the old
    /// identity (spec 12.3 point 1): `Advanced` turns an `Active` contact to
    /// `KeysChanged { child, seen_at: now }`, `child` being the valid child
    /// of the pinned head, and so does `Forked`, `child` being the smallest
    /// sibling (the fork itself is the caller's to report, spec 12.3 point
    /// 4). Head and keys stay (S22: adopting is the owner's decision).
    /// `Same` and `Unknown` change nothing. An unknown contact is
    /// `NotFound`, a removed one `Validation`.
    pub fn refresh_contact(
        &mut self,
        account_id: Id,
        records: &[LineageRecord],
        intros: &[SignedIntro],
        now: i64,
    ) -> Result<ForeignLineage> {
        let entry = self.contact(account_id)?.ok_or(Error::NotFound)?;
        if matches!(entry.state, ContactState::Removed { .. }) {
            return Err(refused("contact", "removed"));
        }
        let legacy = LegacyIntros {
            intros: &[],
            genesis_params: None,
        };
        let result = follow_foreign(&entry.pin(), records, intros, &legacy);
        let child = match &result {
            ForeignLineage::Advanced { chain, .. } => chain.first().copied(),
            ForeignLineage::Forked { siblings } => siblings.iter().min().copied(),
            _ => None,
        };
        if let Some(child) = child
            && entry.state == ContactState::Active
        {
            self.edit_contact(account_id, |e| {
                if e.state == ContactState::Active {
                    e.state = ContactState::KeysChanged {
                        child,
                        seen_at: now,
                    };
                }
                Ok(())
            })?;
        }
        Ok(result)
    }

    /// The book, verified against the one last accepted, which it then
    /// becomes.
    pub(super) fn read_book(&mut self) -> Result<Option<Stored<ContactEntry>>> {
        let book = self.read_list::<ContactEntry>()?;
        if let Some(b) = &book {
            self.chain.contact_book = Some(b.body.seen());
        }
        Ok(book)
    }

    /// Apply `edit` to one entry and write the next book if it changed.
    pub(super) fn edit_contact(
        &mut self,
        account_id: Id,
        edit: impl FnOnce(&mut ContactEntry) -> Result<()>,
    ) -> Result<()> {
        let current = self.read_book()?.ok_or(Error::NotFound)?;
        let mut entries = current.body.entries.clone();
        let entry = entries
            .iter_mut()
            .find(|e| e.account_id == account_id)
            .ok_or(Error::NotFound)?;
        let before = entry.clone();
        edit(entry)?;
        if *entry == before {
            return Ok(());
        }
        self.write_list(Some(&current), entries)
    }

    /// This device's id in the device list (registering it first, as
    /// `devices` does), or else the trust state's.
    pub(super) fn this_device(&mut self) -> Result<Id> {
        if self.chain.device_id.is_none() {
            self.maintain_lists(None)?;
        }
        if let Some(id) = self.chain.device_id {
            return Ok(id);
        }
        match self.store.trust_state() {
            Ok(Some(t)) => Ok(t.me.device_id),
            _ => Err(refused("device", "no device id")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_ordered() {
        assert!(ContactLevel::Verified > ContactLevel::Link);
    }
}
