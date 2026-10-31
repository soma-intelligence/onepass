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
//! Merge (`MonotoneEntry::merge`), in this order:
//! - two geneses for one account id: the older entry stays (earliest
//!   `verified_at`, then the smaller encoding), never a silent replacement,
//!   and the book raises `ContactAlert::ContactBookConflict`;
//! - `Removed` wins, the earliest date kept;
//! - the pinned head of the higher generation brings its identity and
//!   keys, and its verification (level, date, device, transcript); at equal
//!   head `Verified` wins over `Link`, the earliest `verified_at` of the
//!   winning level;
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
    /// The contact's account rotated past the pinned head (`child` is the
    /// valid child of the pinned head, first seen at `seen_at`). The old
    /// identity is no longer used; the new one only after the explicit
    /// confirmation (sharing spec 12.3, a later task).
    KeysChanged {
        child: [u8; 32],
        seen_at: i64,
    },
    /// Removed by the owner: for good, never active again.
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
    pub transcript_hash: [u8; 32],
    /// The name the owner chose: never the card's, never the server's.
    pub name_local: String,
    pub state: ContactState,
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
    /// higher generation first, then (a fork) the smaller hash; at equal
    /// head the higher level, then the earliest date, device and
    /// transcript, then the smaller encoding of the keys, so that the order
    /// is total.
    #[allow(clippy::type_complexity)]
    fn rank(
        &self,
    ) -> (
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

/// The earliest removal of either side.
fn removal(a: &ContactEntry, b: &ContactEntry) -> Option<ContactState> {
    [a, b]
        .iter()
        .filter_map(|e| match e.state {
            ContactState::Removed { at } => Some(at),
            _ => None,
        })
        .min()
        .map(|at| ContactState::Removed { at })
}

/// The state of a merge at `head`: the earliest removal of either side,
/// otherwise the states of the sides at `head`, `KeysChanged` (the
/// earliest sighting, then the smaller child) over `Active`.
fn merged_state(a: &ContactEntry, b: &ContactEntry, head: &LineageHead) -> ContactState {
    if let Some(removed) = removal(a, b) {
        return removed;
    }
    [a, b]
        .iter()
        .filter(|e| e.pinned_head == *head)
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
            return ContactEntry {
                state: removal(self, other).unwrap_or(kept.state),
                ..kept.clone()
            };
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
            state: merged_state(self, other, &win.pinned_head),
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
fn check_card_lineage(card: &SignedContactCard) -> Result<()> {
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
    /// tasks). The card's name becomes the local name, as the suggestion the
    /// user accepted.
    ///
    /// Refused, with nothing written: a card of this account
    /// (`Validation`); a card that breaks the card rules (`InvalidFormat`);
    /// a card whose signatures or lineage do not hold (`Integrity`, see
    /// `SignedContactCard::keys` and `check_card_lineage`); no device id for
    /// this device (`Validation("device")`); a contact already in the book
    /// that was removed, or pinned at another head (moving the pin is the
    /// confirmation path's job, spec 12.3), or under another genesis (also
    /// raises `ContactBookConflict`): `Validation`. A contact pinned at the
    /// same head is merged (a higher level wins, the local name and a
    /// `KeysChanged` state stay). A lost race is `Conflict`.
    pub(crate) fn pin_contact(
        &mut self,
        card: &SignedContactCard,
        level: ContactLevel,
        transcript_hash: [u8; 32],
        now: i64,
    ) -> Result<ContactEntry> {
        let c = &card.card;
        if c.account_id == self.account.params.account_id {
            return Err(refused("contact", "own account"));
        }
        let card = SignedContactCard::decode(&card.encode())?;
        let keys = card.keys()?;
        check_card_lineage(&card)?;
        let c = &card.card;
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
            name_local: c.name.clone(),
            state: ContactState::Active,
        };
        let current = self.read_book()?;
        let mut entries = current
            .as_ref()
            .map(|b| b.body.entries.clone())
            .unwrap_or_default();
        let entry = match entries
            .iter()
            .position(|e| e.account_id == fresh.account_id)
        {
            None => {
                entries.push(fresh.clone());
                fresh
            }
            Some(i) => {
                let old = &entries[i];
                if matches!(old.state, ContactState::Removed { .. }) {
                    return Err(refused("contact", "removed"));
                }
                if old.genesis != fresh.genesis {
                    self.contact_alerts.push(ContactAlert::ContactBookConflict {
                        account_id: old.account_id,
                        kept: old.genesis,
                        refused: fresh.genesis,
                    });
                    return Err(refused("contact", "another genesis"));
                }
                if old.pinned_head != fresh.pinned_head {
                    return Err(refused("contact", "another head"));
                }
                let merged = old.merge_preferring(&fresh);
                if merged == *old {
                    return Ok(merged);
                }
                entries[i] = merged.clone();
                merged
            }
        };
        self.write_list(current.as_ref(), entries)?;
        Ok(entry)
    }

    /// `pin_contact` for the integration tests: the verification flows are
    /// later tasks.
    #[cfg(feature = "dev-fast-kdf")]
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

    /// Remove a contact for good (the first removal date stays). An
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
    /// reads `Same`, failing safe). `Advanced` turns an `Active` contact to
    /// `KeysChanged { child, seen_at: now }`, `child` being the valid child
    /// of the pinned head; head and keys stay (S22: adopting is the owner's
    /// decision). `Forked` and `Unknown` change nothing: the caller alerts.
    /// An unknown contact is `NotFound`, a removed one `Validation`.
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
        if let ForeignLineage::Advanced { chain, .. } = &result
            && entry.state == ContactState::Active
        {
            let child = chain[0];
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
    fn read_book(&mut self) -> Result<Option<Stored<ContactEntry>>> {
        let book = self.read_list::<ContactEntry>()?;
        if let Some(b) = &book {
            self.chain.contact_book = Some(b.body.seen());
        }
        Ok(book)
    }

    /// Apply `edit` to one entry and write the next book if it changed.
    fn edit_contact(
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
    fn this_device(&mut self) -> Result<Id> {
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
