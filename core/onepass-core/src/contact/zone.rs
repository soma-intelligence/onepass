//! The mailbox of a contact pair, offered during the verification (sharing
//! spec 13.5, decision 16): the creator makes the pair's zone and hands the
//! other side a credential seed in a signed offer; neither side pins the
//! other without the zone.

use std::fmt;

use super::book::check_card_lineage;
use super::{ContactEntry, ContactLevel, SignedContactCard, pair_id};
use crate::crypto::HybridKemPublic;
use crate::lists::AccountList;
use crate::repo::Repository;
use crate::share::{
    AccessTarget, ContactZoneOffer, MemberRef, SignedContactZoneOffer, ZoneHome, ZoneSeed,
    open_zone_credential, verify_contact_zone_offer, wrap_zone_credential,
};
use crate::store::{Record, RecordStore, Zone};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

fn no_zone() -> Error {
    ValidationError {
        field: "contact".into(),
        reason: "no zone",
    }
    .into()
}

/// Who creates the pair's mailbox: at a distance the inviter, face to face
/// the smaller account id.
pub fn is_contact_zone_creator(me: Id, peer: Id, remote_inviter: Option<Id>) -> bool {
    match remote_inviter {
        Some(inviter) => inviter == me,
        None => me < peer,
    }
}

/// The creator's side between `prepare_contact_zone` and
/// `seal_contact_zone_offer`: the app makes the child mailbox (kind
/// `Contact`, owner `owner_public_key`) and grants `peer_public_key`
/// (`ZoneRole::Write`). The peer's seed lives only here, in memory.
pub struct ContactZonePlan {
    pub zone: Zone,
    pub owner_public_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    peer_seed: ZoneSeed,
    peer: MemberRef,
    peer_kem: HybridKemPublic,
}

impl fmt::Debug for ContactZonePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactZonePlan")
            .field("zone", &self.zone)
            .finish_non_exhaustive()
    }
}

impl<S: RecordStore> Repository<S> {
    fn pair_zone(&self, peer: Id) -> Zone {
        Zone::Contact(pair_id(self.account.params.account_id, peer))
    }

    /// The creator's first step: my `ZoneAccess` of the pair's zone without
    /// a home (a fresh seed; an existing access is kept, home included),
    /// and a fresh seed for the peer in the plan. Refused: a card that does
    /// not check, my own card.
    pub fn prepare_contact_zone(
        &mut self,
        peer: &SignedContactCard,
        now: i64,
    ) -> Result<ContactZonePlan> {
        let _ = now;
        let card = SignedContactCard::decode(&peer.encode())?;
        let keys = card.keys()?;
        check_card_lineage(&card)?;
        let peer_id = card.card.account_id;
        if peer_id == self.account.params.account_id {
            return Err(ValidationError {
                field: "contact".into(),
                reason: "own account",
            }
            .into());
        }
        let zone = self.pair_zone(peer_id);
        // A pair whose mailbox exists keeps it: a new offer only grants
        // the peer a fresh credential on it.
        let mine = match self.zone_access(AccessTarget::Zone(zone))? {
            Some((_, seed)) => seed,
            None => {
                let seed = ZoneSeed::generate()?;
                self.write_zone_access(AccessTarget::Zone(zone), None, &seed)?;
                seed
            }
        };
        let peer_seed = ZoneSeed::generate()?;
        Ok(ContactZonePlan {
            zone,
            owner_public_key: mine.public_key(),
            peer_public_key: peer_seed.public_key(),
            peer: MemberRef {
                account_id: peer_id,
                identity_id: keys.identity_id,
            },
            peer_kem: keys.kem_pub,
            peer_seed,
        })
    }

    /// The creator's second step, once the mailbox exists at `home`: my
    /// access gets its home, and the offer for the peer is signed and
    /// encoded.
    pub fn seal_contact_zone_offer(
        &mut self,
        plan: ContactZonePlan,
        home: ZoneHome,
    ) -> Result<Vec<u8>> {
        home.check()?;
        self.set_zone_home(AccessTarget::Zone(plan.zone), home.clone())?;
        let credential = wrap_zone_credential(
            &plan.peer_kem,
            &plan.peer_seed,
            plan.zone,
            home.mailbox_id,
            &plan.peer,
        )?;
        let Zone::Contact(pair) = plan.zone else {
            return Err(IntegrityError::WrongContext.into());
        };
        let offer = ContactZoneOffer {
            pair_id: pair,
            home,
            creator: self.me(),
            credential,
        };
        Ok(SignedContactZoneOffer::sign(offer, &self.account.keyset().signing)?.encode())
    }

    /// The zone side of a pin (decision 16): as the creator, my access of
    /// the pair's zone with its home and no offer from the peer; as the
    /// other side, the peer's offer checked against its card (signature,
    /// pair, creator), its seed opened for me, and the access record to
    /// write with the pin. `Validation("contact", "no zone")` otherwise.
    pub(super) fn contact_zone_on_pin(
        &mut self,
        card: &SignedContactCard,
        creator: bool,
        offer: Option<&[u8]>,
    ) -> Result<Option<(Record, Option<u64>)>> {
        let peer_id = card.card.account_id;
        if peer_id == self.account.params.account_id {
            return Err(ValidationError {
                field: "contact".into(),
                reason: "own account",
            }
            .into());
        }
        let zone = self.pair_zone(peer_id);
        if creator {
            if offer.is_some() {
                return Err(ValidationError {
                    field: "contact".into(),
                    reason: "offer from the non-creator",
                }
                .into());
            }
            return match self.zone_access(AccessTarget::Zone(zone))? {
                Some((a, _)) if a.home.is_some() => Ok(None),
                _ => Err(no_zone()),
            };
        }
        let bytes = offer.ok_or_else(no_zone)?;
        let keys = card.keys()?;
        let me = self.me();
        let Zone::Contact(pair) = zone else {
            return Err(no_zone());
        };
        let offer = verify_contact_zone_offer(bytes, &keys.sign_pub, &me, pair)?;
        if offer.creator.account_id != peer_id || offer.creator.identity_id != keys.identity_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let seed = open_zone_credential(
            self.account.keyset(),
            &offer.credential,
            zone,
            offer.home.mailbox_id,
            &me,
        )?;
        let access = self.zone_access_record(AccessTarget::Zone(zone), Some(offer.home), &seed)?;
        Ok(Some(access))
    }

    /// `pin_contact` with `extra` private records in the same transaction.
    pub(super) fn pin_with(
        &mut self,
        card: &SignedContactCard,
        level: ContactLevel,
        transcript_hash: [u8; 32],
        now: i64,
        extra: Option<(Record, Option<u64>)>,
    ) -> Result<ContactEntry> {
        let (entry, write) = self.plan_pin(card, level, transcript_hash, now)?;
        let mut writes: Vec<(Zone, Record, Option<u64>)> = Vec::new();
        let mut seen = None;
        if let Some((current, entries)) = write {
            let (rec, expected, body) = self.list_write(current.as_ref(), entries)?;
            writes.push((Zone::Private, rec, expected));
            seen = Some(body.seen());
        }
        if let Some((r, e)) = extra {
            writes.push((Zone::Private, r, e));
        }
        if !writes.is_empty() {
            self.store.put_all_zoned(writes, vec![], None, &[])?;
        }
        if let Some(s) = seen {
            ContactEntry::set_seen(&mut self.chain, s);
        }
        Ok(entry)
    }
}
