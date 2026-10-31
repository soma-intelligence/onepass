//! Following another account's lineage from a pinned head (sharing spec
//! 5.5 and 12.3 point 1).
//!
//! A contact pins the genesis and a head of the account it verified. A
//! newer head is checked the way a restored device of key rotation v2
//! checks a roster: each rotation is signed by a device of its parent's
//! roster (the genesis creator or the rotation's roster, plus the intros
//! accepted under that parent), with that roster's key, never with a key
//! the rotation itself carries, and by the new identity it names.
//!
//! This proves that a device of the account made the rotation, not which
//! device was honest (spec 12.1): nothing here picks between siblings.
//! Two valid children of the same record give `Forked`, whatever their
//! exclusions say; the user decides (spec 12.3 point 4). Withholding
//! records or intros can only stop the walk earlier.
//!
//! Pure: no clock, no I/O, no randomness.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::IdentityVerifyingKey;
use crate::lineage::{
    LineageRecord, RosterEntry, RotationBody, Signed, SignedIntro, verify_intro,
    verify_intro_identity, verify_rotation,
};
use crate::trust::LineageHead;
use crate::{Error, Id, Result};

use super::MAX_CARD_INTROS_PER_RECORD;

/// What a contact pinned of another account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignPin {
    pub account_id: Id,
    /// Lineage hash of the account's genesis.
    pub genesis: [u8; 32],
    pub head: LineageHead,
    /// The identity of `head`.
    pub identity_pub: IdentityVerifyingKey,
}

/// Where the account's lineage stands against the pin.
///
/// `Advanced` holds the rotation body as the plan's interface names it, not
/// boxed: one value per call, never kept in bulk.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignLineage {
    /// No valid child of the pinned head.
    Same,
    /// One valid rotation after another from the pinned head.
    Advanced {
        /// Lineage hashes after the pinned head, oldest first.
        chain: Vec<[u8; 32]>,
        head: LineageHead,
        /// The identity of the new head.
        identity_pub: IdentityVerifyingKey,
        last_rotation: RotationBody,
    },
    /// Two or more valid children of one record (the pinned head or one of
    /// its valid descendants): sorted lineage hashes.
    Forked { siblings: Vec<[u8; 32]> },
    /// The records do not lead from the pinned genesis to the pinned head.
    Unknown,
}

/// The roster of the genesis or rotation whose lineage hash is `head`,
/// plus the intros bound to `head` that extend it (spec 5.5), sorted by
/// device id. An intro is accepted when its device is not yet a member and
/// it verifies under its introducer, a member (`verify_intro`); a kit
/// self-intro (`introducer == entry.device_id`) also needs the signature
/// of `head`'s identity. At most `MAX_CARD_INTROS_PER_RECORD` intros.
///
/// The record's own signatures are not checked here: `follow_foreign`
/// calls this only on records it has validated. No record hashing to
/// `head` is `NotFound`; one that breaks the structural rules is
/// `InvalidFormat`.
pub fn roster_at(
    records: &[LineageRecord],
    intros: &[SignedIntro],
    head: &[u8; 32],
) -> Result<Vec<RosterEntry>> {
    let record = records
        .iter()
        .find(|r| r.hash() == *head)
        .ok_or(Error::NotFound)?;
    LineageRecord::decode(&record.encode())?;
    Ok(roster_with(record, intros, &BTreeSet::new()))
}

/// `roster_at` for a known record, where the devices of `excluded`
/// (revoked by an ancestor) are neither members nor introducers, nor
/// introduced.
fn roster_with(
    record: &LineageRecord,
    intros: &[SignedIntro],
    excluded: &BTreeSet<Id>,
) -> Vec<RosterEntry> {
    let head = record.hash();
    let pending: Vec<SignedIntro> = intros
        .iter()
        .filter(|i| i.body.head == head && i.body.account_id == record.account_id())
        .filter(|i| SignedIntro::decode(&i.encode()).is_ok())
        .cloned()
        .collect();
    let (mut members, _) = grow_roster(record, pending, excluded);
    members.sort_by_key(|e| e.device_id);
    members
}

/// The record's roster (the genesis creator, or the rotation's roster)
/// without `excluded`, grown by each intro of `pending` accepted, until
/// none more is. Returns the members and the intros accepted, in the order
/// accepted. `pending` is bound to `record` by the caller.
pub(super) fn grow_roster(
    record: &LineageRecord,
    mut pending: Vec<SignedIntro>,
    excluded: &BTreeSet<Id>,
) -> (Vec<RosterEntry>, Vec<SignedIntro>) {
    let mut members: Vec<RosterEntry> = match record {
        LineageRecord::Genesis(s) => vec![s.body.creator.clone()],
        LineageRecord::Rotation(s) => s.body.roster.clone(),
    };
    members.retain(|m| !excluded.contains(&m.device_id));
    let mut accepted = Vec::new();
    let mut progress = true;
    while progress && accepted.len() < MAX_CARD_INTROS_PER_RECORD {
        progress = false;
        let mut rest = Vec::new();
        for intro in pending {
            let b = &intro.body;
            let ok = accepted.len() < MAX_CARD_INTROS_PER_RECORD
                && !excluded.contains(&b.entry.device_id)
                && !members.iter().any(|m| m.device_id == b.entry.device_id)
                && if b.introducer == b.entry.device_id {
                    verify_intro_identity(&intro, record.identity_pub()).is_ok()
                        && verify_intro(&intro, &b.entry.sign_pub).is_ok()
                } else {
                    members
                        .iter()
                        .find(|m| m.device_id == b.introducer)
                        .is_some_and(|m| verify_intro(&intro, &m.sign_pub).is_ok())
                };
            if ok {
                members.push(b.entry.clone());
                accepted.push(intro);
                progress = true;
            } else {
                rest.push(intro);
            }
        }
        pending = rest;
    }
    (members, accepted)
}

/// Follow the account's lineage from `pin.head` (spec 5.5).
///
/// The records must hold the path from the pinned genesis to the pinned
/// head (each record's parent one generation down), the head under the
/// pinned identity: otherwise `Unknown`, never a step back. The path is
/// bound by its hashes, so its signatures are not checked again; every
/// device it revokes stays revoked for all descendants.
///
/// Then, from the head, while exactly one valid child exists, the walk
/// moves to it. A child of `p` is valid when: it is a rotation of this
/// account, one generation after `p`, that passes the structural rules;
/// its rotator is in `roster_at(p)` and was revoked by no record from the
/// genesis to `p`; the rotator's entry in its own roster carries the same
/// signing key; every device it revokes is in `roster_at(p)` or was
/// revoked before; and some copy of it verifies under the rotator's key
/// from `roster_at(p)` and under the identity it names. Devices revoked
/// by an ancestor can neither introduce nor be introduced. Two valid
/// children of one record give `Forked`.
pub fn follow_foreign(
    pin: &ForeignPin,
    records: &[LineageRecord],
    intros: &[SignedIntro],
) -> ForeignLineage {
    // Every copy of each record of this account that passes the strict
    // checks, by lineage hash; the rotations by parent.
    let mut by_hash: BTreeMap<[u8; 32], Vec<&LineageRecord>> = BTreeMap::new();
    let mut children: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>> = BTreeMap::new();
    for r in records {
        if r.account_id() != pin.account_id || LineageRecord::decode(&r.encode()).is_err() {
            continue;
        }
        let h = r.hash();
        if let Some(parent) = r.parent() {
            children.entry(parent).or_default().insert(h);
        }
        by_hash.entry(h).or_default().push(r);
    }

    // The pinned path, back to the genesis.
    let mut revoked: BTreeSet<Id> = BTreeSet::new();
    let mut at = pin.head.hash;
    let mut generation = pin.head.generation;
    loop {
        let Some(record) = by_hash.get(&at).map(|c| c[0]) else {
            return ForeignLineage::Unknown;
        };
        if record.generation() != generation {
            return ForeignLineage::Unknown;
        }
        if at == pin.head.hash && *record.identity_pub() != pin.identity_pub {
            return ForeignLineage::Unknown;
        }
        match record {
            LineageRecord::Genesis(_) => {
                if at != pin.genesis {
                    return ForeignLineage::Unknown;
                }
                break;
            }
            LineageRecord::Rotation(s) => {
                revoked.extend(s.body.revoked.iter().copied());
                at = s.body.parent;
                // A rotation's generation is at least 1.
                generation -= 1;
            }
        }
    }

    // The walk down.
    let mut chain: Vec<[u8; 32]> = Vec::new();
    let mut last: Option<&Signed<RotationBody>> = None;
    let mut at = pin.head.hash;
    let mut generation = pin.head.generation;
    loop {
        let parent = by_hash[&at][0];
        let roster = roster_with(parent, intros, &revoked);
        let mut valid: Vec<([u8; 32], &Signed<RotationBody>)> = Vec::new();
        for h in children.get(&at).into_iter().flatten() {
            if let Some(s) = valid_child(&by_hash[h], generation, &roster, &revoked) {
                valid.push((*h, s));
            }
        }
        match valid.as_slice() {
            [] => break,
            [(h, s)] => {
                chain.push(*h);
                revoked.extend(s.body.revoked.iter().copied());
                last = Some(s);
                at = *h;
                generation = s.body.generation;
            }
            _ => {
                return ForeignLineage::Forked {
                    siblings: valid.into_iter().map(|(h, _)| h).collect(),
                };
            }
        }
    }

    match last {
        None => ForeignLineage::Same,
        Some(s) => ForeignLineage::Advanced {
            head: LineageHead {
                generation: s.body.generation,
                hash: at,
            },
            chain,
            identity_pub: s.body.identity_pub.clone(),
            last_rotation: s.body.clone(),
        },
    }
}

/// The copy of a child that makes it valid under a parent of generation
/// `generation` whose roster (intros included, revoked devices removed) is
/// `roster`, `revoked` holding every device revoked from the genesis to
/// the parent. See `follow_foreign`.
fn valid_child<'a>(
    copies: &[&'a LineageRecord],
    generation: u64,
    roster: &[RosterEntry],
    revoked: &BTreeSet<Id>,
) -> Option<&'a Signed<RotationBody>> {
    let LineageRecord::Rotation(first) = copies.first()? else {
        return None;
    };
    let b = &first.body;
    if generation.checked_add(1) != Some(b.generation) || revoked.contains(&b.rotator) {
        return None;
    }
    let signer = roster.iter().find(|e| e.device_id == b.rotator)?;
    if b.roster
        .iter()
        .any(|e| e.device_id == b.rotator && e.sign_pub != signer.sign_pub)
    {
        return None;
    }
    let known = |id: &Id| roster.iter().any(|e| e.device_id == *id) || revoked.contains(id);
    if !b.revoked.iter().all(known) {
        return None;
    }
    copies.iter().find_map(|r| match r {
        LineageRecord::Rotation(s) if verify_rotation(s, &signer.sign_pub).is_ok() => Some(s),
        _ => None,
    })
}
