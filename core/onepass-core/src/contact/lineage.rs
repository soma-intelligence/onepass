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

use aws_lc_rs::digest;

use crate::account::AccountParams;
use crate::crypto::{HybridKemPublic, HybridVerifyingKey, IdentityVerifyingKey};
use crate::lineage::{
    GenesisBody, LineageRecord, RosterEntry, RotationBody, Signed, SignedIntro, SignedLegacyIntro,
    intro_id, verify_intro, verify_intro_identity, verify_legacy_intro, verify_rotation,
};
use crate::trust::LineageHead;
use crate::{Error, Id, Result};

use super::MAX_CARD_INTROS_PER_RECORD;

/// Most copies of one record (same lineage hash, other signatures) that
/// `follow_foreign` keeps and checks: exact duplicates count once, and the
/// copies with the smallest SHA-256 of their encoding are kept. A server
/// sending more bad copies can only hide the record (`Same`), which
/// withholding it does anyway.
pub const MAX_FOREIGN_COPIES: usize = 8;

/// The legacy (TOFU) devices of an account migrated from before key
/// rotation v2 (rotation spec 15, owner ruling O4), as a card carries
/// them.
#[derive(Debug, Clone, Copy, Default)]
pub struct LegacyIntros<'a> {
    /// Legacy intros bound to the genesis.
    pub intros: &'a [SignedLegacyIntro],
    /// The `AccountParams` record of the genesis identity, signed by it:
    /// its account signing key checks `intros`. Without it (or if it does
    /// not verify under the genesis identity), no legacy intro counts.
    pub genesis_params: Option<&'a [u8]>,
}

/// The legacy intros a genesis accepts (`accept_legacy_intros`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyAccepted {
    /// One entry per device id, sorted by device id.
    pub entries: Vec<RosterEntry>,
    /// Ids claimed with two different key pairs: neither key is trusted,
    /// and the id may not be introduced under the genesis either (spec 15
    /// step 3: excluded until verified).
    pub conflicting: BTreeSet<Id>,
}

fn same_keys(a: &RosterEntry, b: &RosterEntry) -> bool {
    a.sign_pub == b.sign_pub && a.kem_pub == b.kem_pub
}

fn keys_of(e: &RosterEntry) -> (&HybridVerifyingKey, &HybridKemPublic) {
    (&e.sign_pub, &e.kem_pub)
}

/// Spec 15 step 3, the part a lineage alone can check (the account-signed
/// device list is the own account's business, not a contact's): an intro
/// counts when it is bound to `genesis` (its hash and account), strictly
/// shaped, and verifies under `account_sign`, the account signing key of
/// the genesis identity (`verify_legacy_intro`). Once per id: an id named
/// with two different key pairs goes to `conflicting` and is not
/// accepted; with one key pair and several intros, the entry with the
/// smallest encoding is kept. The genesis creator's id is never claimed
/// by a legacy intro (the genesis names its key). At most
/// `MAX_CARD_INTROS_PER_RECORD` entries, the smallest ids first.
/// Deterministic: the result depends on the set of intros, not their
/// order.
pub fn accept_legacy_intros(
    genesis: &Signed<GenesisBody>,
    account_sign: &HybridVerifyingKey,
    intros: &[SignedLegacyIntro],
) -> LegacyAccepted {
    let genesis_hash = LineageRecord::Genesis(genesis.clone()).hash();
    let creator = genesis.body.creator.device_id;
    let mut claims: BTreeMap<Id, Vec<RosterEntry>> = BTreeMap::new();
    for i in intros {
        let b = &i.body;
        if b.account_id != genesis.body.account_id
            || b.genesis_hash != genesis_hash
            || b.entry.device_id == creator
            || SignedLegacyIntro::decode(&i.encode()).is_err()
            || verify_legacy_intro(i, account_sign).is_err()
        {
            continue;
        }
        claims
            .entry(b.entry.device_id)
            .or_default()
            .push(b.entry.clone());
    }
    let mut out = LegacyAccepted::default();
    for (id, mut entries) in claims {
        let first = keys_of(&entries[0]);
        if entries.iter().any(|e| keys_of(e) != first) {
            out.conflicting.insert(id);
            continue;
        }
        entries.sort_by_key(|e| postcard::to_allocvec(e).expect("roster entry encodes"));
        if out.entries.len() < MAX_CARD_INTROS_PER_RECORD {
            out.entries.push(entries.swap_remove(0));
        }
    }
    out
}

/// `accept_legacy_intros` with the signing key taken from
/// `legacy.genesis_params`, verified under the genesis identity and of
/// the genesis account. Nothing when the params do not verify.
fn legacy_of(genesis: &Signed<GenesisBody>, legacy: &LegacyIntros<'_>) -> LegacyAccepted {
    if legacy.intros.is_empty() {
        return LegacyAccepted::default();
    }
    let Some(bytes) = legacy.genesis_params else {
        return LegacyAccepted::default();
    };
    match AccountParams::decode_verified(bytes, &genesis.body.identity_pub) {
        Ok(p) if p.account_id == genesis.body.account_id => {
            accept_legacy_intros(genesis, &p.signing_pub, legacy.intros)
        }
        _ => LegacyAccepted::default(),
    }
}

/// What a contact pinned of another account: the last head it confirmed.
/// The pin moves only after the confirmation of spec 12.3 point 3 (the
/// rotation code, or QR in person for writer roles, founder decision 6),
/// never because `follow_foreign` returned `Advanced`. Keeping it at the
/// last confirmed head is also what lets a sibling revealed later come
/// back as `Forked`.
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
    /// One valid rotation after another from the pinned head. Never an
    /// adoption: it means the old identity is dropped at once and the
    /// contact goes to `KeysChanged` (spec 12.3 point 1). The new identity
    /// is used only after the confirmation of 12.3 point 3; until then the
    /// pin stays where it is.
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
/// plus the devices accepted under `head` (spec 5.5), sorted by device id.
///
/// Under a genesis, the legacy devices of `legacy` come first
/// (`accept_legacy_intros`). Then the intros bound to `head`, to a
/// fixpoint: an intro counts when its device is not yet a member and it
/// verifies under its introducer, a member (`verify_intro`); a kit
/// self-intro (`introducer == entry.device_id`) also needs the signature
/// of `head`'s identity. An id that the intros (or legacy intros) under
/// `head` name with two different key pairs is never introduced, so the
/// result depends on the set of intros, not their order. At most
/// `MAX_CARD_INTROS_PER_RECORD` intros.
///
/// This is the roster `head` itself grants: revocations by its ancestors
/// are not applied (`follow_foreign` applies them), so a caller must not
/// show its entries as current members. The record's own signatures are
/// not checked either. No record hashing to `head` is `NotFound`; one
/// that breaks the structural rules is `InvalidFormat`.
pub fn roster_at(
    records: &[LineageRecord],
    intros: &[SignedIntro],
    legacy: &LegacyIntros<'_>,
    head: &[u8; 32],
) -> Result<Vec<RosterEntry>> {
    let record = records
        .iter()
        .find(|r| r.hash() == *head)
        .ok_or(Error::NotFound)?;
    LineageRecord::decode(&record.encode())?;
    Ok(roster_with(record, intros, legacy, &BTreeSet::new()))
}

/// `roster_at` for a known record, where the devices of `excluded`
/// (revoked by an ancestor) are neither members nor introducers, nor
/// introduced.
fn roster_with(
    record: &LineageRecord,
    intros: &[SignedIntro],
    legacy: &LegacyIntros<'_>,
    excluded: &BTreeSet<Id>,
) -> Vec<RosterEntry> {
    let head = record.hash();
    let pending: Vec<SignedIntro> = intros
        .iter()
        .filter(|i| i.body.head == head && i.body.account_id == record.account_id())
        .filter(|i| SignedIntro::decode(&i.encode()).is_ok())
        .cloned()
        .collect();
    let legacy = match record {
        LineageRecord::Genesis(g) => legacy_of(g, legacy),
        LineageRecord::Rotation(_) => LegacyAccepted::default(),
    };
    let (mut members, _) = grow_roster(record, &legacy, pending, excluded);
    members.sort_by_key(|e| e.device_id);
    members
}

/// The record's roster (the genesis creator, or the rotation's roster),
/// then the accepted legacy entries (genesis only), without `excluded`,
/// grown by the intros of `pending` (bound to `record` by the caller) in
/// passes until none more is accepted.
///
/// Each pass looks only at intros that verify against the members as they
/// stood at the start of the pass (a forged intro never counts, so it can
/// never block an honest one), for ids that are not members, excluded or
/// in `legacy.conflicting`. Per id: if the verifying intros agree on the
/// key pair, the one with the smallest intro id is accepted; if they name
/// two key pairs, the id is refused for good. The outcome depends on the
/// set of intros only, never on their order. Returns the members and the
/// intros accepted, in the order accepted.
pub(super) fn grow_roster(
    record: &LineageRecord,
    legacy: &LegacyAccepted,
    mut pending: Vec<SignedIntro>,
    excluded: &BTreeSet<Id>,
) -> (Vec<RosterEntry>, Vec<SignedIntro>) {
    let mut members: Vec<RosterEntry> = match record {
        LineageRecord::Genesis(s) => vec![s.body.creator.clone()],
        LineageRecord::Rotation(s) => s.body.roster.clone(),
    };
    for e in &legacy.entries {
        if !members.iter().any(|m| m.device_id == e.device_id) {
            members.push(e.clone());
        }
    }
    members.retain(|m| !excluded.contains(&m.device_id));
    let mut refused = legacy.conflicting.clone();
    pending.sort_by_key(|i| intro_id(&i.body));

    let mut accepted = Vec::new();
    while accepted.len() < MAX_CARD_INTROS_PER_RECORD {
        let verifies = |intro: &SignedIntro| {
            let b = &intro.body;
            if b.introducer == b.entry.device_id {
                verify_intro_identity(intro, record.identity_pub()).is_ok()
                    && verify_intro(intro, &b.entry.sign_pub).is_ok()
            } else {
                members
                    .iter()
                    .find(|m| m.device_id == b.introducer)
                    .is_some_and(|m| verify_intro(intro, &m.sign_pub).is_ok())
            }
        };
        // Candidate intros per id, in intro id order.
        let mut by_id: BTreeMap<Id, Vec<usize>> = BTreeMap::new();
        for (n, intro) in pending.iter().enumerate() {
            let id = intro.body.entry.device_id;
            if excluded.contains(&id)
                || refused.contains(&id)
                || members.iter().any(|m| m.device_id == id)
                || !verifies(intro)
            {
                continue;
            }
            by_id.entry(id).or_default().push(n);
        }
        if by_id.is_empty() {
            break;
        }
        let mut taken: BTreeSet<usize> = BTreeSet::new();
        let mut added = Vec::new();
        for (id, ns) in by_id {
            let first = &pending[ns[0]].body.entry;
            if ns
                .iter()
                .any(|n| !same_keys(&pending[*n].body.entry, first))
            {
                refused.insert(id);
            } else if accepted.len() + added.len() < MAX_CARD_INTROS_PER_RECORD {
                added.push(ns[0]);
                taken.insert(ns[0]);
            }
        }
        if added.is_empty() {
            break;
        }
        for n in &added {
            members.push(pending[*n].body.entry.clone());
        }
        let mut rest = Vec::new();
        for (n, intro) in pending.into_iter().enumerate() {
            if taken.contains(&n) {
                accepted.push(intro);
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
/// signing key; and some copy of it (of the `MAX_FOREIGN_COPIES` kept)
/// verifies under the rotator's key from
/// `roster_at(p)` and under the identity it names. The ids a rotation
/// revokes need not be known: they can only shrink later rosters.
/// Devices revoked by an ancestor can neither introduce nor be
/// introduced. Two valid children of one record give `Forked`.
///
/// `Advanced` is never an adoption (see [`ForeignLineage::Advanced`]).
pub fn follow_foreign(
    pin: &ForeignPin,
    records: &[LineageRecord],
    intros: &[SignedIntro],
    legacy: &LegacyIntros<'_>,
) -> ForeignLineage {
    // Every copy of each record of this account that passes the strict
    // checks, by lineage hash; the rotations by parent.
    // Per lineage hash, the distinct copies keyed by the SHA-256 of their
    // encoding, keeping the `MAX_FOREIGN_COPIES` smallest: a function of
    // the set of copies, bounded whatever the server sends.
    let mut by_hash: BTreeMap<[u8; 32], BTreeMap<[u8; 32], &LineageRecord>> = BTreeMap::new();
    let mut children: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>> = BTreeMap::new();
    for r in records {
        if r.account_id() != pin.account_id {
            continue;
        }
        let bytes = r.encode();
        if LineageRecord::decode(&bytes).is_err() {
            continue;
        }
        let h = r.hash();
        if let Some(parent) = r.parent() {
            children.entry(parent).or_default().insert(h);
        }
        let copies = by_hash.entry(h).or_default();
        copies.insert(copy_key(&bytes), r);
        if copies.len() > MAX_FOREIGN_COPIES {
            copies.pop_last();
        }
    }
    let by_hash: BTreeMap<[u8; 32], Vec<&LineageRecord>> = by_hash
        .into_iter()
        .map(|(h, c)| (h, c.into_values().collect()))
        .collect();

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
        let roster = roster_with(parent, intros, legacy, &revoked);
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

/// Sort key of a copy: SHA-256 of its encoding.
fn copy_key(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, bytes).as_ref());
    out
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
    copies.iter().find_map(|r| match r {
        LineageRecord::Rotation(s) if verify_rotation(s, &signer.sign_pub).is_ok() => Some(s),
        _ => None,
    })
}
