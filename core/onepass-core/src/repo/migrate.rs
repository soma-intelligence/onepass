//! Genesis and migration of key rotation v2 (spec 6.2, 15, R17, O4).
//!
//! - A new account writes its genesis at creation
//!   (`Repository::create_account_v2`), this device its creator, `Verified`.
//! - A device of a legacy account (no trust state) migrates on its first
//!   unlock after the update (`Repository::migrate_to_v2`, called by the
//!   app right after the unlock, with the device keys it just created; a
//!   password unlock and a Face ID unlock both open the session it needs).
//!   Among the valid genesis records of the account it takes the one it
//!   made itself, else the one with the smallest hash whose creator is
//!   listed and not revoked in the account-signed device list, and
//!   publishes a legacy intro for itself under it; with none, it writes
//!   the legacy genesis. Its trust state is written in the same
//!   transaction, only if none is stored, its chain state merged with the
//!   stored one.
//! - Legacy intros are accepted by `lineage::accept_legacy_intros` (the one
//!   rule, shared with the sharing branch) while the head is the genesis,
//!   at `Tofu`; two keys for one id exclude it until a verification
//!   (`Repository::verify_device`, "Vérifier mes appareils").
//! - Devices revoked in the device list (milestone 2b) are excluded at
//!   migration; if no rotation followed, the device shows once "Un appareil
//!   retiré garde encore les clés de ton compte. Fais tourner les clés
//!   maintenant." (`MigrationAlerts::rotate_now`).
//! - A genesis of the account other than this device's own root is never
//!   followed: it raises an alert (`MigrationAlerts::other_genesis`).
//!
//! A legacy device that fetched a rotation before migrating still unlocks
//! (the generation 0 records are its own) and reads its vaults from the
//! copy its store retained (`SyncStore`, `retained`); once migrated, a
//! rotation that does not list it leaves it `Orphaned` (re-pair), one that
//! lists it prompts as usual.

use std::collections::{BTreeMap, BTreeSet};

use super::follow::lineage_records;
use super::pairing::{insert_sorted, same_keys};
use super::{Repository, trust_of};
use crate::crypto::{HybridKemPublic, HybridSignature, HybridVerifyingKey};
use crate::device_keys::{DeviceKeys, DevicePublic, sign_pop, verify_pop};
use crate::devices::{DeviceEntry, now};
use crate::lineage::{
    GenesisBody, LINEAGE_FORMAT, LegacyAnchor, LegacyIntroBody, LegacyIntros, LineageRecord,
    MAX_ROSTER, RosterEntry, Signed, SignedIntro, SignedLegacyIntro, accept_legacy_intros,
    body_bytes, legacy_intro_id, sign_genesis, sign_legacy_intro, verify_genesis,
    verify_legacy_intro,
};
use crate::store::{Record, RecordKind, RecordStore};
use crate::trust::{DeviceLineageState, LineageHead, MAX_OTHER_GENESIS, TrustLevel, TrustState};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// What `Repository::migrate_to_v2` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migration {
    /// The device already had a trust state: nothing written.
    Already,
    /// This device created the genesis with this lineage hash (or found
    /// its own again).
    Genesis([u8; 32]),
    /// This device joined the genesis with this lineage hash, with a
    /// legacy intro.
    Joined([u8; 32]),
}

/// The one-time screens of spec 15 (`Repository::migration_alerts`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrationAlerts {
    /// Spec 15 step 5: a device revoked under milestone 2b still holds the
    /// account keys and no rotation followed. Shown once, then
    /// `clear_rotate_now_prompt`.
    pub rotate_now: bool,
    /// Spec 15 step 2: another genesis of this account appeared (never
    /// followed). Shown once, then `clear_genesis_alert`.
    pub other_genesis: bool,
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// This device's roster entry: its keys, and its name, kind and mode from
/// the device list.
fn entry_from(me: &DevicePublic, listed: &DeviceEntry) -> RosterEntry {
    RosterEntry {
        device_id: me.device_id,
        sign_pub: me.sign_pub.clone(),
        kem_pub: me.kem_pub.clone(),
        name: listed.name.clone(),
        kind: listed.kind,
        mode: listed.mode,
        introduced_by: None,
    }
}

/// Every intro record of the store that decodes as a `SignedLegacyIntro`
/// and not as a `SignedIntro` (spec 15: one record kind for both).
pub(crate) fn stored_legacy_intros<S: RecordStore + ?Sized>(
    store: &S,
) -> Result<Vec<SignedLegacyIntro>> {
    Ok(store
        .list(RecordKind::DeviceIntro)?
        .iter()
        .filter(|r| SignedIntro::decode(&r.data).is_err())
        .filter_map(|r| SignedLegacyIntro::decode(&r.data).ok())
        .collect())
}

/// The genesis records of `account_id` signed by `identity` whose two
/// signatures verify, with their lineage hashes, smallest hash first.
fn valid_geneses<'a>(
    records: &'a [LineageRecord],
    account_id: Id,
    identity: &crate::crypto::IdentityVerifyingKey,
) -> Vec<([u8; 32], &'a Signed<GenesisBody>)> {
    let mut out: Vec<_> = records
        .iter()
        .filter_map(|r| match r {
            LineageRecord::Genesis(g)
                if g.body.account_id == account_id
                    && &g.body.identity_pub == identity
                    && verify_genesis(g).is_ok() =>
            {
                Some((r.hash(), g))
            }
            _ => None,
        })
        .collect();
    out.sort_by_key(|(h, _)| *h);
    out
}

/// Spec 15 step 2 as amended (Task 14 review I3): the genesis every
/// device of a legacy account settles on, among `geneses` (valid, signed by
/// the generation 0 identity): the smallest hash whose creator is in
/// `eligible` (listed and not revoked, and listed when this device
/// migrated), not in `excluded`, and not contested: no other valid record
/// (another genesis, a valid legacy intro under any genesis, or this
/// device's own key) claims the creator's id with other keys. A contested
/// creator proves a forgery by a holder of the account keys: such a
/// genesis is never chosen, so grinding a smaller hash under a real
/// device's id captures nothing.
fn winner<'a>(
    geneses: &[([u8; 32], &'a Signed<GenesisBody>)],
    intros: &[SignedLegacyIntro],
    account_id: Id,
    account_sign: &HybridVerifyingKey,
    eligible: &BTreeSet<Id>,
    excluded: &BTreeSet<Id>,
    me: &DevicePublic,
) -> Option<([u8; 32], &'a Signed<GenesisBody>)> {
    let mut claims: BTreeMap<Id, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut claim = |id: Id, sign: &HybridVerifyingKey, kem: &HybridKemPublic| {
        claims
            .entry(id)
            .or_default()
            .insert(body_bytes(&(sign, kem)));
    };
    claim(me.device_id, &me.sign_pub, &me.kem_pub);
    for (_, g) in geneses {
        let c = &g.body.creator;
        claim(c.device_id, &c.sign_pub, &c.kem_pub);
    }
    for i in intros {
        let e = &i.body.entry;
        if i.body.account_id == account_id && verify_legacy_intro(i, account_sign).is_ok() {
            claim(e.device_id, &e.sign_pub, &e.kem_pub);
        }
    }
    geneses
        .iter()
        .find(|(_, g)| {
            let id = g.body.creator.device_id;
            eligible.contains(&id)
                && !excluded.contains(&id)
                && claims.get(&id).is_some_and(|k| k.len() == 1)
        })
        .map(|(h, g)| (*h, *g))
}

/// Ids present and not revoked, and ids revoked, in the device list.
fn split_list(entries: &[DeviceEntry]) -> (BTreeSet<Id>, BTreeSet<Id>) {
    let (live, gone): (Vec<&DeviceEntry>, Vec<&DeviceEntry>) =
        entries.iter().partition(|e| e.revoked_at.is_none());
    (
        live.iter().map(|e| e.device_id).collect(),
        gone.iter().map(|e| e.device_id).collect(),
    )
}

/// A legacy intro record for `entry` under `genesis`.
fn legacy_intro_record(
    account_id: Id,
    genesis: [u8; 32],
    entry: RosterEntry,
    keys: &DeviceKeys,
    me: &DevicePublic,
    account_sign: &crate::crypto::HybridSigningKey,
) -> Result<Record> {
    let body = LegacyIntroBody {
        account_id,
        genesis_hash: genesis,
        entry,
        pop: sign_pop(keys, &account_id.0, me)?,
    };
    let signed = sign_legacy_intro(body, account_sign)?;
    Ok(Record {
        id: legacy_intro_id(&signed.body),
        kind: RecordKind::DeviceIntro,
        version: 0,
        data: signed.encode(),
    })
}

/// The genesis at the root of the chain from `head`, walked back by parent
/// hash; `None` when a record of the chain is missing.
fn root_of(records: &[LineageRecord], head: [u8; 32]) -> Option<(&Signed<GenesisBody>, [u8; 32])> {
    let mut h = head;
    for _ in 0..=records.len() {
        let r = records.iter().find(|r| r.hash() == h)?;
        match r {
            LineageRecord::Genesis(g) => return Some((g, h)),
            LineageRecord::Rotation(s) => h = s.body.parent,
        }
    }
    None
}

/// Add to `trust.other_genesis` every valid genesis of its account, signed
/// by the identity of its own root genesis, that is not that root (spec
/// 15 step 2: never followed, an alert). Whether anything was added.
fn note_other_genesis(trust: &mut TrustState, records: &[LineageRecord]) -> bool {
    let Some((root, root_hash)) = root_of(records, trust.head.hash) else {
        return false;
    };
    let mut added = false;
    for (h, _) in valid_geneses(records, trust.account_id, &root.body.identity_pub) {
        if h != root_hash && !trust.other_genesis.contains(&h) {
            trust.other_genesis.push(h);
            added = true;
        }
    }
    if added {
        trust.other_genesis.sort();
        trust.other_genesis.truncate(MAX_OTHER_GENESIS);
        trust.genesis_alert = true;
    }
    added
}

/// Apply the outcome of `accept_legacy_intros` to `trust` (this device's
/// policy on top of the shared rule): this device's own id is never
/// touched; a device pinned `Verified` (a SAS pairing or verification)
/// keeps its key; an accepted device joins at `Tofu` unless revoked or
/// excluded; a `Tofu` device a later intro gives another key, or that the
/// rule excludes, leaves the roster for `excluded` and `conflicted`.
/// Whether anything changed.
fn apply_legacy(trust: &mut TrustState, out: &LegacyIntros) -> bool {
    let before = trust.clone();
    let me = trust.me.device_id;
    let verified =
        |t: &TrustState, id: &Id| t.levels.get(id) == Some(&TrustLevel::Verified) && *id != me;
    let exclude = |t: &mut TrustState, id: Id| {
        t.roster.retain(|e| e.device_id != id);
        t.levels.remove(&id);
        t.excluded.insert(id);
        t.conflicted.insert(id);
    };
    for id in &out.excluded {
        let pinned = trust.roster.iter().any(|e| e.device_id == *id);
        if *id == me || (pinned && verified(trust, id)) {
            continue;
        }
        exclude(trust, *id);
    }
    for e in &out.accepted {
        let id = e.device_id;
        if id == me || trust.revoked.contains(&id) || trust.excluded.contains(&id) {
            continue;
        }
        match trust.roster.iter().find(|r| r.device_id == id) {
            Some(r) if r.sign_pub == e.sign_pub && r.kem_pub == e.kem_pub => {}
            Some(_) if !verified(trust, &id) => exclude(trust, id),
            Some(_) => {}
            None if trust.roster.len() < MAX_ROSTER => {
                insert_sorted(&mut trust.roster, e.clone());
                trust.levels.insert(id, TrustLevel::Tofu);
            }
            None => {}
        }
    }
    *trust != before
}

impl<S: RecordStore> Repository<S> {
    /// Spec 15 steps 1 to 3 and 5, on the first unlock after the update:
    /// `device_keys` are the keys the app just created for this device.
    /// The session must be the generation 0 one of a legacy device (no
    /// trust state); the caller ran a full sync first, so the genesis of a
    /// device that migrated earlier is here.
    ///
    /// This device is registered in the device list first if it is not
    /// (`maintain_lists`). Then, in one transaction conditional on no trust
    /// state being stored (`RecordStore::put_first_trust`): the legacy
    /// genesis (signed by `device_keys` and the account identity) or this
    /// device's legacy intro (signed by `device_keys` for the proof of
    /// possession and by the account signing key), and the trust state:
    /// head the genesis, roster its creator (`Tofu`), this device
    /// (`Verified`) and the devices whose legacy intros are accepted
    /// (`Tofu`); the other devices listed and not revoked are `Tofu` until
    /// their intro arrives (never "Appairage incomplet"); the devices the
    /// list revokes are excluded; `rotate_now` when the list revokes one
    /// and no rotation is known; the other valid genesis records noted and
    /// alerted. The session then looks for intros and rotations again
    /// (`refresh_pending_rotation`).
    ///
    /// `Migration::Already` when a trust state exists. Refused: a store
    /// that keeps no chain state (`InvalidFormat`), a session on another
    /// generation (`Validation("account")`), a device the list revokes
    /// (`Validation("device")`, it must not join), a lost race with another
    /// migration on this device (`Conflict`).
    pub fn migrate_to_v2(&mut self, device_keys: &DeviceKeys) -> Result<Migration> {
        if let Some(trust) = trust_of(&self.store)? {
            return Ok(match self.join_winner(trust, device_keys)? {
                Some(h) => Migration::Joined(h),
                None => Migration::Already,
            });
        }
        if !self.store.persists_chain() {
            return Err(Error::InvalidFormat(
                "device registration needs a sync store",
            ));
        }
        let account_id = self.account.params.account_id;
        if self.records_id != account_id {
            return Err(refused("account", "not generation 0"));
        }
        self.maintain_lists(None)?;
        let me_id = self.chain.device_id.ok_or(Error::NotFound)?;
        let list = self.read_list::<DeviceEntry>()?.ok_or(Error::NotFound)?;
        let mine = list.body.entry(me_id).cloned().ok_or(Error::NotFound)?;
        if mine.revoked_at.is_some() {
            return Err(refused("device", "revoked"));
        }
        let me = device_keys.public(me_id)?;
        let my_entry = entry_from(&me, &mine);
        let (listed, revoked_2b) = split_list(&list.body.entries);

        let records = lineage_records(&self.store)?;
        let identity = self.account.params.identity_pub.clone();
        let geneses = valid_geneses(&records, account_id, &identity);
        let intros = stored_legacy_intros(&self.store)?;
        let chosen = winner(
            &geneses,
            &intros,
            account_id,
            &self.account.params.signing_pub,
            &listed,
            &revoked_2b,
            &me,
        );
        let keyset = self.account.keyset();
        let mut writes = Vec::new();
        let (genesis_hash, creator, outcome) = match chosen {
            Some((h, g)) if g.body.creator.device_id == me_id => {
                (h, g.body.creator.clone(), Migration::Genesis(h))
            }
            Some((h, g)) => {
                writes.push((
                    legacy_intro_record(
                        account_id,
                        h,
                        my_entry.clone(),
                        device_keys,
                        &me,
                        &keyset.signing,
                    )?,
                    None,
                ));
                (h, g.body.creator.clone(), Migration::Joined(h))
            }
            None => {
                let body = GenesisBody {
                    format: LINEAGE_FORMAT,
                    account_id,
                    identity_pub: identity.clone(),
                    creator: my_entry.clone(),
                    created_at: now(),
                };
                let g = LineageRecord::Genesis(sign_genesis(body, device_keys, &keyset.identity)?);
                let h = g.hash();
                writes.push((
                    Record {
                        id: g.record_id(),
                        kind: RecordKind::Lineage,
                        version: 0,
                        data: g.encode(),
                    },
                    None,
                ));
                (h, my_entry.clone(), Migration::Genesis(h))
            }
        };

        let creator_id = creator.device_id;
        let mut roster = vec![my_entry];
        if creator_id != me_id {
            roster.push(creator);
        }
        roster.sort_by_key(|e| e.device_id);
        let mut trust = TrustState::new(
            account_id,
            me,
            LineageHead {
                generation: 0,
                hash: genesis_hash,
            },
            identity,
            roster,
            DeviceLineageState::Current,
        );
        trust.levels.insert(me_id, TrustLevel::Verified);
        if creator_id != me_id {
            trust.levels.insert(creator_id, TrustLevel::Tofu);
        }
        for id in &listed {
            if *id != me_id && *id != creator_id {
                trust.levels.insert(*id, TrustLevel::Tofu);
            }
        }
        trust
            .excluded
            .extend(revoked_2b.iter().filter(|id| **id != me_id));
        trust.migration_listed = listed.clone();
        let out = accept_legacy_intros(
            &intros,
            &LegacyAnchor {
                account_id,
                genesis_hash,
                account_sign: &self.account.params.signing_pub,
                creator: creator_id,
                listed: &listed,
            },
        );
        apply_legacy(&mut trust, &out);
        // Listed devices whose intro is not in yet stay `Tofu` (pending);
        // an excluded one has no level.
        let excluded = trust.excluded.clone();
        trust.levels.retain(|id, _| !excluded.contains(id));
        // Review I1: never from unverified records; a rotation that moves
        // the head hides it (`migration_alerts`).
        trust.rotate_now = !revoked_2b.is_empty();
        // Spec 15 step 2: the other valid genesis records are never
        // followed; seen at migration, they alert at once.
        trust.other_genesis = geneses
            .iter()
            .map(|(h, _)| *h)
            .filter(|h| *h != genesis_hash)
            .take(MAX_OTHER_GENESIS)
            .collect();
        trust.genesis_alert = !trust.other_genesis.is_empty();

        self.store
            .put_first_trust(writes, Some(self.chain.clone()), &trust)?;
        self.refresh_pending_rotation()?;
        Ok(outcome)
    }

    /// Spec 15 step 3, after the migration: while the head is the genesis
    /// and the device is `Current` or `Candidate`, the stored legacy intros
    /// accepted by `accept_legacy_intros` (against the genesis, its
    /// creator, the account signing key of this session's generation 0
    /// identity and the devices listed and not revoked) join the roster at
    /// `Tofu`, or exclude the ids they conflict on (`apply_legacy`); then
    /// the other genesis records are noted (spec 15 step 2). One write,
    /// conditional on `trust` (a `Conflict` leaves it for the next look).
    /// A device list that does not verify leaves the intros waiting.
    /// Returns the trust state in force.
    pub(crate) fn apply_migration_records(&mut self, trust: TrustState) -> Result<TrustState> {
        let records = lineage_records(&self.store)?;
        let mut next = trust.clone();
        if trust.head.generation == 0
            && matches!(
                trust.state,
                DeviceLineageState::Current | DeviceLineageState::Candidate { .. }
            )
            && self.records_id == trust.account_id
            && self.account.params.identity_pub == trust.identity_pub
            && let Some(LineageRecord::Genesis(g)) =
                records.iter().find(|r| r.hash() == trust.head.hash)
            && let Ok(Some(list)) = self.read_list::<DeviceEntry>()
        {
            let (listed, revoked_now) = split_list(&list.body.entries);
            // Review M1: a 2b revocation written after this device migrated
            // (by a device not updated yet) drops a `Tofu` device here and
            // asks for the rotation again; a `Verified` pin stays.
            for id in &revoked_now {
                if *id != trust.me.device_id
                    && next.levels.get(id) == Some(&TrustLevel::Tofu)
                    && !next.excluded.contains(id)
                {
                    next.roster.retain(|e| e.device_id != *id);
                    next.levels.remove(id);
                    next.excluded.insert(*id);
                    next.rotate_now = true;
                }
            }
            // Review I2: only devices listed when this device migrated.
            let eligible: BTreeSet<Id> = listed
                .intersection(&trust.migration_listed)
                .copied()
                .collect();
            let out = accept_legacy_intros(
                &stored_legacy_intros(&self.store)?,
                &LegacyAnchor {
                    account_id: trust.account_id,
                    genesis_hash: trust.head.hash,
                    account_sign: &self.account.params.signing_pub,
                    creator: g.body.creator.device_id,
                    listed: &eligible,
                },
            );
            apply_legacy(&mut next, &out);
        }
        note_other_genesis(&mut next, &records);
        if next == trust {
            return Ok(trust);
        }
        match self
            .store
            .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
        {
            Ok(()) => Ok(next),
            Err(Error::Conflict) => Ok(trust),
            Err(e) => Err(e),
        }
    }

    /// The one-time screens of spec 15 for this device. `rotate_now` holds
    /// only while no rotation moved the head (generation 0). Both `false`
    /// without a trust state.
    pub fn migration_alerts(&self) -> Result<MigrationAlerts> {
        Ok(
            trust_of(&self.store)?.map_or_else(MigrationAlerts::default, |t| MigrationAlerts {
                rotate_now: t.rotate_now
                    && t.head.generation == 0
                    && !matches!(
                        t.state,
                        DeviceLineageState::Quarantined { .. }
                            | DeviceLineageState::Orphaned { .. }
                    ),
                other_genesis: t.genesis_alert,
            }),
        )
    }

    /// The user saw "Fais tourner les clés maintenant": not shown again.
    /// Conditional on the trust state read (`Conflict`).
    pub fn clear_rotate_now_prompt(&mut self) -> Result<()> {
        self.edit_trust(|t| t.rotate_now = false)
    }

    /// The user saw the other-genesis alert: not shown again for the
    /// genesis records known now. Conditional on the trust state read
    /// (`Conflict`).
    pub fn clear_genesis_alert(&mut self) -> Result<()> {
        self.edit_trust(|t| t.genesis_alert = false)
    }

    fn edit_trust(&mut self, edit: impl FnOnce(&mut TrustState)) -> Result<()> {
        let trust = trust_of(&self.store)?.ok_or_else(|| refused("device", "no device keys"))?;
        let mut next = trust.clone();
        edit(&mut next);
        if next == trust {
            return Ok(());
        }
        self.store
            .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
    }

    /// Review I3 (spec 15 step 2 as amended): a device still at generation
    /// 0 on a genesis that is not the winner (`winner`, computed with the
    /// devices listed now and when this device migrated) moves to the
    /// winner, with no user step, when nothing makes the move costly: the
    /// state is `Current`, no rotation record of the account is known on
    /// either side, and it pins no other device `Verified` (no SAS pairing
    /// or verification made on its own genesis). It publishes its legacy
    /// intro under the winner (unless it created it), and its trust state
    /// moves in the same transaction: head the winner, roster this device
    /// and the winner's creator (`Tofu`), the devices it pinned before
    /// pending `Tofu` until their own intro under the winner (they move the
    /// same way), the genesis it left noted with the alert kept. Then the
    /// legacy intros under the winner are applied. Run by `migrate_to_v2`,
    /// which the app calls at each unlock. `None` when it does not move.
    /// Once a rotation exists the divergence is left to the user: the
    /// alert, then a re-pair (`repair_from_grant`, an A9 follow).
    fn join_winner(&mut self, trust: TrustState, keys: &DeviceKeys) -> Result<Option<[u8; 32]>> {
        let me = trust.me.device_id;
        if trust.head.generation != 0
            || trust.state != DeviceLineageState::Current
            || self.pending.is_some()
            || self.lineage_lock.is_some()
            || self.records_id != trust.account_id
            || self.account.params.identity_pub != trust.identity_pub
            || keys.public(me)? != trust.me
            || trust.roster.iter().any(|e| {
                e.device_id != me && trust.levels.get(&e.device_id) == Some(&TrustLevel::Verified)
            })
        {
            return Ok(None);
        }
        let records = lineage_records(&self.store)?;
        if records
            .iter()
            .any(|r| matches!(r, LineageRecord::Rotation(_)) && r.account_id() == trust.account_id)
        {
            return Ok(None);
        }
        let Some(list) = self.read_list::<DeviceEntry>()? else {
            return Ok(None);
        };
        let (listed, _) = split_list(&list.body.entries);
        let eligible: BTreeSet<Id> = listed
            .intersection(&trust.migration_listed)
            .copied()
            .collect();
        let geneses = valid_geneses(&records, trust.account_id, &trust.identity_pub);
        let intros = stored_legacy_intros(&self.store)?;
        let Some((h, g)) = winner(
            &geneses,
            &intros,
            trust.account_id,
            &self.account.params.signing_pub,
            &eligible,
            &trust.excluded,
            &trust.me,
        ) else {
            return Ok(None);
        };
        if h == trust.head.hash {
            return Ok(None);
        }
        let mine = trust
            .roster
            .iter()
            .find(|e| e.device_id == me)
            .cloned()
            .ok_or_else(|| refused("device", "not in its own roster"))?;
        let creator = g.body.creator.clone();
        let mut writes = Vec::new();
        if creator.device_id != me {
            writes.push((
                legacy_intro_record(
                    trust.account_id,
                    h,
                    mine.clone(),
                    keys,
                    &trust.me,
                    &self.account.keyset().signing,
                )?,
                None,
            ));
        }
        let mut next = trust.clone();
        next.head.hash = h;
        for e in &trust.roster {
            if e.device_id != me {
                next.levels.insert(e.device_id, TrustLevel::Tofu);
            }
        }
        next.roster = vec![mine];
        if creator.device_id != me {
            next.levels.insert(creator.device_id, TrustLevel::Tofu);
            insert_sorted(&mut next.roster, creator.clone());
        }
        next.other_genesis.retain(|x| *x != h);
        if !next.other_genesis.contains(&trust.head.hash) {
            next.other_genesis.push(trust.head.hash);
            next.other_genesis.sort();
            next.other_genesis.truncate(MAX_OTHER_GENESIS);
        }
        next.genesis_alert = true;
        let out = accept_legacy_intros(
            &intros,
            &LegacyAnchor {
                account_id: trust.account_id,
                genesis_hash: h,
                account_sign: &self.account.params.signing_pub,
                creator: creator.device_id,
                listed: &eligible,
            },
        );
        apply_legacy(&mut next, &out);
        self.store
            .put_with_trust_cas(writes, Vec::new(), None, &trust, &next)?;
        self.refresh_pending_rotation()?;
        Ok(Some(h))
    }

    /// Concern 5 (spec 15, Task 17 UI): the devices of the account that
    /// have not migrated, as this device sees them: listed and not revoked
    /// in the device list, not this device, not in the roster, neither
    /// revoked along the lineage nor excluded, and pinned `Tofu` with no
    /// roster entry (listed when this device migrated, no accepted legacy
    /// intro since). A rotation now leaves them out ("devra être
    /// réappairé"): the rotation screen lists them before a generation 0
    /// rotation, and after one they are the devices to re-pair. Sorted.
    /// Empty without a trust state.
    pub fn unmigrated_devices(&self) -> Result<Vec<Id>> {
        let Some(t) = trust_of(&self.store)? else {
            return Ok(Vec::new());
        };
        let Some(list) = self.read_list::<DeviceEntry>()? else {
            return Ok(Vec::new());
        };
        let (listed, _) = split_list(&list.body.entries);
        Ok(listed
            .into_iter()
            .filter(|id| {
                *id != t.me.device_id
                    && !t.roster.iter().any(|e| e.device_id == *id)
                    && !t.revoked.contains(id)
                    && !t.excluded.contains(id)
                    && t.levels.get(id) == Some(&TrustLevel::Tofu)
            })
            .collect())
    }

    /// "Vérifier mes appareils" (spec 15 step 4, R17): the pairing QR and
    /// SAS ran between this device and `peer` with no grant, and the
    /// authenticated channel carried `peer`'s public key with its proof of
    /// possession `pop` over `transcript` (the session transcript hash, as
    /// in `Message::ConfirmedWithKey`). `peer` becomes `Verified` here (the
    /// other side runs the same with this device's key).
    ///
    /// A roster device with these keys is upgraded. A device excluded for
    /// conflicting legacy intros (`TrustState::conflicted`) whose stored
    /// legacy intro under this device's genesis carries these keys joins
    /// the roster `Verified` and leaves `excluded`: the SAS decided between
    /// the two claims. One write, conditional on the trust state read.
    ///
    /// Refused: no trust state, this device's own id, a device locked or
    /// orphaned (`Validation("device")`); a proof of possession that does
    /// not verify (`Integrity(Signature)`); a roster that pins another key
    /// for that id (`Integrity(WrongContext)`); any other device
    /// (`Validation("device")`: pair it instead).
    pub fn verify_device(
        &mut self,
        peer: &DevicePublic,
        transcript: &[u8],
        pop: &HybridSignature,
    ) -> Result<()> {
        let trust = trust_of(&self.store)?.ok_or_else(|| refused("device", "no device keys"))?;
        let id = peer.device_id;
        if id == trust.me.device_id
            || self.lineage_lock.is_some()
            || matches!(
                trust.state,
                DeviceLineageState::Legacy
                    | DeviceLineageState::Quarantined { .. }
                    | DeviceLineageState::Orphaned { .. }
            )
        {
            return Err(refused("device", "not verifiable"));
        }
        verify_pop(transcript, peer, pop)?;
        let mut next = trust.clone();
        if let Some(e) = trust.roster.iter().find(|e| e.device_id == id) {
            if !same_keys(e, peer) {
                return Err(IntegrityError::WrongContext.into());
            }
            next.levels.insert(id, TrustLevel::Verified);
        } else if trust.conflicted.contains(&id)
            && trust.head.generation == 0
            && self.account.params.identity_pub == trust.identity_pub
        {
            let signer = &self.account.params.signing_pub;
            let entry = stored_legacy_intros(&self.store)?
                .into_iter()
                .filter(|i| {
                    i.body.account_id == trust.account_id
                        && i.body.genesis_hash == trust.head.hash
                        && i.body.entry.device_id == id
                        && i.body.entry.introduced_by.is_none()
                        && same_keys(&i.body.entry, peer)
                        && verify_legacy_intro(i, signer).is_ok()
                })
                .map(|i| i.body.entry)
                .min_by_key(crate::lineage::body_bytes)
                .ok_or_else(|| refused("device", "not pinned"))?;
            if next.roster.len() >= MAX_ROSTER {
                return Err(refused("device", "roster full"));
            }
            insert_sorted(&mut next.roster, entry);
            next.levels.insert(id, TrustLevel::Verified);
            next.excluded.remove(&id);
            next.conflicted.remove(&id);
        } else {
            return Err(refused("device", "not pinned"));
        }
        if next == trust {
            return Ok(());
        }
        self.store
            .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
    }
}
