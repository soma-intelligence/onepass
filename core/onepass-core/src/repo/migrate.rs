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

use std::collections::BTreeSet;

use super::follow::lineage_records;
use super::pairing::{insert_sorted, same_keys};
use super::{Repository, trust_of};
use crate::crypto::HybridSignature;
use crate::device_keys::{DeviceKeys, DevicePublic, sign_pop, verify_pop};
use crate::devices::{DeviceEntry, now};
use crate::lineage::{
    GenesisBody, LINEAGE_FORMAT, LegacyAnchor, LegacyIntroBody, LegacyIntros, LineageRecord,
    MAX_ROSTER, RosterEntry, Signed, SignedIntro, SignedLegacyIntro, accept_legacy_intros,
    legacy_intro_id, sign_genesis, sign_legacy_intro, verify_genesis, verify_legacy_intro,
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
        if trust_of(&self.store)?.is_some() {
            return Ok(Migration::Already);
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
        let listed: BTreeSet<Id> = list
            .body
            .entries
            .iter()
            .filter(|e| e.revoked_at.is_none())
            .map(|e| e.device_id)
            .collect();
        let revoked_2b: BTreeSet<Id> = list
            .body
            .entries
            .iter()
            .filter(|e| e.revoked_at.is_some())
            .map(|e| e.device_id)
            .collect();

        let records = lineage_records(&self.store)?;
        let identity = self.account.params.identity_pub.clone();
        let geneses = valid_geneses(&records, account_id, &identity);
        let own = geneses
            .iter()
            .find(|(_, g)| g.body.creator.device_id == me_id && same_keys(&g.body.creator, &me));
        let chosen = own.or_else(|| {
            geneses.iter().find(|(_, g)| {
                g.body.creator.device_id != me_id && listed.contains(&g.body.creator.device_id)
            })
        });
        let keyset = self.account.keyset();
        let mut writes = Vec::new();
        let (genesis_hash, creator, outcome) = match chosen {
            Some((h, g)) if g.body.creator.device_id == me_id => {
                (*h, g.body.creator.clone(), Migration::Genesis(*h))
            }
            Some((h, g)) => {
                let body = LegacyIntroBody {
                    account_id,
                    genesis_hash: *h,
                    entry: my_entry.clone(),
                    pop: sign_pop(device_keys, &account_id.0, &me)?,
                };
                let signed = sign_legacy_intro(body, &keyset.signing)?;
                writes.push((
                    Record {
                        id: legacy_intro_id(&signed.body),
                        kind: RecordKind::DeviceIntro,
                        version: 0,
                        data: signed.encode(),
                    },
                    None,
                ));
                (*h, g.body.creator.clone(), Migration::Joined(*h))
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
        let out = accept_legacy_intros(
            &stored_legacy_intros(&self.store)?,
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
        trust.rotate_now = !revoked_2b.is_empty()
            && !records.iter().any(
                |r| matches!(r, LineageRecord::Rotation(s) if s.body.account_id == account_id),
            );
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
            let listed: BTreeSet<Id> = list
                .body
                .entries
                .iter()
                .filter(|e| e.revoked_at.is_none())
                .map(|e| e.device_id)
                .collect();
            let out = accept_legacy_intros(
                &stored_legacy_intros(&self.store)?,
                &LegacyAnchor {
                    account_id: trust.account_id,
                    genesis_hash: trust.head.hash,
                    account_sign: &self.account.params.signing_pub,
                    creator: g.body.creator.device_id,
                    listed: &listed,
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
                rotate_now: t.rotate_now && t.head.generation == 0,
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
        } else if trust.conflicted.contains(&id) && trust.head.generation == 0 {
            let signer = &self.account.params.signing_pub;
            let entry = stored_legacy_intros(&self.store)?
                .into_iter()
                .filter(|i| {
                    i.body.account_id == trust.account_id
                        && i.body.genesis_hash == trust.head.hash
                        && i.body.entry.device_id == id
                        && i.body.entry.introduced_by.is_none()
                        && same_keys(&i.body.entry, peer)
                        && self.account.params.identity_pub == trust.identity_pub
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
