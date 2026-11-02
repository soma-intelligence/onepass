//! Emergency Kit restore of key rotation v2 (spec 7.5, 8.2, R14; formal
//! model `rotation.pv`: `PinRoster(restore_new) ==> Rotated` holds,
//! `restore_old` fails by design).
//!
//! - `Repository::restore_from_kit` finds the identity the kit opens (2SKD:
//!   the Secret Key and the master password open its keyset, on the
//!   identity-keyed records of spec 6.6), then the lineage record that
//!   introduces that identity. That record is pinned only through its
//!   identity signature, on a chain verified back to a genesis (each
//!   ancestor found by the parent hash its child signs): 2SKD
//!   authenticates the identity, the identity authenticates the roster.
//!   No key handed over by the server is trusted on its own.
//! - An identity with a visible valid child (a rotation of its head by a
//!   device of its roster, both signatures verified), or whose head lost
//!   to a sibling branch, is an outdated kit: `Error::OutdatedKit`, with
//!   the rotator's local name (`UNKNOWN_ROTATOR` on a device that never
//!   pinned it) and the child's date. Nothing is written. A server that
//!   hides the child lets an outdated kit restore onto the old identity:
//!   the documented limit (spec 11, `restore_old`).
//! - The restored device is a new device: a new device id, the device keys
//!   the app just made, a self-intro (`Intro` with `introducer` = itself,
//!   signed by its device key and by the identity). It stays outside its
//!   own roster until a device of the roster pins it: the other devices
//!   show the question (`kit_restored_devices`) and pin it only on the
//!   user's yes (`accept_kit_restored`, which writes their own intro for
//!   it and its device list entry), or exclude it (`reject_kit_restored`).
//!   The restored device sees that intro and joins its own roster
//!   (`pairing::accept_intros`).
//! - Until then (`awaiting_pin`) it reads and writes items, but it does
//!   not rotate, approve a pairing (`trust_snapshot`, `introduce`), sign a
//!   list (device or vault list: no self-registration, no vault created or
//!   deleted) or join another genesis. When it is the only device left
//!   (spec 7.5 as amended, Task 15), the user says so on it
//!   (`claim_only_device`, "Je n'ai plus d'autre appareil", after the
//!   master password): it pins itself and may rotate from then on. A
//!   device that still exists then sees a rotation by a device it never
//!   pinned (invalid, ignored), is cut off from the vaults that rotation
//!   seals again, and re-pairs from the restored device.
//! - Over a device that already holds the account, the restore is one of
//!   the exits of a locked device (spec 8.2): only from `Quarantined` or
//!   `Orphaned` (stored, or found by the resolver). A successful restore
//!   replaces the trust state, so it ends the quarantine and its 7-day
//!   erase. It succeeds only with a kit whose identity has no visible
//!   child; the record that locked the device is in its own store, so that
//!   is the latest kit. An outdated kit, a wrong password or any other
//!   refusal changes nothing: the erase clock keeps running from its
//!   `since`. The revocations, exclusions, rejected records, retired
//!   identities and own writes of the device are kept (the own writes wait
//!   for their replay as after a follow).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use super::follow::{
    abandoned_rotation_rows, current_records_id, lineage_records, look_for, rotations,
};
use super::migrate::{
    apply_legacy, split_list, stored_legacy_intros, valid_geneses, winner as genesis_winner,
};
use super::pairing::{accept_intros, insert_sorted, intro_record, same_keys, stored_intros};
use super::{DeviceState, Repository, pin, trust_of};
use crate::account::{Account, AccountParams, PinnedAccount};
use crate::chain::ChainState;
use crate::crypto::{KdfParams, SecretKey};
use crate::device_keys::{DeviceKeys, sign_pop};
use crate::devices::{DeviceEntry, DeviceKind, DeviceMode, check_mode, check_name, now};
use crate::lineage::resolve::{Completeness, Decision, resolve};
use crate::lineage::{
    IntroBody, LINEAGE_FORMAT, LegacyAnchor, LineageRecord, MAX_ROSTER, RosterEntry, SignedIntro,
    accept_legacy_intros, intro_id, sign_intro, verify_genesis, verify_intro,
    verify_intro_identity, verify_rotation,
};
use crate::lists::{AccountList, Stored};
use crate::store::{Record, RecordKind, RecordStore, account_record_id};
use crate::trust::{DeviceLineageState, LineageHead, RetiredIdentity, TrustLevel, TrustState};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// The rotator's name in `Error::OutdatedKit` when this device never pinned
/// it (a new device): the app's neutral wording, never the server's text.
pub const UNKNOWN_ROTATOR: &str = "un autre appareil";

/// What `Repository::restore_from_kit` needs from the app.
pub struct KitRestore<'a> {
    /// The master password the user typed.
    pub password: &'a str,
    /// The Secret Key of the kit.
    pub secret_key: &'a SecretKey,
    /// The device keys the app just created for this device (stored in the
    /// Keychain under the account, as at pairing).
    pub device_keys: &'a DeviceKeys,
    /// This device's name, kind and mode, as at pairing.
    pub name: &'a str,
    pub kind: DeviceKind,
    pub mode: DeviceMode,
    /// The device state the app saved (default on a new device). Only its
    /// vaults are read: a restore starts again from the kit's identity.
    pub device: DeviceState,
}

/// A device restored with the Emergency Kit that asks to be trusted (spec
/// 7.5 step 5): "Nouvel appareil restauré avec l'Emergency Kit : <nom>.
/// Faire confiance ?". The name is the one its identity-signed self-intro
/// carries, chosen by whoever holds the kit: the app always shows it with
/// the "restauré par Kit" marker, never as a known device (review m3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitRestored {
    pub device_id: Id,
    pub name: String,
    pub kind: DeviceKind,
    pub mode: DeviceMode,
    /// The name is the name of a device already in this device's roster:
    /// the app says so ("porte le même nom qu'un de tes appareils").
    pub name_in_use: bool,
    /// The device already signed a rotation (review I1, concern 2): it
    /// claimed to be the only device (`claim_only_device`), or runs a
    /// modified client. It can no longer be accepted (re-pair it from that
    /// device instead), and the app raises the alert "Quelqu'un a restauré
    /// avec ton Emergency Kit et changé les clés" with three actions:
    /// change the master password, make a new kit, reject the device
    /// (`reject_kit_restored`, which ends the alert). See
    /// `Repository::kit_rotation_alerts`.
    pub rotated: bool,
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

/// A device restored with the kit that no device pinned yet (and that did
/// not claim to be the only one): it is outside its own roster. Every
/// other device is in its own roster from its genesis, migration, pairing
/// or adoption on.
pub(crate) fn kit_unpinned(t: &TrustState) -> bool {
    !t.roster
        .iter()
        .any(|e| same_keys(e, &t.me) && e.device_id == t.me.device_id)
}

/// `Validation("device", "not pinned")` on a device `kit_unpinned`.
pub(crate) fn check_pinned(t: &TrustState) -> Result<()> {
    if kit_unpinned(t) {
        return Err(refused("device", "not pinned"));
    }
    Ok(())
}

/// Each rotation's rotator is checked against the record's own roster,
/// not its parent's (review m5): the identity-signed head fixes every
/// ancestor by hash, so the parent's roster adds nothing an attacker
/// could change; the resolver applies the parent rule on followers.
///
/// The chain from a genesis to `head`, oldest first: each record found by
/// the parent hash its child signs (so the head fixes every ancestor),
/// generations stepping down by one, one account, and both signatures of
/// each record verified (a genesis under the creator key and the identity
/// it names; a rotation under its rotator's key from its own roster and
/// the identity it names). `None` when a record is missing or fails.
fn verified_chain<'a>(
    by_hash: &BTreeMap<[u8; 32], &'a LineageRecord>,
    head: [u8; 32],
    account_id: Id,
) -> Option<Vec<&'a LineageRecord>> {
    let mut out: Vec<&LineageRecord> = Vec::new();
    let mut h = head;
    loop {
        let r = *by_hash.get(&h)?;
        if r.account_id() != account_id
            || out
                .last()
                .is_some_and(|child| child.generation() != r.generation() + 1)
        {
            return None;
        }
        out.push(r);
        match r {
            LineageRecord::Genesis(g) => {
                verify_genesis(g).ok()?;
                break;
            }
            LineageRecord::Rotation(s) => {
                let rotator = s
                    .body
                    .roster
                    .iter()
                    .find(|e| e.device_id == s.body.rotator)?;
                verify_rotation(s, &rotator.sign_pub).ok()?;
                h = s.body.parent;
            }
        }
        if out.len() > by_hash.len() {
            return None;
        }
    }
    out.reverse();
    Some(out)
}

/// The first valid child of `t`'s head, by hash (spec 7.5 step 4: a
/// rotation of this account whose parent is the head, one generation
/// below, signed by a device of the roster, not revoked or excluded here,
/// not rejected here, both signatures verified with that device's key
/// from `t`); else the target of a decision of the resolver that moves
/// away from the head (a sibling branch wins). `None` when the head is the
/// latest.
fn newer_than_head(t: &TrustState, records: &[LineageRecord]) -> Option<[u8; 32]> {
    let mut children: Vec<[u8; 32]> = records
        .iter()
        .filter_map(|r| match r {
            LineageRecord::Rotation(s)
                if s.body.account_id == t.account_id
                    && s.body.parent == t.head.hash
                    && t.head.generation.checked_add(1) == Some(s.body.generation)
                    && !t.ignored.contains(&r.hash())
                    && !t.revoked.contains(&s.body.rotator)
                    && !t.excluded.contains(&s.body.rotator)
                    && t.roster.iter().any(|e| {
                        e.device_id == s.body.rotator && verify_rotation(s, &e.sign_pub).is_ok()
                    }) =>
            {
                Some(r.hash())
            }
            _ => None,
        })
        .collect();
    children.sort();
    if let Some(h) = children.first() {
        return Some(*h);
    }
    match resolve(t, records, &Completeness::default()) {
        Decision::Prompt(p) => p.children.first().copied(),
        Decision::Quarantine { by } => Some(by),
        Decision::Orphaned { child } => Some(child),
        Decision::Switch { to } => Some(to),
        Decision::Stay | Decision::Wait { .. } => None,
    }
}

/// Spec 7.5 step 5: the valid kit self-intros under `t`'s head, one per
/// device (the smallest intro id; two keys for one id count for none):
/// an intro of this account and head whose introducer is the device it
/// introduces (`introduced_by` none), signed by that device's own key and
/// by the head's identity (`t.identity_pub`, from the local trust state),
/// its proof of possession over the account id verified, for a device that
/// is not this one, not revoked or excluded, and not in the roster.
fn self_intros<'a>(t: &TrustState, intros: &'a [SignedIntro]) -> BTreeMap<Id, &'a SignedIntro> {
    let mut found: BTreeMap<Id, Vec<(Id, &SignedIntro)>> = BTreeMap::new();
    for i in intros {
        let b = &i.body;
        let id = b.entry.device_id;
        if i.identity_sig.is_none()
            || b.account_id != t.account_id
            || b.head != t.head.hash
            || b.introducer != id
            || b.entry.introduced_by.is_some()
            || id == t.me.device_id
            || t.revoked.contains(&id)
            || t.excluded.contains(&id)
            || t.roster.iter().any(|e| e.device_id == id)
            || verify_intro_identity(i, &t.identity_pub).is_err()
            || verify_intro(i, &b.entry.sign_pub).is_err()
        {
            continue;
        }
        found.entry(id).or_default().push((intro_id(b), i));
    }
    found
        .into_iter()
        .filter_map(|(id, mut v)| {
            v.sort_by_key(|(iid, _)| *iid);
            let first = &v[0].1.body.entry;
            v.iter()
                .all(|(_, i)| {
                    i.body.entry.sign_pub == first.sign_pub && i.body.entry.kem_pub == first.kem_pub
                })
                .then(|| (id, v[0].1))
        })
        .collect()
}

/// What `kit_restored_devices` shows for a valid self-intro: whether its
/// name is one of the roster's, and whether the device signed any
/// rotation of this account (its own key from the self-intro, both
/// signatures verified).
fn kit_restored(t: &TrustState, records: &[LineageRecord], i: &SignedIntro) -> KitRestored {
    let e = &i.body.entry;
    let rotated = records.iter().any(|r| match r {
        LineageRecord::Rotation(s) => {
            s.body.account_id == t.account_id
                && s.body.rotator == e.device_id
                && verify_rotation(s, &e.sign_pub).is_ok()
        }
        LineageRecord::Genesis(_) => false,
    });
    KitRestored {
        device_id: e.device_id,
        name: e.name.clone(),
        kind: e.kind,
        mode: e.mode,
        name_in_use: t.roster.iter().any(|r| r.name == e.name),
        rotated,
    }
}

/// The generation 0 account id of the store: the one params record whose
/// id is the account id it names (`NotFound` with none,
/// `InvalidFormat("account params")` with several).
fn store_account_id<S: RecordStore>(store: &S) -> Result<Id> {
    let ids: BTreeSet<Id> = store
        .list(RecordKind::AccountParams)?
        .iter()
        .filter_map(|r| {
            AccountParams::decode(&r.data)
                .ok()
                .filter(|p| p.account_id == r.id)
                .map(|p| p.account_id)
        })
        .collect();
    match ids.len() {
        0 => Err(Error::NotFound),
        1 => Ok(*ids.iter().next().expect("one id")),
        _ => Err(Error::InvalidFormat("account params")),
    }
}

/// Most key derivations (Argon2id) one restore runs (review m1): the
/// identities named by records whose chain verifies come first, newest
/// generation first, then the others (to tell a tampered head from a wrong
/// password). A hostile server can name any number of identities with
/// self-consistent forged chains; it cannot make a restore derive more
/// than this. The cost is that a kit more than 16 identities older than
/// the newest one tried is `WrongPassword`, not `OutdatedKit`.
pub const MAX_KIT_DERIVATIONS: usize = 16;

/// The account the kit opens: among the identities the lineage records
/// name (verified chains first, then newest generation first, at most
/// `MAX_KIT_DERIVATIONS` derivations), the first whose params verify under
/// it and whose keyset opens under the password and the kit's Secret Key.
/// `WrongPassword` when none opens.
fn open_with_kit<S: RecordStore>(
    store: &S,
    account_id: Id,
    records: &[LineageRecord],
    password: &str,
    secret_key: &SecretKey,
) -> Result<(Account, Record)> {
    let by_hash: BTreeMap<[u8; 32], &LineageRecord> =
        records.iter().map(|r| (r.hash(), r)).collect();
    let mut named: Vec<(bool, u64, &crate::crypto::IdentityVerifyingKey)> = by_hash
        .iter()
        .map(|(h, r)| {
            let verified = verified_chain(&by_hash, *h, account_id).is_some();
            (verified, r.generation(), r.identity_pub())
        })
        .collect();
    named.sort_by_key(|a| (std::cmp::Reverse(a.0), std::cmp::Reverse(a.1)));
    let mut tried: Vec<Id> = Vec::new();
    let mut derivations = 0usize;
    for (_, generation, identity) in named {
        let id = account_record_id(account_id, (generation > 0).then_some(identity));
        if tried.contains(&id) {
            continue;
        }
        tried.push(id);
        let (Some(params), Some(keyset)) = (
            store.get(RecordKind::AccountParams, id)?,
            store.get(RecordKind::Keyset, id)?,
        ) else {
            continue;
        };
        // G8: never derive with params the identity did not sign.
        if AccountParams::decode_verified(&params.data, identity).is_err() {
            continue;
        }
        if derivations >= MAX_KIT_DERIVATIONS {
            break;
        }
        derivations += 1;
        let expected = PinnedAccount {
            account_id,
            identity_pub: identity.clone(),
            kdf_floor: KdfParams {
                m_kib: 0,
                t: 0,
                p: 0,
                salt: [0; 32],
            },
        };
        if let Ok((account, _)) = Account::unlock_exporting_auk_at(
            password,
            secret_key,
            &params.data,
            &keyset.data,
            Some(&expected),
            0,
        ) {
            return Ok((account, params));
        }
    }
    Err(Error::WrongPassword)
}

impl<S: RecordStore> Repository<S> {
    /// "Restaurer avec mon Emergency Kit" (spec 7.5, R14). See the module
    /// doc. The caller ran a full sync first.
    ///
    /// In one transaction (conditional on no trust state, or on the one
    /// read): the trust state (head the record introducing the kit's
    /// identity, its roster from that record, `Verified`; at a genesis
    /// head, its creator and the devices listed are `Tofu`, as at a
    /// migration; this device outside the roster, `Current`), the new
    /// chain state (a new device id, the identity's params epoch) and the
    /// self-intro. The session opens on the kit's identity and looks for
    /// intros and rotations (`refresh_pending_rotation`).
    ///
    /// Refused, nothing written:
    /// - a bad name or mode: `Validation`; a store that keeps no chain
    ///   state: `InvalidFormat`;
    /// - a device with a trust state that is not locked (`Quarantined` or
    ///   `Orphaned`, stored or found): `Validation("device")` (its exits
    ///   are a follow or a re-pair); a store holding the account without a
    ///   trust state but with a device id (a legacy device migrates, it
    ///   does not restore): `Validation("device")`;
    /// - no identity of the lineage opens with the password and the Secret
    ///   Key: `WrongPassword`;
    /// - the identity it opens is introduced by no record whose chain to a
    ///   genesis verifies: `Integrity(Signature)`; by two different
    ///   rotations: `Validation("lineage")`;
    /// - an outdated kit: `OutdatedKit`.
    ///
    /// An account with no lineage record at all (never migrated) restores
    /// as before: a plain `unlock` (trust on first use), then the app runs
    /// `migrate_to_v2`.
    pub fn restore_from_kit(store: S, req: KitRestore<'_>) -> Result<Repository<S>> {
        check_name(req.name)?;
        check_mode(req.mode)?;
        if !store.persists_chain() {
            return Err(Error::InvalidFormat(
                "device registration needs a sync store",
            ));
        }
        let existing = trust_of(&store)?;
        match &existing {
            None if store.chain_state()?.device_id.is_some() => {
                return Err(refused("device", "holds the account"));
            }
            None => {}
            Some(t) => {
                let locked = matches!(
                    t.state,
                    DeviceLineageState::Quarantined { .. } | DeviceLineageState::Orphaned { .. }
                ) || look_for(&store, t)?.lock.is_some();
                if !locked {
                    return Err(refused("device", "not locked"));
                }
            }
        }
        let account_id = store_account_id(&store)?;
        if existing
            .as_ref()
            .is_some_and(|t| t.account_id != account_id)
        {
            return Err(IntegrityError::WrongContext.into());
        }
        let records: Vec<LineageRecord> = lineage_records(&store)?
            .into_iter()
            .filter(|r| r.account_id() == account_id)
            .collect();
        if records.is_empty() {
            if existing.is_some() {
                return Err(Error::NotFound);
            }
            return Self::unlock(store, req.password, req.secret_key, req.device);
        }

        // Spec 7.5 step 2: the identity the kit opens (2SKD).
        let (account, params) =
            open_with_kit(&store, account_id, &records, req.password, req.secret_key)?;
        let identity = account.params.identity_pub.clone();

        // Step 3: the record that introduces it, on a verified chain.
        let by_hash: BTreeMap<[u8; 32], &LineageRecord> =
            records.iter().map(|r| (r.hash(), r)).collect();
        let mut heads: Vec<[u8; 32]> = by_hash
            .iter()
            .filter(|(h, r)| {
                r.identity_pub() == &identity && verified_chain(&by_hash, **h, account_id).is_some()
            })
            .map(|(h, _)| *h)
            .collect();
        heads.sort();
        if heads.is_empty() {
            return Err(IntegrityError::Signature.into());
        }

        let new_id = Id::new();
        let me = req.device_keys.public(new_id)?;
        let chain = ChainState {
            sync_home: None,
            params_epoch: account.params.epoch,
            device_list: None,
            vault_list: None,
            approver_list: None,
            contact_book: None,
            device_id: Some(new_id),
        };
        let device = DeviceState {
            pinned: Some(pin(&account)),
            last_seen: BTreeMap::new(),
            epoch: 0,
        };
        // Every vault the saved device state or the store names: the
        // session's (empty) map replaces them on the next persist.
        let mut dropped: BTreeSet<Id> = req.device.last_seen.keys().copied().collect();
        dropped.extend(store.list(RecordKind::VaultKey)?.iter().map(|r| r.id));
        let mut repo = Repository {
            store,
            account,
            device,
            dropped,
            epoch_rewound: true,
            epoch_cache: Mutex::new(None),
            chain,
            travel_parked: BTreeSet::new(),
            travel_parked_items: std::collections::BTreeMap::new(),
            travelling: false,
            lists_forced: true,
            records_id: params.id,
            pending: None,
            lineage_mark: None,
            lineage_lock: None,
            contact_alerts: Vec::new(),
        };

        // At generation 0 the device list says who is listed (trust on
        // first use, as at a migration, spec 15).
        let list: Option<Stored<DeviceEntry>> = repo.read_list().unwrap_or_default();
        let (listed, revoked_2b) = list
            .as_ref()
            .map(|l| split_list(&l.body.entries))
            .unwrap_or_default();
        let head_hash = match heads.as_slice() {
            [h] => *h,
            many if many
                .iter()
                .all(|h| matches!(by_hash[h], LineageRecord::Genesis(_))) =>
            {
                let geneses = valid_geneses(&records, account_id, &identity);
                genesis_winner(
                    &geneses,
                    &stored_legacy_intros(&repo.store)?,
                    account_id,
                    &repo.account.params.signing_pub,
                    &listed,
                    &revoked_2b,
                    &me,
                )
                .map(|(h, _)| h)
                .ok_or_else(|| refused("lineage", "no genesis wins"))?
            }
            _ => return Err(refused("lineage", "ambiguous")),
        };
        let head_record = by_hash[&head_hash];
        let ancestry = verified_chain(&by_hash, head_hash, account_id)
            .ok_or(Error::Integrity(IntegrityError::Signature))?;

        let mut trust = TrustState::new(
            account_id,
            me.clone(),
            LineageHead {
                generation: head_record.generation(),
                hash: head_hash,
            },
            identity.clone(),
            Vec::new(),
            DeviceLineageState::Current,
        );
        match head_record {
            LineageRecord::Genesis(g) => {
                let creator = g.body.creator.clone();
                for id in &listed {
                    trust.levels.insert(*id, TrustLevel::Tofu);
                }
                trust.levels.insert(creator.device_id, TrustLevel::Tofu);
                trust.roster = vec![creator];
                trust.excluded.extend(revoked_2b.iter().copied());
                trust.migration_listed = listed.clone();
            }
            LineageRecord::Rotation(s) => {
                trust.roster = s.body.roster.clone();
                for e in &trust.roster {
                    trust.levels.insert(e.device_id, TrustLevel::Verified);
                }
            }
        }
        for r in &ancestry {
            if let LineageRecord::Rotation(s) = r {
                trust.add_revoked(&s.body.revoked);
            }
        }
        if let Some(old) = &existing {
            // What this device learned and decided stays (monotone sets,
            // the user's own answers, its own writes).
            trust.revoked.extend(old.revoked.iter().copied());
            trust.excluded.extend(old.excluded.iter().copied());
            trust.conflicted.extend(old.conflicted.iter().copied());
            for h in &old.ignored {
                trust.ignore(*h);
            }
            trust.other_genesis = old.other_genesis.clone();
            trust.genesis_alert = old.genesis_alert;
            trust.retired = old.retired.clone();
            if let Some(p) = repo
                .store
                .get(RecordKind::AccountParams, current_records_id(old))?
                && let Ok(left) = AccountParams::decode_verified(&p.data, &old.identity_pub)
                && old.identity_pub != identity
            {
                trust.retired.push(RetiredIdentity {
                    identity_id: crate::lineage::identity_id(&old.identity_pub),
                    sign_pub: left.signing_pub,
                    identity_pub: old.identity_pub.clone(),
                    generation: old.head.generation,
                });
            }
            trust.own_writes = old.own_writes.clone();
            let heads = match head_record {
                LineageRecord::Rotation(s) if s.body.parent == old.head.hash => {
                    s.body.from_heads.clone()
                }
                _ => BTreeMap::new(),
            };
            trust.own_writes.adopt(&heads);
        }
        // An excluded or revoked device has no level.
        let gone: BTreeSet<Id> = trust.excluded.union(&trust.revoked).copied().collect();
        trust.levels.retain(|id, _| !gone.contains(id));

        // The roster at the head as the other devices see it: the intros
        // (and, at a genesis, the legacy intros) made under it.
        if let LineageRecord::Genesis(g) = head_record {
            let eligible = listed.clone();
            let out = accept_legacy_intros(
                &stored_legacy_intros(&repo.store)?,
                &LegacyAnchor {
                    account_id,
                    genesis_hash: head_hash,
                    account_sign: &repo.account.params.signing_pub,
                    creator: g.body.creator.device_id,
                    listed: &eligible,
                },
            );
            apply_legacy(&mut trust, &out);
        }
        let intros = stored_intros(&repo.store)?;
        while let Some(next) = accept_intros(&trust, &intros) {
            trust = next;
        }

        // Step 4: an outdated kit restores nothing.
        if let Some(h) = newer_than_head(&trust, &records) {
            let bodies = rotations(&records);
            let body = bodies.get(&h).ok_or(Error::NotFound)?;
            let rotator = existing
                .as_ref()
                .and_then(|t| t.roster.iter().find(|e| e.device_id == body.rotator))
                .map_or_else(|| UNKNOWN_ROTATOR.to_string(), |e| e.name.clone());
            return Err(Error::OutdatedKit {
                rotator,
                at: body.issued_at,
            });
        }

        // Step 5: the self-intro, by this device's key and the identity.
        let entry = RosterEntry {
            device_id: new_id,
            sign_pub: me.sign_pub.clone(),
            kem_pub: me.kem_pub.clone(),
            name: req.name.to_owned(),
            kind: req.kind,
            mode: req.mode,
            introduced_by: None,
        };
        let body = IntroBody {
            format: LINEAGE_FORMAT,
            account_id,
            head: head_hash,
            entry,
            introducer: new_id,
            pop: sign_pop(req.device_keys, &account_id.0, &me)?,
        };
        let signed = sign_intro(body, req.device_keys, Some(&repo.account.keyset().identity))?;
        let intro = Record {
            id: intro_id(&signed.body),
            kind: RecordKind::DeviceIntro,
            version: trust.head.generation,
            data: signed.encode(),
        };

        // Spec 6.8 (O6): this device's acknowledgment of the head it pins,
        // in the same transaction (display only).
        let ack = crate::lineage::ack::ack_write(
            &repo.store,
            &trust,
            req.device_keys,
            crate::devices::now(),
        )?;
        let mut writes = vec![(intro, None)];
        writes.extend(ack);
        match &existing {
            None => {
                repo.store
                    .put_first_trust(writes, Some(repo.chain.clone()), &trust)?;
            }
            Some(old) => {
                // The device's unsent rotation and a password change made
                // under the identity it leaves never go out (as at a
                // follow, Task 11).
                let old_records = lineage_records(&repo.store)?;
                let mut drop = abandoned_rotation_rows(&repo.store, old, &rotations(&old_records))?;
                let left = current_records_id(old);
                for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
                    if repo.store.is_pending_write(kind, left)? && !drop.contains(&(kind, left)) {
                        drop.push((kind, left));
                    }
                }
                if !drop.is_empty() {
                    let stored = repo.store.chain_state()?;
                    repo.store
                        .put_follow(Vec::new(), stored, old, old, Vec::new(), drop)?;
                }
                repo.store.put_with_trust_cas(
                    writes,
                    Vec::new(),
                    Some(repo.chain.clone()),
                    old,
                    &trust,
                )?;
            }
        }
        // Committed: nothing below fails the call.
        let _ = repo.refresh_pending_rotation();
        let _ = repo.replay_own_writes();
        Ok(repo)
    }

    /// `Validation("device", "not pinned")` on a kit-restored device no
    /// device pinned yet: it signs no device or vault list (spec 7.5 step
    /// 5 as ruled, Task 15).
    pub(crate) fn signs_lists(&self) -> Result<()> {
        match trust_of(&self.store)? {
            Some(t) => check_pinned(&t),
            None => Ok(()),
        }
    }

    /// Whether this device was restored with the Emergency Kit and no
    /// device pinned it yet (nor did the user claim it is the only one).
    /// `false` without a trust state.
    pub fn awaiting_pin(&self) -> Result<bool> {
        Ok(trust_of(&self.store)?.is_some_and(|t| kit_unpinned(&t)))
    }

    /// The devices restored with the Emergency Kit that ask this device to
    /// trust them (spec 7.5 step 5), sorted by id: valid self-intros under
    /// this device's head. Empty without a trust state, on a device not
    /// pinned itself, or outside `Current` and `Rotating`.
    pub fn kit_restored_devices(&self) -> Result<Vec<KitRestored>> {
        let Some(t) = trust_of(&self.store)? else {
            return Ok(Vec::new());
        };
        if kit_unpinned(&t)
            || !matches!(
                t.state,
                DeviceLineageState::Current | DeviceLineageState::Rotating { .. }
            )
        {
            return Ok(Vec::new());
        }
        let intros = stored_intros(&self.store)?;
        let records = lineage_records(&self.store)?;
        Ok(self_intros(&t, &intros)
            .into_values()
            .map(|i| kit_restored(&t, &records, i))
            .collect())
    }

    /// Review concern 2: the kit-restored devices this device never pinned
    /// that signed a rotation (`KitRestored::rotated`). Non-empty means
    /// someone holding the latest kit and the master password changed the
    /// keys without this device: the app shows the alert and its actions
    /// (change the password, new kit, reject). Nothing here trusts that
    /// rotation (its rotator is not in the roster). Read from the stored
    /// records each time; rejecting the device ends it.
    pub fn kit_rotation_alerts(&self) -> Result<Vec<KitRestored>> {
        Ok(self
            .kit_restored_devices()?
            .into_iter()
            .filter(|k| k.rotated)
            .collect())
    }

    /// The user's yes to `kit_restored_devices` (R14): in one transaction
    /// conditional on the trust state read and the device list's version,
    /// this device's intro for it (signed by `device_keys`, its proof of
    /// possession taken from its self-intro), its device list entry
    /// (added by this device) unless listed already, and the trust state
    /// with it in the roster, `Tofu` (fix round 3: a yes is not a
    /// verification; `verify_device` upgrades it). The other devices pin
    /// it from that intro, `Tofu` too (it has a kit self-intro).
    ///
    /// Refused: a read-only or locked device (`ReadOnly`); no trust state,
    /// other device keys, a device not pinned itself, a state other than
    /// `Current` or `Rotating`, an id with no valid self-intro, a bad name
    /// or mode, a full roster: `Validation`; a lost race: `Conflict`.
    pub fn accept_kit_restored(&mut self, id: Id, device_keys: &DeviceKeys) -> Result<()> {
        self.writable()?;
        let trust = trust_of(&self.store)?.ok_or_else(|| refused("device", "no device keys"))?;
        let me = trust.me.device_id;
        if device_keys.public(me)? != trust.me {
            return Err(refused("device", "other device keys"));
        }
        check_pinned(&trust)?;
        if !matches!(
            trust.state,
            DeviceLineageState::Current | DeviceLineageState::Rotating { .. }
        ) {
            return Err(refused("device", "state"));
        }
        let intros = stored_intros(&self.store)?;
        let found = self_intros(&trust, &intros);
        let asked = found
            .get(&id)
            .ok_or_else(|| refused("device", "no kit intro"))?;
        // Review I1: accepting a device that already rotated would make
        // its rotation valid here (a prompt, or a quarantine if it revoked
        // this device). Refused: re-pair from it instead.
        if kit_restored(&trust, &lineage_records(&self.store)?, asked).rotated {
            return Err(refused("device", "already rotated"));
        }
        let asked_entry = &asked.body.entry;
        check_name(&asked_entry.name)?;
        check_mode(asked_entry.mode)?;
        if trust.roster.len() >= MAX_ROSTER {
            return Err(refused("device", "roster full"));
        }
        let entry = RosterEntry {
            introduced_by: Some(me),
            ..asked_entry.clone()
        };
        let mut writes = vec![(
            intro_record(&trust, entry.clone(), asked.body.pop.clone(), device_keys)?,
            None,
        )];
        let current = self.read_list::<DeviceEntry>()?;
        let mut list_body = None;
        if current.as_ref().is_none_or(|c| c.body.entry(id).is_none()) {
            let mut entries: Vec<DeviceEntry> = current
                .as_ref()
                .map(|c| c.body.entries.clone())
                .unwrap_or_default();
            entries.push(DeviceEntry {
                device_id: id,
                name: entry.name.clone(),
                kind: entry.kind,
                mode: entry.mode,
                added_at: now(),
                added_by: Some(me),
                revoked_at: None,
            });
            let (rec, expected, body) = self.list_write(current.as_ref(), entries)?;
            writes.push((rec, expected));
            list_body = Some(body);
        }
        let mut next = trust.clone();
        insert_sorted(&mut next.roster, entry);
        // Fix round 3 (N3): a yes is not a verification. Anyone with the
        // kit and the password can restore, so the device is `Tofu` until
        // "Vérifier mes appareils" (`verify_device`) runs with it.
        next.levels.insert(id, TrustLevel::Tofu);
        self.store
            .put_with_trust_cas(writes, Vec::new(), None, &trust, &next)?;
        if let Some(body) = list_body {
            DeviceEntry::set_seen(&mut self.chain, body.seen());
        }
        Ok(())
    }

    /// The user's no to `kit_restored_devices`: the device is excluded on
    /// this device (its intros are no longer accepted here, its rotations
    /// not valid). Conditional on the trust state read (`Conflict`).
    /// Refused as `accept_kit_restored` (no device keys needed): read-only
    /// or locked, no trust state, not pinned, not `Current` or `Rotating`,
    /// no valid self-intro for `id`. A device that already rotated can be
    /// rejected (it ends `kit_rotation_alerts`).
    pub fn reject_kit_restored(&mut self, id: Id) -> Result<()> {
        self.writable()?;
        let trust = trust_of(&self.store)?.ok_or_else(|| refused("device", "no device keys"))?;
        check_pinned(&trust)?;
        if !matches!(
            trust.state,
            DeviceLineageState::Current | DeviceLineageState::Rotating { .. }
        ) {
            return Err(refused("device", "state"));
        }
        let intros = stored_intros(&self.store)?;
        if !self_intros(&trust, &intros).contains_key(&id) {
            return Err(refused("device", "no kit intro"));
        }
        let mut next = trust.clone();
        next.excluded.insert(id);
        next.levels.remove(&id);
        self.store
            .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
    }

    /// Spec 7.5 as amended (Task 15): on a device restored with the kit
    /// and not pinned yet, the user states that no other device of the
    /// account remains ("Je n'ai plus d'autre appareil", the app asks the
    /// master password first). The device joins its own roster
    /// (`Verified`, the entry of its self-intro), so it may rotate, pair
    /// and sign lists from then on; its first rotation should remove the
    /// devices it cannot reach. A device that still exists is cut off by
    /// that rotation (signed by a device it never pinned) and re-pairs.
    /// Conditional on the trust state read (`Conflict`).
    ///
    /// Refused: a read-only or locked device (`ReadOnly`); no trust state,
    /// a device already pinned, a state other than `Current`:
    /// `Validation("device")`; its self-intro under the head missing:
    /// `NotFound`.
    pub fn claim_only_device(&mut self) -> Result<()> {
        self.writable()?;
        let trust = trust_of(&self.store)?.ok_or_else(|| refused("device", "no device keys"))?;
        if !kit_unpinned(&trust) {
            return Err(refused("device", "pinned"));
        }
        if trust.state != DeviceLineageState::Current {
            return Err(refused("device", "state"));
        }
        let intros = stored_intros(&self.store)?;
        let entry = intros
            .iter()
            .find(|i| {
                i.identity_sig.is_some()
                    && i.body.head == trust.head.hash
                    && i.body.introducer == trust.me.device_id
                    && same_keys(&i.body.entry, &trust.me)
            })
            .map(|i| i.body.entry.clone())
            .ok_or(Error::NotFound)?;
        let mut next = trust.clone();
        insert_sorted(&mut next.roster, entry);
        next.levels.insert(trust.me.device_id, TrustLevel::Verified);
        self.store
            .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
    }
}
