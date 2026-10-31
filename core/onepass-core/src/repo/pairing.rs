//! Pairing with device keys, on the repository side (key rotation v2, spec
//! 5.2, 6.4, 7.4, 8.5, 15, R16, ruling A9).
//!
//! - The approver sends its trust snapshot (`Repository::trust_snapshot`)
//!   in a `Grant::FullV2`, and once the newcomer acknowledged it with its
//!   proof of possession over the account id, writes a signed intro for it
//!   and adds it to its roster, in one transaction
//!   (`Repository::introduce`). A legacy newcomer (plain `Confirmed`) is
//!   listed as before and marked `Tofu` (`Repository::mark_legacy_device`).
//! - Every device accepts the intros made under its head by a device of its
//!   roster that is neither revoked nor excluded (`accept_intros`, run by
//!   `Repository::refresh_pending_rotation`): the new device joins its
//!   roster at that head.
//! - After an adoption a device introduces again, under the new head, the
//!   devices it introduced itself that the new roster misses
//!   (`reintroduce`, from `follow::commit_adoption`), reusing their proof of
//!   possession over the account id from the first intro.
//! - A device that already holds the account re-pairs as a follow
//!   (`repair_from_grant`, ruling A9): its local data stays, its own writes
//!   are replayed under the approver's identity.
//!
//! Where the intro of a pairing comes from (spec 5.2 as amended
//! 2026-10-31): an intro's `pop` is over the account id (spec 6.4,
//! Task 2 ruling), which a newcomer does not know before the grant. Its
//! first proof of possession, over the session transcript, is what the
//! approver checks before granting; its second, over the account id it
//! learns from the grant, comes back as its acknowledgment (a second
//! `Message::ConfirmedWithKey`), and the intro is written then. The device
//! list entry is still written with the sealed grant (spec 2b 15.6).
//!
//! Where legacy intros live (spec 15, Task 14): in the same record kind,
//! `RecordKind::DeviceIntro` (11), immutable, data =
//! `SignedLegacyIntro::encode()`, version 0 (the genesis they attach to),
//! id `lineage::legacy_intro_id` (`SHA-256("onepass/intro-id/v1" ||
//! postcard(LegacyIntroBody))[..16]`, the intro-id prefix of spec 6.1, no
//! new label). A reader tells the two apart by strict decoding: a
//! record is an intro if it decodes as a `SignedIntro`, else a legacy intro
//! if it decodes as a `SignedLegacyIntro` (the layouts differ, so one
//! record never passes both strict decodings with valid key lengths; if it
//! ever did, its signatures could verify under one form only). They are
//! accepted against the genesis head, `Tofu`, by the one rule
//! `lineage::accept_legacy_intros` (applied by `crate::repo::migrate`; the
//! sharing branch's `contact::accept_legacy_intros` calls it at merge).
//! `accept_intros` here takes `SignedIntro`s only, and skips a kit
//! self-intro (an intro with an identity signature, Task 15).

use std::collections::BTreeMap;

use super::follow::{
    Adoption, abandoned_rotation_rows, commit_adoption, lineage_records, rotations,
};
use super::{Repository, trust_of};
use crate::account::{Account, AccountParams, Auk, PinnedAccount};
use crate::crypto::{HybridKemSecret, HybridSignature, KdfParams, SecretKey};
use crate::device_keys::{DeviceKeys, DevicePublic, verify_pop};
use crate::devices::{DeviceMode, check_name};
use crate::lineage::{
    IntroBody, LINEAGE_FORMAT, LineageRecord, MAX_ROSTER, RosterEntry, SignedIntro, identity_id,
    intro_id, sign_intro, verify_intro,
};
use crate::pairing::{DeviceInfo, FullGrantV2, MAX_TRUST_LINEAGE, TrustSnapshot, check_trust_for};
use crate::store::{Record, RecordKind, RecordStore, account_record_id};
use crate::sync::SyncStore;
use crate::trust::{DeviceLineageState, LineageHead, RetiredIdentity, TrustLevel, TrustState};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

fn public_of(e: &RosterEntry) -> DevicePublic {
    DevicePublic {
        device_id: e.device_id,
        sign_pub: e.sign_pub.clone(),
        kem_pub: e.kem_pub.clone(),
    }
}

pub(crate) fn same_keys(e: &RosterEntry, p: &DevicePublic) -> bool {
    e.sign_pub == p.sign_pub && e.kem_pub == p.kem_pub
}

pub(crate) fn insert_sorted(roster: &mut Vec<RosterEntry>, e: RosterEntry) {
    let at = roster.partition_point(|x| x.device_id < e.device_id);
    roster.insert(at, e);
}

/// Every intro record of the store that decodes as a `SignedIntro`; the
/// others (legacy intros, garbage) are skipped.
fn stored_intros<S: RecordStore + ?Sized>(store: &S) -> Result<Vec<SignedIntro>> {
    Ok(store
        .list(RecordKind::DeviceIntro)?
        .iter()
        .filter_map(|r| SignedIntro::decode(&r.data).ok())
        .collect())
}

/// The intro record for `entry` under `trust`'s head, signed by this
/// device.
fn intro_record(
    trust: &TrustState,
    entry: RosterEntry,
    pop: HybridSignature,
    keys: &DeviceKeys,
) -> Result<Record> {
    let body = IntroBody {
        format: LINEAGE_FORMAT,
        account_id: trust.account_id,
        head: trust.head.hash,
        entry,
        introducer: trust.me.device_id,
        pop,
    };
    let signed = sign_intro(body, keys, None)?;
    Ok(Record {
        id: intro_id(&signed.body),
        kind: RecordKind::DeviceIntro,
        version: trust.head.generation,
        data: signed.encode(),
    })
}

/// Spec 6.4: the roster `trust` gets from `intros`. An intro counts when it
/// is for this account and the current head, carries no identity
/// signature, is signed by a roster device that is neither revoked nor
/// excluded (its key from the local roster), names that device as the
/// entry's `introduced_by`, and its proof of possession over the account id
/// verifies; the new device must not be this one, revoked, excluded or in
/// the roster already (a roster device is never re-keyed). Two valid
/// intros that give one device two keys add neither. The device joins at
/// `Verified` (pinned through a SAS pairing), the roster stays sorted and
/// within 64 entries. `None` when nothing changes, or the device is not
/// `Current`, `Candidate` or `Rotating`.
pub(crate) fn accept_intros(trust: &TrustState, intros: &[SignedIntro]) -> Option<TrustState> {
    if !matches!(
        trust.state,
        DeviceLineageState::Current
            | DeviceLineageState::Candidate { .. }
            | DeviceLineageState::Rotating { .. }
    ) {
        return None;
    }
    let mut found: BTreeMap<Id, Vec<(Id, &RosterEntry)>> = BTreeMap::new();
    for i in intros {
        let b = &i.body;
        let new = b.entry.device_id;
        if i.identity_sig.is_some()
            || b.account_id != trust.account_id
            || b.head != trust.head.hash
            || new == trust.me.device_id
            || new == b.introducer
            || b.entry.introduced_by != Some(b.introducer)
            || trust.revoked.contains(&new)
            || trust.excluded.contains(&new)
            || trust.revoked.contains(&b.introducer)
            || trust.excluded.contains(&b.introducer)
            || trust.roster.iter().any(|e| e.device_id == new)
        {
            continue;
        }
        let Some(introducer) = trust.roster.iter().find(|e| e.device_id == b.introducer) else {
            continue;
        };
        if verify_intro(i, &introducer.sign_pub).is_err() {
            continue;
        }
        found.entry(new).or_default().push((intro_id(b), &b.entry));
    }
    let mut next = trust.clone();
    for (id, mut candidates) in found {
        candidates.sort_by_key(|c| c.0);
        let first = candidates[0].1;
        if candidates
            .iter()
            .any(|(_, e)| e.sign_pub != first.sign_pub || e.kem_pub != first.kem_pub)
        {
            continue;
        }
        if next.roster.len() >= MAX_ROSTER {
            break;
        }
        insert_sorted(&mut next.roster, first.clone());
        next.levels.insert(id, TrustLevel::Verified);
    }
    (next.roster != trust.roster).then_some(next)
}

/// `accept_intros` on the stored intros, written conditionally on `trust`
/// (a `Conflict` leaves it for the next look). Returns the trust state in
/// force.
pub(crate) fn apply_intros<S: RecordStore + ?Sized>(
    store: &mut S,
    trust: TrustState,
) -> Result<TrustState> {
    let Some(next) = accept_intros(&trust, &stored_intros(store)?) else {
        return Ok(trust);
    };
    match store.put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next) {
        Ok(()) => Ok(next),
        Err(Error::Conflict) => Ok(trust),
        Err(e) => Err(e),
    }
}

/// Spec 6.4, 8.5: after an adoption (`old` to `next`, committed), introduce
/// again under the new head every device this one introduced (its
/// `introduced_by`) that the new roster misses and that is neither revoked
/// nor excluded, with the proof of possession over the account id of a
/// stored intro of that device and key. One write, conditional on `next`.
/// A device whose proof is not found here is left out (its next pairing
/// introduces it).
pub(crate) fn reintroduce<S: RecordStore + ?Sized>(
    store: &mut S,
    next: &TrustState,
    old: &TrustState,
    keys: &DeviceKeys,
) -> Result<()> {
    let me = next.me.device_id;
    if keys.public(me)? != next.me {
        return Ok(());
    }
    let intros = stored_intros(store)?;
    let mut after = next.clone();
    let mut writes = Vec::new();
    for e in &old.roster {
        let id = e.device_id;
        if e.introduced_by != Some(me)
            || id == me
            || after.roster.iter().any(|r| r.device_id == id)
            || after.revoked.contains(&id)
            || after.excluded.contains(&id)
        {
            continue;
        }
        if after.roster.len() >= MAX_ROSTER {
            break;
        }
        let public = public_of(e);
        let Some(pop) = intros
            .iter()
            .filter(|i| {
                i.body.account_id == next.account_id
                    && i.body.entry.device_id == id
                    && same_keys(&i.body.entry, &public)
            })
            .map(|i| &i.body.pop)
            .find(|p| verify_pop(&next.account_id.0, &public, p).is_ok())
        else {
            continue;
        };
        writes.push((intro_record(next, e.clone(), pop.clone(), keys)?, None));
        insert_sorted(&mut after.roster, e.clone());
        let level = old.levels.get(&id).copied().unwrap_or(TrustLevel::Verified);
        after.levels.insert(id, level);
    }
    if writes.is_empty() {
        return Ok(());
    }
    store.put_with_trust_cas(writes, Vec::new(), None, next, &after)
}

impl<S: RecordStore> Repository<S> {
    /// What this device trusts, for a `Grant::FullV2` (spec 5.2): its
    /// lineage chain from the genesis to its head (walked back by parent
    /// hash from the stored records), its roster and its device public key.
    /// Refused without a trust state (`Validation("device")`), outside
    /// `Current` and `Rotating` (`Validation("device")`: a device waiting
    /// for the user, locked or orphaned pins nobody); a chain record missing
    /// is `NotFound`.
    pub fn trust_snapshot(&self) -> Result<TrustSnapshot> {
        let trust = trust_of(&self.store)?.ok_or_else(|| refused("device", "no device keys"))?;
        if !matches!(
            trust.state,
            DeviceLineageState::Current | DeviceLineageState::Rotating { .. }
        ) {
            return Err(refused("device", "state"));
        }
        let records = lineage_records(&self.store)?;
        let by_hash: BTreeMap<[u8; 32], &LineageRecord> =
            records.iter().map(|r| (r.hash(), r)).collect();
        let mut chain = Vec::new();
        let mut h = trust.head.hash;
        loop {
            let r = *by_hash.get(&h).ok_or(Error::NotFound)?;
            chain.push(r.clone());
            if chain.len() > MAX_TRUST_LINEAGE {
                return Err(refused("lineage", "too long"));
            }
            match r.parent() {
                Some(p) => h = p,
                None => break,
            }
        }
        chain.reverse();
        // A roster device without a recorded level is sent as `Tofu`: the
        // newcomer never pins it higher than this device does.
        let levels = trust
            .roster
            .iter()
            .map(|e| {
                let level = if e.device_id == trust.me.device_id {
                    TrustLevel::Verified
                } else {
                    trust
                        .levels
                        .get(&e.device_id)
                        .copied()
                        .unwrap_or(TrustLevel::Tofu)
                };
                (e.device_id, level)
            })
            .collect();
        let snapshot = TrustSnapshot {
            lineage: chain,
            roster: trust.roster,
            approver: trust.me,
            levels,
        };
        snapshot.check()?;
        Ok(snapshot)
    }

    /// The approver's intro for a newcomer that acknowledged its `FullV2`
    /// (spec 5.2, 6.4): `newcomer` and `account_pop` from the session
    /// (`Approver::newcomer_key`, `Approver::newcomer_account_pop`), `info`
    /// from the Hello, `mode` the granted one. Writes, in one transaction
    /// conditional on the trust state read, the signed intro record (id
    /// `intro_id`, version the head's generation, immutable) and the
    /// trust state with the newcomer in the roster (`Verified`,
    /// `introduced_by` this device).
    ///
    /// Refused: a read-only or locked device (`ReadOnly`, as any write);
    /// no trust state or other device keys (`Validation("device")`); a
    /// `newcomer` whose id is not `info`'s, this device's, revoked or
    /// excluded, or a full roster (`Validation("device")`); a bad name
    /// (`Validation`); a proof of possession that does not verify over the
    /// account id (`Integrity(Signature)`); a roster that pins another key
    /// for that id (`Integrity(WrongContext)`). A newcomer already in the
    /// roster with these keys is a no-op.
    pub fn introduce(
        &mut self,
        newcomer: &DevicePublic,
        info: &DeviceInfo,
        mode: DeviceMode,
        account_pop: &HybridSignature,
        device_keys: &DeviceKeys,
    ) -> Result<()> {
        self.writable()?;
        let trust = trust_of(&self.store)?.ok_or_else(|| refused("device", "no device keys"))?;
        let me = trust.me.device_id;
        if device_keys.public(me)? != trust.me {
            return Err(refused("device", "other device keys"));
        }
        check_name(&info.name)?;
        let id = newcomer.device_id;
        if id != info.device_id
            || id == me
            || trust.revoked.contains(&id)
            || trust.excluded.contains(&id)
        {
            return Err(refused("device", "not introducible"));
        }
        verify_pop(&trust.account_id.0, newcomer, account_pop)?;
        if let Some(e) = trust.roster.iter().find(|e| e.device_id == id) {
            return if same_keys(e, newcomer) {
                Ok(())
            } else {
                Err(IntegrityError::WrongContext.into())
            };
        }
        if trust.roster.len() >= MAX_ROSTER {
            return Err(refused("device", "roster full"));
        }
        let entry = RosterEntry {
            device_id: id,
            sign_pub: newcomer.sign_pub.clone(),
            kem_pub: newcomer.kem_pub.clone(),
            name: info.name.clone(),
            kind: info.kind,
            mode,
            introduced_by: Some(me),
        };
        let record = intro_record(&trust, entry.clone(), account_pop.clone(), device_keys)?;
        let mut next = trust.clone();
        insert_sorted(&mut next.roster, entry);
        next.levels.insert(id, TrustLevel::Verified);
        self.store
            .put_with_trust_cas(vec![(record, None)], Vec::new(), None, &trust, &next)
    }

    /// A newcomer paired without a device key (an older app sent plain
    /// `Confirmed`, spec 5.2, 15): it is trusted on first use, recorded as
    /// `Tofu` in this device's levels until its legacy intro (Task 14) or a
    /// verification upgrades it. A device without a trust state records
    /// nothing. Conditional on the trust state read (`Conflict`).
    pub fn mark_legacy_device(&mut self, id: Id) -> Result<()> {
        let Some(trust) = trust_of(&self.store)? else {
            return Ok(());
        };
        if trust.levels.get(&id) == Some(&TrustLevel::Tofu) {
            return Ok(());
        }
        if trust.roster.iter().any(|e| e.device_id == id) || id == trust.me.device_id {
            return Err(refused("device", "already pinned"));
        }
        let mut next = trust.clone();
        next.levels.insert(id, TrustLevel::Tofu);
        self.store
            .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
    }
}

/// Re-pair a device that already holds this account (spec 7.4, ruling A9):
/// the grant is applied as a follow, never as the empty-store import, so
/// the local data stays and this device's own writes are replayed under
/// the approver's identity (spec 10.4). `session` is open on the identity
/// the device is on (its keys sealed its own writes); the user confirmed
/// the approver's head (shown from the trust snapshot) and typed the
/// master password.
///
/// The snapshot rows are staged and committed as a remote fetch (the checks
/// of a hostile store apply). When the approver's head is this device's,
/// nothing moves: the session is opened again with the granted Secret Key.
/// Otherwise the head, identity and roster become the approver's (this
/// device kept, with its own entry), every revocation along its chain is
/// added, the identity left is retired, the own-write log goes to its
/// replay (against the head's `from_heads` when the head is a child of this
/// device's head, else against nothing), and the session opens on the new
/// identity with its vaults from the head's `from_heads`, in the one
/// transaction of a follow (`commit_adoption`). Returns the session, its
/// Account Unlock Key and the Secret Key.
///
/// Refused, with nothing adopted: no trust state, other device keys, a
/// grant for another device id, another account, or a quarantined device
/// (`Validation("device")`, `Validation("account")`); a session on another
/// identity (`Validation("session")`); a trust snapshot this device cannot
/// pin (`Validation`, `InvalidFormat`); an approver whose head is an
/// ancestor of this device's (`Validation("rotation")`: it is behind); the
/// head's params or keyset missing (`NotFound`); a wrong password
/// (`WrongPassword`).
pub fn repair_from_grant(
    session: Repository<SyncStore>,
    grant: &FullGrantV2,
    password: &str,
    device_keys: &DeviceKeys,
) -> Result<(Repository<SyncStore>, Auk, SecretKey)> {
    let trust = trust_of(&session.store)?.ok_or_else(|| refused("device", "no device keys"))?;
    let me = trust.me.device_id;
    if device_keys.public(me)? != trust.me || grant.full.device_id != me {
        return Err(refused("device", "other device"));
    }
    if grant.full.account_id != trust.account_id {
        return Err(refused("account", "another account"));
    }
    if matches!(
        trust.state,
        DeviceLineageState::Quarantined { .. } | DeviceLineageState::Legacy
    ) {
        return Err(refused("device", "state"));
    }
    if session.account.params.identity_pub != trust.identity_pub {
        return Err(refused("session", "another identity"));
    }
    grant.check()?;
    check_trust_for(&grant.trust, &trust.me)?;
    let secret_key = SecretKey::parse(&grant.full.secret_key)?;
    let head = grant.trust.head().ok_or(Error::NotFound)?.clone();
    let head_hash = head.hash();

    // The approver is behind when its head is on this device's own chain,
    // below its head.
    let mine = lineage_records(&session.store)?;
    let by_hash: BTreeMap<[u8; 32], &LineageRecord> = mine.iter().map(|r| (r.hash(), r)).collect();
    let mut h = by_hash.get(&trust.head.hash).and_then(|r| r.parent());
    while let Some(p) = h {
        if p == head_hash {
            return Err(refused("rotation", "approver behind"));
        }
        h = by_hash.get(&p).and_then(|r| r.parent());
    }

    let keyset = session.account.keyset();
    let mut left_kem = Vec::with_capacity(keyset.retired_kem.len() + 1);
    for k in std::iter::once(&keyset.kem).chain(&keyset.retired_kem) {
        left_kem.push(HybridKemSecret::from_bytes(&k.to_bytes())?);
    }
    let device = session.device.clone();
    let Repository { mut store, .. } = session;
    for r in &grant.full.snapshot {
        store.stage_remote(r.to_remote_change()?)?;
    }
    store.commit_remote()?;

    if head_hash == trust.head.hash {
        let (repo, auk) = Repository::unlock_exporting_auk(store, password, &secret_key, device)?;
        return Ok((repo, auk, secret_key));
    }

    let rid = account_record_id(
        trust.account_id,
        (head.generation() > 0).then_some(head.identity_pub()),
    );
    let params = store
        .get(RecordKind::AccountParams, rid)?
        .ok_or(Error::NotFound)?;
    let keyset_rec = store.get(RecordKind::Keyset, rid)?.ok_or(Error::NotFound)?;
    // The approver vouches for its head through the SAS: the params are
    // verified under the identity its head names.
    let expected = PinnedAccount {
        account_id: trust.account_id,
        identity_pub: head.identity_pub().clone(),
        kdf_floor: KdfParams {
            m_kib: 0,
            t: 0,
            p: 0,
            salt: [0; 32],
        },
    };
    let (account, auk): (Account, Auk) = Account::unlock_exporting_auk_at(
        password,
        &secret_key,
        &params.data,
        &keyset_rec.data,
        Some(&expected),
        0,
    )?;
    let current = store
        .get(
            RecordKind::AccountParams,
            account_record_id(
                trust.account_id,
                (trust.head.generation > 0).then_some(&trust.identity_pub),
            ),
        )?
        .ok_or(Error::NotFound)?;
    let left = AccountParams::decode_verified(&current.data, &trust.identity_pub)?;

    let own_entry = trust
        .roster
        .iter()
        .find(|e| e.device_id == me)
        .cloned()
        .ok_or_else(|| refused("device", "not in its own roster"))?;
    let mut next = trust.clone();
    next.head = LineageHead {
        generation: head.generation(),
        hash: head_hash,
    };
    next.identity_pub = head.identity_pub().clone();
    // Review m6: a device this one revoked or excluded stays out.
    next.roster = grant
        .trust
        .roster
        .iter()
        .filter(|e| !trust.revoked.contains(&e.device_id) && !trust.excluded.contains(&e.device_id))
        .cloned()
        .collect();
    if !next.roster.iter().any(|e| e.device_id == me) {
        if next.roster.len() >= MAX_ROSTER {
            return Err(refused("device", "roster full"));
        }
        insert_sorted(&mut next.roster, own_entry);
    }
    // Review I1: this device `Verified`; another device at the level this
    // device recorded, else the approver's (never a default).
    let mut levels = BTreeMap::new();
    for e in &next.roster {
        let level = if e.device_id == me {
            TrustLevel::Verified
        } else {
            trust
                .levels
                .get(&e.device_id)
                .copied()
                .or_else(|| grant.trust.level(e.device_id))
                .ok_or_else(|| refused("trust snapshot", "level missing"))?
        };
        levels.insert(e.device_id, level);
    }
    next.levels = levels;
    next.add_revoked(&grant.trust.revoked());
    if head.identity_pub() != &trust.identity_pub {
        next.retired.push(RetiredIdentity {
            identity_id: identity_id(&trust.identity_pub),
            sign_pub: left.signing_pub,
            identity_pub: trust.identity_pub.clone(),
            generation: trust.head.generation,
        });
    }
    next.state = DeviceLineageState::Current;
    // Review I3: a rotator re-paired onto another head drops what of its
    // own rotation never went out, in the follow's transaction.
    let drop_pending = abandoned_rotation_rows(&store, &trust, &rotations(&mine))?;
    let from_heads = match &head {
        LineageRecord::Rotation(s) => s.body.from_heads.clone(),
        LineageRecord::Genesis(_) => BTreeMap::new(),
    };
    let child = head.parent() == Some(trust.head.hash);
    let no_heads = BTreeMap::new();
    next.own_writes
        .adopt(if child { &from_heads } else { &no_heads });
    let repo = commit_adoption(
        store,
        Adoption {
            trust: &trust,
            next,
            account,
            rid,
            from_heads,
            left_kem: Some(&left_kem),
            drop_pending,
            device_keys,
        },
    )?;
    Ok((repo, auk, secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKey;
    use crate::device_keys::sign_pop;
    use crate::devices::DeviceKind;

    struct Dev {
        keys: DeviceKeys,
        public: DevicePublic,
    }

    fn dev() -> Dev {
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(Id::new()).unwrap();
        Dev { keys, public }
    }

    fn entry(d: &Dev, by: Option<Id>) -> RosterEntry {
        RosterEntry {
            device_id: d.public.device_id,
            sign_pub: d.public.sign_pub.clone(),
            kem_pub: d.public.kem_pub.clone(),
            name: "Mac".into(),
            kind: DeviceKind::Mac,
            mode: DeviceMode::Personal,
            introduced_by: by,
        }
    }

    fn trust_of_me(me: &Dev, others: &[&Dev]) -> TrustState {
        let identity = IdentityKey::generate().unwrap().verifying_key();
        let mut roster = vec![entry(me, None)];
        roster.extend(others.iter().map(|d| entry(d, None)));
        roster.sort_by_key(|e| e.device_id);
        TrustState::new(
            Id([7; 16]),
            me.public.clone(),
            LineageHead {
                generation: 0,
                hash: [1; 32],
            },
            identity,
            roster,
            DeviceLineageState::Current,
        )
    }

    fn intro(t: &TrustState, by: &Dev, new: &Dev) -> SignedIntro {
        let pop = sign_pop(&new.keys, &t.account_id.0, &new.public).unwrap();
        let body = IntroBody {
            format: LINEAGE_FORMAT,
            account_id: t.account_id,
            head: t.head.hash,
            entry: entry(new, Some(by.public.device_id)),
            introducer: by.public.device_id,
            pop,
        };
        sign_intro(body, &by.keys, None).unwrap()
    }

    #[test]
    fn a_valid_intro_joins_the_roster() {
        let (me, b, n) = (dev(), dev(), dev());
        let t = trust_of_me(&me, &[&b]);
        let next = accept_intros(&t, &[intro(&t, &b, &n)]).unwrap();
        assert!(
            next.roster
                .iter()
                .any(|e| e.device_id == n.public.device_id)
        );
        assert!(
            next.roster
                .windows(2)
                .all(|w| w[0].device_id < w[1].device_id)
        );
        assert_eq!(
            next.levels.get(&n.public.device_id),
            Some(&TrustLevel::Verified)
        );
        // Accepted once: nothing more to do.
        assert_eq!(accept_intros(&next, &[intro(&t, &b, &n)]), None);
    }

    #[test]
    fn refused_intros() {
        let (me, b, n, stranger) = (dev(), dev(), dev(), dev());
        let t = trust_of_me(&me, &[&b]);
        // By a device not in the roster.
        assert_eq!(accept_intros(&t, &[intro(&t, &stranger, &n)]), None);
        // By a revoked or an excluded introducer.
        let mut revoked = t.clone();
        revoked.add_revoked(&[b.public.device_id]);
        assert_eq!(accept_intros(&revoked, &[intro(&t, &b, &n)]), None);
        let mut excluded = t.clone();
        excluded.excluded.insert(b.public.device_id);
        assert_eq!(accept_intros(&excluded, &[intro(&t, &b, &n)]), None);
        // Under another head.
        let mut moved = t.clone();
        moved.head.hash = [2; 32];
        assert_eq!(accept_intros(&moved, &[intro(&t, &b, &n)]), None);
        // For a revoked new device.
        let mut gone = t.clone();
        gone.add_revoked(&[n.public.device_id]);
        assert_eq!(accept_intros(&gone, &[intro(&t, &b, &n)]), None);
        // A pop by another key.
        let mut forged = intro(&t, &b, &n);
        forged.body.pop = sign_pop(&stranger.keys, &t.account_id.0, &n.public).unwrap();
        let forged = sign_intro(forged.body, &b.keys, None).unwrap();
        assert_eq!(accept_intros(&t, &[forged]), None);
        // Two keys for one id: neither.
        let other = Dev {
            keys: DeviceKeys::generate_software().unwrap(),
            public: DevicePublic {
                device_id: n.public.device_id,
                ..dev().public
            },
        };
        let other = Dev {
            public: other.keys.public(n.public.device_id).unwrap(),
            keys: other.keys,
        };
        assert_eq!(
            accept_intros(&t, &[intro(&t, &b, &n), intro(&t, &b, &other)]),
            None
        );
        // A locked device accepts nothing.
        let mut orphaned = t.clone();
        orphaned.state = DeviceLineageState::Orphaned {
            child: [3; 32],
            rotator: b.public.device_id,
            resume: None,
        };
        assert_eq!(accept_intros(&orphaned, &[intro(&t, &b, &n)]), None);
    }
}
