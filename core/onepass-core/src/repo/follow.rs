//! Key rotation v2 on a remaining device (spec 7.2, 9, R4, R5, R10, R12,
//! K9): what the device asks the user, and the two answers.
//!
//! - `pending_rotation` reads the trust state and the lineage records,
//!   without unlocking, runs the resolver (`lineage::resolve`) and turns a
//!   `Prompt` into what the confirmation screen shows: for each choice,
//!   the rotator's name and the names of the devices it removed, **from
//!   the local roster** (never from the record), when it was issued, and
//!   the rotation code. A choice is offered only once its delivery for
//!   this device, its params and its keyset are present and hash-match.
//! - `follow_rotation` ("C'est moi" and the master password): open this
//!   device's Secret Key delivery with its device keys, open the new
//!   identity's params and keyset with the password and that Secret Key,
//!   then move to the new head in one local transaction (trust state and
//!   chain state, conditional on the trust state read), and open a session
//!   on the new identity whose vaults start from the rotation's
//!   `from_heads` (R12). No Secret Key is typed (R4); a biometric-only
//!   device follows with the password once (O5).
//! - `reject_rotation` ("Ce n'était pas moi"): the record joins `ignored`,
//!   its signer `excluded` on request, and the device is `Current` again.
//!
//! The follow moves the own-write log to its replay list and replays it
//! under the new keys (`crate::repo::replay`, spec 10.4).
//!
//! A normal unlock never follows (K9): it opens the identity the device
//! is on, and when a prompt is pending the session is read-only
//! (`Error::ReadOnly`, R10) and reports it (`Repository::pending_prompt`).
//!
//! - `follow_switch` (Task 11, spec 8.5): the same from the session open
//!   on the identity the device is on, which a switch needs (its own copy
//!   of each vault is wrapped again for the replay); the prompt names the
//!   devices along the path from the divergence to the target, flags a
//!   removal of a rotator of the device's own chain on the other branch,
//!   and lists the removals to re-apply (`Repository::reapply`).
//!
//! Quarantine and exclusion (Task 12, spec 8.1, 8.2, 8.4, R8, O1): a valid
//! lineage record that revokes this device locks it (no unlock, no read,
//! no write, no push); one that does not list it makes it `Orphaned`
//! (reads, no write, no push). `quarantine_tick` records the quarantine
//! with the caller's clock and erases the store 7 days later;
//! `quarantine_resolve` erases now or, with the password, answers "Ce
//! n'était pas moi" (the signer excluded, back to `Current`), for an
//! orphaned device too. Nothing else erases.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use aws_lc_rs::digest::{self, SHA256, digest};

use super::{DeviceState, Repository, pin, trust_of};
use crate::account::{Account, AccountParams, Auk, PinnedAccount};
use crate::chain::ChainState;
use crate::crypto::{HybridKemSecret, KdfParams, SecretKey, unwrap_key, wrap_key};
use crate::device_keys::DeviceKeys;
use crate::lineage::resolve::{Completeness, Decision, Prompt, PromptKind, resolve};
use crate::lineage::{LineageRecord, RotationBody, delivery_id, identity_id, rotation_code};
use crate::store::{Record, RecordKind, RecordStore, account_record_id};
use crate::trust::{DeviceLineageState, LineageHead, RetiredIdentity, TrustLevel, TrustState};
use crate::vault::{Vault, kem_context};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// What the confirmation screen shows (spec 9). Names come from the local
/// roster only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationPrompt {
    pub kind: PromptKind,
    /// One for `Single`, `Switch` and `Reapply`; every side of a `Mutual`.
    pub choices: Vec<PromptChoice>,
    /// The 6-digit rotation code of the only choice (O2: shown, comparing
    /// it is not mandatory); `None` for a `Mutual` prompt.
    pub code: Option<u32>,
    /// A rotator of a choice is trusted on first use only (O7, spec 15):
    /// "Cet appareil n'a pas été vérifié depuis la mise à jour."
    pub tofu_signer: bool,
    /// This device changed the master password and has not pushed it yet
    /// (spec 7.3): the screen offers to apply it to the new keys.
    pub pending_password_change: bool,
    /// A switch whose path removes the rotator of a record this device is
    /// on (controller ruling, Task 4 review): "iPhone de Quentin a retiré
    /// iPad de Quentin sur un autre jeu de clés." (`rotator_name` removed
    /// `revoked_names`). Never a quarantine, never adopted without the user.
    pub cross_branch_revocation: bool,
    /// The devices this device removed that the choice keeps (spec 8.5
    /// step 5), local names: `Repository::reapply` removes them again
    /// after the follow, in the same user step.
    pub reapply_names: Vec<String>,
}

/// One record the user can confirm or reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptChoice {
    /// The lineage hash to pass to `follow_rotation` or `reject_rotation`.
    pub hash: [u8; 32],
    /// The device that made the keys: for a switch, the rotator of the
    /// first record past the divergence (the sibling that won).
    pub rotator_name: String,
    /// The devices it removed (for a switch, along the whole path to the
    /// target), in record order, without repeats.
    pub revoked_names: Vec<String>,
    /// Informative, from the target record.
    pub issued_at: i64,
    /// This device's delivery, the params and the keyset of the target are
    /// present and match its hashes: "C'est moi" can follow. An incomplete
    /// choice still makes the device read-only and can be rejected ("Ce
    /// n'était pas moi"); following it fails until the records arrive.
    pub complete: bool,
}

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, b).as_ref());
    out
}

/// Every lineage record of the store that decodes; the others are
/// ignored (the resolver never sees them).
pub(crate) fn lineage_records<S: RecordStore + ?Sized>(store: &S) -> Result<Vec<LineageRecord>> {
    Ok(store
        .list(RecordKind::Lineage)?
        .iter()
        .filter_map(|r| LineageRecord::decode(&r.data).ok())
        .collect())
}

pub(crate) fn rotations(records: &[LineageRecord]) -> BTreeMap<[u8; 32], &RotationBody> {
    records
        .iter()
        .filter_map(|r| match r {
            LineageRecord::Rotation(s) => Some((r.hash(), &s.body)),
            LineageRecord::Genesis(_) => None,
        })
        .collect()
}

/// Spec 7.2 "complete for me": this device's delivery, the params and the
/// keyset of `body` are present and match the hashes it lists.
fn complete_for<S: RecordStore + ?Sized>(
    store: &S,
    h: &[u8; 32],
    body: &RotationBody,
    me: Id,
) -> Result<bool> {
    let Some((_, want)) = body.deliveries.iter().find(|(id, _)| *id == me) else {
        return Ok(false);
    };
    let matches = |kind, id, want: &[u8; 32]| -> Result<bool> {
        Ok(store
            .get(kind, id)?
            .is_some_and(|r| sha256(&r.data) == *want))
    };
    let rid = identity_id(&body.identity_pub);
    if !matches(RecordKind::KeyDelivery, delivery_id(h, me), want)? {
        return Ok(false);
    }
    let Some(params) = store.get(RecordKind::AccountParams, rid)? else {
        return Ok(false);
    };
    if later_epoch(&params.data, body) {
        // The keyset was sealed again with the password change: the unlock
        // checks it against the verified params.
        return Ok(store.get(RecordKind::Keyset, rid)?.is_some());
    }
    Ok(sha256(&params.data) == body.params_hash
        && matches(RecordKind::Keyset, rid, &body.keyset_hash)?)
}

/// Controller ruling I6 (Task 9, spec 6.3 and 7.2): the params of the new
/// identity after a password change there (epoch 2 and on) no longer hash
/// to `params_hash`, which binds epoch 1 only. Such params count when they
/// verify under the identity the record names, for the same account, at
/// an epoch above 1 (G8: a params record the identity did not sign is
/// ignored).
fn later_epoch(params: &[u8], body: &RotationBody) -> bool {
    AccountParams::decode_verified(params, &body.identity_pub)
        .is_ok_and(|p| p.account_id == body.account_id && p.epoch > 1)
}

fn completeness<S: RecordStore + ?Sized>(
    store: &S,
    records: &[LineageRecord],
    me: Id,
) -> Result<Completeness> {
    let mut present = BTreeSet::new();
    for (h, body) in rotations(records) {
        if complete_for(store, &h, body, me)? {
            present.insert(h);
        }
    }
    Ok(Completeness { present })
}

/// A digest of everything a rotation prompt depends on: the lineage
/// records, the intros, the deliveries, the account params and keysets
/// (ids, versions, contents) and the trust state. A change means the prompt must be looked
/// for again.
pub(crate) fn lineage_mark<S: RecordStore + ?Sized>(store: &S) -> Result<[u8; 32]> {
    let mut ctx = digest::Context::new(&SHA256);
    for kind in [
        RecordKind::Lineage,
        RecordKind::DeviceIntro,
        RecordKind::KeyDelivery,
        RecordKind::AccountParams,
        RecordKind::Keyset,
    ] {
        let mut rows = store.list(kind)?;
        rows.sort_by_key(|r| r.id);
        for r in rows {
            ctx.update(&[kind.code()]);
            ctx.update(&r.id.0);
            ctx.update(&r.version.to_be_bytes());
            ctx.update(&sha256(&r.data));
        }
    }
    if let Some(mut t) = trust_of(store)? {
        // The own-write log changes with every item write and decides no
        // prompt.
        t.own_writes = Default::default();
        ctx.update(&t.encode());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    Ok(out)
}

/// The id of the account records of the trust state's identity (spec 6.6).
fn current_records_id(trust: &TrustState) -> Id {
    account_record_id(
        trust.account_id,
        (trust.head.generation > 0).then_some(&trust.identity_pub),
    )
}

/// A local roster name, or the device id for a device this one never
/// pinned (only possible along a switch path).
fn local_name(trust: &TrustState, id: Id) -> String {
    trust
        .roster
        .iter()
        .find(|e| e.device_id == id)
        .map_or_else(|| id.to_string(), |e| e.name.clone())
}

/// The records from the first one past this device's own chain down to
/// `target` (only `target` for a child of the head).
fn path_to<'a>(
    trust: &TrustState,
    bodies: &BTreeMap<[u8; 32], &'a RotationBody>,
    target: [u8; 32],
) -> Vec<&'a RotationBody> {
    let mut own = BTreeSet::from([trust.head.hash]);
    let mut h = trust.head.hash;
    while let Some(b) = bodies.get(&h) {
        own.insert(b.parent);
        h = b.parent;
    }
    let mut path = Vec::new();
    let mut h = target;
    while let Some(b) = bodies.get(&h) {
        path.push(*b);
        if own.contains(&b.parent) || path.len() > bodies.len() {
            break;
        }
        h = b.parent;
    }
    path.reverse();
    path
}

/// The resolver's prompt and what the screen shows for it, or `None` for
/// any other decision.
///
/// Controller ruling (Task 9 fix round 1): a valid record this device
/// cannot complete yet (its delivery, params or keyset missing or not
/// matching) still makes it `Candidate` at once, so a server withholding
/// a delivery cannot keep it writing under the old keys. When the
/// resolver waits for completeness only (`Wait` with no unknown parent),
/// it is asked again with every record that delivers to this device
/// counted as complete; the prompt it gives is shown with those choices
/// marked `complete: false`. The resolver's own rule stands: nothing
/// incomplete is ever adopted (`follow_rotation` fails on it).
fn look_in<S: RecordStore + ?Sized>(
    store: &S,
    trust: &TrustState,
    records: &[LineageRecord],
    complete: &Completeness,
) -> Result<Look> {
    let p = match resolve(trust, records, complete) {
        Decision::Prompt(p) => p,
        Decision::Wait { unknown_parent } if unknown_parent.is_empty() => {
            let me = trust.me.device_id;
            let mut assumed = complete.clone();
            for (h, b) in rotations(records) {
                if b.deliveries.iter().any(|(id, _)| *id == me) {
                    assumed.present.insert(h);
                }
            }
            match resolve(trust, records, &assumed) {
                Decision::Prompt(p) => p,
                _ => return Ok(Look::default()),
            }
        }
        Decision::Quarantine { by } => {
            return Ok(Look {
                prompt: None,
                lock: Some(LineageLock::Quarantine { by }),
            });
        }
        Decision::Orphaned { child } => {
            return Ok(Look {
                prompt: None,
                lock: Some(LineageLock::Orphaned { child }),
            });
        }
        _ => return Ok(Look::default()),
    };
    let bodies = rotations(records);
    let mut choices = Vec::with_capacity(p.children.len());
    let mut tofu_signer = false;
    for h in &p.children {
        let Some(target) = bodies.get(h) else {
            continue;
        };
        let path = path_to(trust, &bodies, *h);
        let first = path.first().copied().unwrap_or(target);
        let mut revoked = Vec::new();
        for b in &path {
            tofu_signer |= trust.levels.get(&b.rotator) == Some(&TrustLevel::Tofu);
            for id in &b.revoked {
                if !revoked.contains(id) {
                    revoked.push(*id);
                }
            }
        }
        choices.push(PromptChoice {
            hash: *h,
            rotator_name: local_name(trust, first.rotator),
            revoked_names: revoked.iter().map(|id| local_name(trust, *id)).collect(),
            issued_at: target.issued_at,
            complete: complete.present.contains(h),
        });
    }
    let code = match p.children.as_slice() {
        [h] if p.kind != PromptKind::Mutual => Some(rotation_code(h)),
        _ => None,
    };
    let pending_password_change =
        store.is_pending_write(RecordKind::AccountParams, current_records_id(trust))?;
    // The rotators of the device's own chain, from the head back.
    let mut own_rotators = BTreeSet::new();
    let mut h = trust.head.hash;
    while let Some(b) = bodies.get(&h) {
        own_rotators.insert(b.rotator);
        h = b.parent;
        if own_rotators.len() > bodies.len() {
            break;
        }
    }
    let mut cross_branch_revocation = false;
    let mut reapply = BTreeSet::new();
    if matches!(p.kind, PromptKind::Switch | PromptKind::Reapply) {
        for target in &p.children {
            let path = path_to(trust, &bodies, *target);
            cross_branch_revocation |= path
                .iter()
                .any(|b| b.revoked.iter().any(|id| own_rotators.contains(id)));
        }
    }
    for target in p.children.iter().filter_map(|h| bodies.get(h)) {
        for e in &target.roster {
            if e.device_id != trust.me.device_id && trust.revoked.contains(&e.device_id) {
                reapply.insert(e.device_id);
            }
        }
    }
    let shown = RotationPrompt {
        kind: p.kind,
        choices,
        code,
        tofu_signer,
        pending_password_change,
        cross_branch_revocation,
        reapply_names: reapply.iter().map(|id| local_name(trust, *id)).collect(),
    };
    Ok(Look {
        prompt: Some((p, shown)),
        lock: None,
    })
}

/// What a device with this trust state shows now: the lock its stored
/// state records (a quarantine or an orphaned state stays until the user
/// answers, whatever the server holds since), else the resolver's lock or
/// prompt.
pub(crate) fn look_for<S: RecordStore + ?Sized>(store: &S, trust: &TrustState) -> Result<Look> {
    if let Some(lock) = LineageLock::stored(&trust.state) {
        return Ok(Look {
            prompt: None,
            lock: Some(lock),
        });
    }
    let records = lineage_records(store)?;
    let complete = completeness(store, &records, trust.me.device_id)?;
    look_in(store, trust, &records, &complete)
}

/// The confirmation the device waits for (spec 7.2, 9), read without
/// unlocking: `None` without a trust state (a legacy device), or when the
/// resolver decides anything but a prompt (nothing new, waiting for a
/// parent or a delivery), or the device is locked (`lineage_lock`).
pub fn pending_rotation(store: &dyn RecordStore) -> Result<Option<RotationPrompt>> {
    let Some(trust) = trust_of(store)? else {
        return Ok(None);
    };
    Ok(look_for(store, &trust)?.prompt.map(|(_, shown)| shown))
}

/// The lock a valid lineage record puts on this device (spec 8.1, 8.4),
/// read without unlocking: the stored `Quarantined` or `Orphaned` state, or
/// the resolver's `Quarantine` or `Orphaned` decision before
/// `quarantine_tick` records it. `None` without a trust state.
pub fn lineage_lock(store: &dyn RecordStore) -> Result<Option<LineageLock>> {
    let Some(trust) = trust_of(store)? else {
        return Ok(None);
    };
    Ok(look_for(store, &trust)?.lock)
}

/// The prompt offering `choice` now, or `Validation("rotation")`.
/// `choice` counts as complete for the resolver, so a delivery or record
/// that does not match is reported by the checks that follow (typed
/// errors) rather than as a choice not offered; nothing is adopted unless
/// those checks pass.
fn offered<S: RecordStore + ?Sized>(
    store: &S,
    trust: &TrustState,
    records: &[LineageRecord],
    choice: [u8; 32],
) -> Result<Prompt> {
    let mut complete = completeness(store, records, trust.me.device_id)?;
    complete.present.insert(choice);
    match resolve(trust, records, &complete) {
        Decision::Prompt(p) if p.children.contains(&choice) => Ok(p),
        _ => Err(refused("rotation", "not offered")),
    }
}

/// Follow the rotation `choice` after "C'est moi" and the master password
/// (spec 7.2 steps 1 to 4). Returns the session on the new identity, its
/// Account Unlock Key (to enroll biometrics again) and the new Secret Key
/// (to promote in the Keychain, and for the next unlock).
///
/// Refused, with nothing written:
/// - no trust state, or `device_keys` other than the pinned ones:
///   `Validation("device")`;
/// - `choice` not offered by the resolver now, a record that does not
///   list this device or revokes it: `Validation("rotation")`; a switch
///   (`PromptKind::Switch` or `Reapply`) follows from the open session
///   only (`follow_switch`): `Validation("rotation")`;
/// - this device's delivery, the params or the keyset missing:
///   `NotFound`; one that does not match the hash the signed record lists
///   (a substituted envelope is refused before any decapsulation):
///   `Integrity(Signature)`, except params of a later epoch verified under
///   the record's identity (a password change there, ruling I6); a roster
///   that pins another key for a device this one pinned:
///   `Integrity(WrongContext)`;
/// - a wrong password: `WrongPassword`;
/// - the trust state changed since it was read (another writer):
///   `Conflict`; the commit failing: its error.
///
/// The transaction writes the trust state (new head, identity, roster,
/// revoked, the left identity retired, `Current`) and the chain state of
/// the new identity (params epoch, lists unseen). The device state is the
/// caller's to persist (`persist_device_state`); until then a reopen
/// moves the pin to the trust state's identity and starts the vaults from
/// `from_heads` (`reconcile_pin`). Nothing fails after the commit.
pub fn follow_rotation<S: RecordStore>(
    store: S,
    choice: [u8; 32],
    password: &str,
    device_keys: &DeviceKeys,
) -> Result<(Repository<S>, Auk, SecretKey)> {
    follow_with(store, choice, password, device_keys, None)
}

/// Follow `choice` from the session open on the identity this device is on
/// (any prompt kind; a switch needs it, spec 8.5 step 4). The session's
/// keys are those the device's own writes since its last adoption were
/// sealed with: after the commit, the device's own copy of each vault with
/// writes to replay is wrapped again for the identity followed and kept
/// (`RecordStore::put_retained`) until the replay is done (spec 10.4).
/// The refusals of `follow_rotation` apply, and a session on another
/// identity than the trust state's is `Validation("session")`. A device
/// pushing its own rotation (`Rotating`) may follow a switch.
///
/// The switch moves the head to the winner's descendant (`choice`), adds
/// every removal along the path from the divergence to it, retires the
/// identity left and replays the own writes against nothing (the content
/// of another branch reflects none of them). The removals this device
/// made that the new head lacks are re-applied by `Repository::reapply`,
/// in the same user step (spec 8.5 step 5).
pub fn follow_switch<S: RecordStore>(
    session: Repository<S>,
    choice: [u8; 32],
    password: &str,
    device_keys: &DeviceKeys,
) -> Result<(Repository<S>, Auk, SecretKey)> {
    let trust = trust_of(&session.store)?.ok_or_else(|| refused("device", "no device keys"))?;
    if session.account.params.identity_pub != trust.identity_pub {
        return Err(refused("session", "another identity"));
    }
    let keyset = session.account.keyset();
    let mut left = Vec::with_capacity(keyset.retired_kem.len() + 1);
    for k in std::iter::once(&keyset.kem).chain(&keyset.retired_kem) {
        left.push(HybridKemSecret::from_bytes(&k.to_bytes())?);
    }
    let Repository { store, .. } = session;
    follow_with(store, choice, password, device_keys, Some(&left))
}

fn follow_with<S: RecordStore>(
    store: S,
    choice: [u8; 32],
    password: &str,
    device_keys: &DeviceKeys,
    left_kem: Option<&[HybridKemSecret]>,
) -> Result<(Repository<S>, Auk, SecretKey)> {
    let trust = trust_of(&store)?.ok_or_else(|| refused("device", "no device keys"))?;
    let me = trust.me.device_id;
    if device_keys.public(me)? != trust.me {
        return Err(refused("device", "other device keys"));
    }
    let records = lineage_records(&store)?;
    let prompt = offered(&store, &trust, &records, choice)?;
    let switch = matches!(prompt.kind, PromptKind::Switch | PromptKind::Reapply);
    if switch && left_kem.is_none() {
        return Err(refused("rotation", "switch needs the open session"));
    }
    // Review M1 (Task 9): not out of a quarantine or an orphaned state
    // (Task 12); out of a rotation being pushed only for a switch.
    let state_ok = match trust.state {
        DeviceLineageState::Current | DeviceLineageState::Candidate { resume: None, .. } => true,
        DeviceLineageState::Rotating { .. }
        | DeviceLineageState::Candidate {
            resume: Some(_), ..
        } => switch,
        _ => false,
    };
    if !state_ok {
        return Err(refused("rotation", "state"));
    }
    let bodies = rotations(&records);
    let body = *bodies
        .get(&choice)
        .ok_or_else(|| refused("rotation", "not offered"))?;
    if body.revoked.contains(&me) || !body.roster.iter().any(|e| e.device_id == me) {
        return Err(refused("rotation", "not for this device"));
    }
    // A roster may add devices (intros the rotator saw), never re-key one
    // this device pinned.
    for e in &body.roster {
        if let Some(mine) = trust.roster.iter().find(|m| m.device_id == e.device_id)
            && (mine.sign_pub != e.sign_pub || mine.kem_pub != e.kem_pub)
        {
            return Err(IntegrityError::WrongContext.into());
        }
    }

    // Step 1: the Secret Key, from this device's delivery, its hash
    // checked against the signed body before decapsulation.
    let envelope = store
        .get(RecordKind::KeyDelivery, delivery_id(&choice, me))?
        .ok_or(Error::NotFound)?;
    let secret_key = super::rotate::open_key_delivery(device_keys, body, me, &envelope.data)?;

    // Step 2: the params and keyset of the new identity, hash-matched (or,
    // after a password change there, verified under the identity the
    // record names: ruling I6), verified under that identity (G8), opened
    // with the password.
    let rid = identity_id(&body.identity_pub);
    let params = store
        .get(RecordKind::AccountParams, rid)?
        .ok_or(Error::NotFound)?;
    let keyset = store.get(RecordKind::Keyset, rid)?.ok_or(Error::NotFound)?;
    let bound =
        sha256(&params.data) == body.params_hash && sha256(&keyset.data) == body.keyset_hash;
    if !bound && !later_epoch(&params.data, body) {
        return Err(IntegrityError::Signature.into());
    }
    // The KDF costs are bound by the signed record (params hash, or the new
    // identity's signature at a later epoch): no floor beyond the build's
    // own.
    let expected = PinnedAccount {
        account_id: trust.account_id,
        identity_pub: body.identity_pub.clone(),
        kdf_floor: KdfParams {
            m_kib: 0,
            t: 0,
            p: 0,
            salt: [0; 32],
        },
    };
    let (account, auk) = Account::unlock_exporting_auk_at(
        password,
        &secret_key,
        &params.data,
        &keyset.data,
        Some(&expected),
        0,
    )?;

    // The identity this device leaves (public data).
    let current = store
        .get(RecordKind::AccountParams, current_records_id(&trust))?
        .ok_or(Error::NotFound)?;
    let left = AccountParams::decode_verified(&current.data, &trust.identity_pub)?;

    // Step 3: the new trust state.
    let mut next = trust.clone();
    next.head = LineageHead {
        generation: body.generation,
        hash: choice,
    };
    next.identity_pub = body.identity_pub.clone();
    let rotator_level = trust
        .levels
        .get(&body.rotator)
        .copied()
        .unwrap_or(TrustLevel::Verified);
    next.levels = body
        .roster
        .iter()
        .map(|e| {
            let level = trust.levels.get(&e.device_id).copied();
            (e.device_id, level.unwrap_or(rotator_level))
        })
        .collect();
    next.roster = body.roster.clone();
    // A switch adopts every removal from the divergence to the target.
    for b in path_to(&trust, &bodies, choice) {
        next.add_revoked(&b.revoked);
    }
    next.add_revoked(&body.revoked);
    if prompt.kind == PromptKind::Mutual {
        // Spec 8.3: keeping one side excludes the other signers.
        for other in prompt.children.iter().filter(|h| **h != choice) {
            if let Some(b) = bodies.get(other)
                && b.rotator != me
                && b.rotator != body.rotator
            {
                next.excluded.insert(b.rotator);
            }
            next.ignore(*other);
        }
    }
    next.retired.push(RetiredIdentity {
        identity_id: identity_id(&trust.identity_pub),
        sign_pub: left.signing_pub,
        identity_pub: trust.identity_pub.clone(),
        generation: trust.head.generation,
    });
    next.state = DeviceLineageState::Current;
    // Spec 10.4: the own writes so far wait for their replay under the new
    // keys, against the rotation's `from_heads`; after a switch, against
    // nothing (another branch's content reflects none of them, and its
    // manifests' seqs say nothing of this device's).
    let no_heads = BTreeMap::new();
    next.own_writes
        .adopt(if switch { &no_heads } else { &body.from_heads });
    // Review M1 (Task 11): a switch away from this device's own rotation
    // drops what of its phase 1 has not gone out.
    let drop_pending = if switch {
        abandoned_rotation_rows(&store, &trust, &bodies)?
    } else {
        Vec::new()
    };
    let repo = commit_adoption(
        store,
        Adoption {
            trust: &trust,
            next,
            account,
            rid,
            from_heads: body.from_heads.clone(),
            left_kem,
            drop_pending,
            device_keys,
        },
    )?;
    Ok((repo, auk, secret_key))
}

/// The pending rows of this device's own rotation at `trust.head` that
/// never went out (review M1 of Task 11, I3 of Task 13): its lineage
/// record, the deliveries of its Secret Key and its signed lists under its
/// identity. A device leaving that rotation for another head (a switch, a
/// re-pair) drops them in the same transaction: nobody acts on a lineage
/// record that never reached the server. Empty when the head is not this
/// device's rotation.
pub(crate) fn abandoned_rotation_rows<S: RecordStore + ?Sized>(
    store: &S,
    trust: &TrustState,
    bodies: &BTreeMap<[u8; 32], &RotationBody>,
) -> Result<Vec<(RecordKind, Id)>> {
    let mut drop = Vec::new();
    let Some(own_head) = bodies.get(&trust.head.hash) else {
        return Ok(drop);
    };
    if own_head.rotator != trust.me.device_id {
        return Ok(drop);
    }
    let left_id = current_records_id(trust);
    let mut id = [0u8; 16];
    id.copy_from_slice(&trust.head.hash[..16]);
    let mut rows = vec![(RecordKind::Lineage, Id(id))];
    rows.extend(
        own_head
            .deliveries
            .iter()
            .map(|(r, _)| (RecordKind::KeyDelivery, delivery_id(&trust.head.hash, *r))),
    );
    for kind in [RecordKind::DeviceList, RecordKind::VaultList] {
        rows.push((kind, left_id));
    }
    for (kind, id) in rows {
        if store.is_pending_write(kind, id)? {
            drop.push((kind, id));
        }
    }
    Ok(drop)
}

/// An adoption ready to commit: the trust state read (`trust`) and the one
/// to write (`next`: new head, identity, roster, own-write log moved to its
/// replay list), the account of the new identity opened with the password,
/// its records id, the manifests its vaults start from, the left KEM
/// secrets of a session-based adoption, and the extra pending rows to drop.
pub(crate) struct Adoption<'a> {
    pub(crate) trust: &'a TrustState,
    pub(crate) next: TrustState,
    pub(crate) account: Account,
    pub(crate) rid: Id,
    pub(crate) from_heads: BTreeMap<Id, crate::manifest::SeenManifest>,
    pub(crate) left_kem: Option<&'a [HybridKemSecret]>,
    pub(crate) drop_pending: Vec<(RecordKind, Id)>,
    pub(crate) device_keys: &'a DeviceKeys,
}

/// The commit of a follow, a switch or a re-pair (spec 7.2 step 3, 7.4,
/// 8.5, 10.4): one local transaction (`RecordStore::put_follow`) with the
/// chain state of the new identity, the trust state, the own copies kept
/// for the replay and the pending rows dropped; then, best effort (nothing
/// fails after the commit), the re-introductions this device owes (spec
/// 6.4, 8.5), the replay of its own writes and a fresh look at the lineage.
pub(crate) fn commit_adoption<S: RecordStore>(
    mut store: S,
    a: Adoption<'_>,
) -> Result<Repository<S>> {
    let Adoption {
        trust,
        next,
        account,
        rid,
        from_heads,
        left_kem,
        mut drop_pending,
        device_keys,
    } = a;
    let chain = ChainState {
        params_epoch: account.params.epoch,
        device_list: None,
        vault_list: None,
        device_id: store.chain_state()?.device_id,
    };
    // Every vault a stored `last_seen` may name: the session's map replaces
    // them on the next persist.
    let mut dropped: BTreeSet<Id> = from_heads.keys().copied().collect();
    let keys = store.list(RecordKind::VaultKey)?;
    dropped.extend(keys.iter().map(|r| r.id));
    // The vaults whose own copy the replay needs: intents to replay, or a
    // vault this device wrote and has not pushed (created there).
    let mut own: BTreeSet<Id> = next.own_writes.replay_vaults();
    for k in &keys {
        if store.is_pending_write(RecordKind::Manifest, k.id)? {
            own.insert(k.id);
        }
    }

    // A switch keeps the own copies for the replay, in the same
    // transaction (review M7: the left KEM secrets are gone after this
    // call). A vault whose copy cannot be kept is reported by the replay as
    // lost, with the log's alert.
    let retained = match left_kem {
        Some(left_kem) => own_copies(&store, &own, left_kem, &account)?,
        None => Vec::new(),
    };
    // Fix round 2: a password change made under the identity left is
    // dropped (never pushed: review I3), not held forever. The prompt
    // reported it (`pending_password_change`) before this call.
    let left_id = current_records_id(trust);
    for kind in [RecordKind::AccountParams, RecordKind::Keyset] {
        if store.is_pending_write(kind, left_id)? && !drop_pending.contains(&(kind, left_id)) {
            drop_pending.push((kind, left_id));
        }
    }
    store.put_follow(chain.clone(), trust, &next, retained, drop_pending)?;
    // Spec 6.4, 8.5: the devices this one introduced that the new roster
    // misses, introduced again under the new head (best effort).
    let _ = super::pairing::reintroduce(&mut store, &next, trust, device_keys);

    // Committed: nothing below can fail the call.
    // Step 4: the session on the new identity, its vaults from
    // `from_heads` (R12).
    let device = DeviceState {
        pinned: Some(pin(&account)),
        last_seen: from_heads.clone(),
        epoch: 0,
    };
    let repo = Repository {
        store,
        account,
        device,
        dropped,
        epoch_rewound: true,
        epoch_cache: Mutex::new(None),
        chain,
        travel_parked: BTreeSet::new(),
        lists_forced: true,
        records_id: rid,
        pending: None,
        lineage_mark: None,
        lineage_lock: None,
    };
    let mut repo = repo;
    // Spec 10.4: replay this device's own writes under the new keys (best
    // effort: nothing fails after the commit; what waits is tried again at
    // the next unlock or rebase). The replay's `writable` resolves the
    // lineage first (its mark is unset), so a child of the new head already
    // known makes it wait and prompts at once (review I2 of Task 9).
    let _ = repo.replay_own_writes();
    let _ = repo.refresh_pending_rotation();
    Ok(repo)
}

/// After a switch: for each vault of `vaults`, the device's own copy sealed
/// under the identity it left, kept for the replay: its vault key wrapped
/// again for the identity followed (`account`), with the meta it pairs
/// with, as retained rows for `RecordStore::put_follow` (which also moves
/// its pending key and meta of that identity there, so the followed
/// identity's key shows once it arrives). `left_kem` is the left
/// identity's KEM secret, then the ones it retired. The copy under the left
/// identity's own key comes first (the writes since its adoption are sealed
/// under it); without one, a copy the followed identity's retired secrets
/// open already (older writes still waiting for their replay) stays as it
/// is.
fn own_copies<S: RecordStore>(
    store: &S,
    vaults: &BTreeSet<Id>,
    left_kem: &[HybridKemSecret],
    account: &Account,
) -> Result<Vec<Record>> {
    let keyset = account.keyset();
    let mut out = Vec::new();
    for &vault in vaults {
        let ctx = kem_context(vault);
        let retained = store.retained_rows(vault)?;
        let opens_now = retained.iter().any(|r| {
            r.kind == RecordKind::VaultKey
                && keyset
                    .retired_kem
                    .iter()
                    .any(|k| unwrap_key(k, &r.data, &ctx).is_ok())
        });
        let mut rows: Vec<Record> = retained;
        for kind in [RecordKind::VaultKey, RecordKind::VaultMeta] {
            rows.extend(store.get(kind, vault)?);
        }
        let of = |kind| rows.iter().filter(move |r: &&Record| r.kind == kind);
        'found: for (i, secret) in left_kem.iter().enumerate() {
            if i == 1 && opens_now {
                break;
            }
            for key in of(RecordKind::VaultKey) {
                let Ok(k) = unwrap_key(secret, &key.data, &ctx) else {
                    continue;
                };
                let Some(meta) = of(RecordKind::VaultMeta)
                    .find(|m| Vault::open_with_kem(secret, vault, &key.data, &m.data).is_ok())
                else {
                    continue;
                };
                let envelope = wrap_key(&account.params.kem_pub, &k, &ctx)?;
                out.push(Record {
                    data: envelope,
                    ..key.clone()
                });
                out.push(meta.clone());
                break 'found;
            }
        }
    }
    Ok(out)
}

/// "Ce n'était pas moi" for `choice` (spec 8.2): the record joins
/// `ignored`, its signer joins `excluded` when `exclude_signer`, and a
/// `Candidate` device is `Current` again (another pending record prompts
/// on the next check). `choice` must be offered now
/// (`Validation("rotation")`); the trust state is written conditionally
/// on the one read (`Conflict`).
pub fn reject_rotation(
    store: &mut dyn RecordStore,
    choice: [u8; 32],
    exclude_signer: bool,
) -> Result<()> {
    let trust = trust_of(&*store)?.ok_or_else(|| refused("device", "no device keys"))?;
    // Task 12: a locked device answers with `quarantine_resolve`.
    if LineageLock::stored(&trust.state).is_some() {
        return Err(refused("rotation", "state"));
    }
    let records = lineage_records(&*store)?;
    let complete = completeness(&*store, &records, trust.me.device_id)?;
    // Incomplete choices are offered too: "not me" never waits.
    let offered = look_in(&*store, &trust, &records, &complete)?
        .prompt
        .is_some_and(|(p, _)| p.children.contains(&choice));
    if !offered {
        return Err(refused("rotation", "not offered"));
    }
    let bodies = rotations(&records);
    let body = bodies
        .get(&choice)
        .ok_or_else(|| refused("rotation", "not offered"))?;
    let mut next = trust.clone();
    if exclude_signer && body.rotator != trust.me.device_id {
        next.excluded.insert(body.rotator);
    }
    next.ignore(choice);
    if let DeviceLineageState::Candidate { resume, .. } = next.state {
        // Review I1 (Task 11): a rotator that rejects the sibling that beat
        // it goes back to pushing its own rotation.
        next.state = resume.map_or(DeviceLineageState::Current, |phase| {
            DeviceLineageState::Rotating { phase }
        });
    }
    store.put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)
}

/// The params epoch of the account records this device is on, without
/// unlocking: the "password changed elsewhere" poll. With a trust state,
/// the params of its identity (spec 6.6), verified under it: a rotation
/// waiting for the user changes nothing here, and once followed the poll
/// reads the new identity's params. Without one (a legacy device), the
/// single params record, verified under `pinned`'s identity (or its own on
/// a device that pinned nothing yet).
pub fn stored_params_epoch(store: &dyn RecordStore, pinned: Option<&PinnedAccount>) -> Result<u64> {
    if let Some(trust) = trust_of(store)? {
        let rec = store
            .get(RecordKind::AccountParams, current_records_id(&trust))?
            .ok_or(Error::NotFound)?;
        return Ok(AccountParams::decode_verified(&rec.data, &trust.identity_pub)?.epoch);
    }
    let params = store.list(RecordKind::AccountParams)?;
    let record = params.first().ok_or(Error::NotFound)?;
    let identity = match pinned {
        Some(pin) => pin.identity_pub.clone(),
        None => AccountParams::decode(&record.data)?.identity_pub,
    };
    Ok(AccountParams::decode_verified(&record.data, &identity)?.epoch)
}

/// Seconds between the first time this device reads a valid lineage
/// record revoking it (`since`) and its erase (spec 8.4, R8, O1 ruled
/// 2026-10-30).
pub const QUARANTINE_ERASE_AFTER_SECS: u64 = 7 * 86_400;

/// The lock a valid lineage record puts on this device (spec 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageLock {
    /// A valid record (`by`, its lineage hash) revokes this device: locked,
    /// erased 7 days after `since` unless the user answers "Ce n'était pas
    /// moi" (`quarantine_resolve`).
    Quarantine { by: [u8; 32] },
    /// A valid record (`child`) does not list this device: it reads, writes
    /// nothing, pushes nothing, never erases.
    Orphaned { child: [u8; 32] },
}

impl LineageLock {
    /// The lock a stored state records.
    pub(crate) fn stored(state: &DeviceLineageState) -> Option<LineageLock> {
        match state {
            DeviceLineageState::Quarantined { by, .. } => Some(LineageLock::Quarantine { by: *by }),
            DeviceLineageState::Orphaned { child, .. } => {
                Some(LineageLock::Orphaned { child: *child })
            }
            _ => None,
        }
    }

    /// The lineage hash of the record that locks.
    fn hash(self) -> [u8; 32] {
        match self {
            LineageLock::Quarantine { by } => by,
            LineageLock::Orphaned { child } => child,
        }
    }

    /// The state that records this lock on a device in `from` (review I1,
    /// I2 of Task 12): the signer of the locking record, kept so "Ce n'était
    /// pas moi" excludes it even once the record is gone, and the phase of
    /// this device's own rotation it stopped. `since` for a quarantine.
    /// `None` when the record is not among `records` (never for a lock the
    /// resolver just found in them).
    fn state(
        self,
        from: &DeviceLineageState,
        records: &[LineageRecord],
        since: u64,
    ) -> Option<DeviceLineageState> {
        let rotator = rotations(records).get(&self.hash())?.rotator;
        let resume = resume_of(from);
        Some(match self {
            LineageLock::Quarantine { by } => DeviceLineageState::Quarantined {
                by,
                rotator,
                since,
                resume,
            },
            LineageLock::Orphaned { child } => DeviceLineageState::Orphaned {
                child,
                rotator,
                resume,
            },
        })
    }
}

/// The phase of this device's own rotation that `state` stopped or pushes.
fn resume_of(state: &DeviceLineageState) -> Option<u8> {
    match state {
        DeviceLineageState::Rotating { phase } => Some(*phase),
        DeviceLineageState::Candidate { resume, .. }
        | DeviceLineageState::Quarantined { resume, .. }
        | DeviceLineageState::Orphaned { resume, .. } => *resume,
        DeviceLineageState::Legacy | DeviceLineageState::Current => None,
    }
}

/// What the lineage asks of this device now: a prompt, or a lock (never
/// both).
#[derive(Default)]
pub(crate) struct Look {
    pub(crate) prompt: Option<(Prompt, RotationPrompt)>,
    pub(crate) lock: Option<LineageLock>,
}

/// The refusal of a quarantined device: it is locked (spec 8.4).
pub(crate) fn quarantined() -> Error {
    refused("device", "quarantined")
}

/// The user's answer on the quarantine or orphaned screen (spec 8.2, 8.4,
/// 9, Task 4 ruling).
pub enum QuarantineChoice<'a> {
    /// "Effacer cet appareil": erase now. Quarantine only.
    Erase,
    /// "Ce n'était pas moi": the master password and the Secret Key of the
    /// identity the device is on (checked by an unlock, as `Repository::
    /// unlock`), and the device state saved by the app.
    NotMe {
        password: &'a str,
        secret_key: &'a SecretKey,
        device: DeviceState,
    },
}

/// What `quarantine_tick` found or did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineTick {
    /// No valid lineage record revokes this device (or it was erased
    /// already: nothing is left to look at). The tick may have recorded an
    /// orphaned state (review M6): the screen asks `lineage_lock`.
    NotQuarantined,
    /// Locked; erased at device time `erase_at` (Unix seconds) unless the
    /// user answers first.
    Waiting { erase_at: u64 },
    /// The store was erased now (`RecordStore::erase_device`). The app
    /// deletes what it keeps for the account outside the store (Keychain
    /// items: Secret Key, Account Unlock Key, device keys).
    Erased,
}

/// The quarantine clock (spec 8.4, R8, O1), with the caller's clock `now`
/// (Unix seconds; the core never reads one): the app calls it at launch and
/// on the quarantine screen. No password.
///
/// - A device whose trust state is not quarantined yet is quarantined when
///   the resolver decides `Quarantine`, i.e. a valid lineage record
///   (signed by a device pinned in the local roster, not revoked, excluded
///   or ignored, and by the identity it names) revokes it: the state
///   `Quarantined { by, since: now }` is written in one write, conditional
///   on the trust state read (`Conflict`). Anything else (nothing, a
///   prompt, an invalid or unverifiable record, the signed device list) is
///   `NotQuarantined` and writes nothing, except a valid record that drops
///   this device, recorded as `Orphaned` (it never erases).
/// - Once quarantined, the state stays whatever the server holds since:
///   only `quarantine_resolve` or the erase ends it. `since` is never
///   moved.
/// - The store is erased (`RecordStore::erase_device`, conditional on the
///   trust state read) once `now - since` reaches
///   `QUARANTINE_ERASE_AFTER_SECS`; a clock moved back only delays it
///   (saturating arithmetic, never early). Otherwise `Waiting` with
///   `erase_at = since + QUARANTINE_ERASE_AFTER_SECS` (saturating).
pub fn quarantine_tick(store: &mut dyn RecordStore, now: u64) -> Result<QuarantineTick> {
    let Some(trust) = trust_of(&*store)? else {
        return Ok(QuarantineTick::NotQuarantined);
    };
    let (trust, since) = match trust.state {
        DeviceLineageState::Quarantined { since, .. } => (trust, since),
        DeviceLineageState::Legacy => return Ok(QuarantineTick::NotQuarantined),
        _ => {
            let records = lineage_records(&*store)?;
            let complete = completeness(&*store, &records, trust.me.device_id)?;
            let lock = look_in(&*store, &trust, &records, &complete)?.lock;
            let Some(state) = lock.and_then(|l| l.state(&trust.state, &records, now)) else {
                return Ok(QuarantineTick::NotQuarantined);
            };
            if LineageLock::stored(&state) == LineageLock::stored(&trust.state) {
                return Ok(QuarantineTick::NotQuarantined);
            }
            let mut next = trust.clone();
            next.state = state;
            store.put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)?;
            if !matches!(next.state, DeviceLineageState::Quarantined { .. }) {
                return Ok(QuarantineTick::NotQuarantined);
            }
            (next, now)
        }
    };
    if now.saturating_sub(since) < QUARANTINE_ERASE_AFTER_SECS {
        return Ok(QuarantineTick::Waiting {
            erase_at: since.saturating_add(QUARANTINE_ERASE_AFTER_SECS),
        });
    }
    store.erase_device(&trust)?;
    Ok(QuarantineTick::Erased)
}

/// The user's answer on a locked device (spec 8.2, 8.4).
///
/// - `Erase` ("Effacer cet appareil"), on a quarantined device only (the
///   stored state, or the resolver's `Quarantine` before the first tick):
///   the store is erased now (`RecordStore::erase_device`, conditional on
///   the trust state read); `None`.
/// - `NotMe` ("Ce n'était pas moi"), on a quarantined or orphaned device:
///   the password and Secret Key are checked by an unlock of the identity
///   the device is on (a wrong password is `WrongPassword`, nothing
///   written); then the record that locked joins `ignored`, its signer
///   (stored at entry) `excluded`, the state is `Current` again, or
///   `Rotating { phase }` when the lock stopped this device's own rotation
///   (one write, conditional on the trust state read: `Conflict`), and the
///   session opens as after
///   `Repository::unlock` (another pending record prompts or locks again
///   there). The erase is cancelled.
///
/// Anything else is `Validation`: no trust state, a device not locked,
/// `Erase` on an orphaned device (it never erases).
pub fn quarantine_resolve<S: RecordStore>(
    mut store: S,
    choice: QuarantineChoice<'_>,
) -> Result<Option<Repository<S>>> {
    let trust = trust_of(&store)?.ok_or_else(|| refused("device", "no device keys"))?;
    let lock = match LineageLock::stored(&trust.state) {
        Some(lock) => lock,
        None if trust.state == DeviceLineageState::Legacy => {
            return Err(refused("device", "not locked"));
        }
        None => look_for(&store, &trust)?
            .lock
            .ok_or_else(|| refused("device", "not locked"))?,
    };
    match choice {
        QuarantineChoice::Erase => {
            if !matches!(lock, LineageLock::Quarantine { .. }) {
                return Err(refused("device", "not quarantined"));
            }
            store.erase_device(&trust)?;
            Ok(None)
        }
        QuarantineChoice::NotMe {
            password,
            secret_key,
            mut device,
        } => {
            let (params, keyset) = super::account_records(&store)?;
            let chain = store.chain_state()?;
            let moved = super::reconcile_pin(&store, &mut device)?;
            let (account, _auk) = Account::unlock_exporting_auk_at(
                password,
                secret_key,
                &params.data,
                &keyset.data,
                device.pinned.as_ref(),
                chain.params_epoch,
            )?;
            let h = lock.hash();
            // Review I2: the signer stored at entry, so a record the server
            // deleted since still has its signer excluded.
            let rotator = match &trust.state {
                DeviceLineageState::Quarantined { rotator, .. }
                | DeviceLineageState::Orphaned { rotator, .. } => Some(*rotator),
                _ => rotations(&lineage_records(&store)?)
                    .get(&h)
                    .map(|b| b.rotator),
            };
            let mut next = trust.clone();
            if let Some(r) = rotator
                && r != trust.me.device_id
            {
                next.excluded.insert(r);
            }
            next.ignore(h);
            // Review I1: a rotation this device was pushing resumes.
            next.state = resume_of(&trust.state).map_or(DeviceLineageState::Current, |phase| {
                DeviceLineageState::Rotating { phase }
            });
            store.put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next)?;
            Repository::finish_unlock(store, account, &params, device, chain, moved).map(Some)
        }
    }
}

impl<S: RecordStore> Repository<S> {
    /// The rotation prompt this session waits on (found at unlock or by
    /// `refresh_pending_rotation`): while there is one, every write is
    /// `Error::ReadOnly` (R10).
    pub fn pending_prompt(&self) -> Option<&RotationPrompt> {
        self.pending.as_ref()
    }

    /// The lock a valid lineage record puts on this device, as this session
    /// last saw it (`refresh_pending_rotation`).
    pub fn pending_lock(&self) -> Option<LineageLock> {
        self.lineage_lock
    }

    /// Look for a rotation prompt again (after a sync), remember it for
    /// this session and record the device state (spec 8.2: `Current` to
    /// `Candidate` with the children to decide, and back to `Current` when
    /// none is left). The state write is conditional on the trust state
    /// read and best effort: the session stays read-only either way.
    ///
    /// Task 12: a valid record that drops this device records `Orphaned`
    /// (no clock needed); one that revokes it locks the session, and
    /// `quarantine_tick` records `Quarantined` with the caller's clock. A
    /// lock never goes back to `Current` here, whatever the server holds
    /// since (only the user's answer, `quarantine_resolve`, does). Other
    /// states (rotating with no switch, quarantined, orphaned) are left as
    /// they are.
    ///
    /// Task 13: first, the valid intros under the head join the roster
    /// (`pairing::accept_intros`, spec 6.4), written conditionally on the
    /// trust state read.
    pub fn refresh_pending_rotation(&mut self) -> Result<Option<RotationPrompt>> {
        let Some(trust) = trust_of(&self.store)? else {
            self.pending = None;
            self.lineage_lock = None;
            return Ok(None);
        };
        // Task 13 (spec 6.4): the intros made under the head by a trusted
        // device join the roster first, so a rotation they sign is judged
        // with their keys.
        let trust = super::pairing::apply_intros(&mut self.store, trust)?;
        // Task 14 (spec 15): the legacy intros under the genesis, and any
        // other genesis (an alert).
        let trust = self.apply_migration_records(trust)?;
        let look = look_for(&self.store, &trust)?;
        let found = look.prompt;
        let state = match (&trust.state, &found, look.lock) {
            (
                DeviceLineageState::Current
                | DeviceLineageState::Candidate { .. }
                | DeviceLineageState::Rotating { .. },
                _,
                Some(lock @ LineageLock::Orphaned { .. }),
            ) => lock.state(&trust.state, &lineage_records(&self.store)?, 0),
            (_, _, Some(_)) => None,
            (DeviceLineageState::Current, Some((p, _)), None) => {
                Some(DeviceLineageState::Candidate {
                    children: p.children.clone(),
                    resume: None,
                })
            }
            (DeviceLineageState::Candidate { children, resume }, Some((p, _)), None)
                if *children != p.children =>
            {
                Some(DeviceLineageState::Candidate {
                    children: p.children.clone(),
                    resume: *resume,
                })
            }
            // Review I1: nothing left to decide; a rotator whose winning
            // sibling went away resumes its own phases.
            (DeviceLineageState::Candidate { resume, .. }, None, None) => {
                Some(resume.map_or(DeviceLineageState::Current, |phase| {
                    DeviceLineageState::Rotating { phase }
                }))
            }
            // Spec 8.2: a sibling of the device's own rotation wins; the
            // push of its phases stops until the user answers.
            (DeviceLineageState::Rotating { phase }, Some((p, _)), None)
                if matches!(p.kind, PromptKind::Switch | PromptKind::Reapply) =>
            {
                Some(DeviceLineageState::Candidate {
                    children: p.children.clone(),
                    resume: Some(*phase),
                })
            }
            _ => None,
        };
        if let Some(state) = state {
            let mut next = trust.clone();
            next.state = state;
            let _ = self
                .store
                .put_with_trust_cas(Vec::new(), Vec::new(), None, &trust, &next);
        }
        self.pending = found.map(|(_, shown)| shown);
        self.lineage_lock = look.lock;
        self.lineage_mark = Some(lineage_mark(&self.store)?);
        Ok(self.pending.clone())
    }

    /// `Error::ReadOnly` while a rotation prompt waits for the user, or a
    /// valid lineage record locks this device: found by this session, or
    /// recorded in the stored trust state (`Candidate`, `Quarantined`,
    /// `Orphaned`, by any process on the device). Every write checks it
    /// first (R10, spec 8.1).
    ///
    /// Review I1: when the lineage records, deliveries, account records or
    /// the trust state changed since the last look (a sync pulled a
    /// rotation into an open session), the prompt is looked for again
    /// first (`refresh_pending_rotation`), so no app call is needed.
    pub(crate) fn writable(&mut self) -> Result<()> {
        if trust_of(&self.store)?.is_some() && self.lineage_mark != Some(lineage_mark(&self.store)?)
        {
            self.refresh_pending_rotation()?;
        }
        if self.pending.is_some() || self.lineage_lock.is_some() {
            return Err(Error::ReadOnly);
        }
        if let Some(t) = trust_of(&self.store)?
            && matches!(
                t.state,
                DeviceLineageState::Candidate { .. }
                    | DeviceLineageState::Quarantined { .. }
                    | DeviceLineageState::Orphaned { .. }
            )
        {
            return Err(Error::ReadOnly);
        }
        Ok(())
    }

    /// `Validation("device", "quarantined")` on a quarantined device (spec
    /// 8.1, 8.4: locked, its data stays encrypted until the erase or the
    /// user's "Ce n'était pas moi"): found by this session, or recorded in
    /// the stored trust state. An orphaned device reads.
    pub(crate) fn readable(&self) -> Result<()> {
        let stored = trust_of(&self.store)?
            .is_some_and(|t| matches!(t.state, DeviceLineageState::Quarantined { .. }));
        if stored || matches!(self.lineage_lock, Some(LineageLock::Quarantine { .. })) {
            return Err(quarantined());
        }
        Ok(())
    }
}
