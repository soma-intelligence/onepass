//! Lineage resolver (key rotation v2, spec 7.2, 8.2, 8.3 and 8.5): what a
//! device does with the lineage records it knows.
//!
//! Devices, sorted by id as in a roster: A (iPhone, rotates and revokes B),
//! B (lost iPad, every record it signs is the attacker's), C (a follower),
//! D (rotates concurrently with A) and E (a second follower). Every record
//! is built and signed once for the whole file: an SLH-DSA identity
//! signature takes about 10 s in debug, so the jobs run in parallel.
//!
//! Records (all children of the genesis G unless said otherwise):
//! - `A`: A revokes B. `A2`: A rotates again, child of `A`.
//! - `D_lo`, `D_hi`: D rotates, revokes nobody; `D_lo < A < D_hi` by hash.
//!   `D2_lo`, `D2_hi`: D again, child of `D_lo` and `D_hi`.
//! - `B`: B revokes A (the race of 8.3). `Bq`: B revokes C. `Bd`: B revokes
//!   D. `Bs`: B rotates, below `D_hi`. `DB_lo`: B rotates under `D_lo`,
//!   below `D2_lo`. `J`: B, generation 3, parent
//!   unknown to everyone.
//! - Shield cases (unit tests only): `Bo` (B drops C), `Dq` (D, below `Bq`
//!   and `Bo`), `Dz` (D, above both), `BqU` (B revokes C under `D_lo`,
//!   above `D2_lo`).
//! - `F`: claims rotator A with an embedded key for A that is not A's;
//!   signed by that impostor key. `BadId`: signed by A's real device key,
//!   identity signature garbage. `AnoE`: A rotates without E in the roster.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};

use onepass_core::Id;
use onepass_core::crypto::{HybridSignature, IdentityKey, IdentitySignature, IdentityVerifyingKey};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::devices::{DeviceKind, DeviceMode};
use onepass_core::lineage::resolve::{
    Completeness, Decision, Prompt, PromptKind, VerifyCache, excludes, resolve, resolve_cached,
    winner,
};
use onepass_core::lineage::{
    GenesisBody, LineageRecord, ROTATION_DOMAIN, RosterEntry, RotationBody, RotationReason, Signed,
    sign_rotation,
};
use onepass_core::trust::{DeviceLineageState, LineageHead, TrustLevel, TrustState};
use proptest::prelude::*;

const ACCOUNT: Id = Id([0xAC; 16]);
const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
const D: usize = 3;
const E: usize = 4;
const T0: i64 = 1_761_800_000;

struct Dev {
    keys: DeviceKeys,
    public: DevicePublic,
}

struct World {
    devs: Vec<Dev>,
    genesis: LineageRecord,
    recs: BTreeMap<&'static str, Signed<RotationBody>>,
}

fn entry(p: &DevicePublic) -> RosterEntry {
    RosterEntry {
        device_id: p.device_id,
        sign_pub: p.sign_pub.clone(),
        kem_pub: p.kem_pub.clone(),
        name: format!("device {}", p.device_id.0[0]),
        kind: DeviceKind::Phone,
        mode: DeviceMode::Personal,
        introduced_by: None,
    }
}

fn dummy_hybrid() -> HybridSignature {
    HybridSignature {
        mldsa: vec![0; 4627],
        ed25519: [0; 64],
    }
}

fn dummy_identity_sig() -> IdentitySignature {
    postcard::from_bytes(&postcard::to_allocvec(&vec![0u8; 29792]).unwrap()).unwrap()
}

fn hash_of(body: &RotationBody) -> [u8; 32] {
    LineageRecord::Rotation(Signed {
        body: body.clone(),
        device_sig: dummy_hybrid(),
        identity_sig: dummy_identity_sig(),
    })
    .hash()
}

#[allow(clippy::too_many_arguments)]
fn body(
    parent: [u8; 32],
    generation: u64,
    rotator: Id,
    reason: RotationReason,
    revoked: &[Id],
    roster: &[&DevicePublic],
    identity: &IdentityVerifyingKey,
    issued_at: i64,
) -> RotationBody {
    let mut roster: Vec<RosterEntry> = roster.iter().map(|p| entry(p)).collect();
    roster.sort_by_key(|e| e.device_id);
    let deliveries = roster
        .iter()
        .filter(|e| e.device_id != rotator)
        .map(|e| (e.device_id, [e.device_id.0[0]; 32]))
        .collect();
    let mut revoked = revoked.to_vec();
    revoked.sort();
    RotationBody {
        format: 1,
        account_id: ACCOUNT,
        generation,
        parent,
        rotator,
        reason,
        revoked,
        roster,
        identity_pub: identity.clone(),
        params_hash: [1; 32],
        keyset_hash: [2; 32],
        deliveries,
        from_heads: BTreeMap::new(),
        issued_at,
    }
}

fn build() -> World {
    let devs: Vec<Dev> = (1..=5u8)
        .map(|n| {
            let keys = DeviceKeys::generate_software().unwrap();
            let public = keys.public(Id([n; 16])).unwrap();
            Dev { keys, public }
        })
        .collect();
    let impostor_keys = DeviceKeys::generate_software().unwrap();
    let impostor = impostor_keys.public(devs[A].public.device_id).unwrap();
    let honest = IdentityKey::generate().unwrap();
    let attacker = IdentityKey::generate().unwrap();
    let hv = honest.verifying_key();
    let av = attacker.verifying_key();
    let p = |i: usize| &devs[i].public;
    let id = |i: usize| devs[i].public.device_id;
    use RotationReason::{Revoke, Rotate};

    let genesis = LineageRecord::Genesis(Signed {
        body: GenesisBody {
            format: 1,
            account_id: ACCOUNT,
            identity_pub: hv.clone(),
            creator: entry(p(A)),
            created_at: T0 - 1_000,
        },
        device_sig: dummy_hybrid(),
        identity_sig: dummy_identity_sig(),
    });
    let g = genesis.hash();
    let all = [p(A), p(B), p(C), p(D), p(E)];

    let ra = body(
        g,
        1,
        id(A),
        Revoke,
        &[id(B)],
        &[p(A), p(C), p(D), p(E)],
        &hv,
        T0,
    );
    let ha = hash_of(&ra);
    let search = |want_lo: bool| {
        (T0 + 1..)
            .map(|t| body(g, 1, id(D), Rotate, &[], &all, &hv, t))
            .find(|b| (hash_of(b) < ha) == want_lo)
            .unwrap()
    };
    let d_lo = search(true);
    let d_hi = search(false);
    let ra2 = body(
        ha,
        2,
        id(A),
        Rotate,
        &[],
        &[p(A), p(C), p(D), p(E)],
        &hv,
        T0 + 10,
    );
    let d2_lo = body(hash_of(&d_lo), 2, id(D), Rotate, &[], &all, &hv, T0 + 11);
    let d2_hi = body(hash_of(&d_hi), 2, id(D), Rotate, &[], &all, &hv, T0 + 12);
    let rb = body(
        g,
        1,
        id(B),
        Revoke,
        &[id(A)],
        &[p(B), p(C), p(D), p(E)],
        &av,
        T0 + 2,
    );
    let rbq = body(
        g,
        1,
        id(B),
        Revoke,
        &[id(C)],
        &[p(A), p(B), p(D), p(E)],
        &av,
        T0 + 3,
    );
    let rbd = body(
        g,
        1,
        id(B),
        Revoke,
        &[id(D)],
        &[p(A), p(B), p(C), p(E)],
        &av,
        T0 + 4,
    );
    // B under D_lo, below D2_lo by hash: a withheld winner-by-order.
    let hd2 = hash_of(&d2_lo);
    let db_lo = (T0 + 13..)
        .map(|t| body(hash_of(&d_lo), 2, id(B), Rotate, &[], &all, &av, t))
        .find(|b| hash_of(b) < hd2)
        .unwrap();
    // B rotates for itself, below D_hi by hash (D does not exclude it).
    let hdh = hash_of(&d_hi);
    let bs = (T0 + 20..)
        .map(|t| body(g, 1, id(B), Rotate, &[], &all, &av, t))
        .find(|b| hash_of(b) < hdh)
        .unwrap();
    let rj = body(
        [0x55; 32],
        3,
        id(B),
        Rotate,
        &[],
        &[p(B), p(C), p(D), p(E)],
        &av,
        T0 + 5,
    );
    let rf = body(
        g,
        1,
        id(A),
        Revoke,
        &[id(B)],
        &[&impostor, p(C), p(D), p(E)],
        &av,
        T0 + 6,
    );
    let ano_e = body(
        g,
        1,
        id(A),
        Rotate,
        &[],
        &[p(A), p(B), p(C), p(D)],
        &hv,
        T0 + 7,
    );
    let bad_id = body(g, 1, id(A), Rotate, &[], &all, &hv, T0 + 8);

    // Shield cases (unit tests only, not in the proptest pool).
    // Bo: B drops C without revoking it. Dq below Bq and Bo, Dz above both.
    // BqU: B revokes C under D_lo, above D2_lo.
    let bo = body(
        g,
        1,
        id(B),
        Rotate,
        &[],
        &[p(A), p(B), p(D), p(E)],
        &av,
        T0 + 30,
    );
    let (hbq, hbo) = (hash_of(&rbq), hash_of(&bo));
    let dq = (T0 + 40..)
        .map(|t| body(g, 1, id(D), Rotate, &[], &all, &hv, t))
        .find(|b| hash_of(b) < hbq.min(hbo))
        .unwrap();
    let dz = (T0 + 40..)
        .map(|t| body(g, 1, id(D), Rotate, &[], &all, &hv, t))
        .find(|b| hash_of(b) > hbq.max(hbo))
        .unwrap();
    let bq_u = (T0 + 60..)
        .map(|t| {
            body(
                hash_of(&d_lo),
                2,
                id(B),
                Revoke,
                &[id(C)],
                &[p(A), p(B), p(D), p(E)],
                &av,
                t,
            )
        })
        .find(|b| hash_of(b) > hd2)
        .unwrap();

    let jobs: Vec<(&'static str, RotationBody, &DeviceKeys, &IdentityKey)> = vec![
        ("Bo", bo, &devs[B].keys, &attacker),
        ("Dq", dq, &devs[D].keys, &honest),
        ("Dz", dz, &devs[D].keys, &honest),
        ("BqU", bq_u, &devs[B].keys, &attacker),
        ("A", ra, &devs[A].keys, &honest),
        ("D_lo", d_lo, &devs[D].keys, &honest),
        ("D_hi", d_hi, &devs[D].keys, &honest),
        ("A2", ra2, &devs[A].keys, &honest),
        ("D2_lo", d2_lo, &devs[D].keys, &honest),
        ("D2_hi", d2_hi, &devs[D].keys, &honest),
        ("B", rb, &devs[B].keys, &attacker),
        ("Bq", rbq, &devs[B].keys, &attacker),
        ("Bd", rbd, &devs[B].keys, &attacker),
        ("DB_lo", db_lo, &devs[B].keys, &attacker),
        ("Bs", bs, &devs[B].keys, &attacker),
        ("J", rj, &devs[B].keys, &attacker),
        ("F", rf, &impostor_keys, &attacker),
        ("AnoE", ano_e, &devs[A].keys, &honest),
    ];
    let mut recs: BTreeMap<&'static str, Signed<RotationBody>> = std::thread::scope(|s| {
        let handles: Vec<_> = jobs
            .into_iter()
            .map(|(name, b, dk, ik)| s.spawn(move || (name, sign_rotation(b, dk, ik).unwrap())))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let msg = postcard::to_allocvec(&bad_id).unwrap();
    recs.insert(
        "BadId",
        Signed {
            device_sig: devs[A].keys.sign(ROTATION_DOMAIN, &msg).unwrap(),
            identity_sig: dummy_identity_sig(),
            body: bad_id,
        },
    );
    World {
        devs,
        genesis,
        recs,
    }
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(build)
}

fn did(i: usize) -> Id {
    world().devs[i].public.device_id
}

fn signed(name: &str) -> &'static Signed<RotationBody> {
    &world().recs[name]
}

fn rec(name: &str) -> LineageRecord {
    LineageRecord::Rotation(signed(name).clone())
}

fn hashes() -> &'static BTreeMap<&'static str, [u8; 32]> {
    static H: OnceLock<BTreeMap<&'static str, [u8; 32]>> = OnceLock::new();
    H.get_or_init(|| {
        world()
            .recs
            .iter()
            .map(|(n, r)| (*n, hash_of(&r.body)))
            .collect()
    })
}

fn h(name: &str) -> [u8; 32] {
    hashes()[name]
}

/// The genesis plus the named records.
fn recs(names: &[&str]) -> Vec<LineageRecord> {
    let mut v = vec![world().genesis.clone()];
    v.extend(names.iter().map(|n| rec(n)));
    v
}

fn complete(names: &[&str]) -> Completeness {
    Completeness {
        present: names.iter().map(|n| h(n)).collect(),
    }
}

/// Device `me` at the genesis, every device pinned and verified.
fn at_genesis(me: usize) -> TrustState {
    let w = world();
    let mut t = TrustState::new(
        ACCOUNT,
        w.devs[me].public.clone(),
        LineageHead {
            generation: 0,
            hash: w.genesis.hash(),
        },
        w.genesis.identity_pub().clone(),
        w.devs.iter().map(|d| entry(&d.public)).collect(),
        DeviceLineageState::Current,
    );
    for d in &w.devs {
        t.levels.insert(d.public.device_id, TrustLevel::Verified);
    }
    t
}

/// What the follow step (Task 9) will write: the new head, its roster
/// and identity, and the removals along the way.
fn move_head(t: &mut TrustState, path: &[&RotationBody]) {
    let last = path.last().unwrap();
    for b in path {
        t.add_revoked(&b.revoked);
    }
    t.head = LineageHead {
        generation: last.generation,
        hash: hash_of(last),
    };
    t.roster = last.roster.clone();
    t.identity_pub = last.identity_pub.clone();
    t.state = DeviceLineageState::Current;
}

/// Device `me` after following the named chain from the genesis.
fn after(me: usize, chain: &[&str]) -> TrustState {
    let mut t = at_genesis(me);
    let path: Vec<&RotationBody> = chain.iter().map(|n| &signed(n).body).collect();
    move_head(&mut t, &path);
    t
}

/// "Ce n'était pas moi" for `name`: its signer excluded, the record ignored.
fn reject(t: &mut TrustState, name: &str) {
    t.excluded.insert(signed(name).body.rotator);
    t.ignore(h(name));
}

fn prompt(kind: PromptKind, names: &[&str]) -> Decision {
    let mut children: Vec<[u8; 32]> = names.iter().map(|n| h(n)).collect();
    children.sort();
    Decision::Prompt(Prompt { kind, children })
}

fn all_complete(names: &[&str]) -> Decision {
    resolve(&at_genesis(C), &recs(names), &complete(names))
}

// ---------------------------------------------------------------------
// Spec 8.2, one test per row the resolver decides.

/// `Current`, valid child for me: `Candidate` (a prompt, writes blocked).
#[test]
fn current_valid_child_for_me_prompts() {
    assert_eq!(all_complete(&["A"]), prompt(PromptKind::Single, &["A"]));
}

/// `Current`, valid child revoking me: `Quarantined`. No delivery exists
/// for a revoked device, so completeness is not asked.
#[test]
fn current_child_revoking_me_quarantines() {
    let d = resolve(&at_genesis(C), &recs(&["Bq"]), &complete(&[]));
    assert_eq!(d, Decision::Quarantine { by: h("Bq") });
}

/// `Current`, valid child without me: `Orphaned`.
#[test]
fn current_child_without_me_orphans() {
    let d = resolve(&at_genesis(E), &recs(&["AnoE"]), &complete(&[]));
    assert_eq!(d, Decision::Orphaned { child: h("AnoE") });
    // The same record lists C: an ordinary prompt there.
    assert_eq!(
        all_complete(&["AnoE"]),
        prompt(PromptKind::Single, &["AnoE"])
    );
}

/// `Current`, a valid sibling of the head wins the order: `Candidate`
/// with the switch explained.
#[test]
fn current_sibling_wins_prompts_switch() {
    let t = after(C, &["D_hi"]);
    let d = resolve(&t, &recs(&["D_hi", "A"]), &complete(&["A"]));
    assert_eq!(d, prompt(PromptKind::Switch, &["A"]));
    // Incomplete: the switch waits, it never prompts without the delivery.
    let d = resolve(&t, &recs(&["D_hi", "A"]), &complete(&[]));
    assert_eq!(
        d,
        Decision::Wait {
            unknown_parent: vec![]
        }
    );
}

/// `Rotating`, a valid sibling of the device's own rotation wins: the
/// switch carries the re-application (8.5 step 5).
#[test]
fn rotating_sibling_wins_prompts_reapply() {
    let mut t = after(D, &["D_hi"]);
    t.state = DeviceLineageState::Rotating { phase: 3 };
    let d = resolve(&t, &recs(&["D_hi", "A"]), &complete(&["A"]));
    assert_eq!(d, prompt(PromptKind::Reapply, &["A"]));
    // D's own rotation wins against A: nothing to do.
    let t = after(D, &["D_lo"]);
    let d = resolve(&t, &recs(&["D_lo", "A"]), &complete(&["A"]));
    assert_eq!(d, Decision::Stay);
}

/// `Candidate`, user confirms child X: `Current { head: X }`, and the
/// resolver has nothing more to say about the race.
#[test]
fn candidate_confirmed_then_stays() {
    let t = after(C, &["A"]);
    let d = resolve(&t, &recs(&["A", "B"]), &complete(&["A", "B"]));
    assert_eq!(d, Decision::Stay);
}

/// `Candidate`, "Ce n'était pas moi" for X: `Current` if no other child;
/// otherwise the other child is asked about.
#[test]
fn candidate_not_me_returns_to_current() {
    let mut t = at_genesis(C);
    let names = ["B"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Single, &["B"])
    );
    reject(&mut t, "B");
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        Decision::Stay
    );

    let mut t = at_genesis(C);
    let names = ["B", "D_hi"];
    let first = winner(&[signed("B"), signed("D_hi")]).unwrap();
    let d = resolve(&t, &recs(&names), &complete(&names));
    assert_eq!(
        d,
        Decision::Prompt(Prompt {
            kind: PromptKind::Single,
            children: vec![first]
        })
    );
    // Reject B whichever came first: D's rotation is what remains.
    reject(&mut t, "B");
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Single, &["D_hi"])
    );
}

/// `Quarantined`, "Ce n'était pas moi": `Current`, the signer excluded.
#[test]
fn quarantined_not_me_returns_to_current() {
    let mut t = at_genesis(C);
    assert_eq!(
        resolve(&t, &recs(&["Bq"]), &complete(&[])),
        Decision::Quarantine { by: h("Bq") }
    );
    reject(&mut t, "Bq");
    assert_eq!(resolve(&t, &recs(&["Bq"]), &complete(&[])), Decision::Stay);
    // Every other record of B is now refused too.
    assert_eq!(
        resolve(&t, &recs(&["Bq", "B", "Bd"]), &complete(&["B", "Bd"])),
        Decision::Stay
    );
}

/// A record on the device's own chain, at or below the head, is old.
#[test]
fn old_record_on_own_chain_is_ignored() {
    let t = after(C, &["A", "A2"]);
    assert_eq!(
        resolve(&t, &recs(&["A", "A2"]), &complete(&["A", "A2"])),
        Decision::Stay
    );
}

/// 8.5 step 3: branches compare at their first divergence, the target is
/// the winning branch's newest descendant.
#[test]
fn ancestor_divergence_targets_newest_descendant() {
    let t = after(C, &["A", "A2"]);
    let names = ["A", "A2", "D_lo", "D2_lo"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&["D2_lo"])),
        prompt(PromptKind::Switch, &["D2_lo"])
    );
    // The newest descendant's delivery is withheld: the newest complete
    // one is the target.
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&["D_lo"])),
        prompt(PromptKind::Switch, &["D_lo"])
    );
    // Nothing on the winning branch is complete: wait for it.
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&[])),
        Decision::Wait {
            unknown_parent: vec![]
        }
    );
    // A larger sibling at the divergence changes nothing.
    let names = ["A", "A2", "D_hi", "D2_hi"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        Decision::Stay
    );
}

// ---------------------------------------------------------------------
// Spec 8.3, the race A revokes B, B revokes A.

/// On C, R_A seen first: confirmation naming R_A. Once followed, R_B is
/// invalid (B revoked).
#[test]
fn race_a_first() {
    let names = ["A"];
    assert_eq!(
        resolve(&at_genesis(C), &recs(&names), &complete(&names)),
        prompt(PromptKind::Single, &["A"])
    );
    let t = after(C, &["A"]);
    let names = ["A", "B"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        Decision::Stay
    );
}

/// On C, R_B seen first, R_A withheld: confirmation naming R_B. The user
/// did not do this: B is excluded, and R_A, once it arrives, is asked.
#[test]
fn race_b_first() {
    let mut t = at_genesis(C);
    let names = ["B"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Single, &["B"])
    );
    reject(&mut t, "B");
    let names = ["B", "A"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Single, &["A"])
    );
}

/// On C, both seen: mutual exclusion, the user picks.
#[test]
fn race_both() {
    assert_eq!(
        all_complete(&["A", "B"]),
        prompt(PromptKind::Mutual, &["A", "B"])
    );
    // Arrival order does not matter.
    let d = resolve(
        &at_genesis(C),
        &[rec("B"), rec("A"), world().genesis.clone()],
        &complete(&["A", "B"]),
    );
    assert_eq!(d, prompt(PromptKind::Mutual, &["A", "B"]));
}

/// On A: B is revoked the moment A commits R_A, so R_B is invalid.
#[test]
fn on_a_record_signed_by_revoked_b_is_invalid() {
    let mut t = after(A, &["A"]);
    t.state = DeviceLineageState::Rotating { phase: 1 };
    assert!(t.revoked.contains(&did(B)));
    let names = ["A", "B"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        Decision::Stay
    );
}

/// The rotator id is pinned, but the record carries another key for it:
/// the pinned key is used, the signature fails.
#[test]
fn signer_from_record_not_trusted() {
    let f = &signed("F").body;
    assert_eq!(f.rotator, did(A));
    let embedded = f.roster.iter().find(|e| e.device_id == did(A)).unwrap();
    assert_ne!(embedded.sign_pub, world().devs[A].public.sign_pub);
    assert_eq!(all_complete(&["F"]), Decision::Stay);
}

/// A good device signature with a bad identity signature is invalid.
#[test]
fn bad_identity_signature_is_invalid() {
    assert_eq!(all_complete(&["BadId"]), Decision::Stay);
}

/// A rotator absent from the local roster is never trusted.
#[test]
fn rotator_not_in_local_roster_is_invalid() {
    let mut t = at_genesis(C);
    t.roster.retain(|e| e.device_id != did(A));
    assert_eq!(
        resolve(&t, &recs(&["A"]), &complete(&["A"])),
        Decision::Stay
    );
}

/// Only generation 2 known: wait for its parent.
#[test]
fn grandchild_before_child() {
    assert_eq!(
        all_complete(&["A2"]),
        Decision::Wait {
            unknown_parent: vec![h("A")]
        }
    );
    // A record whose parent nobody knows waits too, unless its signer is
    // refused.
    let mut t = at_genesis(C);
    assert_eq!(
        resolve(&t, &recs(&["J"]), &complete(&["J"])),
        Decision::Wait {
            unknown_parent: vec![[0x55; 32]]
        }
    );
    t.excluded.insert(did(B));
    assert_eq!(
        resolve(&t, &recs(&["J"]), &complete(&["J"])),
        Decision::Stay
    );
}

/// A valid child absent from `complete` gives `Wait` with no prompt.
#[test]
fn incomplete_child_waits() {
    let d = resolve(&at_genesis(C), &recs(&["A"]), &complete(&[]));
    assert_eq!(
        d,
        Decision::Wait {
            unknown_parent: vec![]
        }
    );
    // Two lone incomplete children: still nothing to ask.
    let d = resolve(&at_genesis(C), &recs(&["A", "D_hi"]), &complete(&[]));
    assert_eq!(
        d,
        Decision::Wait {
            unknown_parent: vec![]
        }
    );
}

/// 8.3 with B withholding its own delivery: the mutual prompt still comes
/// as soon as A's side is complete, and lists both, so B cannot stall its
/// revocation.
#[test]
fn withheld_b_delivery_does_not_stall_mutual() {
    assert_eq!(
        resolve(&at_genesis(C), &recs(&["A", "B"]), &complete(&["A"])),
        prompt(PromptKind::Mutual, &["A", "B"])
    );
    // Either side complete is enough; neither is not.
    assert_eq!(
        resolve(&at_genesis(C), &recs(&["A", "B"]), &complete(&["B"])),
        prompt(PromptKind::Mutual, &["A", "B"])
    );
    assert_eq!(
        resolve(&at_genesis(C), &recs(&["A", "B"]), &complete(&[])),
        Decision::Wait {
            unknown_parent: vec![]
        }
    );
}

/// A smaller-hash sibling of B, never complete, does not block an honest
/// complete sibling (8.5 step 2 among complete accepted siblings).
#[test]
fn withheld_smaller_b_sibling_does_not_block() {
    assert!(h("Bs") < h("D_hi"));
    assert_eq!(
        resolve(&at_genesis(C), &recs(&["Bs", "D_hi"]), &complete(&["D_hi"])),
        prompt(PromptKind::Single, &["D_hi"])
    );
    // Once complete, B's record is the winner again and is asked about.
    let names = ["Bs", "D_hi"];
    assert_eq!(
        resolve(&at_genesis(C), &recs(&names), &complete(&names)),
        prompt(PromptKind::Single, &["Bs"])
    );
    // At a divergence: C on D_hi, the smaller Bs withheld. No switch; a
    // wait, since a better sibling may still arrive.
    let t = after(C, &["D_hi"]);
    assert_eq!(
        resolve(&t, &recs(&["D_hi", "Bs"]), &complete(&["D_hi"])),
        Decision::Wait {
            unknown_parent: vec![]
        }
    );
}

/// Shield rule at the children of the head: a smaller honest record that
/// is withheld keeps B's revocation (or drop) of C from acting.
#[test]
fn shield_children_of_head() {
    assert!(h("Dq") < h("Bq") && h("Dq") < h("Bo"));
    let wait = Decision::Wait {
        unknown_parent: vec![],
    };
    for b in ["Bq", "Bo"] {
        let names = ["Dq", b];
        assert_eq!(
            resolve(&at_genesis(C), &recs(&names), &complete(&[])),
            wait,
            "{b}"
        );
        assert_eq!(
            resolve(&at_genesis(C), &recs(&names), &complete(&["Dq"])),
            prompt(PromptKind::Single, &["Dq"]),
            "{b}"
        );
    }
    // Alone, B's records still act.
    assert_eq!(
        resolve(&at_genesis(C), &recs(&["Bo"]), &complete(&[])),
        Decision::Orphaned { child: h("Bo") }
    );
    assert_eq!(
        resolve(&at_genesis(C), &recs(&["Bq"]), &complete(&[])),
        Decision::Quarantine { by: h("Bq") }
    );
}

/// Shield rule at a divergence: C on Dz, the larger sibling; Dq withheld
/// ahead of B's record.
#[test]
fn shield_divergence() {
    assert!(h("Bq") < h("Dz") && h("Bo") < h("Dz"));
    let t = after(C, &["Dz"]);
    for b in ["Bq", "Bo"] {
        let names = ["Dz", "Dq", b];
        assert_eq!(
            resolve(&t, &recs(&names), &complete(&[])),
            Decision::Wait {
                unknown_parent: vec![]
            },
            "{b}"
        );
        assert_eq!(
            resolve(&t, &recs(&names), &complete(&["Dq"])),
            prompt(PromptKind::Switch, &["Dq"]),
            "{b}"
        );
    }
    // Without Dq, B's record is first and acts.
    assert_eq!(
        resolve(&t, &recs(&["Dz", "Bq"]), &complete(&[])),
        Decision::Quarantine { by: h("Bq") }
    );
}

/// Shield rule inside the winning branch: under D_lo, D2_lo withheld
/// ahead of BqU (B revokes C). The switch never ends in quarantine.
#[test]
fn shield_branch() {
    assert!(h("D2_lo") < h("BqU"));
    let t = after(C, &["D_hi"]);
    let names = ["D_hi", "D_lo", "D2_lo", "BqU"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&["D_lo"])),
        prompt(PromptKind::Switch, &["D_lo"])
    );
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&[])),
        Decision::Wait {
            unknown_parent: vec![]
        }
    );
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&["D_lo", "D2_lo"])),
        prompt(PromptKind::Switch, &["D2_lo"])
    );
    // On D_lo, the same pair as children of the head: wait, then D2_lo.
    let t = after(C, &["D_lo"]);
    let names = ["D_lo", "D2_lo", "BqU"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&[])),
        Decision::Wait {
            unknown_parent: vec![]
        }
    );
    // Without D2_lo, BqU is first and acts.
    assert_eq!(
        resolve(&t, &recs(&["D_lo", "BqU"]), &complete(&[])),
        Decision::Quarantine { by: h("BqU") }
    );
}

/// A withheld B-signed descendant on the winning branch does not block
/// the switch to the newest complete one.
#[test]
fn withheld_b_descendant_does_not_block_switch() {
    assert!(h("DB_lo") < h("D2_lo"));
    // C followed D_hi, so B is still trusted there; D_lo wins the divergence.
    let t = after(C, &["D_hi"]);
    let names = ["D_hi", "D_lo", "D2_lo", "DB_lo"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&["D_lo", "D2_lo"])),
        prompt(PromptKind::Switch, &["D2_lo"])
    );
    // Only D_lo complete: the newest complete record is the target.
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&["D_lo"])),
        prompt(PromptKind::Switch, &["D_lo"])
    );
    // Complete, B's descendant is the newest winner and is what is asked
    // (the user rejects it).
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Switch, &["DB_lo"])
    );
    // On a device that revoked B by following A, B's descendant is refused.
    let t = after(C, &["A"]);
    let names = ["A", "D_lo", "D2_lo", "DB_lo"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Switch, &["D2_lo"])
    );
}

/// A child signed by an excluded device, or whose hash is ignored.
#[test]
fn excluded_and_ignored_skip() {
    let mut t = at_genesis(C);
    t.excluded.insert(did(A));
    assert_eq!(
        resolve(&t, &recs(&["A"]), &complete(&["A"])),
        Decision::Stay
    );
    let mut t = at_genesis(C);
    t.ignore(h("A"));
    assert_eq!(
        resolve(&t, &recs(&["A"]), &complete(&["A"])),
        Decision::Stay
    );
    // A revoked rotator too.
    let mut t = at_genesis(C);
    t.add_revoked(&[did(A)]);
    assert_eq!(
        resolve(&t, &recs(&["A"]), &complete(&["A"])),
        Decision::Stay
    );
}

/// Two honest siblings: the smaller hash wins, on every device.
#[test]
fn order_is_smallest_hash() {
    assert!(h("D_lo") < h("A") && h("A") < h("D_hi"));
    // Head on the larger one: switch to the smaller.
    let t = after(C, &["A"]);
    let names = ["A", "D_lo"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Switch, &["D_lo"])
    );
    let t = after(C, &["D_hi"]);
    let names = ["D_hi", "A"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Switch, &["A"])
    );
    // Head on the smaller one: stay.
    let t = after(C, &["D_lo"]);
    let names = ["D_lo", "A"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        Decision::Stay
    );
    // At the parent: the winner is the one asked about.
    assert_eq!(
        all_complete(&["A", "D_hi"]),
        prompt(PromptKind::Single, &["A"])
    );
    assert_eq!(
        all_complete(&["A", "D_lo"]),
        prompt(PromptKind::Single, &["D_lo"])
    );
    assert_eq!(winner(&[signed("A"), signed("D_lo")]), Some(h("D_lo")));
    assert_eq!(winner(&[signed("D_hi"), signed("A")]), Some(h("A")));
}

#[test]
fn exclusion_rule() {
    let (a, b, d, bd) = (
        &signed("A").body,
        &signed("B").body,
        &signed("D_lo").body,
        &signed("Bd").body,
    );
    assert!(excludes(a, b) && excludes(b, a));
    assert!(!excludes(a, d) && !excludes(d, a));
    assert!(excludes(bd, d) && !excludes(d, bd));
    // Mutual: no winner, the user picks.
    assert_eq!(winner(&[signed("A"), signed("B")]), None);
    assert_eq!(winner(&[]), None);
    // The excluded one is never recommended, whatever its hash.
    assert_eq!(winner(&[signed("Bd"), signed("D_hi")]), Some(h("Bd")));
}

/// A mutual pair beside an honest third sibling still needs the user: the
/// order alone would let B's record decide which honest sibling wins.
#[test]
fn mutual_pair_beside_third_sibling_asks() {
    assert_eq!(
        all_complete(&["A", "B", "D_hi"]),
        prompt(PromptKind::Mutual, &["A", "B"])
    );
    // The user keeps A: then the order between A and D decides.
    let mut t = at_genesis(C);
    reject(&mut t, "B");
    let names = ["A", "B", "D_hi"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Single, &["A"])
    );
}

/// A record excluded by an accepted sibling loses its own exclusions: B's
/// `Bd` cannot knock D's rotation out once A revoked B.
#[test]
fn excluded_sibling_cannot_exclude() {
    assert_eq!(
        winner(&[signed("A"), signed("Bd"), signed("D_lo")]),
        Some(h("D_lo"))
    );
    assert_eq!(
        all_complete(&["A", "Bd", "D_lo"]),
        prompt(PromptKind::Single, &["D_lo"])
    );
    // Same result on a device that already revoked B by following A.
    let t = after(C, &["A"]);
    let names = ["A", "Bd", "D_lo"];
    assert_eq!(
        resolve(&t, &recs(&names), &complete(&names)),
        prompt(PromptKind::Switch, &["D_lo"])
    );
}

/// Records of another account are not lineage of this one.
#[test]
fn other_account_is_ignored() {
    let mut t = at_genesis(C);
    t.account_id = Id([0xBB; 16]);
    assert_eq!(
        resolve(&t, &recs(&["A"]), &complete(&["A"])),
        Decision::Stay
    );
}

/// The cache changes nothing: the same decisions with or without it.
#[test]
fn cache_is_transparent() {
    let mut cache = VerifyCache::default();
    for names in [
        &["A", "B"][..],
        &["F", "BadId"],
        &["A2"],
        &["Bq"],
        &["A", "D_lo"],
    ] {
        let t = at_genesis(C);
        let r = recs(names);
        let c = complete(names);
        let first = resolve_cached(&t, &r, &c, &mut cache);
        assert_eq!(first, resolve(&t, &r, &c));
        assert_eq!(first, resolve_cached(&t, &r, &c, &mut cache));
    }
    // A copy of A's body with a broken signature, seen first, does not
    // poison the valid copy.
    let mut broken = signed("A").clone();
    broken.identity_sig = dummy_identity_sig();
    let mut cache = VerifyCache::default();
    let t = at_genesis(C);
    let only_broken = vec![
        world().genesis.clone(),
        LineageRecord::Rotation(broken.clone()),
    ];
    assert_eq!(
        resolve_cached(&t, &only_broken, &complete(&["A"]), &mut cache),
        Decision::Stay
    );
    let both = vec![
        world().genesis.clone(),
        LineageRecord::Rotation(broken),
        rec("A"),
    ];
    assert_eq!(
        resolve_cached(&t, &both, &complete(&["A"]), &mut cache),
        prompt(PromptKind::Single, &["A"])
    );
}

// ---------------------------------------------------------------------
// Interleavings (8.5, G6): random withholding and arrival order, two
// followers C and E, a user who confirms what they did and rejects the rest.

/// Records the user recognizes.
fn honest(name: &str) -> bool {
    matches!(name, "A" | "A2" | "D_lo" | "D_hi" | "D2_lo" | "D2_hi")
}

/// Records that must never reach a decision.
fn forged(name: &str) -> bool {
    matches!(name, "F" | "BadId")
}

fn name_of(hash: &[u8; 32]) -> &'static str {
    hashes()
        .iter()
        .find(|(_, v)| *v == hash)
        .map(|(n, _)| *n)
        .expect("decisions name known records")
}

/// The pool for one variant: `lo` puts D's rotation below A's.
fn pool(lo: bool) -> Vec<&'static str> {
    let mut v = vec!["A", "A2", "B", "Bq", "Bd", "Bs", "J", "F", "BadId"];
    if lo {
        v.extend(["D_lo", "D2_lo", "DB_lo"]);
    } else {
        v.extend(["D_hi", "D2_hi"]);
    }
    v
}

static CACHE: LazyLock<Mutex<VerifyCache>> = LazyLock::new(|| Mutex::new(VerifyCache::default()));

/// One cache for every case: each record is verified once per key.
fn cache() -> MutexGuard<'static, VerifyCache> {
    CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

struct Follower {
    trust: TrustState,
    known: Vec<&'static str>,
    complete: BTreeSet<[u8; 32]>,
    /// Switches per divergence point (the parent where the branches split).
    switches: BTreeMap<[u8; 32], u32>,
}

impl Follower {
    fn records(&self) -> Vec<LineageRecord> {
        recs(&self.known)
    }

    fn decide(&self, records: &[LineageRecord]) -> Decision {
        let c = Completeness {
            present: self.complete.clone(),
        };
        let before = records.to_vec();
        let d = resolve_cached(&self.trust, records, &c, &mut cache());
        // (d) nothing is added, dropped or changed in the records.
        assert_eq!(records, &before[..]);
        // (b) the same pins and the same set, in another order with
        // duplicates, give the same decision.
        let mut shuffled: Vec<LineageRecord> = records.iter().rev().cloned().collect();
        shuffled.extend(records.iter().step_by(2).cloned());
        assert_eq!(d, resolve_cached(&self.trust, &shuffled, &c, &mut cache()));
        d
    }

    /// Hashes of the own chain, head first, back to the genesis.
    fn chain(&self) -> Vec<[u8; 32]> {
        let mut out = vec![self.trust.head.hash];
        let mut cur = self.trust.head.hash;
        while let Some(n) = self.known.iter().find(|n| h(n) == cur) {
            cur = signed(n).body.parent;
            out.push(cur);
        }
        out
    }

    /// Follow `target`: the records from the divergence point down to it.
    /// Returns the divergence point.
    fn follow(&mut self, target: [u8; 32]) -> [u8; 32] {
        let chain = self.chain();
        let mut path = vec![&signed(name_of(&target)).body];
        while !chain.contains(&path.last().unwrap().parent) {
            let parent = path.last().unwrap().parent;
            path.push(&signed(name_of(&parent)).body);
        }
        let split = path.last().unwrap().parent;
        path.reverse();
        move_head(&mut self.trust, &path);
        split
    }

    /// Resolve and answer until nothing is asked.
    fn settle(&mut self) -> Decision {
        for _ in 0..16 {
            let d = self.decide(&self.records());
            let named: Vec<[u8; 32]> = match &d {
                Decision::Prompt(p) => p.children.clone(),
                Decision::Quarantine { by } => vec![*by],
                Decision::Orphaned { child } => vec![*child],
                _ => vec![],
            };
            for x in &named {
                let n = name_of(x);
                assert!(!forged(n), "a forged record reached a decision: {n}");
                assert!(!self.trust.ignored.contains(x), "ignored record named");
                assert!(
                    !self.trust.excluded.contains(&signed(n).body.rotator),
                    "excluded signer named"
                );
            }
            match d {
                Decision::Stay | Decision::Wait { .. } => return d,
                // (a) the head never moves without the user.
                Decision::Switch { .. } => panic!("resolve returned an adoption"),
                Decision::Orphaned { .. } => panic!("every pooled record lists C and E"),
                Decision::Quarantine { by } => {
                    assert!(!honest(name_of(&by)));
                    reject(&mut self.trust, name_of(&by));
                }
                Decision::Prompt(p) => match p.kind {
                    PromptKind::Mutual => {
                        assert!(p.children.len() >= 2);
                        let bad: Vec<_> = p
                            .children
                            .iter()
                            .map(name_of)
                            .filter(|n| !honest(n))
                            .collect();
                        assert!(!bad.is_empty(), "two honest records excluding each other");
                        for n in bad {
                            reject(&mut self.trust, n);
                        }
                    }
                    PromptKind::Reapply => panic!("followers never rotate"),
                    kind => {
                        assert_eq!(p.children.len(), 1);
                        let n = name_of(&p.children[0]);
                        if honest(n) {
                            let split = self.follow(p.children[0]);
                            if kind == PromptKind::Switch {
                                let c = self.switches.entry(split).or_default();
                                *c += 1;
                                // (c) at most once per divergence point.
                                assert!(*c <= 1, "switched twice at one divergence");
                            }
                        } else {
                            reject(&mut self.trust, n);
                        }
                    }
                },
            }
        }
        panic!("the user was asked more than 16 times in a row");
    }
}

fn run(me: usize, arrivals: &[&'static str], late: &BTreeSet<&'static str>) -> Follower {
    let mut f = Follower {
        trust: at_genesis(me),
        known: vec![],
        complete: BTreeSet::new(),
        switches: BTreeMap::new(),
    };
    for n in arrivals {
        f.known.push(n);
        if !late.contains(n) {
            f.complete.insert(h(n));
        }
        f.settle();
    }
    f.complete.extend(arrivals.iter().map(|n| h(n)));
    let last = f.settle();
    assert!(matches!(last, Decision::Stay | Decision::Wait { .. }));
    f
}

fn order(names: &[&'static str], keys: &[u32]) -> Vec<&'static str> {
    let mut v: Vec<(u32, &'static str)> = names
        .iter()
        .copied()
        .zip(keys.iter().copied())
        .map(|(n, k)| (k, n))
        .collect();
    v.sort();
    v.into_iter().map(|(_, n)| n).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn interleavings(
        lo in any::<bool>(),
        keep in prop::collection::vec(any::<bool>(), 12),
        late in prop::collection::vec(any::<bool>(), 12),
        keys_c in prop::collection::vec(any::<u32>(), 12),
        keys_e in prop::collection::vec(any::<u32>(), 12),
    ) {
        let pool = pool(lo);
        let kept: Vec<&'static str> = pool.iter().copied().zip(&keep).filter(|(_, k)| **k).map(|(n, _)| n).collect();
        let late: BTreeSet<&'static str> = pool.iter().copied().zip(&late).filter(|(_, l)| **l).map(|(n, _)| n).collect();
        let fc = run(C, &order(&kept, &keys_c), &late);
        let fe = run(E, &order(&kept, &keys_e), &late);
        // The same records, a user who answers truthfully: one head.
        prop_assert_eq!(fc.trust.head, fe.trust.head);
        // Never an attacker's record as head (rotation.pv: not Adopt(C, B)).
        let head = fc.trust.head.hash;
        prop_assert!(head == world().genesis.hash() || honest(name_of(&head)));
        // The uncached resolver agrees with the cached one.
        let c = Completeness { present: fc.complete.clone() };
        let r = fc.records();
        prop_assert_eq!(
            resolve(&fc.trust, &r, &c),
            resolve_cached(&fc.trust, &r, &c, &mut cache())
        );
    }
}
