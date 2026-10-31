//! The lineage resolver of key rotation v2 (spec 7.2, 8.2, 8.3 and 8.5):
//! a pure function from the local [`TrustState`], the lineage records a
//! device knows and the completeness of their deliveries, to a
//! [`Decision`].
//!
//! It reads no clock, does no I/O, uses no randomness, never writes a
//! record and never moves the head: every decision that leads to a new
//! identity is a prompt, and adopting is a user call (Task 9). It also
//! ignores `trust.state`, so the decision depends only on the pins and the
//! set of records, never on their arrival order or on what was decided
//! before.
//!
//! The order of work is fixed (plan Task 4, Step 3):
//!
//! 1. **Filter**: a record counts only if it is a rotation of this account
//!    that passes the structural rules, is not in `ignored`, and whose
//!    rotator is in the local roster, not `revoked` and not `excluded`.
//!    Both signatures are checked with the rotator's key **from the local
//!    roster** (never from a record or the server) and the identity named
//!    in the body. For a child of the head the rotator and every revoked
//!    id must be in the local roster (the parent roster).
//! 2. **Classify**: the own chain is walked from the head back by hash;
//!    at each level, valid siblings of the own record are contenders
//!    (8.5, first divergence); then valid children of the head.
//! 3. **Exclusion** (8.5 step 1): X excludes Y if `X.revoked` contains
//!    `Y.rotator`. Exclusions are settled as a grounded fixpoint: a record
//!    no contender excludes is accepted, a record excluded by an accepted
//!    one is out, and an excluded record's own exclusions stop counting.
//!    What is left (a cycle, such as A revokes B and B revokes A) needs the
//!    user: a `Mutual` prompt (8.3).
//! 4. **Order** (8.5 step 2): among accepted records, the smallest lineage
//!    hash wins.
//!
//! Then "for me" (7.2): a winner that revokes this device gives
//! `Quarantine`, one that does not list it gives `Orphaned`, and a winner
//! whose delivery, params and keyset are not all present gives `Wait`.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    GenesisBody, LineageRecord, RosterEntry, RotationBody, Signed, body_bytes, check_rotation,
    rotation_hash, sha256, verify_rotation,
};
use crate::Id;
use crate::crypto::HybridVerifyingKey;
use crate::trust::TrustState;

/// Lineage hashes whose delivery for this device, params and keyset are
/// present and hash-match (the caller checks them; spec 7.2 "complete for
/// me").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Completeness {
    pub present: BTreeSet<[u8; 32]>,
}

/// What the device does with the lineage it knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing to do.
    Stay,
    /// A valid record is known but cannot be acted on yet: its parents
    /// (sorted) are unknown, or (empty list) its delivery is incomplete.
    Wait { unknown_parent: Vec<[u8; 32]> },
    /// The user decides (`Candidate`, writes blocked).
    Prompt(Prompt),
    /// A valid record revokes this device (spec 8.4). The caller records
    /// `since` from its own clock the first time.
    Quarantine { by: [u8; 32] },
    /// A valid record does not list this device (spec 8.6).
    Orphaned { child: [u8; 32] },
    /// Reserved: never returned. Moving the head is always a user call;
    /// a switch is `Prompt` with `PromptKind::Switch` or `Reapply`.
    Switch { to: [u8; 32] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    /// One child of the head to confirm or reject.
    Single,
    /// Records that exclude each other (8.3): the user keeps one signer.
    Mutual,
    /// The head is on a losing branch: move to the winner's newest
    /// descendant (8.5 step 4).
    Switch,
    /// Like `Switch`, and the losing branch holds this device's own
    /// rotation, to re-apply on the winner (8.5 step 5).
    Reapply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub kind: PromptKind,
    /// Sorted lineage hashes. One for `Single`, `Switch` and `Reapply`.
    pub children: Vec<[u8; 32]>,
}

/// Memo of signature checks, keyed by the hash of the whole signed record
/// and of the key, so a copy with broken signatures never stands for a
/// good one. Only [`resolve_cached`] fills it, with the result of
/// `verify_rotation`: a caller cannot make a record valid through it. The
/// caller owns its lifetime (it grows by one entry per record and key).
#[derive(Debug, Default)]
pub struct VerifyCache {
    seen: BTreeMap<([u8; 32], [u8; 32]), bool>,
}

impl VerifyCache {
    fn check(&mut self, r: &Signed<RotationBody>, key: &HybridVerifyingKey) -> bool {
        let k = (sha256(&[&body_bytes(r)]), sha256(&[&body_bytes(key)]));
        *self
            .seen
            .entry(k)
            .or_insert_with(|| verify_rotation(r, key).is_ok())
    }
}

/// Spec 8.5 step 1: `x` excludes `y` if `x` revokes `y`'s rotator.
pub fn excludes(x: &RotationBody, y: &RotationBody) -> bool {
    x.revoked.contains(&y.rotator)
}

/// The winner among siblings (8.5 steps 1 and 2): the smallest lineage
/// hash among the accepted ones. `None` when the list is empty or when
/// exclusions are left for the user (a mutual revocation).
pub fn winner(siblings: &[&Signed<RotationBody>]) -> Option<[u8; 32]> {
    let mut nodes: BTreeMap<[u8; 32], &RotationBody> = BTreeMap::new();
    for s in siblings {
        nodes.insert(rotation_hash(&s.body), &s.body);
    }
    match settle(&nodes) {
        Some(Settled::Winner(h)) => Some(h),
        _ => None,
    }
}

enum Settled {
    Winner([u8; 32]),
    /// Sorted, at least two.
    Mutual(Vec<[u8; 32]>),
}

/// Grounded settlement of the exclusion graph, then the order. `None` for
/// an empty set.
fn settle(nodes: &BTreeMap<[u8; 32], &RotationBody>) -> Option<Settled> {
    if nodes.is_empty() {
        return None;
    }
    let attackers: BTreeMap<[u8; 32], Vec<[u8; 32]>> = nodes
        .iter()
        .map(|(hy, y)| {
            let by = nodes
                .iter()
                .filter(|(hx, x)| *hx != hy && excludes(x, y))
                .map(|(hx, _)| *hx)
                .collect();
            (*hy, by)
        })
        .collect();
    let mut accepted: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut out: BTreeSet<[u8; 32]> = BTreeSet::new();
    loop {
        let mut changed = false;
        for (h, by) in &attackers {
            if accepted.contains(h) || out.contains(h) {
                continue;
            }
            if by.iter().all(|a| out.contains(a)) {
                accepted.insert(*h);
                changed = true;
            } else if by.iter().any(|a| accepted.contains(a)) {
                out.insert(*h);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let undecided: Vec<[u8; 32]> = nodes
        .keys()
        .filter(|h| !accepted.contains(*h) && !out.contains(*h))
        .copied()
        .collect();
    if !undecided.is_empty() {
        return Some(Settled::Mutual(undecided));
    }
    accepted.first().map(|h| Settled::Winner(*h))
}

/// Resolve with a fresh signature cache.
pub fn resolve(trust: &TrustState, records: &[LineageRecord], complete: &Completeness) -> Decision {
    resolve_cached(trust, records, complete, &mut VerifyCache::default())
}

/// [`resolve`], reusing the signature checks of earlier calls.
pub fn resolve_cached(
    trust: &TrustState,
    records: &[LineageRecord],
    complete: &Completeness,
    cache: &mut VerifyCache,
) -> Decision {
    let mut view = View::new(trust, records, cache);
    if let Some(d) = view.divergence(complete) {
        return d;
    }
    view.children_of_head(complete)
}

/// One rotation body and every copy of it that was given.
struct Node<'a> {
    body: &'a RotationBody,
    copies: Vec<&'a Signed<RotationBody>>,
}

/// Who may appear in a record whose parent is `hash`.
struct Parent<'a> {
    hash: [u8; 32],
    generation: u64,
    /// The parent record's roster, when the parent is not the head.
    roster: Option<&'a [RosterEntry]>,
    /// Revoked between the divergence point and this parent.
    path_revoked: BTreeSet<Id>,
}

struct View<'a, 'c> {
    trust: &'a TrustState,
    rotations: BTreeMap<[u8; 32], Node<'a>>,
    genesis: BTreeMap<[u8; 32], &'a GenesisBody>,
    children: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    cache: &'c mut VerifyCache,
}

impl<'a, 'c> View<'a, 'c> {
    fn new(
        trust: &'a TrustState,
        records: &'a [LineageRecord],
        cache: &'c mut VerifyCache,
    ) -> View<'a, 'c> {
        let mut rotations: BTreeMap<[u8; 32], Node<'a>> = BTreeMap::new();
        let mut genesis = BTreeMap::new();
        let mut children: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>> = BTreeMap::new();
        for r in records {
            if r.account_id() != trust.account_id {
                continue;
            }
            match r {
                LineageRecord::Genesis(g) => {
                    genesis.insert(r.hash(), &g.body);
                }
                LineageRecord::Rotation(s) => {
                    if check_rotation(&s.body).is_err() {
                        continue;
                    }
                    let h = rotation_hash(&s.body);
                    children.entry(s.body.parent).or_default().insert(h);
                    rotations
                        .entry(h)
                        .or_insert_with(|| Node {
                            body: &s.body,
                            copies: Vec::new(),
                        })
                        .copies
                        .push(s);
                }
            }
        }
        View {
            trust,
            rotations,
            genesis,
            children,
            cache,
        }
    }

    fn me(&self) -> Id {
        self.trust.me.device_id
    }

    fn pinned(&self, id: Id) -> Option<&'a RosterEntry> {
        self.trust.roster.iter().find(|e| e.device_id == id)
    }

    /// Rotator pinned locally, not revoked, excluded or ignored, and some
    /// copy verifies under the pinned key.
    fn trusted_signer(&mut self, hash: &[u8; 32], extra_revoked: &BTreeSet<Id>) -> bool {
        let Some(node) = self.rotations.get(hash) else {
            return false;
        };
        let b = node.body;
        if self.trust.ignored.contains(hash)
            || self.trust.revoked.contains(&b.rotator)
            || self.trust.excluded.contains(&b.rotator)
            || extra_revoked.contains(&b.rotator)
        {
            return false;
        }
        let Some(pinned) = self.pinned(b.rotator) else {
            return false;
        };
        let copies = node.copies.clone();
        copies.iter().any(|s| self.cache.check(s, &pinned.sign_pub))
    }

    /// Spec 7.2 "valid", for a record under `parent`.
    fn valid_under(&mut self, hash: &[u8; 32], parent: &Parent<'a>) -> bool {
        let Some(node) = self.rotations.get(hash) else {
            return false;
        };
        let b = node.body;
        if b.parent != parent.hash || parent.generation.checked_add(1) != Some(b.generation) {
            return false;
        }
        let in_local = |id: &Id| self.trust.roster.iter().any(|e| e.device_id == *id);
        let member = |id: &Id| match parent.roster {
            // The head: the local roster is the parent roster.
            None => in_local(id),
            // Elsewhere: the parent record's roster, plus what this device
            // pinned or saw revoked since (intros are not records).
            Some(r) => {
                r.iter().any(|e| e.device_id == *id)
                    || in_local(id)
                    || self.trust.revoked.contains(id)
            }
        };
        if !member(&b.rotator) || !b.revoked.iter().all(member) {
            return false;
        }
        if let (Some(r), Some(pinned)) = (parent.roster, self.pinned(b.rotator))
            && r.iter()
                .any(|e| e.device_id == b.rotator && e.sign_pub != pinned.sign_pub)
        {
            return false;
        }
        self.trusted_signer(hash, &parent.path_revoked)
    }

    fn valid_children(&mut self, parent: &Parent<'a>) -> BTreeMap<[u8; 32], &'a RotationBody> {
        let kids: Vec<[u8; 32]> = self
            .children
            .get(&parent.hash)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let mut out = BTreeMap::new();
        for h in kids {
            if self.valid_under(&h, parent) {
                out.insert(h, self.rotations[&h].body);
            }
        }
        out
    }

    /// The roster of a known record, for its children's membership rules.
    fn roster_of(&self, hash: &[u8; 32]) -> Option<&'a [RosterEntry]> {
        if let Some(n) = self.rotations.get(hash) {
            return Some(&n.body.roster);
        }
        self.genesis
            .get(hash)
            .map(|g| std::slice::from_ref(&g.creator))
    }

    /// The own chain from the head back, each with its body, while the
    /// records are known and the generations step down by one.
    fn chain(&self) -> Vec<([u8; 32], &'a RotationBody)> {
        let mut out = Vec::new();
        let mut h = self.trust.head.hash;
        let mut generation = self.trust.head.generation;
        while let Some(n) = self.rotations.get(&h) {
            if n.body.generation != generation {
                break;
            }
            out.push((h, n.body));
            h = n.body.parent;
            generation -= 1;
        }
        out
    }

    fn lists_me(&self, b: &RotationBody) -> bool {
        b.roster.iter().any(|e| e.device_id == self.me())
    }

    /// Mutual prompt over `set`, if every member that lists this device is
    /// complete.
    fn mutual(&self, set: Vec<[u8; 32]>, complete: &Completeness) -> Decision {
        let ready = set
            .iter()
            .all(|h| !self.lists_me(self.rotations[h].body) || complete.present.contains(h));
        if !ready {
            return Decision::Wait {
                unknown_parent: vec![],
            };
        }
        Decision::Prompt(Prompt {
            kind: PromptKind::Mutual,
            children: set,
        })
    }

    /// 8.5: at the first level of the own chain where a sibling beats the
    /// own record, the decision about the winning branch.
    fn divergence(&mut self, complete: &Completeness) -> Option<Decision> {
        let chain = self.chain();
        for (i, (own_hash, own)) in chain.iter().enumerate().rev() {
            let parent = Parent {
                hash: own.parent,
                generation: own.generation - 1,
                roster: Some(self.roster_of(&own.parent).unwrap_or(&[])),
                path_revoked: BTreeSet::new(),
            };
            let mut contenders = self.valid_children(&parent);
            contenders.remove(own_hash);
            if contenders.is_empty() {
                continue;
            }
            contenders.insert(*own_hash, own);
            match settle(&contenders)? {
                Settled::Mutual(mut set) => {
                    // The own record is listed only when it is one side of
                    // the pair (its revocations were not recorded locally).
                    if set.iter().filter(|h| *h != own_hash).count() >= 2 {
                        set.retain(|h| h != own_hash);
                    }
                    return Some(self.mutual(set, complete));
                }
                Settled::Winner(w) if w == *own_hash => continue,
                Settled::Winner(w) => {
                    let mine = chain[..=i].iter().any(|(_, b)| b.rotator == self.me());
                    let kind = if mine {
                        PromptKind::Reapply
                    } else {
                        PromptKind::Switch
                    };
                    return Some(self.switch(w, kind, complete));
                }
            }
        }
        None
    }

    /// Down the winning branch to its newest descendant this device can
    /// validate, winner after winner; stop at a level the user must settle.
    fn switch(&mut self, w: [u8; 32], kind: PromptKind, complete: &Completeness) -> Decision {
        let mut path = vec![(w, self.rotations[&w].body)];
        let mut revoked: BTreeSet<Id> = path[0].1.revoked.iter().copied().collect();
        loop {
            let (p, pb) = *path.last().expect("path starts with the winner");
            let parent = Parent {
                hash: p,
                generation: pb.generation,
                roster: Some(&pb.roster),
                path_revoked: revoked.clone(),
            };
            let kids = self.valid_children(&parent);
            match settle(&kids) {
                Some(Settled::Winner(k)) => {
                    let kb = self.rotations[&k].body;
                    revoked.extend(kb.revoked.iter().copied());
                    path.push((k, kb));
                }
                _ => break,
            }
        }
        for (h, b) in &path {
            if b.revoked.contains(&self.me()) {
                return Decision::Quarantine { by: *h };
            }
            if !self.lists_me(b) {
                return Decision::Orphaned { child: *h };
            }
        }
        let (target, _) = *path.last().expect("path starts with the winner");
        if !complete.present.contains(&target) {
            return Decision::Wait {
                unknown_parent: vec![],
            };
        }
        Decision::Prompt(Prompt {
            kind,
            children: vec![target],
        })
    }

    /// Spec 7.2 and 8.3: the children of the head.
    fn children_of_head(&mut self, complete: &Completeness) -> Decision {
        let parent = Parent {
            hash: self.trust.head.hash,
            generation: self.trust.head.generation,
            roster: None,
            path_revoked: BTreeSet::new(),
        };
        let kids = self.valid_children(&parent);
        match settle(&kids) {
            None => self.wait_or_stay(),
            Some(Settled::Mutual(set)) => self.mutual(set, complete),
            Some(Settled::Winner(w)) => {
                let b = kids[&w];
                if b.revoked.contains(&self.me()) {
                    Decision::Quarantine { by: w }
                } else if !self.lists_me(b) {
                    Decision::Orphaned { child: w }
                } else if !complete.present.contains(&w) {
                    Decision::Wait {
                        unknown_parent: vec![],
                    }
                } else {
                    Decision::Prompt(Prompt {
                        kind: PromptKind::Single,
                        children: vec![w],
                    })
                }
            }
        }
    }

    /// Records newer than the head, signed by a trusted device, whose
    /// parent is unknown: wait for the parents (8.2 last paragraph).
    fn wait_or_stay(&mut self) -> Decision {
        let candidates: Vec<([u8; 32], [u8; 32])> = self
            .rotations
            .iter()
            .filter(|(_, n)| {
                n.body.generation > self.trust.head.generation
                    && n.body.parent != self.trust.head.hash
                    && !self.rotations.contains_key(&n.body.parent)
                    && !self.genesis.contains_key(&n.body.parent)
            })
            .map(|(h, n)| (*h, n.body.parent))
            .collect();
        let mut parents = BTreeSet::new();
        for (h, parent) in candidates {
            if self.trusted_signer(&h, &BTreeSet::new()) {
                parents.insert(parent);
            }
        }
        if parents.is_empty() {
            Decision::Stay
        } else {
            Decision::Wait {
                unknown_parent: parents.into_iter().collect(),
            }
        }
    }
}
