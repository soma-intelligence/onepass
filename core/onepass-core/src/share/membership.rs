//! The signed membership chain of a shared vault (spec 7.1, 7.2, 7.4).
//!
//! Record `RecordKind::Membership`, id = vault id, version = `seq`, in the
//! vault's zone. Every body is signed by a manager under
//! `onepass/membership/v1` (or, for `Leave`, by the member who leaves), and
//! each device accepts the next body against the head it pinned: the
//! signer's key always comes from the pinned body, never from the body
//! received.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::access::ZoneHome;
use super::{MAX_MEMBERS, MEMBERSHIP_DOMAIN, MemberRef, Role, sha256};
use crate::contact::ContactLevel;
use crate::crypto::kem::MLKEM_PUBLIC_LEN;
use crate::crypto::sign::MLDSA_PUBLIC_LEN;
use crate::crypto::{HybridKemPublic, HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::lineage::decode_strict_with;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// Format byte of a membership body.
pub const MEMBERSHIP_FORMAT: u8 = 1;
/// Ancestors a body keeps in `history`.
pub const MEMBERSHIP_HISTORY: usize = 64;

const BAD: Error = Error::InvalidFormat("membership");

fn refused(field: &str, reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: field.into(),
        reason,
    })
}

/// Why a body was written (spec 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipReason {
    Create,
    Add,
    Remove,
    Leave,
    Role,
    Rekey,
    IdentityUpdate,
    Meta,
}

/// One member of a shared vault (spec 7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub account_id: Id,
    pub identity_id: Id,
    pub identity_pub_hash: [u8; 32],
    pub sign_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
    pub role: Role,
    pub owner: bool,
    pub level: ContactLevel,
    pub added_by: MemberRef,
    pub added_at: i64,
    /// No envelope at this generation (spec 12.3).
    pub key_pending: bool,
    /// The member's credential in the zone's mailbox (spec 13.4).
    pub credential_id: [u8; 16],
}

impl Member {
    pub fn member_ref(&self) -> MemberRef {
        MemberRef {
            account_id: self.account_id,
            identity_id: self.identity_id,
        }
    }
}

/// A removed member, kept forever (rule 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    pub account_id: Id,
    pub identity_id: Id,
    pub removed_at: i64,
    pub by: MemberRef,
}

/// Where a vault moved (plan 2 ruling A-10): the account whose mailbox
/// holds the new zone, and its home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MovedTo {
    pub owner: MemberRef,
    pub home: ZoneHome,
}

/// The pointer a manifest or a state keeps to a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipSeen {
    pub seq: u64,
    pub hash: [u8; 32],
}

/// One body of the membership chain (spec 7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipBody {
    pub format: u8,
    pub vault_id: Id,
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub generation: u32,
    pub key_commit: [u8; 32],
    pub members: Vec<Member>,
    pub removed: Vec<Removed>,
    pub signer: MemberRef,
    pub reason: MembershipReason,
    pub moved_to: Option<MovedTo>,
    pub history: Vec<(u64, [u8; 32])>,
    pub issued_at: i64,
}

impl MembershipBody {
    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("membership body encodes")
    }

    /// SHA-256 of the encoded body.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&[&self.encode()])
    }

    pub fn seen(&self) -> MembershipSeen {
        MembershipSeen {
            seq: self.seq,
            hash: self.hash(),
        }
    }

    pub fn member(&self, account_id: Id) -> Option<&Member> {
        self.members
            .binary_search_by(|m| m.account_id.cmp(&account_id))
            .ok()
            .map(|i| &self.members[i])
    }

    pub fn managers(&self) -> impl Iterator<Item = &Member> {
        self.members.iter().filter(|m| m.role == Role::Manage)
    }

    pub fn owner(&self) -> Option<&Member> {
        self.members.iter().find(|m| m.owner)
    }

    /// The next body: `seq + 1`, chained to this one, this one in
    /// `history` (the 64 most recent), signed by `signer` for `reason`.
    /// The caller then changes members, generation and key commitment.
    pub fn next(
        &self,
        signer: MemberRef,
        reason: MembershipReason,
        now: i64,
    ) -> Result<MembershipBody> {
        let seq = self.seq.checked_add(1).ok_or(BAD)?;
        let mut history = self.history.clone();
        history.push((self.seq, self.hash()));
        if history.len() > MEMBERSHIP_HISTORY {
            history.drain(..history.len() - MEMBERSHIP_HISTORY);
        }
        Ok(MembershipBody {
            seq,
            prev_hash: self.hash(),
            signer,
            reason,
            moved_to: None,
            history,
            issued_at: now,
            ..self.clone()
        })
    }

    /// Shape rules (rule 1, the shape part of rules 3, 4 and 6, decision
    /// 1). `InvalidFormat` on any failure.
    pub fn check(&self) -> Result<()> {
        if self.format != MEMBERSHIP_FORMAT || self.seq == 0 || self.generation == 0 {
            return Err(BAD);
        }
        if self.seq == 1 && (self.prev_hash != [0; 32] || !self.history.is_empty()) {
            return Err(BAD);
        }
        if self.members.is_empty() || self.members.len() > MAX_MEMBERS {
            return Err(Error::InvalidFormat("membership size"));
        }
        if !self
            .members
            .windows(2)
            .all(|w| w[0].account_id < w[1].account_id)
        {
            return Err(Error::InvalidFormat("membership order"));
        }
        let mut credentials = BTreeSet::new();
        for m in &self.members {
            if m.sign_pub.mldsa.len() != MLDSA_PUBLIC_LEN
                || m.kem_pub.mlkem.len() != MLKEM_PUBLIC_LEN
            {
                return Err(Error::InvalidFormat("membership keys"));
            }
            if !credentials.insert(m.credential_id) {
                return Err(Error::InvalidFormat("membership credential"));
            }
            // Decision 1, rule 6 extended: anything that writes is Verified.
            if m.role > Role::Read && m.level != ContactLevel::Verified {
                return Err(Error::InvalidFormat("membership level"));
            }
        }
        if self.members.iter().filter(|m| m.owner).count() > 1 {
            return Err(Error::InvalidFormat("membership owner"));
        }
        if self.managers().next().is_none() {
            return Err(Error::InvalidFormat("membership managers"));
        }
        if !self
            .removed
            .windows(2)
            .all(|w| (w[0].account_id, w[0].identity_id) < (w[1].account_id, w[1].identity_id))
        {
            return Err(Error::InvalidFormat("membership removed order"));
        }
        for r in &self.removed {
            if self
                .member(r.account_id)
                .is_some_and(|m| m.identity_id == r.identity_id)
            {
                return Err(Error::InvalidFormat("membership removed"));
            }
        }
        if self.history.len() > MEMBERSHIP_HISTORY
            || !self.history.windows(2).all(|w| w[0].0 < w[1].0)
            || self.history.last().is_some_and(|(s, _)| *s >= self.seq)
        {
            return Err(Error::InvalidFormat("membership history"));
        }
        if self.moved_to.is_some() {
            if self.reason != MembershipReason::Rekey {
                return Err(Error::InvalidFormat("membership moved_to"));
            }
            if let Some(m) = &self.moved_to {
                m.home.check()?;
            }
        }
        Ok(())
    }
}

/// A body and its signature (domain `onepass/membership/v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMembership {
    pub body: MembershipBody,
    pub sig: HybridSignature,
}

impl SignedMembership {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("signed membership encodes")
    }

    /// Strict: the whole buffer, canonical, the shape rules of the body.
    /// No signature is verified (see `accept_next`, `accept_first`).
    pub fn decode(b: &[u8]) -> Result<SignedMembership> {
        let s: SignedMembership = decode_strict_with(b, BAD)?;
        s.body.check()?;
        Ok(s)
    }

    fn verify_with(&self, key: &HybridVerifyingKey) -> Result<()> {
        key.verify(MEMBERSHIP_DOMAIN, &self.body.encode(), &self.sig)
    }
}

/// Check `body`'s shape, then sign it.
pub fn sign_membership(body: MembershipBody, key: &HybridSigningKey) -> Result<SignedMembership> {
    body.check()?;
    let sig = key.sign(MEMBERSHIP_DOMAIN, &body.encode())?;
    Ok(SignedMembership { body, sig })
}

/// The first body a device pins (spec 7.3: an invite, or the head a
/// second device of a member joins from). Shape, then the signature under
/// `signer_key`, which the caller took from its contact book (or its own
/// account); the signer must be a manager of the body. Whether the signer
/// may be trusted is the caller's decision.
pub fn accept_first(
    next: &SignedMembership,
    signer_key: &HybridVerifyingKey,
) -> Result<MembershipBody> {
    next.body.check()?;
    let signer = next
        .body
        .member(next.body.signer.account_id)
        .filter(|m| m.identity_id == next.body.signer.identity_id)
        .ok_or_else(|| refused("membership", "signer not a member"))?;
    if signer.role != Role::Manage {
        return Err(refused("membership", "signer not a manager"));
    }
    if &signer.sign_pub != signer_key {
        return Err(IntegrityError::Signature.into());
    }
    next.verify_with(signer_key)?;
    Ok(next.body.clone())
}

/// Accept `next` after the pinned head `pinned` (spec 7.2, rules in
/// order). Returns the body to pin.
pub fn accept_next(pinned: &MembershipBody, next: &SignedMembership) -> Result<MembershipBody> {
    let n = &next.body;
    // Rule 1: shape and chain.
    n.check()?;
    if n.vault_id != pinned.vault_id {
        return Err(IntegrityError::WrongContext.into());
    }
    let pinned_hash = pinned.hash();
    if n.seq == pinned.seq {
        return if n.hash() == pinned_hash {
            Ok(pinned.clone())
        } else {
            Err(IntegrityError::MembershipFork.into())
        };
    }
    if n.seq < pinned.seq {
        if pinned
            .history
            .iter()
            .any(|(s, h)| *s == n.seq && *h != n.hash())
        {
            return Err(IntegrityError::MembershipFork.into());
        }
        return Err(IntegrityError::MembershipRollback.into());
    }
    let chained = if n.seq == pinned.seq + 1 {
        n.prev_hash == pinned_hash
    } else {
        n.history.contains(&(pinned.seq, pinned_hash))
    };
    if !chained {
        return Err(IntegrityError::MembershipRollback.into());
    }

    // Rule 2: the signer, with its key from the pinned body.
    let signer = pinned
        .member(n.signer.account_id)
        .filter(|m| m.identity_id == n.signer.identity_id)
        .ok_or_else(|| refused("membership", "signer not a member"))?;
    next.verify_with(&signer.sign_pub)?;
    if n.reason == MembershipReason::Leave {
        // Any member may leave, and a leave only removes its signer.
        return accept_leave(pinned, n);
    }
    if signer.role != Role::Manage {
        return Err(refused("membership", "signer not a manager"));
    }

    // Rule 3: removed only grows; a member who disappears is removed (or,
    // for an identity update, comes back under a new identity).
    check_removed_monotone(pinned, n)?;
    for m in &pinned.members {
        let still = n.member(m.account_id);
        let gone = still.is_none_or(|s| s.identity_id != m.identity_id);
        if gone {
            let listed = n
                .removed
                .iter()
                .any(|r| r.account_id == m.account_id && r.identity_id == m.identity_id);
            let replaced = n.reason == MembershipReason::IdentityUpdate && still.is_some();
            if !listed && !replaced {
                return Err(refused("membership", "member dropped without removal"));
            }
        }
    }

    // Rule 4: the owner is changed only by itself; never a new owner.
    if let Some(owner) = pinned.owner() {
        let by_owner = n.signer.account_id == owner.account_id;
        if !by_owner {
            match n.member(owner.account_id) {
                Some(o) if o.owner && o.role == owner.role => {}
                _ => return Err(refused("membership", "owner protected")),
            }
        }
    }
    if let Some(o) = n.owner()
        && pinned.owner().is_none_or(|p| p.account_id != o.account_id)
    {
        return Err(refused("membership", "new owner"));
    }

    // Rule 5: generation.
    check_generation(pinned, n)?;
    Ok(n.clone())
}

fn check_removed_monotone(pinned: &MembershipBody, n: &MembershipBody) -> Result<()> {
    for r in &pinned.removed {
        if !n
            .removed
            .iter()
            .any(|x| x.account_id == r.account_id && x.identity_id == r.identity_id)
        {
            return Err(refused("membership", "removed shrank"));
        }
    }
    Ok(())
}

fn check_generation(pinned: &MembershipBody, n: &MembershipBody) -> Result<()> {
    use MembershipReason::*;
    if n.generation == pinned.generation {
        if n.key_commit != pinned.key_commit {
            return Err(refused(
                "membership",
                "key commitment without new generation",
            ));
        }
        return Ok(());
    }
    if n.generation < pinned.generation {
        return Err(IntegrityError::MembershipRollback.into());
    }
    if n.key_commit == pinned.key_commit {
        return Err(refused("membership", "new generation without new key"));
    }
    if !matches!(n.reason, Remove | Leave | Rekey | IdentityUpdate) {
        return Err(refused("membership", "new generation for this reason"));
    }
    Ok(())
}

/// `Leave`: the signer leaves, nothing else changes (rule 2 exception).
fn accept_leave(pinned: &MembershipBody, n: &MembershipBody) -> Result<MembershipBody> {
    let me = n.signer;
    let mut expected: Vec<Member> = pinned.members.clone();
    expected.retain(|m| m.account_id != me.account_id);
    if n.members != expected {
        return Err(refused("membership", "leave changes others"));
    }
    check_removed_monotone(pinned, n)?;
    let added: Vec<&Removed> = n
        .removed
        .iter()
        .filter(|r| {
            !pinned
                .removed
                .iter()
                .any(|p| p.account_id == r.account_id && p.identity_id == r.identity_id)
        })
        .collect();
    if added.len() != 1
        || added[0].account_id != me.account_id
        || added[0].identity_id != me.identity_id
    {
        return Err(refused("membership", "leave removes another"));
    }
    if n.generation != pinned.generation || n.key_commit != pinned.key_commit {
        return Err(refused("membership", "leave changes the key"));
    }
    if pinned
        .owner()
        .is_some_and(|o| o.account_id == me.account_id)
    {
        return Err(refused("membership", "owner cannot leave"));
    }
    Ok(n.clone())
}

/// Three-way merge of two concurrent member lists over `base` (spec 7.4):
/// a removal on either side wins, the lowest role wins when both changed
/// it, the earliest `added_at` is kept, the result does not depend on the
/// order of `mine` and `theirs`.
pub fn merge_concurrent(
    base: &MembershipBody,
    mine: &MembershipBody,
    theirs: &MembershipBody,
) -> Result<Vec<Member>> {
    let index = |b: &MembershipBody| -> BTreeMap<Id, Member> {
        b.members
            .iter()
            .map(|m| (m.account_id, m.clone()))
            .collect()
    };
    let (b, m, t) = (index(base), index(mine), index(theirs));
    let removed: BTreeSet<(Id, Id)> = merge_removed(base, mine, theirs)
        .into_iter()
        .map(|r| (r.account_id, r.identity_id))
        .collect();
    let accounts: BTreeSet<Id> = b.keys().chain(m.keys()).chain(t.keys()).copied().collect();
    let mut out = Vec::new();
    for a in accounts {
        let merged = match (b.get(&a), m.get(&a), t.get(&a)) {
            // Removed on at least one side: removal wins.
            (Some(_), None, _) | (Some(_), _, None) => None,
            (None, Some(x), None) | (None, None, Some(x)) => Some(x.clone()),
            (None, Some(x), Some(y)) => Some(join(x, y, None)),
            (Some(z), Some(x), Some(y)) => Some(join(x, y, Some(z))),
            (_, None, None) => None,
        };
        if let Some(mm) = merged
            && !removed.contains(&(mm.account_id, mm.identity_id))
        {
            out.push(mm);
        }
    }
    if out.len() > MAX_MEMBERS {
        return Err(Error::InvalidFormat("membership size"));
    }
    Ok(out)
}

/// Symmetric join of two versions of one member.
fn join(x: &Member, y: &Member, base: Option<&Member>) -> Member {
    let changed = |v: &Member| base.is_none_or(|b| b.role != v.role);
    let role = match (changed(x), changed(y)) {
        (true, false) => x.role,
        (false, true) => y.role,
        _ => x.role.min(y.role),
    };
    // The identity (and the keys with it): the side that changed it, else
    // the smaller encoding, so that the join commutes.
    let ident_changed = |v: &Member| base.is_none_or(|b| b.identity_id != v.identity_id);
    let pick = match (ident_changed(x), ident_changed(y)) {
        (true, false) => x,
        (false, true) => y,
        _ => {
            if postcard::to_allocvec(x).ok() <= postcard::to_allocvec(y).ok() {
                x
            } else {
                y
            }
        }
    };
    Member {
        role,
        added_at: x.added_at.min(y.added_at),
        key_pending: x.key_pending || y.key_pending,
        ..pick.clone()
    }
}

/// Union of the removed lists, earliest `removed_at` per identity (ties:
/// the smaller `by`), sorted.
pub fn merge_removed(
    base: &MembershipBody,
    mine: &MembershipBody,
    theirs: &MembershipBody,
) -> Vec<Removed> {
    let mut map: BTreeMap<(Id, Id), Removed> = BTreeMap::new();
    for r in base
        .removed
        .iter()
        .chain(&mine.removed)
        .chain(&theirs.removed)
    {
        let k = (r.account_id, r.identity_id);
        match map.get(&k) {
            Some(cur) if (cur.removed_at, cur.by) <= (r.removed_at, r.by) => {}
            _ => {
                map.insert(k, r.clone());
            }
        }
    }
    map.into_values().collect()
}
