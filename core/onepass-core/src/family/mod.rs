//! The signed family body (sharing spec 11.1, 11.2, decisions 2 and 13).
//!
//! Record `RecordKind::Family`, id = family id, version = `seq`, in the
//! zone `Family(family_id)`. The chain follows the membership chain of a
//! shared vault (plan 2): every body is signed by an organizer under
//! `onepass/family/v1` (or, for `Leave`, by the member who leaves), and a
//! device accepts the next body against the head it pinned, the signer's
//! key taken from the pinned body.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::contact::ContactLevel;
use crate::crypto::kem::MLKEM_PUBLIC_LEN;
use crate::crypto::sign::MLDSA_PUBLIC_LEN;
use crate::crypto::{HybridKemPublic, HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::lineage::decode_strict_with;
use crate::share::{MAX_CREDENTIAL_ENVELOPE, MemberRef, Removed, ZoneHome, sha256};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// Signature domain of a family body.
pub const FAMILY_DOMAIN: &[u8] = b"onepass/family/v1";
/// Signature domain of a family invitation.
pub const FAMILY_INVITE_DOMAIN: &[u8] = b"onepass/family-invite/v1";
/// Accounts in a family (decision 2).
pub const MAX_FAMILY: usize = 6;
/// Format byte of a family body.
pub const FAMILY_FORMAT: u8 = 1;
/// Ancestors a body keeps in `history`.
pub const FAMILY_HISTORY: usize = 64;
/// Vaults a family lists.
pub const MAX_FAMILY_VAULTS: usize = 64;

const BAD: Error = Error::InvalidFormat("family");

fn refused(reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: "family".into(),
        reason,
    })
}

/// A member's place in the family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FamilyRole {
    Member,
    Organizer,
}

/// One account of the family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyMember {
    pub account_id: Id,
    pub identity_id: Id,
    pub sign_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
    pub role: FamilyRole,
    pub level: ContactLevel,
    pub added_at: i64,
}

impl FamilyMember {
    pub fn member_ref(&self) -> MemberRef {
        MemberRef {
            account_id: self.account_id,
            identity_id: self.identity_id,
        }
    }
}

/// Why a body was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FamilyReason {
    Create,
    Add,
    Remove,
    Leave,
    Role,
    IdentityUpdate,
    Vaults,
}

/// The pointer a state keeps to a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilySeen {
    pub seq: u64,
    pub hash: [u8; 32],
}

/// One body of the family chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyBody {
    pub format: u8,
    pub family_id: Id,
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub members: Vec<FamilyMember>,
    pub removed: Vec<Removed>,
    /// The family's shared vaults, sorted.
    pub vaults: Vec<Id>,
    pub signer: MemberRef,
    pub reason: FamilyReason,
    /// Recent ancestors `(seq, hash)`, so that a device that missed a
    /// body still follows (as the membership chain, plan 2).
    pub history: Vec<(u64, [u8; 32])>,
    pub issued_at: i64,
}

impl FamilyBody {
    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("family body encodes")
    }

    /// SHA-256 of the encoded body.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&[&self.encode()])
    }

    pub fn seen(&self) -> FamilySeen {
        FamilySeen {
            seq: self.seq,
            hash: self.hash(),
        }
    }

    pub fn member(&self, account_id: Id) -> Option<&FamilyMember> {
        self.members
            .binary_search_by(|m| m.account_id.cmp(&account_id))
            .ok()
            .map(|i| &self.members[i])
    }

    pub fn organizers(&self) -> impl Iterator<Item = &FamilyMember> {
        self.members
            .iter()
            .filter(|m| m.role == FamilyRole::Organizer)
    }

    /// The next body: `seq + 1`, chained to this one, signed by `signer`
    /// for `reason`. The caller then changes members or vaults.
    pub fn next(&self, signer: MemberRef, reason: FamilyReason, now: i64) -> Result<FamilyBody> {
        let mut history = self.history.clone();
        history.push((self.seq, self.hash()));
        if history.len() > FAMILY_HISTORY {
            history.drain(..history.len() - FAMILY_HISTORY);
        }
        Ok(FamilyBody {
            seq: self.seq.checked_add(1).ok_or(BAD)?,
            prev_hash: self.hash(),
            history,
            signer,
            reason,
            issued_at: now,
            ..self.clone()
        })
    }

    /// Shape rules. `InvalidFormat` on any failure.
    pub fn check(&self) -> Result<()> {
        if self.format != FAMILY_FORMAT || self.seq == 0 {
            return Err(BAD);
        }
        if self.seq == 1 && (self.prev_hash != [0; 32] || !self.history.is_empty()) {
            return Err(BAD);
        }
        if self.history.len() > FAMILY_HISTORY
            || !self.history.windows(2).all(|w| w[0].0 < w[1].0)
            || self.history.last().is_some_and(|(s, _)| *s >= self.seq)
        {
            return Err(Error::InvalidFormat("family history"));
        }
        if self.members.is_empty() || self.members.len() > MAX_FAMILY {
            return Err(Error::InvalidFormat("family size"));
        }
        if !self
            .members
            .windows(2)
            .all(|w| w[0].account_id < w[1].account_id)
        {
            return Err(Error::InvalidFormat("family order"));
        }
        for m in &self.members {
            if m.sign_pub.mldsa.len() != MLDSA_PUBLIC_LEN
                || m.kem_pub.mlkem.len() != MLKEM_PUBLIC_LEN
            {
                return Err(Error::InvalidFormat("family keys"));
            }
            // Every organizer is Verified (decision 13).
            if m.role == FamilyRole::Organizer && m.level != ContactLevel::Verified {
                return Err(Error::InvalidFormat("family organizer level"));
            }
        }
        if self.organizers().next().is_none() {
            return Err(Error::InvalidFormat("family organizers"));
        }
        if !self
            .removed
            .windows(2)
            .all(|w| (w[0].account_id, w[0].identity_id) < (w[1].account_id, w[1].identity_id))
        {
            return Err(Error::InvalidFormat("family removed order"));
        }
        for r in &self.removed {
            if self
                .member(r.account_id)
                .is_some_and(|m| m.identity_id == r.identity_id)
            {
                return Err(Error::InvalidFormat("family removed"));
            }
        }
        if self.vaults.len() > MAX_FAMILY_VAULTS || !self.vaults.windows(2).all(|w| w[0] < w[1]) {
            return Err(Error::InvalidFormat("family vaults"));
        }
        Ok(())
    }
}

/// A body and its signature (domain `onepass/family/v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFamily {
    pub body: FamilyBody,
    pub sig: HybridSignature,
}

impl SignedFamily {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("signed family encodes")
    }

    /// Strict: the whole buffer, canonical, the shape rules of the body.
    /// No signature is verified (see `accept_next_family`).
    pub fn decode(b: &[u8]) -> Result<SignedFamily> {
        let s: SignedFamily = decode_strict_with(b, BAD)?;
        s.body.check()?;
        Ok(s)
    }

    pub fn verify_with(&self, key: &HybridVerifyingKey) -> Result<()> {
        key.verify(FAMILY_DOMAIN, &self.body.encode(), &self.sig)
    }
}

/// Check `body`'s shape, then sign it.
pub fn sign_family(body: FamilyBody, key: &HybridSigningKey) -> Result<SignedFamily> {
    body.check()?;
    let sig = key.sign(FAMILY_DOMAIN, &body.encode())?;
    Ok(SignedFamily { body, sig })
}

/// The first body a device pins (an invite, or its own creation): shape,
/// the signer an organizer of the body, the signature under `signer_key`
/// (from the caller's contact book or its own account).
pub fn accept_first_family(
    next: &SignedFamily,
    signer_key: &HybridVerifyingKey,
) -> Result<FamilyBody> {
    let n = &next.body;
    n.check()?;
    let signer = n
        .member(n.signer.account_id)
        .filter(|m| m.identity_id == n.signer.identity_id)
        .ok_or_else(|| refused("signer not a member"))?;
    if signer.role != FamilyRole::Organizer {
        return Err(refused("signer not an organizer"));
    }
    if &signer.sign_pub != signer_key {
        return Err(IntegrityError::Signature.into());
    }
    next.verify_with(signer_key)?;
    Ok(n.clone())
}

/// Accept `next` after the pinned head `pinned` (the rules of spec 7.2,
/// an organizer in the place of a manager). Returns the body to pin.
pub fn accept_next_family(pinned: &FamilyBody, next: &SignedFamily) -> Result<FamilyBody> {
    let n = &next.body;
    n.check()?;
    if n.family_id != pinned.family_id {
        return Err(IntegrityError::WrongContext.into());
    }
    if n.seq <= pinned.seq {
        return if n.seq == pinned.seq && n.hash() == pinned.hash() {
            Ok(pinned.clone())
        } else {
            Err(IntegrityError::FamilyRollback.into())
        };
    }
    let chained = if n.seq == pinned.seq + 1 {
        n.prev_hash == pinned.hash()
    } else {
        n.history.contains(&(pinned.seq, pinned.hash()))
    };
    if !chained {
        return Err(IntegrityError::FamilyRollback.into());
    }
    let signer = pinned
        .member(n.signer.account_id)
        .filter(|m| m.identity_id == n.signer.identity_id)
        .ok_or_else(|| refused("signer not a member"))?;
    next.verify_with(&signer.sign_pub)?;
    if n.reason == FamilyReason::Leave {
        return accept_leave(pinned, n);
    }
    if signer.role != FamilyRole::Organizer {
        return Err(refused("signer not an organizer"));
    }
    for r in &pinned.removed {
        if !n
            .removed
            .iter()
            .any(|x| x.account_id == r.account_id && x.identity_id == r.identity_id)
        {
            return Err(refused("removed shrank"));
        }
    }
    for m in &pinned.members {
        let still = n.member(m.account_id);
        if still.is_none_or(|s| s.identity_id != m.identity_id) {
            let listed = n
                .removed
                .iter()
                .any(|r| r.account_id == m.account_id && r.identity_id == m.identity_id);
            let replaced = n.reason == FamilyReason::IdentityUpdate && still.is_some();
            if !listed && !replaced {
                return Err(refused("member dropped without removal"));
            }
        }
    }
    Ok(n.clone())
}

/// A `Leave` body: the signer is gone and listed as removed by itself;
/// nothing else changed.
fn accept_leave(pinned: &FamilyBody, n: &FamilyBody) -> Result<FamilyBody> {
    let me = n.signer;
    let mut expected = pinned.clone();
    expected.members.retain(|m| m.account_id != me.account_id);
    let mut removed = n
        .removed
        .iter()
        .filter(|r| !(r.account_id == me.account_id && r.identity_id == me.identity_id))
        .cloned()
        .collect::<Vec<_>>();
    removed.sort_by_key(|r| (r.account_id, r.identity_id));
    let left = n
        .removed
        .iter()
        .any(|r| r.account_id == me.account_id && r.identity_id == me.identity_id && r.by == me);
    // Over a skip, the bodies in between may have changed the rest: only
    // the leave itself is checked.
    if left && n.seq > pinned.seq + 1 && n.member(me.account_id).is_none() {
        return Ok(n.clone());
    }
    if !left
        || n.members != expected.members
        || removed != pinned.removed
        || n.vaults != pinned.vaults
    {
        return Err(refused("leave only removes its signer"));
    }
    Ok(n.clone())
}

/// An organizer's invitation of a member to the family (arbitrage B-5):
/// the body that adds the member, where the family zone lives and the
/// member's credential seed wrapped for its pinned KEM key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyInvite {
    pub family: SignedFamily,
    pub home: ZoneHome,
    pub credential: Vec<u8>,
    pub signer: MemberRef,
    pub sig: HybridSignature,
}

fn invite_message(
    family: &SignedFamily,
    home: &ZoneHome,
    credential: &[u8],
    signer: &MemberRef,
) -> Vec<u8> {
    postcard::to_allocvec(&(family, home, credential, signer)).expect("family invite encodes")
}

impl FamilyInvite {
    pub fn sign(
        family: SignedFamily,
        home: ZoneHome,
        credential: Vec<u8>,
        signer: MemberRef,
        key: &HybridSigningKey,
    ) -> Result<FamilyInvite> {
        let invite = FamilyInvite {
            sig: key.sign(
                FAMILY_INVITE_DOMAIN,
                &invite_message(&family, &home, &credential, &signer),
            )?,
            family,
            home,
            credential,
            signer,
        };
        invite.check()?;
        Ok(invite)
    }

    /// Shape: the body, the home, the envelope size.
    pub fn check(&self) -> Result<()> {
        self.family.body.check()?;
        self.home.check()?;
        if self.credential.is_empty() || self.credential.len() > MAX_CREDENTIAL_ENVELOPE {
            return Err(BAD);
        }
        Ok(())
    }

    pub fn verify(&self, signer_key: &HybridVerifyingKey) -> Result<()> {
        signer_key.verify(
            FAMILY_INVITE_DOMAIN,
            &invite_message(&self.family, &self.home, &self.credential, &self.signer),
            &self.sig,
        )
    }
}

/// Members whose account ids repeat (a shape the caller builds wrong).
pub fn sorted_members(mut members: Vec<FamilyMember>) -> Result<Vec<FamilyMember>> {
    members.sort_by_key(|m| m.account_id);
    let ids: BTreeSet<Id> = members.iter().map(|m| m.account_id).collect();
    if ids.len() != members.len() {
        return Err(Error::InvalidFormat("family order"));
    }
    Ok(members)
}
