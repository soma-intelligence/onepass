//! The signed org roster (spec 5.5, plan B Task 6): who belongs to the
//! organization, with which roles and which devices. One record per
//! sequence number, chained by `prev_hash`, pinned to an org lineage head
//! by `org_head`, signed by one admin device.
//!
//! Message: `postcard(body)` signed under `ORG_ROSTER_DOMAIN`; the record
//! hash is `SHA-256(ORG_ROSTER_DOMAIN || postcard(body))`. Devices are
//! named by fingerprint (D23); an invited member has no identity yet and is
//! bound by `invite_commit` (D1); `account_kem_hash` names the account KEM
//! key (D24); `RecoveryOfficer` is refused in E1 (D8); a removed member
//! keeps no roles and no devices (D10).

use serde::{Deserialize, Serialize};

use super::{
    DeviceFpr, MAX_MEMBER_DEVICES, MAX_ORG_RECORD_BYTES, MAX_ROSTER_MEMBERS, ORG_FORMAT,
    ORG_INVITE_PREFIX, ORG_MEMBER_KEM_PREFIX, ORG_ROSTER_DOMAIN, OrgId, SCIM_ID_PREFIX, sha256,
};
use crate::crypto::sign::SLH_PUBLIC_LEN;
use crate::crypto::{HybridKemPublic, HybridSignature, IdentityVerifyingKey};
use crate::device_keys::{DeviceKeys, DevicePublic};
use crate::lineage::{check_hybrid_sig, decode_strict_with};
use crate::{Error, Id, Result, ValidationError};

/// One role, its bit in a `RoleSet`. Frozen values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Role {
    Owner = 0x01,
    Admin = 0x02,
    UserManager = 0x04,
    PolicyManager = 0x08,
    Auditor = 0x10,
    /// Reserved: refused on every member in E1 (D8).
    RecoveryOfficer = 0x20,
    Provisioner = 0x40,
}

/// A set of roles, one byte on the wire. Bit 0x80 is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct RoleSet(u8);

const ROLE_BITS: u8 = 0x7F;

impl RoleSet {
    pub const EMPTY: RoleSet = RoleSet(0);

    pub fn of(roles: &[Role]) -> RoleSet {
        roles.iter().fold(RoleSet::EMPTY, |s, r| s.with(*r))
    }

    pub fn contains(self, r: Role) -> bool {
        self.0 & r as u8 != 0
    }

    pub fn with(self, r: Role) -> RoleSet {
        RoleSet(self.0 | r as u8)
    }

    pub fn without(self, r: Role) -> RoleSet {
        RoleSet(self.0 & !(r as u8))
    }

    pub fn union(self, o: RoleSet) -> RoleSet {
        RoleSet(self.0 | o.0)
    }

    pub fn intersection(self, o: RoleSet) -> RoleSet {
        RoleSet(self.0 & o.0)
    }

    pub fn difference(self, o: RoleSet) -> RoleSet {
        RoleSet(self.0 & !o.0)
    }

    pub fn is_subset(self, o: RoleSet) -> bool {
        self.0 & !o.0 == 0
    }

    pub fn bits(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for RoleSet {
    type Error = Error;

    fn try_from(b: u8) -> Result<RoleSet> {
        if b & !ROLE_BITS != 0 {
            return Err(bad("role set"));
        }
        Ok(RoleSet(b))
    }
}

impl From<RoleSet> for u8 {
    fn from(s: RoleSet) -> u8 {
        s.0
    }
}

/// Postcard enum: append-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberState {
    /// No identity, no device, zero `account_kem_hash`.
    Invited,
    Active,
    Suspended,
    /// No roles, no devices; identity and hashes kept.
    Removed {
        at: i64,
        by: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMember {
    pub account_id: Id,
    /// `None` while Invited.
    pub account_identity_pub: Option<IdentityVerifyingKey>,
    /// `scim_id_hash(org, external id)`; zero: no directory link.
    pub scim_id_hash: [u8; 32],
    /// `invite_commit(org, account, nonce)`; zero: not invited by nonce
    /// (founding owners, lineage owners).
    pub invite_commit: [u8; 32],
    /// `member_kem_hash(account KEM pub)`, zero while Invited.
    pub account_kem_hash: [u8; 32],
    pub roles: RoleSet,
    pub state: MemberState,
    /// `DevicePublic::fingerprint()` of the member's devices, sorted, unique.
    pub devices: Vec<DeviceFpr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterBody {
    pub format: u8,
    pub org_id: OrgId,
    /// `>= 1`.
    pub seq: u64,
    /// The hash of roster `seq - 1`; zero at `seq == 1`.
    pub prev_hash: [u8; 32],
    /// The org lineage head this roster was written under.
    pub org_head: [u8; 32],
    /// Sorted by `account_id`, unique, at most `MAX_ROSTER_MEMBERS`.
    pub members: Vec<OrgMember>,
}

impl RosterBody {
    /// `postcard(self)`, the signed message.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("roster body encodes")
    }

    /// `SHA-256(ORG_ROSTER_DOMAIN || postcard(self))`.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&[ORG_ROSTER_DOMAIN, &self.encode()])
    }

    pub fn member(&self, a: Id) -> Option<&OrgMember> {
        self.members.iter().find(|m| m.account_id == a)
    }

    /// The member whose device list names `fpr`.
    pub fn device_holder(&self, fpr: &DeviceFpr) -> Option<&OrgMember> {
        self.members.iter().find(|m| m.devices.contains(fpr))
    }

    /// The following roster: `seq + 1`, `prev_hash = self.hash()`, the rest
    /// unchanged.
    pub fn next(&self) -> Result<RosterBody> {
        let seq = self.seq.checked_add(1).ok_or(bad("roster seq"))?;
        Ok(RosterBody {
            seq,
            prev_hash: self.hash(),
            ..self.clone()
        })
    }

    /// Every shape rule (what `SignedRoster::decode` enforces on the body).
    /// The member cap is checked before any member is looked at.
    pub fn check(&self) -> Result<()> {
        if self.format != ORG_FORMAT {
            return Err(bad("roster format"));
        }
        if self.seq == 0 {
            return Err(bad("roster seq"));
        }
        if self.seq == 1 && self.prev_hash != [0; 32] {
            return Err(bad("roster prev hash"));
        }
        if self.members.len() > MAX_ROSTER_MEMBERS {
            return Err(bad("roster member count"));
        }
        if !self
            .members
            .windows(2)
            .all(|w| w[0].account_id < w[1].account_id)
        {
            return Err(bad("roster members order"));
        }
        let mut all: Vec<DeviceFpr> = Vec::new();
        for m in &self.members {
            check_member(m)?;
            all.extend_from_slice(&m.devices);
        }
        // At most MAX_ROSTER_MEMBERS * MAX_MEMBER_DEVICES fingerprints.
        all.sort_unstable();
        if all.windows(2).any(|w| w[0] == w[1]) {
            return Err(bad("roster device held twice"));
        }
        Ok(())
    }
}

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

fn check_identity_pub(k: &IdentityVerifyingKey) -> Result<()> {
    if k.as_bytes().len() != SLH_PUBLIC_LEN {
        return Err(bad("member identity key"));
    }
    Ok(())
}

/// Roles, device count and order, then the state's shape.
fn check_member(m: &OrgMember) -> Result<()> {
    if m.roles.contains(Role::RecoveryOfficer) {
        return Err(bad("member recovery officer role"));
    }
    if m.devices.len() > MAX_MEMBER_DEVICES {
        return Err(bad("member device count"));
    }
    if !m.devices.windows(2).all(|w| w[0] < w[1]) {
        return Err(bad("member devices order"));
    }
    if let Some(k) = &m.account_identity_pub {
        check_identity_pub(k)?;
    }
    match m.state {
        MemberState::Invited => {
            if m.account_identity_pub.is_some()
                || !m.devices.is_empty()
                || m.account_kem_hash != [0; 32]
            {
                return Err(bad("invited member shape"));
            }
        }
        MemberState::Active | MemberState::Suspended => {
            if m.account_identity_pub.is_none()
                || m.devices.is_empty()
                || m.account_kem_hash == [0; 32]
            {
                return Err(bad("member shape"));
            }
        }
        MemberState::Removed { .. } => {
            if m.roles != RoleSet::EMPTY || !m.devices.is_empty() {
                return Err(bad("removed member shape"));
            }
        }
    }
    Ok(())
}

/// A roster signed by one device (the signer's full public key inline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRoster {
    pub body: RosterBody,
    pub signer: DevicePublic,
    pub sig: HybridSignature,
}

impl SignedRoster {
    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("signed roster encodes")
    }

    /// Strict: size cap before parsing, the whole buffer, canonical
    /// re-encoding, `RosterBody::check`, the signer key as
    /// `DevicePublic::decode` checks it, the signature length. No signature
    /// is checked.
    pub fn decode(b: &[u8]) -> Result<SignedRoster> {
        if b.len() > MAX_ORG_RECORD_BYTES {
            return Err(bad("roster size"));
        }
        let rec: SignedRoster = decode_strict_with(b, bad("roster"))?;
        rec.body.check()?;
        check_signer(&rec.signer)?;
        check_hybrid_sig(&rec.sig)?;
        Ok(rec)
    }
}

/// The checks of `DevicePublic::decode`: key lengths, a parsable ML-KEM key.
fn check_signer(p: &DevicePublic) -> Result<()> {
    DevicePublic::decode(&p.encode()).map_err(|_| bad("roster signer key"))?;
    Ok(())
}

/// Checks `body`, signs it with `keys` and refuses keys that do not match
/// `signer`.
pub fn sign_roster(
    body: RosterBody,
    signer: &DevicePublic,
    keys: &DeviceKeys,
) -> Result<SignedRoster> {
    body.check()?;
    check_signer(signer)?;
    let msg = body.encode();
    let sig = keys.sign(ORG_ROSTER_DOMAIN, &msg)?;
    signer
        .sign_pub
        .verify(ORG_ROSTER_DOMAIN, &msg, &sig)
        .map_err(|_| {
            Error::Validation(ValidationError {
                field: "roster signer".into(),
                reason: "keys do not match the public key",
            })
        })?;
    Ok(SignedRoster {
        body,
        signer: signer.clone(),
        sig,
    })
}

/// `SHA-256(SCIM_ID_PREFIX || org_id || external_id)`, the directory link
/// without the directory id in clear.
pub fn scim_id_hash(org_id: OrgId, external_id: &str) -> [u8; 32] {
    sha256(&[SCIM_ID_PREFIX, &org_id.0, external_id.as_bytes()])
}

/// `SHA-256(ORG_INVITE_PREFIX || org_id || account_id || nonce)`.
pub fn invite_commit(org_id: OrgId, account_id: Id, nonce: &[u8; 32]) -> [u8; 32] {
    sha256(&[ORG_INVITE_PREFIX, &org_id.0, &account_id.0, nonce])
}

/// `SHA-256(ORG_MEMBER_KEM_PREFIX || kem_pub.to_bytes())`.
pub fn member_kem_hash(kem_pub: &HybridKemPublic) -> [u8; 32] {
    sha256(&[ORG_MEMBER_KEM_PREFIX, &kem_pub.to_bytes()])
}
