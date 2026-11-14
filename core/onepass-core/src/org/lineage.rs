//! The org lineage (spec 5.4, plan B Task 4): the root of trust of an
//! organization. A genesis names the org identity key, the audit KEM key
//! and the owners; every later change carries the org identity signature
//! and the device signatures of a strict majority of the parent
//! generation's owner accounts.
//!
//! Messages: `postcard(body)` of the inner body (`OrgGenesisBody` or
//! `OrgChangeBody`), signed under `ORG_GENESIS_DOMAIN` or
//! `ORG_CHANGE_DOMAIN` by the identity and by every owner device alike.
//! The record hash is `SHA-256(domain || postcard(body))`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    DeviceFpr, MAX_MEMBER_DEVICES, MAX_ORG_NAME_CHARS, MAX_ORG_OWNERS, MAX_ORG_RECORD_BYTES,
    ORG_CHANGE_DOMAIN, ORG_FORMAT, ORG_GENESIS_DOMAIN, OrgId, org_fingerprint, sha256,
};
use crate::crypto::sign::{MLDSA_PUBLIC_LEN, SLH_PUBLIC_LEN};
use crate::crypto::{
    HybridKemPublic, HybridSignature, IdentityKey, IdentitySignature, IdentityVerifyingKey,
};
use crate::device_keys::{DeviceKeys, DevicePublic};
use crate::lineage::{check_hybrid_sig, check_identity_sig, decode_strict_with};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// At most every device of every owner signs a record.
const MAX_OWNER_SIGS: usize = MAX_ORG_OWNERS * MAX_MEMBER_DEVICES;

/// An owner (or, later, a member) as the org lineage names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRef {
    pub account_id: Id,
    pub account_identity_pub: IdentityVerifyingKey,
    /// The full key: the owner keyset is sealed to it (Task 5).
    pub account_kem_pub: HybridKemPublic,
    /// `DevicePublic::fingerprint()` of the account's devices, sorted, unique.
    pub devices: Vec<DeviceFpr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgGenesisBody {
    pub format: u8,
    pub org_id: OrgId,
    pub name: String,
    pub org_identity_pub: IdentityVerifyingKey,
    pub audit_kem_pub: HybridKemPublic,
    /// Sorted by `account_id`, unique, `1..=MAX_ORG_OWNERS`.
    pub owners: Vec<MemberRef>,
    pub created_at: i64,
}

/// The last roster the co-signing owners of an `OwnersChanged` accepted
/// (X17): `seq` and `RosterBody::hash`, `(0, [0; 32])` when no roster
/// exists yet. A zero hash goes only with seq 0, and seq 0 only with a
/// zero hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterCheckpoint {
    pub seq: u64,
    pub hash: [u8; 32],
}

impl RosterCheckpoint {
    /// No roster yet.
    pub const NONE: RosterCheckpoint = RosterCheckpoint {
        seq: 0,
        hash: [0; 32],
    };

    pub(crate) fn check(&self) -> Result<()> {
        if (self.seq == 0) != (self.hash == [0; 32]) {
            return Err(bad("org roster checkpoint"));
        }
        Ok(())
    }
}

/// What a change does. Postcard enum: append-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrgChangeKind {
    /// The new owners, and the roster checkpoint (X17): rosters up to it
    /// are judged with the owners of the generation before this change.
    OwnersChanged {
        owners: Vec<MemberRef>,
        roster_checkpoint: RosterCheckpoint,
    },
    AuditKeyRotated {
        audit_kem_pub: HybridKemPublic,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgChangeBody {
    pub format: u8,
    pub org_id: OrgId,
    /// `>= 1`; the genesis is generation 0.
    pub generation: u64,
    /// The hash of the record at `generation - 1`.
    pub parent: [u8; 32],
    pub kind: OrgChangeKind,
    pub issued_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrgRecordBody {
    Genesis(OrgGenesisBody),
    Change(OrgChangeBody),
}

impl OrgRecordBody {
    /// The signing domain and `postcard` of the inner body.
    fn message(&self) -> (&'static [u8], Vec<u8>) {
        match self {
            OrgRecordBody::Genesis(g) => (
                ORG_GENESIS_DOMAIN,
                postcard::to_allocvec(g).expect("org genesis body encodes"),
            ),
            OrgRecordBody::Change(c) => (
                ORG_CHANGE_DOMAIN,
                postcard::to_allocvec(c).expect("org change body encodes"),
            ),
        }
    }
}

/// An org lineage record with its identity signature and the owner device
/// signatures (the signer's full public key inline, sorted by fingerprint,
/// unique).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrgRecord {
    pub body: OrgRecordBody,
    pub identity_sig: IdentitySignature,
    pub owner_sigs: Vec<(DevicePublic, HybridSignature)>,
}

impl SignedOrgRecord {
    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("org record encodes")
    }

    /// Strict: size cap before parsing, the whole buffer, canonical
    /// re-encoding, every shape rule. No signature is checked.
    pub fn decode(b: &[u8]) -> Result<SignedOrgRecord> {
        if b.len() > MAX_ORG_RECORD_BYTES {
            return Err(bad("org record size"));
        }
        let rec: SignedOrgRecord = decode_strict_with(b, bad("org record"))?;
        check_record(&rec)?;
        Ok(rec)
    }

    /// `SHA-256(domain || postcard(body))`.
    pub fn hash(&self) -> [u8; 32] {
        let (domain, msg) = self.body.message();
        sha256(&[domain, &msg])
    }

    /// 0 for a genesis.
    pub fn generation(&self) -> u64 {
        match &self.body {
            OrgRecordBody::Genesis(_) => 0,
            OrgRecordBody::Change(c) => c.generation,
        }
    }

    pub fn org_id(&self) -> OrgId {
        match &self.body {
            OrgRecordBody::Genesis(g) => g.org_id,
            OrgRecordBody::Change(c) => c.org_id,
        }
    }
}

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

pub(crate) fn check_kem(k: &HybridKemPublic, what: &'static str) -> Result<()> {
    HybridKemPublic::from_bytes(&k.to_bytes()).map_err(|_| bad(what))?;
    Ok(())
}

pub(crate) fn check_identity_pub(k: &IdentityVerifyingKey, what: &'static str) -> Result<()> {
    if k.as_bytes().len() != SLH_PUBLIC_LEN {
        return Err(bad(what));
    }
    Ok(())
}

/// Identity key length, a parsable KEM key, `1..=MAX_MEMBER_DEVICES`
/// device fingerprints, sorted and unique.
fn check_member_ref(m: &MemberRef) -> Result<()> {
    check_identity_pub(&m.account_identity_pub, "member identity key")?;
    check_kem(&m.account_kem_pub, "member kem key")?;
    if m.devices.is_empty() || m.devices.len() > MAX_MEMBER_DEVICES {
        return Err(bad("member device count"));
    }
    if !m.devices.windows(2).all(|w| w[0] < w[1]) {
        return Err(bad("member devices order"));
    }
    Ok(())
}

/// `1..=MAX_ORG_OWNERS` owners sorted by account id, unique, no device
/// fingerprint named by two owners.
pub(crate) fn check_owners(owners: &[MemberRef]) -> Result<()> {
    if owners.is_empty() || owners.len() > MAX_ORG_OWNERS {
        return Err(bad("org owner count"));
    }
    if !owners.windows(2).all(|w| w[0].account_id < w[1].account_id) {
        return Err(bad("org owners order"));
    }
    let mut seen = BTreeSet::new();
    for m in owners {
        check_member_ref(m)?;
        for f in &m.devices {
            if !seen.insert(*f) {
                return Err(bad("org owner device repeated"));
            }
        }
    }
    Ok(())
}

pub(crate) fn check_name(name: &str) -> Result<()> {
    let n = name.chars().count();
    if n == 0 || n > MAX_ORG_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(bad("org name"));
    }
    Ok(())
}

fn check_genesis_body(g: &OrgGenesisBody) -> Result<()> {
    if g.format != ORG_FORMAT {
        return Err(bad("org genesis format"));
    }
    check_name(&g.name)?;
    check_identity_pub(&g.org_identity_pub, "org identity key")?;
    check_kem(&g.audit_kem_pub, "org audit kem key")?;
    check_owners(&g.owners)
}

fn check_change_body(c: &OrgChangeBody) -> Result<()> {
    if c.format != ORG_FORMAT {
        return Err(bad("org change format"));
    }
    if c.generation == 0 {
        return Err(bad("org change generation"));
    }
    match &c.kind {
        OrgChangeKind::OwnersChanged {
            owners,
            roster_checkpoint,
        } => {
            check_owners(owners)?;
            roster_checkpoint.check()
        }
        OrgChangeKind::AuditKeyRotated { audit_kem_pub } => {
            check_kem(audit_kem_pub, "org audit kem key")
        }
    }
}

fn check_body(b: &OrgRecordBody) -> Result<()> {
    match b {
        OrgRecordBody::Genesis(g) => check_genesis_body(g),
        OrgRecordBody::Change(c) => check_change_body(c),
    }
}

/// The `DevicePublic::decode` checks on a signer key.
fn check_device_public(p: &DevicePublic) -> Result<()> {
    if p.sign_pub.mldsa.len() != MLDSA_PUBLIC_LEN {
        return Err(bad("owner signer key"));
    }
    check_kem(&p.kem_pub, "owner signer key")
}

/// `1..=MAX_OWNER_SIGS` signatures, sound keys and lengths, sorted by
/// signer fingerprint without repeat.
fn check_owner_sigs(sigs: &[(DevicePublic, HybridSignature)]) -> Result<()> {
    if sigs.is_empty() || sigs.len() > MAX_OWNER_SIGS {
        return Err(bad("owner signature count"));
    }
    let mut prev: Option<DeviceFpr> = None;
    for (p, s) in sigs {
        check_device_public(p)?;
        check_hybrid_sig(s)?;
        let f = p.fingerprint();
        if prev.is_some_and(|q| q >= f) {
            return Err(bad("owner signatures order"));
        }
        prev = Some(f);
    }
    Ok(())
}

/// Every shape rule of a record (what `decode` enforces), so records built
/// in memory get the same checks before verification.
fn check_record(r: &SignedOrgRecord) -> Result<()> {
    check_body(&r.body)?;
    check_identity_sig(&r.identity_sig)?;
    check_owner_sigs(&r.owner_sigs)
}

fn sign_record(
    body: OrgRecordBody,
    identity: &IdentityKey,
    owner_devices: &[(&DevicePublic, &DeviceKeys)],
) -> Result<SignedOrgRecord> {
    check_body(&body)?;
    let (domain, msg) = body.message();
    let identity_sig = identity.sign(domain, &msg)?;
    let mut rec = SignedOrgRecord {
        body,
        identity_sig,
        owner_sigs: Vec::with_capacity(owner_devices.len()),
    };
    for (public, keys) in owner_devices {
        add_owner_signature(&mut rec, public, keys)?;
    }
    Ok(rec)
}

/// The genesis signed by the org identity and by each of `owner_devices`.
pub fn sign_org_genesis(
    body: OrgGenesisBody,
    identity: &IdentityKey,
    owner_devices: &[(&DevicePublic, &DeviceKeys)],
) -> Result<SignedOrgRecord> {
    sign_record(OrgRecordBody::Genesis(body), identity, owner_devices)
}

/// A change signed by the org identity and by each of `owner_devices`.
pub fn sign_org_change(
    body: OrgChangeBody,
    identity: &IdentityKey,
    owner_devices: &[(&DevicePublic, &DeviceKeys)],
) -> Result<SignedOrgRecord> {
    sign_record(OrgRecordBody::Change(body), identity, owner_devices)
}

/// Co-signing on another owner's device: adds (or replaces) this device's
/// signature, keeping the list sorted by fingerprint. Refuses keys that do
/// not match `public`.
pub fn add_owner_signature(
    rec: &mut SignedOrgRecord,
    public: &DevicePublic,
    keys: &DeviceKeys,
) -> Result<()> {
    check_device_public(public)?;
    let (domain, msg) = rec.body.message();
    let sig = keys.sign(domain, &msg)?;
    public.sign_pub.verify(domain, &msg, &sig).map_err(|_| {
        Error::Validation(ValidationError {
            field: "owner device".into(),
            reason: "keys do not match the public key",
        })
    })?;
    let f = public.fingerprint();
    match rec
        .owner_sigs
        .binary_search_by(|(p, _)| p.fingerprint().cmp(&f))
    {
        Ok(i) => rec.owner_sigs[i] = (public.clone(), sig),
        Err(i) => rec.owner_sigs.insert(i, (public.clone(), sig)),
    }
    Ok(())
}

/// A strict majority of `n` owners: `n / 2 + 1`.
pub fn quorum(n: usize) -> usize {
    n / 2 + 1
}

/// The identity signature first, then every owner signature against the
/// parent owners: an unknown signer device is `OrgQuorum`, any bad
/// signature fails the record, distinct accounts must reach the quorum.
fn verify_signatures(
    rec: &SignedOrgRecord,
    identity_pub: &IdentityVerifyingKey,
    parent_owners: &[MemberRef],
) -> Result<()> {
    let (domain, msg) = rec.body.message();
    identity_pub.verify(domain, &msg, &rec.identity_sig)?;
    let mut accounts = BTreeSet::new();
    for (public, sig) in &rec.owner_sigs {
        let f = public.fingerprint();
        let owner = parent_owners
            .iter()
            .find(|m| m.devices.binary_search(&f).is_ok())
            .ok_or(Error::Integrity(IntegrityError::OrgQuorum))?;
        public.sign_pub.verify(domain, &msg, sig)?;
        accounts.insert(owner.account_id);
    }
    if accounts.len() < quorum(parent_owners.len()) {
        return Err(IntegrityError::OrgQuorum.into());
    }
    Ok(())
}

/// The alarm for a record that conflicts with a known generation: a fork
/// (`OrgLineageFork`) only if the org identity signed it, so the alarm
/// comes with evidence; otherwise the identity signature's error.
pub(crate) fn fork_or_bad_signature(
    rec: &SignedOrgRecord,
    identity_pub: &IdentityVerifyingKey,
) -> Error {
    let (domain, msg) = rec.body.message();
    match identity_pub.verify(domain, &msg, &rec.identity_sig) {
        Ok(()) => IntegrityError::OrgLineageFork.into(),
        Err(e) => e,
    }
}

/// One accepted generation. `roster_checkpoint` is the one its
/// `OwnersChanged` carries (X17), `None` for the genesis and an audit key
/// rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgHeadInfo {
    pub generation: u64,
    pub hash: [u8; 32],
    pub owners: Vec<MemberRef>,
    pub roster_checkpoint: Option<RosterCheckpoint>,
}

/// A verified org lineage. `fingerprint` is the genesis's, pinned for good;
/// `audit_kem_pub` is the current one; `heads` holds every generation from
/// the genesis on, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgLineage {
    pub org_id: OrgId,
    pub fingerprint: [u8; 32],
    pub name: String,
    pub identity_pub: IdentityVerifyingKey,
    pub audit_kem_pub: HybridKemPublic,
    pub heads: Vec<OrgHeadInfo>,
}

impl OrgLineage {
    /// The latest generation.
    pub fn head(&self) -> &OrgHeadInfo {
        self.heads.last().expect("an org lineage has a genesis")
    }

    pub fn find(&self, hash: &[u8; 32]) -> Option<&OrgHeadInfo> {
        self.heads.iter().find(|h| &h.hash == hash)
    }

    /// Accepts the change right after `head()`. Order: org id
    /// (`WrongContext`), generation and parent (an older or equal
    /// generation with another hash is a fork, an older one with the known
    /// hash a rollback, the current head again changes nothing, a gap is
    /// `NotFound`, a wrong parent a fork), identity, quorum of
    /// `head().owners`, then the new head. A fork is reported only for a
    /// record the org identity signed (else the signature error).
    ///
    /// The current head again returns `Ok` after comparing bodies only: it
    /// proves nothing about the received signatures, so never store the
    /// received record, keep your own.
    pub fn apply(&self, next: &SignedOrgRecord) -> Result<OrgLineage> {
        check_record(next)?;
        if next.org_id() != self.org_id {
            return Err(IntegrityError::WrongContext.into());
        }
        let head = self.head();
        let g = next.generation();
        if g <= head.generation {
            let h = next.hash();
            let known = self.heads.iter().find(|i| i.generation == g);
            return match known {
                Some(k) if k.hash != h => Err(fork_or_bad_signature(next, &self.identity_pub)),
                Some(_) if g == head.generation => Ok(self.clone()),
                _ => Err(IntegrityError::OrgLineageRollback.into()),
            };
        }
        if g > head.generation + 1 {
            return Err(Error::NotFound);
        }
        let OrgRecordBody::Change(c) = &next.body else {
            return Err(bad("org change expected"));
        };
        if c.parent != head.hash {
            return Err(fork_or_bad_signature(next, &self.identity_pub));
        }
        verify_signatures(next, &self.identity_pub, &head.owners)?;
        let mut out = self.clone();
        let (owners, roster_checkpoint) = match &c.kind {
            OrgChangeKind::OwnersChanged {
                owners,
                roster_checkpoint,
            } => (owners.clone(), Some(*roster_checkpoint)),
            OrgChangeKind::AuditKeyRotated { audit_kem_pub } => {
                out.audit_kem_pub = audit_kem_pub.clone();
                (head.owners.clone(), None)
            }
        };
        out.heads.push(OrgHeadInfo {
            generation: g,
            hash: next.hash(),
            owners,
            roster_checkpoint,
        });
        Ok(out)
    }
}

/// A genesis signed by its own identity key and a quorum of its own
/// owners.
pub fn verify_org_genesis(rec: &SignedOrgRecord) -> Result<OrgLineage> {
    check_record(rec)?;
    let OrgRecordBody::Genesis(g) = &rec.body else {
        return Err(bad("org genesis expected"));
    };
    verify_signatures(rec, &g.org_identity_pub, &g.owners)?;
    let fingerprint = org_fingerprint(g);
    Ok(OrgLineage {
        org_id: g.org_id,
        fingerprint,
        name: g.name.clone(),
        identity_pub: g.org_identity_pub.clone(),
        audit_kem_pub: g.audit_kem_pub.clone(),
        heads: vec![OrgHeadInfo {
            generation: 0,
            hash: rec.hash(),
            owners: g.owners.clone(),
            roster_checkpoint: None,
        }],
    })
}

/// The genesis first, then consecutive changes. An empty chain is
/// `NotFound`; a record repeated in the chain is a rollback.
pub fn verify_org_chain(records: &[SignedOrgRecord]) -> Result<OrgLineage> {
    let (first, rest) = records.split_first().ok_or(Error::NotFound)?;
    let mut lineage = verify_org_genesis(first)?;
    for rec in rest {
        if rec.generation() <= lineage.head().generation {
            // `apply` treats the current head again as a no-op; in a chain
            // every record must move it forward.
            lineage.apply(rec)?;
            return Err(IntegrityError::OrgLineageRollback.into());
        }
        lineage = lineage.apply(rec)?;
    }
    Ok(lineage)
}
