//! Invitation and join request (spec 5.6, plan B Task 9). An admin invites
//! a member: a fresh account id and a random nonce, the roster keeps only
//! `invite_commit(org, account, nonce)` (D1). The member creates a managed
//! account whose genesis (format 2) names the org and that account id, and
//! sends a join request signed by the genesis creator device under
//! `ORG_JOIN_DOMAIN`. The admin verifies it against the pinned roster and
//! the org fingerprint, then activates the member (Invited -> Active).
//!
//! `join_code` is display only: the member reads it on its screen and the
//! admin compares it with the code of the request in the console, which
//! catches a request swapped by a server that saw the invitation nonce
//! (README 20.7). Nothing verifies it and no decision rests on it.

use serde::{Deserialize, Serialize};

use super::{
    MAX_DISPLAY_NAME_BYTES, MAX_ORG_RECORD_BYTES, MemberState, ORG_FORMAT, ORG_JOIN_CODE_PREFIX,
    ORG_JOIN_DOMAIN, OrgId, OrgMember, RoleSet, RosterBody, invite_commit, member_kem_hash, sha256,
};
use crate::crypto::{HybridKemPublic, HybridSignature, IdentityVerifyingKey, random_array};
use crate::device_keys::{DeviceKeys, DevicePublic};
use crate::lineage::{
    GENESIS_FORMAT_MANAGED, LineageRecord, check_hybrid_sig, decode_strict_with, verify_genesis,
};
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// Most bytes of the account genesis carried by a join request.
pub const MAX_JOIN_GENESIS_BYTES: usize = 64 * 1024;
/// Devices of a join request in E1: exactly the genesis creator.
const JOIN_DEVICES: usize = 1;

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

fn invalid(field: &str, reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: field.into(),
        reason,
    })
}

fn wrong_context() -> Error {
    IntegrityError::WrongContext.into()
}

/// What the invite carries besides the server URL and the org fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub account_id: Id,
    pub nonce: [u8; 32],
}

/// The roster after `prev` with a new Invited member: a fresh account id,
/// `invite_commit(org, account, nonce)` with a random nonce, `roles` and
/// `scim_id_hash`, no identity, device or KEM hash.
pub fn invite_member(
    prev: &RosterBody,
    scim_id_hash: [u8; 32],
    roles: RoleSet,
) -> Result<(RosterBody, Invitation)> {
    let account_id = Id::new();
    let nonce = random_array::<32>()?;
    let mut next = prev.next()?;
    let m = OrgMember {
        account_id,
        account_identity_pub: None,
        scim_id_hash,
        invite_commit: invite_commit(prev.org_id, account_id, &nonce),
        account_kem_hash: [0; 32],
        roles,
        state: MemberState::Invited,
        devices: Vec::new(),
    };
    match next
        .members
        .binary_search_by(|x| x.account_id.cmp(&account_id))
    {
        Ok(_) => return Err(invalid("account id", "already in the roster")),
        Err(i) => next.members.insert(i, m),
    }
    next.check()?;
    Ok((next, Invitation { account_id, nonce }))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequestBody {
    pub format: u8,
    pub org_id: OrgId,
    pub account_id: Id,
    pub invite_nonce: [u8; 32],
    /// The org fingerprint the member pinned from the invite.
    pub pinned_fpr: [u8; 32],
    /// `LineageRecord::Genesis` of the member's managed account, at most
    /// `MAX_JOIN_GENESIS_BYTES`.
    #[serde(with = "serde_bytes")]
    pub account_genesis: Vec<u8>,
    /// Exactly one in E1: the genesis creator device.
    pub devices: Vec<DevicePublic>,
    /// At most `MAX_DISPLAY_NAME_BYTES` of UTF-8, no control char, shown
    /// to the admin only.
    pub display_name: String,
    /// Ed25519 public key of the member's org mailbox credential.
    pub mailbox_credential: [u8; 32],
    /// The account KEM key, hashed into the roster on activation.
    pub account_kem_pub: HybridKemPublic,
    pub issued_at: i64,
}

impl JoinRequestBody {
    /// `postcard(self)`, the signed message.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("join request body encodes")
    }

    /// Every shape rule (what `SignedJoinRequest::decode` enforces).
    pub fn check(&self) -> Result<()> {
        if self.format != ORG_FORMAT {
            return Err(bad("join request format"));
        }
        if self.account_genesis.len() > MAX_JOIN_GENESIS_BYTES {
            return Err(bad("join request genesis size"));
        }
        if self.devices.len() != JOIN_DEVICES {
            return Err(bad("join request device count"));
        }
        for d in &self.devices {
            DevicePublic::decode(&d.encode()).map_err(|_| bad("join request device"))?;
        }
        if self.display_name.len() > MAX_DISPLAY_NAME_BYTES
            || self.display_name.chars().any(char::is_control)
        {
            return Err(bad("join request display name"));
        }
        HybridKemPublic::from_bytes(&self.account_kem_pub.to_bytes())
            .map_err(|_| bad("join request kem key"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedJoinRequest {
    pub body: JoinRequestBody,
    /// By `body.devices[0]` under `ORG_JOIN_DOMAIN` over `postcard(body)`.
    pub device_sig: HybridSignature,
}

impl SignedJoinRequest {
    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("join request encodes")
    }

    /// Strict: size cap before parsing, the whole buffer, canonical
    /// re-encoding, `JoinRequestBody::check`, the signature length. No
    /// signature is checked and the genesis is not parsed.
    pub fn decode(b: &[u8]) -> Result<SignedJoinRequest> {
        if b.len() > MAX_ORG_RECORD_BYTES {
            return Err(bad("join request size"));
        }
        let req: SignedJoinRequest = decode_strict_with(b, bad("join request"))?;
        req.body.check()?;
        check_hybrid_sig(&req.device_sig)?;
        Ok(req)
    }
}

/// Checks `body`, signs it with `keys` and refuses keys that do not match
/// `body.devices[0]`.
pub fn sign_join_request(body: JoinRequestBody, keys: &DeviceKeys) -> Result<SignedJoinRequest> {
    body.check()?;
    let msg = body.encode();
    let device_sig = keys.sign(ORG_JOIN_DOMAIN, &msg)?;
    body.devices[0]
        .sign_pub
        .verify(ORG_JOIN_DOMAIN, &msg, &device_sig)
        .map_err(|_| invalid("join request signer", "keys do not match devices[0]"))?;
    Ok(SignedJoinRequest { body, device_sig })
}

/// A verified join request, what `activate_member` writes into the roster:
/// the identity, the devices' fingerprints and `member_kem_hash` of
/// `account_kem_pub`. Plan C grants `mailbox_credential` read access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJoin {
    pub account_id: Id,
    pub account_identity_pub: IdentityVerifyingKey,
    pub devices: Vec<DevicePublic>,
    pub display_name: String,
    pub mailbox_credential: [u8; 32],
    pub account_kem_pub: HybridKemPublic,
}

/// `SHA-256(ORG_JOIN_CODE_PREFIX || postcard(req.body))`, its first 8
/// bytes big-endian modulo 10^8, as two zero-padded groups of four digits
/// (`"0123 4567"`). Display only.
pub fn join_code(req: &SignedJoinRequest) -> String {
    let h = sha256(&[ORG_JOIN_CODE_PREFIX, &req.body.encode()]);
    let mut first = [0u8; 8];
    first.copy_from_slice(&h[..8]);
    let n = u64::from_be_bytes(first) % 100_000_000;
    format!("{:04} {:04}", n / 10_000, n % 10_000)
}

/// Verifies a join request against the pinned `roster` and the admin's
/// pinned `org_fpr`. Order: shape; org id (`WrongContext`); the member
/// exists and is Invited (`Validation`); `invite_commit` (`WrongContext`);
/// `pinned_fpr == org_fpr` (`OrgPinMismatch`); the genesis decodes as a
/// `LineageRecord::Genesis` and `verify_genesis` holds (its own errors),
/// then format 2, org, account id and `devices[0]` equal to the creator
/// (`WrongContext`); last the device signature (`Signature`).
pub fn verify_join_request(
    req: &SignedJoinRequest,
    roster: &RosterBody,
    org_fpr: &[u8; 32],
) -> Result<VerifiedJoin> {
    let body = &req.body;
    body.check()?;
    check_hybrid_sig(&req.device_sig)?;
    if body.org_id != roster.org_id {
        return Err(wrong_context());
    }
    let m = roster
        .member(body.account_id)
        .ok_or_else(|| invalid("join request account", "not in the roster"))?;
    if m.state != MemberState::Invited {
        return Err(invalid("join request account", "member is not invited"));
    }
    if invite_commit(body.org_id, body.account_id, &body.invite_nonce) != m.invite_commit {
        return Err(wrong_context());
    }
    if body.pinned_fpr != *org_fpr {
        return Err(IntegrityError::OrgPinMismatch.into());
    }
    let LineageRecord::Genesis(g) = LineageRecord::decode(&body.account_genesis)? else {
        return Err(wrong_context());
    };
    verify_genesis(&g)?;
    let gb = &g.body;
    let device = &body.devices[0];
    if gb.format != GENESIS_FORMAT_MANAGED
        || gb.org != Some(body.org_id.0)
        || gb.account_id != body.account_id
        || gb.creator.device_id != device.device_id
        || gb.creator.sign_pub != device.sign_pub
        || gb.creator.kem_pub != device.kem_pub
    {
        return Err(wrong_context());
    }
    device
        .sign_pub
        .verify(ORG_JOIN_DOMAIN, &body.encode(), &req.device_sig)?;
    Ok(VerifiedJoin {
        account_id: body.account_id,
        account_identity_pub: gb.identity_pub.clone(),
        devices: body.devices.clone(),
        display_name: body.display_name.clone(),
        mailbox_credential: body.mailbox_credential,
        account_kem_pub: body.account_kem_pub.clone(),
    })
}

/// The roster after `prev` with the joined member Active: its identity,
/// its devices' fingerprints (sorted) and `member_kem_hash(account_kem_pub)`;
/// everything else kept. The member must be Invited (`Validation`).
pub fn activate_member(prev: &RosterBody, joined: &VerifiedJoin) -> Result<RosterBody> {
    let mut next = prev.next()?;
    let m = next
        .members
        .iter_mut()
        .find(|m| m.account_id == joined.account_id)
        .ok_or_else(|| invalid("joined account", "not in the roster"))?;
    if m.state != MemberState::Invited {
        return Err(invalid("joined account", "member is not invited"));
    }
    let mut devices: Vec<_> = joined
        .devices
        .iter()
        .map(DevicePublic::fingerprint)
        .collect();
    devices.sort_unstable();
    m.account_identity_pub = Some(joined.account_identity_pub.clone());
    m.devices = devices;
    m.account_kem_hash = member_kem_hash(&joined.account_kem_pub);
    m.state = MemberState::Active;
    next.check()?;
    Ok(next)
}
