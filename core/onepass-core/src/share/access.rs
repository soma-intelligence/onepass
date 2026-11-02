//! Zone mailboxes (sharing spec 13.3 to 13.5): where a zone lives, the
//! signed per-account access to it, member credential seeds and the
//! contact zone offer.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{MemberRef, Role, id16, sha256};
use crate::account::Keyset;
use crate::crypto::kem::{unwrap_key_labeled, wrap_key_labeled};
use crate::crypto::sign::{ed25519_public_of, ed25519_sign};
use crate::crypto::{
    HybridKemPublic, HybridSignature, HybridSigningKey, HybridVerifyingKey, SymmetricKey,
};
use crate::lineage::decode_strict_with;
use crate::store::{RecordKind, Zone};
use crate::{Error, Id, Result};

/// `wrap_key_labeled` label of a member's zone credential seed (spec 13.4).
pub const ZONE_CREDENTIAL_LABEL: &[u8] = b"onepass/share/zone-credential/v1";
/// Signature domain of a `ZoneAccess` (spec 13.4).
pub const ZONE_ACCESS_DOMAIN: &[u8] = b"onepass/zone-access/v1";
/// `wrap_key_labeled` label of the seed a `ZoneAccess` keeps for its own
/// account (spec 13.4).
pub const ZONE_ACCESS_SEED_LABEL: &[u8] = b"onepass/zone-access-seed/v1";
/// Hash prefix of a `ZoneAccess` record id.
pub const ZONE_ACCESS_ID_PREFIX: &[u8] = b"onepass/zone-access-id/v1";
/// Signature domain of a contact zone offer (spec 13.5).
pub const CONTACT_ZONE_DOMAIN: &[u8] = b"onepass/contact-zone/v1";
/// Hash prefix of a mailbox credential id: the formula of the mailbox
/// protocol (`onepass-mailbox-proto`, `credential_id`).
pub const MAILBOX_CREDENTIAL_ID_PREFIX: &[u8] = b"onepass/mailbox-credential-id/v1";
/// Record kind of a `ZoneAccess`, in the private zone only. Plan 2 ruling:
/// no new record kind (the 2026-11-02 brief closes the table at 25 for
/// sharing), and `ShareInvite` records only ever live in contact zones, so
/// the private zone's `ShareInvite` rows are zone accesses.
pub const ZONE_ACCESS_KIND: RecordKind = RecordKind::ShareInvite;
/// Largest credential envelope accepted.
pub const MAX_CREDENTIAL_ENVELOPE: usize = 4096;

/// Longest `ZoneHome::url`, in bytes.
pub const MAX_ZONE_URL_BYTES: usize = 256;
/// Longest `ZoneHome::extra_ca_pem`, in bytes.
pub const MAX_ZONE_CA_PEM_BYTES: usize = 8 * 1024;

/// Where a zone's mailbox lives: the server and the mailbox id on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneHome {
    pub url: String,
    pub mailbox_id: [u8; 16],
    pub extra_ca_pem: Option<String>,
}

impl ZoneHome {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("zone home encodes")
    }

    /// Strict decoding, then `check`.
    pub fn decode(b: &[u8]) -> Result<ZoneHome> {
        let h: ZoneHome = decode_strict_with(b, Error::InvalidFormat("zone home"))?;
        h.check()?;
        Ok(h)
    }

    /// Shape rules: an `https://` URL of at most 256 bytes, a PEM of at
    /// most 8 KiB. `InvalidFormat` otherwise.
    pub fn check(&self) -> Result<()> {
        let bad = Error::InvalidFormat("zone home");
        if self.url.len() > MAX_ZONE_URL_BYTES
            || !self.url.starts_with("https://")
            || self.url.len() == "https://".len()
            || self.url.chars().any(char::is_control)
        {
            return Err(bad);
        }
        if self
            .extra_ca_pem
            .as_ref()
            .is_some_and(|p| p.len() > MAX_ZONE_CA_PEM_BYTES || p.is_empty())
        {
            return Err(bad);
        }
        Ok(())
    }

    /// The host of `url`, for the screens.
    pub fn host(&self) -> &str {
        let rest = &self.url["https://".len()..];
        rest.split(['/', '?', '#']).next().unwrap_or(rest)
    }
}

/// A credential's role on a zone mailbox (spec 13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneRole {
    Read,
    Write,
    Manage,
}

/// The mailbox role that follows a member's role (spec 13.4): a reader
/// writes only its own chain records (`Membership`, `MemberKey`,
/// `MemberLineage`, `RekeyRequest`, as a bitmap of record kind codes), a
/// writer writes, a manager manages the credentials.
pub fn server_role(role: Role) -> (ZoneRole, Option<[u8; 32]>) {
    match role {
        Role::Read => {
            let mut kinds = [0u8; 32];
            for k in [
                RecordKind::Membership,
                RecordKind::MemberKey,
                RecordKind::MemberLineage,
                RecordKind::RekeyRequest,
            ] {
                let c = k.code() as usize;
                kinds[c / 8] |= 1 << (c % 8);
            }
            (ZoneRole::Write, Some(kinds))
        }
        Role::Write => (ZoneRole::Write, None),
        Role::Manage => (ZoneRole::Manage, None),
    }
}

/// The Ed25519 seed of one mailbox credential. Lives in clear only in
/// memory: the store and the share actions see envelopes and public keys.
pub struct ZoneSeed(Zeroizing<[u8; 32]>);

impl ZoneSeed {
    pub fn generate() -> Result<ZoneSeed> {
        let k = SymmetricKey::generate()?;
        Ok(ZoneSeed(Zeroizing::new(*k.expose())))
    }

    /// For the transport, which signs mailbox requests with it.
    pub fn from_bytes(b: [u8; 32]) -> ZoneSeed {
        ZoneSeed(Zeroizing::new(b))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn public_key(&self) -> [u8; 32] {
        ed25519_public_of(&self.0).expect("an Ed25519 seed has a public key")
    }

    /// `SHA-256(MAILBOX_CREDENTIAL_ID_PREFIX || public key)[..16]`.
    pub fn credential_id(&self) -> [u8; 16] {
        credential_id_of(&self.public_key())
    }

    /// Ed25519 signature of `m`, for a mailbox request.
    pub fn sign(&self, m: &[u8]) -> Result<[u8; 64]> {
        ed25519_sign(&self.0, m)
    }

    fn as_key(&self) -> SymmetricKey {
        SymmetricKey::from_bytes(*self.0)
    }
}

impl std::fmt::Debug for ZoneSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZoneSeed(..)")
    }
}

/// The mailbox credential id of an Ed25519 public key.
pub fn credential_id_of(public_key: &[u8; 32]) -> [u8; 16] {
    let h = sha256(&[MAILBOX_CREDENTIAL_ID_PREFIX, public_key]);
    id16(&h).0
}

fn credential_context(zone: Zone, mailbox_id: [u8; 16], member: &MemberRef) -> Vec<u8> {
    postcard::to_allocvec(&(
        zone.key(),
        mailbox_id,
        member.account_id,
        member.identity_id,
    ))
    .expect("context encodes")
}

/// Wrap `seed` for a member's pinned KEM key, bound to the zone, its
/// mailbox and the member (spec 13.4).
pub fn wrap_zone_credential(
    kem_pub: &HybridKemPublic,
    seed: &ZoneSeed,
    zone: Zone,
    mailbox_id: [u8; 16],
    member: &MemberRef,
) -> Result<Vec<u8>> {
    wrap_key_labeled(
        kem_pub,
        &seed.as_key(),
        ZONE_CREDENTIAL_LABEL,
        &credential_context(zone, mailbox_id, member),
    )
}

/// Open a credential envelope with this account's keyset: the current KEM
/// key, then each retired one.
pub fn open_zone_credential(
    keyset: &Keyset,
    envelope: &[u8],
    zone: Zone,
    mailbox_id: [u8; 16],
    me: &MemberRef,
) -> Result<ZoneSeed> {
    open_labeled(
        keyset,
        envelope,
        ZONE_CREDENTIAL_LABEL,
        &credential_context(zone, mailbox_id, me),
    )
}

fn open_labeled(keyset: &Keyset, envelope: &[u8], label: &[u8], ctx: &[u8]) -> Result<ZoneSeed> {
    let mut last = Error::Crypto;
    for kem in std::iter::once(&keyset.kem).chain(keyset.retired_kem.iter()) {
        match unwrap_key_labeled(kem, envelope, label, ctx) {
            Ok(k) => return Ok(ZoneSeed(Zeroizing::new(*k.expose()))),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// What a zone access opens: a shared zone, or the account's own anchor
/// mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AccessTarget {
    Zone(Zone),
    Anchor,
}

impl AccessTarget {
    /// `0 || zone key` or `1`. A private zone is no target.
    pub fn key(&self) -> Result<Vec<u8>> {
        match self {
            AccessTarget::Zone(z) if z.is_shared() => {
                let mut k = vec![0u8];
                k.extend(z.key());
                Ok(k)
            }
            AccessTarget::Zone(_) => Err(Error::InvalidFormat("zone access target")),
            AccessTarget::Anchor => Ok(vec![1u8]),
        }
    }

    /// Record id of the access: `SHA-256(ZONE_ACCESS_ID_PREFIX || key)[..16]`.
    pub fn record_id(&self) -> Result<Id> {
        Ok(id16(&sha256(&[ZONE_ACCESS_ID_PREFIX, &self.key()?])))
    }
}

/// An account's access to one target, kept in its private zone so every
/// device of the account finds the mailbox and the credential (spec 13.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneAccess {
    pub target: AccessTarget,
    /// `None` until the mailbox exists (only the zone this account creates).
    pub home: Option<ZoneHome>,
    pub credential_id: [u8; 16],
    /// The seed, wrapped for this account under `ZONE_ACCESS_SEED_LABEL`.
    pub envelope: Vec<u8>,
}

impl ZoneAccess {
    fn check(&self) -> Result<()> {
        self.target.key()?;
        if let Some(h) = &self.home {
            h.check()?;
        }
        if self.envelope.is_empty() || self.envelope.len() > MAX_CREDENTIAL_ENVELOPE {
            return Err(Error::InvalidFormat("zone access"));
        }
        Ok(())
    }
}

/// A `ZoneAccess` signed by its account's signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedZoneAccess {
    pub access: ZoneAccess,
    pub sig: HybridSignature,
}

fn access_message(account_id: Id, access: &ZoneAccess) -> Vec<u8> {
    postcard::to_allocvec(&(account_id, access)).expect("zone access encodes")
}

fn seed_context(target: &AccessTarget, account_id: Id) -> Result<Vec<u8>> {
    Ok(postcard::to_allocvec(&(target.key()?, account_id)).expect("context encodes"))
}

impl SignedZoneAccess {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("zone access encodes")
    }

    /// Strict decoding and shape rules; nothing verified.
    pub fn decode(b: &[u8]) -> Result<SignedZoneAccess> {
        let s: SignedZoneAccess = decode_strict_with(b, Error::InvalidFormat("zone access"))?;
        s.access.check()?;
        Ok(s)
    }

    /// Wrap `seed` for this account's KEM key and sign the access.
    pub fn seal(
        account_id: Id,
        kem_pub: &HybridKemPublic,
        signing: &HybridSigningKey,
        target: AccessTarget,
        home: Option<ZoneHome>,
        seed: &ZoneSeed,
    ) -> Result<SignedZoneAccess> {
        let envelope = wrap_key_labeled(
            kem_pub,
            &seed.as_key(),
            ZONE_ACCESS_SEED_LABEL,
            &seed_context(&target, account_id)?,
        )?;
        let access = ZoneAccess {
            target,
            home,
            credential_id: seed.credential_id(),
            envelope,
        };
        access.check()?;
        let sig = signing.sign(ZONE_ACCESS_DOMAIN, &access_message(account_id, &access))?;
        Ok(SignedZoneAccess { access, sig })
    }

    /// Check the signature against the account's signing key.
    pub fn verify(&self, account_id: Id, signing_pub: &HybridVerifyingKey) -> Result<&ZoneAccess> {
        signing_pub.verify(
            ZONE_ACCESS_DOMAIN,
            &access_message(account_id, &self.access),
            &self.sig,
        )?;
        Ok(&self.access)
    }

    /// Verify, then open the seed; it must match `credential_id`.
    pub fn open(
        &self,
        account_id: Id,
        signing_pub: &HybridVerifyingKey,
        keyset: &Keyset,
    ) -> Result<ZoneSeed> {
        let a = self.verify(account_id, signing_pub)?;
        let seed = open_labeled(
            keyset,
            &a.envelope,
            ZONE_ACCESS_SEED_LABEL,
            &seed_context(&a.target, account_id)?,
        )?;
        if seed.credential_id() != a.credential_id {
            return Err(crate::IntegrityError::WrongContext.into());
        }
        Ok(seed)
    }
}

/// The creator's offer of a contact pair's mailbox, sent during the
/// verification (spec 13.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactZoneOffer {
    pub pair_id: Id,
    pub home: ZoneHome,
    pub creator: MemberRef,
    /// The peer's credential seed, `wrap_zone_credential` for the peer.
    pub credential: Vec<u8>,
}

/// A `ContactZoneOffer` signed by the creator's account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContactZoneOffer {
    pub offer: ContactZoneOffer,
    pub sig: HybridSignature,
}

impl SignedContactZoneOffer {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("offer encodes")
    }

    pub fn decode(b: &[u8]) -> Result<SignedContactZoneOffer> {
        let s: SignedContactZoneOffer =
            decode_strict_with(b, Error::InvalidFormat("contact zone offer"))?;
        s.offer.home.check()?;
        if s.offer.credential.is_empty() || s.offer.credential.len() > MAX_CREDENTIAL_ENVELOPE {
            return Err(Error::InvalidFormat("contact zone offer"));
        }
        Ok(s)
    }

    pub fn sign(
        offer: ContactZoneOffer,
        signing: &HybridSigningKey,
    ) -> Result<SignedContactZoneOffer> {
        let msg = postcard::to_allocvec(&offer).expect("offer encodes");
        let sig = signing.sign(CONTACT_ZONE_DOMAIN, &msg)?;
        let s = SignedContactZoneOffer { offer, sig };
        SignedContactZoneOffer::decode(&s.encode())?;
        Ok(s)
    }
}

/// Decode and verify an offer: signed by the creator's pinned key, for
/// this pair. The credential is opened by the caller (it needs the zone).
pub fn verify_contact_zone_offer(
    bytes: &[u8],
    creator_sign_pub: &HybridVerifyingKey,
    my: &MemberRef,
    pair_id: Id,
) -> Result<ContactZoneOffer> {
    let s = SignedContactZoneOffer::decode(bytes)?;
    let msg = postcard::to_allocvec(&s.offer).expect("offer encodes");
    creator_sign_pub.verify(CONTACT_ZONE_DOMAIN, &msg, &s.sig)?;
    if s.offer.pair_id != pair_id || s.offer.creator.account_id == my.account_id {
        return Err(crate::IntegrityError::WrongContext.into());
    }
    Ok(s.offer)
}
