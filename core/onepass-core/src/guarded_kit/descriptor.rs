//! The guard descriptor kept in storage (spec 7.3).
//!
//! The placements (realm id and guard id per realm) are sealed under a key
//! derived from the Secret Key: storage alone cannot find the guard at the
//! realms, so it cannot burn the attempts. Encoding:
//! `"OPGDS01" || postcard(GuardDescriptor)`.

use aws_lc_rs::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use super::wire::GuardId;
use super::{GuardError, RealmInfo};
use crate::Id;
use crate::crypto::key::hkdf32;
use crate::crypto::{Aad, BlobKind, SecretKey, open, seal};

const MAGIC: &[u8; 7] = b"OPGDS01";
const FORMAT: u8 = 1;
const LOCATOR_INFO: &[u8] = b"onepass/guard/locator/v1";
const REALM_SET_DOMAIN: &[u8] = b"onepass/guard/realm-set/v1";
const LOCATOR_SCHEMA: u16 = 1;

/// Where one share lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    pub realm_id: [u8; 16],
    pub guard_id: GuardId,
    /// Index of this realm's OPRF key share (1 to N).
    pub index: u8,
}

/// The sealed part: what a restoring client needs to ask the realms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locator {
    pub version: u32,
    pub threshold: u8,
    pub placements: Vec<Placement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardDescriptor {
    pub format: u8,
    pub account_id: Id,
    pub version: u32,
    pub threshold: u8,
    pub realm_set_hash: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub locator_ct: Vec<u8>,
}

/// SHA-256 over the realm list, in the order given: the list a guard was
/// registered with. A release whose pinned list hashes differently makes
/// the app re-register (spec 8.3).
pub fn realm_set_hash(realms: &[RealmInfo]) -> [u8; 32] {
    let mut m = REALM_SET_DOMAIN.to_vec();
    for r in realms {
        m.extend_from_slice(&r.id);
        m.extend_from_slice(&r.response_key);
    }
    let d = digest(&SHA256, &m);
    let mut h = [0u8; 32];
    h.copy_from_slice(d.as_ref());
    h
}

fn locator_aad(account_id: Id, version: u32) -> Aad {
    // The version rides in the vault id slot: a locator of one version
    // never opens as another.
    let mut v = [0u8; 16];
    v[12..].copy_from_slice(&version.to_be_bytes());
    Aad {
        blob_id: account_id,
        vault_id: Some(Id(v)),
        schema: LOCATOR_SCHEMA,
    }
}

impl GuardDescriptor {
    pub fn seal(
        secret_key: &SecretKey,
        account_id: Id,
        realms: &[RealmInfo],
        locator: &Locator,
    ) -> Result<GuardDescriptor, GuardError> {
        let key = hkdf32(&[], &secret_key.0, &[LOCATOR_INFO]).map_err(|_| GuardError::Crypto)?;
        let plain = postcard::to_allocvec(locator).map_err(|_| GuardError::Malformed("locator"))?;
        let locator_ct = seal(
            &key,
            BlobKind::GuardLocator,
            &locator_aad(account_id, locator.version),
            &plain,
        )
        .map_err(|_| GuardError::Crypto)?;
        Ok(GuardDescriptor {
            format: FORMAT,
            account_id,
            version: locator.version,
            threshold: locator.threshold,
            realm_set_hash: realm_set_hash(realms),
            locator_ct,
        })
    }

    /// Open the locator with the Secret Key. A locator whose plain header
    /// (version, threshold) disagrees with its sealed content is refused.
    pub fn open_locator(&self, secret_key: &SecretKey) -> Result<Locator, GuardError> {
        if self.format != FORMAT {
            return Err(GuardError::Malformed("descriptor format"));
        }
        let key = hkdf32(&[], &secret_key.0, &[LOCATOR_INFO]).map_err(|_| GuardError::Crypto)?;
        let plain = open(
            &key,
            BlobKind::GuardLocator,
            &locator_aad(self.account_id, self.version),
            &self.locator_ct,
        )
        .map_err(|_| GuardError::LocatorRefused)?;
        let locator: Locator =
            postcard::from_bytes(&plain).map_err(|_| GuardError::Malformed("locator"))?;
        if locator.version != self.version || locator.threshold != self.threshold {
            return Err(GuardError::LocatorRefused);
        }
        Ok(locator)
    }

    pub fn encode(&self) -> Result<Vec<u8>, GuardError> {
        let mut out = MAGIC.to_vec();
        out.extend(postcard::to_allocvec(self).map_err(|_| GuardError::Malformed("descriptor"))?);
        Ok(out)
    }

    pub fn decode(b: &[u8]) -> Result<GuardDescriptor, GuardError> {
        let rest = b
            .strip_prefix(MAGIC.as_slice())
            .ok_or(GuardError::Malformed("descriptor magic"))?;
        postcard::from_bytes(rest).map_err(|_| GuardError::Malformed("descriptor"))
    }

    /// SHA-256 of the encoding, carried in the identity-signed account
    /// parameters (spec 7.3).
    pub fn hash(&self) -> Result<[u8; 32], GuardError> {
        let d = digest(&SHA256, &self.encode()?);
        let mut h = [0u8; 32];
        h.copy_from_slice(d.as_ref());
        Ok(h)
    }
}
