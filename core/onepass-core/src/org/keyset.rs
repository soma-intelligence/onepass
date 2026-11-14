//! The owner keyset (plan B Task 5): the org identity and audit secrets,
//! sealed to one owner's account KEM key. The record id is plan A's, not
//! computed here. After an owner's account rotation an `OwnersChanged`
//! carries the new key and the keyset is resealed.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;
use zeroize::Zeroizing;

use super::{MAX_ORG_RECORD_BYTES, ORG_FORMAT, ORG_KEYSET_LABEL, OrgId, OrgLineage, OrgSecrets};
use crate::crypto::aead::{Aad, BlobKind, open, seal};
use crate::crypto::kem::{self, HybridKemPublic, HybridKemSecret};
use crate::crypto::{IdentityKey, SymmetricKey};
use crate::lineage::decode_strict_with;
use crate::{Error, Id, IntegrityError, Result};

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

/// The org's secrets with the org they belong to. No `Serialize`; `Debug`
/// redacts.
pub struct OrgKeyset {
    pub org_id: OrgId,
    pub secrets: OrgSecrets,
}

impl fmt::Debug for OrgKeyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrgKeyset")
            .field("org_id", &self.org_id)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl OrgKeyset {
    /// The identity and the lineage's current audit key must be the ones
    /// this keyset holds, else `Integrity(OrgPinMismatch)`.
    pub fn check_against(&self, lineage: &OrgLineage) -> Result<()> {
        let identity_ok = self.secrets.identity.verifying_key() == lineage.identity_pub;
        let audit_ok = self.secrets.audit.public()? == lineage.audit_kem_pub;
        if self.org_id != lineage.org_id || !identity_ok || !audit_ok {
            return Err(IntegrityError::OrgPinMismatch.into());
        }
        Ok(())
    }
}

/// A keyset sealed to one owner's account KEM key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOrgKeyset {
    pub format: u8,
    pub org_id: OrgId,
    pub account_id: Id,
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub blob: Vec<u8>,
}

impl SealedOrgKeyset {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("sealed org keyset encodes")
    }

    /// Strict: size cap before parsing, the whole buffer, canonical
    /// re-encoding, format 1, the exact envelope length.
    pub fn decode(b: &[u8]) -> Result<SealedOrgKeyset> {
        if b.len() > MAX_ORG_RECORD_BYTES {
            return Err(bad("org keyset size"));
        }
        let s: SealedOrgKeyset = decode_strict_with(b, bad("org keyset"))?;
        if s.format != ORG_FORMAT || s.envelope.len() != kem::envelope_len() {
            return Err(bad("org keyset"));
        }
        Ok(s)
    }
}

fn kem_context(org_id: OrgId, account_id: Id) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..16].copy_from_slice(&org_id.0);
    c[16..].copy_from_slice(&account_id.0);
    c
}

fn aad(org_id: OrgId, account_id: Id) -> Aad {
    Aad {
        blob_id: account_id,
        vault_id: Some(Id(org_id.0)),
        schema: 1,
    }
}

/// Seal `keyset` to the owner's account KEM key.
pub fn seal_org_keyset(
    keyset: &OrgKeyset,
    owner_account_id: Id,
    owner_kem_pub: &HybridKemPublic,
) -> Result<SealedOrgKeyset> {
    let key = SymmetricKey::generate()?;
    let envelope = kem::wrap_key_labeled(
        owner_kem_pub,
        &key,
        ORG_KEYSET_LABEL,
        &kem_context(keyset.org_id, owner_account_id),
    )?;
    let identity = keyset.secrets.identity.to_bytes();
    let audit = keyset.secrets.audit.to_bytes();
    let plain = Zeroizing::new(
        postcard::to_allocvec(&(
            ORG_FORMAT,
            keyset.org_id,
            Bytes::new(&identity),
            Bytes::new(&audit),
        ))
        .map_err(|_| bad("org keyset"))?,
    );
    let blob = seal(
        &key,
        BlobKind::OrgKeyset,
        &aad(keyset.org_id, owner_account_id),
        &plain,
    )?;
    Ok(SealedOrgKeyset {
        format: ORG_FORMAT,
        org_id: keyset.org_id,
        account_id: owner_account_id,
        envelope,
        blob,
    })
}

/// Open `sealed` with the owner's account KEM secret. The context is the
/// caller's `org_id` and `owner_account_id`, never the sealed record's own
/// claim, and the plaintext's org id must equal `org_id`.
pub fn open_org_keyset(
    sealed: &SealedOrgKeyset,
    org_id: OrgId,
    owner_account_id: Id,
    owner_kem: &HybridKemSecret,
) -> Result<OrgKeyset> {
    if sealed.format != ORG_FORMAT
        || sealed.envelope.len() != kem::envelope_len()
        || sealed.blob.len() > MAX_ORG_RECORD_BYTES
    {
        return Err(bad("org keyset"));
    }
    if sealed.org_id != org_id || sealed.account_id != owner_account_id {
        return Err(IntegrityError::WrongContext.into());
    }
    let key = kem::unwrap_key_labeled(
        owner_kem,
        &sealed.envelope,
        ORG_KEYSET_LABEL,
        &kem_context(org_id, owner_account_id),
    )?;
    let plain = open(
        &key,
        BlobKind::OrgKeyset,
        &aad(org_id, owner_account_id),
        &sealed.blob,
    )?;
    let ((format, plain_org, identity, audit), rest) =
        postcard::take_from_bytes::<(u8, OrgId, &Bytes, &Bytes)>(&plain)
            .map_err(|_| bad("org keyset"))?;
    if !rest.is_empty() || format != ORG_FORMAT {
        return Err(bad("org keyset"));
    }
    let canonical = Zeroizing::new(
        postcard::to_allocvec(&(format, plain_org, identity, audit))
            .map_err(|_| bad("org keyset"))?,
    );
    if canonical.as_slice() != plain.as_slice() {
        return Err(bad("org keyset"));
    }
    if plain_org != org_id {
        return Err(IntegrityError::WrongContext.into());
    }
    Ok(OrgKeyset {
        org_id,
        secrets: OrgSecrets {
            identity: IdentityKey::from_bytes(identity)?,
            audit: HybridKemSecret::from_bytes(audit)?,
        },
    })
}
