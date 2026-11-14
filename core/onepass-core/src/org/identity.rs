//! The org identity: the org's own SLH-DSA identity key and its audit KEM
//! key, the public half members pin, its fingerprint and the 20 words a
//! human compares out of band.

use serde::{Deserialize, Serialize};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

use super::{ORG_FPR_PREFIX, ORG_WORDS_PREFIX, OrgId, sha256};
use crate::Result;
use crate::crypto::{HybridKemPublic, HybridKemSecret, IdentityKey, IdentityVerifyingKey};
use crate::generator::{Wordlist, words_of};

/// The org's secrets, held by its owners.
pub struct OrgSecrets {
    pub identity: IdentityKey,
    pub audit: HybridKemSecret,
}

impl OrgSecrets {
    /// A fresh identity key and audit KEM key.
    pub fn generate() -> Result<OrgSecrets> {
        Ok(OrgSecrets {
            identity: IdentityKey::generate()?,
            audit: HybridKemSecret::generate()?,
        })
    }

    /// The public half of the org named `org_id`.
    pub fn public(&self, org_id: OrgId) -> Result<OrgIdentityPublic> {
        Ok(OrgIdentityPublic {
            org_id,
            identity_pub: self.identity.verifying_key(),
            audit_kem_pub: self.audit.public()?,
        })
    }
}

/// What members pin about their org.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgIdentityPublic {
    pub org_id: OrgId,
    pub identity_pub: IdentityVerifyingKey,
    pub audit_kem_pub: HybridKemPublic,
}

/// `SHA-256("onepass/org-fpr/v1" || postcard(p))`.
pub fn org_fingerprint(p: &OrgIdentityPublic) -> [u8; 32] {
    let enc = postcard::to_allocvec(p).expect("org identity public encodes");
    sha256(&[ORG_FPR_PREFIX, &enc])
}

/// Words per group and groups of `fingerprint_words`.
const GROUP_WORDS: usize = 5;
const GROUPS: usize = 4;

/// 20 words of `list` (4 groups of 5) drawn from
/// `SHAKE256("onepass/org-words/v1" || fpr)`: 2-byte big-endian draws below
/// the largest multiple of the list length that fits in 2^16 pick word
/// `v % n`, the others are skipped, so there is no modulo bias. With 7776
/// words, 20 words carry 258 bits, above the fingerprint's 256.
pub fn fingerprint_words(fpr: &[u8; 32], list: Wordlist) -> [[String; GROUP_WORDS]; GROUPS] {
    let words = words_of(list);
    let n = words.len() as u32;
    assert!(n == 7776, "fingerprint words need a 7776-word list");
    let limit = 65536 - (65536 % n);
    let mut xof = Shake256::default();
    xof.update(ORG_WORDS_PREFIX);
    xof.update(fpr);
    let mut reader = xof.finalize_xof();
    let mut out: Vec<&str> = Vec::with_capacity(GROUP_WORDS * GROUPS);
    while out.len() < GROUP_WORDS * GROUPS {
        let mut b = [0u8; 2];
        reader.read(&mut b);
        let v = u32::from(u16::from_be_bytes(b));
        if v < limit {
            out.push(words[(v % n) as usize]);
        }
    }
    std::array::from_fn(|g| std::array::from_fn(|i| out[g * GROUP_WORDS + i].to_owned()))
}
