//! Two-secret key derivation (2SKD): password plus Secret Key give the AUK.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::key::{SymmetricKey, hkdf32};
use super::random::random_array;
use super::secret_key::SecretKey;
use crate::{Error, Result};

/// Minimum accepted Argon2id cost as `(m_kib, t, p)`.
pub const KDF_FLOOR: (u32, u32, u32) = (262144, 4, 4);

/// The floor of dev and test builds only: the fast parameters of the unit
/// tests and of `ONEPASS_DEV_FAST_KDF`. Enforced in place of `KDF_FLOOR`
/// under `cfg(test)`, or with the `dev-fast-kdf` feature in a build with
/// debug assertions; never in a release build.
pub const DEV_KDF_FLOOR: (u32, u32, u32) = (8192, 1, 1);

const AUK_INFO: &[u8] = b"onepass/auk/v1";

/// Argon2id cost parameters and salt, stored with the account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: [u8; 32],
}

impl KdfParams {
    /// The floor parameters with a fresh random salt.
    pub fn new_default() -> Result<KdfParams> {
        let (m_kib, t, p) = KDF_FLOOR;
        Ok(KdfParams {
            m_kib,
            t,
            p,
            salt: random_array::<32>()?,
        })
    }

    /// True when memory, time and parallelism are all at least `floor`'s.
    pub fn is_at_least(&self, floor: &KdfParams) -> bool {
        self.m_kib >= floor.m_kib && self.t >= floor.t && self.p >= floor.p
    }
}

/// NFC-normalize into a wiped-on-drop buffer. The buffer is grown by hand so
/// that no unwiped copy is left behind by a reallocation.
fn nfc_password(password: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(password.len().saturating_mul(2) + 4));
    for c in password.nfc() {
        if out.len() + c.len_utf8() > out.capacity() {
            let mut bigger = Zeroizing::new(String::with_capacity(out.capacity() * 2));
            bigger.push_str(&out);
            out = bigger; // the old buffer is wiped when dropped here
        }
        out.push(c);
    }
    out
}

/// Derive the Account Unlock Key.
///
/// `AUK = HKDF-SHA256(salt = params.salt, ikm = argon2id(NFC(password)) || secret_key,
/// info = "onepass/auk/v1")`, 32 bytes.
///
/// Errors: Argon2 parameters that the Argon2 implementation rejects (for
/// example a memory cost below 8 KiB per lane) give `Error::Crypto`.
pub fn derive_auk(
    password: &str,
    secret_key: &SecretKey,
    params: &KdfParams,
) -> Result<SymmetricKey> {
    let pw = nfc_password(password);
    let argon_params =
        Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| Error::Crypto)?;
    // Caller-owned working memory, so it is wiped on drop (the crate's own
    // allocation is freed unwiped). try_reserve_exact turns an allocation
    // failure into an error instead of an abort, and never reallocates.
    let mut memory: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(argon_params.block_count())
        .map_err(|_| Error::Crypto)?;
    memory.resize(argon_params.block_count(), Block::new());
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    ikm.resize(32, 0);
    argon
        .hash_password_into_with_memory(
            pw.as_bytes(),
            &params.salt,
            &mut ikm[..32],
            memory.as_mut_slice(),
        )
        .map_err(|_| Error::Crypto)?;
    ikm.extend_from_slice(&secret_key.0);

    hkdf32(&params.salt, &ikm, &[AUK_INFO])
}
