//! Cryptographic primitives.

pub mod aead;
pub mod kdf;
pub mod kem;
pub mod key;
// The only module of the crate allowed to use `unsafe`.
#[allow(unsafe_code)]
pub mod locked;
pub mod random;
pub mod secret_key;
pub mod sign;

pub use aead::{Aad, BlobKind, HEADER_LEN, open, padded_len, seal};
pub use kdf::{DEV_KDF_FLOOR, KDF_FLOOR, KdfParams, derive_auk};
pub use kem::{HybridKemPublic, HybridKemSecret, unwrap_key, wrap_key};
pub use key::SymmetricKey;
pub use random::{fill_random, random_array};
pub use secret_key::SecretKey;
pub use sign::{
    HybridSignature, HybridSigningKey, HybridVerifyingKey, IdentityKey, IdentitySignature,
    IdentityVerifyingKey,
};
