//! Cryptographic primitives.

pub mod aead;
pub mod kdf;
pub mod kem;
pub mod key;
pub mod random;
pub mod secret_key;
pub mod sign;

pub use aead::{Aad, BlobKind, HEADER_LEN, open, padded_len, seal};
pub use kdf::{KDF_FLOOR, KdfParams, derive_auk};
pub use kem::{HybridKemPublic, HybridKemSecret, unwrap_key, wrap_key};
pub use key::SymmetricKey;
pub use random::{fill_random, random_array};
pub use secret_key::SecretKey;
pub use sign::{
    HybridSignature, HybridSigningKey, HybridVerifyingKey, IdentityKey, IdentitySignature,
    IdentityVerifyingKey,
};
