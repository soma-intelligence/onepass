//! Cryptographic primitives.

pub mod aead;
pub mod kdf;
pub mod key;
pub mod random;
pub mod secret_key;

pub use aead::{Aad, BlobKind, HEADER_LEN, open, padded_len, seal};
pub use kdf::{KDF_FLOOR, KdfParams, derive_auk};
pub use key::SymmetricKey;
pub use random::{fill_random, random_array};
pub use secret_key::SecretKey;
