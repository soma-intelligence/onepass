//! Cryptographic primitives.

pub mod key;
pub mod random;
pub mod secret_key;

pub use key::SymmetricKey;
pub use random::{fill_random, random_array};
pub use secret_key::SecretKey;
