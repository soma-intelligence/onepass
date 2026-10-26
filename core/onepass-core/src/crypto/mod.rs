//! Cryptographic primitives.

pub mod key;
pub mod random;

pub use key::SymmetricKey;
pub use random::{fill_random, random_array};
