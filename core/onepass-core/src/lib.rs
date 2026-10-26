//! Core library of OnePass: a post-quantum password manager.

pub mod crypto;
pub mod error;
pub mod id;
pub mod model;

pub use error::{Error, IntegrityError, Result, ValidationError};
pub use id::Id;
