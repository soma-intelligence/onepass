//! Core library of OnePass: a post-quantum password manager.

pub mod error;
pub mod id;

pub use error::{Error, IntegrityError, Result, ValidationError};
pub use id::Id;
