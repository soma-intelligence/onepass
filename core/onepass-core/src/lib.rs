//! Core library of OnePass: a post-quantum password manager.

pub mod account;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod id;
pub mod manifest;
pub mod model;
pub mod repo;
pub mod store;
pub mod vault;

pub use error::{Error, IntegrityError, Result, ValidationError};
pub use id::Id;
