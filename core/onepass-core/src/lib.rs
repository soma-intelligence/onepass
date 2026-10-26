//! Core library of OnePass: a post-quantum password manager.

pub mod account;
pub mod archive;
pub mod crypto;
pub mod error;
pub mod export;
pub mod generator;
pub mod icon;
pub mod id;
pub mod import;
pub mod manifest;
pub mod model;
pub mod reference;
pub mod repo;
pub mod store;
pub mod totp;
pub mod vault;
pub mod watchtower;

pub use error::{Error, IntegrityError, Result, ValidationError};
pub use id::Id;
