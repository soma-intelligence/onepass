//! Core library of OnePass: a post-quantum password manager.

// Only crypto::locked may use `unsafe` (page-locked key slots).
#![deny(unsafe_code)]

pub mod account;
pub mod archive;
pub mod chain;
pub mod companion;
pub mod crypto;
pub mod devices;
pub mod epoch;
pub mod error;
pub mod export;
pub mod format;
pub mod generator;
pub mod icon;
pub mod id;
pub mod import;
pub mod lists;
pub mod manifest;
pub mod model;
pub mod pairing;
pub mod reference;
pub mod repo;
pub mod store;
pub mod sync;
pub mod totp;
pub mod vault;
pub mod vaultlist;
pub mod watchtower;
pub mod webauthn;

pub use error::{Error, IntegrityError, Result, ValidationError};
pub use id::Id;
