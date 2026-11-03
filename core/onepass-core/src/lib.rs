//! Core library of OnePass: a post-quantum password manager.

// Only crypto::locked may use `unsafe` (page-locked key slots).
#![deny(unsafe_code)]

pub mod account;
pub mod approvers;
pub mod archive;
pub mod attachment;
pub mod autofill_history;
pub mod chain;
pub mod companion;
pub mod contact;
pub mod crypto;
pub mod device_keys;
pub mod devices;
pub mod duplicates;
pub mod enroll_request;
pub mod epoch;
pub mod error;
pub mod export;
pub mod family;
pub mod fill_plan;
pub mod format;
pub mod generator;
pub mod icon;
pub mod id;
pub mod import;
pub mod lineage;
pub mod lists;
pub mod mailbox_recovery;
pub mod manifest;
pub mod model;
pub mod pairing;
pub mod profiles;
pub mod recovery;
pub mod reference;
pub mod remote;
pub mod remote_unlock;
pub mod repo;
pub mod send;
pub mod share;
pub mod site_password;
pub mod store;
pub mod sync;
pub mod synchome;
pub mod totp;
pub mod trust;
pub mod vault;
pub mod vaultlist;
pub mod wallet_watch;
pub mod watchtower;
pub mod webauthn;

pub use error::{Error, IntegrityError, Result, ValidationError};
pub use id::Id;
