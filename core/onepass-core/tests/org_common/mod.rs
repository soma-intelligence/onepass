//! Shared fixtures for the org tests (Business E1). SLH-DSA keygen is slow,
//! so every key here is generated once per test binary behind a `OnceLock`.
//! Each binary uses a subset, hence the `dead_code` allowance.

#![allow(dead_code)]

use std::sync::OnceLock;

use onepass_core::Id;
use onepass_core::crypto::{HybridKemPublic, HybridKemSecret, IdentityKey, IdentityVerifyingKey};
use onepass_core::device_keys::{DeviceKeys, DevicePublic};
use onepass_core::org::OrgSecrets;

/// The org secrets of the test organization.
pub fn org_secrets() -> &'static OrgSecrets {
    static CELL: OnceLock<OrgSecrets> = OnceLock::new();
    CELL.get_or_init(|| OrgSecrets::generate().unwrap())
}

/// Identity key `i` of a pool of 3 (one per test account, `i < 3`).
pub fn identity_pool(i: usize) -> &'static (IdentityKey, IdentityVerifyingKey) {
    static POOL: OnceLock<Vec<(IdentityKey, IdentityVerifyingKey)>> = OnceLock::new();
    &POOL.get_or_init(|| {
        (0..3)
            .map(|_| {
                let k = IdentityKey::generate().unwrap();
                let vk = k.verifying_key();
                (k, vk)
            })
            .collect()
    })[i]
}

/// KEM key pair `i` of a pool of 3 (member KEM keys, `i < 3`).
pub fn kem_pool(i: usize) -> &'static (HybridKemSecret, HybridKemPublic) {
    static POOL: OnceLock<Vec<(HybridKemSecret, HybridKemPublic)>> = OnceLock::new();
    &POOL.get_or_init(|| {
        (0..3)
            .map(|_| {
                let s = HybridKemSecret::generate().unwrap();
                let p = s.public().unwrap();
                (s, p)
            })
            .collect()
    })[i]
}

/// A software device and its public half.
pub struct TestDevice {
    pub keys: DeviceKeys,
    pub public: DevicePublic,
}

/// A fresh software device with id `Id([tag; 16])`.
pub fn device(tag: u8) -> TestDevice {
    let keys = DeviceKeys::generate_software().unwrap();
    let public = keys.public(Id([tag; 16])).unwrap();
    TestDevice { keys, public }
}

/// SHA-256 over the concatenation of `parts` (the crate's helper is private).
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}
