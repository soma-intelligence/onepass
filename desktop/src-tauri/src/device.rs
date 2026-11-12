//! This device's keys as the core sees them: the classical bytes and the
//! software post-quantum half (spec 2026-10-30 section 6.1: no TPM holds
//! ML-DSA or ML-KEM, so the half is software, sealed with the rest in
//! `device.bin`).

use std::sync::Arc;

use onepass_core::device_keys::{PqDeviceHalf, SoftwarePqHalf};
use onepass_ffi::{FfiPqDeviceHalf, OnePassError};

/// The half the core calls back into. Never calls the FFI itself.
pub struct SoftwareHalf(SoftwarePqHalf);

impl SoftwareHalf {
    pub fn open(bytes: &[u8]) -> Result<Arc<dyn FfiPqDeviceHalf>, OnePassError> {
        let half = SoftwarePqHalf::from_bytes(bytes).map_err(|_| OnePassError::Crypto)?;
        Ok(Arc::new(SoftwareHalf(half)))
    }

    /// Fresh keys, as the bytes `device.bin` keeps.
    pub fn generate() -> Result<zeroize::Zeroizing<Vec<u8>>, OnePassError> {
        Ok(SoftwarePqHalf::generate()
            .map_err(|_| OnePassError::Crypto)?
            .to_bytes())
    }
}

impl FfiPqDeviceHalf for SoftwareHalf {
    fn mldsa_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.0.mldsa_public().map_err(|_| OnePassError::Crypto)
    }

    fn mlkem_public(&self) -> Result<Vec<u8>, OnePassError> {
        self.0.mlkem_public().map_err(|_| OnePassError::Crypto)
    }

    fn mldsa_sign(&self, message: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        self.0.mldsa_sign(&message).map_err(|_| OnePassError::Crypto)
    }

    fn mlkem_decapsulate(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, OnePassError> {
        Ok(self
            .0
            .mlkem_decapsulate(&ciphertext)
            .map_err(|_| OnePassError::Crypto)?
            .to_vec())
    }
}
