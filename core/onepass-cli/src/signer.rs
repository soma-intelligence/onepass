//! Local signatures of the account for `onepass-guard`: the signed MCP
//! policy and the audit log head.
//!
//! A signature is the postcard encoding of the core's `HybridSignature`,
//! made by `Repository::sign_local`, which binds the domain itself
//! (`b"local:" || domain`) as the `LocalSigner` contract requires.

use std::cell::RefCell;
use std::rc::Rc;

use onepass_core::crypto::HybridSignature;
use onepass_core::repo::Repository;
use onepass_core::store::RecordStore;
use onepass_guard::{GuardError, LocalSigner};

use crate::session::LongSession;

/// [`LocalSigner`] over an unlocked repository.
pub struct RepoSigner<'a, S: RecordStore>(pub &'a Repository<S>);

/// Signs with `repo`'s account key under `domain`.
fn sign<S: RecordStore>(
    repo: &Repository<S>,
    domain: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, GuardError> {
    let sig = repo
        .sign_local(domain, msg)
        .map_err(|_| GuardError::Format("local signature"))?;
    postcard::to_allocvec(&sig).map_err(|_| GuardError::Format("local signature"))
}

/// Verifies `sig` against `repo`'s account key under `domain`. Anything
/// that does not decode or verify is a bad signature.
fn verify<S: RecordStore>(
    repo: &Repository<S>,
    domain: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), GuardError> {
    let (sig, rest): (HybridSignature, &[u8]) =
        postcard::take_from_bytes(sig).map_err(|_| GuardError::Signature)?;
    if !rest.is_empty() {
        return Err(GuardError::Signature);
    }
    repo.verify_local(domain, msg, &sig)
        .map_err(|_| GuardError::Signature)
}

impl<S: RecordStore> LocalSigner for RepoSigner<'_, S> {
    fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, GuardError> {
        sign(self.0, domain, msg)
    }

    fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError> {
        verify(self.0, domain, msg, sig)
    }
}

/// [`LocalSigner`] over the session of a long-running server. Signing
/// touches neither the store nor `device.bin`, so it takes no lock.
pub struct SharedSigner(pub Rc<RefCell<LongSession>>);

impl LocalSigner for SharedSigner {
    fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, GuardError> {
        sign(self.0.borrow().repo(), domain, msg)
    }

    fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError> {
        verify(self.0.borrow().repo(), domain, msg, sig)
    }
}
