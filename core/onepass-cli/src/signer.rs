//! Local signatures of the account for `onepass-guard`: the signed MCP
//! policy and the audit log head.
//!
//! A signature is the postcard encoding of the core's `HybridSignature`,
//! made by `Repository::sign_local`, which binds the domain itself
//! (`b"local:" || domain`) as the `LocalSigner` contract requires.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

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

/// [`SharedSigner`] for a session shared between threads (`onepass
/// ssh-agent`). Like it, it takes no data directory lock.
pub struct SyncSigner(pub Arc<Mutex<LongSession>>);

impl LocalSigner for SyncSigner {
    fn sign(&self, domain: &[u8], msg: &[u8]) -> Result<Vec<u8>, GuardError> {
        // A poisoned lock (a panic mid-request) leaves the session suspect:
        // no signature from it, reported like any bad signature.
        let session = self.0.lock().map_err(|_| GuardError::Signature)?;
        sign(session.repo(), domain, msg)
    }

    fn verify(&self, domain: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), GuardError> {
        // Same mapping as `sign` for a poisoned lock.
        let session = self.0.lock().map_err(|_| GuardError::Signature)?;
        verify(session.repo(), domain, msg, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    use onepass_core::account::{Account, NewAccount};
    use onepass_core::crypto::{KdfParams, random_array};
    use onepass_core::repo::DeviceState;
    use onepass_core::store::{MemoryStore, Record, RecordKind};

    const PW: &str = "signer test pw";

    fn new_account() -> NewAccount {
        let kdf = KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: random_array().unwrap(),
        };
        Account::create_with_params(PW, kdf).unwrap()
    }

    /// Two accounts per test binary: SLH-DSA creation is slow in debug.
    fn accounts() -> &'static (NewAccount, NewAccount) {
        static A: OnceLock<(NewAccount, NewAccount)> = OnceLock::new();
        A.get_or_init(|| (new_account(), new_account()))
    }

    fn repo(n: &NewAccount) -> Repository<MemoryStore> {
        let id = n.account.params.account_id;
        let mut store = MemoryStore::new();
        for (kind, data) in [
            (RecordKind::AccountParams, &n.params_record),
            (RecordKind::Keyset, &n.keyset_record),
        ] {
            store
                .put(Record {
                    id,
                    kind,
                    version: 1,
                    data: data.clone(),
                })
                .unwrap();
        }
        Repository::unlock(store, PW, &n.secret_key, DeviceState::default()).unwrap()
    }

    #[test]
    fn roundtrip_and_refusals() {
        let (a, b) = accounts();
        let ra = repo(a);
        let rb = repo(b);
        let s = RepoSigner(&ra);
        let sig = s.sign(b"mcp-policy", b"payload").unwrap();
        assert_eq!(s.verify(b"mcp-policy", b"payload", &sig), Ok(()));
        // Wrong domain, wrong message.
        assert_eq!(
            s.verify(b"audit-head", b"payload", &sig),
            Err(GuardError::Signature)
        );
        assert_eq!(
            s.verify(b"mcp-policy", b"payloaD", &sig),
            Err(GuardError::Signature)
        );
        // Trailing bytes, truncation, garbage.
        let mut longer = sig.clone();
        longer.push(0);
        assert_eq!(
            s.verify(b"mcp-policy", b"payload", &longer),
            Err(GuardError::Signature)
        );
        assert_eq!(
            s.verify(b"mcp-policy", b"payload", &sig[..sig.len() - 1]),
            Err(GuardError::Signature)
        );
        assert_eq!(
            s.verify(b"mcp-policy", b"payload", b"junk"),
            Err(GuardError::Signature)
        );
        // A signature of another account is refused, both ways.
        let other = RepoSigner(&rb);
        assert_eq!(
            other.verify(b"mcp-policy", b"payload", &sig),
            Err(GuardError::Signature)
        );
        let sig_b = other.sign(b"mcp-policy", b"payload").unwrap();
        assert_eq!(
            s.verify(b"mcp-policy", b"payload", &sig_b),
            Err(GuardError::Signature)
        );
    }

    #[test]
    fn domains_do_not_collide_with_the_message() {
        // "ab" + "c" and "a" + "bc" must not share a signature.
        let (a, _) = accounts();
        let ra = repo(a);
        let s = RepoSigner(&ra);
        let sig = s.sign(b"ab", b"c").unwrap();
        assert_eq!(s.verify(b"a", b"bc", &sig), Err(GuardError::Signature));
    }
}
