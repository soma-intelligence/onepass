//! The device's mailbox credential: an Ed25519 pair made on the device
//! (spec 4.7), distinct from the rotation v2 device keys.

use std::fmt;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use onepass_mailbox_proto::{CredentialId, credential_id, hex};
use zeroize::Zeroizing;

use crate::MailboxError;

/// Public half of a mailbox credential. A type of its own, not an alias of
/// `[u8; 32]`, so a key cannot be passed where an id or a hash is expected.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialKey([u8; 32]);

impl CredentialKey {
    pub fn from_bytes(bytes: [u8; 32]) -> CredentialKey {
        CredentialKey(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `SHA-256("onepass/mailbox-credential-id/v1" || key)[..16]`.
    pub fn id(&self) -> CredentialId {
        credential_id(&self.0)
    }
}

impl fmt::Debug for CredentialKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialKey({})", hex(&self.0))
    }
}

/// The signing half. Not `Clone`; its `Debug` shows the id only. The seed
/// is what the app stores (`DeviceSecrets`, spec 6) and is wiped on drop.
pub struct Credential {
    seed: Zeroizing<[u8; 32]>,
    pair: Ed25519KeyPair,
    public: CredentialKey,
}

impl Credential {
    /// A fresh pair from the system's random source.
    pub fn generate() -> Result<Credential, MailboxError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(&mut seed[..]).map_err(|_| MailboxError::Malformed("random"))?;
        Credential::from_seed(&seed[..])
    }

    /// The pair of a stored 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Credential, MailboxError> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| MailboxError::Malformed("seed length"))?;
        let seed = Zeroizing::new(seed);
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed[..])
            .map_err(|_| MailboxError::Malformed("seed"))?;
        let public: [u8; 32] = pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| MailboxError::Malformed("public key"))?;
        Ok(Credential {
            seed,
            pair,
            public: CredentialKey(public),
        })
    }

    /// A copy of the seed, wiped when dropped, for the app to store.
    pub fn seed(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.seed.to_vec())
    }

    pub fn public_key(&self) -> CredentialKey {
        self.public
    }

    pub fn id(&self) -> CredentialId {
        self.public.id()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.pair.sign(msg).as_ref());
        out
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &hex(&self.id()))
            .finish_non_exhaustive()
    }
}
