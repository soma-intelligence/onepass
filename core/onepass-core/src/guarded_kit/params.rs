//! The guard as the account carries it (spec 7.3 and 8): `GuardParams`
//! inside the signed account parameters, and how an unlock gets `G`.
//!
//! - `descriptor`: the public part, sealed locator included (spec 7.3). It
//!   sits in the account parameters, so the identity signs it and it is
//!   written in the same transaction as the keyset it guards (spec 7.1
//!   step 5): no separate record, no torn write between the two.
//! - `keep_ct`: `G` and the clear locator, sealed under
//!   `HKDF(kem_secret, "onepass/guard/keep/v1")`, a key only an opened
//!   keyset gives. Every unlocked device (password, biometrics, pairing)
//!   finds `G` there to poll the realms, re-register or turn the guard off
//!   (spec 7.1 step 6, 8.3, 8.4); a kit holder without the keyset does
//!   not. A rotation makes a new keyset and a new `G` (spec 8.2).
//!
//! An unlock with the password needs `G` before the keyset opens: from the
//! device (`GuardAccess::Secret`, kept from an earlier unlock) or from the
//! realms (`GuardAccess::Realms`, a restore, spec 7.2).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::descriptor::{GuardDescriptor, Locator, realm_set_hash};
use super::{GuardError, GuardSecret, RealmInfo, RealmTransport, restore};
use crate::Id;
use crate::crypto::key::hkdf32;
use crate::crypto::{Aad, BlobKind, HybridKemSecret, SecretKey, SymmetricKey, open, seal};

const KEEP_INFO: &[u8] = b"onepass/guard/keep/v1";
const KEEP_SCHEMA: u16 = 1;

/// The guard in the signed account parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardParams {
    pub descriptor: GuardDescriptor,
    /// `G` and the locator for the devices (module doc).
    #[serde(with = "serde_bytes")]
    pub keep_ct: Vec<u8>,
}

/// How an unlock with the password gets `G` on a guarded account.
#[derive(Clone, Copy)]
pub enum GuardAccess<'a> {
    /// None: a guarded account refuses with `GuardError::Required`.
    None,
    /// The device kept `G` (secure storage).
    Secret(&'a GuardSecret),
    /// Ask the realms (spec 7.2): needs the Secret Key to open the locator,
    /// and spends one attempt at T realms.
    Realms {
        transport: &'a dyn RealmTransport,
        pinned: &'a [RealmInfo],
    },
}

/// What the settings screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardState {
    Off,
    On {
        version: u32,
        threshold: u8,
        realms: u8,
        /// The guard was registered at the realms this build pins. False
        /// after a realm list change in a release: re-register (spec 8.3).
        realm_set_current: bool,
    },
}

#[derive(Serialize, Deserialize)]
struct Kept {
    #[serde(with = "serde_bytes")]
    guard: Vec<u8>,
    locator: Locator,
}

fn keep_key(kem: &HybridKemSecret) -> Result<SymmetricKey, GuardError> {
    hkdf32(&[], &kem.to_bytes(), &[KEEP_INFO]).map_err(|_| GuardError::Crypto)
}

fn keep_aad(account_id: Id, version: u32) -> Aad {
    let mut v = [0u8; 16];
    v[12..].copy_from_slice(&version.to_be_bytes());
    Aad {
        blob_id: account_id,
        vault_id: Some(Id(v)),
        schema: KEEP_SCHEMA,
    }
}

impl GuardParams {
    /// Build the parameters of a guard just registered.
    pub fn new(
        descriptor: GuardDescriptor,
        guard: &GuardSecret,
        locator: &Locator,
        kem: &HybridKemSecret,
    ) -> Result<GuardParams, GuardError> {
        let kept = Kept {
            guard: guard.expose().to_vec(),
            locator: locator.clone(),
        };
        let plain = Zeroizing::new(
            postcard::to_allocvec(&kept).map_err(|_| GuardError::Malformed("kept guard"))?,
        );
        let keep_ct = seal(
            &keep_key(kem)?,
            BlobKind::GuardKeep,
            &keep_aad(descriptor.account_id, descriptor.version),
            &plain,
        )
        .map_err(|_| GuardError::Crypto)?;
        Ok(GuardParams {
            descriptor,
            keep_ct,
        })
    }

    /// `G` and the locator, with the account's KEM secret.
    pub fn open_kept(&self, kem: &HybridKemSecret) -> Result<(GuardSecret, Locator), GuardError> {
        let plain = Zeroizing::new(
            open(
                &keep_key(kem)?,
                BlobKind::GuardKeep,
                &keep_aad(self.descriptor.account_id, self.descriptor.version),
                &self.keep_ct,
            )
            .map_err(|_| GuardError::LocatorRefused)?,
        );
        let kept: Kept =
            postcard::from_bytes(&plain).map_err(|_| GuardError::Malformed("kept guard"))?;
        let g: [u8; 32] = kept
            .guard
            .as_slice()
            .try_into()
            .map_err(|_| GuardError::Malformed("kept guard"))?;
        if kept.locator.version != self.descriptor.version
            || kept.locator.threshold != self.descriptor.threshold
        {
            return Err(GuardError::LocatorRefused);
        }
        Ok((GuardSecret::from_bytes(g), kept.locator))
    }

    /// The state for the settings screen, against the realms `pinned`.
    pub fn state(&self, pinned: &[RealmInfo]) -> GuardState {
        GuardState::On {
            version: self.descriptor.version,
            threshold: self.descriptor.threshold,
            realms: u8::try_from(pinned.len()).unwrap_or(u8::MAX),
            realm_set_current: !pinned.is_empty()
                && self.descriptor.realm_set_hash == realm_set_hash(pinned),
        }
    }
}

/// `G` for an unlock with the password: `x` is the guard input of the
/// stretched password (`crypto::guard_input`).
pub(crate) fn resolve(
    access: GuardAccess<'_>,
    params: &GuardParams,
    secret_key: &SecretKey,
    x: &[u8; 32],
) -> Result<GuardSecret, GuardError> {
    match access {
        GuardAccess::None => Err(GuardError::Required),
        GuardAccess::Secret(g) => Ok(GuardSecret::from_bytes(*g.expose())),
        GuardAccess::Realms { transport, pinned } => {
            let locator = params.descriptor.open_locator(secret_key)?;
            restore(transport, pinned, &locator, x)
        }
    }
}
