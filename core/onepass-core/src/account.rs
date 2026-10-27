//! Account: creation, verified unlock, signed parameters and master
//! password change.
//!
//! The storage server is not trusted. `unlock` checks the parameters'
//! signature and, when the device pinned the account, its identity, KDF
//! floor and params epoch before any expensive derivation, then checks that
//! the decrypted keyset matches the signed public keys.
//!
//! Two record formats, both read:
//! - v1 (milestone 2): params are the plain postcard of `(account_id, kdf,
//!   identity_pub, signing_pub, kem_pub, identity_sig)`, signed under
//!   `b"account-params"`, epoch 0; the keyset is a bare blob (schema 1,
//!   blob id = account id).
//! - v2: params are `"OPP2" || postcard(account_id, kdf, identity_pub,
//!   signing_pub, kem_pub, epoch, identity_sig)` with `epoch >= 1`, the
//!   signature covering the epoch under `b"account-params/v2"`; the keyset
//!   is `"OPK2" || epoch (8 bytes, big endian) || params hash (32) || blob`,
//!   where the params hash is the SHA-256 of the params' signed message.
//!   The blob is sealed at schema 2 with the epoch XORed into the last 8
//!   bytes of its blob id and the first 16 bytes of the params hash in the
//!   context's vault id slot (a keyset has no vault).
//!   The clear epoch and hash let a torn fetch (params and keyset of two
//!   epochs, or of two different changes at the same epoch) fail as
//!   `IntegrityError::WrongContext` before any key is tried, instead of
//!   looking like a wrong password; the sealed context makes the clear
//!   header binding.
//!
//! Accounts created now write v2 at epoch 1. The epoch is the counter of
//! the signed params, bumped by every change of them (a master password
//! change today); a device pins the highest one it accepted
//! (`chain::ChainState::params_epoch`) and refuses older ones.

use std::fmt;

use aws_lc_rs::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;
use zeroize::Zeroizing;

use crate::crypto::aead::{OpenStage, open_detailed};
use crate::crypto::{
    Aad, BlobKind, DEV_KDF_FLOOR, HybridKemPublic, HybridKemSecret, HybridSigningKey,
    HybridVerifyingKey, IdentityKey, IdentitySignature, IdentityVerifyingKey, KDF_FLOOR, KdfParams,
    SecretKey, SymmetricKey, derive_auk, seal,
};
use crate::{Error, Id, IntegrityError, Result};

/// Signature domain of the v1 account parameters.
const PARAMS_DOMAIN: &[u8] = b"account-params";
/// Signature domain of the v2 account parameters.
const PARAMS_DOMAIN_V2: &[u8] = b"account-params/v2";
/// Prefix of a v2 params record.
const PARAMS_V2_PREFIX: &[u8; 4] = b"OPP2";
/// Schema version bound into a v1 keyset blob.
const KEYSET_SCHEMA: u16 = 1;
/// Schema version bound into a v2 keyset blob.
const KEYSET_SCHEMA_V2: u16 = 2;
/// Prefix of a v2 keyset record, followed by the big-endian epoch and the
/// params hash.
const KEYSET_V2_PREFIX: &[u8; 4] = b"OPK2";
/// Bytes before the blob in a v2 keyset record: prefix, epoch, params hash.
const KEYSET_V2_HEADER: usize = 44;
/// Largest accepted Argon2id cost as `(m_kib, t, p)`: 2 GiB, 16 passes, 16
/// lanes. Parameters come from the server, so they are bounded before Argon2
/// runs.
const KDF_CEILING: (u32, u32, u32) = (2097152, 16, 16);
/// Largest postcard varint length prefix of a `u32`.
const MAX_VARINT: usize = 5;

/// Public account parameters, stored in clear (no secret). At epoch 0 (v1),
/// `identity_sig` signs the postcard encoding of `(account_id, kdf,
/// signing_pub, kem_pub)` under the domain `b"account-params"`; at epoch 1
/// and above (v2), of `(account_id, kdf, signing_pub, kem_pub, epoch)` under
/// `b"account-params/v2"`. Stored with `encode`, read with `decode` (see
/// the module doc for both layouts).
#[derive(Debug, Clone, PartialEq)]
pub struct AccountParams {
    pub account_id: Id,
    pub kdf: KdfParams,
    pub identity_pub: IdentityVerifyingKey,
    pub signing_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
    pub identity_sig: IdentitySignature,
    /// The params epoch: 0 for a v1 record, then 1 at creation, plus one at
    /// each change of the signed params (master password change). Signed;
    /// a device refuses an epoch below the one it pinned.
    pub epoch: u64,
}

/// The account's secret keys.
pub struct Keyset {
    pub kem: HybridKemSecret,
    pub signing: HybridSigningKey,
    pub identity: IdentityKey,
}

impl fmt::Debug for Keyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keyset(**)")
    }
}

/// An unlocked account.
#[derive(Debug)]
pub struct Account {
    pub params: AccountParams,
    keyset: Keyset,
}

/// A freshly created account with the records to store and the Secret Key to
/// show the user once.
#[derive(Debug)]
pub struct NewAccount {
    pub account: Account,
    pub secret_key: SecretKey,
    pub params_record: Vec<u8>,
    pub keyset_record: Vec<u8>,
}

/// A master password change ready to be written (`Account::rekey`): the
/// account under its new params, the new Account Unlock Key and both
/// records.
pub(crate) struct Rekeyed {
    pub(crate) account: Account,
    pub(crate) auk: Auk,
    pub(crate) params_record: Vec<u8>,
    pub(crate) keyset_record: Vec<u8>,
}

/// What the device remembered about the account at first sign-in. The KDF
/// floor is raised after every successful unlock (`raise_floor`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PinnedAccount {
    pub account_id: Id,
    pub identity_pub: IdentityVerifyingKey,
    pub kdf_floor: KdfParams,
}

impl PinnedAccount {
    /// Raise the floor to the componentwise maximum of itself and the
    /// parameters just accepted (their salt is kept), so that once stronger
    /// parameters were seen, an older, weaker signed set is refused.
    pub fn raise_floor(&mut self, accepted: &KdfParams) {
        let f = &mut self.kdf_floor;
        f.m_kib = f.m_kib.max(accepted.m_kib);
        f.t = f.t.max(accepted.t);
        f.p = f.p.max(accepted.p);
        f.salt = accepted.salt;
    }
}

/// The floor for a build: `DEV_KDF_FLOOR` in a dev build, else `KDF_FLOOR`.
fn floor_for(dev: bool) -> (u32, u32, u32) {
    if dev { DEV_KDF_FLOOR } else { KDF_FLOOR }
}

/// The floor every unlock and every creation enforces. The dev floor needs
/// `cfg(test)`, or the `dev-fast-kdf` feature together with debug
/// assertions: a release build always enforces `KDF_FLOOR`.
fn enforced_floor() -> (u32, u32, u32) {
    floor_for(cfg!(any(
        test,
        all(feature = "dev-fast-kdf", debug_assertions)
    )))
}

fn above_floor(kdf: &KdfParams) -> bool {
    let (m_kib, t, p) = enforced_floor();
    kdf.m_kib >= m_kib && kdf.t >= t && kdf.p >= p
}

impl Account {
    pub fn keyset(&self) -> &Keyset {
        &self.keyset
    }

    /// Create an account with the default (floor) KDF parameters.
    pub fn create(password: &str) -> Result<NewAccount> {
        Self::create_with_params(password, KdfParams::new_default()?)
    }

    /// Create an account with explicit KDF parameters (fast ones in tests).
    ///
    /// Errors: parameters above the KDF ceiling or below the enforced floor
    /// give `InvalidFormat("kdf params")`, since such an account could not
    /// unlock.
    pub fn create_with_params(password: &str, kdf: KdfParams) -> Result<NewAccount> {
        if !within_ceiling(&kdf) || !above_floor(&kdf) {
            return Err(Error::InvalidFormat("kdf params"));
        }
        let account_id = Id::new();
        let secret_key = SecretKey::generate()?;
        let keyset = Keyset {
            kem: HybridKemSecret::generate()?,
            signing: HybridSigningKey::generate()?,
            identity: IdentityKey::generate()?,
        };
        let params = sign_params(
            account_id,
            kdf,
            keyset.signing.verifying_key()?,
            keyset.kem.public()?,
            1,
            &keyset.identity,
        )?;
        let auk = derive_auk(password, &secret_key, &params.kdf)?;
        let keyset_record = seal_keyset(&auk, &params, &keyset)?;
        let params_record = params.encode()?;
        Ok(NewAccount {
            account: Account { params, keyset },
            secret_key,
            params_record,
            keyset_record,
        })
    }

    /// Unlock from stored records, which may come from a hostile server.
    ///
    /// Checks, in order:
    /// 1. `params_record` decodes and `identity_sig` verifies under its own
    ///    `identity_pub`; with `pinned`, the account id and identity must match
    ///    the pinned ones. Otherwise `IntegrityError::ParamsUnsigned`.
    ///    (`unlock_exporting_auk_at` and `unlock_with_auk_at` also refuse an
    ///    epoch below the pinned one: `IntegrityError::ParamsRollback`.)
    /// 2. With `pinned`, the KDF parameters are at least the pinned floor,
    ///    and with or without it, at least the enforced floor (`KDF_FLOOR`,
    ///    or `DEV_KDF_FLOOR` in a dev build), otherwise
    ///    `IntegrityError::ParamsDowngrade`.
    /// 3. The KDF parameters are within the ceiling, otherwise
    ///    `InvalidFormat("kdf params")`. Then the AUK is derived and the
    ///    keyset blob opened.
    /// 4. The keyset record's epoch must be the params' one (a v1 keyset
    ///    goes with v1 params only), otherwise `IntegrityError::WrongContext`
    ///    (a torn fetch, not a wrong password). A key commitment mismatch on
    ///    a well-formed blob is
    ///    `Error::WrongPassword`. Any other blob failure keeps its own error:
    ///    a damaged ciphertext under a valid commitment is
    ///    `IntegrityError::Aead`, a malformed header its format error.
    /// 5. The keyset's public keys must equal the signed ones, otherwise
    ///    `IntegrityError::Signature`.
    ///
    /// An undecodable `params_record` is `InvalidFormat("account params")`,
    /// an undecodable keyset record or plaintext `InvalidFormat("keyset")`.
    pub fn unlock(
        password: &str,
        secret_key: &SecretKey,
        params_record: &[u8],
        keyset_record: &[u8],
        pinned: Option<&PinnedAccount>,
    ) -> Result<Account> {
        Ok(Self::unlock_exporting_auk_at(
            password,
            secret_key,
            params_record,
            keyset_record,
            pinned,
            0,
        )?
        .0)
    }

    /// Like `unlock`, and also hand back the derived Account Unlock Key, so
    /// that a device can keep it (in the Keychain, behind biometrics) and
    /// reopen the account later without the password and Secret Key.
    pub fn unlock_exporting_auk(
        password: &str,
        secret_key: &SecretKey,
        params_record: &[u8],
        keyset_record: &[u8],
        pinned: Option<&PinnedAccount>,
    ) -> Result<(Account, Auk)> {
        Self::unlock_exporting_auk_at(
            password,
            secret_key,
            params_record,
            keyset_record,
            pinned,
            0,
        )
    }

    /// `unlock_exporting_auk` on a device that pinned params epoch
    /// `min_epoch`: params with a lower epoch are refused
    /// (`IntegrityError::ParamsRollback`) before any derivation.
    pub fn unlock_exporting_auk_at(
        password: &str,
        secret_key: &SecretKey,
        params_record: &[u8],
        keyset_record: &[u8],
        pinned: Option<&PinnedAccount>,
        min_epoch: u64,
    ) -> Result<(Account, Auk)> {
        let params = verify_params(params_record, pinned, min_epoch)?;
        let key = derive_auk(password, secret_key, &params.kdf)?;
        let auk = Auk::from_bytes(*key.expose());
        let account = open_keyset(&key, params, keyset_record)?;
        Ok((account, auk))
    }

    /// Unlock with an Account Unlock Key kept from an earlier unlock. The
    /// same checks as `unlock` apply, in the same order (steps 1 to 5), only
    /// the derivation is skipped. A key that does not open the keyset is
    /// `Error::WrongPassword`.
    pub fn unlock_with_auk(
        auk: &Auk,
        params_record: &[u8],
        keyset_record: &[u8],
        pinned: Option<&PinnedAccount>,
    ) -> Result<Account> {
        Self::unlock_with_auk_at(auk, params_record, keyset_record, pinned, 0)
    }

    /// `unlock_with_auk` on a device that pinned params epoch `min_epoch`
    /// (see `unlock_exporting_auk_at`).
    pub fn unlock_with_auk_at(
        auk: &Auk,
        params_record: &[u8],
        keyset_record: &[u8],
        pinned: Option<&PinnedAccount>,
        min_epoch: u64,
    ) -> Result<Account> {
        let params = verify_params(params_record, pinned, min_epoch)?;
        open_keyset(
            &SymmetricKey::from_bytes(*auk.as_bytes()),
            params,
            keyset_record,
        )
    }

    /// The same keys under a new master password: fresh salt, each Argon2id
    /// cost the maximum of the current one and the enforced floor, v2 params
    /// at the next epoch signed by the identity key, and the keyset resealed
    /// at that epoch under the new Account Unlock Key. The caller checked the
    /// current password (by opening `self` from the stored records).
    ///
    /// Errors: an epoch at `u64::MAX` is `InvalidFormat("account params")`.
    pub(crate) fn rekey(self, secret_key: &SecretKey, new_password: &str) -> Result<Rekeyed> {
        let current = &self.params;
        let (m_kib, t, p) = enforced_floor();
        let kdf = KdfParams {
            m_kib: current.kdf.m_kib.max(m_kib),
            t: current.kdf.t.max(t),
            p: current.kdf.p.max(p),
            salt: KdfParams::new_default()?.salt,
        };
        if !within_ceiling(&kdf) {
            return Err(Error::InvalidFormat("kdf params"));
        }
        let epoch = current
            .epoch
            .checked_add(1)
            .ok_or(Error::InvalidFormat("account params"))?;
        let params = sign_params(
            current.account_id,
            kdf,
            current.signing_pub.clone(),
            current.kem_pub.clone(),
            epoch,
            &self.keyset.identity,
        )?;
        let key = derive_auk(new_password, secret_key, &params.kdf)?;
        let keyset_record = seal_keyset(&key, &params, &self.keyset)?;
        let params_record = params.encode()?;
        // Prove the new pair opens before anything is written.
        let account = open_keyset(&key, params, &keyset_record)?;
        Ok(Rekeyed {
            account,
            auk: Auk::from_bytes(*key.expose()),
            params_record,
            keyset_record,
        })
    }
}

/// The Account Unlock Key: what `derive_auk` yields from the password and
/// the Secret Key. Whoever holds it can open the account, so it is wiped on
/// drop and never printed.
pub struct Auk(Zeroizing<[u8; 32]>);

impl Auk {
    pub fn from_bytes(b: [u8; 32]) -> Auk {
        Auk(Zeroizing::new(b))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Auk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Auk(**)")
    }
}

/// Step 1 of `Account::unlock`: `params_record` decodes and its
/// `identity_sig` verifies under its own `identity_pub`, and with `pinned`
/// the account id and identity are the pinned ones (otherwise
/// `IntegrityError::ParamsUnsigned`). The signing key it carries is then
/// the account's, without any unlock (the sync store checks the signed vault
/// list with it).
pub(crate) fn signed_params(
    params_record: &[u8],
    pinned: Option<&PinnedAccount>,
) -> Result<AccountParams> {
    let params = AccountParams::decode(params_record)?;
    let unsigned = Error::Integrity(IntegrityError::ParamsUnsigned);
    let msg = signed_message(
        &params.account_id,
        &params.kdf,
        &params.signing_pub,
        &params.kem_pub,
        params.epoch,
    )?;
    params
        .identity_pub
        .verify(params_domain(params.epoch), &msg, &params.identity_sig)
        .map_err(|_| unsigned.clone())?;
    if let Some(pin) = pinned
        && (pin.account_id != params.account_id || pin.identity_pub != params.identity_pub)
    {
        return Err(unsigned);
    }
    Ok(params)
}

/// Steps 1 to 3 of `Account::unlock`, before any derivation: decode and
/// verify the signed parameters, check the pin, the pinned epoch, the floors
/// and the ceiling.
fn verify_params(
    params_record: &[u8],
    pinned: Option<&PinnedAccount>,
    min_epoch: u64,
) -> Result<AccountParams> {
    let params = signed_params(params_record, pinned)?;
    // An older epoch than the one this device accepted: a replay of signed
    // params the account has since replaced.
    if params.epoch < min_epoch {
        return Err(IntegrityError::ParamsRollback.into());
    }
    if let Some(pin) = pinned
        && !params.kdf.is_at_least(&pin.kdf_floor)
    {
        return Err(IntegrityError::ParamsDowngrade.into());
    }
    if !above_floor(&params.kdf) {
        return Err(IntegrityError::ParamsDowngrade.into());
    }
    if !within_ceiling(&params.kdf) {
        return Err(Error::InvalidFormat("kdf params"));
    }
    Ok(params)
}

/// Steps 4 and 5 of `Account::unlock`: check the keyset record's epoch and
/// params hash against the params, open the keyset blob under `auk` and
/// check it against the signed public keys.
fn open_keyset(auk: &SymmetricKey, params: AccountParams, keyset_record: &[u8]) -> Result<Account> {
    let (bound, blob) = split_keyset(keyset_record)?;
    let aad = keyset_aad(&params)?;
    let expected = match aad.vault_id {
        None => None,
        Some(_) => Some((params.epoch, params_hash(&params)?)),
    };
    if bound != expected {
        return Err(IntegrityError::WrongContext.into());
    }
    let plaintext =
        open_detailed(auk, BlobKind::Keyset, &aad, blob).map_err(|(stage, e)| match stage {
            OpenStage::Commitment => Error::WrongPassword,
            _ => e,
        })?;
    let keyset = decode_keyset(&plaintext)?;

    if keyset.kem.public()? != params.kem_pub
        || keyset.signing.verifying_key()? != params.signing_pub
        || keyset.identity.verifying_key() != params.identity_pub
    {
        return Err(IntegrityError::Signature.into());
    }
    Ok(Account { params, keyset })
}

fn within_ceiling(kdf: &KdfParams) -> bool {
    let (m_kib, t, p) = KDF_CEILING;
    kdf.m_kib <= m_kib && kdf.t <= t && kdf.p <= p
}

fn params_domain(epoch: u64) -> &'static [u8] {
    if epoch == 0 {
        PARAMS_DOMAIN
    } else {
        PARAMS_DOMAIN_V2
    }
}

/// Canonical postcard encoding of the signed fields: without the epoch at
/// epoch 0 (v1), with it from epoch 1 (v2).
fn signed_message(
    account_id: &Id,
    kdf: &KdfParams,
    signing_pub: &HybridVerifyingKey,
    kem_pub: &HybridKemPublic,
    epoch: u64,
) -> Result<Vec<u8>> {
    if epoch == 0 {
        postcard::to_allocvec(&(account_id, kdf, signing_pub, kem_pub))
    } else {
        postcard::to_allocvec(&(account_id, kdf, signing_pub, kem_pub, epoch))
    }
    .map_err(|_| Error::InvalidFormat("account params"))
}

fn sign_params(
    account_id: Id,
    kdf: KdfParams,
    signing_pub: HybridVerifyingKey,
    kem_pub: HybridKemPublic,
    epoch: u64,
    identity: &IdentityKey,
) -> Result<AccountParams> {
    let msg = signed_message(&account_id, &kdf, &signing_pub, &kem_pub, epoch)?;
    let identity_sig = identity.sign(params_domain(epoch), &msg)?;
    Ok(AccountParams {
        account_id,
        kdf,
        identity_pub: identity.verifying_key(),
        signing_pub,
        kem_pub,
        identity_sig,
        epoch,
    })
}

/// The v1 record layout: the six fields in order, no epoch.
type ParamsV1 = (
    Id,
    KdfParams,
    IdentityVerifyingKey,
    HybridVerifyingKey,
    HybridKemPublic,
    IdentitySignature,
);

/// The v2 record layout after the prefix: the epoch before the signature.
type ParamsV2 = (
    Id,
    KdfParams,
    IdentityVerifyingKey,
    HybridVerifyingKey,
    HybridKemPublic,
    u64,
    IdentitySignature,
);

impl AccountParams {
    /// The stored record: v1 at epoch 0, v2 (`"OPP2"` prefix) from epoch 1.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bad = |_| Error::InvalidFormat("account params");
        if self.epoch == 0 {
            return postcard::to_allocvec(&(
                &self.account_id,
                &self.kdf,
                &self.identity_pub,
                &self.signing_pub,
                &self.kem_pub,
                &self.identity_sig,
            ))
            .map_err(bad);
        }
        postcard::to_extend(
            &(
                &self.account_id,
                &self.kdf,
                &self.identity_pub,
                &self.signing_pub,
                &self.kem_pub,
                self.epoch,
                &self.identity_sig,
            ),
            PARAMS_V2_PREFIX.to_vec(),
        )
        .map_err(bad)
    }

    /// Decode a stored params record, which may come from a hostile store:
    /// the whole buffer, trailing bytes refused, and a v2 record must carry
    /// an epoch of at least 1 (`InvalidFormat("account params")`). Nothing
    /// is verified here; see `Account::unlock`.
    ///
    /// A record that starts with `"OPP2"` but does not decode as v2 is tried
    /// as v1: a v1 record starts with the account id, which could begin with
    /// those four bytes.
    pub fn decode(record: &[u8]) -> Result<AccountParams> {
        if let Some(body) = record.strip_prefix(PARAMS_V2_PREFIX)
            && let Ok((
                (account_id, kdf, identity_pub, signing_pub, kem_pub, epoch, identity_sig),
                [],
            )) = postcard::take_from_bytes::<ParamsV2>(body)
            && epoch >= 1
        {
            return Ok(AccountParams {
                account_id,
                kdf,
                identity_pub,
                signing_pub,
                kem_pub,
                identity_sig,
                epoch,
            });
        }
        match postcard::take_from_bytes::<ParamsV1>(record) {
            Ok(((account_id, kdf, identity_pub, signing_pub, kem_pub, identity_sig), [])) => {
                Ok(AccountParams {
                    account_id,
                    kdf,
                    identity_pub,
                    signing_pub,
                    kem_pub,
                    identity_sig,
                    epoch: 0,
                })
            }
            _ => Err(Error::InvalidFormat("account params")),
        }
    }
}

/// SHA-256 of the params' signed message: binds a v2 keyset to these exact
/// params (epoch, KDF and salt, public keys).
fn params_hash(params: &AccountParams) -> Result<[u8; 32]> {
    let msg = signed_message(
        &params.account_id,
        &params.kdf,
        &params.signing_pub,
        &params.kem_pub,
        params.epoch,
    )?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, &msg).as_ref());
    Ok(out)
}

/// The context a keyset blob is sealed to: at epoch 0 (v1), schema 1 and the
/// account id; from epoch 1 (v2), schema 2, the account id with the
/// big-endian epoch XORed into its last 8 bytes, and the first 16 bytes of
/// the params hash in the vault id slot.
fn keyset_aad(params: &AccountParams) -> Result<Aad> {
    if params.epoch == 0 {
        return Ok(Aad {
            blob_id: params.account_id,
            vault_id: None,
            schema: KEYSET_SCHEMA,
        });
    }
    let mut blob_id = params.account_id;
    for (b, e) in blob_id.0[8..].iter_mut().zip(params.epoch.to_be_bytes()) {
        *b ^= e;
    }
    let mut bound = [0u8; 16];
    bound.copy_from_slice(&params_hash(params)?[..16]);
    Ok(Aad {
        blob_id,
        vault_id: Some(Id(bound)),
        schema: KEYSET_SCHEMA_V2,
    })
}

/// A keyset record's binding and blob: a v2 record is `"OPK2" || epoch_be ||
/// params hash || blob` with an epoch of at least 1, giving
/// `Some((epoch, hash))`; anything else is a v1 blob (`None`). A v2 header
/// that is cut short or carries epoch 0 is `InvalidFormat("keyset")`.
type KeysetBinding = Option<(u64, [u8; 32])>;

fn split_keyset(record: &[u8]) -> Result<(KeysetBinding, &[u8])> {
    if !record.starts_with(KEYSET_V2_PREFIX) {
        return Ok((None, record));
    }
    let bad = Error::InvalidFormat("keyset");
    let (header, blob) = record
        .split_at_checked(KEYSET_V2_HEADER)
        .ok_or(bad.clone())?;
    let mut be = [0u8; 8];
    be.copy_from_slice(&header[4..12]);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&header[12..KEYSET_V2_HEADER]);
    match u64::from_be_bytes(be) {
        0 => Err(bad),
        epoch => Ok((Some((epoch, hash)), blob)),
    }
}

/// Seal the postcard encoding of the three secret keys' bytes for `params`
/// (a v1 bare blob at epoch 0, a v2 record bound to the params above). The
/// plaintext is written into a buffer sized up front and wiped on drop.
fn seal_keyset(auk: &SymmetricKey, params: &AccountParams, keyset: &Keyset) -> Result<Vec<u8>> {
    let kem = keyset.kem.to_bytes();
    let signing = keyset.signing.to_bytes();
    let identity = keyset.identity.to_bytes();
    let mut buf = Zeroizing::new(vec![
        0u8;
        kem.len()
            + signing.len()
            + identity.len()
            + 3 * MAX_VARINT
    ]);
    let used = postcard::to_slice(
        &(
            Bytes::new(&kem),
            Bytes::new(&signing),
            Bytes::new(&identity),
        ),
        &mut buf[..],
    )
    .map_err(|_| Error::InvalidFormat("keyset"))?
    .len();
    let blob = seal(auk, BlobKind::Keyset, &keyset_aad(params)?, &buf[..used])?;
    if params.epoch == 0 {
        return Ok(blob);
    }
    let mut out = Vec::with_capacity(KEYSET_V2_HEADER + blob.len());
    out.extend_from_slice(KEYSET_V2_PREFIX);
    out.extend_from_slice(&params.epoch.to_be_bytes());
    out.extend_from_slice(&params_hash(params)?);
    out.extend_from_slice(&blob);
    Ok(out)
}

fn decode_keyset(plaintext: &[u8]) -> Result<Keyset> {
    let bad = Error::InvalidFormat("keyset");
    let (kem, signing, identity) =
        match postcard::take_from_bytes::<(&[u8], &[u8], &[u8])>(plaintext) {
            Ok((parts, [])) => parts,
            _ => return Err(bad),
        };
    Ok(Keyset {
        kem: HybridKemSecret::from_bytes(kem)?,
        signing: HybridSigningKey::from_bytes(signing)?,
        identity: IdentityKey::from_bytes(identity)?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::crypto::random_array;

    fn fast() -> KdfParams {
        KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: random_array().unwrap(),
        }
    }

    /// One account shared by the tests: identity signing is slow in debug.
    fn shared() -> &'static NewAccount {
        static N: OnceLock<NewAccount> = OnceLock::new();
        N.get_or_init(|| Account::create_with_params("pw", fast()).unwrap())
    }

    fn pin(n: &NewAccount) -> PinnedAccount {
        PinnedAccount {
            account_id: n.account.params.account_id,
            identity_pub: n.account.params.identity_pub.clone(),
            kdf_floor: n.account.params.kdf.clone(),
        }
    }

    #[test]
    fn create_then_unlock() {
        let n = shared();
        let a = Account::unlock(
            "pw",
            &n.secret_key,
            &n.params_record,
            &n.keyset_record,
            None,
        )
        .unwrap();
        assert_eq!(a.params.account_id, n.account.params.account_id);
        assert_eq!(a.params, n.account.params);
        // Pinned at the account's own floor: accepted too.
        let a = Account::unlock(
            "pw",
            &n.secret_key,
            &n.params_record,
            &n.keyset_record,
            Some(&pin(n)),
        )
        .unwrap();
        assert_eq!(
            a.keyset().identity.verifying_key(),
            n.account.params.identity_pub
        );
        assert_eq!(a.keyset().kem.public().unwrap(), n.account.params.kem_pub);
    }

    #[test]
    fn wrong_password_is_reported_as_such() {
        let n = shared();
        assert!(matches!(
            Account::unlock(
                "nope",
                &n.secret_key,
                &n.params_record,
                &n.keyset_record,
                None
            ),
            Err(Error::WrongPassword)
        ));
        let other = SecretKey::generate().unwrap();
        assert!(matches!(
            Account::unlock("pw", &other, &n.params_record, &n.keyset_record, None),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn corrupted_keyset_is_not_reported_as_wrong_password() {
        let n = shared();
        let mut ks = n.keyset_record.clone();
        let last = ks.len() - 1;
        ks[last] ^= 1;
        assert!(matches!(
            Account::unlock("pw", &n.secret_key, &n.params_record, &ks, None),
            Err(Error::Integrity(IntegrityError::Aead))
        ));
    }

    #[test]
    fn malformed_keyset_header_is_not_reported_as_wrong_password() {
        let n = shared();
        // The blob after the v2 keyset header.
        let at = KEYSET_V2_HEADER;
        let mut ks = n.keyset_record.clone();
        ks[at] ^= 1;
        assert_eq!(
            Account::unlock("nope", &n.secret_key, &n.params_record, &ks, None).unwrap_err(),
            Error::InvalidFormat("magic")
        );
        let mut ks = n.keyset_record.clone();
        ks[at + 5] = 2; // another blob kind
        assert_eq!(
            Account::unlock("nope", &n.secret_key, &n.params_record, &ks, None).unwrap_err(),
            Error::Integrity(IntegrityError::WrongKind)
        );
    }

    #[test]
    fn downgraded_kdf_params_are_refused() {
        let n = shared();
        let pinned = PinnedAccount {
            kdf_floor: KdfParams {
                m_kib: 16384,
                ..fast()
            },
            ..pin(n)
        };
        assert!(matches!(
            Account::unlock(
                "pw",
                &n.secret_key,
                &n.params_record,
                &n.keyset_record,
                Some(&pinned)
            ),
            Err(Error::Integrity(IntegrityError::ParamsDowngrade))
        ));
    }

    #[test]
    fn params_signed_by_another_identity_are_refused() {
        let a = shared();
        let b = Account::create_with_params("pw", fast()).unwrap();
        assert!(matches!(
            Account::unlock(
                "pw",
                &b.secret_key,
                &b.params_record,
                &b.keyset_record,
                Some(&pin(a))
            ),
            Err(Error::Integrity(IntegrityError::ParamsUnsigned))
        ));
        // Same identity, another account id: refused too.
        let pinned = PinnedAccount {
            account_id: Id::new(),
            ..pin(a)
        };
        assert!(matches!(
            Account::unlock(
                "pw",
                &a.secret_key,
                &a.params_record,
                &a.keyset_record,
                Some(&pinned)
            ),
            Err(Error::Integrity(IntegrityError::ParamsUnsigned))
        ));
    }

    #[test]
    fn tampered_params_are_refused_without_a_pin() {
        let n = shared();
        let mut params = n.account.params.clone();
        params.kdf.t += 1;
        let record = params.encode().unwrap();
        assert!(matches!(
            Account::unlock("pw", &n.secret_key, &record, &n.keyset_record, None),
            Err(Error::Integrity(IntegrityError::ParamsUnsigned))
        ));
    }

    #[test]
    fn params_record_must_decode_exactly() {
        let n = shared();
        let mut record = n.params_record.clone();
        record.push(0);
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &record, &n.keyset_record, None).unwrap_err(),
            Error::InvalidFormat("account params")
        );
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &[1, 2, 3], &n.keyset_record, None).unwrap_err(),
            Error::InvalidFormat("account params")
        );
    }

    #[test]
    fn kdf_ceiling_bounds_each_cost() {
        let ok = KdfParams {
            m_kib: KDF_CEILING.0,
            t: KDF_CEILING.1,
            p: KDF_CEILING.2,
            salt: [0; 32],
        };
        assert!(within_ceiling(&ok));
        assert!(!within_ceiling(&KdfParams {
            m_kib: KDF_CEILING.0 + 1,
            ..ok.clone()
        }));
        assert!(!within_ceiling(&KdfParams {
            t: KDF_CEILING.1 + 1,
            ..ok.clone()
        }));
        assert!(!within_ceiling(&KdfParams {
            p: KDF_CEILING.2 + 1,
            ..ok.clone()
        }));
    }

    #[test]
    fn signed_params_above_the_kdf_ceiling_are_refused_before_argon2() {
        let n = shared();
        let p = &n.account.params;
        let kdf = KdfParams {
            m_kib: u32::MAX,
            ..p.kdf.clone()
        };
        let params = sign_params(
            p.account_id,
            kdf,
            p.signing_pub.clone(),
            p.kem_pub.clone(),
            p.epoch,
            &n.account.keyset().identity,
        )
        .unwrap();
        let record = params.encode().unwrap();
        // Argon2 at 4 TiB would fail or hang; the ceiling answers first.
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &record, &n.keyset_record, None).unwrap_err(),
            Error::InvalidFormat("kdf params")
        );
        // Creation refuses such parameters too, before any key generation.
        assert_eq!(
            Account::create_with_params(
                "pw",
                KdfParams {
                    t: KDF_CEILING.1 + 1,
                    ..fast()
                }
            )
            .unwrap_err(),
            Error::InvalidFormat("kdf params")
        );
    }

    #[test]
    fn the_floor_is_the_spec_floor_outside_dev_builds() {
        assert_eq!(floor_for(false), KDF_FLOOR);
        assert_eq!(floor_for(true), DEV_KDF_FLOOR);
        // Unit tests run with the dev floor.
        assert_eq!(enforced_floor(), DEV_KDF_FLOOR);
    }

    #[test]
    fn signed_params_below_the_floor_are_refused_without_a_pin() {
        let n = shared();
        let p = &n.account.params;
        let weak = KdfParams {
            m_kib: DEV_KDF_FLOOR.0 / 2,
            ..p.kdf.clone()
        };
        let params = sign_params(
            p.account_id,
            weak.clone(),
            p.signing_pub.clone(),
            p.kem_pub.clone(),
            p.epoch,
            &n.account.keyset().identity,
        )
        .unwrap();
        let record = params.encode().unwrap();
        // Validly signed, first unlock on this device: the floor still holds.
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &record, &n.keyset_record, None).unwrap_err(),
            Error::Integrity(IntegrityError::ParamsDowngrade)
        );
        assert_eq!(
            Account::create_with_params("pw", weak).unwrap_err(),
            Error::InvalidFormat("kdf params")
        );
    }

    #[test]
    fn raise_floor_takes_the_componentwise_max() {
        let mut pin = pin(shared());
        pin.kdf_floor = KdfParams {
            m_kib: 4096,
            t: 3,
            p: 1,
            salt: [7; 32],
        };
        let accepted = KdfParams {
            m_kib: 8192,
            t: 1,
            p: 2,
            salt: [9; 32],
        };
        pin.raise_floor(&accepted);
        assert_eq!(
            pin.kdf_floor,
            KdfParams {
                m_kib: 8192,
                t: 3,
                p: 2,
                salt: [9; 32],
            }
        );
    }

    #[test]
    fn keyset_that_does_not_match_the_params_is_refused() {
        let n = shared();
        let ks = n.account.keyset();
        let swapped = Keyset {
            kem: HybridKemSecret::generate().unwrap(),
            signing: HybridSigningKey::from_bytes(&ks.signing.to_bytes()).unwrap(),
            identity: IdentityKey::from_bytes(&ks.identity.to_bytes()).unwrap(),
        };
        let auk = derive_auk("pw", &n.secret_key, &n.account.params.kdf).unwrap();
        let record = seal_keyset(&auk, &n.account.params, &swapped).unwrap();
        assert!(matches!(
            Account::unlock("pw", &n.secret_key, &n.params_record, &record, None),
            Err(Error::Integrity(IntegrityError::Signature))
        ));
    }

    #[test]
    fn keyset_debug_is_redacted() {
        let n = shared();
        assert_eq!(format!("{:?}", n.account.keyset()), "Keyset(**)");
        assert!(!format!("{n:?}").contains(&n.secret_key.to_display()));
    }

    #[test]
    fn unlock_with_auk_matches_password_unlock() {
        let n = shared();
        let (a, auk) = Account::unlock_exporting_auk(
            "pw",
            &n.secret_key,
            &n.params_record,
            &n.keyset_record,
            None,
        )
        .unwrap();
        let b = Account::unlock_with_auk(&auk, &n.params_record, &n.keyset_record, None).unwrap();
        assert_eq!(a.params, b.params);
        assert_eq!(b.params, n.account.params);
        assert_eq!(format!("{auk:?}"), "Auk(**)");
        let again = Auk::from_bytes(*auk.as_bytes());
        assert_eq!(again.as_bytes(), auk.as_bytes());
    }

    #[test]
    fn unlock_with_auk_rejects_wrong_auk() {
        let n = shared();
        let auk = Auk::from_bytes(random_array().unwrap());
        assert_eq!(
            Account::unlock_with_auk(&auk, &n.params_record, &n.keyset_record, None).unwrap_err(),
            Error::WrongPassword
        );
    }

    #[test]
    fn unlock_with_auk_checks_pin() {
        let n = shared();
        let (_, auk) = Account::unlock_exporting_auk(
            "pw",
            &n.secret_key,
            &n.params_record,
            &n.keyset_record,
            None,
        )
        .unwrap();
        let other = PinnedAccount {
            account_id: Id::new(),
            ..pin(n)
        };
        assert_eq!(
            Account::unlock_with_auk(&auk, &n.params_record, &n.keyset_record, Some(&other))
                .unwrap_err(),
            Error::Integrity(IntegrityError::ParamsUnsigned)
        );
    }

    #[test]
    fn unlock_with_auk_enforces_floor() {
        let n = shared();
        let p = &n.account.params;
        let weak = KdfParams {
            m_kib: DEV_KDF_FLOOR.0 / 2,
            ..p.kdf.clone()
        };
        let params = sign_params(
            p.account_id,
            weak,
            p.signing_pub.clone(),
            p.kem_pub.clone(),
            p.epoch,
            &n.account.keyset().identity,
        )
        .unwrap();
        let record = params.encode().unwrap();
        let auk = Auk::from_bytes([1u8; 32]);
        assert_eq!(
            Account::unlock_with_auk(&auk, &record, &n.keyset_record, None).unwrap_err(),
            Error::Integrity(IntegrityError::ParamsDowngrade)
        );
    }

    /// The shared account's keys as a milestone 2 client stored them: v1
    /// params (no prefix, epoch 0) and a schema-1 keyset.
    fn v1_records(n: &NewAccount) -> (Vec<u8>, Vec<u8>) {
        let p = &n.account.params;
        let params = sign_params(
            p.account_id,
            p.kdf.clone(),
            p.signing_pub.clone(),
            p.kem_pub.clone(),
            0,
            &n.account.keyset().identity,
        )
        .unwrap();
        let auk = derive_auk("pw", &n.secret_key, &p.kdf).unwrap();
        let keyset = seal_keyset(&auk, &params, n.account.keyset()).unwrap();
        (params.encode().unwrap(), keyset)
    }

    /// The shared account's params re-signed at `epoch`, same KDF.
    fn params_at(n: &NewAccount, epoch: u64) -> Vec<u8> {
        let p = &n.account.params;
        sign_params(
            p.account_id,
            p.kdf.clone(),
            p.signing_pub.clone(),
            p.kem_pub.clone(),
            epoch,
            &n.account.keyset().identity,
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    #[test]
    fn params_v2_round_trip_and_signature() {
        let n = shared();
        // New accounts write v2 at epoch 1.
        assert!(n.params_record.starts_with(b"OPP2"));
        assert_eq!(n.account.params.epoch, 1);
        let decoded = AccountParams::decode(&n.params_record).unwrap();
        assert_eq!(decoded, n.account.params);
        assert_eq!(decoded.encode().unwrap(), n.params_record);
        assert!(n.keyset_record.starts_with(b"OPK2"));

        // The epoch is signed: changing it without re-signing is refused.
        let mut bumped = n.account.params.clone();
        bumped.epoch = 2;
        let record = bumped.encode().unwrap();
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &record, &n.keyset_record, None).unwrap_err(),
            Error::Integrity(IntegrityError::ParamsUnsigned)
        );
        // A v2 signature does not verify as a v1 one (other message, other
        // domain), so a v2 record cannot be rewritten as v1.
        let mut as_v1 = n.account.params.clone();
        as_v1.epoch = 0;
        let record = as_v1.encode().unwrap();
        assert!(!record.starts_with(b"OPP2"));
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &record, &n.keyset_record, None).unwrap_err(),
            Error::Integrity(IntegrityError::ParamsUnsigned)
        );
        // A v2 record never carries epoch 0 (that is v1).
        // Same fields, epoch 0 written in the v2 layout by hand.
        let mut zero = b"OPP2".to_vec();
        zero.extend(
            postcard::to_allocvec(&(
                &as_v1.account_id,
                &as_v1.kdf,
                &as_v1.identity_pub,
                &as_v1.signing_pub,
                &as_v1.kem_pub,
                0u64,
                &as_v1.identity_sig,
            ))
            .unwrap(),
        );
        assert_eq!(
            AccountParams::decode(&zero).unwrap_err(),
            Error::InvalidFormat("account params")
        );
        // Trailing bytes after a v2 record are refused.
        let mut long = n.params_record.clone();
        long.push(0);
        assert_eq!(
            AccountParams::decode(&long).unwrap_err(),
            Error::InvalidFormat("account params")
        );
    }

    #[test]
    fn v1_params_still_unlock() {
        let n = shared();
        let (params, keyset) = v1_records(n);
        // The milestone 2 layout: plain postcard of the six fields.
        assert!(!params.starts_with(b"OPP2"));
        let p = &n.account.params;
        let v1 = AccountParams::decode(&params).unwrap();
        assert_eq!(v1.epoch, 0);
        assert_eq!(
            params,
            postcard::to_allocvec(&(
                &p.account_id,
                &p.kdf,
                &p.identity_pub,
                &p.signing_pub,
                &p.kem_pub,
                &v1.identity_sig,
            ))
            .unwrap()
        );
        assert!(keyset.starts_with(b"OPB"));
        let a = Account::unlock("pw", &n.secret_key, &params, &keyset, Some(&pin(n))).unwrap();
        assert_eq!(a.params.epoch, 0);
        assert_eq!(a.params.kem_pub, p.kem_pub);
        let (_, auk) =
            Account::unlock_exporting_auk("pw", &n.secret_key, &params, &keyset, None).unwrap();
        Account::unlock_with_auk(&auk, &params, &keyset, None).unwrap();
        assert_eq!(
            Account::unlock("nope", &n.secret_key, &params, &keyset, None).unwrap_err(),
            Error::WrongPassword
        );
    }

    #[test]
    fn epoch_bound_into_keyset() {
        let n = shared();
        let wrong = Error::Integrity(IntegrityError::WrongContext);
        let (v1_params, v1_keyset) = v1_records(n);
        // v2 params with a schema-1 keyset: a torn fetch, not a bad password.
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &n.params_record, &v1_keyset, None).unwrap_err(),
            wrong
        );
        // v1 params with a v2 keyset.
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &v1_params, &n.keyset_record, None).unwrap_err(),
            wrong
        );
        // Params at epoch 2 with the keyset sealed for epoch 1.
        let epoch2 = params_at(n, 2);
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &epoch2, &n.keyset_record, None).unwrap_err(),
            wrong
        );
        let auk = Auk::from_bytes(
            *derive_auk("pw", &n.secret_key, &n.account.params.kdf)
                .unwrap()
                .expose(),
        );
        assert_eq!(
            Account::unlock_with_auk(&auk, &epoch2, &n.keyset_record, None).unwrap_err(),
            wrong
        );
        // Relabelling the keyset's clear epoch does not help: the epoch is
        // in the sealed context too, and the blob does not open.
        let mut relabelled = n.keyset_record.clone();
        relabelled[4..12].copy_from_slice(&2u64.to_be_bytes());
        let hash = params_hash(&AccountParams::decode(&epoch2).unwrap()).unwrap();
        relabelled[12..KEYSET_V2_HEADER].copy_from_slice(&hash);
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &epoch2, &relabelled, None).unwrap_err(),
            Error::WrongPassword
        );
        // A truncated or zero-epoch v2 keyset header is malformed.
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &n.params_record, b"OPK2\0\0", None).unwrap_err(),
            Error::InvalidFormat("keyset")
        );
        let mut zero = n.keyset_record.clone();
        zero[4..12].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &n.params_record, &zero, None).unwrap_err(),
            Error::InvalidFormat("keyset")
        );
    }

    #[test]
    fn pinned_epoch_refuses_older_params() {
        let n = shared();
        let rollback = Error::Integrity(IntegrityError::ParamsRollback);
        // Epoch 1 accepted at a pin of 0 or 1.
        for min in [0, 1] {
            Account::unlock_exporting_auk_at(
                "pw",
                &n.secret_key,
                &n.params_record,
                &n.keyset_record,
                Some(&pin(n)),
                min,
            )
            .unwrap();
        }
        // Refused at a pin of 2, before any derivation: the password does
        // not matter.
        for pw in ["pw", "nope"] {
            assert_eq!(
                Account::unlock_exporting_auk_at(
                    pw,
                    &n.secret_key,
                    &n.params_record,
                    &n.keyset_record,
                    Some(&pin(n)),
                    2,
                )
                .unwrap_err(),
                rollback
            );
        }
        let auk = Auk::from_bytes([3; 32]);
        assert_eq!(
            Account::unlock_with_auk_at(&auk, &n.params_record, &n.keyset_record, None, 2)
                .unwrap_err(),
            rollback
        );
        // v1 params are epoch 0: refused once epoch 1 was seen.
        let (v1_params, v1_keyset) = v1_records(n);
        assert_eq!(
            Account::unlock_exporting_auk_at("pw", &n.secret_key, &v1_params, &v1_keyset, None, 1)
                .unwrap_err(),
            rollback
        );
    }

    #[test]
    fn same_epoch_mix_is_wrong_context() {
        let n = shared();
        let open = || {
            Account::unlock(
                "pw",
                &n.secret_key,
                &n.params_record,
                &n.keyset_record,
                None,
            )
            .unwrap()
        };
        // Two different changes from the same epoch: both at epoch 2.
        let a = open().rekey(&n.secret_key, "mot de passe A").unwrap();
        let b = open().rekey(&n.secret_key, "mot de passe B").unwrap();
        assert_eq!(a.account.params.epoch, 2);
        assert_eq!(b.account.params.epoch, 2);
        // Each pair opens with its own password.
        for (r, pw) in [(&a, "mot de passe A"), (&b, "mot de passe B")] {
            Account::unlock(pw, &n.secret_key, &r.params_record, &r.keyset_record, None).unwrap();
        }
        // A mix is a torn pair, never a wrong password, whichever password.
        for pw in ["mot de passe A", "mot de passe B", "pw"] {
            assert_eq!(
                Account::unlock(pw, &n.secret_key, &a.params_record, &b.keyset_record, None)
                    .unwrap_err(),
                Error::Integrity(IntegrityError::WrongContext)
            );
            assert_eq!(
                Account::unlock(pw, &n.secret_key, &b.params_record, &a.keyset_record, None)
                    .unwrap_err(),
                Error::Integrity(IntegrityError::WrongContext)
            );
        }
        // Relabelling the clear hash does not help: it is sealed too.
        let mut relabelled = b.keyset_record.clone();
        relabelled[12..KEYSET_V2_HEADER].copy_from_slice(&params_hash(&a.account.params).unwrap());
        assert_eq!(
            Account::unlock(
                "mot de passe B",
                &n.secret_key,
                &a.params_record,
                &relabelled,
                None
            )
            .unwrap_err(),
            Error::WrongPassword
        );
    }

    #[test]
    fn rekey_migrates_a_v1_account_to_v2() {
        let n = shared();
        let (v1_params, v1_keyset) = v1_records(n);
        let account = Account::unlock("pw", &n.secret_key, &v1_params, &v1_keyset, None).unwrap();
        assert_eq!(account.params.epoch, 0);
        let r = account.rekey(&n.secret_key, "nouveau").unwrap();
        assert_eq!(r.account.params.epoch, 1);
        assert!(r.params_record.starts_with(b"OPP2"));
        assert!(r.keyset_record.starts_with(b"OPK2"));
        let a = Account::unlock(
            "nouveau",
            &n.secret_key,
            &r.params_record,
            &r.keyset_record,
            None,
        )
        .unwrap();
        assert_eq!(a.params.kem_pub, n.account.params.kem_pub);
        // Old password with the new params: wrong password.
        assert_eq!(
            Account::unlock(
                "pw",
                &n.secret_key,
                &r.params_record,
                &r.keyset_record,
                None
            )
            .unwrap_err(),
            Error::WrongPassword
        );
        // Torn: new params with the v1 keyset, v1 params with the new keyset.
        assert_eq!(
            Account::unlock("nouveau", &n.secret_key, &r.params_record, &v1_keyset, None)
                .unwrap_err(),
            Error::Integrity(IntegrityError::WrongContext)
        );
        assert_eq!(
            Account::unlock("pw", &n.secret_key, &v1_params, &r.keyset_record, None).unwrap_err(),
            Error::Integrity(IntegrityError::WrongContext)
        );
        // A device that saw epoch 1 refuses the v1 params again.
        assert_eq!(
            Account::unlock_exporting_auk_at("pw", &n.secret_key, &v1_params, &v1_keyset, None, 1)
                .unwrap_err(),
            Error::Integrity(IntegrityError::ParamsRollback)
        );
    }
}
