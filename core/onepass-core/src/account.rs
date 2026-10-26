//! Account: creation, verified unlock and signed parameters.
//!
//! The storage server is not trusted. `unlock` checks the parameters'
//! signature and, when the device pinned the account, its identity and KDF
//! floor before any expensive derivation, then checks that the decrypted
//! keyset matches the signed public keys.

use std::fmt;

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

/// Signature domain of the account parameters.
const PARAMS_DOMAIN: &[u8] = b"account-params";
/// Schema version bound into the keyset blob.
const KEYSET_SCHEMA: u16 = 1;
/// Largest accepted Argon2id cost as `(m_kib, t, p)`: 2 GiB, 16 passes, 16
/// lanes. Parameters come from the server, so they are bounded before Argon2
/// runs.
const KDF_CEILING: (u32, u32, u32) = (2097152, 16, 16);
/// Largest postcard varint length prefix of a `u32`.
const MAX_VARINT: usize = 5;

/// Public account parameters, stored in clear (no secret). `identity_sig`
/// signs the postcard encoding of `(account_id, kdf, signing_pub, kem_pub)`
/// under the domain `b"account-params"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountParams {
    pub account_id: Id,
    pub kdf: KdfParams,
    pub identity_pub: IdentityVerifyingKey,
    pub signing_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
    pub identity_sig: IdentitySignature,
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
            &keyset.identity,
        )?;
        let auk = derive_auk(password, &secret_key, &params.kdf)?;
        let keyset_record = seal_keyset(&auk, account_id, &keyset)?;
        let params_record =
            postcard::to_allocvec(&params).map_err(|_| Error::InvalidFormat("account params"))?;
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
    /// 2. With `pinned`, the KDF parameters are at least the pinned floor,
    ///    and with or without it, at least the enforced floor (`KDF_FLOOR`,
    ///    or `DEV_KDF_FLOOR` in a dev build), otherwise
    ///    `IntegrityError::ParamsDowngrade`.
    /// 3. The KDF parameters are within the ceiling, otherwise
    ///    `InvalidFormat("kdf params")`. Then the AUK is derived and the
    ///    keyset blob opened.
    /// 4. A key commitment mismatch on a well-formed blob is
    ///    `Error::WrongPassword`. Any other blob failure keeps its own error:
    ///    a damaged ciphertext under a valid commitment is
    ///    `IntegrityError::Aead`, a malformed header its format error.
    /// 5. The keyset's public keys must equal the signed ones, otherwise
    ///    `IntegrityError::Signature`.
    ///
    /// An undecodable `params_record` is `InvalidFormat("account params")`,
    /// an undecodable keyset plaintext `InvalidFormat("keyset")`.
    pub fn unlock(
        password: &str,
        secret_key: &SecretKey,
        params_record: &[u8],
        keyset_record: &[u8],
        pinned: Option<&PinnedAccount>,
    ) -> Result<Account> {
        let params = decode_params(params_record)?;
        let unsigned = Error::Integrity(IntegrityError::ParamsUnsigned);
        let msg = signed_message(
            &params.account_id,
            &params.kdf,
            &params.signing_pub,
            &params.kem_pub,
        )?;
        params
            .identity_pub
            .verify(PARAMS_DOMAIN, &msg, &params.identity_sig)
            .map_err(|_| unsigned.clone())?;
        if let Some(pin) = pinned {
            if pin.account_id != params.account_id || pin.identity_pub != params.identity_pub {
                return Err(unsigned);
            }
            if !params.kdf.is_at_least(&pin.kdf_floor) {
                return Err(IntegrityError::ParamsDowngrade.into());
            }
        }
        if !above_floor(&params.kdf) {
            return Err(IntegrityError::ParamsDowngrade.into());
        }
        if !within_ceiling(&params.kdf) {
            return Err(Error::InvalidFormat("kdf params"));
        }

        let auk = derive_auk(password, secret_key, &params.kdf)?;
        let plaintext = open_detailed(
            &auk,
            BlobKind::Keyset,
            &keyset_aad(params.account_id),
            keyset_record,
        )
        .map_err(|(stage, e)| match stage {
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
}

fn within_ceiling(kdf: &KdfParams) -> bool {
    let (m_kib, t, p) = KDF_CEILING;
    kdf.m_kib <= m_kib && kdf.t <= t && kdf.p <= p
}

/// Canonical postcard encoding of the signed fields.
fn signed_message(
    account_id: &Id,
    kdf: &KdfParams,
    signing_pub: &HybridVerifyingKey,
    kem_pub: &HybridKemPublic,
) -> Result<Vec<u8>> {
    postcard::to_allocvec(&(account_id, kdf, signing_pub, kem_pub))
        .map_err(|_| Error::InvalidFormat("account params"))
}

fn sign_params(
    account_id: Id,
    kdf: KdfParams,
    signing_pub: HybridVerifyingKey,
    kem_pub: HybridKemPublic,
    identity: &IdentityKey,
) -> Result<AccountParams> {
    let msg = signed_message(&account_id, &kdf, &signing_pub, &kem_pub)?;
    let identity_sig = identity.sign(PARAMS_DOMAIN, &msg)?;
    Ok(AccountParams {
        account_id,
        kdf,
        identity_pub: identity.verifying_key(),
        signing_pub,
        kem_pub,
        identity_sig,
    })
}

/// Decode the whole record: trailing bytes are rejected.
fn decode_params(record: &[u8]) -> Result<AccountParams> {
    match postcard::take_from_bytes::<AccountParams>(record) {
        Ok((params, [])) => Ok(params),
        _ => Err(Error::InvalidFormat("account params")),
    }
}

fn keyset_aad(account_id: Id) -> Aad {
    Aad {
        blob_id: account_id,
        vault_id: None,
        schema: KEYSET_SCHEMA,
    }
}

/// Seal the postcard encoding of the three secret keys' bytes. The plaintext
/// is written into a buffer sized up front and wiped on drop.
fn seal_keyset(auk: &SymmetricKey, account_id: Id, keyset: &Keyset) -> Result<Vec<u8>> {
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
    seal(auk, BlobKind::Keyset, &keyset_aad(account_id), &buf[..used])
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
        let mut ks = n.keyset_record.clone();
        ks[0] ^= 1;
        assert_eq!(
            Account::unlock("nope", &n.secret_key, &n.params_record, &ks, None).unwrap_err(),
            Error::InvalidFormat("magic")
        );
        let mut ks = n.keyset_record.clone();
        ks[5] = 2; // another blob kind
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
        let record = postcard::to_allocvec(&params).unwrap();
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
            &n.account.keyset().identity,
        )
        .unwrap();
        let record = postcard::to_allocvec(&params).unwrap();
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
            &n.account.keyset().identity,
        )
        .unwrap();
        let record = postcard::to_allocvec(&params).unwrap();
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
        let record = seal_keyset(&auk, n.account.params.account_id, &swapped).unwrap();
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
}
