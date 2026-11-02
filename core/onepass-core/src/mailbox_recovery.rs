//! What the Secret Key alone finds again of a mailbox account (spec D.4):
//! the locator a mailbox registers so a restore can find it, and the seed
//! of the recovery credential granted on that mailbox.
//!
//! Both are HKDF-SHA256 of the 32 Secret Key bytes, empty salt, under
//! their own info. The locator says nothing of the key (a one-way 128-bit
//! value) and changes with it: a key rotation registers the new one. The
//! recovery seed is bound to one mailbox, so a credential seen on one
//! server is no use on another. Neither is ever stored: a device derives
//! them during a restore or a rotation, uses them and drops them.

use zeroize::Zeroizing;

use crate::Result;
use crate::crypto::SecretKey;
use crate::crypto::key::hkdf32;

/// HKDF info of the locator.
pub const LOCATOR_INFO: &[u8] = b"onepass/mailbox-locator/v1";
/// HKDF info prefix of the recovery credential seed (the mailbox id
/// follows).
pub const RECOVERY_INFO: &[u8] = b"onepass/mailbox-recovery-credential/v1";

/// The first 16 bytes of `HKDF(ikm = secret_key, salt = "", info =
/// LOCATOR_INFO)`.
pub fn mailbox_locator(secret_key: &SecretKey) -> Result<[u8; 16]> {
    let okm = hkdf32(&[], &secret_key.0, &[LOCATOR_INFO])?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&okm.expose()[..16]);
    Ok(out)
}

/// `HKDF(ikm = secret_key, salt = "", info = RECOVERY_INFO || mailbox_id)`:
/// the Ed25519 seed of the recovery credential of `mailbox_id`.
pub fn mailbox_recovery_seed(
    secret_key: &SecretKey,
    mailbox_id: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>> {
    let okm = hkdf32(&[], &secret_key.0, &[RECOVERY_INFO, mailbox_id])?;
    Ok(Zeroizing::new(*okm.expose()))
}
