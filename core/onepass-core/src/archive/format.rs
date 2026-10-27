//! Archive container (spec 5.2 to 5.4).
//!
//! `"OPARCH" || format (1) || header length (u32 big-endian) || postcard(Header)
//! || sealed payload`. A random content key `K` seals the payload and is
//! wrapped for each recipient: a passphrase (Argon2id then HKDF to a KEK) or
//! an account (hybrid KEM). An archive with an account recipient is signed
//! by that account's hybrid signing key.
//!
//! The wire types are public so that tests and fuzzers can build hostile
//! archives; `open` never trusts any of their fields.

use std::fmt;

use aws_lc_rs::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::account::Account;
use crate::crypto::aead::{LEN_PREFIX, OpenStage, TAG_LEN, open_detailed};
use crate::crypto::{
    Aad, BlobKind, DEV_KDF_FLOOR, HEADER_LEN, HybridSignature, KDF_FLOOR, KdfParams, SecretKey,
    SymmetricKey, derive_auk, padded_len, seal, unwrap_key, wrap_key,
};
use crate::model::Item;
use crate::vault::VaultMeta;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

/// Container magic.
pub const MAGIC: &[u8; 6] = b"OPARCH";
/// Container format byte.
pub const FORMAT: u8 = 1;
/// Signature domain, also the prefix of the account envelope context.
pub const SIGN_DOMAIN: &[u8] = b"onepass/archive/v1";
/// Newest payload schema this build reads and the one it writes.
pub const CURRENT_SCHEMA: u16 = 1;

/// HKDF info turning the passphrase AUK into the key-encryption key.
const KEK_INFO: &[u8] = b"onepass/archive/kek/v1";
/// AAD schema of the passphrase-wrapped content key.
const KEY_SCHEMA: u16 = 0;
/// `MAGIC || FORMAT || header length`.
const PREFIX_LEN: usize = 11;
const MAX_HEADER: usize = 64 * 1024;
const MAX_RECIPIENTS: usize = 8;
const MAX_PAYLOAD: usize = 1 << 30;
const MAX_VAULTS: usize = 10_000;
const MAX_ITEMS: usize = 1_000_000;
/// Largest accepted Argon2id cost on open, as `(m_kib, t, p)`: the account
/// ceiling (2 GiB, 16 passes, 16 lanes). Checked before Argon2 runs.
const KDF_CEILING: (u32, u32, u32) = (2097152, 16, 16);
/// zxcvbn scores at most this many leading characters of a passphrase: its
/// cost grows with the length (same bound as the Watchtower weak check).
const MAX_ZXCVBN_CHARS: usize = 128;
const MIN_PASSPHRASE_SCORE: u8 = 3;

/// What an archive is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveKind {
    /// Portable export, passphrase recipient only, unsigned.
    Export,
    /// Account backup: account recipient, signed; optional passphrase.
    Backup,
}

/// One vault of an archive with its items (trashed and archived included).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchivedVault {
    pub id: Id,
    pub meta: VaultMeta,
    pub items: Vec<Item>,
}

/// An opened archive.
#[derive(Debug, Clone, PartialEq)]
pub struct Contents {
    pub archive_id: Id,
    pub kind: ArchiveKind,
    pub created_at: i64,
    pub source_account: Option<Id>,
    pub vaults: Vec<ArchivedVault>,
}

/// How to open an archive.
#[derive(Clone, Copy)]
pub enum Unlock<'a> {
    Passphrase(&'a str),
    Account(&'a Account),
}

impl fmt::Debug for Unlock<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passphrase(_) => f.write_str("Unlock::Passphrase(**)"),
            Self::Account(a) => write!(f, "Unlock::Account({})", a.params.account_id),
        }
    }
}

/// The clear header of an archive, without any key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderInfo {
    pub archive_id: Id,
    pub kind: ArchiveKind,
    pub created_at: i64,
    pub payload_schema: u16,
    /// A passphrase recipient is present.
    pub passphrase: bool,
    /// The first account recipient.
    pub account: Option<Id>,
    pub signed: bool,
}

/// Clear archive header (wire type).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub archive_id: Id,
    pub kind: ArchiveKind,
    pub created_at: i64,
    pub payload_schema: u16,
    pub recipients: Vec<Recipient>,
    /// Required when an account recipient is present.
    pub signature: Option<Signed>,
}

/// A party able to unwrap the content key (wire type). Variants are encoded
/// by index: append only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Recipient {
    Passphrase {
        kdf: KdfParams,
        #[serde(with = "serde_bytes")]
        wrapped_key: Vec<u8>,
    },
    Account {
        account_id: Id,
        #[serde(with = "serde_bytes")]
        envelope: Vec<u8>,
    },
}

/// Hybrid signature of an archive by an account (wire type).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signed {
    pub account_id: Id,
    pub signature: HybridSignature,
}

/// Sealed payload (wire type). The first four fields repeat the header's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    pub archive_id: Id,
    pub kind: ArchiveKind,
    pub created_at: i64,
    pub payload_schema: u16,
    pub source_account: Option<Id>,
    pub vaults: Vec<ArchivedVault>,
}

/// KEM context of an account recipient: `SIGN_DOMAIN || archive_id`.
pub fn envelope_context(archive_id: Id) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(SIGN_DOMAIN.len() + 16);
    ctx.extend_from_slice(SIGN_DOMAIN);
    ctx.extend_from_slice(&archive_id.0);
    ctx
}

/// The signed message: `SHA-256(MAGIC || FORMAT || postcard(header with
/// signature = None) || sealed payload)`. The header encoding is
/// self-delimiting, so the concatenation is unambiguous.
pub fn signed_digest(header: &Header, sealed_payload: &[u8]) -> Result<[u8; 32]> {
    let unsigned = Header {
        signature: None,
        ..header.clone()
    };
    let h = postcard::to_allocvec(&unsigned).map_err(|_| Error::InvalidFormat("archive header"))?;
    let mut ctx = Context::new(&SHA256);
    ctx.update(MAGIC);
    ctx.update(&[FORMAT]);
    ctx.update(&h);
    ctx.update(sealed_payload);
    ctx.finish().as_ref().try_into().map_err(|_| Error::Crypto)
}

/// Frame a header and a sealed payload. Refuses a header above 64 KiB.
pub fn encode_container(header: &Header, sealed_payload: &[u8]) -> Result<Vec<u8>> {
    let bad = Error::InvalidFormat("archive header");
    let h = postcard::to_allocvec(header).map_err(|_| bad.clone())?;
    if h.len() > MAX_HEADER {
        return Err(bad);
    }
    let len = u32::try_from(h.len()).map_err(|_| bad)?;
    let mut out = Vec::with_capacity(PREFIX_LEN + h.len() + sealed_payload.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(sealed_payload);
    Ok(out)
}

/// Parse the framing and the header: magic, format, header length (64 KiB at
/// most, within the input), header decoding with no trailing byte and in
/// canonical encoding, 1 to 8 recipients. Returns the header and the sealed
/// payload. Nothing is verified or decrypted here.
pub fn decode_container(bytes: &[u8]) -> Result<(Header, &[u8])> {
    let bad = || Error::InvalidFormat("archive header");
    let rest = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or(Error::InvalidFormat("archive magic"))?;
    let (&format, rest) = rest
        .split_first()
        .ok_or(Error::InvalidFormat("archive format"))?;
    if format != FORMAT {
        return Err(Error::InvalidFormat("archive format"));
    }
    let (len, rest) = rest.split_first_chunk::<4>().ok_or_else(bad)?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| bad())?;
    if len > MAX_HEADER {
        return Err(bad());
    }
    let (h, sealed) = rest.split_at_checked(len).ok_or_else(bad)?;
    let header = match postcard::take_from_bytes::<Header>(h) {
        Ok((header, [])) => header,
        _ => return Err(bad()),
    };
    // One encoding per header: the signature covers a re-encoding, so a
    // non-canonical variant of the same header is refused outright.
    if postcard::to_allocvec(&header).map_err(|_| bad())? != h {
        return Err(bad());
    }
    if header.recipients.is_empty() || header.recipients.len() > MAX_RECIPIENTS {
        return Err(Error::InvalidFormat("archive recipients"));
    }
    Ok((header, sealed))
}

/// The enforced Argon2id floor, as for accounts: `DEV_KDF_FLOOR` under
/// `cfg(test)`, or with `dev-fast-kdf` and debug assertions; else `KDF_FLOOR`.
fn enforced_floor() -> (u32, u32, u32) {
    if cfg!(any(test, all(feature = "dev-fast-kdf", debug_assertions))) {
        DEV_KDF_FLOOR
    } else {
        KDF_FLOOR
    }
}

fn above_floor(kdf: &KdfParams) -> bool {
    let (m_kib, t, p) = enforced_floor();
    kdf.m_kib >= m_kib && kdf.t >= t && kdf.p >= p
}

fn within_ceiling(kdf: &KdfParams) -> bool {
    let (m_kib, t, p) = KDF_CEILING;
    kdf.m_kib <= m_kib && kdf.t <= t && kdf.p <= p
}

/// Passphrase strength (zxcvbn score at least 3) and KDF bounds on create.
fn check_passphrase(passphrase: &str, kdf: &KdfParams) -> Result<()> {
    // zxcvbn's cost grows with the length: score the first 128 characters
    // (cut on a char boundary), which must be strong on their own.
    let end = passphrase
        .char_indices()
        .nth(MAX_ZXCVBN_CHARS)
        .map_or(passphrase.len(), |(i, _)| i);
    let scored = passphrase.get(..end).unwrap_or(passphrase);
    if u8::from(zxcvbn::zxcvbn(scored, &[]).score()) < MIN_PASSPHRASE_SCORE {
        return Err(ValidationError {
            field: "passphrase".into(),
            reason: "too weak",
        }
        .into());
    }
    if !above_floor(kdf) || !within_ceiling(kdf) {
        return Err(Error::InvalidFormat("kdf params"));
    }
    Ok(())
}

/// `KEK = HKDF(derive_auk(NFC(passphrase), zero Secret Key, kdf),
/// "onepass/archive/kek/v1")`. `derive_auk` normalizes to NFC.
fn passphrase_kek(passphrase: &str, kdf: &KdfParams) -> Result<SymmetricKey> {
    derive_auk(passphrase, &SecretKey([0; 32]), kdf)?.derive(KEK_INFO)
}

fn key_aad(archive_id: Id) -> Aad {
    Aad {
        blob_id: archive_id,
        vault_id: None,
        schema: KEY_SCHEMA,
    }
}

fn payload_aad(archive_id: Id, schema: u16) -> Aad {
    Aad {
        blob_id: archive_id,
        vault_id: None,
        schema,
    }
}

fn too_large() -> Error {
    Error::InvalidFormat("archive too large")
}

fn check_counts(vaults: &[ArchivedVault]) -> Result<()> {
    let items = vaults
        .iter()
        .try_fold(0usize, |n, v| n.checked_add(v.items.len()))
        .ok_or_else(too_large)?;
    if vaults.len() > MAX_VAULTS || items > MAX_ITEMS {
        return Err(too_large());
    }
    Ok(())
}

/// Postcard of the payload in a buffer sized up front and wiped on drop.
fn encode_payload(payload: &Payload) -> Result<Zeroizing<Vec<u8>>> {
    let bad = Error::InvalidFormat("archive payload");
    let size = postcard::experimental::serialized_size(payload).map_err(|_| bad.clone())?;
    if size > MAX_PAYLOAD {
        return Err(too_large());
    }
    let mut buf = Zeroizing::new(vec![0u8; size]);
    postcard::to_slice(payload, &mut buf[..]).map_err(|_| bad)?;
    Ok(buf)
}

/// Export: passphrase recipient only, unsigned.
///
/// Errors: a passphrase with a zxcvbn score below 3 is
/// `Validation { field: "passphrase", reason: "too weak" }`; KDF parameters
/// below the enforced floor or above the ceiling are
/// `InvalidFormat("kdf params")`.
pub fn export(vaults: Vec<ArchivedVault>, passphrase: &str, kdf: KdfParams) -> Result<Vec<u8>> {
    check_passphrase(passphrase, &kdf)?;
    build(ArchiveKind::Export, vaults, None, Some((passphrase, kdf)))
}

/// Backup of `account`: account recipient and signature, plus a passphrase
/// recipient when asked (same checks as `export`).
pub fn backup(
    account: &Account,
    vaults: Vec<ArchivedVault>,
    passphrase: Option<(&str, KdfParams)>,
) -> Result<Vec<u8>> {
    if let Some((p, kdf)) = &passphrase {
        check_passphrase(p, kdf)?;
    }
    build(ArchiveKind::Backup, vaults, Some(account), passphrase)
}

fn build(
    kind: ArchiveKind,
    vaults: Vec<ArchivedVault>,
    account: Option<&Account>,
    passphrase: Option<(&str, KdfParams)>,
) -> Result<Vec<u8>> {
    check_counts(&vaults)?;
    let archive_id = Id::new();
    let created_at = OffsetDateTime::now_utc().unix_timestamp();
    let k = SymmetricKey::generate()?;

    let payload = Payload {
        archive_id,
        kind,
        created_at,
        payload_schema: CURRENT_SCHEMA,
        source_account: account.map(|a| a.params.account_id),
        vaults,
    };
    let sealed = {
        let plain = encode_payload(&payload)?;
        seal(
            &k,
            BlobKind::Archive,
            &payload_aad(archive_id, CURRENT_SCHEMA),
            &plain,
        )?
    };
    drop(payload);

    let mut recipients = Vec::with_capacity(2);
    if let Some(a) = account {
        recipients.push(Recipient::Account {
            account_id: a.params.account_id,
            envelope: wrap_key(&a.params.kem_pub, &k, &envelope_context(archive_id))?,
        });
    }
    if let Some((p, kdf)) = passphrase {
        let kek = passphrase_kek(p, &kdf)?;
        let wrapped_key = seal(&kek, BlobKind::Archive, &key_aad(archive_id), k.expose())?;
        recipients.push(Recipient::Passphrase { kdf, wrapped_key });
    }

    let mut header = Header {
        archive_id,
        kind,
        created_at,
        payload_schema: CURRENT_SCHEMA,
        recipients,
        signature: None,
    };
    if let Some(a) = account {
        let digest = signed_digest(&header, &sealed)?;
        header.signature = Some(Signed {
            account_id: a.params.account_id,
            signature: a.keyset().signing.sign(SIGN_DOMAIN, &digest)?,
        });
    }
    encode_container(&header, &sealed)
}

/// Read the clear header only, for `onepass backup inspect`. Recipients are
/// reported without their bytes. A newer payload schema is reported, not
/// refused.
pub fn inspect(bytes: &[u8]) -> Result<HeaderInfo> {
    let (header, _) = decode_container(bytes)?;
    Ok(HeaderInfo {
        archive_id: header.archive_id,
        kind: header.kind,
        created_at: header.created_at,
        payload_schema: header.payload_schema,
        passphrase: header
            .recipients
            .iter()
            .any(|r| matches!(r, Recipient::Passphrase { .. })),
        account: header.recipients.iter().find_map(|r| match r {
            Recipient::Account { account_id, .. } => Some(*account_id),
            Recipient::Passphrase { .. } => None,
        }),
        signed: header.signature.is_some(),
    })
}

fn check_schema(schema: u16) -> Result<()> {
    if schema == 0 {
        Err(Error::InvalidFormat("archive schema"))
    } else if schema > CURRENT_SCHEMA {
        Err(Error::InvalidFormat("archive from a newer version"))
    } else {
        Ok(())
    }
}

/// The opening account must be the signer, and the signature must verify
/// under its signing key over `signed_digest`.
fn verify_signature(header: &Header, sealed: &[u8], account: &Account) -> Result<()> {
    let refused = || Error::Integrity(IntegrityError::Signature);
    let signed = header.signature.as_ref().ok_or_else(refused)?;
    if signed.account_id != account.params.account_id {
        return Err(refused());
    }
    let digest = signed_digest(header, sealed)?;
    account
        .params
        .signing_pub
        .verify(SIGN_DOMAIN, &digest, &signed.signature)
        .map_err(|_| refused())
}

/// Copy a 32-byte unwrapped key straight into a key buffer.
fn content_key(plain: &[u8]) -> Result<SymmetricKey> {
    if plain.len() != 32 {
        return Err(Error::InvalidFormat("archive key"));
    }
    let mut k = SymmetricKey::zeroed();
    k.bytes_mut().copy_from_slice(plain);
    Ok(k)
}

fn unwrap_content_key(header: &Header, sealed: &[u8], unlock: Unlock<'_>) -> Result<SymmetricKey> {
    match unlock {
        Unlock::Account(account) => {
            let id = account.params.account_id;
            let envelope = header
                .recipients
                .iter()
                .find_map(|r| match r {
                    Recipient::Account {
                        account_id,
                        envelope,
                    } if *account_id == id => Some(envelope),
                    _ => None,
                })
                .ok_or(Error::WrongPassword)?;
            verify_signature(header, sealed, account)?;
            unwrap_key(
                &account.keyset().kem,
                envelope,
                &envelope_context(header.archive_id),
            )
        }
        Unlock::Passphrase(passphrase) => {
            let (kdf, wrapped_key) = header
                .recipients
                .iter()
                .find_map(|r| match r {
                    Recipient::Passphrase { kdf, wrapped_key } => Some((kdf, wrapped_key)),
                    Recipient::Account { .. } => None,
                })
                .ok_or(Error::WrongPassword)?;
            // A floor is not enforced on open: weak parameters only weaken
            // the archive's own author. The ceiling bounds the work.
            if !within_ceiling(kdf) {
                return Err(Error::InvalidFormat("kdf params"));
            }
            let kek = passphrase_kek(passphrase, kdf)?;
            let plain = open_detailed(
                &kek,
                BlobKind::Archive,
                &key_aad(header.archive_id),
                wrapped_key,
            )
            .map_err(|(stage, e)| match stage {
                OpenStage::Commitment => Error::WrongPassword,
                _ => e,
            })?;
            content_key(&plain)
        }
    }
}

/// Decode and check the payload: schema first (a newer one may not decode
/// as this one), then the whole payload with no trailing byte, the repeated
/// fields against the header, and the counts.
fn decode_payload(header: &Header, plain: &[u8]) -> Result<Contents> {
    let bad = Error::InvalidFormat("archive payload");
    // Enum variant indexes are varint u32 in postcard: the prefix decodes
    // whatever kinds a newer version adds.
    let ((_, _, _, schema), _) =
        postcard::take_from_bytes::<(Id, u32, i64, u16)>(plain).map_err(|_| bad.clone())?;
    check_schema(schema)?;
    let payload = match postcard::take_from_bytes::<Payload>(plain) {
        Ok((payload, [])) => payload,
        _ => return Err(bad),
    };
    if payload.archive_id != header.archive_id
        || payload.kind != header.kind
        || payload.created_at != header.created_at
        || payload.payload_schema != header.payload_schema
    {
        return Err(IntegrityError::WrongContext.into());
    }
    check_counts(&payload.vaults)?;
    Ok(Contents {
        archive_id: payload.archive_id,
        kind: payload.kind,
        created_at: payload.created_at,
        source_account: payload.source_account,
        vaults: payload.vaults,
    })
}

/// Open an archive, which may be hostile.
///
/// Checks, in order: magic, format, header length and decoding (64 KiB at
/// most, no trailing byte, canonical), recipient count (1 to 8), payload
/// schema (`InvalidFormat("archive from a newer version")` above
/// `CURRENT_SCHEMA`), payload size; then the recipient matching `unlock`
/// (none: `WrongPassword`). By account: the signature, which must be by the
/// opening account and verify under its signing key
/// (`IntegrityError::Signature`), then the KEM unwrap. By passphrase: the
/// KDF ceiling (`InvalidFormat("kdf params")`) before Argon2 runs, then the
/// unwrap, where a key commitment mismatch is `WrongPassword`. Then the
/// payload opens under `K` (any failure keeps its integrity error, never
/// `WrongPassword`), its schema is checked again, it decodes with no
/// trailing byte, its repeated fields equal the header's
/// (`IntegrityError::WrongContext`) and its counts are within bounds.
pub fn open(bytes: &[u8], unlock: Unlock<'_>) -> Result<Contents> {
    let (header, sealed) = decode_container(bytes)?;
    check_schema(header.payload_schema)?;
    let max_sealed = HEADER_LEN + padded_len(MAX_PAYLOAD + LEN_PREFIX) + TAG_LEN;
    if sealed.len() > max_sealed {
        return Err(too_large());
    }
    let k = unwrap_content_key(&header, sealed, unlock)?;
    let plain = crate::crypto::open(
        &k,
        BlobKind::Archive,
        &payload_aad(header.archive_id, header.payload_schema),
        sealed,
    )?;
    drop(k);
    decode_payload(&header, &plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(recipients: Vec<Recipient>) -> Header {
        Header {
            archive_id: Id([1; 16]),
            kind: ArchiveKind::Export,
            created_at: 5,
            payload_schema: 1,
            recipients,
            signature: None,
        }
    }

    fn pass() -> Recipient {
        Recipient::Passphrase {
            kdf: KdfParams {
                m_kib: 8192,
                t: 1,
                p: 1,
                salt: [0; 32],
            },
            wrapped_key: vec![1, 2, 3],
        }
    }

    const PP: &str = "quartz lantern oyster meadow 91";

    /// A passphrase archive built by hand through the wire helpers, with
    /// any KDF parameters and a payload altered after the header is fixed.
    fn forge_passphrase(kdf: KdfParams, alter: impl FnOnce(&mut Payload)) -> Vec<u8> {
        let k = SymmetricKey::generate().unwrap();
        let mut h = header(vec![]);
        h.archive_id = Id::new();
        let wrapped_key = seal(
            &passphrase_kek(PP, &kdf).unwrap(),
            BlobKind::Archive,
            &key_aad(h.archive_id),
            k.expose(),
        )
        .unwrap();
        h.recipients = vec![Recipient::Passphrase { kdf, wrapped_key }];
        let mut p = Payload {
            archive_id: h.archive_id,
            kind: h.kind,
            created_at: h.created_at,
            payload_schema: h.payload_schema,
            source_account: None,
            vaults: vec![],
        };
        alter(&mut p);
        let sealed = seal(
            &k,
            BlobKind::Archive,
            &payload_aad(h.archive_id, h.payload_schema),
            &postcard::to_allocvec(&p).unwrap(),
        )
        .unwrap();
        encode_container(&h, &sealed).unwrap()
    }

    fn dev_kdf() -> KdfParams {
        KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: [5; 32],
        }
    }

    #[test]
    fn repeated_field_mismatch_is_wrong_context() {
        let wrong = Error::Integrity(IntegrityError::WrongContext);
        let unlock = Unlock::Passphrase(PP);
        assert!(open(&forge_passphrase(dev_kdf(), |_| {}), unlock).is_ok());
        let created = forge_passphrase(dev_kdf(), |p| p.created_at += 1);
        assert_eq!(open(&created, unlock).unwrap_err(), wrong);
        let kind = forge_passphrase(dev_kdf(), |p| p.kind = ArchiveKind::Backup);
        assert_eq!(open(&kind, unlock).unwrap_err(), wrong);
        let id = forge_passphrase(dev_kdf(), |p| p.archive_id = Id([7; 16]));
        assert_eq!(open(&id, unlock).unwrap_err(), wrong);
    }

    #[test]
    fn kdf_below_floor_accepted_on_open() {
        let low = KdfParams {
            m_kib: 4096,
            ..dev_kdf()
        };
        assert!(!above_floor(&low));
        let bytes = forge_passphrase(low, |_| {});
        let c = open(&bytes, Unlock::Passphrase(PP)).unwrap();
        assert_eq!(c.kind, ArchiveKind::Export);
        assert!(c.vaults.is_empty());
    }

    #[test]
    fn container_roundtrip() {
        let h = header(vec![pass()]);
        let bytes = encode_container(&h, b"xyz").unwrap();
        let (back, sealed) = decode_container(&bytes).unwrap();
        assert_eq!(back, h);
        assert_eq!(sealed, b"xyz");
    }

    #[test]
    fn recipient_count_bounds() {
        let none = encode_container(&header(vec![]), b"").unwrap();
        assert_eq!(
            decode_container(&none).unwrap_err(),
            Error::InvalidFormat("archive recipients")
        );
        let nine = encode_container(&header(vec![pass(); 9]), b"").unwrap();
        assert_eq!(
            decode_container(&nine).unwrap_err(),
            Error::InvalidFormat("archive recipients")
        );
        let eight = encode_container(&header(vec![pass(); 8]), b"").unwrap();
        assert!(decode_container(&eight).is_ok());
    }

    #[test]
    fn framing_errors() {
        let bytes = encode_container(&header(vec![pass()]), b"").unwrap();
        let mut b = bytes.clone();
        b[0] = b'X';
        assert_eq!(
            decode_container(&b).unwrap_err(),
            Error::InvalidFormat("archive magic")
        );
        let mut b = bytes.clone();
        b[6] = 2;
        assert_eq!(
            decode_container(&b).unwrap_err(),
            Error::InvalidFormat("archive format")
        );
        // Declared header length above 64 KiB.
        let mut b = bytes.clone();
        b[7..11].copy_from_slice(&(MAX_HEADER as u32 + 1).to_be_bytes());
        assert_eq!(
            decode_container(&b).unwrap_err(),
            Error::InvalidFormat("archive header")
        );
        // Declared header length past the end.
        let mut b = bytes.clone();
        b[7..11].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        assert!(decode_container(&b).is_err());
    }

    #[test]
    fn non_canonical_header_refused() {
        let h = header(vec![pass()]);
        let mut enc = postcard::to_allocvec(&h).unwrap();
        // created_at = 5 is a zigzag varint 0x0a after the 16 id bytes and
        // the kind byte; rewrite it as an overlong two-byte varint.
        assert_eq!(enc[17], 0x0a);
        enc.splice(17..18, [0x8a, 0x00]);
        assert_eq!(postcard::from_bytes::<Header>(&enc).unwrap(), h);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT);
        bytes.extend_from_slice(&(enc.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&enc);
        assert_eq!(
            decode_container(&bytes).unwrap_err(),
            Error::InvalidFormat("archive header")
        );
    }

    #[test]
    fn schema_bounds() {
        assert_eq!(
            check_schema(0).unwrap_err(),
            Error::InvalidFormat("archive schema")
        );
        assert!(check_schema(CURRENT_SCHEMA).is_ok());
        assert_eq!(
            check_schema(CURRENT_SCHEMA + 1).unwrap_err(),
            Error::InvalidFormat("archive from a newer version")
        );
    }

    #[test]
    fn floor_is_the_dev_floor_in_tests() {
        assert_eq!(enforced_floor(), DEV_KDF_FLOOR);
        let mut k = KdfParams {
            m_kib: 8192,
            t: 1,
            p: 1,
            salt: [0; 32],
        };
        assert!(above_floor(&k) && within_ceiling(&k));
        k.p = 17;
        assert!(!within_ceiling(&k));
    }

    #[test]
    fn signed_digest_ignores_the_signature_field() {
        let mut h = header(vec![pass()]);
        let d = signed_digest(&h, b"payload").unwrap();
        h.signature = Some(Signed {
            account_id: Id([9; 16]),
            signature: HybridSignature {
                mldsa: vec![1],
                ed25519: [2; 64],
            },
        });
        assert_eq!(signed_digest(&h, b"payload").unwrap(), d);
        assert_ne!(signed_digest(&h, b"payloaD").unwrap(), d);
        h.created_at += 1;
        assert_ne!(signed_digest(&h, b"payload").unwrap(), d);
    }

    #[test]
    fn content_key_length() {
        assert!(content_key(&[0; 31]).is_err());
        assert!(content_key(&[0; 33]).is_err());
        assert_eq!(content_key(&[7; 32]).unwrap().expose(), &[7; 32]);
    }

    #[test]
    fn counts_bounded() {
        let v = ArchivedVault {
            id: Id([0; 16]),
            meta: VaultMeta {
                name: String::new(),
                icon: String::new(),
                color: String::new(),
                travel_safe: false,
                mcp_access: false,
            },
            items: vec![],
        };
        assert!(check_counts(&vec![v.clone(); MAX_VAULTS]).is_ok());
        assert_eq!(
            check_counts(&vec![v; MAX_VAULTS + 1]).unwrap_err(),
            too_large()
        );
    }
}
