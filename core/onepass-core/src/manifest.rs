//! Signed vault manifest: the list of items a vault holds, with a Merkle root
//! and a sequence number, so a storage server cannot drop, replay, inject or
//! swap items, or serve an older manifest, without being caught.

use std::collections::BTreeMap;

use aws_lc_rs::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    Aad, BlobKind, HybridSignature, HybridSigningKey, HybridVerifyingKey, open, seal,
};
use crate::vault::{ItemRecord, Vault};
use crate::{Error, Id, IntegrityError, Result};

/// One item listed in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub item_id: Id,
    pub version: u64,
    /// SHA-256 of `postcard(ItemRecord)`.
    pub record_hash: [u8; 32],
}

/// The state of a vault at one sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub vault_id: Id,
    pub seq: u64,
    pub prev_hash: [u8; 32],
    /// Sorted by `item_id`, no duplicates.
    pub entries: Vec<ManifestEntry>,
    pub merkle_root: [u8; 32],
}

/// A sealed manifest and the signature over the sealed blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    pub blob: Vec<u8>,
    pub sig: HybridSignature,
}

/// Signature domain of manifests.
const DOMAIN: &[u8] = b"manifest";
const SCHEMA: u16 = 1;
const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;
const EMPTY: u8 = 0x02;
const BAD: Error = Error::InvalidFormat("manifest");

fn finish(ctx: Context) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// SHA-256 of `prefix || postcard(value)`. Serializing these fixed-shape
/// types into a `Vec` cannot fail, hence the infallible signature.
fn hash_postcard<T: Serialize>(prefix: &[u8], value: &T) -> [u8; 32] {
    let bytes = postcard::to_allocvec(value).expect("postcard into a Vec is infallible");
    let mut ctx = Context::new(&SHA256);
    ctx.update(prefix);
    ctx.update(&bytes);
    finish(ctx)
}

/// SHA-256 of `postcard(rec)`, the `record_hash` of its manifest entry.
pub fn record_hash(rec: &ItemRecord) -> [u8; 32] {
    hash_postcard(&[], rec)
}

/// Merkle root of the entries, in the given order. Leaf
/// `SHA-256(0x00 || postcard(entry))`, node `SHA-256(0x01 || left || right)`,
/// an odd last node is promoted as is, the empty list gives `SHA-256(0x02)`.
pub fn merkle_root(entries: &[ManifestEntry]) -> [u8; 32] {
    if entries.is_empty() {
        let mut ctx = Context::new(&SHA256);
        ctx.update(&[EMPTY]);
        return finish(ctx);
    }
    let mut level: Vec<[u8; 32]> = entries.iter().map(|e| hash_postcard(&[LEAF], e)).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => {
                    let mut ctx = Context::new(&SHA256);
                    ctx.update(&[NODE]);
                    ctx.update(left);
                    ctx.update(right);
                    finish(ctx)
                }
                [odd] => *odd,
                _ => unreachable!("chunks(2) yields one or two nodes"),
            })
            .collect();
    }
    level[0]
}

/// Strictly increasing item ids: sorted and without duplicates.
fn strictly_sorted(entries: &[ManifestEntry]) -> bool {
    entries.windows(2).all(|w| w[0].item_id < w[1].item_id)
}

fn aad(vault_id: Id) -> Aad {
    Aad {
        blob_id: vault_id,
        vault_id: Some(vault_id),
        schema: SCHEMA,
    }
}

/// Checks shared by signing and verifying, after the vault check.
/// Unsorted or duplicate entries are a malformed manifest
/// (`InvalidFormat("manifest")`); a root that does not match the entries
/// means the listed items are not the ones committed to
/// (`IntegrityError::ManifestItemMismatch`).
fn check_shape(vault: &Vault, m: &Manifest) -> Result<()> {
    if m.vault_id != vault.id {
        return Err(IntegrityError::WrongContext.into());
    }
    if !strictly_sorted(&m.entries) {
        return Err(BAD);
    }
    if merkle_root(&m.entries) != m.merkle_root {
        return Err(IntegrityError::ManifestItemMismatch.into());
    }
    Ok(())
}

impl Manifest {
    /// The manifest following `prev` (or the first one): `seq = prev.seq + 1`
    /// (or 1), `prev_hash = SHA-256(postcard(prev))` (or zeros). Entries are
    /// sorted by item id. Duplicates are kept, and refused by `sign_manifest`.
    pub fn next(
        prev: Option<&Manifest>,
        vault_id: Id,
        mut entries: Vec<ManifestEntry>,
    ) -> Manifest {
        entries.sort_by_key(|e| e.item_id);
        let (seq, prev_hash) = match prev {
            Some(p) => (p.seq + 1, hash_postcard(&[], p)),
            None => (1, [0u8; 32]),
        };
        let merkle_root = merkle_root(&entries);
        Manifest {
            vault_id,
            seq,
            prev_hash,
            entries,
            merkle_root,
        }
    }
}

/// Seal the manifest with the vault key and sign the sealed blob (domain
/// `"manifest"`). Refuses a manifest that `verify_manifest` would refuse:
/// another vault, unsorted or duplicate entries, or a wrong Merkle root.
pub fn sign_manifest(
    vault: &Vault,
    signer: &HybridSigningKey,
    m: &Manifest,
) -> Result<SignedManifest> {
    check_shape(vault, m)?;
    let plain = postcard::to_allocvec(m).map_err(|_| BAD)?;
    let blob = seal(vault.key(), BlobKind::Manifest, &aad(vault.id), &plain)?;
    let sig = signer.sign(DOMAIN, &blob)?;
    Ok(SignedManifest { blob, sig })
}

/// Verify, in order: the signature over the blob, the opening with the vault
/// key, the decoding, the vault id (`WrongContext`), sorted unique entries
/// (`InvalidFormat("manifest")`), the Merkle root (`ManifestItemMismatch`),
/// then `seq >= last_seen_seq` (`ManifestRollback`; equal is the same
/// manifest read again).
pub fn verify_manifest(
    vault: &Vault,
    verifier: &HybridVerifyingKey,
    sm: &SignedManifest,
    last_seen_seq: Option<u64>,
) -> Result<Manifest> {
    verifier.verify(DOMAIN, &sm.blob, &sm.sig)?;
    let plain = open(vault.key(), BlobKind::Manifest, &aad(vault.id), &sm.blob)?;
    let m: Manifest = postcard::from_bytes(&plain).map_err(|_| BAD)?;
    check_shape(vault, &m)?;
    if last_seen_seq.is_some_and(|last| m.seq < last) {
        return Err(IntegrityError::ManifestRollback.into());
    }
    Ok(m)
}

/// Match the records served by the store against the manifest, by item id:
/// every entry needs exactly one record with the same version and hash
/// (`ManifestMissingItem`, `ManifestItemMismatch`), and no other record may
/// appear (`ManifestUnexpectedItem`, also for a record served twice).
pub fn check_records(m: &Manifest, records: &[ItemRecord]) -> Result<()> {
    let mut by_id: BTreeMap<Id, &ItemRecord> = BTreeMap::new();
    for rec in records {
        if by_id.insert(rec.item_id, rec).is_some() {
            return Err(IntegrityError::ManifestUnexpectedItem.into());
        }
    }
    for e in &m.entries {
        let rec = by_id
            .remove(&e.item_id)
            .ok_or(IntegrityError::ManifestMissingItem)?;
        if rec.version != e.version || record_hash(rec) != e.record_hash {
            return Err(IntegrityError::ManifestItemMismatch.into());
        }
    }
    if !by_id.is_empty() {
        return Err(IntegrityError::ManifestUnexpectedItem.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use aws_lc_rs::digest::{SHA256, digest};

    use super::*;
    use crate::account::{Account, NewAccount};
    use crate::crypto::{KdfParams, random_array};
    use crate::model::{FieldValue, Item, ItemType, new_item};
    use crate::vault::VaultMeta;

    fn shared() -> &'static NewAccount {
        static N: OnceLock<NewAccount> = OnceLock::new();
        N.get_or_init(|| {
            let kdf = KdfParams {
                m_kib: 8192,
                t: 1,
                p: 1,
                salt: random_array().unwrap(),
            };
            Account::create_with_params("pw", kdf).unwrap()
        })
    }

    fn signer() -> &'static HybridSigningKey {
        static K: OnceLock<HybridSigningKey> = OnceLock::new();
        K.get_or_init(|| HybridSigningKey::generate().unwrap())
    }

    fn vault() -> Vault {
        let meta = VaultMeta {
            name: "A".into(),
            icon: "key".into(),
            color: "blue".into(),
            travel_safe: true,
            mcp_access: false,
        };
        Vault::create(&shared().account, meta).unwrap().0
    }

    fn sha(parts: &[&[u8]]) -> [u8; 32] {
        let mut buf = Vec::new();
        for p in parts {
            buf.extend_from_slice(p);
        }
        digest(&SHA256, &buf).as_ref().try_into().unwrap()
    }

    fn leaf(e: &ManifestEntry) -> [u8; 32] {
        sha(&[&[0x00], &postcard::to_allocvec(e).unwrap()])
    }

    fn entry(n: u8) -> ManifestEntry {
        ManifestEntry {
            item_id: Id([n; 16]),
            version: u64::from(n) * 1000,
            record_hash: [n.wrapping_add(7); 32],
        }
    }

    fn login(v: &Vault) -> Item {
        let mut item = new_item(ItemType::Login, v.id, "Example");
        item.field_mut("username").unwrap().value = FieldValue::Text("alice".into());
        item
    }

    fn record(v: &Vault, version: u64) -> ItemRecord {
        v.seal_item(&login(v), version).unwrap()
    }

    fn entry_for(rec: &ItemRecord) -> ManifestEntry {
        ManifestEntry {
            item_id: rec.item_id,
            version: rec.version,
            record_hash: sha(&[&postcard::to_allocvec(rec).unwrap()]),
        }
    }

    /// Seal and sign any manifest, skipping the checks of `sign_manifest`,
    /// as a malicious or buggy signer would.
    fn forge(v: &Vault, m: &Manifest) -> SignedManifest {
        let aad = Aad {
            blob_id: v.id,
            vault_id: Some(v.id),
            schema: 1,
        };
        let blob = seal(
            v.key(),
            BlobKind::Manifest,
            &aad,
            &postcard::to_allocvec(m).unwrap(),
        )
        .unwrap();
        let sig = signer().sign(b"manifest", &blob).unwrap();
        SignedManifest { blob, sig }
    }

    fn verifier() -> HybridVerifyingKey {
        signer().verifying_key().unwrap()
    }

    fn integrity(r: Result<Manifest>) -> IntegrityError {
        match r {
            Err(Error::Integrity(e)) => e,
            other => panic!("expected an integrity error, got {other:?}"),
        }
    }

    #[test]
    fn merkle_root_known_values() {
        assert_eq!(merkle_root(&[]), sha(&[&[0x02]]));

        let (e0, e1, e2) = (entry(1), entry(2), entry(3));
        assert_eq!(merkle_root(std::slice::from_ref(&e0)), leaf(&e0));

        let two = sha(&[&[0x01], &leaf(&e0), &leaf(&e1)]);
        assert_eq!(merkle_root(&[e0.clone(), e1.clone()]), two);

        // Odd node promoted as is to the next level.
        let three = sha(&[&[0x01], &two, &leaf(&e2)]);
        assert_eq!(merkle_root(&[e0.clone(), e1.clone(), e2.clone()]), three);

        let e3 = entry(4);
        let right = sha(&[&[0x01], &leaf(&e2), &leaf(&e3)]);
        let four = sha(&[&[0x01], &two, &right]);
        assert_eq!(merkle_root(&[e0, e1, e2, e3]), four);
    }

    #[test]
    fn record_hash_is_sha256_of_postcard() {
        let v = vault();
        let rec = record(&v, 3);
        assert_eq!(record_hash(&rec), entry_for(&rec).record_hash);
    }

    #[test]
    fn next_sorts_and_chains() {
        let v = vault();
        let m1 = Manifest::next(None, v.id, vec![entry(3), entry(1), entry(2)]);
        assert_eq!(m1.seq, 1);
        assert_eq!(m1.prev_hash, [0u8; 32]);
        assert_eq!(m1.vault_id, v.id);
        assert_eq!(m1.entries, vec![entry(1), entry(2), entry(3)]);
        assert_eq!(m1.merkle_root, merkle_root(&m1.entries));

        let m2 = Manifest::next(Some(&m1), v.id, vec![entry(1)]);
        assert_eq!(m2.seq, 2);
        assert_eq!(m2.prev_hash, sha(&[&postcard::to_allocvec(&m1).unwrap()]));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let v = vault();
        let m = Manifest::next(None, v.id, vec![entry(2), entry(1)]);
        let sm = sign_manifest(&v, signer(), &m).unwrap();
        assert_eq!(verify_manifest(&v, &verifier(), &sm, None).unwrap(), m);
        // The same manifest read again is accepted.
        assert_eq!(verify_manifest(&v, &verifier(), &sm, Some(1)).unwrap(), m);
        // Empty vault.
        let empty = Manifest::next(Some(&m), v.id, vec![]);
        let sm = sign_manifest(&v, signer(), &empty).unwrap();
        assert_eq!(
            verify_manifest(&v, &verifier(), &sm, Some(1)).unwrap(),
            empty
        );
    }

    #[test]
    fn older_seq_is_rollback() {
        let v = vault();
        let m1 = Manifest::next(None, v.id, vec![entry(1)]);
        let m2 = Manifest::next(Some(&m1), v.id, vec![entry(1), entry(2)]);
        let s1 = sign_manifest(&v, signer(), &m1).unwrap();
        let s2 = sign_manifest(&v, signer(), &m2).unwrap();
        assert_eq!(verify_manifest(&v, &verifier(), &s2, Some(1)).unwrap(), m2);
        assert_eq!(
            integrity(verify_manifest(&v, &verifier(), &s1, Some(2))),
            IntegrityError::ManifestRollback
        );
    }

    #[test]
    fn manifest_signed_by_other_key_is_refused() {
        let v = vault();
        let m = Manifest::next(None, v.id, vec![entry(1)]);
        let other = HybridSigningKey::generate().unwrap();
        let sm = sign_manifest(&v, &other, &m).unwrap();
        assert_eq!(
            integrity(verify_manifest(&v, &verifier(), &sm, None)),
            IntegrityError::Signature
        );
    }

    #[test]
    fn tampered_blob_fails_signature() {
        let v = vault();
        let m = Manifest::next(None, v.id, vec![entry(1)]);
        let mut sm = sign_manifest(&v, signer(), &m).unwrap();
        let last = sm.blob.len() - 1;
        sm.blob[last] ^= 1;
        assert_eq!(
            integrity(verify_manifest(&v, &verifier(), &sm, None)),
            IntegrityError::Signature
        );
    }

    #[test]
    fn manifest_of_another_vault_is_refused() {
        let a = vault();
        let b = vault();
        let m = Manifest::next(None, a.id, vec![entry(1)]);
        let sm = sign_manifest(&a, signer(), &m).unwrap();
        // Valid signature, but sealed under another vault key and context.
        assert!(matches!(
            verify_manifest(&b, &verifier(), &sm, None),
            Err(Error::Integrity(_))
        ));
        // Sealed in this vault's context but naming another vault inside.
        let inner = Manifest::next(None, a.id, vec![entry(1)]);
        let sm = forge(&b, &inner);
        assert_eq!(
            integrity(verify_manifest(&b, &verifier(), &sm, None)),
            IntegrityError::WrongContext
        );
        // sign_manifest refuses to sign it in the first place.
        assert_eq!(
            sign_manifest(&b, signer(), &inner).unwrap_err(),
            Error::Integrity(IntegrityError::WrongContext)
        );
    }

    #[test]
    fn unsorted_or_duplicate_entries_are_refused() {
        let v = vault();
        for entries in [vec![entry(2), entry(1)], vec![entry(1), entry(1)]] {
            let mut m = Manifest::next(None, v.id, vec![]);
            m.merkle_root = merkle_root(&entries);
            m.entries = entries;
            assert_eq!(
                verify_manifest(&v, &verifier(), &forge(&v, &m), None).unwrap_err(),
                Error::InvalidFormat("manifest")
            );
            assert_eq!(
                sign_manifest(&v, signer(), &m).unwrap_err(),
                Error::InvalidFormat("manifest")
            );
        }
    }

    #[test]
    fn wrong_merkle_root_is_refused() {
        let v = vault();
        let mut m = Manifest::next(None, v.id, vec![entry(1), entry(2)]);
        m.merkle_root[0] ^= 1;
        assert_eq!(
            integrity(verify_manifest(&v, &verifier(), &forge(&v, &m), None)),
            IntegrityError::ManifestItemMismatch
        );
        assert_eq!(
            sign_manifest(&v, signer(), &m).unwrap_err(),
            Error::Integrity(IntegrityError::ManifestItemMismatch)
        );
    }

    #[test]
    fn check_records_detects_each_case() {
        let v = vault();
        let (r1, r2) = (record(&v, 1), record(&v, 1));
        let m = Manifest::next(None, v.id, vec![entry_for(&r1), entry_for(&r2)]);
        let err = |records: &[ItemRecord]| match check_records(&m, records) {
            Err(Error::Integrity(e)) => e,
            other => panic!("expected an integrity error, got {other:?}"),
        };

        assert_eq!(check_records(&m, &[r2.clone(), r1.clone()]), Ok(()));
        assert_eq!(
            err(std::slice::from_ref(&r1)),
            IntegrityError::ManifestMissingItem
        );
        assert_eq!(
            err(&[r1.clone(), r2.clone(), record(&v, 1)]),
            IntegrityError::ManifestUnexpectedItem
        );
        // Same item, other version (an older or newer record replayed).
        let mut old = v.seal_item(&login(&v), 1).unwrap();
        old.item_id = r2.item_id;
        let mut bumped = r2.clone();
        bumped.version = 2;
        assert_eq!(
            err(&[r1.clone(), bumped]),
            IntegrityError::ManifestItemMismatch
        );
        // Same id and version, other content.
        assert_eq!(
            err(&[r1.clone(), old]),
            IntegrityError::ManifestItemMismatch
        );
        // The same record served twice.
        assert_eq!(
            err(&[r1.clone(), r2.clone(), r2.clone()]),
            IntegrityError::ManifestUnexpectedItem
        );
    }
}
