//! Encrypted file attachments (architecture spec 4.2): a PDF, a scan or any
//! file kept with an item.
//!
//! Each attachment has its own random 256-bit key. The file is cut into
//! chunks of [`CHUNK`] bytes, each one a record of kind
//! `RecordKind::Attachment`, so that no record goes over the sync limit
//! (`sync::MAX_RECORD_BYTES`). A chunk record is laid out like an item
//! record, `vault_id (16 bytes) || postcard(AttachmentChunk)`, so the sync
//! layer holds, hides and drops it with its vault. Its id is
//! [`chunk_id`]: the attachment id for the first chunk, derived from the
//! attachment id and the index for the others.
//!
//! - The attachment key is sealed under the vault key, kind `Attachment`,
//!   context `(attachment id, vault id)`, and copied into every chunk:
//!   each chunk opens on its own. Moving the item to another vault or a key
//!   rotation re-wraps the key; the chunks themselves are not re-encrypted.
//! - A chunk's bytes are sealed under the attachment key, kind
//!   `Attachment`, context `(chunk id, no vault)`: a chunk cannot be read
//!   at another index or in another attachment.
//! - The item lists its attachments (`Item::attachments`, an
//!   `AttachmentRef` with id, name, size and type). The item is covered by
//!   the signed manifest; the size it records fixes the number of chunks
//!   and the length of each, so a missing, cut or extra chunk is refused.
//!
//! An attachment is immutable: replacing a file is a new attachment.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use aws_lc_rs::digest::{SHA256, digest};

use crate::crypto::aead::{Aad, BlobKind, open, seal};
use crate::crypto::key::SymmetricKey;
use crate::error::{Error, Result};
use crate::format::ITEM_SCHEMA;
use crate::id::Id;
use crate::model::AttachmentRef;
use crate::store::{Record, RecordKind};
use crate::vault::Vault;

/// Plaintext bytes per chunk (512 KiB): a sealed chunk record stays well
/// under the 900 KiB sync limit.
pub const CHUNK: usize = 512 * 1024;
/// Largest attachment (20 MiB).
pub const MAX_ATTACHMENT: usize = 20 * 1024 * 1024;
/// Most attachments on one item.
pub const MAX_PER_ITEM: usize = 32;
/// Longest file name kept, in bytes.
pub const MAX_NAME: usize = 255;

/// One chunk record body. `attachment_id`, `index` and `count` are in
/// clear so a store can group chunks; nothing in them is trusted: the
/// item's `AttachmentRef` and the sealed contexts are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentChunk {
    pub attachment_id: Id,
    pub index: u32,
    pub count: u32,
    /// The attachment key, sealed under the vault key.
    pub wrapped_key: Vec<u8>,
    /// This chunk's bytes, sealed under the attachment key.
    pub blob: Vec<u8>,
}

impl AttachmentChunk {
    /// Decode a chunk body, which may come from a hostile store: the whole
    /// buffer, trailing bytes refused.
    pub fn decode(bytes: &[u8]) -> Result<AttachmentChunk> {
        match postcard::take_from_bytes(bytes) {
            Ok((c, [])) => Ok(c),
            _ => Err(Error::InvalidFormat("attachment chunk")),
        }
    }
}

/// Record id of chunk `index`: the attachment id for the first one, else
/// the first 16 bytes of `SHA-256("onepass/attachment-chunk/v1" ||
/// attachment id || index BE)`.
pub fn chunk_id(attachment: Id, index: u32) -> Id {
    if index == 0 {
        return attachment;
    }
    let mut input = b"onepass/attachment-chunk/v1".to_vec();
    input.extend_from_slice(&attachment.0);
    input.extend_from_slice(&index.to_be_bytes());
    let h = digest(&SHA256, &input);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.as_ref()[..16]);
    Id(id)
}

/// How many chunks hold `size` bytes: at least one, so an empty file still
/// has a record.
pub fn chunk_count(size: u64) -> Result<u32> {
    let size = usize::try_from(size).map_err(|_| Error::InvalidFormat("attachment size"))?;
    if size > MAX_ATTACHMENT {
        return Err(Error::InvalidFormat("attachment too large"));
    }
    u32::try_from(size.div_ceil(CHUNK).max(1)).map_err(|_| Error::InvalidFormat("attachment size"))
}

/// The record ids of every chunk of `r`.
pub fn chunk_ids(r: &AttachmentRef) -> Result<Vec<Id>> {
    Ok((0..chunk_count(r.size)?)
        .map(|i| chunk_id(r.id, i))
        .collect())
}

fn key_aad(attachment: Id, vault: Id) -> Aad {
    Aad {
        blob_id: attachment,
        vault_id: Some(vault),
        schema: ITEM_SCHEMA,
    }
}

fn chunk_aad(attachment: Id, index: u32) -> Aad {
    Aad {
        blob_id: chunk_id(attachment, index),
        vault_id: None,
        schema: ITEM_SCHEMA,
    }
}

/// A file name fit to keep: trimmed, without path or control characters,
/// at most `MAX_NAME` bytes (cut on a character boundary), never empty.
pub fn clean_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mut out: String = base.chars().filter(|c| !c.is_control()).collect();
    out = out.trim().to_owned();
    while out.len() > MAX_NAME {
        out.pop();
    }
    if out.is_empty() {
        "Fichier".to_owned()
    } else {
        out
    }
}

fn record(vault: Id, id: Id, version: u64, chunk: &AttachmentChunk) -> Result<Record> {
    let mut data = vault.0.to_vec();
    data.extend_from_slice(
        &postcard::to_allocvec(chunk).map_err(|_| Error::InvalidFormat("attachment chunk"))?,
    );
    Ok(Record {
        id,
        kind: RecordKind::Attachment,
        version,
        data,
    })
}

/// Encrypt `bytes` as a new attachment of `vault`: its reference for the
/// item and its chunk records (version 1), ready to store.
pub fn seal_attachment(
    vault: &Vault,
    name: &str,
    mime: &str,
    bytes: &[u8],
) -> Result<(AttachmentRef, Vec<Record>)> {
    if bytes.len() > MAX_ATTACHMENT {
        return Err(Error::InvalidFormat("attachment too large"));
    }
    let id = Id::new();
    let key = SymmetricKey::generate()?;
    let wrapped_key = seal(
        vault.key(),
        BlobKind::Attachment,
        &key_aad(id, vault.id),
        key.expose(),
    )?;
    let size = bytes.len() as u64;
    let count = chunk_count(size)?;
    let mut records = Vec::with_capacity(count as usize);
    for index in 0..count {
        let start = (index as usize) * CHUNK;
        let part = bytes
            .get(start..bytes.len().min(start + CHUNK))
            .unwrap_or_default();
        let blob = seal(&key, BlobKind::Attachment, &chunk_aad(id, index), part)?;
        let chunk = AttachmentChunk {
            attachment_id: id,
            index,
            count,
            wrapped_key: wrapped_key.clone(),
            blob,
        };
        records.push(record(vault.id, chunk_id(id, index), 1, &chunk)?);
    }
    let reference = AttachmentRef {
        id,
        name: clean_name(name),
        size,
        mime: mime.trim().to_owned(),
    };
    Ok((reference, records))
}

/// The vault prefix and chunk of a stored record.
fn split(rec: &Record) -> Result<(Id, AttachmentChunk)> {
    if rec.kind != RecordKind::Attachment {
        return Err(Error::InvalidFormat("attachment chunk"));
    }
    let (prefix, body) = rec
        .data
        .split_at_checked(16)
        .ok_or(Error::InvalidFormat("attachment chunk"))?;
    let mut v = [0u8; 16];
    v.copy_from_slice(prefix);
    Ok((Id(v), AttachmentChunk::decode(body)?))
}

fn unwrap_key(vault: &Vault, attachment: Id, chunk: &AttachmentChunk) -> Result<SymmetricKey> {
    let plain = open(
        vault.key(),
        BlobKind::Attachment,
        &key_aad(attachment, vault.id),
        &chunk.wrapped_key,
    )?;
    if plain.len() != 32 {
        return Err(Error::InvalidFormat("attachment key length"));
    }
    let mut key = SymmetricKey::zeroed();
    key.bytes_mut().copy_from_slice(&plain);
    Ok(key)
}

/// Decrypt the attachment `r` of an item of `vault`. `get` returns the
/// stored record of a chunk id (`None` when missing: not synced yet, or
/// lost). Every chunk is checked against `r`: its vault, its id, its
/// count, its length; the bytes returned are exactly `r.size` long.
pub fn open_attachment(
    vault: &Vault,
    r: &AttachmentRef,
    mut get: impl FnMut(Id) -> Result<Option<Record>>,
) -> Result<Zeroizing<Vec<u8>>> {
    let count = chunk_count(r.size)?;
    let size = usize::try_from(r.size).map_err(|_| Error::InvalidFormat("attachment size"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    let mut key: Option<SymmetricKey> = None;
    for index in 0..count {
        let rec = get(chunk_id(r.id, index))?.ok_or(Error::NotFound)?;
        let (prefix, chunk) = split(&rec)?;
        if prefix != vault.id
            || chunk.attachment_id != r.id
            || chunk.index != index
            || chunk.count != count
        {
            return Err(Error::InvalidFormat("attachment chunk"));
        }
        if key.is_none() {
            key = Some(unwrap_key(vault, r.id, &chunk)?);
        }
        let k = key.as_ref().ok_or(Error::Crypto)?;
        let part = open(
            k,
            BlobKind::Attachment,
            &chunk_aad(r.id, index),
            &chunk.blob,
        )?;
        let expected = if index + 1 == count {
            size - CHUNK * (count as usize - 1)
        } else {
            CHUNK
        };
        if part.len() != expected {
            return Err(Error::InvalidFormat("attachment chunk length"));
        }
        out.extend_from_slice(&part);
    }
    Ok(out)
}

/// The chunk record `rec` of vault `from`, re-wrapped for vault `to` (a
/// move or a key rotation): the attachment key sealed under `to`'s key,
/// the vault prefix changed, the chunk bytes untouched, the version
/// bumped.
pub fn rewrap(from: &Vault, to: &Vault, rec: &Record) -> Result<Record> {
    let (prefix, mut chunk) = split(rec)?;
    if prefix != from.id || chunk_id(chunk.attachment_id, chunk.index) != rec.id {
        return Err(Error::InvalidFormat("attachment chunk"));
    }
    let key = unwrap_key(from, chunk.attachment_id, &chunk)?;
    chunk.wrapped_key = seal(
        to.key(),
        BlobKind::Attachment,
        &key_aad(chunk.attachment_id, to.id),
        key.expose(),
    )?;
    record(to.id, rec.id, rec.version.saturating_add(1), &chunk)
}

/// The vault a stored chunk record belongs to, from its prefix.
pub fn vault_of(rec: &Record) -> Option<Id> {
    split(rec).ok().map(|(v, _)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultMeta;
    use std::collections::BTreeMap;

    fn vault() -> Vault {
        Vault::create_for_tests(VaultMeta {
            name: "Perso".into(),
            icon: String::new(),
            color: String::new(),
            travel_safe: false,
            mcp_access: false,
        })
    }

    fn store(records: &[Record]) -> BTreeMap<Id, Record> {
        records.iter().map(|r| (r.id, r.clone())).collect()
    }

    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn roundtrip_across_sizes() {
        let v = vault();
        for n in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            let data = bytes(n);
            let (r, recs) = seal_attachment(&v, "contrat.pdf", "application/pdf", &data).unwrap();
            assert_eq!(r.size, n as u64);
            assert_eq!(recs.len(), chunk_count(r.size).unwrap() as usize);
            assert_eq!(
                chunk_ids(&r).unwrap(),
                recs.iter().map(|x| x.id).collect::<Vec<_>>()
            );
            for rec in &recs {
                assert!(rec.data.len() < crate::sync::MAX_RECORD_BYTES);
                assert_eq!(vault_of(rec), Some(v.id));
            }
            let s = store(&recs);
            let out = open_attachment(&v, &r, |id| Ok(s.get(&id).cloned())).unwrap();
            assert_eq!(&out[..], &data[..]);
        }
    }

    #[test]
    fn too_large_is_refused() {
        let v = vault();
        assert!(seal_attachment(&v, "x", "", &vec![0u8; MAX_ATTACHMENT + 1]).is_err());
        assert!(chunk_count(MAX_ATTACHMENT as u64 + 1).is_err());
    }

    #[test]
    fn missing_swapped_or_tampered_chunks_are_refused() {
        let v = vault();
        let data = bytes(2 * CHUNK + 5);
        let (r, recs) = seal_attachment(&v, "a.bin", "", &data).unwrap();
        // A missing chunk: not synced yet.
        let mut s = store(&recs);
        s.remove(&recs[1].id);
        assert_eq!(
            open_attachment(&v, &r, |id| Ok(s.get(&id).cloned())).unwrap_err(),
            Error::NotFound
        );
        // Two chunks swapped.
        let mut s = store(&recs);
        let (a, b) = (recs[0].clone(), recs[1].clone());
        s.insert(
            a.id,
            Record {
                id: a.id,
                ..b.clone()
            },
        );
        s.insert(b.id, Record { id: b.id, ..a });
        assert!(open_attachment(&v, &r, |id| Ok(s.get(&id).cloned())).is_err());
        // A flipped byte.
        let mut s = store(&recs);
        let mut t = recs[2].clone();
        let last = t.data.len() - 1;
        t.data[last] ^= 1;
        s.insert(t.id, t);
        assert!(open_attachment(&v, &r, |id| Ok(s.get(&id).cloned())).is_err());
        // A size that does not match the chunks.
        let s = store(&recs);
        let short = AttachmentRef {
            size: r.size - 1,
            ..r.clone()
        };
        assert!(open_attachment(&v, &short, |id| Ok(s.get(&id).cloned())).is_err());
        // Another vault's key.
        let other = vault();
        let s = store(&recs);
        assert!(open_attachment(&other, &r, |id| Ok(s.get(&id).cloned())).is_err());
    }

    #[test]
    fn chunks_of_two_attachments_do_not_mix() {
        let v = vault();
        let (r1, recs1) = seal_attachment(&v, "1", "", &bytes(10)).unwrap();
        let (_, recs2) = seal_attachment(&v, "2", "", &bytes(10)).unwrap();
        let mut forged = recs2[0].clone();
        forged.id = r1.id;
        let s = store(&[forged]);
        assert!(open_attachment(&v, &r1, |id| Ok(s.get(&id).cloned())).is_err());
        drop(recs1);
    }

    #[test]
    fn rewrap_moves_the_key_to_another_vault() {
        let (a, b) = (vault(), vault());
        let data = bytes(CHUNK + 3);
        let (r, recs) = seal_attachment(&a, "f", "", &data).unwrap();
        let moved: Vec<Record> = recs.iter().map(|x| rewrap(&a, &b, x).unwrap()).collect();
        assert!(
            moved
                .iter()
                .all(|x| x.version == 2 && vault_of(x) == Some(b.id))
        );
        let s = store(&moved);
        assert_eq!(
            &open_attachment(&b, &r, |id| Ok(s.get(&id).cloned())).unwrap()[..],
            &data[..]
        );
        assert!(open_attachment(&a, &r, |id| Ok(s.get(&id).cloned())).is_err());
        // A record of another vault is not re-wrapped.
        assert!(rewrap(&b, &a, &recs[0]).is_err());
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean_name("/tmp/../facture.pdf"), "facture.pdf");
        assert_eq!(clean_name("C:\\docs\\a\u{0}b.pdf"), "ab.pdf");
        assert_eq!(clean_name("   "), "Fichier");
        assert!(clean_name(&"é".repeat(300)).len() <= MAX_NAME);
    }

    #[test]
    fn chunk_ids_are_distinct_and_stable() {
        let id = Id::new();
        assert_eq!(chunk_id(id, 0), id);
        assert_ne!(chunk_id(id, 1), chunk_id(id, 2));
        assert_eq!(chunk_id(id, 7), chunk_id(id, 7));
    }
}
