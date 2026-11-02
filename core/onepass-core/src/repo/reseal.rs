//! The resealing pass shared by the key rotation (step 3, spec 6.7 of the
//! rotation) and by sharing a vault (sharing spec 9.5): every listed item
//! of a vault (live, archived, trashed) resealed under another vault key
//! with a fresh item key, at version + 1, and the next manifest, unsigned.

use std::collections::BTreeMap;

use super::{Loaded, Repository, entry};
use crate::manifest::{Manifest, SeenManifest, manifest_hash, record_hash};
use crate::store::{Record, RecordKind, RecordStore};
use crate::vault::{ItemRecord, Vault};
use crate::{Error, Id, Result};

/// What `reseal_vault` produces.
pub(crate) struct Resealed {
    /// The resealed item records, under fresh blob ids.
    pub(crate) items: Vec<Record>,
    /// Attachment chunks with their key re-wrapped under the new vault key
    /// (same id), and the version they replace.
    pub(crate) attachments: Vec<(Record, u64)>,
    /// The next manifest after the loaded one, unsigned, without meta.
    pub(crate) manifest: Manifest,
    /// The manifest the pass started from.
    pub(crate) from: SeenManifest,
    /// Blob ids of the records the loaded manifest listed.
    pub(crate) collect: Vec<Id>,
    /// `record_hash` of each resealed item, by item id.
    pub(crate) hashes: BTreeMap<Id, [u8; 32]>,
}

/// The stored record of an item: `vault_id || postcard(ItemRecord)` under a
/// fresh blob id (see the layout in `repo`).
pub(crate) fn item_record(vault_id: Id, rec: &ItemRecord) -> Result<Record> {
    let mut data = vault_id.0.to_vec();
    data.extend(postcard::to_allocvec(rec).map_err(|_| Error::InvalidFormat("item record"))?);
    Ok(Record {
        id: Id::new(),
        kind: RecordKind::Item,
        version: rec.version,
        data,
    })
}

impl<S: RecordStore> Repository<S> {
    /// Reseal every item `loaded` lists from `from` to `to`. Attachment
    /// chunks are read from the private zone; one not synced yet is left
    /// as it is.
    pub(crate) fn reseal_vault(
        &self,
        from: &Vault,
        to: &Vault,
        loaded: &Loaded,
    ) -> Result<Resealed> {
        let mut items = Vec::with_capacity(loaded.records.len());
        let mut attachments = Vec::new();
        let mut entries = Vec::with_capacity(loaded.records.len());
        let mut collect = Vec::with_capacity(loaded.records.len());
        let mut hashes = BTreeMap::new();
        for (blob, rec) in &loaded.records {
            collect.push(*blob);
            let item = from.open_item(rec)?;
            let version = rec
                .version
                .checked_add(1)
                .ok_or(Error::InvalidFormat("item version"))?;
            let sealed = to.reseal_item(&item, version)?;
            hashes.insert(item.id, record_hash(&sealed));
            entries.push(entry(&sealed));
            items.push(item_record(to.id, &sealed)?);
            for r in &item.attachments {
                for id in crate::attachment::chunk_ids(r).unwrap_or_default() {
                    if let Some(chunk) = self.store.get(RecordKind::Attachment, id)?
                        && let Ok(moved) = crate::attachment::rewrap(from, to, &chunk)
                    {
                        attachments.push((moved, chunk.version));
                    }
                }
            }
        }
        // Spec 6.7 of the rotation: prev_hash and seq follow the manifest
        // loaded.
        let manifest = Manifest::next(Some(&loaded.manifest), to.id, entries)?;
        Ok(Resealed {
            items,
            attachments,
            manifest,
            from: SeenManifest {
                seq: loaded.manifest.seq,
                hash: manifest_hash(&loaded.manifest),
            },
            collect,
            hashes,
        })
    }
}
