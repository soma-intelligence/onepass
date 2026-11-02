//! Attachments of an item (`crate::attachment`): add, read, remove, and the
//! chunk records that follow an item when it moves or goes away.
//!
//! Writes go chunks first, item second: the item never lists an attachment
//! whose chunks were not written on this device. A failed item write
//! deletes the chunks it just wrote. Removing an attachment saves the item
//! without it first, then deletes the chunks, so a crash in between leaves
//! unreferenced chunks, never a reference without its file.

use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::{Repository, Use};
use crate::attachment::{self, MAX_PER_ITEM};
use crate::error::{Error, Result};
use crate::id::Id;
use crate::model::{AttachmentRef, EventKind, Item};
use crate::store::{RecordKind, RecordStore};
use crate::vault::Vault;

impl<S: RecordStore> Repository<S> {
    fn listed_item(&mut self, vault: &Vault, item_id: Id, use_: Use) -> Result<Item> {
        let loaded = self.served(vault, use_)?;
        let (_, rec) = loaded.listed(item_id).ok_or(Error::NotFound)?;
        vault.open_item(rec)
    }

    /// Encrypt `bytes` and attach them to the item `item_id` of `vault`
    /// (at most `attachment::MAX_PER_ITEM` per item, each at most
    /// `attachment::MAX_ATTACHMENT` bytes). The item gets a new version
    /// listing it. Returns the new reference.
    pub fn add_attachment(
        &mut self,
        vault: &Vault,
        item_id: Id,
        name: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<AttachmentRef> {
        let mut item = self.listed_item(vault, item_id, Use::Write)?;
        if item.attachments.len() >= MAX_PER_ITEM {
            return Err(Error::InvalidFormat("too many attachments"));
        }
        let (reference, records) = attachment::seal_attachment(vault, name, mime, bytes)?;
        let ids: Vec<Id> = records.iter().map(|r| r.id).collect();
        let written = records
            .into_iter()
            .try_for_each(|r| self.store.put(r))
            .and_then(|()| {
                let now = OffsetDateTime::now_utc();
                item.attachments.push(reference.clone());
                item.record(
                    now,
                    EventKind::AttachmentAdded {
                        name: reference.name.clone(),
                    },
                );
                item.updated_at = now;
                self.save_item(vault, item)
            });
        if let Err(e) = written {
            for id in ids {
                let _ = self.store.delete(RecordKind::Attachment, id);
            }
            return Err(e);
        }
        Ok(reference)
    }

    /// Detach the attachment `attachment_id` from the item and delete its
    /// chunks. `NotFound` when the item does not list it.
    pub fn remove_attachment(
        &mut self,
        vault: &Vault,
        item_id: Id,
        attachment_id: Id,
    ) -> Result<()> {
        let mut item = self.listed_item(vault, item_id, Use::Write)?;
        let at = item
            .attachments
            .iter()
            .position(|a| a.id == attachment_id)
            .ok_or(Error::NotFound)?;
        let removed = item.attachments.remove(at);
        item.updated_at = OffsetDateTime::now_utc();
        self.save_item(vault, item)?;
        self.delete_attachment_chunks(std::slice::from_ref(&removed));
        Ok(())
    }

    /// The decrypted bytes of an attachment the item lists. `NotFound` when
    /// the item does not list it or a chunk is missing (not synced yet).
    /// A chunk still under another vault of the account (a move cut short)
    /// is re-wrapped for this vault first.
    pub fn read_attachment(
        &mut self,
        vault: &Vault,
        item_id: Id,
        attachment_id: Id,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.readable()?;
        let item = self.listed_item(vault, item_id, Use::Read)?;
        let reference = item
            .attachments
            .iter()
            .find(|a| a.id == attachment_id)
            .ok_or(Error::NotFound)?
            .clone();
        self.heal_attachment(vault, &reference)?;
        let store = &self.store;
        attachment::open_attachment(vault, &reference, |id| {
            store.get(RecordKind::Attachment, id)
        })
    }

    /// Chunks of `r` whose prefix names another vault this account opens
    /// (a move or a rotation cut short): re-wrapped into `vault`.
    fn heal_attachment(&mut self, vault: &Vault, r: &AttachmentRef) -> Result<()> {
        let mut others: Option<Vec<Vault>> = None;
        for id in attachment::chunk_ids(r)? {
            let Some(rec) = self.store.get(RecordKind::Attachment, id)? else {
                continue;
            };
            let Some(owner) = attachment::vault_of(&rec) else {
                continue;
            };
            if owner == vault.id {
                continue;
            }
            if others.is_none() {
                others = Some(self.personal_vaults()?);
            }
            if let Some(from) = others.iter().flatten().find(|v| v.id == owner)
                && let Ok(moved) = attachment::rewrap(from, vault, &rec)
                && self.writable().is_ok()
            {
                self.store.put(moved)?;
            }
        }
        Ok(())
    }

    /// Best effort: delete the chunks of `refs` (an item deleted for good,
    /// an attachment removed). A chunk already gone is fine.
    pub(crate) fn delete_attachment_chunks(&mut self, refs: &[AttachmentRef]) {
        for r in refs {
            for id in attachment::chunk_ids(r).unwrap_or_default() {
                let _ = self.store.delete(RecordKind::Attachment, id);
            }
        }
    }

    /// Re-wrap the chunks of `refs` from vault `from` to vault `to` (the
    /// item moved). Best effort: a chunk not synced yet, or already moved,
    /// stays as it is; `read_attachment` heals what is left.
    pub(crate) fn move_attachment_chunks(
        &mut self,
        from: &Vault,
        to: &Vault,
        refs: &[AttachmentRef],
    ) {
        for r in refs {
            for id in attachment::chunk_ids(r).unwrap_or_default() {
                if let Ok(Some(rec)) = self.store.get(RecordKind::Attachment, id)
                    && let Ok(moved) = attachment::rewrap(from, to, &rec)
                {
                    let _ = self.store.put(moved);
                }
            }
        }
    }
}
