//! The custom icon of an item (`Item::custom_icon`): a small PNG or WebP
//! sealed like an attachment (`crate::attachment`) but kept out of
//! `Item::attachments`, so it never counts toward `MAX_PER_ITEM`.
//!
//! Same write order as `attachments.rs`: chunks first, item second. A failed
//! item write deletes the chunks just written. Replacing or clearing saves
//! the item first, then deletes the old chunks, so a crash in between leaves
//! unreferenced chunks, never a reference without its file.

use std::collections::HashSet;

use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::{Repository, Use};
use crate::attachment;
use crate::error::{Error, Result};
use crate::id::Id;
use crate::model::{AttachmentRef, EventKind, Item};
use crate::store::{RecordKind, RecordStore};
use crate::vault::Vault;

/// Largest custom icon, in bytes.
pub const MAX_CUSTOM_ICON: usize = 65_536;

/// Name under which an icon is sealed (never shown).
const ICON_NAME: &str = "icon";

const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// `mime` is PNG or WebP, and `bytes` start like that format.
fn check_icon(mime: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_CUSTOM_ICON {
        return Err(Error::InvalidFormat("custom icon too large"));
    }
    let matches = match mime {
        "image/png" => bytes.starts_with(&PNG_MAGIC),
        "image/webp" => bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP",
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(Error::InvalidFormat("custom icon type"))
    }
}

/// Chunk ids of every attachment of `item`: an icon reference must never
/// reach them (read or delete). A malformed attachment reference adds none.
fn attachment_chunks(item: &Item) -> HashSet<Id> {
    item.attachments
        .iter()
        .flat_map(|a| attachment::chunk_ids(a).unwrap_or_default())
        .collect()
}

/// The stored reference is one a set could have written: PNG or WebP, at
/// most `MAX_CUSTOM_ICON` bytes, and none of its chunks is an attachment's.
/// Checked on read, since a synced item may carry any reference.
fn check_reference(item: &Item, r: &AttachmentRef) -> Result<()> {
    if r.size > MAX_CUSTOM_ICON as u64 {
        return Err(Error::InvalidFormat("custom icon too large"));
    }
    if r.mime != "image/png" && r.mime != "image/webp" {
        return Err(Error::InvalidFormat("custom icon type"));
    }
    let taken = attachment_chunks(item);
    let ids = attachment::chunk_ids(r)?;
    if item.attachments.iter().any(|a| a.id == r.id) || ids.iter().any(|id| taken.contains(id)) {
        return Err(Error::InvalidFormat("custom icon reference"));
    }
    Ok(())
}

/// Chunks of the old icon `old` that are safe to delete: never one an
/// attachment of `item` still references.
fn deletable_chunks(item: &Item, old: &AttachmentRef) -> Vec<Id> {
    let taken = attachment_chunks(item);
    // A malformed reference deletes nothing, as in `attachments.rs`.
    attachment::chunk_ids(old)
        .unwrap_or_default()
        .into_iter()
        .filter(|id| !taken.contains(id))
        .collect()
}

impl<S: RecordStore> Repository<S> {
    fn icon_item(&mut self, vault: &Vault, item_id: Id, use_: Use) -> Result<Item> {
        let loaded = self.served(vault, use_)?;
        let (_, rec) = loaded.listed(item_id).ok_or(Error::NotFound)?;
        vault.open_item(rec)
    }

    /// Set (or replace) the custom icon of the item `item_id` of `vault`:
    /// `bytes` is a PNG or WebP of at most `MAX_CUSTOM_ICON` bytes. The item
    /// gets a new version; the previous icon's chunks are deleted once it is
    /// saved. Returns the new reference.
    pub fn set_custom_icon(
        &mut self,
        vault: &Vault,
        item_id: Id,
        mime: &str,
        bytes: &[u8],
    ) -> Result<AttachmentRef> {
        check_icon(mime, bytes)?;
        let mut item = self.icon_item(vault, item_id, Use::Write)?;
        let (reference, records) = attachment::seal_attachment(vault, ICON_NAME, mime, bytes)?;
        let ids: Vec<Id> = records.iter().map(|r| r.id).collect();
        let zone = vault.zone();
        // The previous icon's chunks, never an attachment's.
        let gone = item
            .custom_icon
            .as_ref()
            .map(|old| deletable_chunks(&item, old))
            .unwrap_or_default();
        let written = self.put_chunks(zone, records).and_then(|()| {
            let now = OffsetDateTime::now_utc();
            item.custom_icon = Some(reference.clone());
            item.record(
                now,
                EventKind::FieldChanged {
                    label: "icon".into(),
                },
            );
            item.updated_at = now;
            self.save_item(vault, item)
        });
        if let Err(e) = written {
            self.delete_chunks(zone, &ids);
            return Err(e);
        }
        self.delete_chunks(zone, &gone);
        Ok(reference)
    }

    /// Remove the custom icon of the item and delete its chunks. Nothing to
    /// do (and no new version) when the item has none.
    pub fn clear_custom_icon(&mut self, vault: &Vault, item_id: Id) -> Result<()> {
        let mut item = self.icon_item(vault, item_id, Use::Write)?;
        let Some(old) = item.custom_icon.take() else {
            return Ok(());
        };
        let now = OffsetDateTime::now_utc();
        item.record(
            now,
            EventKind::FieldChanged {
                label: "icon".into(),
            },
        );
        item.updated_at = now;
        let ids = deletable_chunks(&item, &old);
        self.save_item(vault, item)?;
        self.delete_chunks(vault.zone(), &ids);
        Ok(())
    }

    /// The decrypted bytes of the item's custom icon. `NotFound` when none
    /// is set or a chunk is missing (not synced yet). A reference a set
    /// could not have written (too large, not PNG or WebP, pointing at an
    /// attachment) or bytes that do not start like their type are refused
    /// with `InvalidFormat`: a synced item may carry any reference.
    pub fn read_custom_icon(&mut self, vault: &Vault, item_id: Id) -> Result<Zeroizing<Vec<u8>>> {
        self.readable()?;
        let item = self.icon_item(vault, item_id, Use::Read)?;
        let reference = item.custom_icon.clone().ok_or(Error::NotFound)?;
        check_reference(&item, &reference)?;
        self.heal_attachment(vault, &reference)?;
        let store = &self.store;
        let zone = vault.zone();
        let bytes = attachment::open_attachment(vault, &reference, |id| {
            store.get_in(zone, RecordKind::Attachment, id)
        })?;
        check_icon(&reference.mime, &bytes)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::account::{Account, NewAccount};
    use crate::crypto::{KdfParams, random_array};
    use crate::model::{FieldValue, ItemType, new_item};
    use crate::repo::DeviceState;
    use crate::repo::duplicates::ItemKey;
    use crate::store::{MemoryStore, Record};
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

    fn meta(name: &str) -> VaultMeta {
        VaultMeta {
            name: name.into(),
            icon: "key".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        }
    }

    fn fresh() -> (Repository<MemoryStore>, Vault) {
        let n = shared();
        let id = n.account.params.account_id;
        let mut store = MemoryStore::default();
        for (kind, data) in [
            (RecordKind::AccountParams, &n.params_record),
            (RecordKind::Keyset, &n.keyset_record),
        ] {
            store
                .put(Record {
                    id,
                    kind,
                    version: 1,
                    data: data.clone(),
                })
                .unwrap();
        }
        let mut repo =
            Repository::unlock(store, "pw", &n.secret_key, DeviceState::default()).unwrap();
        let v = repo.create_vault(meta("A")).unwrap();
        (repo, v)
    }

    fn login(v: &Vault, title: &str) -> Item {
        let mut item = new_item(ItemType::Login, v.id, title);
        item.field_mut("username").unwrap().value = FieldValue::Text("me".into());
        item
    }

    fn with_item() -> (Repository<MemoryStore>, Vault, Item) {
        let (mut repo, v) = fresh();
        let item = login(&v, "Example");
        repo.save_item(&v, item.clone()).unwrap();
        (repo, v, item)
    }

    fn png(len: usize) -> Vec<u8> {
        let mut b = PNG_MAGIC.to_vec();
        b.resize(len, 7);
        b
    }

    fn webp(len: usize) -> Vec<u8> {
        let mut b = b"RIFF\x00\x00\x00\x00WEBP".to_vec();
        b.resize(len, 9);
        b
    }

    fn stored(repo: &mut Repository<MemoryStore>, v: &Vault, id: Id) -> Item {
        repo.items(v)
            .unwrap()
            .into_iter()
            .find(|i| i.id == id)
            .unwrap()
    }

    fn chunk_present(repo: &Repository<MemoryStore>, r: &AttachmentRef) -> bool {
        attachment::chunk_ids(r).unwrap().iter().all(|id| {
            repo.store
                .get(RecordKind::Attachment, *id)
                .unwrap()
                .is_some()
        })
    }

    fn chunk_gone(repo: &Repository<MemoryStore>, r: &AttachmentRef) -> bool {
        attachment::chunk_ids(r).unwrap().iter().all(|id| {
            repo.store
                .get(RecordKind::Attachment, *id)
                .unwrap()
                .is_none()
        })
    }

    #[test]
    fn set_then_read_round_trip() {
        let (mut repo, v, item) = with_item();
        for (mime, bytes) in [("image/png", png(300)), ("image/webp", webp(300))] {
            let r = repo.set_custom_icon(&v, item.id, mime, &bytes).unwrap();
            assert_eq!(r.mime, mime);
            assert_eq!(r.size, 300);
            let got = stored(&mut repo, &v, item.id);
            assert_eq!(got.custom_icon, Some(r));
            assert!(got.attachments.is_empty());
            assert_eq!(&repo.read_custom_icon(&v, item.id).unwrap()[..], &bytes[..]);
        }
        // The largest allowed size goes through.
        repo.set_custom_icon(&v, item.id, "image/png", &png(MAX_CUSTOM_ICON))
            .unwrap();
    }

    #[test]
    fn replace_deletes_old_chunks() {
        let (mut repo, v, item) = with_item();
        let first = repo
            .set_custom_icon(&v, item.id, "image/png", &png(100))
            .unwrap();
        assert!(chunk_present(&repo, &first));
        let second = repo
            .set_custom_icon(&v, item.id, "image/webp", &webp(120))
            .unwrap();
        assert_ne!(first.id, second.id);
        assert!(chunk_gone(&repo, &first));
        assert!(chunk_present(&repo, &second));
        assert_eq!(
            stored(&mut repo, &v, item.id).custom_icon,
            Some(second.clone())
        );
        assert_eq!(
            &repo.read_custom_icon(&v, item.id).unwrap()[..],
            &webp(120)[..]
        );
    }

    #[test]
    fn clear_deletes_chunks() {
        let (mut repo, v, item) = with_item();
        let r = repo
            .set_custom_icon(&v, item.id, "image/png", &png(100))
            .unwrap();
        repo.clear_custom_icon(&v, item.id).unwrap();
        assert!(chunk_gone(&repo, &r));
        assert_eq!(stored(&mut repo, &v, item.id).custom_icon, None);
        assert!(matches!(
            repo.read_custom_icon(&v, item.id),
            Err(Error::NotFound)
        ));
        // Clearing again is a no-op.
        repo.clear_custom_icon(&v, item.id).unwrap();
    }

    #[test]
    fn too_large_refused() {
        let (mut repo, v, item) = with_item();
        let e = repo
            .set_custom_icon(&v, item.id, "image/png", &png(MAX_CUSTOM_ICON + 1))
            .unwrap_err();
        assert!(
            matches!(e, Error::InvalidFormat("custom icon too large")),
            "{e:?}"
        );
        assert_eq!(stored(&mut repo, &v, item.id).custom_icon, None);
    }

    #[test]
    fn wrong_mime_refused() {
        let (mut repo, v, item) = with_item();
        let e = repo
            .set_custom_icon(&v, item.id, "image/jpeg", &png(100))
            .unwrap_err();
        assert!(
            matches!(e, Error::InvalidFormat("custom icon type")),
            "{e:?}"
        );
    }

    #[test]
    fn magic_mismatch_refused() {
        let (mut repo, v, item) = with_item();
        for (mime, bytes) in [
            ("image/webp", png(100)),
            ("image/png", webp(100)),
            ("image/png", b"not an image".to_vec()),
        ] {
            let e = repo.set_custom_icon(&v, item.id, mime, &bytes).unwrap_err();
            assert!(
                matches!(e, Error::InvalidFormat("custom icon type")),
                "{e:?}"
            );
        }
        assert_eq!(stored(&mut repo, &v, item.id).custom_icon, None);
    }

    #[test]
    fn read_when_unset_is_not_found() {
        let (mut repo, v, item) = with_item();
        assert!(matches!(
            repo.read_custom_icon(&v, item.id),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn merge_keeps_it() {
        let (mut repo, a) = fresh();
        let b = repo.create_vault(meta("B")).unwrap();
        let primary = login(&a, "Primary");
        let other = login(&b, "Other");
        repo.save_item(&a, primary.clone()).unwrap();
        repo.save_item(&b, other.clone()).unwrap();
        let icon = repo
            .set_custom_icon(&b, other.id, "image/png", &png(100))
            .unwrap();
        let key = |i: &Item| ItemKey {
            vault_id: i.vault_id,
            item_id: i.id,
        };
        let merged = repo
            .merge_duplicates(key(&primary), &[key(&other)], "merged")
            .unwrap();
        let mine = merged.custom_icon.clone().unwrap();
        // Its own copy of the file, not the folded item's reference.
        assert_ne!(mine.id, icon.id);
        assert_eq!(
            (mine.size, mine.mime.as_str()),
            (icon.size, icon.mime.as_str())
        );
        assert_eq!(stored(&mut repo, &a, primary.id).custom_icon, Some(mine));
        assert_eq!(
            &repo.read_custom_icon(&a, primary.id).unwrap()[..],
            &png(100)[..]
        );
        // Deleting the archived copy leaves the primary's icon alone.
        repo.delete_item(&b, other.id).unwrap();
        assert_eq!(
            &repo.read_custom_icon(&a, primary.id).unwrap()[..],
            &png(100)[..]
        );
    }

    /// Store `reference` as the item's icon without any check, as a synced
    /// item from another device could.
    fn forge(repo: &mut Repository<MemoryStore>, v: &Vault, id: Id, reference: AttachmentRef) {
        let mut item = stored(repo, v, id);
        item.custom_icon = Some(reference);
        repo.save_item(v, item).unwrap();
    }

    #[test]
    fn read_refuses_oversized_reference() {
        let (mut repo, v, item) = with_item();
        let mut r = repo
            .set_custom_icon(&v, item.id, "image/png", &png(100))
            .unwrap();
        r.size = MAX_CUSTOM_ICON as u64 + 1;
        forge(&mut repo, &v, item.id, r);
        let e = repo.read_custom_icon(&v, item.id).unwrap_err();
        assert!(
            matches!(e, Error::InvalidFormat("custom icon too large")),
            "{e:?}"
        );
    }

    #[test]
    fn read_refuses_other_mime() {
        let (mut repo, v, item) = with_item();
        let mut r = repo
            .set_custom_icon(&v, item.id, "image/png", &png(100))
            .unwrap();
        r.mime = "image/svg+xml".into();
        forge(&mut repo, &v, item.id, r);
        let e = repo.read_custom_icon(&v, item.id).unwrap_err();
        assert!(
            matches!(e, Error::InvalidFormat("custom icon type")),
            "{e:?}"
        );
    }

    #[test]
    fn read_checks_magic_of_decrypted_bytes() {
        let (mut repo, v, item) = with_item();
        let mut r = repo
            .set_custom_icon(&v, item.id, "image/png", &png(100))
            .unwrap();
        // A PNG file declared as WebP.
        r.mime = "image/webp".into();
        forge(&mut repo, &v, item.id, r);
        let e = repo.read_custom_icon(&v, item.id).unwrap_err();
        assert!(
            matches!(e, Error::InvalidFormat("custom icon type")),
            "{e:?}"
        );
    }

    #[test]
    fn attachment_alias_refused_and_never_deleted() {
        let (mut repo, v, item) = with_item();
        let doc = repo
            .add_attachment(&v, item.id, "scan.png", "image/png", &png(100))
            .unwrap();
        forge(&mut repo, &v, item.id, doc.clone());
        let e = repo.read_custom_icon(&v, item.id).unwrap_err();
        assert!(
            matches!(e, Error::InvalidFormat("custom icon reference")),
            "{e:?}"
        );
        // Clearing the alias keeps the attachment's file.
        repo.clear_custom_icon(&v, item.id).unwrap();
        assert!(chunk_present(&repo, &doc));
        assert_eq!(
            &repo.read_attachment(&v, item.id, doc.id).unwrap()[..],
            &png(100)[..]
        );
        // Replacing an alias keeps it too.
        forge(&mut repo, &v, item.id, doc.clone());
        repo.set_custom_icon(&v, item.id, "image/png", &png(120))
            .unwrap();
        assert!(chunk_present(&repo, &doc));
        assert_eq!(
            &repo.read_custom_icon(&v, item.id).unwrap()[..],
            &png(120)[..]
        );
    }

    #[test]
    fn alias_of_a_later_chunk_refused() {
        let (mut repo, v, item) = with_item();
        let big = vec![1u8; attachment::CHUNK + 10];
        let doc = repo
            .add_attachment(&v, item.id, "big.bin", "application/octet-stream", &big)
            .unwrap();
        let ids = attachment::chunk_ids(&doc).unwrap();
        assert!(ids.len() > 1, "needs a second chunk");
        let r = AttachmentRef {
            id: ids[1],
            name: ICON_NAME.into(),
            size: 100,
            mime: "image/png".into(),
        };
        forge(&mut repo, &v, item.id, r);
        let e = repo.read_custom_icon(&v, item.id).unwrap_err();
        assert!(
            matches!(e, Error::InvalidFormat("custom icon reference")),
            "{e:?}"
        );
        repo.clear_custom_icon(&v, item.id).unwrap();
        assert!(chunk_present(&repo, &doc));
    }

    fn chunk_count(repo: &Repository<MemoryStore>) -> usize {
        repo.store.list(RecordKind::Attachment).unwrap().len()
    }

    #[test]
    fn move_item_keeps_custom_icon_readable() {
        let (mut repo, a, item) = with_item();
        let b = repo.create_vault(meta("B")).unwrap();
        repo.set_custom_icon(&a, item.id, "image/png", &png(200))
            .unwrap();
        repo.move_item(item.id, &a, &b).unwrap();
        assert_eq!(
            &repo.read_custom_icon(&b, item.id).unwrap()[..],
            &png(200)[..]
        );
    }

    #[test]
    fn delete_item_removes_custom_icon_chunks() {
        let (mut repo, v, item) = with_item();
        repo.set_custom_icon(&v, item.id, "image/png", &png(200))
            .unwrap();
        assert_eq!(chunk_count(&repo), 1);
        repo.delete_item(&v, item.id).unwrap();
        assert_eq!(chunk_count(&repo), 0);
    }

    #[test]
    fn delete_vault_removes_custom_icon_chunks() {
        let (mut repo, _a) = fresh();
        let b = repo.create_vault(meta("B")).unwrap();
        let item = login(&b, "Doomed");
        repo.save_item(&b, item.clone()).unwrap();
        repo.set_custom_icon(&b, item.id, "image/png", &png(200))
            .unwrap();
        repo.trash_item(&b, item.id).unwrap();
        repo.delete_vault(&b).unwrap();
        assert_eq!(chunk_count(&repo), 0);
    }

    #[test]
    fn reseal_vault_carries_custom_icon_chunks() {
        let (mut repo, a, item) = with_item();
        repo.set_custom_icon(&a, item.id, "image/png", &png(200))
            .unwrap();
        let (to, _, _) = Vault::new_shared(a.id, a.meta.clone()).unwrap();
        let loaded = repo.served(&a, Use::Read).unwrap();
        let resealed = repo.reseal_vault(&a, &to, &loaded).unwrap();
        assert_eq!(resealed.attachments.len(), 1);
        let (moved, _) = &resealed.attachments[0];
        let icon = stored(&mut repo, &a, item.id).custom_icon.unwrap();
        let bytes = attachment::open_attachment(&to, &icon, |id| {
            Ok((id == moved.id).then(|| moved.clone()))
        })
        .unwrap();
        assert_eq!(&bytes[..], &png(200)[..]);
    }
}
