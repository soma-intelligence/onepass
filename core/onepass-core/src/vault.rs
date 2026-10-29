//! Vaults and encrypted items, one random key per item.
//!
//! A vault owns a symmetric key, delivered to the account as a KEM envelope.
//! Each item has its own random key, wrapped by the vault key. The item
//! plaintext carries the record version and the full item (including its
//! `vault_id`), so a swapped version or a cross-vault replay is caught on open.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account::Account;
use crate::crypto::{Aad, BlobKind, SymmetricKey, open, seal, unwrap_key, wrap_key};
use crate::model::events::{EventKind, ItemTrailer};
use crate::model::usage::UsageTrailer;
use crate::model::{Item, validate};
use crate::{Error, Id, IntegrityError, Result};

const SCHEMA: u16 = crate::format::ITEM_SCHEMA;

/// Display settings of a vault, sealed with the vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    pub name: String,
    pub icon: String,
    pub color: String,
    pub travel_safe: bool,
    pub mcp_access: bool,
}

/// An unlocked vault.
pub struct Vault {
    pub id: Id,
    pub meta: VaultMeta,
    key: SymmetricKey,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("id", &self.id)
            .field("key", &"**")
            .finish_non_exhaustive()
    }
}

/// A stored item: opaque blobs plus the cleartext id and version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRecord {
    pub item_id: Id,
    pub version: u64,
    pub wrapped_key: Vec<u8>,
    pub blob: Vec<u8>,
}

impl ItemRecord {
    /// Decode an item record body, which may come from a hostile store: the
    /// whole buffer, trailing bytes refused (`InvalidFormat("item record")`).
    /// Nothing is verified here: the manifest and `Vault::open_item` do.
    pub fn decode(bytes: &[u8]) -> Result<ItemRecord> {
        match postcard::take_from_bytes(bytes) {
            Ok((rec, [])) => Ok(rec),
            _ => Err(Error::InvalidFormat("item record")),
        }
    }
}

/// KEM context of a vault key envelope: `"vault:" || vault_id` (22 bytes).
pub(crate) fn kem_context(vault_id: Id) -> Vec<u8> {
    let mut c = b"vault:".to_vec();
    c.extend_from_slice(&vault_id.0);
    c
}

fn meta_aad(vault_id: Id) -> Aad {
    Aad {
        blob_id: vault_id,
        vault_id: Some(vault_id),
        schema: SCHEMA,
    }
}

fn item_aad(item_id: Id, vault_id: Id) -> Aad {
    Aad {
        blob_id: item_id,
        vault_id: Some(vault_id),
        schema: SCHEMA,
    }
}

/// Postcard of `(version, item)` in a buffer wiped on drop, sized up front so
/// no reallocation leaves copies of the plaintext behind. An item with
/// events gets them after, as an `ItemTrailer` (see `model::events`), and
/// an item with usage gets an `ItemTrailer` (even empty) then a
/// `UsageTrailer` (see `model::usage`): an item without either is written
/// exactly as before events existed.
fn encode_item(version: u64, item: &Item) -> Result<Zeroizing<Vec<u8>>> {
    const BAD: Error = Error::InvalidFormat("item");
    let value = (version, item);
    let has_usage = !item.usage.is_empty() || !item.usage_forgotten.is_empty();
    let trailer = (!item.events.is_empty() || has_usage).then(|| ItemTrailer {
        events: item.events.clone(),
    });
    let usage = has_usage.then(|| item.usage_trailer());
    let head = postcard::experimental::serialized_size(&value).map_err(|_| BAD)?;
    let mid = match &trailer {
        Some(t) => postcard::experimental::serialized_size(t).map_err(|_| BAD)?,
        None => 0,
    };
    let tail = match &usage {
        Some(u) => postcard::experimental::serialized_size(u).map_err(|_| BAD)?,
        None => 0,
    };
    let mut buf = Zeroizing::new(vec![0u8; head + mid + tail]);
    let (first, rest) = buf.split_at_mut(head);
    let (second, third) = rest.split_at_mut(mid);
    postcard::to_slice(&value, first).map_err(|_| BAD)?;
    if let Some(t) = &trailer {
        postcard::to_slice(t, second).map_err(|_| BAD)?;
    }
    if let Some(u) = &usage {
        postcard::to_slice(u, third).map_err(|_| BAD)?;
    }
    Ok(buf)
}

/// `(version, item)` then, when bytes remain, an `ItemTrailer` and a
/// `UsageTrailer`. The item itself is strict. The trailers are history and
/// fill memory only: one this build cannot read (a variant added later, a
/// further trailer, damage, more than `MAX_EVENTS` events or `MAX_SITES`
/// sites or tombstones)
/// leaves the item without it instead of locking it, and with it the whole
/// vault listing, out. An unreadable `ItemTrailer` hides the usage too: its
/// end is unknown. The bytes stay inside the sealed blob, so nobody without
/// the item key can put anything there.
fn decode_item(plain: &[u8]) -> Result<(u64, Item)> {
    const BAD: Error = Error::InvalidFormat("item");
    let ((version, mut item), rest): ((u64, Item), &[u8]) =
        postcard::take_from_bytes(plain).map_err(|_| BAD)?;
    if !rest.is_empty()
        && let Ok((trailer, later)) = postcard::take_from_bytes::<ItemTrailer>(rest)
    {
        if (1..=crate::model::events::MAX_EVENTS).contains(&trailer.events.len()) {
            item.events = trailer.events;
        }
        if !later.is_empty()
            && let Ok((usage, _beyond)) = postcard::take_from_bytes::<UsageTrailer>(later)
            && usage.sites.len() <= crate::model::usage::MAX_SITES
            && usage.forgotten.len() <= crate::model::usage::MAX_SITES
        {
            item.set_usage_trailer(usage);
        }
    }
    Ok((version, item))
}

impl Vault {
    /// Create a vault. Returns the vault, the key envelope for the account
    /// (KEM context `"vault:" || vault_id`) and the sealed meta blob.
    pub fn create(account: &Account, meta: VaultMeta) -> Result<(Vault, Vec<u8>, Vec<u8>)> {
        let id = Id::new();
        let key = SymmetricKey::generate()?;
        let envelope = wrap_key(&account.params.kem_pub, &key, &kem_context(id))?;
        let meta_blob = seal_meta(&key, id, &meta)?;
        Ok((Vault { id, meta, key }, envelope, meta_blob))
    }

    /// Open a vault from its stored envelope and meta blob.
    pub fn open(account: &Account, id: Id, key_envelope: &[u8], meta_blob: &[u8]) -> Result<Vault> {
        let key = unwrap_key(&account.keyset().kem, key_envelope, &kem_context(id))?;
        let plain = open(&key, BlobKind::VaultMeta, &meta_aad(id), meta_blob)?;
        let meta: VaultMeta = match postcard::take_from_bytes(&plain) {
            Ok((meta, [])) => meta,
            _ => return Err(Error::InvalidFormat("vault meta")),
        };
        Ok(Vault { id, meta, key })
    }

    /// The vault key. The manifest of the vault is sealed with it.
    pub(crate) fn key(&self) -> &SymmetricKey {
        &self.key
    }

    /// Validate and encrypt an item under a fresh random item key. The
    /// version is part of the sealed plaintext and checked again on open.
    pub fn seal_item(&self, item: &Item, version: u64) -> Result<ItemRecord> {
        validate(item)?;
        if item.vault_id != self.id {
            return Err(IntegrityError::WrongContext.into());
        }
        let item_key = SymmetricKey::generate()?;
        self.seal_with(&item_key, item, version)
    }

    fn seal_with(&self, item_key: &SymmetricKey, item: &Item, version: u64) -> Result<ItemRecord> {
        let aad = item_aad(item.id, self.id);
        let wrapped_key = seal(self.key(), BlobKind::ItemKey, &aad, item_key.expose())?;
        let plain = encode_item(version, item)?;
        let blob = seal(item_key, BlobKind::Item, &aad, &plain)?;
        Ok(ItemRecord {
            item_id: item.id,
            version,
            wrapped_key,
            blob,
        })
    }

    fn unwrap_item_key(&self, rec: &ItemRecord) -> Result<SymmetricKey> {
        let plain = open(
            self.key(),
            BlobKind::ItemKey,
            &item_aad(rec.item_id, self.id),
            &rec.wrapped_key,
        )?;
        if plain.len() != 32 {
            return Err(Error::InvalidFormat("item key length"));
        }
        // Straight into the key buffer: no [u8; 32] temporary.
        let mut key = SymmetricKey::zeroed();
        key.bytes_mut().copy_from_slice(&plain);
        Ok(key)
    }

    fn open_with(&self, item_key: &SymmetricKey, rec: &ItemRecord) -> Result<Item> {
        let plain = open(
            item_key,
            BlobKind::Item,
            &item_aad(rec.item_id, self.id),
            &rec.blob,
        )?;
        let (version, item) = decode_item(&plain)?;
        if version != rec.version || item.vault_id != self.id || item.id != rec.item_id {
            return Err(IntegrityError::WrongContext.into());
        }
        Ok(item)
    }

    /// Decrypt an item. Refuses a record whose inner version, item id or
    /// vault id differ from the record and this vault.
    pub fn open_item(&self, rec: &ItemRecord) -> Result<Item> {
        let item_key = self.unwrap_item_key(rec)?;
        self.open_with(&item_key, rec)
    }

    /// Move an item to another vault. The item key is unchanged and is only
    /// re-wrapped under the target vault key. The item blob is re-sealed too,
    /// because `vault_id` is part of both the AAD and the plaintext.
    pub fn move_item(&self, to: &Vault, rec: &ItemRecord, new_version: u64) -> Result<ItemRecord> {
        let item_key = self.unwrap_item_key(rec)?;
        let mut item = self.open_with(&item_key, rec)?;
        item.vault_id = to.id;
        item.record(
            time::OffsetDateTime::now_utc(),
            // The source vault's name stays out: members of the target vault
            // read this item, and "Santé" or "Perso" is not theirs to see.
            EventKind::Moved {
                from: String::new(),
                to: to.meta.name.clone(),
            },
        );
        to.seal_with(&item_key, &item, new_version)
    }
}

fn seal_meta(key: &SymmetricKey, id: Id, meta: &VaultMeta) -> Result<Vec<u8>> {
    let plain = Zeroizing::new(
        postcard::to_allocvec(meta).map_err(|_| Error::InvalidFormat("vault meta"))?,
    );
    seal(key, BlobKind::VaultMeta, &meta_aad(id), &plain)
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::account::NewAccount;
    use crate::crypto::{KdfParams, random_array};
    use crate::model::{FieldValue, ItemType, new_item};

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
            travel_safe: true,
            mcp_access: false,
        }
    }

    fn vault(name: &str) -> (Vault, Vec<u8>, Vec<u8>) {
        Vault::create(&shared().account, meta(name)).unwrap()
    }

    fn login(v: &Vault) -> Item {
        let mut item = new_item(ItemType::Login, v.id, "Example");
        item.field_mut("username").unwrap().value = FieldValue::Text("alice".into());
        item
    }

    #[test]
    fn vault_create_open_roundtrip() {
        let (v, env, mb) = vault("Perso");
        let o = Vault::open(&shared().account, v.id, &env, &mb).unwrap();
        assert_eq!(o.id, v.id);
        assert_eq!(o.meta, v.meta);
        // The envelope is bound to the vault id.
        assert!(Vault::open(&shared().account, Id::new(), &env, &mb).is_err());
    }

    #[test]
    fn seal_open_item() {
        let (v, _, _) = vault("A");
        let item = login(&v);
        let rec = v.seal_item(&item, 1).unwrap();
        assert_eq!(rec.item_id, item.id);
        assert_eq!(rec.version, 1);
        assert_eq!(v.open_item(&rec).unwrap(), item);
        // A fresh item key per seal.
        let rec2 = v.seal_item(&item, 1).unwrap();
        assert_ne!(rec.wrapped_key, rec2.wrapped_key);
    }

    #[test]
    fn events_ride_in_a_trailer_and_old_records_still_open() {
        let (v, _, _) = vault("A");
        let mut item = login(&v);
        // Without events the plaintext is exactly the pre-events encoding.
        let plain = encode_item(3, &item).unwrap();
        assert_eq!(
            &plain[..],
            &postcard::to_allocvec(&(3u64, &item)).unwrap()[..]
        );
        assert_eq!(decode_item(&plain).unwrap(), (3, item.clone()));
        item.record(item.created_at, EventKind::Created);
        item.record(item.created_at, EventKind::Archived);
        let rec = v.seal_item(&item, 1).unwrap();
        let opened = v.open_item(&rec).unwrap();
        assert_eq!(opened.events, item.events);
        assert_eq!(opened, item);
        // A trailer this build cannot read (empty, an unknown event kind)
        // opens the item without its history; a later trailer after a
        // readable one is skipped.
        let mut bare = item.clone();
        bare.events.clear();
        let mut odd = postcard::to_allocvec(&(1u64, &item)).unwrap();
        odd.push(0);
        assert_eq!(decode_item(&odd).unwrap(), (1, bare.clone()));
        odd.pop();
        odd.extend([1, 0xff]);
        assert_eq!(decode_item(&odd).unwrap(), (1, bare));
        let mut later = encode_item(4, &item).unwrap().to_vec();
        later.extend([7, 7, 7]);
        assert_eq!(decode_item(&later).unwrap(), (4, item.clone()));
        // A damaged item itself is still refused.
        let whole = postcard::to_allocvec(&(1u64, &item)).unwrap();
        assert!(decode_item(&whole[..whole.len() / 2]).is_err());
    }

    fn with_usage(mut item: Item) -> Item {
        use crate::fill_plan::context::FieldRole;
        use crate::model::usage::{SiteUsage, StepKind, form_shape_hash};
        item.usage = vec![SiteUsage {
            site: "example.com".into(),
            form_shape_hash: form_shape_hash(&[FieldRole::Username, FieldRole::CurrentPassword]),
            intent: crate::fill_plan::intent::Intent::Login,
            step_seq: vec![StepKind::Fill, StepKind::Otp],
            count: 2,
            last_at: item.created_at,
        }];
        item
    }

    #[test]
    fn item_without_usage_encodes_as_before() {
        let (v, _, _) = vault("A");
        let mut item = login(&v);
        assert_eq!(
            &encode_item(3, &item).unwrap()[..],
            &postcard::to_allocvec(&(3u64, &item)).unwrap()[..]
        );
        item.record(item.created_at, EventKind::Created);
        let mut expected = postcard::to_allocvec(&(3u64, &item)).unwrap();
        expected.extend(
            postcard::to_allocvec(&ItemTrailer {
                events: item.events.clone(),
            })
            .unwrap(),
        );
        assert_eq!(&encode_item(3, &item).unwrap()[..], &expected[..]);
    }

    #[test]
    fn usage_roundtrips_without_events() {
        let (v, _, _) = vault("A");
        let item = with_usage(login(&v));
        let plain = encode_item(1, &item).unwrap();
        // An empty `ItemTrailer` holds the first place.
        let (_, rest): ((u64, Item), &[u8]) = postcard::take_from_bytes(&plain).unwrap();
        let (events, rest): (ItemTrailer, &[u8]) = postcard::take_from_bytes(rest).unwrap();
        assert!(events.events.is_empty());
        let (usage, rest): (UsageTrailer, &[u8]) = postcard::take_from_bytes(rest).unwrap();
        assert_eq!((usage.sites, rest), (item.usage.clone(), &[][..]));
        let opened = v.open_item(&v.seal_item(&item, 1).unwrap()).unwrap();
        assert_eq!(opened, item);
        assert!(opened.events.is_empty());
    }

    #[test]
    fn usage_tombstones_roundtrip_alone() {
        let (v, _, _) = vault("A");
        let mut item = login(&v);
        item.usage_forgotten = vec![("example.com".into(), item.created_at)];
        let opened = v.open_item(&v.seal_item(&item, 1).unwrap()).unwrap();
        assert_eq!(opened.usage_forgotten, item.usage_forgotten);
        assert_eq!(opened, item);
    }

    #[test]
    fn usage_roundtrips_with_events() {
        let (v, _, _) = vault("A");
        let mut item = with_usage(login(&v));
        item.usage_forgotten = vec![("old.example".into(), item.created_at)];
        item.record(item.created_at, EventKind::Created);
        let opened = v.open_item(&v.seal_item(&item, 1).unwrap()).unwrap();
        assert_eq!(opened.events, item.events);
        assert_eq!(opened.usage, item.usage);
        assert_eq!(opened, item);
    }

    #[test]
    fn unreadable_usage_trailer_opens_item_without_usage() {
        let (v, _, _) = vault("A");
        let mut item = login(&v);
        item.record(item.created_at, EventKind::Created);
        let mut head = encode_item(1, &item).unwrap().to_vec();
        // Damaged: one site whose name length runs past the end.
        let mut bad = head.clone();
        bad.extend([1, 0xff]);
        assert_eq!(decode_item(&bad).unwrap(), (1, item.clone()));
        // Too many sites for this build.
        let site = with_usage(item.clone()).usage.remove(0);
        let many = UsageTrailer {
            sites: vec![site; crate::model::usage::MAX_SITES + 1],
            forgotten: vec![],
        };
        let mut over = head.clone();
        over.extend(postcard::to_allocvec(&many).unwrap());
        assert_eq!(decode_item(&over).unwrap(), (1, item.clone()));
        // Too many tombstones too.
        let gone = UsageTrailer {
            sites: vec![],
            forgotten: vec![("a.com".into(), item.created_at); crate::model::usage::MAX_SITES + 1],
        };
        head.extend(postcard::to_allocvec(&gone).unwrap());
        assert_eq!(decode_item(&head).unwrap(), (1, item));
    }

    #[test]
    fn usage_not_in_item_serde_json() {
        let (v, _, _) = vault("A");
        let item = with_usage(login(&v));
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("form_shape_hash"));
        assert!(!json.contains("example.com"));
    }

    #[test]
    fn move_records_only_the_target_vault_name() {
        let (a, _, _) = vault("Perso");
        let (b, _, _) = vault("Projet Atlas");
        let rec = a.seal_item(&login(&a), 1).unwrap();
        let moved = b.open_item(&a.move_item(&b, &rec, 1).unwrap()).unwrap();
        assert_eq!(
            moved.events.last().unwrap().kind,
            EventKind::Moved {
                from: String::new(),
                to: "Projet Atlas".into()
            }
        );
    }

    #[test]
    fn item_from_another_vault_is_refused() {
        let (a, _, _) = vault("A");
        let (b, _, _) = vault("B");
        let rec = a.seal_item(&login(&a), 1).unwrap();
        assert!(matches!(b.open_item(&rec), Err(Error::Integrity(_))));
        // An item that names another vault is not sealed either.
        assert!(matches!(
            b.seal_item(&login(&a), 1),
            Err(Error::Integrity(IntegrityError::WrongContext))
        ));
    }

    #[test]
    fn version_swap_is_refused() {
        let (v, _, _) = vault("A");
        let mut rec = v.seal_item(&login(&v), 1).unwrap();
        rec.version = 2;
        assert!(matches!(
            v.open_item(&rec),
            Err(Error::Integrity(IntegrityError::WrongContext))
        ));
    }

    #[test]
    fn swapped_item_id_is_refused() {
        let (v, _, _) = vault("A");
        let mut rec = v.seal_item(&login(&v), 1).unwrap();
        rec.item_id = Id::new();
        assert!(matches!(v.open_item(&rec), Err(Error::Integrity(_))));
    }

    #[test]
    fn move_item_keeps_content_and_changes_vault() {
        let (a, _, _) = vault("A");
        let (b, _, _) = vault("B");
        let item = login(&a);
        let rec = a.seal_item(&item, 1).unwrap();
        let moved = a.move_item(&b, &rec, 2).unwrap();
        assert_eq!(moved.version, 2);
        let out = b.open_item(&moved).unwrap();
        assert_eq!(out.vault_id, b.id);
        let mut expected = item;
        expected.vault_id = b.id;
        expected.events.clone_from(&out.events);
        assert_eq!(out, expected);
        assert!(a.open_item(&moved).is_err());
    }

    #[test]
    fn invalid_item_is_not_sealed() {
        let (v, _, _) = vault("A");
        let item = new_item(ItemType::CreditCard, v.id, "Visa");
        assert!(matches!(v.seal_item(&item, 1), Err(Error::Validation(_))));
    }

    #[test]
    fn unreadable_item_history_opens_but_trailing_meta_bytes_are_refused() {
        let (v, env, _) = vault("A");
        let item = login(&v);
        let rec = v.seal_item(&item, 1).unwrap();
        let item_key = v.unwrap_item_key(&rec).unwrap();
        let mut plain = encode_item(1, &item).unwrap().to_vec();
        plain.push(0);
        let bad = ItemRecord {
            blob: seal(&item_key, BlobKind::Item, &item_aad(item.id, v.id), &plain).unwrap(),
            ..rec
        };
        // Item history is best effort: the item opens, without events.
        assert_eq!(v.open_item(&bad).unwrap(), item);

        let mut meta = postcard::to_allocvec(&v.meta).unwrap();
        meta.push(0);
        let blob = seal(v.key(), BlobKind::VaultMeta, &meta_aad(v.id), &meta).unwrap();
        assert_eq!(
            Vault::open(&shared().account, v.id, &env, &blob).err(),
            Some(Error::InvalidFormat("vault meta"))
        );
    }

    #[test]
    fn debug_hides_the_key() {
        let (v, _, _) = vault("A");
        assert!(format!("{v:?}").contains("**"));
    }
}
