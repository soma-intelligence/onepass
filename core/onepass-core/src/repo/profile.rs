//! The account profile: the display name and photo every device of the
//! account shows. It syncs as a hidden item (`PROFILE_TAG`) of a vault, so
//! it is sealed, bound to the manifest and merged like any item: the newest
//! `updated_at` wins.
//!
//! - The item id is derived from the account id (`profile_item_id`): two
//!   devices that publish a first profile before seeing each other's write
//!   the same item, and the rebase keeps the newest.
//! - It is written in the vault that already holds it, else in the first
//!   vault by id, the same on every device.
//! - `Repository::items` never lists it, so no listing, search, export,
//!   Watchtower check, MCP tool or browser fill sees it.
//! - Limits are those of the pairing profile card: 64 characters for the
//!   name (control characters dropped), 256 KiB for the photo.
//! - It may name a main identity and a main card (`ItemRef`), as two more
//!   fields of its section: a build that reads the name and photo only
//!   ignores them, and a profile written before them reads as naming none.
//!   A build that knows only the name and photo drops them when it writes.

use data_encoding::BASE64;
use time::OffsetDateTime;

use super::{Repository, Use};
use crate::error::ValidationError;
use crate::model::{Field, FieldType, FieldValue, Item, ItemType, PROFILE_TAG, Section, new_item};
use crate::pairing::messages::{MAX_PROFILE_NAME_CHARS, MAX_PROFILE_PHOTO_BYTES};
use crate::store::RecordStore;
use crate::{Error, Id, Result};

const TITLE: &str = "Profile";
const SECTION: &str = "profile";
const NAME: &str = "name";
const PHOTO: &str = "photo";
const MAIN_IDENTITY: &str = "main_identity";
const MAIN_CARD: &str = "main_card";

/// An item of a vault, as the profile names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItemRef {
    pub vault_id: Id,
    pub item_id: Id,
}

impl ItemRef {
    /// `<vault id>/<item id>`, as stored in the profile.
    fn encode(&self) -> String {
        format!("{}/{}", self.vault_id, self.item_id)
    }

    /// `None` for an empty or unreadable value.
    fn decode(s: &str) -> Option<ItemRef> {
        let (vault, item) = s.split_once('/')?;
        Some(ItemRef {
            vault_id: vault.parse().ok()?,
            item_id: item.parse().ok()?,
        })
    }
}

/// The account profile as every device shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    /// JPEG bytes, empty for no photo.
    pub photo: Vec<u8>,
    /// The identity the app shows first, if the user chose one. It may
    /// name an item since deleted or moved: the caller checks.
    pub main_identity: Option<ItemRef>,
    /// The credit card the app shows first, as `main_identity`.
    pub main_card: Option<ItemRef>,
    pub updated_at: OffsetDateTime,
}

/// The id of the account's profile item: the first 16 bytes of
/// SHA-256("onepass.profile.v1" || account id).
pub fn profile_item_id(account_id: Id) -> Id {
    let mut input = b"onepass.profile.v1".to_vec();
    input.extend_from_slice(&account_id.0);
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &input);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest.as_ref()[..16]);
    Id(id)
}

fn invalid(field: &str, reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: field.to_owned(),
        reason,
    })
}

fn text(item: &Item, id: &str) -> String {
    match item.field(id).map(|f| &f.value) {
        Some(FieldValue::Text(s)) => s.clone(),
        _ => String::new(),
    }
}

fn read(item: &Item) -> Profile {
    Profile {
        name: text(item, NAME),
        photo: BASE64
            .decode(text(item, PHOTO).as_bytes())
            .unwrap_or_default(),
        main_identity: ItemRef::decode(&text(item, MAIN_IDENTITY)),
        main_card: ItemRef::decode(&text(item, MAIN_CARD)),
        updated_at: item.updated_at,
    }
}

fn field(id: &str, value: String) -> Field {
    Field {
        id: id.into(),
        label: id.into(),
        kind: FieldType::Text,
        value: FieldValue::Text(value),
        required: false,
        repeatable: false,
        autofill: false,
    }
}

impl<S: RecordStore> Repository<S> {
    /// The profile items of the readable vaults, newest first.
    fn profile_items(&mut self) -> Result<Vec<Item>> {
        let id = profile_item_id(self.account.params.account_id);
        let mut found = Vec::new();
        for vault in self.personal_vaults()? {
            if let Some(item) = self.all_items(&vault)?.into_iter().find(|i| i.id == id) {
                found.push(item);
            }
        }
        found.sort_by_key(|i| std::cmp::Reverse(i.updated_at));
        Ok(found)
    }

    /// The account profile, `None` until a device sets one.
    pub fn profile(&mut self) -> Result<Option<Profile>> {
        Ok(self.profile_items()?.first().map(read))
    }

    /// Set the account profile, dated `now`. A name over 64 characters or
    /// a photo over 256 KiB is refused (`Validation`); control characters
    /// are dropped from the name. An empty name and photo clear it.
    pub fn set_profile(
        &mut self,
        name: &str,
        photo: &[u8],
        now: OffsetDateTime,
    ) -> Result<Profile> {
        let name: String = name.chars().filter(|c| !c.is_control()).collect();
        if name.chars().count() > MAX_PROFILE_NAME_CHARS {
            return Err(invalid(NAME, "is too long"));
        }
        if photo.len() > MAX_PROFILE_PHOTO_BYTES {
            return Err(invalid(PHOTO, "is too large"));
        }
        let existing = self.profile_items()?;
        let (main_identity, main_card) = existing
            .first()
            .map(read)
            .map_or((None, None), |p| (p.main_identity, p.main_card));
        self.write_profile(existing, &name, photo, main_identity, main_card, now)
    }

    /// Name the main identity and the main card of the profile, dated
    /// `now`, the name and photo left as they are (`None` names none). Each
    /// must be a live item of a readable vault (`NotFound`, also for a
    /// trashed one) of the right type: an Identity, a CreditCard
    /// (`Validation` otherwise).
    pub fn set_profile_main(
        &mut self,
        identity: Option<ItemRef>,
        card: Option<ItemRef>,
        now: OffsetDateTime,
    ) -> Result<Profile> {
        if let Some(r) = identity {
            self.check_main(r, ItemType::Identity, MAIN_IDENTITY)?;
        }
        if let Some(r) = card {
            self.check_main(r, ItemType::CreditCard, MAIN_CARD)?;
        }
        let existing = self.profile_items()?;
        let (name, photo) = existing
            .first()
            .map(read)
            .map_or((String::new(), Vec::new()), |p| (p.name, p.photo));
        self.write_profile(existing, &name, &photo, identity, card, now)
    }

    fn check_main(&mut self, r: ItemRef, kind: ItemType, field: &str) -> Result<()> {
        let vault = self
            .vaults()?
            .into_iter()
            .find(|v| v.id == r.vault_id)
            .ok_or(Error::NotFound)?;
        let item = self
            .items(&vault)?
            .into_iter()
            .find(|i| i.id == r.item_id && i.trashed_at.is_none())
            .ok_or(Error::NotFound)?;
        if item.item_type != kind {
            return Err(invalid(field, "is not of the right type"));
        }
        Ok(())
    }

    /// Write the profile item (`existing`: the profile items, newest first).
    fn write_profile(
        &mut self,
        existing: Vec<Item>,
        name: &str,
        photo: &[u8],
        main_identity: Option<ItemRef>,
        main_card: Option<ItemRef>,
        now: OffsetDateTime,
    ) -> Result<Profile> {
        let vaults = self.personal_vaults()?;
        let vault_id = match existing.first() {
            Some(item) => item.vault_id,
            None => vaults.first().ok_or(Error::NotFound)?.id,
        };
        let vault = vaults
            .iter()
            .find(|v| v.id == vault_id)
            .ok_or(Error::NotFound)?;
        let mut item = match existing.first() {
            Some(item) => item.clone(),
            None => {
                let mut item = new_item(ItemType::SecureNote, vault.id, TITLE);
                item.id = profile_item_id(self.account.params.account_id);
                item.created_at = now;
                item
            }
        };
        item.title = TITLE.into();
        item.tags = vec![PROFILE_TAG.to_owned()];
        item.hide_from_autofill = true;
        let mut fields = vec![
            field(NAME, name.to_owned()),
            field(PHOTO, BASE64.encode(photo)),
        ];
        // Written only when set: a profile without them stays as before.
        if let Some(r) = main_identity {
            fields.push(field(MAIN_IDENTITY, r.encode()));
        }
        if let Some(r) = main_card {
            fields.push(field(MAIN_CARD, r.encode()));
        }
        item.sections = vec![Section {
            id: SECTION.into(),
            label: SECTION.into(),
            fields,
        }];
        item.updated_at = now;
        self.save_item(vault, item.clone())?;
        // A copy left in another vault (one parked by the Travel Mode when
        // this one was written) is dropped.
        for other in existing.iter().skip(1) {
            if other.vault_id == vault.id {
                continue;
            }
            if let Some(v) = vaults.iter().find(|v| v.id == other.vault_id) {
                self.delete_item(v, other.id)?;
            }
        }
        Ok(read(&item))
    }

    /// Publish a profile kept on this device only (from before the profile
    /// synced) when the account has none yet: dated at the Unix epoch, so a
    /// profile any device set for real wins the merge. `false` when a
    /// profile already exists (nothing written).
    pub fn seed_profile(&mut self, name: &str, photo: &[u8]) -> Result<bool> {
        if !self.profile_items()?.is_empty() {
            return Ok(false);
        }
        self.set_profile(name, photo, OffsetDateTime::UNIX_EPOCH)?;
        Ok(true)
    }

    /// The items of a vault, profile included (`items` leaves it out).
    pub(crate) fn all_items(&mut self, vault: &crate::vault::Vault) -> Result<Vec<Item>> {
        self.readable()?;
        self.sync_epoch()?;
        let loaded = self.served(vault, Use::Read)?;
        let items = loaded
            .records
            .iter()
            .map(|(_, r)| vault.open_item(r))
            .collect::<Result<Vec<_>>>()?;
        // A shared vault keeps its last manifest in its share state.
        if !vault.zone().is_shared() {
            self.device
                .last_seen
                .insert(vault.id, super::seen(&loaded.manifest));
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_item(fields: Vec<Field>) -> Item {
        let mut item = new_item(ItemType::SecureNote, Id::new(), TITLE);
        item.sections = vec![Section {
            id: SECTION.into(),
            label: SECTION.into(),
            fields,
        }];
        item
    }

    #[test]
    fn item_refs_roundtrip_and_bad_values_read_as_none() {
        let r = ItemRef {
            vault_id: Id::new(),
            item_id: Id::new(),
        };
        assert_eq!(ItemRef::decode(&r.encode()), Some(r));
        for bad in ["", "x", "a/b", &format!("{}", r.vault_id)] {
            assert_eq!(ItemRef::decode(bad), None);
        }
    }

    #[test]
    fn old_and_new_profiles_read_both_ways() {
        // Written before the main items: they read as none.
        let old = profile_item(vec![
            field(NAME, "Camille".into()),
            field(PHOTO, String::new()),
        ]);
        let p = read(&old);
        assert_eq!(
            (p.name.as_str(), p.main_identity, p.main_card),
            ("Camille", None, None)
        );
        // Written with them: a reader of the name and photo only (an older
        // build reads its fields by id) still finds them.
        let r = ItemRef {
            vault_id: Id::new(),
            item_id: Id::new(),
        };
        let new = profile_item(vec![
            field(NAME, "Camille".into()),
            field(PHOTO, BASE64.encode(&[1, 2])),
            field(MAIN_IDENTITY, r.encode()),
            field(MAIN_CARD, "damaged".into()),
        ]);
        assert_eq!(text(&new, NAME), "Camille");
        assert_eq!(text(&new, PHOTO), BASE64.encode(&[1, 2]));
        let p = read(&new);
        assert_eq!((p.main_identity, p.main_card), (Some(r), None));
    }
}
