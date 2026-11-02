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

/// The account profile as every device shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    /// JPEG bytes, empty for no photo.
    pub photo: Vec<u8>,
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
        for vault in self.vaults()? {
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
        let vaults = self.vaults()?;
        let existing = self.profile_items()?;
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
        item.sections = vec![Section {
            id: SECTION.into(),
            label: SECTION.into(),
            fields: vec![field(NAME, name), field(PHOTO, BASE64.encode(photo))],
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
        self.device
            .last_seen
            .insert(vault.id, super::seen(&loaded.manifest));
        Ok(items)
    }
}
