//! Versions of the persisted formats, and the rule for migrating them.
//!
//! Every format the core persists carries a version, so that a newer one is
//! refused clearly instead of being misread:
//! - `DeviceState`: `b"ODS" || version u8 || postcard`, version
//!   [`DEVICE_STATE_VERSION`]; the headerless encoding before it is
//!   version 1, still read and migrated (`epoch = 0`);
//! - items: the schema in the AAD of every sealed blob, [`ITEM_SCHEMA`];
//! - the sync SQLite store: `PRAGMA user_version`, [`STORE_USER_VERSION`].
//!
//! Rule for a future migration: the reader keeps every older version it
//! ever wrote and converts it on read to the current one ([`migrate_item`]
//! for items), writes only the current version, and refuses a version newer
//! than its own with `InvalidFormat("... from a newer version")`.

use crate::model::Item;
use crate::{Error, Result};

/// Version written in the `DeviceState` header.
pub const DEVICE_STATE_VERSION: u8 = 2;

/// Schema of sealed vault blobs (items, item keys, vault meta), bound in
/// their AAD.
pub const ITEM_SCHEMA: u16 = 1;

/// `PRAGMA user_version` of the sync SQLite store.
pub const STORE_USER_VERSION: i64 = 1;

/// Decode an item written under `schema` into the current `Item`.
///
/// Today only schema 1 exists, decoded as is (the whole buffer, trailing
/// bytes refused, `InvalidFormat("item")`). A newer schema is
/// `InvalidFormat("item from a newer version")`, any other
/// `InvalidFormat("item schema")`.
pub fn migrate_item(schema: u16, bytes: &[u8]) -> Result<Item> {
    if schema > ITEM_SCHEMA {
        return Err(Error::InvalidFormat("item from a newer version"));
    }
    if schema != ITEM_SCHEMA {
        return Err(Error::InvalidFormat("item schema"));
    }
    match postcard::take_from_bytes::<Item>(bytes) {
        Ok((item, [])) => Ok(item),
        _ => Err(Error::InvalidFormat("item")),
    }
}

/// Serde helper for a `DeviceState` field of a file the caller persists
/// (`#[serde(with = "onepass_core::format::device_state_bytes")]`): the
/// field is the byte string of `DeviceState::encode`, so the state stays
/// versioned inside the file. The serde derive of `DeviceState` itself is
/// not a persistence format.
pub mod device_state_bytes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::repo::DeviceState;

    pub fn serialize<S: Serializer>(state: &DeviceState, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&state.encode())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DeviceState, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        DeviceState::decode(&bytes).map_err(|_| D::Error::custom("device state"))
    }
}

/// Serde helper reading the legacy inline layout of a `DeviceState` field
/// (`#[serde(deserialize_with = "onepass_core::format::device_state_v1_inline::deserialize")]`):
/// the version 1 struct `{ pinned, last_seen }` serialized in place, as
/// `device.bin` held it before [`device_state_bytes`]. Migrated with
/// `epoch = 0`. Read only: write [`device_state_bytes`].
pub mod device_state_v1_inline {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer};

    use crate::Id;
    use crate::account::PinnedAccount;
    use crate::manifest::SeenManifest;
    use crate::repo::DeviceState;

    #[derive(Deserialize)]
    struct V1 {
        pinned: Option<PinnedAccount>,
        last_seen: BTreeMap<Id, SeenManifest>,
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DeviceState, D::Error> {
        let v1 = V1::deserialize(d)?;
        Ok(DeviceState {
            pinned: v1.pinned,
            last_seen: v1.last_seen,
            epoch: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Id;
    use crate::model::{ItemType, new_item};

    #[test]
    fn item_schema_1_reads() {
        let item = new_item(ItemType::Login, Id::new(), "Mail");
        let mut bytes = postcard::to_allocvec(&item).unwrap();
        assert_eq!(migrate_item(ITEM_SCHEMA, &bytes).unwrap(), item);
        assert_eq!(migrate_item(1, &bytes).unwrap(), item);
        bytes.push(0);
        assert_eq!(
            migrate_item(ITEM_SCHEMA, &bytes),
            Err(Error::InvalidFormat("item"))
        );
    }

    #[test]
    fn item_schema_2_refused() {
        let item = new_item(ItemType::Login, Id::new(), "Mail");
        let bytes = postcard::to_allocvec(&item).unwrap();
        for newer in [2, u16::MAX] {
            assert_eq!(
                migrate_item(newer, &bytes),
                Err(Error::InvalidFormat("item from a newer version"))
            );
        }
        assert_eq!(
            migrate_item(0, &bytes),
            Err(Error::InvalidFormat("item schema"))
        );
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct File {
        #[serde(with = "device_state_bytes")]
        state: crate::repo::DeviceState,
    }

    #[derive(serde::Deserialize)]
    struct LegacyFile {
        #[serde(deserialize_with = "device_state_v1_inline::deserialize")]
        state: crate::repo::DeviceState,
    }

    #[test]
    fn device_state_field_helpers() {
        let state = crate::repo::DeviceState {
            epoch: 3,
            ..Default::default()
        };
        let file = File { state };
        let bytes = postcard::to_allocvec(&file).unwrap();
        // A byte string: length, then the versioned encoding.
        assert_eq!(&bytes[1..5], b"ODS\x02");
        assert_eq!(postcard::from_bytes::<File>(&bytes).unwrap(), file);
        // The legacy inline layout is not a byte string of a valid state.
        let legacy = [0u8, 0];
        assert!(postcard::from_bytes::<File>(&legacy).is_err());
        let old: LegacyFile = postcard::from_bytes(&legacy).unwrap();
        assert_eq!(old.state, crate::repo::DeviceState::default());
    }
}
