//! The device-local key-use queue: the uses of a key this device could not
//! write into the item's log yet (`crate::model::key_use`). Two cases: a
//! read-only session (`Error::ReadOnly`), and a use inside the hour after
//! the last write of the same entry, so the item is written at most once
//! an hour per entry. The repository folds a queued row into the item at
//! its next write, or at a flush (`Repository::flush_key_use_queue`).
//!
//! Privacy: a row holds what the item's log holds (channel, action,
//! device, client and field labels, times, a count), never a value, a
//! command line or a path. Each row lives in the device's own database,
//! sealed under a key derived from the account keyset
//! (`BlobKind::KeyUseQueue`) and filed under a keyed tag of the item id,
//! so the file shows neither the items nor the uses. Never synced, never
//! sent anywhere. The Travel Mode erases it.
//!
//! Wire format: `QueuedKeyUse` is postcard behind a version byte, its
//! entry a `KeyUse` as the item's log encodes it. A row a build cannot
//! open (another version, an older keyset after a rotation) is dropped:
//! a lost count is better than a stuck queue.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::crypto::aead::{Aad, BlobKind, open, seal};
use crate::crypto::key::SymmetricKey;
use crate::id::Id;
use crate::model::key_use::{KeyUse, KeyUseInput, sanitize_label};
use crate::{Error, Result};

/// Rows kept on the device, the oldest dropped first.
pub const MAX_QUEUE_ROWS: usize = 1000;
/// Version byte in front of an encoded row.
const ROW_VERSION: u8 = 1;
/// Schema of the AAD of a sealed row.
const AAD_SCHEMA: u16 = 1;
const KEY_SALT: &[u8] = b"onepass/key-use-queue/v1";
const SEAL_INFO: &[u8] = b"seal";
const TAG_INFO: &[u8] = b"item-tag";

/// One queued entry of one item: the uses of one coalescing key since the
/// row was made, with their count and first and last times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedKeyUse {
    pub vault_id: Id,
    pub item_id: Id,
    pub entry: KeyUse,
}

impl QueuedKeyUse {
    /// A first use `u` of the item at `at`, its labels sanitized as the log
    /// keeps them.
    pub fn new(vault_id: Id, item_id: Id, u: &KeyUseInput, at: OffsetDateTime) -> QueuedKeyUse {
        QueuedKeyUse {
            vault_id,
            item_id,
            entry: KeyUse {
                channel: u.channel,
                action: u.action,
                device_id: u.device_id,
                device_name: sanitize_label(&u.device_name),
                client: sanitize_label(&u.client),
                field: sanitize_label(&u.field),
                first_at: at,
                last_at: at,
                count: 1,
            },
        }
    }

    /// Whether `u` coalesces into this row (the log's key: channel, action,
    /// device, client and field).
    pub fn same_key(&self, u: &KeyUseInput) -> bool {
        let e = &self.entry;
        e.channel == u.channel
            && e.action == u.action
            && e.device_id == u.device_id
            && e.client == sanitize_label(&u.client)
            && e.field == sanitize_label(&u.field)
    }

    /// One more use at `at`.
    pub fn bump(&mut self, u: &KeyUseInput, at: OffsetDateTime) {
        let e = &mut self.entry;
        e.count = e.count.saturating_add(1);
        e.first_at = e.first_at.min(at);
        if at >= e.last_at {
            e.device_name = sanitize_label(&u.device_name);
        }
        e.last_at = e.last_at.max(at);
    }

    /// The use this row stands for, as a log input.
    pub fn input(&self) -> KeyUseInput {
        let e = &self.entry;
        KeyUseInput {
            channel: e.channel,
            action: e.action,
            device_id: e.device_id,
            device_name: e.device_name.clone(),
            client: e.client.clone(),
            field: e.field.clone(),
        }
    }
}

/// The keys of the queue of one account: sealing, and the keyed item tag.
/// Derived from the account's KEM secret, so a key rotation leaves the old
/// rows unreadable (they are dropped at the next read).
pub struct QueueKeys {
    seal: SymmetricKey,
    tag: SymmetricKey,
}

impl QueueKeys {
    /// HKDF-SHA256 of `ikm` (the account's secret key material) salted
    /// with the queue label, bound to the account id.
    pub(crate) fn derive(ikm: &[u8], account_id: Id) -> Result<QueueKeys> {
        let root = crate::crypto::key::hkdf32(KEY_SALT, ikm, &[&account_id.0])?;
        Ok(QueueKeys {
            seal: root.derive(SEAL_INFO)?,
            tag: root.derive(TAG_INFO)?,
        })
    }

    /// HMAC-SHA256 of the item id under the tag key: what the store files
    /// the rows of an item under, without the id in clear.
    pub fn item_tag(&self, item_id: Id) -> [u8; 32] {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, self.tag.expose());
        let t = aws_lc_rs::hmac::sign(&key, &item_id.0);
        let mut out = [0u8; 32];
        out.copy_from_slice(t.as_ref());
        out
    }

    fn aad(tag: &[u8; 32]) -> Aad {
        let mut id = [0u8; 16];
        id.copy_from_slice(&tag[..16]);
        Aad {
            blob_id: Id(id),
            vault_id: None,
            schema: AAD_SCHEMA,
        }
    }

    /// The sealed row of `row`, bound to its item tag (a row moved under
    /// another item's tag does not open).
    pub fn seal_row(&self, tag: &[u8; 32], row: &QueuedKeyUse) -> Result<Vec<u8>> {
        let mut plain = vec![ROW_VERSION];
        plain.extend(
            postcard::to_allocvec(row).map_err(|_| Error::InvalidFormat("key-use queue row"))?,
        );
        seal(&self.seal, BlobKind::KeyUseQueue, &Self::aad(tag), &plain)
    }

    /// The row of a sealed blob filed under `tag`. A row whose item id does
    /// not give `tag` is refused.
    pub fn open_row(&self, tag: &[u8; 32], blob: &[u8]) -> Result<QueuedKeyUse> {
        let plain = open(&self.seal, BlobKind::KeyUseQueue, &Self::aad(tag), blob)?;
        let row: QueuedKeyUse = match plain.split_first() {
            Some((&ROW_VERSION, body)) => {
                postcard::from_bytes(body).map_err(|_| Error::InvalidFormat("key-use queue row"))?
            }
            _ => return Err(Error::InvalidFormat("key-use queue row version")),
        };
        if self.item_tag(row.item_id) != *tag {
            return Err(Error::InvalidFormat("key-use queue row tag"));
        }
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    use crate::model::key_use::{KeyUseAction, KeyUseChannel};

    const T: OffsetDateTime = datetime!(2026-11-14 12:00 UTC);

    fn keys() -> QueueKeys {
        QueueKeys::derive(&[7u8; 64], Id([1; 16])).unwrap()
    }

    fn input(field: &str) -> KeyUseInput {
        KeyUseInput {
            channel: KeyUseChannel::Cli,
            action: KeyUseAction::Revealed,
            device_id: Id([3; 16]),
            device_name: "Mac".into(),
            client: "zsh\n".into(),
            field: field.into(),
        }
    }

    #[test]
    fn row_round_trips_under_its_tag_only() {
        let k = keys();
        let row = QueuedKeyUse::new(Id([4; 16]), Id([5; 16]), &input("password"), T);
        let tag = k.item_tag(row.item_id);
        let blob = k.seal_row(&tag, &row).unwrap();
        assert_eq!(k.open_row(&tag, &blob).unwrap(), row);
        let other = k.item_tag(Id([6; 16]));
        assert!(k.open_row(&other, &blob).is_err());
        let rotated = QueueKeys::derive(&[8u8; 64], Id([1; 16])).unwrap();
        assert!(rotated.open_row(&tag, &blob).is_err());
    }

    #[test]
    fn row_keeps_sanitized_labels_and_coalesces() {
        let mut row = QueuedKeyUse::new(Id([4; 16]), Id([5; 16]), &input("password"), T);
        assert_eq!(row.entry.client, "zsh");
        assert!(row.same_key(&input("password")));
        assert!(!row.same_key(&input("otp")));
        row.bump(&input("password"), T + time::Duration::minutes(5));
        assert_eq!(row.entry.count, 2);
        assert_eq!(row.entry.first_at, T);
        assert_eq!(row.entry.last_at, T + time::Duration::minutes(5));
    }
}
