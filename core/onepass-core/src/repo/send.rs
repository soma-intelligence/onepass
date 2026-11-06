//! Sending a copy of one item to a contact (sharing plan 3 Task 7, spec
//! 14.1, 14.2, S29).

use super::Repository;
use crate::contact::ContactLevel;
use crate::crypto::kem::{unwrap_key_labeled, wrap_key_labeled};
use crate::crypto::{Aad, BlobKind, HybridSignature, SymmetricKey, open, seal};
use crate::lineage::identity_id;
use crate::model::{Item, ItemType};
use crate::send::{ITEM_SEND_LABEL, ItemSend, MAX_SEND_TTL_SECS, send_context};
use crate::store::{Record, RecordKind, RecordStore, Zone};
use crate::vault::Vault;
use crate::{Error, Id, Result, ValidationError};

fn refused(field: &str, reason: &'static str) -> Error {
    ValidationError {
        field: field.into(),
        reason,
    }
    .into()
}

fn blob_aad(send_id: Id) -> Aad {
    Aad {
        blob_id: send_id,
        vault_id: None,
        schema: 1,
    }
}

/// An item sent to me, as the screens show it before I take it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedItem {
    pub send_id: Id,
    pub from_name_local: String,
    pub title: String,
    pub kind: ItemType,
    pub expires_at: i64,
}

impl<S: RecordStore> Repository<S> {
    /// Send a copy of item `item_id` of `vault` to contact `to` (an
    /// `Active` contact; `Link` is enough, a copy is a read). The copy
    /// carries no history and no usage; it waits in our contact zone until
    /// `expires_at`, between `now + 1` and `now + MAX_SEND_TTL_SECS`.
    pub fn send_item(
        &mut self,
        vault: &Vault,
        item_id: Id,
        to: Id,
        expires_at: i64,
        now: i64,
    ) -> Result<Id> {
        self.writable()?;
        if expires_at <= now || expires_at > now + MAX_SEND_TTL_SECS {
            return Err(refused("expires_at", "out of bounds"));
        }
        let me = self.me();
        if to == me.account_id {
            return Err(refused("contact", "self"));
        }
        let c = self
            .contact(to)?
            .ok_or_else(|| refused("contact", "unknown"))?;
        if !c.usable_for(ContactLevel::Link) {
            return Err(refused("contact", "not active"));
        }
        let mut item = self
            .items(vault)?
            .into_iter()
            .find(|i| i.id == item_id)
            .ok_or(Error::NotFound)?;
        item.password_history.clear();
        item.events.clear();
        item.usage.clear();
        item.usage_forgotten.clear();
        item.attachments.clear();
        item.custom_icon = None;
        let plain = zeroize::Zeroizing::new(
            postcard::to_allocvec(&item).map_err(|_| Error::InvalidFormat("item"))?,
        );
        let send_id = Id::new();
        let to_identity = identity_id(&c.identity_pub);
        let key = SymmetricKey::generate()?;
        let envelope = wrap_key_labeled(
            &c.kem_pub,
            &key,
            ITEM_SEND_LABEL,
            &send_context(send_id, me.account_id, to, to_identity),
        )?;
        let blob = seal(&key, BlobKind::ItemSend, &blob_aad(send_id), &plain)?;
        let send = ItemSend::sign(
            ItemSend {
                send_id,
                from: me,
                to,
                to_identity,
                envelope,
                blob,
                expires_at,
                sig: HybridSignature {
                    mldsa: Vec::new(),
                    ed25519: [0; 64],
                },
            },
            &self.account.keyset().signing,
        )?;
        let zone = self.contact_zone(to)?;
        self.store.put_all_zoned(
            vec![(
                zone,
                Record {
                    kind: RecordKind::ItemSend,
                    id: send_id,
                    version: 1,
                    data: send.encode(),
                },
                None,
            )],
            vec![],
            None,
            &[],
        )?;
        Ok(send_id)
    }

    /// A send for me in `zone`, checked and opened: from a contact of my
    /// book under the identity it holds there, signed by its book key,
    /// not expired. Returns the send, the item and the sender's name.
    fn opened_send(
        &mut self,
        zone: Zone,
        rec: &Record,
        now: i64,
    ) -> Result<(ItemSend, Item, String)> {
        let send = ItemSend::decode(&rec.data)?;
        let me = self.me();
        if send.send_id != rec.id || send.to != me.account_id {
            return Err(refused("send", "not for me"));
        }
        if send.expires_at <= now {
            return Err(refused("send", "expired"));
        }
        if zone != Zone::Contact(crate::contact::pair_id(me.account_id, send.from.account_id)) {
            return Err(crate::IntegrityError::WrongContext.into());
        }
        let c = self
            .contact(send.from.account_id)?
            .ok_or_else(|| refused("send", "sender not verified"))?;
        // A sender who rotated is followed only once I adopted its new
        // identity (spec 12.3): until then its sends are refused.
        if !c.usable_for(ContactLevel::Link)
            || identity_id(&c.identity_pub) != send.from.identity_id
        {
            return Err(refused("send", "sender not verified"));
        }
        send.verify(&c.sign_pub)?;
        let context = send_context(
            send.send_id,
            send.from.account_id,
            send.to,
            send.to_identity,
        );
        let keyset = self.account.keyset();
        let mut key = None;
        for kem in std::iter::once(&keyset.kem).chain(keyset.retired_kem.iter()) {
            if let Ok(k) = unwrap_key_labeled(kem, &send.envelope, ITEM_SEND_LABEL, &context) {
                key = Some(k);
                break;
            }
        }
        let key = key.ok_or(Error::Crypto)?;
        let plain = open(
            &key,
            BlobKind::ItemSend,
            &blob_aad(send.send_id),
            &send.blob,
        )?;
        let item: Item = crate::lineage::decode_strict_with(&plain, Error::InvalidFormat("item"))?;
        Ok((send, item, c.name_local.clone()))
    }

    fn sends_for_me(&mut self) -> Result<Vec<(Zone, Record)>> {
        let mut out = Vec::new();
        for zone in self.contact_zones()? {
            for rec in self.store.list_in(zone, RecordKind::ItemSend)? {
                out.push((zone, rec));
            }
        }
        Ok(out)
    }

    /// The items sent to me that I can open now (expired ones and those
    /// from a sender outside my book are left out).
    pub fn received_items(&mut self, now: i64) -> Result<Vec<ReceivedItem>> {
        let mut out = Vec::new();
        for (zone, rec) in self.sends_for_me()? {
            let Ok((send, item, name)) = self.opened_send(zone, &rec, now) else {
                continue;
            };
            out.push(ReceivedItem {
                send_id: send.send_id,
                from_name_local: name,
                title: item.title.clone(),
                kind: item.item_type,
                expires_at: send.expires_at,
            });
        }
        out.sort_by_key(|r| r.send_id);
        Ok(out)
    }

    /// Take send `send_id` into `into`, under a new item id; the send
    /// leaves the contact zone.
    pub fn accept_received_item(&mut self, send_id: Id, into: &Vault, now: i64) -> Result<Item> {
        self.writable()?;
        let (zone, rec) = self
            .sends_for_me()?
            .into_iter()
            .find(|(_, r)| r.id == send_id)
            .ok_or(Error::NotFound)?;
        let (_, mut item, _) = self.opened_send(zone, &rec, now)?;
        item.id = Id::new();
        item.vault_id = into.id;
        self.save_item(into, item.clone())?;
        self.store.put_all_zoned(
            vec![],
            vec![(zone, RecordKind::ItemSend, send_id)],
            None,
            &[],
        )?;
        Ok(item)
    }

    /// Refuse send `send_id`: it leaves the contact zone.
    pub fn decline_received_item(&mut self, send_id: Id) -> Result<()> {
        self.writable()?;
        let (zone, _) = self
            .sends_for_me()?
            .into_iter()
            .find(|(_, r)| r.id == send_id)
            .ok_or(Error::NotFound)?;
        self.store.put_all_zoned(
            vec![],
            vec![(zone, RecordKind::ItemSend, send_id)],
            None,
            &[],
        )
    }

    /// Delete my own sends that expired. Returns how many went.
    pub fn purge_expired_sends(&mut self, now: i64) -> Result<u32> {
        self.writable()?;
        let me = self.me();
        let mut deletes = Vec::new();
        for (zone, rec) in self.sends_for_me()? {
            let Ok(send) = ItemSend::decode(&rec.data) else {
                continue;
            };
            if send.from.account_id == me.account_id && send.expires_at <= now {
                deletes.push((zone, RecordKind::ItemSend, rec.id));
            }
        }
        let n = u32::try_from(deletes.len()).unwrap_or(u32::MAX);
        if !deletes.is_empty() {
            self.store.put_all_zoned(vec![], deletes, None, &[])?;
        }
        Ok(n)
    }
}
