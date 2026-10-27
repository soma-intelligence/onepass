//! Pairing messages. postcard encodes enum variants by index: new variants
//! must only ever be appended.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::HybridKemPublic;
use crate::crypto::kem::envelope_len;
use crate::devices::{DeviceKind, DeviceMode, check_name};
use crate::model::Item;
use crate::{Error, Id, Result};

const HELLO_MAGIC: &[u8; 4] = b"OPH1";
const KEY_EXCHANGE_MAGIC: &[u8; 4] = b"OPK1";
/// A Hello is about 1.7 KB: anything much larger is refused unread.
const MAX_HELLO_BYTES: usize = 4096;

/// Who asks to join, as the approver shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: Id,
    pub name: String,
    pub kind: DeviceKind,
}

/// N -> A, in the clear: the ephemeral public key the QR commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub session_id: [u8; 16],
    pub ephemeral_public: HybridKemPublic,
    pub device: DeviceInfo,
    pub requested_mode: DeviceMode,
}

impl Hello {
    /// `"OPH1" || postcard(self)`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = HELLO_MAGIC.to_vec();
        let body =
            postcard::to_allocvec(self).map_err(|_| Error::InvalidFormat("pairing hello"))?;
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse and check a Hello: the key parses as a hybrid public key and
    /// the device name is 1 to 64 characters.
    pub fn from_bytes(b: &[u8]) -> Result<Hello> {
        const BAD: Error = Error::InvalidFormat("pairing hello");
        if b.len() > MAX_HELLO_BYTES {
            return Err(BAD);
        }
        let body = b.strip_prefix(HELLO_MAGIC).ok_or(BAD)?;
        let (hello, rest): (Hello, _) = postcard::take_from_bytes(body).map_err(|_| BAD)?;
        if !rest.is_empty() {
            return Err(BAD);
        }
        HybridKemPublic::from_bytes(&hello.ephemeral_public.to_bytes())?;
        check_name(&hello.device.name)?;
        Ok(hello)
    }
}

/// A -> N, in the clear: the session key wrapped to the ephemeral key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchange {
    pub envelope: Vec<u8>,
}

impl KeyExchange {
    /// `"OPK1" || envelope`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = KEY_EXCHANGE_MAGIC.to_vec();
        out.extend_from_slice(&self.envelope);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<KeyExchange> {
        let envelope = b
            .strip_prefix(KEY_EXCHANGE_MAGIC)
            .filter(|e| e.len() == envelope_len())
            .ok_or(Error::InvalidFormat("pairing key exchange"))?;
        Ok(KeyExchange {
            envelope: envelope.to_vec(),
        })
    }
}

/// A message inside the channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    /// N -> A: the newcomer's user confirmed the SAS.
    Confirmed,
    /// A -> N.
    Grant(Grant),
    /// N -> A: the grant arrived.
    Ack,
    /// N -> A, public session only.
    Audit(AuditEvent),
    /// Either side: the session is over.
    End,
}

impl Message {
    /// postcard, into a buffer wiped on drop: written once at its exact
    /// size, so no reallocation leaves a copy of a secret behind.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bad = |_| Error::InvalidFormat("pairing message");
        let size = postcard::experimental::serialized_size(self).map_err(bad)?;
        let mut out = Zeroizing::new(vec![0u8; size]);
        let used = postcard::to_slice(self, &mut out).map_err(bad)?.len();
        out.truncate(used);
        Ok(out)
    }

    pub(crate) fn decode(b: &[u8]) -> Result<Message> {
        const BAD: Error = Error::InvalidFormat("pairing message");
        let (msg, rest): (Message, _) = postcard::take_from_bytes(b).map_err(|_| BAD)?;
        if !rest.is_empty() {
            return Err(BAD);
        }
        Ok(msg)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Grant {
    /// Personal or shared device: the account itself.
    Full(FullGrant),
    /// Public device: a read-only session, no key.
    Public(PublicGrant),
}

/// Everything a personal or shared device needs to open the account: the
/// master password stays with the user.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct FullGrant {
    pub account_id: Id,
    /// The Secret Key as displayed (`SecretKey::to_display`).
    pub secret_key: Zeroizing<String>,
    pub mode: DeviceMode,
    /// The id the approver listed the newcomer under.
    pub device_id: Id,
    pub snapshot: Vec<SnapshotRecord>,
}

impl fmt::Debug for FullGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FullGrant")
            .field("account_id", &self.account_id)
            .field("secret_key", &"**")
            .field("mode", &self.mode)
            .field("device_id", &self.device_id)
            .field("snapshot_records", &self.snapshot.len())
            .finish()
    }
}

/// Decrypted items lent for a session (spec 4.10): memory only.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicGrant {
    pub session_id: [u8; 16],
    pub expires_at: i64,
    pub read_only: bool,
    pub items: Vec<Item>,
}

impl fmt::Debug for PublicGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicGrant")
            .field("expires_at", &self.expires_at)
            .field("read_only", &self.read_only)
            .field("items", &self.items.len())
            .finish()
    }
}

/// What the public device did with an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub at: i64,
    pub item_id: Id,
    pub action: AuditAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    Opened,
    /// The label of the copied field, never its value.
    Copied(String),
}

/// One store record as the server holds it: already encrypted and signed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    /// `RecordKind::code`.
    pub kind: u8,
    pub id: Id,
    pub version: u64,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl fmt::Debug for SnapshotRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnapshotRecord")
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("version", &self.version)
            .field("len", &self.data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HybridKemSecret;

    fn hello() -> Hello {
        Hello {
            session_id: [1; 16],
            ephemeral_public: HybridKemSecret::generate().unwrap().public().unwrap(),
            device: DeviceInfo {
                device_id: Id::new(),
                name: "Mac de Camille".into(),
                kind: DeviceKind::Mac,
            },
            requested_mode: DeviceMode::Shared,
        }
    }

    #[test]
    fn hello_round_trip_and_checks() {
        let h = hello();
        let b = h.to_bytes().unwrap();
        assert!(b.starts_with(b"OPH1"));
        assert_eq!(Hello::from_bytes(&b).unwrap(), h);
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(Hello::from_bytes(&trailing).is_err());
        assert!(Hello::from_bytes(&b[4..]).is_err());

        let mut bad_key = h.clone();
        bad_key.ephemeral_public.mlkem.truncate(100);
        assert!(Hello::from_bytes(&bad_key.to_bytes().unwrap()).is_err());
        let mut bad_name = h;
        bad_name.device.name = " ".into();
        assert!(Hello::from_bytes(&bad_name.to_bytes().unwrap()).is_err());
    }

    #[test]
    fn key_exchange_has_a_fixed_length() {
        let kx = KeyExchange {
            envelope: vec![0; envelope_len()],
        };
        assert_eq!(KeyExchange::from_bytes(&kx.to_bytes()).unwrap(), kx);
        assert!(KeyExchange::from_bytes(&kx.to_bytes()[..100]).is_err());
        assert!(KeyExchange::from_bytes(&kx.envelope).is_err());
    }

    #[test]
    fn message_variant_indexes_are_stable() {
        assert_eq!(*Message::Confirmed.encode().unwrap(), [0]);
        assert_eq!(*Message::Ack.encode().unwrap(), [2]);
        assert_eq!(*Message::End.encode().unwrap(), [4]);
        let audit = Message::Audit(AuditEvent {
            at: 1,
            item_id: Id([0; 16]),
            action: AuditAction::Opened,
        });
        assert_eq!(audit.encode().unwrap()[0], 3);
        assert_eq!(Message::decode(&audit.encode().unwrap()).unwrap(), audit);
        assert!(Message::decode(&[4, 0]).is_err());
        assert!(Message::decode(&[5]).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let g = FullGrant {
            account_id: Id::new(),
            secret_key: Zeroizing::new("A3-SECRET-KEY".into()),
            mode: DeviceMode::Personal,
            device_id: Id::new(),
            snapshot: vec![SnapshotRecord {
                kind: 5,
                id: Id::new(),
                version: 1,
                data: b"ciphertext".to_vec(),
            }],
        };
        let s = format!("{:?}", Message::Grant(Grant::Full(g)));
        assert!(!s.contains("A3-SECRET-KEY"));
        assert!(!s.contains("99, 105")); // no data bytes
        let p = PublicGrant {
            session_id: [0; 16],
            expires_at: 0,
            read_only: true,
            items: vec![crate::model::new_item(
                crate::model::ItemType::Login,
                Id::new(),
                "Banque exemple.fr",
            )],
        };
        assert!(!format!("{p:?}").contains("Banque"));
    }
}
