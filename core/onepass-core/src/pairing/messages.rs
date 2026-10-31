//! Pairing messages. postcard encodes enum variants by index: new variants
//! must only ever be appended.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::kem::envelope_len;
use crate::crypto::{HybridKemPublic, HybridSignature};
use crate::device_keys::DevicePublic;
use crate::devices::{DeviceKind, DeviceMode, check_name};
use crate::lineage::{LineageRecord, MAX_ROSTER, RosterEntry, check_entry};
use crate::model::Item;
use crate::trust::TrustLevel;
use crate::{Error, Id, Result};

const HELLO_MAGIC: &[u8; 4] = b"OPH1";
const JOIN_HELLO_MAGIC: &[u8; 4] = b"OPH2";
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

/// Length of the proof that closes a `JoinHello`.
pub const JOIN_PROOF_LEN: usize = 32;

/// N -> A in the rendezvous direction (the approver shows the code): a
/// `Hello` plus an HMAC tag proving N knows the code, over the exact Hello
/// bytes. Wire: `"OPH2" || postcard(Hello) || proof (32 bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinHello {
    pub hello: Hello,
    pub proof: [u8; JOIN_PROOF_LEN],
}

impl JoinHello {
    /// The bytes the proof covers: `"OPH2" || postcard(hello)`.
    pub fn signed_part(hello: &Hello) -> Result<Vec<u8>> {
        let mut out = JOIN_HELLO_MAGIC.to_vec();
        let body =
            postcard::to_allocvec(hello).map_err(|_| Error::InvalidFormat("pairing join hello"))?;
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Self::signed_part(&self.hello)?;
        out.extend_from_slice(&self.proof);
        Ok(out)
    }

    /// Parse and check the Hello inside; the proof is checked by the host,
    /// which knows the codes.
    pub fn from_bytes(b: &[u8]) -> Result<JoinHello> {
        const BAD: Error = Error::InvalidFormat("pairing join hello");
        if b.len() > MAX_HELLO_BYTES + JOIN_PROOF_LEN {
            return Err(BAD);
        }
        let body = b.strip_prefix(JOIN_HELLO_MAGIC).ok_or(BAD)?;
        let (hello, rest): (Hello, _) = postcard::take_from_bytes(body).map_err(|_| BAD)?;
        let proof: [u8; JOIN_PROOF_LEN] = rest.try_into().map_err(|_| BAD)?;
        HybridKemPublic::from_bytes(&hello.ephemeral_public.to_bytes())?;
        check_name(&hello.device.name)?;
        Ok(JoinHello { hello, proof })
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
    /// A -> N, invite sessions only (both sides know it), right before a
    /// full grant: how the account shows itself (name and photo), so the
    /// new device looks like the others. Appended: index 5.
    Profile(ProfileCard),
    /// N -> A, key rotation v2 (spec 5.2, R16). Appended: index 6. Sent
    /// twice by a newcomer with device keys:
    ///
    /// 1. in place of `Confirmed`, once its user confirmed the SAS: `pop`
    ///    is the device's proof of possession over the session transcript
    ///    hash (`sign_pop(keys, transcript, device)`, domain
    ///    `onepass/device-pop/v1`); `device.device_id` is the Hello's;
    /// 2. in place of `Ack`, once a `Grant::FullV2` arrived: the same
    ///    `device`, `pop` now over the granted account id, the form an intro
    ///    carries (spec 6.4). The approver writes its intro for N with it.
    ///
    /// `mailbox_credential`: opaque, reserved for the mailbox plan, `None`
    /// on this branch. Every field is authenticated by the channel (the
    /// SAS-confirmed session key and the frame counter); the pop binds the
    /// device key to the session or the account.
    ConfirmedWithKey {
        device: DevicePublic,
        pop: HybridSignature,
        mailbox_credential: Option<[u8; 32]>,
    },
}

/// The account's display name and photo, as the approver's settings hold
/// them. Not secret, but only sent once both users confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileCard {
    pub name: String,
    /// A small image (PNG or JPEG), empty for none.
    pub photo: Vec<u8>,
}

/// Longest profile name, in characters.
pub const MAX_PROFILE_NAME_CHARS: usize = 64;
/// Largest profile photo, in bytes (the apps keep a 256 px square).
pub const MAX_PROFILE_PHOTO_BYTES: usize = 256 * 1024;

impl ProfileCard {
    /// A name of at most 64 characters with no control character, a photo
    /// of at most 256 KiB.
    pub fn check(&self) -> Result<()> {
        if self.name.chars().count() > MAX_PROFILE_NAME_CHARS
            || self.name.chars().any(char::is_control)
            || self.photo.len() > MAX_PROFILE_PHOTO_BYTES
        {
            return Err(Error::InvalidFormat("pairing profile"));
        }
        Ok(())
    }
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
        // The variants of key rotation v2 decode strictly (spec 6): a
        // canonical re-encoding equal to the input and their structural
        // rules, so no trailing or non-canonical field can be added later.
        let strict = match &msg {
            Message::ConfirmedWithKey { device, .. } => {
                DevicePublic::decode(&device.encode()).map_err(|_| BAD)?;
                true
            }
            Message::Grant(Grant::FullV2(g)) => {
                g.check()?;
                true
            }
            _ => false,
        };
        if strict && *msg.encode()? != *b {
            return Err(BAD);
        }
        Ok(msg)
    }
}

// `FullV2` is the large variant: one grant per session, never stored in
// bulk, and the interface the plan fixes holds it by value.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Grant {
    /// Personal or shared device: the account itself.
    Full(FullGrant),
    /// Public device: a read-only session, no key.
    Public(PublicGrant),
    /// Key rotation v2 (spec 5.2): a full grant and the approver's trust
    /// snapshot, for a newcomer that sent its device key
    /// (`Message::ConfirmedWithKey`). Appended: index 2.
    FullV2(FullGrantV2),
}

/// Most lineage records a trust snapshot carries (the approver's chain,
/// genesis to head).
pub const MAX_TRUST_LINEAGE: usize = 1024;
/// Largest opaque `sync` blob of a `FullGrantV2` (mailbox plan).
pub const MAX_GRANT_SYNC_BYTES: usize = 64 * 1024;
/// Largest opaque `enroll` blob of a `FullGrantV2` (mailbox plan).
pub const MAX_GRANT_ENROLL_BYTES: usize = 64 * 1024;

/// What the approver trusts (spec 5.2): its lineage chain from the genesis
/// to its head, in order, its roster at that head (sorted by device id, at
/// most 64), its own device public key, and the trust level of each roster
/// device (`levels`: one per roster entry, in roster order, so a device the
/// approver trusts on first use stays `Tofu` on the newcomer, O7). The
/// newcomer pins the head, the roster and the levels: it trusts the
/// approver because of the SAS, as it does for the Secret Key and the
/// snapshot.
///
/// Size: the whole grant travels in one frame of at most `MAX_FRAME_BYTES`
/// (64 MiB). A rotation record with a full roster is about 300 KB, so a
/// chain of about 200 such rotations fills the frame before
/// `MAX_TRUST_LINEAGE`; such an account cannot pair (the seal fails, nothing
/// is written) until the chain is pruned (not designed yet).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustSnapshot {
    pub lineage: Vec<LineageRecord>,
    pub roster: Vec<RosterEntry>,
    pub approver: DevicePublic,
    /// `(device id, level)` for every roster entry, same order as `roster`.
    pub levels: Vec<(Id, TrustLevel)>,
}

impl TrustSnapshot {
    /// Structural rules: 1 to `MAX_TRUST_LINEAGE` records, each passing the
    /// strict lineage checks, a genesis first and each next record a
    /// rotation whose parent is the previous record's hash, one account;
    /// a sorted, unique roster of at most 64 well-formed entries, none
    /// revoked along the chain, holding the approver with its keys; one
    /// level per roster entry, in roster order.
    pub fn check(&self) -> Result<()> {
        const BAD: Error = Error::InvalidFormat("trust snapshot");
        DevicePublic::decode(&self.approver.encode()).map_err(|_| BAD)?;
        let first = self.lineage.first().ok_or(BAD)?;
        if self.lineage.len() > MAX_TRUST_LINEAGE || !matches!(first, LineageRecord::Genesis(_)) {
            return Err(BAD);
        }
        let account = first.account_id();
        let mut prev: Option<([u8; 32], u64)> = None;
        let mut revoked = std::collections::BTreeSet::new();
        for r in &self.lineage {
            LineageRecord::decode(&r.encode()).map_err(|_| BAD)?;
            if r.account_id() != account {
                return Err(BAD);
            }
            match (r, prev) {
                (LineageRecord::Genesis(_), None) => {}
                (LineageRecord::Rotation(s), Some((h, g)))
                    if s.body.parent == h && s.body.generation == g + 1 =>
                {
                    revoked.extend(s.body.revoked.iter().copied());
                }
                _ => return Err(BAD),
            }
            prev = Some((r.hash(), r.generation()));
        }
        if self.roster.len() > MAX_ROSTER
            || !self
                .roster
                .windows(2)
                .all(|w| w[0].device_id < w[1].device_id)
        {
            return Err(BAD);
        }
        for e in &self.roster {
            check_entry(e).map_err(|_| BAD)?;
            if revoked.contains(&e.device_id) {
                return Err(BAD);
            }
        }
        if self.levels.len() != self.roster.len()
            || self
                .levels
                .iter()
                .zip(&self.roster)
                .any(|((id, _), e)| *id != e.device_id)
        {
            return Err(BAD);
        }
        let a = &self.approver;
        if !self.roster.iter().any(|e| {
            e.device_id == a.device_id && e.sign_pub == a.sign_pub && e.kem_pub == a.kem_pub
        }) {
            return Err(BAD);
        }
        Ok(())
    }

    /// The last record of the chain: the approver's head.
    pub fn head(&self) -> Option<&LineageRecord> {
        self.lineage.last()
    }

    /// The approver's level for `id`, if it is in the roster.
    pub fn level(&self, id: Id) -> Option<TrustLevel> {
        self.levels.iter().find(|(x, _)| *x == id).map(|(_, l)| *l)
    }

    /// Every device revoked along the chain.
    pub fn revoked(&self) -> Vec<Id> {
        let mut out = std::collections::BTreeSet::new();
        for r in &self.lineage {
            if let LineageRecord::Rotation(s) = r {
                out.extend(s.body.revoked.iter().copied());
            }
        }
        out.into_iter().collect()
    }
}

/// A `FullGrant` and the approver's trust snapshot (spec 5.2). `sync` and
/// `enroll` are opaque, reserved for the mailbox plan (`None` on this
/// branch), at most `MAX_GRANT_SYNC_BYTES` and `MAX_GRANT_ENROLL_BYTES`.
/// The whole grant travels in one channel frame: the SAS-confirmed channel
/// authenticates every field, the opaque ones included.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct FullGrantV2 {
    pub full: FullGrant,
    pub trust: TrustSnapshot,
    pub sync: Option<Vec<u8>>,
    pub enroll: Option<Vec<u8>>,
}

impl FullGrantV2 {
    /// The trust snapshot's rules, the opaque caps, and a chain of the
    /// granted account.
    pub fn check(&self) -> Result<()> {
        const BAD: Error = Error::InvalidFormat("pairing grant");
        self.trust.check()?;
        if self
            .sync
            .as_ref()
            .is_some_and(|b| b.len() > MAX_GRANT_SYNC_BYTES)
            || self
                .enroll
                .as_ref()
                .is_some_and(|b| b.len() > MAX_GRANT_ENROLL_BYTES)
            || self.trust.lineage[0].account_id() != self.full.account_id
        {
            return Err(BAD);
        }
        Ok(())
    }
}

impl fmt::Debug for FullGrantV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FullGrantV2")
            .field("full", &self.full)
            .field("lineage", &self.trust.lineage.len())
            .field("roster", &self.trust.roster.len())
            .field("sync", &self.sync.as_ref().map(Vec::len))
            .field("enroll", &self.enroll.as_ref().map(Vec::len))
            .finish()
    }
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

    fn snapshot(account: Id) -> (TrustSnapshot, crate::device_keys::DeviceKeys) {
        use crate::crypto::IdentityKey;
        use crate::device_keys::DeviceKeys;
        use crate::lineage::{GenesisBody, LINEAGE_FORMAT, sign_genesis};
        let keys = DeviceKeys::generate_software().unwrap();
        let approver = keys.public(Id::new()).unwrap();
        let entry = RosterEntry {
            device_id: approver.device_id,
            sign_pub: approver.sign_pub.clone(),
            kem_pub: approver.kem_pub.clone(),
            name: "iPhone".into(),
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            introduced_by: None,
        };
        let identity = IdentityKey::generate().unwrap();
        let genesis = sign_genesis(
            GenesisBody {
                format: LINEAGE_FORMAT,
                account_id: account,
                identity_pub: identity.verifying_key(),
                creator: entry.clone(),
                created_at: 1,
            },
            &keys,
            &identity,
        )
        .unwrap();
        let snap = TrustSnapshot {
            lineage: vec![LineageRecord::Genesis(genesis)],
            levels: vec![(entry.device_id, TrustLevel::Verified)],
            roster: vec![entry],
            approver,
        };
        (snap, keys)
    }

    fn v2_grant() -> FullGrantV2 {
        let account = Id::new();
        FullGrantV2 {
            full: FullGrant {
                account_id: account,
                secret_key: Zeroizing::new("A3-SECRET-KEY".into()),
                mode: DeviceMode::Personal,
                device_id: Id::new(),
                snapshot: vec![],
            },
            trust: snapshot(account).0,
            sync: None,
            enroll: None,
        }
    }

    #[test]
    fn confirmed_encoding_unchanged() {
        // Existing frames stay byte for byte (global constraint).
        assert_eq!(*Message::Confirmed.encode().unwrap(), [0]);
        assert_eq!(Message::decode(&[0]).unwrap(), Message::Confirmed);
    }

    #[test]
    fn v2_variants_are_appended_and_strict() {
        let (snap, keys) = snapshot(Id::new());
        let device = snap.approver.clone();
        let pop = crate::device_keys::sign_pop(&keys, &[1; 32], &device).unwrap();
        for credential in [None, Some([5u8; 32])] {
            let m = Message::ConfirmedWithKey {
                device: device.clone(),
                pop: pop.clone(),
                mailbox_credential: credential,
            };
            let b = m.encode().unwrap();
            assert_eq!(b[0], 6, "ConfirmedWithKey is index 6");
            assert_eq!(Message::decode(&b).unwrap(), m);
            let mut trailing = b.to_vec();
            trailing.push(0);
            assert!(Message::decode(&trailing).is_err());
        }
        let g = v2_grant();
        let m = Message::Grant(Grant::FullV2(g.clone()));
        let b = m.encode().unwrap();
        assert_eq!(&b[..2], &[1, 2], "Grant::FullV2 is index 2");
        assert_eq!(Message::decode(&b).unwrap(), m);
        assert!(!format!("{m:?}").contains("A3-SECRET-KEY"));

        // Bounded opaque fields, and the snapshot's rules, at decode.
        let mut big = g.clone();
        big.sync = Some(vec![0; MAX_GRANT_SYNC_BYTES + 1]);
        let b = Message::Grant(Grant::FullV2(big)).encode().unwrap();
        assert!(Message::decode(&b).is_err());
        let mut big = g.clone();
        big.enroll = Some(vec![0; MAX_GRANT_ENROLL_BYTES + 1]);
        let b = Message::Grant(Grant::FullV2(big)).encode().unwrap();
        assert!(Message::decode(&b).is_err());
        let mut no_approver = g.clone();
        no_approver.trust.approver = snapshot(Id::new()).0.approver;
        let b = Message::Grant(Grant::FullV2(no_approver)).encode().unwrap();
        assert!(Message::decode(&b).is_err());
        let mut other_account = g.clone();
        other_account.full.account_id = Id::new();
        let b = Message::Grant(Grant::FullV2(other_account))
            .encode()
            .unwrap();
        assert!(Message::decode(&b).is_err());
        let mut empty = g;
        empty.trust.lineage.clear();
        let b = Message::Grant(Grant::FullV2(empty)).encode().unwrap();
        assert!(Message::decode(&b).is_err());
    }

    #[test]
    fn trust_snapshot_rules() {
        let (snap, _) = snapshot(Id::new());
        snap.check().unwrap();
        // Unsorted or duplicated roster.
        let mut dup = snap.clone();
        dup.roster.push(dup.roster[0].clone());
        assert!(dup.check().is_err());
        // A chain that does not start with a genesis, or does not link.
        let mut twice = snap.clone();
        twice.lineage.push(twice.lineage[0].clone());
        assert!(twice.check().is_err());
        // Levels missing, or out of roster order.
        let mut no_levels = snap.clone();
        no_levels.levels.clear();
        assert!(no_levels.check().is_err());
        let mut wrong_id = snap.clone();
        wrong_id.levels[0].0 = Id::new();
        assert!(wrong_id.check().is_err());
        // The approver with another key than the roster's.
        let mut rekeyed = snap;
        rekeyed.approver.sign_pub = snapshot(Id::new()).0.approver.sign_pub;
        assert!(rekeyed.check().is_err());
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
