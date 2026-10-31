//! Local trust state of key rotation v2 (spec 5.3 and 8.1): what this device
//! believes about the account's lineage, its roster and the lifecycle state
//! of the device itself.
//!
//! It sits beside `ChainState` in the `meta` table of a store, under the key
//! `trust`, and is written in the same transaction as the records that
//! change it (`RecordStore::put_all_if_version_with_trust`). Nothing in it
//! is secret. Like `DeviceState` it is integrity-protected only by the
//! device (hostile local storage is out of scope).
//!
//! The encoding is `postcard`, versioned by the first field, decoded
//! strictly: the whole buffer, a canonical re-encoding equal to the input,
//! sorted and unique lists, bounded sizes and well-formed keys. Version 2
//! added the own-write log (spec 10.4), version 3 the migration notes of
//! spec 15 (`other_genesis`, `genesis_alert`, `rotate_now`, `conflicted`,
//! `migration_listed`);
//! versions 1 and 2 are refused (they never shipped).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Id;
use crate::crypto::sign::{MLDSA_PUBLIC_LEN, SLH_PUBLIC_LEN};
use crate::crypto::{HybridVerifyingKey, IdentityVerifyingKey};
use crate::device_keys::DevicePublic;
use crate::lineage::{MAX_ROSTER, RosterEntry, check_entry, decode_strict_with};
use crate::manifest::SeenManifest;
use crate::{Error, Result};

/// Layout version, the first byte of `TrustState::encode`.
pub const TRUST_VERSION: u8 = 3;
/// Most rotation records kept in `ignored`.
pub const MAX_IGNORED: usize = 64;
/// Last phase of a rotation (spec 8.1: phases 1 to 3).
pub const MAX_ROTATION_PHASE: u8 = 3;
/// Most genesis hashes kept in `other_genesis`.
pub const MAX_OTHER_GENESIS: usize = 16;

const BAD: Error = Error::InvalidFormat("trust state");

/// How a roster device came to be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Pinned by a verified pairing or a signed lineage record.
    Verified,
    /// Trusted on first use (legacy account, spec 15).
    Tofu,
}

/// The lineage record this device follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageHead {
    pub generation: u64,
    pub hash: [u8; 32],
}

/// An identity this device left (public data only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredIdentity {
    pub identity_id: Id,
    pub sign_pub: HybridVerifyingKey,
    pub identity_pub: IdentityVerifyingKey,
    pub generation: u64,
}

/// Lifecycle of this device along the lineage (spec 8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceLineageState {
    /// No device key yet (paired before this design).
    Legacy,
    /// Normal.
    Current,
    /// Valid children of the head are known (sorted, unique hashes), none
    /// decided by the user yet. Read-only. `resume`: the phase of this
    /// device's own rotation when a winning sibling made it `Candidate`
    /// (spec 8.2): rejecting the sibling, or the sibling going away, takes
    /// it back to `Rotating { phase }`; `None` from `Current`.
    Candidate {
        children: Vec<[u8; 32]>,
        resume: Option<u8>,
    },
    /// This device made the head and pushes phases 1 to 3.
    Rotating { phase: u8 },
    /// A valid child (`by`, signed by `rotator`) revokes this device.
    /// `since` is the device clock, in Unix seconds, when the quarantine was
    /// first entered. `resume`: the phase of this device's own rotation when
    /// the quarantine stopped it (from `Rotating`, or `Candidate` with a
    /// resume): "Ce n'était pas moi" takes it back to `Rotating { phase }`.
    Quarantined {
        by: [u8; 32],
        rotator: Id,
        since: u64,
        resume: Option<u8>,
    },
    /// A valid child (`child`, signed by `rotator`) does not list this
    /// device. Local data stays readable. `resume` as for `Quarantined`.
    Orphaned {
        child: [u8; 32],
        rotator: Id,
        resume: Option<u8>,
    },
}

/// Most intents kept in each list of the own-write log (spec 10.4).
pub const MAX_OWN_WRITES: usize = 10_000;
/// Intents older than this, in seconds, leave the own-write log (30 days).
pub const OWN_WRITE_MAX_AGE_SECS: i64 = 30 * 86_400;

/// One item intent this device wrote (spec 10.4): the item of `vault` it
/// saved, deleted or moved, the manifest the write was based on, when
/// (Unix seconds, device clock), and what it wrote: the `record_hash` of
/// its own item record, `None` for a deletion (or a move out). An intent
/// whose `item` is the vault id itself is a change of the vault's meta;
/// `wrote` is then the SHA-256 of the sealed meta it wrote. The replay
/// brings back only that very record (R11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnWrite {
    pub vault: Id,
    pub item: Id,
    pub based_on: SeenManifest,
    pub at: i64,
    pub wrote: Option<[u8; 32]>,
}

/// Own-write log (spec 10.4, G4, R7). `entries`: the item intents this
/// device wrote since the last head it adopted, one per item (a later
/// write of the same item replaces it and goes last), oldest first.
/// `replay`: the intents of the identity this device left by its last
/// adoption, waiting to be replayed under the new keys
/// (`crate::repo::replay`); `replay_heads` are the `from_heads` of that
/// adoption (empty when two adoptions piled up before a replay finished:
/// every intent then counts as not reflected). Each list keeps at most
/// `MAX_OWN_WRITES` intents, none older than `OWN_WRITE_MAX_AGE_SECS`;
/// `alert` is raised when an intent that may still be needed was dropped
/// for these bounds (the device keeps its local copy, the app offers
/// "Réimporter depuis cet appareil").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnWriteLog {
    pub entries: Vec<OwnWrite>,
    pub replay: Vec<OwnWrite>,
    pub replay_heads: BTreeMap<Id, SeenManifest>,
    pub alert: bool,
}

impl OwnWriteLog {
    /// Remember `w`, replacing an older intent of the same item, then apply
    /// the bounds (`prune` at `w.at`). `needed`: the device waits on a
    /// rotation prompt, so a dropped intent raises `alert`.
    pub fn record(&mut self, w: OwnWrite, needed: bool) {
        let now = w.at;
        self.entries
            .retain(|e| (e.vault, e.item) != (w.vault, w.item));
        self.entries.push(w);
        self.prune(now, needed);
    }

    /// Drop the intents older than `OWN_WRITE_MAX_AGE_SECS` at `now`, then
    /// the oldest beyond `MAX_OWN_WRITES` in each list. Dropping one of
    /// `replay`, or one of `entries` when `needed`, raises `alert`.
    pub fn prune(&mut self, now: i64, needed: bool) {
        let floor = now.saturating_sub(OWN_WRITE_MAX_AGE_SECS);
        let entries = bound(&mut self.entries, floor);
        let replay = bound(&mut self.replay, floor);
        if replay || (entries && needed) {
            self.alert = true;
        }
    }

    /// The adoption of a new head (spec 10.4): the intents written so far
    /// wait for the replay, with the rotation's `from_heads`; intents still
    /// waiting from an earlier adoption stay, and the heads are then
    /// unknown (empty).
    pub fn adopt(&mut self, from_heads: &BTreeMap<Id, SeenManifest>) {
        let fresh = std::mem::take(&mut self.entries);
        if self.replay.is_empty() {
            self.replay_heads = from_heads.clone();
        } else {
            self.replay_heads.clear();
        }
        for w in fresh {
            self.replay
                .retain(|e| (e.vault, e.item) != (w.vault, w.item));
            self.replay.push(w);
        }
        let excess = self.replay.len().saturating_sub(MAX_OWN_WRITES);
        if excess > 0 {
            self.replay.drain(..excess);
            self.alert = true;
        }
    }

    /// The vaults that still have intents to replay.
    pub fn replay_vaults(&self) -> BTreeSet<Id> {
        self.replay.iter().map(|w| w.vault).collect()
    }

    fn check(&self) -> bool {
        let unique = |l: &[OwnWrite]| {
            let keys: BTreeSet<(Id, Id)> = l.iter().map(|w| (w.vault, w.item)).collect();
            keys.len() == l.len()
        };
        self.entries.len() <= MAX_OWN_WRITES
            && self.replay.len() <= MAX_OWN_WRITES
            && unique(&self.entries)
            && unique(&self.replay)
    }
}

/// Drop from `l` the intents older than `floor`, then the oldest beyond
/// `MAX_OWN_WRITES`. Whether any went.
fn bound(l: &mut Vec<OwnWrite>, floor: i64) -> bool {
    let before = l.len();
    l.retain(|w| w.at >= floor);
    let excess = l.len().saturating_sub(MAX_OWN_WRITES);
    l.drain(..excess);
    l.len() != before
}

/// See the module doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustState {
    pub version: u8,
    pub account_id: Id,
    /// This device.
    pub me: DevicePublic,
    pub head: LineageHead,
    /// The identity of `head`.
    pub identity_pub: IdentityVerifyingKey,
    /// Devices trusted at `head`, sorted by id, at most 64.
    pub roster: Vec<RosterEntry>,
    pub levels: BTreeMap<Id, TrustLevel>,
    /// Every device revoked along the lineage. Monotone: only `add_revoked`
    /// touches it, and it never removes.
    pub revoked: BTreeSet<Id>,
    /// Devices the user distrusted on this device.
    pub excluded: BTreeSet<Id>,
    /// Rotation records the user rejected, oldest first, at most 64.
    pub ignored: Vec<[u8; 32]>,
    pub retired: Vec<RetiredIdentity>,
    pub own_writes: OwnWriteLog,
    pub state: DeviceLineageState,
    /// Spec 15.2: genesis records of this account, signed by the identity
    /// of this device's own genesis, that are not that genesis. Never
    /// followed. Sorted, unique, at most `MAX_OTHER_GENESIS`.
    pub other_genesis: Vec<[u8; 32]>,
    /// A hash joined `other_genesis` since the user last saw the alert
    /// (`Repository::clear_genesis_alert`).
    pub genesis_alert: bool,
    /// Spec 15.5: the account-signed device list held a device revoked
    /// under milestone 2b and no rotation followed, when this device
    /// migrated. Shown once: "Un appareil retiré garde encore les clés de
    /// ton compte. Fais tourner les clés maintenant."
    /// (`Repository::clear_rotate_now_prompt`).
    pub rotate_now: bool,
    /// Spec 15.3: devices excluded because two legacy intros gave them two
    /// keys. Always a subset of `excluded`; a verification
    /// (`Repository::verify_device`) lifts it.
    pub conflicted: BTreeSet<Id>,
    /// Spec 15 step 3 (Task 14 review I2): the devices listed and not
    /// revoked in the account-signed device list when this device migrated
    /// (or created the account). Only they can join by a legacy intro, or
    /// create a genesis this device switches to: a device listed later came
    /// through the extended pairing (`Verified`), never through TOFU.
    pub migration_listed: BTreeSet<Id>,
}

impl TrustState {
    /// A fresh state at version `TRUST_VERSION`: no level, no revocation,
    /// nothing ignored or retired, an empty log.
    pub fn new(
        account_id: Id,
        me: DevicePublic,
        head: LineageHead,
        identity_pub: IdentityVerifyingKey,
        roster: Vec<RosterEntry>,
        state: DeviceLineageState,
    ) -> TrustState {
        TrustState {
            version: TRUST_VERSION,
            account_id,
            me,
            head,
            identity_pub,
            roster,
            levels: BTreeMap::new(),
            revoked: BTreeSet::new(),
            excluded: BTreeSet::new(),
            ignored: Vec::new(),
            retired: Vec::new(),
            own_writes: OwnWriteLog::default(),
            state,
            other_genesis: Vec::new(),
            genesis_alert: false,
            rotate_now: false,
            conflicted: BTreeSet::new(),
            migration_listed: BTreeSet::new(),
        }
    }

    /// Canonical postcard encoding (the version is its first byte).
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("trust state encodes")
    }

    /// Strict: a known version, the whole buffer, a canonical re-encoding
    /// equal to the input and the structural rules of the fields.
    /// Anything else is `InvalidFormat("trust state")`.
    pub fn decode(b: &[u8]) -> Result<TrustState> {
        if b.first() != Some(&TRUST_VERSION) {
            return Err(BAD);
        }
        let s: TrustState = decode_strict_with(b, BAD)?;
        s.check()?;
        Ok(s)
    }

    fn check(&self) -> Result<()> {
        // Re-validates the key lengths and the ML-KEM key of this device.
        DevicePublic::decode(&self.me.encode()).map_err(|_| BAD)?;
        if self.identity_pub.as_bytes().len() != SLH_PUBLIC_LEN {
            return Err(BAD);
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
        }
        if self.ignored.len() > MAX_IGNORED || !self.own_writes.check() {
            return Err(BAD);
        }
        let unique: BTreeSet<&[u8; 32]> = self.ignored.iter().collect();
        if unique.len() != self.ignored.len() {
            return Err(BAD);
        }
        if self.other_genesis.len() > MAX_OTHER_GENESIS
            || !self.other_genesis.windows(2).all(|w| w[0] < w[1])
            || !self.conflicted.is_subset(&self.excluded)
        {
            return Err(BAD);
        }
        for r in &self.retired {
            if r.sign_pub.mldsa.len() != MLDSA_PUBLIC_LEN
                || r.identity_pub.as_bytes().len() != SLH_PUBLIC_LEN
            {
                return Err(BAD);
            }
        }
        match &self.state {
            DeviceLineageState::Candidate { children, resume } => {
                if children.is_empty()
                    || !children.windows(2).all(|w| w[0] < w[1])
                    || resume.is_some_and(|p| !(1..=MAX_ROTATION_PHASE).contains(&p))
                {
                    return Err(BAD);
                }
            }
            DeviceLineageState::Rotating { phase } if !(1..=MAX_ROTATION_PHASE).contains(phase) => {
                return Err(BAD);
            }
            DeviceLineageState::Quarantined { resume, .. }
            | DeviceLineageState::Orphaned { resume, .. }
                if resume.is_some_and(|p| !(1..=MAX_ROTATION_PHASE).contains(&p)) =>
            {
                return Err(BAD);
            }
            _ => {}
        }
        Ok(())
    }

    /// Add devices to `revoked`. There is no way to remove one.
    pub fn add_revoked(&mut self, ids: &[Id]) {
        self.revoked.extend(ids.iter().copied());
    }

    /// Remember a rotation record the user rejected. At most 64 are kept:
    /// the oldest goes first, and a hash seen again becomes the newest.
    pub fn ignore(&mut self, h: [u8; 32]) {
        self.ignored.retain(|x| *x != h);
        self.ignored.push(h);
        if self.ignored.len() > MAX_IGNORED {
            let excess = self.ignored.len() - MAX_IGNORED;
            self.ignored.drain(..excess);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto::IdentityKey;
    use crate::device_keys::DeviceKeys;
    use crate::devices::{DeviceKind, DeviceMode};
    use std::sync::OnceLock;

    /// SLH-DSA and ML-DSA key generation is slow: one set for the module.
    fn fixture() -> &'static (DevicePublic, DevicePublic, IdentityVerifyingKey) {
        static F: OnceLock<(DevicePublic, DevicePublic, IdentityVerifyingKey)> = OnceLock::new();
        F.get_or_init(|| {
            let a = DeviceKeys::generate_software().unwrap();
            let b = DeviceKeys::generate_software().unwrap();
            (
                a.public(Id([1; 16])).unwrap(),
                b.public(Id([2; 16])).unwrap(),
                IdentityKey::generate().unwrap().verifying_key(),
            )
        })
    }

    fn entry(p: &DevicePublic) -> RosterEntry {
        RosterEntry {
            device_id: p.device_id,
            sign_pub: p.sign_pub.clone(),
            kem_pub: p.kem_pub.clone(),
            name: "device".into(),
            kind: DeviceKind::Phone,
            mode: DeviceMode::Personal,
            introduced_by: None,
        }
    }

    pub fn sample() -> TrustState {
        let (a, b, id) = fixture();
        let mut s = TrustState::new(
            Id([9; 16]),
            a.clone(),
            LineageHead {
                generation: 3,
                hash: [7; 32],
            },
            id.clone(),
            vec![entry(a), entry(b)],
            DeviceLineageState::Current,
        );
        s.levels.insert(a.device_id, TrustLevel::Verified);
        s.levels.insert(b.device_id, TrustLevel::Tofu);
        s.add_revoked(&[Id([5; 16]), Id([4; 16])]);
        s.excluded.insert(Id([6; 16]));
        s.ignore([1; 32]);
        s.retired.push(RetiredIdentity {
            identity_id: Id([3; 16]),
            sign_pub: a.sign_pub.clone(),
            identity_pub: id.clone(),
            generation: 2,
        });
        let seen = SeenManifest {
            seq: 4,
            hash: [2; 32],
        };
        s.own_writes.record(
            OwnWrite {
                vault: Id([1; 16]),
                item: Id([2; 16]),
                based_on: seen.clone(),
                at: 1_700_000_000,
                wrote: Some([5; 32]),
            },
            false,
        );
        s.own_writes.replay_heads.insert(Id([1; 16]), seen);
        s.other_genesis = vec![[3; 32], [4; 32]];
        s.genesis_alert = true;
        s.rotate_now = true;
        s.conflicted.insert(Id([6; 16]));
        s.migration_listed.insert(Id([2; 16]));
        s
    }

    #[test]
    fn round_trip_every_state() {
        let states = [
            DeviceLineageState::Legacy,
            DeviceLineageState::Current,
            DeviceLineageState::Candidate {
                children: vec![[1; 32], [2; 32]],
                resume: Some(2),
            },
            DeviceLineageState::Rotating { phase: 2 },
            DeviceLineageState::Quarantined {
                by: [8; 32],
                rotator: Id([3; 16]),
                since: 1_700_000_000,
                resume: None,
            },
            DeviceLineageState::Quarantined {
                by: [8; 32],
                rotator: Id([3; 16]),
                since: 1_700_000_000,
                resume: Some(2),
            },
            DeviceLineageState::Orphaned {
                child: [9; 32],
                rotator: Id([3; 16]),
                resume: Some(3),
            },
        ];
        for st in states {
            let mut s = sample();
            s.state = st;
            let bytes = s.encode();
            assert_eq!(bytes[0], TRUST_VERSION);
            assert_eq!(TrustState::decode(&bytes).unwrap(), s);
        }
    }

    #[test]
    fn strict_decode() {
        let bad = Err(Error::InvalidFormat("trust state"));
        let good = sample().encode();
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(TrustState::decode(&trailing), bad);
        let mut version = good.clone();
        version[0] = 4;
        assert_eq!(TrustState::decode(&version), bad);
        // Versions 1 (no own-write log) and 2 (no migration notes) never
        // shipped.
        version[0] = 2;
        assert_eq!(TrustState::decode(&version), bad);
        version[0] = 1;
        assert_eq!(TrustState::decode(&version), bad);
        version[0] = 0;
        assert_eq!(TrustState::decode(&version), bad);
        assert_eq!(TrustState::decode(&[]), bad);
        assert_eq!(TrustState::decode(&good[..good.len() - 1]), bad);
    }

    #[test]
    fn structural_rules_are_enforced() {
        let bad = Err(Error::InvalidFormat("trust state"));
        let mut s = sample();
        s.roster.reverse();
        assert_eq!(TrustState::decode(&s.encode()), bad);

        let mut s = sample();
        s.ignored = (0..65u8).map(|i| [i; 32]).collect();
        assert_eq!(TrustState::decode(&s.encode()), bad);

        let mut s = sample();
        s.ignored = vec![[1; 32], [1; 32]];
        assert_eq!(TrustState::decode(&s.encode()), bad);

        let mut s = sample();
        s.other_genesis = vec![[4; 32], [3; 32]];
        assert_eq!(TrustState::decode(&s.encode()), bad);

        let mut s = sample();
        s.other_genesis = (0..=MAX_OTHER_GENESIS as u8).map(|i| [i; 32]).collect();
        assert_eq!(TrustState::decode(&s.encode()), bad);

        // A conflicted device is always excluded too.
        let mut s = sample();
        s.conflicted.insert(Id([8; 16]));
        assert_eq!(TrustState::decode(&s.encode()), bad);

        for st in [
            DeviceLineageState::Rotating { phase: 0 },
            DeviceLineageState::Rotating { phase: 4 },
            DeviceLineageState::Candidate {
                children: vec![],
                resume: None,
            },
            DeviceLineageState::Candidate {
                children: vec![[2; 32], [1; 32]],
                resume: None,
            },
            DeviceLineageState::Candidate {
                children: vec![[1; 32]],
                resume: Some(4),
            },
            DeviceLineageState::Quarantined {
                by: [8; 32],
                rotator: Id([3; 16]),
                since: 1,
                resume: Some(0),
            },
            DeviceLineageState::Orphaned {
                child: [9; 32],
                rotator: Id([3; 16]),
                resume: Some(4),
            },
        ] {
            let mut s = sample();
            s.state = st;
            assert_eq!(TrustState::decode(&s.encode()), bad);
        }

        let mut s = sample();
        s.me.sign_pub.mldsa.pop();
        assert_eq!(TrustState::decode(&s.encode()), bad);
    }

    #[test]
    fn revoked_is_monotone() {
        let mut s = sample();
        let before = s.revoked.clone();
        s.add_revoked(&[Id([5; 16]), Id([8; 16])]);
        assert!(s.revoked.is_superset(&before));
        assert_eq!(s.revoked.len(), before.len() + 1);
        // Round trip keeps the set, however it is re-encoded.
        let back = TrustState::decode(&s.encode()).unwrap();
        assert_eq!(back.revoked, s.revoked);
        assert_eq!(
            TrustState::decode(&back.encode()).unwrap().revoked,
            s.revoked
        );
    }

    fn write(item: u8, at: i64) -> OwnWrite {
        OwnWrite {
            vault: Id([1; 16]),
            item: Id([item; 16]),
            based_on: SeenManifest {
                seq: 1,
                hash: [0; 32],
            },
            at,
            wrote: None,
        }
    }

    #[test]
    fn own_writes_are_strict() {
        let bad = Err(Error::InvalidFormat("trust state"));
        let mut s = sample();
        s.own_writes.entries.push(s.own_writes.entries[0].clone());
        assert_eq!(TrustState::decode(&s.encode()), bad);
        let mut s = sample();
        s.own_writes.replay = (0..=MAX_OWN_WRITES)
            .map(|i| OwnWrite {
                item: Id((i as u128).to_be_bytes()),
                ..write(0, 0)
            })
            .collect();
        assert_eq!(TrustState::decode(&s.encode()), bad);
    }

    #[test]
    fn own_writes_keep_one_intent_per_item() {
        let mut log = OwnWriteLog::default();
        log.record(write(1, 10), false);
        log.record(write(2, 11), false);
        log.record(write(1, 12), false);
        let items: Vec<(Id, i64)> = log.entries.iter().map(|w| (w.item, w.at)).collect();
        assert_eq!(items, vec![(Id([2; 16]), 11), (Id([1; 16]), 12)]);
        assert!(!log.alert);
    }

    #[test]
    fn adopt_moves_entries_to_replay() {
        let mut log = OwnWriteLog::default();
        log.record(write(1, 10), false);
        let heads = BTreeMap::from([(
            Id([1; 16]),
            SeenManifest {
                seq: 3,
                hash: [3; 32],
            },
        )]);
        log.adopt(&heads);
        assert!(log.entries.is_empty());
        assert_eq!(log.replay.len(), 1);
        assert_eq!(log.replay_heads, heads);
        // A second adoption before the replay finished: heads unknown.
        log.record(write(2, 11), false);
        log.adopt(&heads);
        assert_eq!(log.replay.len(), 2);
        assert!(log.replay_heads.is_empty());
        assert_eq!(log.replay_vaults(), BTreeSet::from([Id([1; 16])]));
    }

    #[test]
    fn ignored_is_capped() {
        let mut s = sample();
        s.ignored.clear();
        for i in 0..65u8 {
            s.ignore([i; 32]);
        }
        assert_eq!(s.ignored.len(), MAX_IGNORED);
        assert_eq!(s.ignored[0], [1; 32], "oldest dropped");
        assert_eq!(s.ignored[63], [64; 32]);
        // Seen again: moved to the newest slot, no duplicate.
        s.ignore([1; 32]);
        assert_eq!(s.ignored.len(), MAX_IGNORED);
        assert_eq!(s.ignored[63], [1; 32]);
        assert_eq!(s.ignored[0], [2; 32]);
        assert!(TrustState::decode(&s.encode()).is_ok());
    }
}
