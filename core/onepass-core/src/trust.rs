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
//! sorted and unique lists, bounded sizes and well-formed keys. A later
//! change of the layout (the own-write log of milestone 10) bumps `version`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Id;
use crate::crypto::sign::{MLDSA_PUBLIC_LEN, SLH_PUBLIC_LEN};
use crate::crypto::{HybridVerifyingKey, IdentityVerifyingKey};
use crate::device_keys::DevicePublic;
use crate::lineage::{MAX_ROSTER, RosterEntry, check_entry, decode_strict_with};
use crate::{Error, Result};

/// Layout version, the first byte of `TrustState::encode`.
pub const TRUST_VERSION: u8 = 1;
/// Most rotation records kept in `ignored`.
pub const MAX_IGNORED: usize = 64;
/// Last phase of a rotation (spec 8.1: phases 1 to 3).
pub const MAX_ROTATION_PHASE: u8 = 3;

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
    /// decided by the user yet. Read-only.
    Candidate { children: Vec<[u8; 32]> },
    /// This device made the head and pushes phases 1 to 3.
    Rotating { phase: u8 },
    /// A valid child revokes this device. `since` is the device clock, in
    /// Unix seconds, when the quarantine was first entered.
    Quarantined { by: [u8; 32], since: u64 },
    /// A valid child does not list this device. Local data stays readable.
    Orphaned { child: [u8; 32] },
}

/// Own-write log (spec 10.4). Empty until milestone 10 fills it; that
/// change bumps `TrustState::version`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnWriteLog {}

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
        if self.ignored.len() > MAX_IGNORED {
            return Err(BAD);
        }
        let unique: BTreeSet<&[u8; 32]> = self.ignored.iter().collect();
        if unique.len() != self.ignored.len() {
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
            DeviceLineageState::Candidate { children } => {
                if children.is_empty() || !children.windows(2).all(|w| w[0] < w[1]) {
                    return Err(BAD);
                }
            }
            DeviceLineageState::Rotating { phase } if !(1..=MAX_ROTATION_PHASE).contains(phase) => {
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
        s
    }

    #[test]
    fn round_trip_every_state() {
        let states = [
            DeviceLineageState::Legacy,
            DeviceLineageState::Current,
            DeviceLineageState::Candidate {
                children: vec![[1; 32], [2; 32]],
            },
            DeviceLineageState::Rotating { phase: 2 },
            DeviceLineageState::Quarantined {
                by: [8; 32],
                since: 1_700_000_000,
            },
            DeviceLineageState::Orphaned { child: [9; 32] },
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
        version[0] = 2;
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

        for st in [
            DeviceLineageState::Rotating { phase: 0 },
            DeviceLineageState::Rotating { phase: 4 },
            DeviceLineageState::Candidate { children: vec![] },
            DeviceLineageState::Candidate {
                children: vec![[2; 32], [1; 32]],
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
