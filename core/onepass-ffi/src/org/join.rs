//! The join requests an org client has read (R2): the change feed cursor
//! and the live requests by account id, kept in memory between polls, and
//! what each one proved against the pin (checked once per pinned roster).

use std::collections::{BTreeMap, HashMap};

use num_bigint::BigUint;
use onepass_core::generator::Wordlist;
use onepass_core::org::{
    MemberState, OrgPin, SignedJoinRequest, VerifiedJoin, join_code_of, member_kem_hash,
    verify_join_request,
};
use onepass_mailbox::ChangeFeed;
use onepass_mailbox::org::{JoinFeedDelta, join_record_id};

/// The feed cursor and the live requests. A fresh client starts with a full
/// fetch; a `reset` delta (expired cursor, new incarnation) rebuilds it.
pub(super) struct JoinCache {
    pub(super) feed: ChangeFeed,
    live: BTreeMap<[u8; 16], Cached>,
}

struct Cached {
    bytes: Vec<u8>,
    /// The verdict and the roster seq of the pin it was reached under.
    verdict: Option<(u64, Verdict)>,
}

/// What a stored request proves under the pinned roster.
#[derive(Clone)]
pub(super) enum Verdict {
    /// Not verifiable (bad signature or shape, another account's invitation,
    /// a credential that is no Ed25519 key, ...): counted nowhere.
    Dropped,
    /// A verified request of an Invited member, waiting for the admin.
    Invited {
        joined: VerifiedJoin,
        code_words: Vec<String>,
        issued_at: i64,
    },
    /// The request of a member past Invited (Active, Suspended, Removed)
    /// whose identity and KEM hash match its roster entry: used for names.
    Member(VerifiedJoin),
}

impl JoinCache {
    pub(super) fn new() -> JoinCache {
        JoinCache {
            feed: ChangeFeed::full(),
            live: BTreeMap::new(),
        }
    }

    /// Applies what the feed returned since the cursor. A tombstone names a
    /// record id only: it is matched with `join_record_id` over the accounts
    /// held.
    pub(super) fn apply(&mut self, org_id: &[u8; 16], delta: JoinFeedDelta) {
        if delta.reset {
            self.live.clear();
        }
        for id in &delta.removed {
            self.live
                .retain(|account, _| join_record_id(org_id, account) != *id);
        }
        for (account, bytes) in delta.upserts {
            self.live.insert(
                account,
                Cached {
                    bytes,
                    verdict: None,
                },
            );
        }
    }

    pub(super) fn remove(&mut self, account: &[u8; 16]) {
        self.live.remove(account);
    }

    /// Every live request with its verdict under `pin` (computed when the
    /// pinned roster changed since the last look).
    pub(super) fn verdicts(&mut self, pin: &OrgPin) -> Vec<Verdict> {
        self.live
            .iter_mut()
            .map(|(account, c)| c.verdict(pin, account))
            .collect()
    }

    /// The verified request of `account` under `pin` (Invited, or past
    /// Invited with the roster's identity and KEM hash), from the requests
    /// read so far; `None` when there is none or it was dropped.
    pub(super) fn verified(&mut self, pin: &OrgPin, account: &[u8; 16]) -> Option<VerifiedJoin> {
        match self.live.get_mut(account)?.verdict(pin, account) {
            Verdict::Invited { joined, .. } | Verdict::Member(joined) => Some(joined),
            Verdict::Dropped => None,
        }
    }

    /// Display names by account id from every verified request.
    pub(super) fn names(&mut self, pin: &OrgPin) -> HashMap<[u8; 16], String> {
        self.verdicts(pin)
            .into_iter()
            .filter_map(|v| match v {
                Verdict::Invited { joined, .. } | Verdict::Member(joined) => {
                    Some((joined.account_id().0, joined.display_name().to_owned()))
                }
                Verdict::Dropped => None,
            })
            .collect()
    }
}

impl Cached {
    /// The verdict under `pin`, judged again once the pinned roster moved.
    fn verdict(&mut self, pin: &OrgPin, account: &[u8; 16]) -> Verdict {
        let seq = pin.roster_seq().unwrap_or(0);
        match &self.verdict {
            Some((at, v)) if *at == seq => v.clone(),
            _ => {
                let v = judge(pin, account, &self.bytes);
                self.verdict = Some((seq, v.clone()));
                v
            }
        }
    }
}

/// The verdict on the request stored under `account`.
fn judge(pin: &OrgPin, account: &[u8; 16], bytes: &[u8]) -> Verdict {
    let Some(roster) = pin.roster() else {
        return Verdict::Dropped;
    };
    let Ok(req) = SignedJoinRequest::decode(bytes) else {
        return Verdict::Dropped;
    };
    if req.body.account_id.0 != *account || !ed25519_point_ok(&req.body.mailbox_credential) {
        return Verdict::Dropped;
    }
    let Some(m) = roster.member(req.body.account_id) else {
        return Verdict::Dropped;
    };
    let fpr = pin.fingerprint();
    if m.state == MemberState::Invited {
        return match (
            verify_join_request(&req, roster, &fpr),
            join_code_of(&req, Wordlist::EffEnglish),
        ) {
            (Ok(joined), Ok(code)) => Verdict::Invited {
                joined,
                code_words: code.into_iter().collect(),
                issued_at: req.body.issued_at,
            },
            _ => Verdict::Dropped,
        };
    }
    // The core verifies Invited members only (R25). The roster entry keeps
    // its `invite_commit` once activated, so the same checks run against a
    // copy of the roster where this member is still Invited; then the
    // identity and KEM key must be the ones the roster froze.
    let mut as_invited = roster.clone();
    for e in as_invited.members.iter_mut() {
        if e.account_id == m.account_id {
            e.state = MemberState::Invited;
        }
    }
    match verify_join_request(&req, &as_invited, &fpr) {
        Ok(joined)
            if m.account_identity_pub.as_ref() == Some(joined.account_identity_pub())
                && member_kem_hash(joined.account_kem_pub()) == m.account_kem_hash =>
        {
            Verdict::Member(joined)
        }
        _ => Verdict::Dropped,
    }
}

/// Small-order encodings the mailbox server refuses as credential keys.
const SMALL_ORDER: [[u8; 32]; 8] = {
    let mut out = [[0u8; 32]; 8];
    out[0][0] = 1;
    out[1] = [0xff; 32];
    out[1][0] = 0xec;
    out[1][31] = 0x7f;
    // out[2] stays zero.
    out[3][31] = 0x80;
    out[4] = [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ];
    out[5] = out[4];
    out[5][31] = 0x85;
    out[6] = [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ];
    out[7] = out[6];
    out[7][31] = 0xfa;
    out
};

/// `key` decodes as an Ed25519 public key (RFC 8032 5.1.3: canonical `y`,
/// a square `x^2`, no negative zero) and is not of small order (R17). The
/// mailbox crate's `CredentialKey` carries the bytes but checks nothing,
/// and aws-lc parses a raw Ed25519 key without decoding the point.
pub(super) fn ed25519_point_ok(bytes: &[u8; 32]) -> bool {
    if SMALL_ORDER.contains(bytes) {
        return false;
    }
    let p = (BigUint::from(1u8) << 255u32) - 19u32;
    let sign = bytes[31] >> 7;
    let mut y = *bytes;
    y[31] &= 0x7f;
    let y = BigUint::from_bytes_le(&y);
    if y >= p {
        return false;
    }
    let inv = |v: &BigUint| v.modpow(&(&p - 2u32), &p);
    // d = -121665 / 121666
    let d = (&p - 121_665u32) * inv(&BigUint::from(121_666u32)) % &p;
    let y2 = &y * &y % &p;
    let u = (&y2 + &p - 1u32) % &p;
    let v = (d * &y2 + 1u32) % &p;
    let x2 = u * inv(&v) % &p;
    if x2 == BigUint::ZERO {
        return sign == 0;
    }
    // Euler's criterion: x^2 has a square root.
    x2.modpow(&((&p - 1u32) >> 1u32), &p) == BigUint::from(1u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_points() {
        // The base point, and a generated credential key.
        let mut base = [0x66u8; 32];
        base[0] = 0x58;
        assert!(ed25519_point_ok(&base));
        let c = onepass_mailbox::Credential::from_seed(&[7; 32]).unwrap();
        assert!(ed25519_point_ok(c.public_key().as_bytes()));
        // y = 2 is off the curve; y = p is not canonical; small order.
        let mut two = [0u8; 32];
        two[0] = 2;
        assert!(!ed25519_point_ok(&two));
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert!(!ed25519_point_ok(&p));
        for k in SMALL_ORDER {
            assert!(!ed25519_point_ok(&k));
        }
        // Negative zero x (y = 1 with the sign bit) is refused.
        let mut neg = [0u8; 32];
        neg[0] = 1;
        neg[31] = 0x80;
        assert!(!ed25519_point_ok(&neg));
    }
}
