//! Legacy intros (spec 15 step 3): the one rule that decides which
//! devices of a legacy account a genesis lets in, trusted on first use.
//!
//! A legacy intro lives in a `RecordKind::DeviceIntro` (11) record, like an
//! intro: id `legacy_intro_id` (the intro-id prefix of spec 6.1, no new
//! label), version 0 (the genesis it attaches to), data
//! `SignedLegacyIntro::encode()`, immutable. A reader tells the two kinds
//! apart by strict decoding (`SignedIntro::decode` first).
//!
//! `accept_legacy_intros` is a pure function of the intros and of what the
//! caller pinned, so every device that sees the same intros reaches the
//! same roster whatever the order they arrived in. It is the only place
//! the rule lives: the rotation code (`crate::repo::migrate`) calls it for
//! the device's own account, and the sharing code (`contact` on the
//! sharing branch) calls it at merge for a contact's account. Callers keep
//! their own policy on top (this device's own id, a roster device already
//! pinned through a SAS pairing).

use std::collections::{BTreeMap, BTreeSet};

use super::{INTRO_ID_PREFIX, LegacyIntroBody, RosterEntry, SignedLegacyIntro, body_bytes, id16};
use super::{sha256, verify_legacy_intro};
use crate::Id;
use crate::crypto::HybridVerifyingKey;

/// `SHA-256("onepass/intro-id/v1" || postcard(LegacyIntroBody))[..16]`: the
/// record id of a legacy intro.
pub fn legacy_intro_id(body: &LegacyIntroBody) -> Id {
    id16(sha256(&[INTRO_ID_PREFIX, &body_bytes(body)]))
}

/// What a legacy intro is checked against. Every field comes from the
/// caller's own pins, never from an intro.
#[derive(Debug, Clone, Copy)]
pub struct LegacyAnchor<'a> {
    pub account_id: Id,
    /// The lineage hash of the genesis the intros attach to.
    pub genesis_hash: [u8; 32],
    /// The account signing key of the genesis identity (the identity the
    /// account had when it migrated), from its verified params.
    pub account_sign: &'a HybridVerifyingKey,
    /// The genesis creator: pinned by the genesis itself, never by a
    /// legacy intro.
    pub creator: Id,
    /// The device ids present and not revoked in the account-signed device
    /// list.
    pub listed: &'a BTreeSet<Id>,
}

/// The outcome of `accept_legacy_intros`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyIntros {
    /// One entry per accepted device, sorted by id, `introduced_by: None`,
    /// to pin at level `Tofu`.
    pub accepted: Vec<RosterEntry>,
    /// Devices two valid intros gave two different keys: excluded until a
    /// verification (spec 15 step 3). Sorted.
    pub excluded: BTreeSet<Id>,
}

/// Spec 15 step 3. A legacy intro counts when it is for `anchor`'s account
/// and genesis, names no introducer, is for a device id listed and not
/// revoked (`anchor.listed`) other than the creator, and both its
/// signatures verify: the account signing key over the body (domain
/// `onepass/legacy-device/v1`) and the device's proof of possession over
/// the account id. One device id gets one entry: several valid intros with
/// the same keys count once (the entry with the smallest encoding wins, so
/// the result does not depend on their order), and valid intros with two
/// different keys put the id in `excluded` instead.
pub fn accept_legacy_intros(
    intros: &[SignedLegacyIntro],
    anchor: &LegacyAnchor<'_>,
) -> LegacyIntros {
    let mut found: BTreeMap<Id, Vec<&RosterEntry>> = BTreeMap::new();
    for i in intros {
        let b = &i.body;
        let id = b.entry.device_id;
        if b.account_id != anchor.account_id
            || b.genesis_hash != anchor.genesis_hash
            || b.entry.introduced_by.is_some()
            || id == anchor.creator
            || !anchor.listed.contains(&id)
            || verify_legacy_intro(i, anchor.account_sign).is_err()
        {
            continue;
        }
        found.entry(id).or_default().push(&b.entry);
    }
    let mut out = LegacyIntros::default();
    for (id, entries) in found {
        let first = entries[0];
        if entries
            .iter()
            .any(|e| e.sign_pub != first.sign_pub || e.kem_pub != first.kem_pub)
        {
            out.excluded.insert(id);
            continue;
        }
        let entry = entries
            .into_iter()
            .min_by_key(|e| body_bytes(*e))
            .expect("one entry at least");
        out.accepted.push(entry.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HybridSigningKey;
    use crate::device_keys::{DeviceKeys, DevicePublic, sign_pop};
    use crate::devices::{DeviceKind, DeviceMode};
    use crate::lineage::sign_legacy_intro;
    use std::sync::OnceLock;

    struct Dev {
        keys: DeviceKeys,
        public: DevicePublic,
    }

    fn dev(id: Id) -> Dev {
        let keys = DeviceKeys::generate_software().unwrap();
        let public = keys.public(id).unwrap();
        Dev { keys, public }
    }

    const ACCOUNT: Id = Id([7; 16]);
    const GENESIS: [u8; 32] = [9; 32];

    /// Account key, creator, B, C, and a second key for B's id.
    fn fixture() -> &'static (HybridSigningKey, Dev, Dev, Dev, Dev) {
        static F: OnceLock<(HybridSigningKey, Dev, Dev, Dev, Dev)> = OnceLock::new();
        F.get_or_init(|| {
            let b = dev(Id([2; 16]));
            (
                HybridSigningKey::generate().unwrap(),
                dev(Id([1; 16])),
                b,
                dev(Id([3; 16])),
                dev(Id([2; 16])),
            )
        })
    }

    fn intro_with(
        d: &Dev,
        name: &str,
        genesis: [u8; 32],
        key: &HybridSigningKey,
    ) -> SignedLegacyIntro {
        let p = &d.public;
        let body = LegacyIntroBody {
            account_id: ACCOUNT,
            genesis_hash: genesis,
            entry: RosterEntry {
                device_id: p.device_id,
                sign_pub: p.sign_pub.clone(),
                kem_pub: p.kem_pub.clone(),
                name: name.into(),
                kind: DeviceKind::Mac,
                mode: DeviceMode::Personal,
                introduced_by: None,
            },
            pop: sign_pop(&d.keys, &ACCOUNT.0, p).unwrap(),
        };
        sign_legacy_intro(body, key).unwrap()
    }

    fn intro(d: &Dev, name: &str) -> SignedLegacyIntro {
        intro_with(d, name, GENESIS, &fixture().0)
    }

    fn accept(intros: &[SignedLegacyIntro], listed: &[Id]) -> LegacyIntros {
        let (key, creator, ..) = fixture();
        let pubkey = key.verifying_key().unwrap();
        let listed: BTreeSet<Id> = listed.iter().copied().collect();
        accept_legacy_intros(
            intros,
            &LegacyAnchor {
                account_id: ACCOUNT,
                genesis_hash: GENESIS,
                account_sign: &pubkey,
                creator: creator.public.device_id,
                listed: &listed,
            },
        )
    }

    #[test]
    fn valid_intros_are_accepted_once_in_any_order() {
        let (_, creator, b, c, _) = fixture();
        let all = [b.public.device_id, c.public.device_id];
        let i = [
            intro(b, "Mac"),
            intro(c, "iPad"),
            intro(b, "Mac de Camille"),
        ];
        let out = accept(&i, &all);
        assert!(out.excluded.is_empty());
        let ids: Vec<Id> = out.accepted.iter().map(|e| e.device_id).collect();
        assert_eq!(ids, all);
        let mut rev = i.clone();
        rev.reverse();
        assert_eq!(accept(&rev, &all), out);
        // Never the creator.
        let mine = intro(creator, "iPhone");
        assert_eq!(
            accept(&[mine], &[creator.public.device_id]),
            LegacyIntros::default()
        );
    }

    #[test]
    fn refused_intros() {
        let (_, _, b, c, _) = fixture();
        let listed = [b.public.device_id, c.public.device_id];
        // Not listed (or revoked in the list).
        assert!(
            accept(&[intro(b, "Mac")], &[c.public.device_id])
                .accepted
                .is_empty()
        );
        // Another genesis.
        let other = intro_with(b, "Mac", [8; 32], &fixture().0);
        assert!(accept(&[other], &listed).accepted.is_empty());
        // Another account signing key.
        let forged = intro_with(b, "Mac", GENESIS, &HybridSigningKey::generate().unwrap());
        assert!(accept(&[forged], &listed).accepted.is_empty());
        // A proof of possession by another key.
        let mut bad_pop = intro(b, "Mac");
        bad_pop.body.pop = sign_pop(&c.keys, &ACCOUNT.0, &b.public).unwrap();
        let bad_pop = sign_legacy_intro(bad_pop.body, &fixture().0).unwrap();
        assert!(accept(&[bad_pop], &listed).accepted.is_empty());
        // An introducer named.
        let mut named = intro(b, "Mac");
        named.body.entry.introduced_by = Some(c.public.device_id);
        let named = sign_legacy_intro(named.body, &fixture().0).unwrap();
        assert!(accept(&[named], &listed).accepted.is_empty());
    }

    #[test]
    fn two_keys_for_one_id_exclude_it() {
        let (_, _, b, c, b2) = fixture();
        let listed = [b.public.device_id, c.public.device_id];
        let out = accept(
            &[intro(b, "Mac"), intro(c, "iPad"), intro(b2, "Mac")],
            &listed,
        );
        assert_eq!(out.excluded, BTreeSet::from([b.public.device_id]));
        assert_eq!(out.accepted.len(), 1);
        assert_eq!(out.accepted[0].device_id, c.public.device_id);
    }
}
