//! Contacts (sharing spec 5): signed contact cards, the signed contact
//! book, account fingerprints, safety numbers and pair ids.
//!
//! A contact card carries no new key: the signing and KEM keys of the
//! account come from its params record, signed by the identity of the
//! card's head (`SignedContactCard::keys`). The lineage in the card is only
//! shape-checked by the card; `follow_foreign` verifies it from a pinned
//! head (spec 5.5).

use aws_lc_rs::digest::{self, SHA256, SHA512};

use crate::Id;

mod book;
mod card;
mod lineage;
mod session;

pub use book::{CONTACT_BOOK_DOMAIN, ContactAlert, ContactEntry, ContactLevel, ContactState};
pub use card::{CardKeys, ContactCard, SignedContactCard};
pub use lineage::{
    ForeignLineage, ForeignPin, LegacyAccepted, LegacyIntros, MAX_FOREIGN_COPIES,
    accept_legacy_intros, follow_foreign, roster_at,
};
pub use session::{
    CONTACT_SESSION_SECS, ContactHello, ContactInitiator, ContactMessage, ContactOutcome,
    ContactResponder, MAX_CONTACT_HELLO_BYTES, MAX_CONTACT_MESSAGE_BYTES, VerifiedPeer,
};

/// Signature domain of a `ContactCard`, by the identity key (spec 19.1).
pub const CONTACT_CARD_DOMAIN: &[u8] = b"onepass/contact-card/v1";
/// Hash prefix of an account fingerprint (spec 19.1).
pub const CONTACT_FPR_PREFIX: &[u8] = b"onepass/contact-fpr/v1";
/// SHA-512 prefix of a safety number (plan ruling A-4).
pub const CONTACT_SAFETY_PREFIX: &[u8] = b"onepass/contact-safety/v1";
/// Hash prefix of a pair id (plan ruling A-6).
pub const CONTACT_PAIR_PREFIX: &[u8] = b"onepass/contact-pair/v1";
/// `wrap_key_labeled` label of the in-person verification channel and of
/// the remote invitation reply (spec 19.1, plan rulings A-2 and A-5).
pub const CONTACT_LABEL: &[u8] = b"onepass/contact/v1";
/// HKDF info of `K_inv` (spec 19.1).
pub const CONTACT_INVITE_INFO: &[u8] = b"onepass/contact-invite/v1";
/// Hash prefix of a public rendezvous id (spec 19.1).
pub const INVITE_RDV_PREFIX: &[u8] = b"onepass/invite-rdv/v1";

/// Format byte of a contact card.
pub const CONTACT_CARD_FORMAT: u8 = 1;
/// Longest display name of a card, in characters.
pub const MAX_CONTACT_NAME_CHARS: usize = 64;
/// Groups of a safety number.
pub const SAFETY_GROUPS: usize = 12;
/// Most intros a card carries under one record of its lineage: each one
/// adds a device to that record's roster, which holds at most
/// `lineage::MAX_ROSTER` devices.
pub const MAX_CARD_INTROS_PER_RECORD: usize = crate::lineage::MAX_ROSTER;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&SHA256);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// `SHA-256("onepass/contact-fpr/v1" || account_id || genesis ||
/// identity_id)` (spec 5.2).
pub fn fingerprint(account_id: Id, genesis: &[u8; 32], identity_id: Id) -> [u8; 32] {
    sha256(&[CONTACT_FPR_PREFIX, &account_id.0, genesis, &identity_id.0])
}

/// The safety number of a pair (plan ruling A-4): `h = SHA-512(
/// "onepass/contact-safety/v1" || min(fa, fb) || max(fa, fb))`, then group
/// `i` (0 to 11) is `u40_be(h[5i..5i+5]) % 100000`. Symmetric.
pub fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> [u32; SAFETY_GROUPS] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut ctx = digest::Context::new(&SHA512);
    ctx.update(CONTACT_SAFETY_PREFIX);
    ctx.update(lo);
    ctx.update(hi);
    let h = ctx.finish();
    let h = h.as_ref();
    let mut out = [0u32; SAFETY_GROUPS];
    for (i, group) in out.iter_mut().enumerate() {
        let v = h[5 * i..5 * i + 5]
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        *group = (v % 100_000) as u32;
    }
    out
}

/// Twelve groups of five digits, zero-padded, separated by one space.
/// Meant for the output of `safety_number`, whose groups are below
/// 100000; a larger group would print more than five digits.
pub fn format_safety_number(n: &[u32; SAFETY_GROUPS]) -> String {
    debug_assert!(n.iter().all(|g| *g < 100_000));
    n.iter()
        .map(|g| format!("{g:05}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `SHA-256("onepass/contact-pair/v1" || min(a, b) || max(a, b))[..16]`
/// over two account ids (plan ruling A-6). Symmetric.
pub fn pair_id(a: Id, b: Id) -> Id {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let h = sha256(&[CONTACT_PAIR_PREFIX, &lo.0, &hi.0]);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    Id(id)
}
