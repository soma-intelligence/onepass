//! The signed contact card (spec 5.2, plan ruling A-3) and its strict codec.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::lineage::{LegacyAccepted, LegacyIntros, accept_legacy_intros, grow_roster};
use super::{
    CONTACT_CARD_DOMAIN, CONTACT_CARD_FORMAT, MAX_CARD_INTROS_PER_RECORD, MAX_CONTACT_NAME_CHARS,
};
use crate::account::AccountParams;
use crate::crypto::sign::{SLH_PUBLIC_LEN, SLH_SIG_LEN};
use crate::crypto::{
    HybridKemPublic, HybridVerifyingKey, IdentityKey, IdentitySignature, IdentityVerifyingKey,
};
use crate::lineage::{
    LineageRecord, SignedIntro, SignedLegacyIntro, decode_strict_with, identity_id, intro_id,
};
use crate::repo::Repository;
use crate::store::{RecordKind, RecordStore};
use crate::trust::LineageHead;
use crate::{Error, Id, IntegrityError, Result, ValidationError};

const BAD: Error = Error::InvalidFormat("contact card");

fn bad(what: &'static str) -> Error {
    Error::InvalidFormat(what)
}

/// What an account shows a contact (spec 5.2). The intros accepted under
/// every record of the lineage travel beside it (plan ruling A-3): a peer
/// pinned at an older head needs them to check a rotation made by a device
/// introduced after its pin (spec 5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCard {
    pub format: u8,
    pub account_id: Id,
    /// Lineage hash of the account's genesis.
    pub genesis: [u8; 32],
    /// Generation and hash of the head when the card was issued.
    pub head: LineageHead,
    /// The identity of `head`.
    pub identity_pub: IdentityVerifyingKey,
    /// The `AccountParams` record of that identity, signed by it.
    pub params: Vec<u8>,
    /// Genesis first, then every rotation up to `head`, in order.
    pub lineage: Vec<LineageRecord>,
    /// Intros accepted under the records of `lineage`, each bound to one of
    /// them, at most `MAX_CARD_INTROS_PER_RECORD` per record, sorted by
    /// intro id, unique.
    pub intros: Vec<SignedIntro>,
    /// Legacy (TOFU) intros of the devices migrated from before key
    /// rotation v2 (rotation spec 15, owner ruling O4): each bound to the
    /// genesis of this account, one per device id, sorted by device id, at
    /// most `MAX_CARD_INTROS_PER_RECORD`.
    pub legacy_intros: Vec<SignedLegacyIntro>,
    /// The `AccountParams` record of the genesis identity, whose account
    /// signing key checks `legacy_intros`: present exactly when
    /// `legacy_intros` is not empty.
    pub genesis_params: Option<Vec<u8>>,
    /// Chosen by the holder: 1 to 64 characters, none of them a control,
    /// bidi, zero-width or line/paragraph separator character.
    /// Never shown as is: the contact book keeps its own name.
    pub name: String,
    pub issued_at: i64,
}

/// A card and the identity signature over `postcard(card)`, domain
/// `onepass/contact-card/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContactCard {
    pub card: ContactCard,
    pub identity_sig: IdentitySignature,
}

/// The account keys a verified card yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardKeys {
    pub sign_pub: HybridVerifyingKey,
    pub kem_pub: HybridKemPublic,
    pub identity_id: Id,
}

/// Control characters (Cc), and the invisible or reordering ones a name
/// could hide behind: soft hyphen, Arabic letter mark, Mongolian vowel
/// separator, zero-width space and bidi marks, embeddings and isolates, line
/// and paragraph separators, word joiner and invisible operators, BOM. ZWNJ
/// (U+200C) and ZWJ (U+200D) stay allowed: Persian names and emoji
/// sequences need them.
fn forbidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'
                | '\u{200E}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

fn check_name(name: &str) -> Result<()> {
    let n = name.chars().count();
    if n == 0 || n > MAX_CONTACT_NAME_CHARS || name.chars().any(forbidden) {
        return Err(bad("contact card name"));
    }
    Ok(())
}

impl ContactCard {
    /// Shape rules (no signature is checked): format, name, key and params
    /// layout, a lineage that starts at a genesis hashing to `genesis`,
    /// chains generation by generation and ends at `head` under
    /// `identity_pub`, and intros each bound to a record of the lineage,
    /// at most `MAX_CARD_INTROS_PER_RECORD` per record, sorted and unique.
    fn check(&self) -> Result<()> {
        if self.format != CONTACT_CARD_FORMAT {
            return Err(bad("contact card format"));
        }
        check_name(&self.name)?;
        if self.identity_pub.as_bytes().len() != SLH_PUBLIC_LEN {
            return Err(bad("identity public key length"));
        }
        AccountParams::decode(&self.params)?;

        let Some(LineageRecord::Genesis(_)) = self.lineage.first() else {
            return Err(bad("contact card lineage"));
        };
        let mut parent: Option<[u8; 32]> = None;
        for (i, record) in self.lineage.iter().enumerate() {
            // The same checks as a record read on its own.
            LineageRecord::decode(&record.encode())?;
            if record.account_id() != self.account_id
                || record.generation() != i as u64
                || record.parent() != parent
            {
                return Err(bad("contact card lineage"));
            }
            parent = Some(record.hash());
        }
        let last = self.lineage.last().expect("lineage is not empty");
        if self.lineage[0].hash() != self.genesis
            || last.hash() != self.head.hash
            || last.generation() != self.head.generation
            || *last.identity_pub() != self.identity_pub
        {
            return Err(bad("contact card head"));
        }

        let hashes: BTreeSet<[u8; 32]> = self.lineage.iter().map(LineageRecord::hash).collect();
        let mut per_record: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        let mut previous: Option<Id> = None;
        for intro in &self.intros {
            SignedIntro::decode(&intro.encode())?;
            let id = intro_id(&intro.body);
            if intro.body.account_id != self.account_id
                || !hashes.contains(&intro.body.head)
                || previous.is_some_and(|p| p >= id)
            {
                return Err(bad("contact card intros"));
            }
            let n = per_record.entry(intro.body.head).or_default();
            *n += 1;
            if *n > MAX_CARD_INTROS_PER_RECORD {
                return Err(bad("contact card intros"));
            }
            previous = Some(id);
        }

        if self.legacy_intros.len() > MAX_CARD_INTROS_PER_RECORD
            || self.legacy_intros.is_empty() != self.genesis_params.is_none()
        {
            return Err(bad("contact card legacy intros"));
        }
        if let Some(p) = &self.genesis_params {
            AccountParams::decode(p)?;
        }
        let mut previous: Option<Id> = None;
        for intro in &self.legacy_intros {
            SignedLegacyIntro::decode(&intro.encode())?;
            let id = intro.body.entry.device_id;
            if intro.body.account_id != self.account_id
                || intro.body.genesis_hash != self.genesis
                || previous.is_some_and(|p| p >= id)
            {
                return Err(bad("contact card legacy intros"));
            }
            previous = Some(id);
        }
        Ok(())
    }

    /// The legacy intros and genesis params, as `follow_foreign` takes them.
    pub fn legacy(&self) -> LegacyIntros<'_> {
        LegacyIntros {
            intros: &self.legacy_intros,
            genesis_params: self.genesis_params.as_deref(),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("contact card encodes")
    }
}

impl SignedContactCard {
    /// Check the card's shape, then sign it with the identity of its head.
    /// A key other than `card.identity_pub` is `Validation`.
    pub fn sign(card: ContactCard, identity: &IdentityKey) -> Result<SignedContactCard> {
        card.check()?;
        if identity.verifying_key() != card.identity_pub {
            return Err(Error::Validation(ValidationError {
                field: "identity".into(),
                reason: "not the identity of the card",
            }));
        }
        let identity_sig = identity.sign(CONTACT_CARD_DOMAIN, &card.bytes())?;
        Ok(SignedContactCard { card, identity_sig })
    }

    /// Canonical postcard encoding.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("signed contact card encodes")
    }

    /// Strict: the whole buffer, a canonical re-encoding equal to the
    /// input, the shape rules of the card and a signature of the right
    /// length. Anything else is `InvalidFormat`. No signature is verified
    /// (see `keys`).
    pub fn decode(b: &[u8]) -> Result<SignedContactCard> {
        let signed: SignedContactCard = decode_strict_with(b, BAD)?;
        signed.card.check()?;
        if signed.identity_sig.as_bytes().len() != SLH_SIG_LEN {
            return Err(bad("identity signature length"));
        }
        Ok(signed)
    }

    /// The account keys of the card: the identity signature under
    /// `identity_pub`, then the params record signed by that identity
    /// (`Integrity(Signature)` otherwise), then the params' account id
    /// equal to the card's (`Integrity(WrongContext)` otherwise). The
    /// lineage is not verified here.
    pub fn keys(&self) -> Result<CardKeys> {
        let card = &self.card;
        card.identity_pub
            .verify(CONTACT_CARD_DOMAIN, &card.bytes(), &self.identity_sig)?;
        let params = AccountParams::decode_verified(&card.params, &card.identity_pub)?;
        if params.account_id != card.account_id {
            return Err(IntegrityError::WrongContext.into());
        }
        Ok(CardKeys {
            sign_pub: params.signing_pub,
            kem_pub: params.kem_pub,
            identity_id: identity_id(&card.identity_pub),
        })
    }
}

impl<S: RecordStore> Repository<S> {
    /// This account's card at the head pinned by the local trust state:
    /// the whole lineage from the genesis, the intros accepted under each
    /// of its records (`accepted_intros`), the params record of the
    /// session's identity and `name`, the profile name the app keeps (the
    /// core stores none). Signed by the identity, then checked with
    /// `keys()` before it leaves.
    ///
    /// Refused: no trust state (`Validation("device")`); a trust state of
    /// another account or identity than the session's (`WrongContext`); a
    /// lineage record or the params record missing (`NotFound`); a `name`
    /// that breaks the card rules (`InvalidFormat`); a params record that
    /// is not the session identity's (`Integrity`).
    pub fn own_contact_card(&self, name: &str, now: i64) -> Result<SignedContactCard> {
        let trust = self.store.trust_state()?.ok_or_else(|| {
            Error::Validation(ValidationError {
                field: "device".into(),
                reason: "no trust state",
            })
        })?;
        let params = &self.account.params;
        if trust.account_id != params.account_id || trust.identity_pub != params.identity_pub {
            return Err(IntegrityError::WrongContext.into());
        }
        let account_id = trust.account_id;

        // Lineage records by hash; the ones that do not decode or belong
        // to another account are ignored (the server may plant them).
        let mut by_hash = BTreeMap::new();
        for r in self.store.list(RecordKind::Lineage)? {
            if let Ok(record) = LineageRecord::decode(&r.data)
                && record.account_id() == account_id
            {
                by_hash.insert(record.hash(), record);
            }
        }
        let mut lineage = Vec::new();
        let mut at = Some(trust.head.hash);
        while let Some(hash) = at {
            let record = by_hash.remove(&hash).ok_or(Error::NotFound)?;
            at = record.parent();
            lineage.push(record);
            if lineage.len() as u64 > trust.head.generation.saturating_add(1) {
                return Err(bad("contact card lineage"));
            }
        }
        lineage.reverse();
        let genesis = lineage[0].hash();

        // Intros and legacy intros share the `DeviceIntro` kind; each
        // record is read as whichever of the two it decodes as.
        let mut by_head: BTreeMap<[u8; 32], Vec<SignedIntro>> = BTreeMap::new();
        let mut legacy_pending: Vec<SignedLegacyIntro> = Vec::new();
        for r in self.store.list(RecordKind::DeviceIntro)? {
            if let Ok(intro) = SignedIntro::decode(&r.data) {
                if intro.body.account_id == account_id {
                    by_head.entry(intro.body.head).or_default().push(intro);
                }
            } else if let Ok(intro) = SignedLegacyIntro::decode(&r.data)
                && intro.body.account_id == account_id
                && intro.body.genesis_hash == genesis
            {
                legacy_pending.push(intro);
            }
        }
        let trusted_now = |e: &crate::lineage::RosterEntry| {
            trust.roster.iter().any(|t| {
                t.device_id == e.device_id && t.sign_pub == e.sign_pub && t.kem_pub == e.kem_pub
            }) && !trust.revoked.contains(&e.device_id)
                && !trust.excluded.contains(&e.device_id)
        };

        // Legacy intros, checked as a contact will check them: under the
        // account signing key of the genesis identity (spec 15 step 3).
        let LineageRecord::Genesis(g) = &lineage[0] else {
            return Err(bad("contact card lineage"));
        };
        let mut genesis_params = None;
        let mut legacy = LegacyAccepted::default();
        if !legacy_pending.is_empty()
            && let Some(rec) = self.store.get(
                RecordKind::AccountParams,
                crate::store::account_record_id(account_id, None),
            )?
            && let Ok(p) = AccountParams::decode_verified(&rec.data, &g.body.identity_pub)
            && p.account_id == account_id
        {
            legacy = accept_legacy_intros(g, &p.signing_pub, &legacy_pending);
            // Under the head, only what this device trusts now.
            if trust.head.generation == 0 {
                legacy.entries.retain(|e| trusted_now(e));
            }
            if !legacy.entries.is_empty() {
                genesis_params = Some(rec.data);
            }
        }
        let legacy_ids: BTreeSet<Id> = legacy.entries.iter().map(|e| e.device_id).collect();
        let mut legacy_intros: Vec<SignedLegacyIntro> = Vec::new();
        for id in &legacy_ids {
            // The intro whose entry was kept (smallest encoding).
            let kept = legacy.entries.iter().find(|e| e.device_id == *id);
            if let Some(i) = legacy_pending
                .iter()
                .filter(|i| Some(&i.body.entry) == kept)
                .min_by_key(|i| i.encode())
            {
                legacy_intros.push(i.clone());
            }
        }
        let mut intros = BTreeMap::new();
        for record in &lineage {
            let pending = by_head.remove(&record.hash()).unwrap_or_default();
            let at_head = record.hash() == trust.head.hash;
            let record_legacy = match record {
                LineageRecord::Genesis(_) => legacy.clone(),
                LineageRecord::Rotation(_) => LegacyAccepted::default(),
            };
            for intro in accepted_intros(record, &record_legacy, pending) {
                // Under the head, only what this device trusts now.
                if !at_head || trusted_now(&intro.body.entry) {
                    intros.insert(intro_id(&intro.body), intro);
                }
            }
        }

        let params_record = self
            .store
            .get(RecordKind::AccountParams, self.records_id)?
            .ok_or(Error::NotFound)?;
        let card = ContactCard {
            format: CONTACT_CARD_FORMAT,
            account_id,
            genesis,
            head: trust.head,
            identity_pub: trust.identity_pub,
            params: params_record.data,
            lineage,
            intros: intros.into_values().collect(),
            legacy_intros,
            genesis_params,
            name: name.to_string(),
            issued_at: now,
        };
        let signed = SignedContactCard::sign(card, &self.account.keyset().identity)?;
        signed.keys()?;
        Ok(signed)
    }
}

/// The intros of `pending` (all bound to `record`) that extend its roster
/// (`lineage::grow_roster`, with the record's legacy entries, nothing
/// excluded), in the order accepted.
fn accepted_intros(
    record: &LineageRecord,
    legacy: &LegacyAccepted,
    pending: Vec<SignedIntro>,
) -> Vec<SignedIntro> {
    grow_roster(record, legacy, pending, &BTreeSet::new()).1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(check_name(&"é".repeat(64)).is_ok());
        assert!(check_name(&"é".repeat(65)).is_err());
        assert!(check_name("").is_err());
        assert!(check_name("a\u{0007}").is_err());
        assert!(check_name("a\nb").is_err());
        assert!(check_name("a\u{7f}").is_err());
        for c in [
            '\u{202E}', '\u{200B}', '\u{2028}', '\u{2029}', '\u{FEFF}', '\u{2066}',
        ] {
            assert!(check_name(&format!("a{c}b")).is_err(), "{c:?}");
        }
        assert!(check_name("Zoë Ångström-Łódź 日本").is_ok());
        assert!(check_name("Camille Durand").is_ok());
        assert!(
            check_name("\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}").is_ok()
        );
        assert!(check_name("Sam \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}").is_ok());
        assert!(check_name("a\u{200E}b").is_err());
    }
}
