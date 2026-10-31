//! The signed contact card (spec 5.2, plan ruling A-3) and its strict codec.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CONTACT_CARD_DOMAIN, CONTACT_CARD_FORMAT, MAX_CONTACT_NAME_CHARS};
use crate::account::AccountParams;
use crate::crypto::sign::{SLH_PUBLIC_LEN, SLH_SIG_LEN};
use crate::crypto::{
    HybridKemPublic, HybridVerifyingKey, IdentityKey, IdentitySignature, IdentityVerifyingKey,
};
use crate::lineage::{
    LineageRecord, MAX_ROSTER, SignedIntro, decode_strict_with, identity_id, intro_id,
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
/// the head travel beside the lineage (plan ruling A-3).
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
    /// Intros accepted under `head`, sorted by intro id, unique.
    pub intros: Vec<SignedIntro>,
    /// Chosen by the holder: 1 to 64 characters, no control character.
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

fn check_name(name: &str) -> Result<()> {
    let n = name.chars().count();
    if n == 0 || n > MAX_CONTACT_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(bad("contact card name"));
    }
    Ok(())
}

impl ContactCard {
    /// Shape rules (no signature is checked): format, name, key and params
    /// layout, a lineage that starts at a genesis hashing to `genesis`,
    /// chains generation by generation and ends at `head` under
    /// `identity_pub`, and intros under `head`, sorted and unique.
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

        if self.intros.len() > MAX_ROSTER {
            return Err(bad("contact card intros"));
        }
        let mut previous: Option<Id> = None;
        for intro in &self.intros {
            SignedIntro::decode(&intro.encode())?;
            let id = intro_id(&intro.body);
            if intro.body.account_id != self.account_id
                || intro.body.head != self.head.hash
                || previous.is_some_and(|p| p >= id)
            {
                return Err(bad("contact card intros"));
            }
            previous = Some(id);
        }
        Ok(())
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
    /// the whole lineage from the genesis, the intros accepted under the
    /// head (their device in the trusted roster with the same keys), the
    /// params record of the session's identity and `name`, the profile
    /// name the app keeps (the core stores none). Signed by the identity.
    ///
    /// Refused: no trust state (`Validation("device")`); a trust state of
    /// another account or identity than the session's (`WrongContext`); a
    /// lineage record or the params record missing (`NotFound`); a `name`
    /// that breaks the card rules (`InvalidFormat`).
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

        let mut intros = BTreeMap::new();
        for r in self.store.list(RecordKind::DeviceIntro)? {
            let Ok(intro) = SignedIntro::decode(&r.data) else {
                continue;
            };
            let e = &intro.body.entry;
            let accepted = trust.roster.iter().any(|t| {
                t.device_id == e.device_id && t.sign_pub == e.sign_pub && t.kem_pub == e.kem_pub
            }) && !trust.revoked.contains(&e.device_id)
                && !trust.excluded.contains(&e.device_id);
            if intro.body.account_id == account_id && intro.body.head == trust.head.hash && accepted
            {
                intros.insert(intro_id(&intro.body), intro);
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
            name: name.to_string(),
            issued_at: now,
        };
        SignedContactCard::sign(card, &self.account.keyset().identity)
    }
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
        assert!(check_name("Camille Durand").is_ok());
    }
}
