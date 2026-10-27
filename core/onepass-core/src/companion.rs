//! Apple Watch companion payload and widget glance snapshot (milestone 6).
//!
//! The watch receives a closed list of fields of the items marked
//! `on_watch`, sealed to the watch's hybrid KEM key:
//! `"OPC1" || generation (u64 BE) || KEM envelope || blob`. The envelope
//! wraps a random payload key under the label `onepass/companion/v1` and
//! the context `"watch" || SHA-256(recipient public key)`. The blob seals
//! the postcard payload under that key (`BlobKind::Companion`), bound to
//! a blob id derived from the magic, the generation and the recipient
//! fingerprint: the generation in the clear header is authenticated.
//!
//! Never copied: a Login password, a card CVV, PIN or full number, notes,
//! and every field outside the allowlist of `allowlist`.

use std::cmp::Ordering;
use std::fmt;

use aws_lc_rs::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::crypto::kem::{self, HybridKemPublic, HybridKemSecret};
use crate::crypto::{Aad, BlobKind, SymmetricKey, open, seal};
use crate::model::{BarcodeFormat, FieldValue, Item, ItemType, template};
use crate::repo::Repository;
use crate::store::RecordStore;
use crate::totp::{self, TotpAlgorithm, TotpConfig};
use crate::{Error, Id, IntegrityError, Result};

/// At most this many entries in a payload.
pub const MAX_ENTRIES: usize = 50;
/// A field value longer than this (in bytes) is left out.
pub const MAX_VALUE_BYTES: usize = 1024;
/// At most this many favorites, and this many code lists, in a snapshot.
pub const MAX_GLANCE_ITEMS: usize = 8;
/// The snapshot window is capped at 24 hours.
pub const MAX_GLANCE_WINDOW_SECS: u64 = 86_400;
/// At most this many codes per item (24 h at 30 s): a short period keeps
/// only the earliest codes, from the period containing `now` forward.
pub const MAX_GLANCE_CODES_PER_ITEM: usize = 2880;

const MAGIC: &[u8; 4] = b"OPC1";
/// Magic and generation.
const HEADER: usize = 12;
const KEM_LABEL: &[u8] = b"onepass/companion/v1";
const KEM_CONTEXT_PREFIX: &[u8] = b"watch";
const SCHEMA: u16 = 1;

/// Everything the watch shows, as of `generated_at` (unix seconds).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompanionPayload {
    pub generation: u64,
    pub generated_at: i64,
    pub entries: Vec<CompanionEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompanionEntry {
    pub item_id: Id,
    pub vault_id: Id,
    pub item_type: ItemType,
    pub title: String,
    pub subtitle: String,
    /// The first filled TOTP field of the item, never repeated in `fields`.
    pub totp: Option<CompanionTotp>,
    pub fields: Vec<CompanionField>,
}

/// A TOTP seed and its parameters (no issuer, no account).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CompanionTotp {
    pub seed: Zeroizing<Vec<u8>>,
    #[serde(with = "algorithm_code")]
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
    pub steam: bool,
}

impl CompanionTotp {
    pub fn from_config(cfg: &TotpConfig) -> CompanionTotp {
        CompanionTotp {
            seed: cfg.secret.clone(),
            algorithm: cfg.algorithm,
            digits: cfg.digits,
            period: cfg.period,
            steam: cfg.steam,
        }
    }

    pub fn config(&self) -> TotpConfig {
        TotpConfig {
            secret: self.seed.clone(),
            algorithm: self.algorithm,
            digits: self.digits,
            period: self.period,
            issuer: None,
            account: None,
            steam: self.steam,
        }
    }
}

impl fmt::Debug for CompanionTotp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompanionTotp")
            .field("seed", &"**")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("steam", &self.steam)
            .finish()
    }
}

/// `TotpAlgorithm` has no serde form of its own: one byte on the wire.
mod algorithm_code {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use crate::totp::TotpAlgorithm;

    pub fn serialize<S: Serializer>(a: &TotpAlgorithm, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(match a {
            TotpAlgorithm::Sha1 => 1,
            TotpAlgorithm::Sha256 => 2,
            TotpAlgorithm::Sha512 => 3,
        })
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<TotpAlgorithm, D::Error> {
        match u8::deserialize(d)? {
            1 => Ok(TotpAlgorithm::Sha1),
            2 => Ok(TotpAlgorithm::Sha256),
            3 => Ok(TotpAlgorithm::Sha512),
            _ => Err(D::Error::custom("otp algorithm")),
        }
    }
}

/// How the watch shows a field. Postcard encodes variants by index: new
/// variants must only ever be appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompanionFieldKind {
    Text,
    Concealed,
    Barcode(BarcodeFormat),
}

/// One copied field: the template's French label and the value as text.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CompanionField {
    pub label: String,
    pub value: Zeroizing<String>,
    pub kind: CompanionFieldKind,
}

impl fmt::Debug for CompanionField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompanionField")
            .field("label", &self.label)
            .field("value", &"**")
            .field("kind", &self.kind)
            .finish()
    }
}

/// What the widgets show while the app is locked: no secret but the codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlanceSnapshot {
    pub generated_at: i64,
    pub valid_until: i64,
    pub favorites: Vec<GlanceItem>,
    pub codes: Vec<GlanceCodes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlanceItem {
    pub item_id: Id,
    pub vault_id: Id,
    pub item_type: ItemType,
    pub title: String,
}

/// The TOTP codes of one favorite: `(period start, code)` for every
/// period that overlaps the snapshot window.
#[derive(Clone, PartialEq, Eq)]
pub struct GlanceCodes {
    pub item_id: Id,
    pub vault_id: Id,
    pub title: String,
    pub period: u32,
    pub codes: Vec<(i64, String)>,
}

impl fmt::Debug for GlanceCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlanceCodes")
            .field("item_id", &self.item_id)
            .field("vault_id", &self.vault_id)
            .field("title", &self.title)
            .field("period", &self.period)
            .field("codes", &self.codes.len())
            .finish()
    }
}

/// How an allowed field is copied.
#[derive(Clone, Copy)]
enum Rule {
    Text,
    Concealed,
    Barcode,
    /// `•••• ` and the last four digits of the card number.
    CardMask,
}

/// The closed list of copied fields per type (spec table 3.2), in order.
fn allowlist(t: ItemType) -> &'static [(&'static str, Rule)] {
    use Rule::{Barcode, CardMask, Concealed, Text};
    match t {
        ItemType::Login => &[("username", Text)],
        ItemType::Router => &[
            ("ssid", Text),
            ("wifi_password", Concealed),
            ("guest_ssid", Text),
            ("guest_password", Concealed),
        ],
        ItemType::Membership => &[
            ("organization", Text),
            ("member_number", Concealed),
            ("barcode", Barcode),
        ],
        ItemType::RewardProgram => &[
            ("company", Text),
            ("member_number", Concealed),
            ("barcode", Barcode),
        ],
        ItemType::CreditCard => &[("cardholder", Text), ("number", CardMask), ("expiry", Text)],
        ItemType::AccessCode => &[
            ("code", Concealed),
            ("alarm_code", Concealed),
            ("instructions", Text),
        ],
        ItemType::IdCard | ItemType::Passport => &[
            ("last_name", Text),
            ("first_names", Text),
            ("number", Concealed),
            ("expiry", Text),
        ],
        ItemType::DriverLicense => &[("full_name", Text), ("number", Concealed), ("expiry", Text)],
        _ => &[],
    }
}

/// TOTP text of a field, parsed like `totp_now` of the FFI: an
/// `otpauth://` URI (prefix in any case), else a bare base32 secret.
fn parse_totp(text: &str) -> Result<TotpConfig> {
    let text = text.trim();
    let is_uri = text
        .get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"));
    if is_uri {
        totp::parse_otpauth(text)
    } else {
        totp::totp_from_secret(text)
    }
}

/// The first filled TOTP field of the item, if it parses and yields a
/// code. An unusable seed is dropped, never an error.
fn item_totp(item: &Item) -> Option<TotpConfig> {
    let text = item
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .find_map(|f| match &f.value {
            FieldValue::Otp(v) if !v.trim().is_empty() => Some(v),
            _ => None,
        })?;
    let cfg = parse_totp(text).ok()?;
    totp::code_at(&cfg, 0).ok()?;
    Some(cfg)
}

/// A value as display text, or `None` for an empty or non-text value.
fn value_text(v: &FieldValue) -> Option<Zeroizing<String>> {
    let s = match v {
        FieldValue::Text(s)
        | FieldValue::Url(s)
        | FieldValue::Email(s)
        | FieldValue::Phone(s)
        | FieldValue::Menu(s) => Zeroizing::new(s.clone()),
        FieldValue::Concealed(s) | FieldValue::Password(s) => s.clone(),
        FieldValue::Number(n) => Zeroizing::new(n.to_string()),
        FieldValue::Date(d) => Zeroizing::new(format!(
            "{:02}/{:02}/{:04}",
            d.day(),
            u8::from(d.month()),
            d.year()
        )),
        FieldValue::MonthYear { year, month } => Zeroizing::new(format!("{month:02}/{year:04}")),
        _ => return None,
    };
    (!s.trim().is_empty()).then_some(s)
}

fn card_mask(v: &FieldValue) -> Option<Zeroizing<String>> {
    let number = value_text(v)?;
    let digits: Zeroizing<Vec<u8>> =
        Zeroizing::new(number.bytes().filter(u8::is_ascii_digit).collect());
    let last4 = digits.get(digits.len().checked_sub(4)?..)?;
    let mut out = Zeroizing::new(String::from("•••• "));
    out.extend(last4.iter().map(|b| char::from(*b)));
    Some(out)
}

fn copy_fields(item: &Item) -> Vec<CompanionField> {
    let labels = template(item.item_type);
    let label_of = |id: &str, fallback: &str| {
        labels
            .iter()
            .flat_map(|s| s.fields.iter())
            .find(|f| f.id == id)
            .map_or_else(|| fallback.to_owned(), |f| f.label.clone())
    };
    let mut out = Vec::new();
    for (id, how) in allowlist(item.item_type) {
        let Some(field) = item.field(id) else {
            continue;
        };
        let copied = match how {
            Rule::Text => value_text(&field.value).map(|v| (v, CompanionFieldKind::Text)),
            Rule::Concealed => value_text(&field.value).map(|v| (v, CompanionFieldKind::Concealed)),
            Rule::CardMask => card_mask(&field.value).map(|v| (v, CompanionFieldKind::Text)),
            Rule::Barcode => match &field.value {
                FieldValue::Barcode { value, format } if !value.trim().is_empty() => Some((
                    Zeroizing::new(value.clone()),
                    CompanionFieldKind::Barcode(*format),
                )),
                _ => None,
            },
        };
        let Some((value, mut kind)) = copied else {
            continue;
        };
        // A secret source value stays masked whatever the rule says (an
        // imported item may hold one in a field the template calls text).
        if kind == CompanionFieldKind::Text
            && matches!(
                field.value,
                FieldValue::Concealed(_) | FieldValue::Password(_)
            )
            && !matches!(how, Rule::CardMask)
        {
            kind = CompanionFieldKind::Concealed;
        }
        if value.len() > MAX_VALUE_BYTES {
            continue;
        }
        out.push(CompanionField {
            label: label_of(id, &field.label),
            value,
            kind,
        });
    }
    out
}

/// Not in the trash, not archived, not behind a biometric reprompt, and
/// not in a vault hidden from this device.
fn is_live(item: &Item, excluded_vaults: &[Id]) -> bool {
    item.trashed_at.is_none()
        && !item.archived
        && !item.reprompt
        && !excluded_vaults.contains(&item.vault_id)
}

/// Case-insensitive title order, then exact title, then id: deterministic.
fn by_title(a: &Item, b: &Item) -> Ordering {
    a.title
        .to_lowercase()
        .cmp(&b.title.to_lowercase())
        .then_with(|| a.title.cmp(&b.title))
        .then_with(|| a.id.cmp(&b.id))
}

/// The live items of every vault not in `excluded_vaults` that `keep`
/// accepts, sorted by title.
fn live_items<S: RecordStore>(
    repo: &mut Repository<S>,
    excluded_vaults: &[Id],
    keep: impl Fn(&Item) -> bool,
) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    for vault in repo.vaults()? {
        if excluded_vaults.contains(&vault.id) {
            continue;
        }
        out.extend(
            repo.items(&vault)?
                .into_iter()
                .filter(|i| is_live(i, excluded_vaults) && keep(i)),
        );
    }
    out.sort_by(by_title);
    Ok(out)
}

/// The watch payload: the live `on_watch` items, sorted by title, at most
/// `MAX_ENTRIES`. An item with no allowed field and no TOTP is left out.
pub fn build_payload<S: RecordStore>(
    repo: &mut Repository<S>,
    generation: u64,
    now: OffsetDateTime,
    excluded_vaults: &[Id],
) -> Result<CompanionPayload> {
    let items = live_items(repo, excluded_vaults, |i| i.on_watch)?;
    let mut entries = Vec::new();
    for item in &items {
        if entries.len() == MAX_ENTRIES {
            break;
        }
        let totp = item_totp(item).map(|c| CompanionTotp::from_config(&c));
        let fields = copy_fields(item);
        if totp.is_none() && fields.is_empty() {
            continue;
        }
        let mut subtitle = item.subtitle();
        if subtitle.len() > MAX_VALUE_BYTES {
            subtitle.clear();
        }
        entries.push(CompanionEntry {
            item_id: item.id,
            vault_id: item.vault_id,
            item_type: item.item_type,
            title: item.title.clone(),
            subtitle,
            totp,
            fields,
        });
    }
    Ok(CompanionPayload {
        generation,
        generated_at: now.unix_timestamp(),
        entries,
    })
}

fn fingerprint(recipient: &HybridKemPublic) -> [u8; 32] {
    let mut fp = [0u8; 32];
    fp.copy_from_slice(digest(&SHA256, &recipient.to_bytes()).as_ref());
    fp
}

fn kem_context(fp: &[u8; 32]) -> Vec<u8> {
    [KEM_CONTEXT_PREFIX, &fp[..]].concat()
}

fn blob_aad(generation: u64, fp: &[u8; 32]) -> Aad {
    let h = digest(
        &SHA256,
        &[&MAGIC[..], &generation.to_be_bytes(), fp].concat(),
    );
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.as_ref()[..16]);
    Aad {
        blob_id: Id(id),
        vault_id: None,
        schema: SCHEMA,
    }
}

/// Seal `payload` to the watch key `recipient`.
pub fn seal_payload(payload: &CompanionPayload, recipient: &HybridKemPublic) -> Result<Vec<u8>> {
    let fp = fingerprint(recipient);
    let key = SymmetricKey::generate()?;
    let envelope = kem::wrap_key_labeled(recipient, &key, KEM_LABEL, &kem_context(&fp))?;
    // Exact size first, then one write into a wiped buffer: no growing
    // plain Vec leaves copies of values or seeds behind.
    let bad = |_| Error::InvalidFormat("companion payload");
    let size = postcard::experimental::serialized_size(payload).map_err(bad)?;
    let mut plain = Zeroizing::new(vec![0u8; size]);
    let used = postcard::to_slice(payload, &mut plain).map_err(bad)?.len();
    plain.truncate(used);
    let blob = seal(
        &key,
        BlobKind::Companion,
        &blob_aad(payload.generation, &fp),
        &plain,
    )?;
    let mut out = Vec::with_capacity(HEADER + envelope.len() + blob.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&payload.generation.to_be_bytes());
    out.extend_from_slice(&envelope);
    out.extend_from_slice(&blob);
    Ok(out)
}

/// Open a payload sealed to `secret`. Fails on an unknown format, a
/// wrong key, any altered byte, or a generation that does not match the
/// one inside the blob.
pub fn open_payload(secret: &HybridKemSecret, sealed: &[u8]) -> Result<CompanionPayload> {
    let env_len = kem::envelope_len();
    if sealed.len() <= HEADER + env_len || &sealed[..4] != MAGIC {
        return Err(Error::InvalidFormat("companion payload"));
    }
    let mut gen_bytes = [0u8; 8];
    gen_bytes.copy_from_slice(&sealed[4..HEADER]);
    let generation = u64::from_be_bytes(gen_bytes);
    let (envelope, blob) = sealed[HEADER..].split_at(env_len);

    let fp = fingerprint(&secret.public()?);
    let key = kem::unwrap_key_labeled(secret, envelope, KEM_LABEL, &kem_context(&fp))?;
    let plain = open(&key, BlobKind::Companion, &blob_aad(generation, &fp), blob)?;
    let payload: CompanionPayload =
        postcard::from_bytes(&plain).map_err(|_| Error::InvalidFormat("companion payload"))?;
    if payload.generation != generation {
        return Err(IntegrityError::WrongContext.into());
    }
    if payload.entries.len() > MAX_ENTRIES {
        return Err(Error::InvalidFormat("companion payload"));
    }
    Ok(payload)
}

/// The widget snapshot at `now_unix`: live favorites sorted by title (at
/// most `MAX_GLANCE_ITEMS`) and, for those with a usable TOTP, the codes
/// of every period that overlaps `[now, now + window]`, at most
/// `MAX_GLANCE_CODES_PER_ITEM` per item. The window is capped at
/// `MAX_GLANCE_WINDOW_SECS`; `valid_until` is not shortened by the code
/// cap (the widget refreshes when a date has no code).
pub fn glance_snapshot<S: RecordStore>(
    repo: &mut Repository<S>,
    now_unix: i64,
    window_secs: u64,
    excluded_vaults: &[Id],
) -> Result<GlanceSnapshot> {
    let now = u64::try_from(now_unix).map_err(|_| Error::InvalidFormat("glance time"))?;
    let window = window_secs.min(MAX_GLANCE_WINDOW_SECS);
    let end = now
        .checked_add(window)
        .filter(|e| i64::try_from(*e).is_ok())
        .ok_or(Error::InvalidFormat("glance time"))?;

    let mut items = live_items(repo, excluded_vaults, |i| i.favorite)?;
    items.truncate(MAX_GLANCE_ITEMS);

    let mut codes = Vec::new();
    for item in &items {
        let Some(cfg) = item_totp(item) else {
            continue;
        };
        let period = u64::from(cfg.period);
        let mut list = Vec::new();
        let mut start = now - now % period;
        while start <= end && list.len() < MAX_GLANCE_CODES_PER_ITEM {
            list.push((start as i64, totp::code_at(&cfg, start)?));
            start += period;
        }
        codes.push(GlanceCodes {
            item_id: item.id,
            vault_id: item.vault_id,
            title: item.title.clone(),
            period: cfg.period,
            codes: list,
        });
    }

    Ok(GlanceSnapshot {
        generated_at: now_unix,
        valid_until: end as i64,
        favorites: items
            .iter()
            .map(|i| GlanceItem {
                item_id: i.id,
                vault_id: i.vault_id,
                item_type: i.item_type,
                title: i.title.clone(),
            })
            .collect(),
        codes,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use time::macros::{date, datetime};

    use super::*;
    use crate::account::{Account, NewAccount};
    use crate::crypto::{KdfParams, random_array};
    use crate::model::{BarcodeFormat, Field, FieldType, FieldValue, Location, Section, new_item};
    use crate::repo::DeviceState;
    use crate::store::{MemoryStore, Record, RecordKind};
    use crate::vault::{Vault, VaultMeta};

    const SEED: &str = "JBSWY3DPEHPK3PXP";
    const NOW: OffsetDateTime = datetime!(2026-10-26 10:00:07 UTC);

    /// One account for every test: SLH-DSA creation is slow.
    fn shared() -> &'static NewAccount {
        static N: OnceLock<NewAccount> = OnceLock::new();
        N.get_or_init(|| {
            let kdf = KdfParams {
                m_kib: 8192,
                t: 1,
                p: 1,
                salt: random_array().unwrap(),
            };
            Account::create_with_params("pw", kdf).unwrap()
        })
    }

    fn vault_meta(name: &str) -> VaultMeta {
        VaultMeta {
            name: name.into(),
            icon: "key".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        }
    }

    /// A fresh store holding a copy of the shared account, unlocked, with
    /// one vault "Perso".
    fn fixture() -> (Repository<MemoryStore>, Vault) {
        let n = shared();
        let id = n.account.params.account_id;
        let mut store = MemoryStore::new();
        for (kind, data) in [
            (RecordKind::AccountParams, &n.params_record),
            (RecordKind::Keyset, &n.keyset_record),
        ] {
            store
                .put(Record {
                    id,
                    kind,
                    version: 1,
                    data: data.clone(),
                })
                .unwrap();
        }
        let mut repo =
            Repository::unlock(store, "pw", &n.secret_key, DeviceState::default()).unwrap();
        let v = repo.create_vault(vault_meta("Perso")).unwrap();
        (repo, v)
    }

    fn item(v: &Vault, t: ItemType, title: &str) -> Item {
        let mut it = new_item(t, v.id, title);
        it.on_watch = true;
        it
    }

    fn set(it: &mut Item, id: &str, value: FieldValue) {
        it.field_mut(id).unwrap().value = value;
    }

    fn text(s: &str) -> FieldValue {
        FieldValue::Text(s.into())
    }

    fn concealed(s: &str) -> FieldValue {
        FieldValue::Concealed(Zeroizing::new(s.into()))
    }

    fn login(v: &Vault, title: &str, user: &str, otp: Option<&str>) -> Item {
        let mut it = item(v, ItemType::Login, title);
        set(&mut it, "username", text(user));
        set(
            &mut it,
            "password",
            FieldValue::Password(Zeroizing::new("motdepasse".into())),
        );
        if let Some(o) = otp {
            set(&mut it, "totp", FieldValue::Otp(Zeroizing::new(o.into())));
        }
        it
    }

    fn save(repo: &mut Repository<MemoryStore>, v: &Vault, items: Vec<Item>) {
        for it in items {
            repo.save_item(v, it).unwrap();
        }
    }

    fn entry<'a>(p: &'a CompanionPayload, title: &str) -> &'a CompanionEntry {
        p.entries.iter().find(|e| e.title == title).unwrap()
    }

    fn fields(e: &CompanionEntry) -> Vec<(&str, &str, CompanionFieldKind)> {
        e.fields
            .iter()
            .map(|f| (f.label.as_str(), f.value.as_str(), f.kind))
            .collect()
    }

    fn sample_payload() -> CompanionPayload {
        let a = CompanionEntry {
            item_id: Id::new(),
            vault_id: Id::new(),
            item_type: ItemType::Login,
            title: "Exemple".into(),
            subtitle: "camille.durand@exemple.fr".into(),
            totp: Some(CompanionTotp::from_config(&parse_totp(SEED).unwrap())),
            fields: vec![CompanionField {
                label: "Identifiant".into(),
                value: Zeroizing::new("camille.durand@exemple.fr".into()),
                kind: CompanionFieldKind::Text,
            }],
        };
        let b = CompanionEntry {
            item_id: Id::new(),
            vault_id: Id::new(),
            item_type: ItemType::Membership,
            title: "Médiathèque".into(),
            subtitle: String::new(),
            totp: None,
            fields: vec![
                CompanionField {
                    label: "Numéro de membre".into(),
                    value: Zeroizing::new("A-1234".into()),
                    kind: CompanionFieldKind::Concealed,
                },
                CompanionField {
                    label: "Code-barres".into(),
                    value: Zeroizing::new("1234567890128".into()),
                    kind: CompanionFieldKind::Barcode(BarcodeFormat::Ean13),
                },
            ],
        };
        CompanionPayload {
            generation: 7,
            generated_at: 1_790_000_000,
            entries: vec![a, b],
        }
    }

    // Sealing.

    #[test]
    fn seal_open_round_trip() {
        let sk = HybridKemSecret::generate().unwrap();
        let p = sample_payload();
        let sealed = seal_payload(&p, &sk.public().unwrap()).unwrap();
        assert_eq!(&sealed[..4], b"OPC1");
        assert_eq!(&sealed[4..12], &7u64.to_be_bytes());
        let opened = open_payload(&sk, &sealed).unwrap();
        assert_eq!(opened, p);
        let cfg = opened.entries[0].totp.as_ref().unwrap().config();
        assert_eq!(
            totp::code_at(&cfg, 59).unwrap(),
            totp::code_at(&parse_totp(SEED).unwrap(), 59).unwrap()
        );
    }

    #[test]
    fn wrong_key_fails() {
        let sk = HybridKemSecret::generate().unwrap();
        let sealed = seal_payload(&sample_payload(), &sk.public().unwrap()).unwrap();
        let other = HybridKemSecret::generate().unwrap();
        assert!(open_payload(&other, &sealed).is_err());
    }

    #[test]
    fn tamper_any_byte_fails() {
        let sk = HybridKemSecret::generate().unwrap();
        let sealed = seal_payload(&sample_payload(), &sk.public().unwrap()).unwrap();
        let blob_start = HEADER + kem::envelope_len();
        for i in [
            0,
            3,
            4,
            11,
            HEADER,
            HEADER + 1600,
            blob_start,
            sealed.len() - 1,
        ] {
            let mut t = sealed.clone();
            t[i] ^= 1;
            assert!(open_payload(&sk, &t).is_err(), "byte {i}");
        }
        assert!(open_payload(&sk, &sealed[..sealed.len() - 1]).is_err());
        assert!(open_payload(&sk, &sealed[..HEADER]).is_err());
        assert!(open_payload(&sk, &[]).is_err());
    }

    #[test]
    fn generation_header_is_authenticated() {
        let sk = HybridKemSecret::generate().unwrap();
        let sealed = seal_payload(&sample_payload(), &sk.public().unwrap()).unwrap();
        let mut t = sealed.clone();
        t[4..12].copy_from_slice(&8u64.to_be_bytes());
        assert!(open_payload(&sk, &t).is_err());
    }

    #[test]
    fn debug_redacts_values() {
        let p = sample_payload();
        let s = format!("{p:?}");
        assert!(!s.contains("A-1234"));
        assert!(!s.contains("1234567890128"));
        assert!(s.contains("Médiathèque"));
    }

    // Payload contents.

    #[test]
    fn field_allowlist_per_type() {
        let (mut repo, v) = fixture();
        let mut lg = login(&v, "Exemple", "camille", Some(SEED));
        lg.sections.push(Section {
            id: "extra".into(),
            label: "Extra".into(),
            fields: vec![Field {
                id: "pin".into(),
                label: "PIN".into(),
                kind: FieldType::Concealed,
                value: concealed("0000"),
                required: false,
                repeatable: false,
                autofill: false,
            }],
        });

        let mut card = item(&v, ItemType::CreditCard, "Carte");
        set(&mut card, "cardholder", text("Camille Durand"));
        set(&mut card, "number", concealed("4970 1012 3459 7890"));
        set(
            &mut card,
            "expiry",
            FieldValue::MonthYear {
                year: 2029,
                month: 4,
            },
        );
        set(&mut card, "cvv", concealed("123"));
        set(&mut card, "pin", concealed("4321"));

        let mut wifi = item(&v, ItemType::Router, "Wi-Fi");
        set(&mut wifi, "ssid", text("Maison"));
        set(
            &mut wifi,
            "wifi_password",
            FieldValue::Password(Zeroizing::new("wifi-secret".into())),
        );
        set(
            &mut wifi,
            "admin_password",
            FieldValue::Password(Zeroizing::new("admin".into())),
        );

        let mut member = item(&v, ItemType::Membership, "Médiathèque");
        set(&mut member, "organization", text("Médiathèque"));
        set(&mut member, "member_number", concealed("A-1234"));
        set(&mut member, "pin", concealed("9999"));
        set(
            &mut member,
            "barcode",
            FieldValue::Barcode {
                value: "1234567890128".into(),
                format: BarcodeFormat::Ean13,
            },
        );

        let mut reward = item(&v, ItemType::RewardProgram, "Fidélité");
        set(&mut reward, "company", text("Boulangerie"));
        set(&mut reward, "member_number", concealed("F-42"));

        let mut code = item(&v, ItemType::AccessCode, "Portail");
        set(&mut code, "code", concealed("1984"));
        set(
            &mut code,
            "place",
            FieldValue::Location(Location {
                label: "Immeuble".into(),
                address: None,
                lat: 48.85,
                lon: 2.35,
                radius_m: 100,
                suggest_nearby: false,
            }),
        );
        set(&mut code, "alarm_code", concealed("2468"));
        set(&mut code, "instructions", text("Porte de gauche"));
        set(&mut code, "contact", text("Gardien"));

        let mut idc = item(&v, ItemType::IdCard, "CNI");
        set(&mut idc, "country", text("France"));
        set(&mut idc, "last_name", text("Durand"));
        set(&mut idc, "first_names", text("Camille"));
        set(&mut idc, "number", concealed("X4RTBPFW4"));
        set(&mut idc, "expiry", FieldValue::Date(date!(2031 - 03 - 09)));

        let mut pass = item(&v, ItemType::Passport, "Passeport");
        set(&mut pass, "issuing_country", text("France"));
        set(&mut pass, "last_name", text("Durand"));
        set(&mut pass, "first_names", text("Camille"));
        set(&mut pass, "number", concealed("20AB12345"));
        set(&mut pass, "expiry", FieldValue::Date(date!(2030 - 12 - 01)));
        set(&mut pass, "mrz", text("P<FRADURAND"));

        let mut dl = item(&v, ItemType::DriverLicense, "Permis");
        set(&mut dl, "full_name", text("Camille Durand"));
        set(&mut dl, "number", concealed("123456789012"));
        set(&mut dl, "expiry", FieldValue::Date(date!(2040 - 01 - 15)));
        set(&mut dl, "region", text("Bretagne"));

        save(
            &mut repo,
            &v,
            vec![lg, card, wifi, member, reward, code, idc, pass, dl],
        );
        let p = build_payload(&mut repo, 3, NOW, &[]).unwrap();
        assert_eq!(p.generation, 3);
        assert_eq!(p.generated_at, NOW.unix_timestamp());
        use CompanionFieldKind::{Barcode, Concealed, Text};

        let e = entry(&p, "Exemple");
        assert_eq!(fields(e), vec![("Identifiant", "camille", Text)]);
        assert_eq!(e.subtitle, "camille");
        assert!(e.totp.is_some());

        assert_eq!(
            fields(entry(&p, "Carte")),
            vec![
                ("Titulaire", "Camille Durand", Text),
                ("Numéro", "•••• 7890", Text),
                ("Expiration", "04/2029", Text),
            ]
        );
        assert_eq!(
            fields(entry(&p, "Wi-Fi")),
            vec![
                ("SSID", "Maison", Text),
                ("Mot de passe Wi-Fi", "wifi-secret", Concealed),
            ]
        );
        assert_eq!(
            fields(entry(&p, "Médiathèque")),
            vec![
                ("Organisation", "Médiathèque", Text),
                ("Numéro de membre", "A-1234", Concealed),
                (
                    "Code-barres",
                    "1234567890128",
                    Barcode(BarcodeFormat::Ean13)
                ),
            ]
        );
        assert_eq!(
            fields(entry(&p, "Fidélité")),
            vec![
                ("Entreprise", "Boulangerie", Text),
                ("Numéro de membre", "F-42", Concealed),
            ]
        );
        assert_eq!(
            fields(entry(&p, "Portail")),
            vec![
                ("Code", "1984", Concealed),
                ("Code de l'alarme", "2468", Concealed),
                ("Instructions", "Porte de gauche", Text),
            ]
        );
        assert_eq!(
            fields(entry(&p, "CNI")),
            vec![
                ("Nom", "Durand", Text),
                ("Prénoms", "Camille", Text),
                ("Numéro", "X4RTBPFW4", Concealed),
                ("Expiration", "09/03/2031", Text),
            ]
        );
        assert_eq!(
            fields(entry(&p, "Passeport")),
            vec![
                ("Nom", "Durand", Text),
                ("Prénoms", "Camille", Text),
                ("Numéro", "20AB12345", Concealed),
                ("Expiration", "01/12/2030", Text),
            ]
        );
        assert_eq!(
            fields(entry(&p, "Permis")),
            vec![
                ("Nom complet", "Camille Durand", Text),
                ("Numéro", "123456789012", Concealed),
                ("Expiration", "15/01/2040", Text),
            ]
        );

        // Nothing excluded leaks anywhere in the payload.
        let all = format!(
            "{:?}",
            p.entries
                .iter()
                .flat_map(|e| e.fields.iter().map(|f| f.value.as_str()))
                .collect::<Vec<_>>()
        );
        for secret in [
            "motdepasse",
            "0000",
            "4970",
            "123\"",
            "4321",
            "admin",
            "9999",
            "Gardien",
            "France",
            "P<FRA",
            "Bretagne",
        ] {
            assert!(!all.contains(secret), "{secret}");
        }
        // Sorted by title.
        let titles: Vec<_> = p.entries.iter().map(|e| e.title.as_str()).collect();
        let mut sorted = titles.clone();
        sorted.sort_by_key(|t| t.to_lowercase());
        assert_eq!(titles, sorted);
    }

    #[test]
    fn card_mask_needs_four_digits() {
        let mask = |s: &str| card_mask(&concealed(s)).map(|m| m.as_str().to_owned());
        assert_eq!(mask("4970101234597890").as_deref(), Some("•••• 7890"));
        assert_eq!(mask(" 4970-1012 3459 7890 ").as_deref(), Some("•••• 7890"));
        assert_eq!(mask("1 234").as_deref(), Some("•••• 1234"));
        assert_eq!(mask("12 3"), None);
        assert_eq!(mask(""), None);
    }

    #[test]
    fn concealed_source_value_stays_concealed() {
        let v = Id::new();
        let mut it = new_item(ItemType::Login, v, "Importé");
        set(&mut it, "username", concealed("camille"));
        let mut card = new_item(ItemType::CreditCard, v, "Carte");
        set(&mut card, "cardholder", concealed("Camille Durand"));
        set(&mut card, "number", concealed("4970101234597890"));
        let kinds = |i: &Item| copy_fields(i).iter().map(|f| f.kind).collect::<Vec<_>>();
        assert_eq!(kinds(&it), vec![CompanionFieldKind::Concealed]);
        // The card mask is computed text, not the secret number.
        assert_eq!(
            kinds(&card),
            vec![CompanionFieldKind::Concealed, CompanionFieldKind::Text]
        );
    }

    #[test]
    fn exclusions() {
        let (mut repo, v) = fixture();
        let hidden = repo.create_vault(vault_meta("Masqué")).unwrap();
        let kept = login(&v, "Gardé", "camille", None);
        let mut trashed = login(&v, "Corbeille", "camille", None);
        trashed.trashed_at = Some(NOW);
        let mut archived = login(&v, "Archivé", "camille", None);
        archived.archived = true;
        let mut reprompt = login(&v, "Redemander", "camille", None);
        reprompt.reprompt = true;
        let mut off = login(&v, "Pas sur la montre", "camille", None);
        off.on_watch = false;
        let mut note = item(&v, ItemType::SecureNote, "Note");
        set(&mut note, "content", text("secret"));
        let mut note_otp = item(&v, ItemType::SecureNote, "Note TOTP");
        set(&mut note_otp, "content", text("secret"));
        note_otp.sections[0].fields.push(Field {
            id: "otp".into(),
            label: "TOTP".into(),
            kind: FieldType::Otp,
            value: FieldValue::Otp(Zeroizing::new(SEED.into())),
            required: false,
            repeatable: false,
            autofill: false,
        });
        save(
            &mut repo,
            &v,
            vec![kept, trashed, archived, reprompt, off, note, note_otp],
        );
        save(
            &mut repo,
            &hidden,
            vec![login(&hidden, "Masqué", "camille", None)],
        );
        let p = build_payload(&mut repo, 1, NOW, &[hidden.id]).unwrap();
        let titles: Vec<_> = p.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, vec!["Gardé", "Note TOTP"]);
        assert!(entry(&p, "Note TOTP").fields.is_empty());
        let all = build_payload(&mut repo, 1, NOW, &[]).unwrap();
        assert_eq!(all.entries.len(), 3);
    }

    #[test]
    fn limits() {
        let (mut repo, v) = fixture();
        let mut items: Vec<Item> = (0..60)
            .rev()
            .map(|i| login(&v, &format!("Compte {i:02}"), "camille", None))
            .collect();
        let long = "a".repeat(2048);
        items.push(login(&v, "000 long avec TOTP", &long, Some(SEED)));
        items.push(login(&v, "000 long sans TOTP", &long, None));
        save(&mut repo, &v, items);
        let p = build_payload(&mut repo, 1, NOW, &[]).unwrap();
        assert_eq!(p.entries.len(), MAX_ENTRIES);
        assert_eq!(p.entries[0].title, "000 long avec TOTP");
        assert!(p.entries[0].fields.is_empty());
        assert!(p.entries[0].subtitle.is_empty());
        assert!(p.entries[0].totp.is_some());
        let expected: Vec<String> = std::iter::once("000 long avec TOTP".to_owned())
            .chain((0..49).map(|i| format!("Compte {i:02}")))
            .collect();
        let titles: Vec<String> = p.entries.iter().map(|e| e.title.clone()).collect();
        assert_eq!(titles, expected);
    }

    #[test]
    fn invalid_totp_is_dropped_not_fatal() {
        let (mut repo, v) = fixture();
        let bad = login(&v, "Mauvais TOTP", "camille", Some("%%%"));
        let mut fav = login(
            &v,
            "Favori cassé",
            "camille",
            Some("otpauth://hotp/x?secret=AAAA"),
        );
        fav.favorite = true;
        fav.on_watch = false;
        let mut good = login(&v, "Favori bon", "camille", Some(SEED));
        good.favorite = true;
        save(&mut repo, &v, vec![bad, fav, good]);
        let p = build_payload(&mut repo, 1, NOW, &[]).unwrap();
        let e = entry(&p, "Mauvais TOTP");
        assert!(e.totp.is_none());
        assert_eq!(e.fields.len(), 1);

        let g = glance_snapshot(&mut repo, NOW.unix_timestamp(), 60, &[]).unwrap();
        let favs: Vec<_> = g.favorites.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(favs, vec!["Favori bon", "Favori cassé"]);
        let codes: Vec<_> = g.codes.iter().map(|c| c.title.as_str()).collect();
        assert_eq!(codes, vec!["Favori bon"]);
    }

    #[test]
    fn otpauth_uri_is_parsed_case_insensitively() {
        let cfg = parse_totp("  OTPAUTH://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8  ").unwrap();
        assert_eq!(cfg.digits, 8);
        assert!(parse_totp("%%%").is_err());
    }

    // Glance.

    #[test]
    fn glance_codes_are_capped_per_item() {
        let (mut repo, v) = fixture();
        let uri = format!("otpauth://totp/x?secret={SEED}&period=1");
        let mut it = login(&v, "Rapide", "camille", Some(&uri));
        it.favorite = true;
        save(&mut repo, &v, vec![it]);
        let now = NOW.unix_timestamp();
        let g = glance_snapshot(&mut repo, now, 86_400, &[]).unwrap();
        assert_eq!(g.valid_until, now + 86_400);
        let c = &g.codes[0];
        assert_eq!(c.period, 1);
        assert_eq!(c.codes.len(), MAX_GLANCE_CODES_PER_ITEM);
        assert!(c.codes[0].0 <= now);
        for (i, (start, _)) in c.codes.iter().enumerate() {
            assert_eq!(*start, c.codes[0].0 + i as i64);
        }
    }

    #[test]
    fn glance_codes_match_totp() {
        let (mut repo, v) = fixture();
        let mut items = Vec::new();
        for i in (0..10).rev() {
            let mut it = login(&v, &format!("Favori {i}"), "camille", Some(SEED));
            it.favorite = true;
            items.push(it);
        }
        let mut gone = login(&v, "000 corbeille", "camille", Some(SEED));
        gone.favorite = true;
        gone.trashed_at = Some(NOW);
        items.push(gone);
        let mut archived = login(&v, "000 archivé", "camille", Some(SEED));
        archived.favorite = true;
        archived.archived = true;
        items.push(archived);
        let mut reprompt = login(&v, "000 redemander", "camille", Some(SEED));
        reprompt.favorite = true;
        reprompt.reprompt = true;
        items.push(reprompt);
        let mut plain = login(&v, "Pas favori", "camille", Some(SEED));
        plain.favorite = false;
        items.push(plain);
        save(&mut repo, &v, items);

        let now = NOW.unix_timestamp();
        let g = glance_snapshot(&mut repo, now, 200_000, &[]).unwrap();
        assert_eq!(g.generated_at, now);
        assert_eq!(g.valid_until, now + MAX_GLANCE_WINDOW_SECS as i64);
        let titles: Vec<String> = g.favorites.iter().map(|f| f.title.clone()).collect();
        let expected: Vec<String> = (0..8).map(|i| format!("Favori {i}")).collect();
        assert_eq!(titles, expected);
        assert_eq!(g.codes.len(), MAX_GLANCE_ITEMS);
        let cfg = parse_totp(SEED).unwrap();
        for c in &g.codes {
            assert_eq!(c.period, 30);
            let (first, _) = c.codes[0];
            let (last, _) = *c.codes.last().unwrap();
            assert!(first <= now && now < first + 30);
            assert!(last <= now + MAX_GLANCE_WINDOW_SECS as i64);
            // 2881 periods overlap 24 h: the cap keeps the earliest 2880.
            assert_eq!(c.codes.len(), MAX_GLANCE_CODES_PER_ITEM);
            assert_eq!(last, first + 30 * (MAX_GLANCE_CODES_PER_ITEM as i64 - 1));
            for (start, code) in &c.codes {
                assert_eq!(start % 30, 0);
                assert_eq!(code, &totp::code_at(&cfg, *start as u64).unwrap());
            }
        }

        let small = glance_snapshot(&mut repo, now, 90, &[v.id]).unwrap();
        assert!(small.favorites.is_empty());
        assert!(small.codes.is_empty());
        assert_eq!(small.valid_until, now + 90);
        let small = glance_snapshot(&mut repo, now, 90, &[]).unwrap();
        assert_eq!(small.codes[0].codes.len(), 4);
        assert!(glance_snapshot(&mut repo, -1, 90, &[]).is_err());
        // Debug shows how many codes, never the codes.
        assert!(format!("{:?}", small.codes[0]).contains("codes: 4 }"));
    }
}
