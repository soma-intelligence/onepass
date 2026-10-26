//! 1Password 1PUX export (spec 4.3, annex A).
//!
//! A zip whose root entry `export.data` is the JSON document
//! `accounts[].vaults[] { attrs.name, items[] }`. Every key is optional and
//! unknown keys are ignored. Each item's `categoryUuid` picks the OnePass
//! type (annex A) and its section fields are matched by field id through
//! [`FIELD_MAP`]; anything else lands in the `imported` section. Entries
//! under `files/` are attachments, skipped with a warning (ruling 19).
//! Secrets come out of serde_json as `String`s and are moved into
//! `Zeroizing` without a copy; the parser's transient buffers inside
//! serde_json are the limit of that guarantee.

// `parse_1pux` is consumed by the import dispatcher (task 9).
#![allow(dead_code)]

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use time::{Date, Month, OffsetDateTime};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::model::{Address, FieldType, FieldValue, ItemType, SshKeyValue, template};

use super::build::Draft;
use super::limits::{MAX_RECORDS, zip_entries};
use super::{Import, Warning};

/// `(categoryUuid, 1Password field id, OnePass template field id)`.
pub(crate) const FIELD_MAP: &[(&str, &str, &str)] = &[
    // Credit Card
    ("002", "cardholder", "cardholder"),
    ("002", "ccnum", "number"),
    ("002", "cvv", "cvv"),
    ("002", "expiry", "expiry"),
    ("002", "type", "card_type"),
    ("002", "bank", "issuer"),
    ("002", "pin", "pin"),
    ("002", "validFrom", "issued_on"),
    // Identity
    ("004", "firstname", "first_name"),
    ("004", "initial", "middle_name"),
    ("004", "lastname", "last_name"),
    ("004", "birthdate", "birth_date"),
    ("004", "company", "company"),
    ("004", "jobtitle", "job_title"),
    ("004", "department", "department"),
    ("004", "address", "address"),
    ("004", "email", "email"),
    ("004", "cellphone", "mobile_phone"),
    ("004", "homephone", "home_phone"),
    ("004", "busphone", "work_phone"),
    ("004", "website", "website"),
    // Password
    ("005", "password", "password"),
    // Software License
    ("100", "product_version", "version"),
    ("100", "reg_code", "license_key"),
    ("100", "reg_name", "licensee_name"),
    ("100", "reg_email", "licensee_email"),
    ("100", "company", "company"),
    ("100", "download_link", "download_url"),
    ("100", "order_number", "order_number"),
    ("100", "order_date", "purchased_on"),
    // Bank Account
    ("101", "bankName", "bank"),
    ("101", "owner", "holder"),
    ("101", "accountType", "account_type"),
    ("101", "routingNo", "routing_number"),
    ("101", "accountNo", "account_number"),
    ("101", "swift", "bic"),
    ("101", "iban", "iban"),
    ("101", "telephonePin", "pin"),
    // Database
    ("102", "database_type", "engine"),
    ("102", "hostname", "host"),
    ("102", "port", "port"),
    ("102", "database", "database"),
    ("102", "username", "username"),
    ("102", "password", "password"),
    ("102", "sid", "service_name"),
    ("102", "alias", "alias"),
    ("102", "options", "connection_options"),
    // Driver License
    ("103", "fullname", "full_name"),
    ("103", "number", "number"),
    ("103", "address", "address"),
    ("103", "birthdate", "birth_date"),
    ("103", "sex", "sex"),
    ("103", "height", "height"),
    ("103", "class", "categories"),
    ("103", "conditions", "restrictions"),
    ("103", "state", "region"),
    ("103", "country", "country"),
    ("103", "expiry_date", "expiry"),
    // Membership
    ("105", "org_name", "organization"),
    ("105", "membership_no", "member_number"),
    ("105", "member_name", "member_name"),
    ("105", "member_since", "joined_on"),
    ("105", "expiry_date", "expiry"),
    ("105", "pin", "pin"),
    ("105", "phone", "phone"),
    ("105", "website", "website"),
    // Passport
    ("106", "type", "passport_type"),
    ("106", "issuing_country", "issuing_country"),
    ("106", "number", "number"),
    ("106", "fullname", "last_name"),
    ("106", "sex", "sex"),
    ("106", "nationality", "nationality"),
    ("106", "issuing_authority", "authority"),
    ("106", "birthdate", "birth_date"),
    ("106", "birthplace", "birth_place"),
    ("106", "issue_date", "issued_on"),
    ("106", "expiry_date", "expiry"),
    // Reward Program
    ("107", "company_name", "company"),
    ("107", "member_name", "member_name"),
    ("107", "membership_no", "member_number"),
    ("107", "pin", "pin"),
    // Social Security Number
    ("108", "name", "name"),
    ("108", "number", "number"),
    // Wireless Router
    ("109", "network_name", "ssid"),
    ("109", "wireless_password", "wifi_password"),
    ("109", "wireless_security", "security"),
    ("109", "name", "model"),
    ("109", "password", "admin_password"),
    ("109", "server", "admin_address"),
    ("109", "airport_id", "mac_address"),
    // Server
    ("110", "url", "host"),
    ("110", "username", "username"),
    ("110", "password", "password"),
    ("110", "admin_console_url", "admin_url"),
    ("110", "admin_console_username", "admin_username"),
    ("110", "admin_console_password", "admin_password"),
    ("110", "name", "hosting_name"),
    ("110", "website", "hosting_console_url"),
    ("110", "support_contact_phone", "hosting_support_phone"),
    // Email Account
    ("111", "pop_username", "incoming_username"),
    ("111", "pop_server", "incoming_server"),
    ("111", "pop_port", "incoming_port"),
    ("111", "pop_password", "password"),
    ("111", "smtp_server", "smtp_server"),
    ("111", "smtp_port", "smtp_port"),
    ("111", "smtp_username", "smtp_username"),
    ("111", "smtp_password", "smtp_password"),
    ("111", "provider", "provider"),
    // API Credential
    ("112", "credential", "key"),
    ("112", "username", "client_id"),
    ("112", "type", "credential_type"),
    ("112", "hostname", "base_url"),
    ("112", "validFrom", "created_on"),
    ("112", "expires", "expires_on"),
    // Medical Record: everything else goes to `imported`.
    ("113", "patient", "patient"),
    // SSH Key
    ("114", "private_key", "private_key"),
    // Crypto Wallet
    ("115", "recoveryPhrase", "recovery_phrase"),
    ("115", "password", "wallet_password"),
    ("115", "walletAddress", "public_addresses"),
];

/// Required name-like fields that 1Password keeps in the item title only:
/// filled from the title when the source has no value for them.
const TITLE_FALLBACK: &[(ItemType, &str)] = &[
    (ItemType::MedicalRecord, "patient"),
    (ItemType::SoftwareLicense, "software"),
    (ItemType::ApiCredential, "service"),
    (ItemType::CryptoWallet, "name"),
];

/// OnePass type of a 1PUX category (annex A). Outdoor License and unknown
/// categories become SecureNotes; a Document without its file falls back
/// to a SecureNote in `Draft::finish`.
fn category_type(c: &str) -> ItemType {
    match c {
        "001" => ItemType::Login,
        "002" => ItemType::CreditCard,
        "004" => ItemType::Identity,
        "005" => ItemType::Password,
        "006" => ItemType::Document,
        "100" => ItemType::SoftwareLicense,
        "101" => ItemType::BankAccount,
        "102" => ItemType::Database,
        "103" => ItemType::DriverLicense,
        "105" => ItemType::Membership,
        "106" => ItemType::Passport,
        "107" => ItemType::RewardProgram,
        "108" => ItemType::SocialSecurityNumber,
        "109" => ItemType::Router,
        "110" => ItemType::Server,
        "111" => ItemType::Email,
        "112" => ItemType::ApiCredential,
        "113" => ItemType::MedicalRecord,
        "114" => ItemType::SshKey,
        "115" => ItemType::CryptoWallet,
        _ => ItemType::SecureNote,
    }
}

/// Router `wireless_security` menu value; an unknown value is kept as is.
fn router_security(raw: &str) -> &str {
    match raw.trim() {
        "wpa2p" => "WPA2",
        "wpa3p" => "WPA3",
        "wep" => "WEP",
        "none" => "ouvert",
        _ => raw,
    }
}

/// A JSON string, number or boolean as text; anything else is absent.
fn lenient<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<String>, D::Error> {
    Ok(scalar(Value::deserialize(d)?).map(|s| s.to_string()))
}

/// Same, moved into `Zeroizing` right away.
fn lenient_secret<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Zeroizing<String>>, D::Error> {
    Ok(scalar(Value::deserialize(d)?))
}

/// Text of a scalar JSON value; a string is moved, not copied.
fn scalar(v: Value) -> Option<Zeroizing<String>> {
    match v {
        Value::String(s) => Some(Zeroizing::new(s)),
        Value::Number(n) => Some(Zeroizing::new(n.to_string())),
        Value::Bool(b) => Some(Zeroizing::new(b.to_string())),
        _ => None,
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Root {
    accounts: Vec<Account>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Account {
    vaults: Vec<Vault>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Vault {
    attrs: VaultAttrs,
    items: Vec<RawItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VaultAttrs {
    #[serde(deserialize_with = "lenient")]
    name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawItem {
    #[serde(rename = "favIndex", deserialize_with = "lenient")]
    fav_index: Option<String>,
    #[serde(rename = "createdAt", deserialize_with = "lenient")]
    created_at: Option<String>,
    #[serde(rename = "updatedAt", deserialize_with = "lenient")]
    updated_at: Option<String>,
    #[serde(deserialize_with = "lenient")]
    state: Option<String>,
    #[serde(rename = "categoryUuid", deserialize_with = "lenient")]
    category_uuid: Option<String>,
    details: Details,
    overview: Overview,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Details {
    #[serde(rename = "loginFields")]
    login_fields: Vec<LoginField>,
    #[serde(rename = "notesPlain", deserialize_with = "lenient")]
    notes_plain: Option<String>,
    #[serde(deserialize_with = "lenient_secret")]
    password: Option<Zeroizing<String>>,
    sections: Vec<RawSection>,
    #[serde(rename = "passwordHistory")]
    password_history: Vec<HistoryEntry>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LoginField {
    #[serde(deserialize_with = "lenient_secret")]
    value: Option<Zeroizing<String>>,
    #[serde(deserialize_with = "lenient")]
    name: Option<String>,
    #[serde(rename = "fieldType", deserialize_with = "lenient")]
    field_type: Option<String>,
    #[serde(deserialize_with = "lenient")]
    designation: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawSection {
    fields: Vec<RawField>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawField {
    #[serde(deserialize_with = "lenient")]
    title: Option<String>,
    #[serde(deserialize_with = "lenient")]
    id: Option<String>,
    /// Object with one key naming the value kind.
    value: Value,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct HistoryEntry {
    #[serde(deserialize_with = "lenient_secret")]
    value: Option<Zeroizing<String>>,
    #[serde(deserialize_with = "lenient")]
    time: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Overview {
    #[serde(deserialize_with = "lenient")]
    title: Option<String>,
    #[serde(deserialize_with = "lenient")]
    url: Option<String>,
    urls: Vec<OverviewUrl>,
    tags: Vec<Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OverviewUrl {
    #[serde(deserialize_with = "lenient")]
    url: Option<String>,
}

/// 1PUX: the 22 categories of annex A. Trashed and deleted items are
/// skipped. The warning entry index runs over every item of every vault,
/// in document order; `attachment_skipped` warnings are numbered by the
/// order of the `files/` entries in the zip.
pub(crate) fn parse_1pux(b: &[u8]) -> Result<Import> {
    let entries = zip_entries(b)?;
    let data = entries
        .iter()
        .find(|(name, _)| name == "export.data")
        .map(|(_, data)| data)
        .ok_or(Error::InvalidFormat("1pux without export.data"))?;
    let root: Root =
        serde_json::from_slice(data).map_err(|_| Error::InvalidFormat("1pux export.data json"))?;
    let total = root
        .accounts
        .iter()
        .flat_map(|a| &a.vaults)
        .map(|v| v.items.len())
        .fold(0usize, usize::saturating_add);
    if total > MAX_RECORDS {
        return Err(Error::InvalidFormat("too many 1pux items"));
    }
    let mut out = Import::default();
    let mut index: u32 = 0;
    for vault in root.accounts.into_iter().flat_map(|a| a.vaults) {
        let folder = vault.attrs.name.unwrap_or_default();
        for raw in vault.items {
            let entry = index;
            index = index.saturating_add(1);
            if matches!(
                raw.state.as_deref().map(str::trim),
                Some("trashed" | "deleted")
            ) {
                out.skipped += 1;
                continue;
            }
            let mut d = item_draft(raw);
            d.folder(&folder);
            d.finish(entry, &mut out);
        }
    }
    let attachments = entries
        .iter()
        .filter(|(name, _)| name.starts_with("files/"))
        .count();
    for i in 0..attachments {
        out.warnings.push(Warning {
            entry: u32::try_from(i).unwrap_or(u32::MAX),
            code: "attachment_skipped",
        });
    }
    Ok(out)
}

fn unix(s: &str) -> Option<OffsetDateTime> {
    let n: i64 = s.trim().parse().ok()?;
    OffsetDateTime::from_unix_timestamp(n).ok()
}

/// Sets a timestamp through `apply`, or keeps the text as `bad_value`.
fn timestamp(d: &mut Draft, label: &str, raw: Option<&str>, apply: fn(&mut Draft, OffsetDateTime)) {
    if let Some(raw) = raw.filter(|r| !r.trim().is_empty()) {
        match unix(raw) {
            Some(t) => apply(d, t),
            None => d.bad_value(label, raw),
        }
    }
}

fn some(s: &Option<String>) -> &str {
    s.as_deref().unwrap_or("")
}

fn secret(s: &Option<Zeroizing<String>>) -> &str {
    s.as_deref().map_or("", String::as_str)
}

/// Kind of template field `id` of type `t`.
fn slot_kind(t: ItemType, id: &str) -> Option<FieldType> {
    template(t)
        .into_iter()
        .flat_map(|s| s.fields)
        .find(|f| f.id == id)
        .map(|f| f.kind)
}

fn item_draft(raw: RawItem) -> Draft {
    let RawItem {
        fav_index,
        created_at,
        updated_at,
        state,
        category_uuid,
        details,
        overview,
    } = raw;
    let category = category_uuid.unwrap_or_default();
    let category = category.trim();
    let kind = category_type(category);
    let mut d = Draft::new(kind);
    let title = some(&overview.title).trim().to_owned();
    d.title(&title);
    let notes = some(&details.notes_plain);
    if kind == ItemType::SecureNote {
        d.set("content", notes);
    } else {
        d.notes(notes);
    }
    let mut seen: Vec<String> = Vec::new();
    for url in std::iter::once(some(&overview.url))
        .chain(overview.urls.iter().map(|u| some(&u.url)))
        .map(str::trim)
    {
        if !url.is_empty() && !seen.iter().any(|s| s == url) {
            seen.push(url.to_owned());
            d.url(url);
        }
    }
    for tag in &overview.tags {
        if let Value::String(t) = tag {
            d.tag(t);
        }
    }
    d.favorite(
        fav_index
            .as_deref()
            .and_then(|f| f.trim().parse::<i64>().ok())
            .is_some_and(|f| f > 0),
    );
    d.archived(state.as_deref().map(str::trim) == Some("archived"));
    timestamp(&mut d, "Création", created_at.as_deref(), Draft::created);
    timestamp(
        &mut d,
        "Modification",
        updated_at.as_deref(),
        Draft::updated,
    );

    let mut filled: Vec<&'static str> = Vec::new();
    for f in &details.login_fields {
        let value = secret(&f.value);
        match f.designation.as_deref().map(str::trim) {
            Some(id @ ("username" | "password")) if !value.trim().is_empty() => {
                d.set(id, value);
            }
            _ => {
                let label = match some(&f.name).trim() {
                    "" => "Champ",
                    n => n,
                };
                let hidden = f.field_type.as_deref().map(str::trim) == Some("P");
                d.extra(label, value, hidden);
            }
        }
    }
    let password = secret(&details.password);
    if !password.trim().is_empty() {
        if slot_kind(kind, "password").is_some() {
            d.set("password", password);
            filled.push("password");
        } else {
            d.extra("password", password, true);
        }
    }
    let mut first_email: Option<String> = None;
    for field in details.sections.into_iter().flat_map(|s| s.fields) {
        let id = some(&field.id).trim().to_owned();
        let label = match (some(&field.title).trim(), id.as_str()) {
            ("", "") => "Champ".to_owned(),
            ("", id) => id.to_owned(),
            (t, _) => t.to_owned(),
        };
        let target = FIELD_MAP
            .iter()
            .find(|(c, src, _)| *c == category && *src == id)
            .map(|(_, _, t)| *t);
        let value = field_value(field.value);
        // Email accounts: the required address is the first user name
        // that looks like one.
        if category == "111"
            && first_email.is_none()
            && matches!(id.as_str(), "pop_username" | "smtp_username")
            && let Val::Text { text, .. } = &value
            && text.contains('@')
        {
            first_email = Some(text.trim().to_owned());
        }
        if let Some(t) = target {
            filled.push(t);
        }
        apply(&mut d, kind, category, target, &label, value);
    }
    if let Some(address) = first_email
        && !filled.contains(&"address")
    {
        d.set("address", &address);
    }
    for (t, id) in TITLE_FALLBACK {
        if *t == kind && !filled.contains(id) {
            d.set(id, &title);
        }
    }
    for h in &details.password_history {
        let when = h.time.as_deref().and_then(unix);
        if let (Some(raw_time), None) = (h.time.as_deref(), when) {
            d.bad_value("Date de l'ancien mot de passe", raw_time);
        }
        d.history(secret(&h.value), when.unwrap_or(OffsetDateTime::UNIX_EPOCH));
    }
    d
}

/// A decoded 1PUX field value.
enum Val {
    Text {
        text: Zeroizing<String>,
        hidden: bool,
    },
    Totp(Zeroizing<String>),
    Date(Date),
    MonthYear {
        year: u16,
        month: u8,
    },
    /// A date or month that does not decode, as source text.
    BadDate(String),
    Address(Address),
    Ssh(SshKeyValue),
    /// Unknown kind: compact JSON, hidden when it is an object.
    Unknown {
        json: Zeroizing<String>,
        hidden: bool,
    },
    None,
}

/// Decodes `{ "<kind>": <inner> }`.
fn field_value(v: Value) -> Val {
    let Value::Object(map) = v else {
        return match scalar(v) {
            Some(text) => Val::Text {
                text,
                hidden: false,
            },
            None => Val::None,
        };
    };
    let Some((kind, inner)) = map.into_iter().next() else {
        return Val::None;
    };
    let text = |inner: Value, hidden: bool| match inner {
        Value::Null => Val::None,
        Value::Object(_) | Value::Array(_) => unknown(&inner),
        other => match scalar(other) {
            Some(text) => Val::Text { text, hidden },
            None => Val::None,
        },
    };
    match kind.as_str() {
        "string" | "url" | "phone" | "menu" | "creditCardType" | "gender" => text(inner, false),
        "concealed" | "creditCardNumber" => text(inner, true),
        "totp" => match scalar(inner) {
            Some(t) => Val::Totp(t),
            None => Val::None,
        },
        "email" => match inner {
            Value::Object(mut m) => text(m.remove("email_address").unwrap_or(Value::Null), false),
            other => text(other, false),
        },
        "date" => match scalar(inner) {
            None => Val::None,
            Some(raw) => match unix(&raw) {
                Some(t) => Val::Date(t.date()),
                None => Val::BadDate(raw.to_string()),
            },
        },
        "monthYear" => match scalar(inner) {
            None => Val::None,
            Some(raw) => match month_year(&raw) {
                Some((year, month)) => Val::MonthYear { year, month },
                None => Val::BadDate(raw.to_string()),
            },
        },
        "address" => match inner {
            Value::Object(m) => address(m),
            other => text(other, false),
        },
        "sshKey" => match inner {
            Value::Object(m) => ssh_key(m),
            other => text(other, true),
        },
        "reference" => Val::None,
        _ => match inner {
            Value::Null => Val::None,
            Value::Object(_) | Value::Array(_) => unknown(&inner),
            other => text(other, false),
        },
    }
}

/// Compact JSON of an unknown value, hidden when it is an object.
fn unknown(v: &Value) -> Val {
    match serde_json::to_string(v) {
        Ok(json) => Val::Unknown {
            json: Zeroizing::new(json),
            hidden: v.is_object(),
        },
        Err(_) => Val::None,
    }
}

/// `YYYYMM` as an integer.
fn month_year(s: &str) -> Option<(u16, u8)> {
    let n: u32 = s.trim().parse().ok()?;
    let year = u16::try_from(n / 100).ok()?;
    let month = u8::try_from(n % 100).ok()?;
    ((1..=12).contains(&month) && (1..=9999).contains(&year)).then_some((year, month))
}

fn take(m: &mut Map<String, Value>, key: &str) -> String {
    m.remove(key)
        .and_then(scalar)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn address(mut m: Map<String, Value>) -> Val {
    let a = Address {
        line1: take(&mut m, "street"),
        line2: String::new(),
        city: take(&mut m, "city"),
        postal_code: take(&mut m, "zip"),
        region: take(&mut m, "state"),
        country: take(&mut m, "country"),
    };
    let blank = [&a.line1, &a.city, &a.postal_code, &a.region, &a.country]
        .iter()
        .all(|s| s.is_empty());
    if blank { Val::None } else { Val::Address(a) }
}

fn ssh_key(mut m: Map<String, Value>) -> Val {
    let Some(pem) = m.remove("privateKey").and_then(scalar) else {
        return Val::None;
    };
    if pem.trim().is_empty() {
        return Val::None;
    }
    let mut meta = match m.remove("metadata") {
        Some(Value::Object(meta)) => meta,
        _ => Map::new(),
    };
    Val::Ssh(SshKeyValue {
        private_pem: pem,
        public_openssh: take(&mut meta, "publicKey"),
        fingerprint_sha256: take(&mut meta, "fingerprint"),
    })
}

/// `YYYY-MM-DD`, read unambiguously by `Draft::set`.
fn ymd(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// Puts one decoded value on the draft: into template field `target` when
/// there is one, else into `imported` under `label`.
fn apply(d: &mut Draft, kind: ItemType, category: &str, target: Option<&str>, label: &str, v: Val) {
    let target_kind = target.and_then(|t| slot_kind(kind, t));
    match (v, target) {
        (Val::None, _) => {}
        (Val::Text { text, .. }, Some(t)) if category == "109" && t == "security" => {
            d.set(t, router_security(&text));
        }
        (Val::Text { text, .. }, Some(t)) => d.set(t, &text),
        (Val::Text { text, hidden }, None) => d.extra(label, &text, hidden),
        (Val::Totp(t), _) => {
            if slot_kind(kind, "totp").is_some() {
                d.set("totp", &t);
            } else {
                d.extra(label, &t, true);
            }
        }
        (Val::Date(date), Some(t)) if target_kind == Some(FieldType::Date) => {
            d.set_value(t, FieldValue::Date(date));
        }
        (Val::Date(date), Some(t)) => d.set(t, &ymd(date)),
        (Val::Date(date), None) => d.extra(label, &ymd(date), false),
        (Val::MonthYear { year, month }, Some(t)) => match target_kind {
            Some(FieldType::Date) => {
                let first = Month::try_from(month)
                    .ok()
                    .and_then(|m| Date::from_calendar_date(i32::from(year), m, 1).ok());
                match first {
                    Some(date) => d.set_value(t, FieldValue::Date(date)),
                    None => d.bad_value(label, &format!("{year:04}{month:02}")),
                }
            }
            Some(FieldType::MonthYear) => d.set_value(t, FieldValue::MonthYear { year, month }),
            _ => d.set(t, &format!("{year:04}-{month:02}")),
        },
        (Val::MonthYear { year, month }, None) => {
            d.extra(label, &format!("{year:04}-{month:02}"), false);
        }
        (Val::BadDate(raw), _) => d.bad_value(label, &raw),
        (Val::Address(a), Some(t)) if target_kind == Some(FieldType::Address) => {
            d.set_value(t, FieldValue::Address(a));
        }
        (Val::Address(a), _) => {
            let text = [&a.line1, &a.postal_code, &a.city, &a.region, &a.country]
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            d.extra(label, &text, false);
        }
        (Val::Ssh(k), Some(t)) if target_kind == Some(FieldType::SshKey) => {
            d.set_value(t, FieldValue::SshKey(k));
        }
        (Val::Ssh(k), _) => d.extra(label, &k.private_pem, true),
        (Val::Unknown { json, hidden }, _) => d.extra(label, &json, hidden),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::CompressionMethod;
    use zip::write::{SimpleFileOptions, ZipWriter};

    use super::*;
    use crate::model::{FieldType, FieldValue, Item, ItemType, template, validate};

    const DATA: &[u8] = include_bytes!("../../tests/fixtures/import/1pux-export.data.json");

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn fixture() -> Import {
        let bytes = zip_of(&[
            ("export.attributes", b"{\"version\":3}"),
            ("export.data", DATA),
            ("files/doc1__contract.pdf", b"%PDF-invented"),
            ("files/doc2__photo.jpg", b"invented"),
        ]);
        parse_1pux(&bytes).unwrap()
    }

    fn by_title<'a>(imp: &'a Import, title: &str) -> &'a super::super::ImportedItem {
        imp.items
            .iter()
            .find(|i| i.item.title == title)
            .unwrap_or_else(|| panic!("{title} present"))
    }

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(
                FieldValue::Text(s)
                | FieldValue::Email(s)
                | FieldValue::Phone(s)
                | FieldValue::Url(s)
                | FieldValue::Menu(s),
            ) => s.clone(),
            Some(
                FieldValue::Password(s)
                | FieldValue::Concealed(s)
                | FieldValue::Otp(s)
                | FieldValue::Mnemonic(s),
            ) => s.to_string(),
            Some(FieldValue::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    }

    fn imported(item: &Item) -> Vec<(String, FieldValue)> {
        item.sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter().map(|f| (f.label.clone(), f.value.clone())))
            .collect()
    }

    fn imported_text(item: &Item, label: &str) -> Option<(String, bool)> {
        imported(item)
            .into_iter()
            .find(|(l, _)| l == label)
            .map(|(_, v)| match v {
                FieldValue::Text(s) => (s, false),
                FieldValue::Concealed(s) => (s.to_string(), true),
                other => panic!("unexpected {other:?}"),
            })
    }

    #[test]
    fn login_with_totp_and_tags() {
        let imp = fixture();
        let li = by_title(&imp, "Example Mail");
        let item = &li.item;
        assert_eq!(item.item_type, ItemType::Login);
        assert!(item.favorite);
        assert!(!item.archived);
        assert_eq!(item.notes, "Main mailbox");
        assert_eq!(item.tags, vec!["mail", "work"]);
        let urls: Vec<_> = item.urls.iter().map(|u| u.url.as_str()).collect();
        assert_eq!(
            urls,
            ["https://mail.example.com", "https://webmail.example.com"]
        );
        assert!(item.urls[0].primary);
        assert_eq!(text(item, "username"), "alice@example.com");
        assert_eq!(text(item, "password"), "Px-Invented-1");
        assert!(text(item, "totp").starts_with("otpauth://totp/Example:alice?"));
        assert_eq!(
            imported_text(item, "remember token"),
            Some(("Remember-Invented".to_owned(), true))
        );
        assert_eq!(item.created_at.unix_timestamp(), 1_650_000_000);
        assert_eq!(item.updated_at.unix_timestamp(), 1_710_000_000);
        assert_eq!(item.password_history.len(), 1);
        assert_eq!(item.password_history[0].value.as_str(), "Old-Invented-0");
        assert_eq!(
            item.password_history[0].replaced_at.unix_timestamp(),
            1_600_000_000
        );
        // The reference field carries no data and is dropped.
        assert!(imported_text(item, "Linked").is_none());
        validate(item).unwrap();
    }

    #[test]
    fn card_and_router_mapping() {
        let imp = fixture();
        let card = &by_title(&imp, "Example Visa").item;
        assert_eq!(card.item_type, ItemType::CreditCard);
        assert_eq!(text(card, "cardholder"), "Alice Example");
        assert_eq!(text(card, "number"), "4111111111111111");
        assert_eq!(text(card, "cvv"), "123");
        assert_eq!(text(card, "pin"), "0000");
        assert_eq!(text(card, "card_type"), "visa");
        assert_eq!(text(card, "issuer"), "Example Bank");
        assert_eq!(
            card.field("expiry").map(|f| &f.value),
            Some(&FieldValue::MonthYear {
                year: 2030,
                month: 12
            })
        );
        assert_eq!(
            card.field("issued_on").map(|f| &f.value),
            Some(&FieldValue::Date(time::macros::date!(2020 - 01 - 01)))
        );
        validate(card).unwrap();

        let router = &by_title(&imp, "Home Wi-Fi").item;
        assert_eq!(router.item_type, ItemType::Router);
        assert_eq!(text(router, "ssid"), "ExampleNet");
        assert_eq!(text(router, "wifi_password"), "Wifi-Invented-1");
        assert_eq!(text(router, "security"), "WPA2");
        assert_eq!(text(router, "model"), "Example Base");
        assert_eq!(text(router, "admin_password"), "Admin-Invented-1");
        assert_eq!(text(router, "admin_address"), "192.168.1.1");
        assert_eq!(text(router, "mac_address"), "AA:BB:CC:DD:EE:FF");
        assert_eq!(
            imported_text(router, "attached storage password"),
            Some(("Disk-Invented-1".to_owned(), true))
        );
        validate(router).unwrap();
    }

    #[test]
    fn router_security_values() {
        for (raw, want) in [
            ("wpa2p", "WPA2"),
            ("wpa3p", "WPA3"),
            ("wep", "WEP"),
            ("none", "ouvert"),
        ] {
            assert_eq!(router_security(raw), want);
        }
        assert_eq!(router_security("wpa2e"), "wpa2e");
    }

    #[test]
    fn archived_kept_trashed_skipped() {
        let imp = fixture();
        let archived = &by_title(&imp, "Old forum").item;
        assert!(archived.archived);
        assert_eq!(text(archived, "username"), "bob");
        assert!(imp.items.iter().all(|i| i.item.title != "Trashed login"));
        assert_eq!(imp.skipped, 1);
        assert_eq!(imp.items.len(), 25);
    }

    #[test]
    fn vault_name_is_folder() {
        let imp = fixture();
        assert_eq!(
            by_title(&imp, "Example Mail").folder.as_deref(),
            Some("Personal")
        );
        assert_eq!(
            by_title(&imp, "Work Portal").folder.as_deref(),
            Some("Work")
        );
    }

    #[test]
    fn attachment_entries_warn() {
        let imp = fixture();
        let n = imp
            .warnings
            .iter()
            .filter(|w| w.code == "attachment_skipped")
            .count();
        assert_eq!(n, 2);
    }

    #[test]
    fn unknown_value_kind_goes_to_extra() {
        let imp = fixture();
        let item = &by_title(&imp, "Example Mail").item;
        let (json, hidden) = imported_text(item, "Mystery").unwrap();
        assert_eq!(json, r#"{"a":1,"b":"x"}"#);
        assert!(hidden, "an object value is hidden");
        assert_eq!(
            imported_text(item, "Odd number"),
            Some(("42".to_owned(), false))
        );
    }

    #[test]
    fn every_category_maps() {
        let imp = fixture();
        let cases = [
            ("Example Mail", ItemType::Login),
            ("Example Visa", ItemType::CreditCard),
            ("Plain note", ItemType::SecureNote),
            ("Alice Identity", ItemType::Identity),
            ("Garage code", ItemType::Password),
            ("Scanned contract", ItemType::SecureNote),
            ("Example Editor", ItemType::SoftwareLicense),
            ("Example Checking", ItemType::BankAccount),
            ("Example DB", ItemType::Database),
            ("Alice DL", ItemType::DriverLicense),
            ("Fishing permit", ItemType::SecureNote),
            ("Example Gym", ItemType::Membership),
            ("Alice Passport", ItemType::Passport),
            ("Example Miles", ItemType::RewardProgram),
            ("Alice SSN", ItemType::SocialSecurityNumber),
            ("Home Wi-Fi", ItemType::Router),
            ("Example Host", ItemType::Server),
            ("Alice Mail Account", ItemType::Email),
            ("Example API", ItemType::ApiCredential),
            ("Checkup 2024", ItemType::MedicalRecord),
            ("Deploy key", ItemType::SshKey),
            ("Cold wallet", ItemType::CryptoWallet),
            ("Mystery item", ItemType::SecureNote),
        ];
        for (title, kind) in cases {
            let item = &by_title(&imp, title).item;
            assert_eq!(item.item_type, kind, "{title}");
            validate(item).unwrap_or_else(|e| panic!("{title}: {e:?}"));
        }
        for li in &imp.items {
            validate(&li.item).unwrap();
            assert_eq!(li.item.vault_id.0, [0; 16]);
        }

        let note = &by_title(&imp, "Plain note").item;
        assert_eq!(text(note, "content"), "Note body");
        let doc = &by_title(&imp, "Scanned contract").item;
        assert_eq!(text(doc, "content"), "contract scan");

        let id = &by_title(&imp, "Alice Identity").item;
        assert_eq!(text(id, "first_name"), "Alice");
        assert_eq!(text(id, "middle_name"), "B");
        assert_eq!(text(id, "last_name"), "Example");
        assert_eq!(text(id, "email"), "alice@example.com");
        assert_eq!(text(id, "mobile_phone"), "+33 6 00 00 00 00");
        assert_eq!(text(id, "job_title"), "Engineer");
        assert_eq!(text(id, "website"), "https://alice.example.com");
        assert_eq!(
            id.field("birth_date").map(|f| &f.value),
            Some(&FieldValue::Date(time::macros::date!(1990 - 01 - 01)))
        );
        let Some(FieldValue::Address(a)) = id.field("address").map(|f| &f.value) else {
            panic!("address")
        };
        assert_eq!(a.line1, "1 Example Street");
        assert_eq!(a.city, "Example City");
        assert_eq!(a.postal_code, "75000");
        assert_eq!(a.region, "IDF");
        assert_eq!(a.country, "fr");

        assert_eq!(
            text(&by_title(&imp, "Garage code").item, "password"),
            "Pw-Invented-5"
        );

        let sw = &by_title(&imp, "Example Editor").item;
        assert_eq!(text(sw, "software"), "Example Editor");
        assert_eq!(text(sw, "license_key"), "AAAA-BBBB-INVENTED");
        assert_eq!(text(sw, "licensee_email"), "alice@example.com");
        assert_eq!(text(sw, "download_url"), "https://example.com/download");
        assert_eq!(
            sw.field("purchased_on").map(|f| &f.value),
            Some(&FieldValue::Date(time::macros::date!(2022 - 01 - 01)))
        );

        let bank = &by_title(&imp, "Example Checking").item;
        assert_eq!(text(bank, "bank"), "Example Bank");
        assert_eq!(text(bank, "holder"), "Alice Example");
        assert_eq!(text(bank, "iban"), "FR76 3000 6000 0112 3456 7890 189");
        assert_eq!(text(bank, "bic"), "EXAMFRPP");
        assert_eq!(text(bank, "pin"), "4321");

        let db = &by_title(&imp, "Example DB").item;
        assert_eq!(text(db, "engine"), "mysql");
        assert_eq!(text(db, "host"), "db.example.com");
        assert_eq!(text(db, "port"), "3306");
        assert_eq!(text(db, "service_name"), "ORCL");
        assert_eq!(text(db, "connection_options"), "sslmode=require");

        let dl = &by_title(&imp, "Alice DL").item;
        assert_eq!(text(dl, "full_name"), "Alice Example");
        assert_eq!(text(dl, "number"), "DL-INVENTED-1");
        assert_eq!(text(dl, "categories"), "B");
        assert_eq!(text(dl, "restrictions"), "glasses");
        assert_eq!(text(dl, "region"), "IDF");
        assert_eq!(
            dl.field("expiry").map(|f| &f.value),
            Some(&FieldValue::Date(time::macros::date!(2030 - 05 - 01)))
        );
        // A plain-text address does not convert to an Address: kept in
        // `imported` under the template label.
        assert_eq!(
            imported_text(dl, "Adresse"),
            Some(("1 Example Street".to_owned(), false))
        );

        let outdoor = &by_title(&imp, "Fishing permit").item;
        assert_eq!(
            imported_text(outdoor, "approved wildlife").unwrap().0,
            "trout"
        );

        let gym = &by_title(&imp, "Example Gym").item;
        assert_eq!(text(gym, "organization"), "Example Gym");
        assert_eq!(text(gym, "member_number"), "M-0001");
        assert_eq!(
            gym.field("joined_on").map(|f| &f.value),
            Some(&FieldValue::Date(time::macros::date!(2019 - 01 - 01)))
        );

        let pp = &by_title(&imp, "Alice Passport").item;
        assert_eq!(text(pp, "passport_type"), "P");
        assert_eq!(text(pp, "last_name"), "Example");
        assert_eq!(text(pp, "authority"), "Prefecture");
        assert_eq!(text(pp, "sex"), "female");

        let miles = &by_title(&imp, "Example Miles").item;
        assert_eq!(text(miles, "company"), "Example Air");
        assert_eq!(text(miles, "member_number"), "R-0001");

        let srv = &by_title(&imp, "Example Host").item;
        assert_eq!(text(srv, "host"), "srv.example.com");
        assert_eq!(text(srv, "admin_url"), "https://admin.example.com");
        assert_eq!(text(srv, "admin_password"), "Console-Invented-1");
        assert_eq!(text(srv, "hosting_name"), "Example Hosting");
        assert_eq!(text(srv, "hosting_support_phone"), "+1 555 0100");

        let mail = &by_title(&imp, "Alice Mail Account").item;
        assert_eq!(text(mail, "address"), "alice@example.com");
        assert_eq!(text(mail, "incoming_server"), "imap.example.com");
        assert_eq!(text(mail, "incoming_port"), "993");
        assert_eq!(text(mail, "password"), "Mail-Invented-1");
        assert_eq!(text(mail, "smtp_password"), "Smtp-Invented-1");
        assert_eq!(text(mail, "provider"), "Example Mail Co");

        let api = &by_title(&imp, "Example API").item;
        assert_eq!(text(api, "service"), "Example API");
        assert_eq!(text(api, "key"), "api-invented-token");
        assert_eq!(text(api, "client_id"), "client-1");
        assert_eq!(text(api, "base_url"), "https://api.example.com");

        let med = &by_title(&imp, "Checkup 2024").item;
        assert_eq!(text(med, "patient"), "Checkup 2024");
        assert_eq!(imported_text(med, "location").unwrap().0, "Example Clinic");

        let ssh = &by_title(&imp, "Deploy key").item;
        let Some(FieldValue::SshKey(k)) = ssh.field("private_key").map(|f| &f.value) else {
            panic!("ssh key")
        };
        assert!(
            k.private_pem
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert_eq!(
            k.public_openssh,
            "ssh-ed25519 AAAAINVENTED alice@example.com"
        );
        assert_eq!(k.fingerprint_sha256, "SHA256:INVENTED");

        let wallet = &by_title(&imp, "Cold wallet").item;
        assert_eq!(text(wallet, "name"), "Cold wallet");
        assert_eq!(text(wallet, "wallet_password"), "Wallet-Invented-1");
        assert_eq!(text(wallet, "public_addresses"), "bc1qinvented");

        let mystery = &by_title(&imp, "Mystery item").item;
        assert_eq!(text(mystery, "content"), "future category");
        assert_eq!(imported_text(mystery, "serial").unwrap().0, "SN-1");
    }

    #[test]
    fn missing_export_data_rejected() {
        let bytes = zip_of(&[("dir/export.data", DATA), ("export.attributes", b"{}")]);
        assert_eq!(
            parse_1pux(&bytes).err(),
            Some(Error::InvalidFormat("1pux without export.data"))
        );
        assert!(matches!(
            parse_1pux(b"not a zip"),
            Err(Error::InvalidFormat(_))
        ));
        let bad = zip_of(&[("export.data", b"{not json")]);
        assert!(matches!(parse_1pux(&bad), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn field_map_ids_exist_in_templates() {
        for (cat, src, id) in FIELD_MAP {
            let kind = category_type(cat);
            assert!(
                template(kind)
                    .into_iter()
                    .flat_map(|s| s.fields)
                    .any(|f| f.id == *id),
                "{cat}: {src} -> {id}"
            );
        }
        // Every category with a typed target has entries.
        for cat in [
            "002", "004", "005", "100", "101", "102", "103", "105", "106", "107", "108", "109",
            "110", "111", "112", "113", "114", "115",
        ] {
            assert!(FIELD_MAP.iter().any(|(c, _, _)| *c == cat), "{cat}");
        }
        let _ = FieldType::Text;
    }

    #[test]
    fn warnings_carry_running_entry_index() {
        let imp = fixture();
        // Document (index 5) and Outdoor License (index 10) fall back to a
        // SecureNote; the Work vault's login is entry 25.
        let notes: Vec<u32> = imp
            .warnings
            .iter()
            .filter(|w| w.code == "to_secure_note")
            .map(|w| w.entry)
            .collect();
        assert!(notes.contains(&5), "{notes:?}");
        assert!(notes.contains(&10), "{notes:?}");
        assert_eq!(imp.items.last().unwrap().item.title, "Work Portal");
    }
}
