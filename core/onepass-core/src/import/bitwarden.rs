//! Bitwarden JSON export (spec 4.3).
//!
//! Root `{ encrypted, folders, items }`. Every key is optional and unknown
//! keys are ignored, so a missing or new key never fails the import.
//! Secrets come out of serde_json as `String`s and are moved into
//! `Zeroizing` as soon as they are deserialized; the parser's transient
//! copies inside serde_json are the limit of that guarantee.

use std::collections::HashMap;

use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD};
use serde::{Deserialize, Deserializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::model::{Address, FieldValue, ItemType, PasskeyCredential, SshKeyValue};

use super::build::Draft;
use super::limits::{MAX_INPUT, MAX_RECORDS};
use super::{Import, Warning};

/// A JSON string, number or boolean as text; anything else is absent.
pub(crate) fn lenient<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Any {
        S(String),
        I(i64),
        F(f64),
        B(bool),
        Other(serde::de::IgnoredAny),
    }
    Ok(match Any::deserialize(d)? {
        Any::S(s) => Some(s),
        Any::I(n) => Some(n.to_string()),
        Any::F(n) => Some(n.to_string()),
        Any::B(b) => Some(b.to_string()),
        Any::Other(_) => None,
    })
}

/// Same, moved into `Zeroizing` right away.
pub(crate) fn lenient_secret<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Zeroizing<String>>, D::Error> {
    Ok(lenient(d)?.map(Zeroizing::new))
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Root {
    #[serde(deserialize_with = "lenient")]
    encrypted: Option<String>,
    folders: Vec<Folder>,
    items: Vec<RawItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Folder {
    #[serde(deserialize_with = "lenient")]
    id: Option<String>,
    #[serde(deserialize_with = "lenient")]
    name: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawItem {
    #[serde(rename = "folderId", deserialize_with = "lenient")]
    folder_id: Option<String>,
    #[serde(rename = "type", deserialize_with = "lenient")]
    kind: Option<String>,
    #[serde(deserialize_with = "lenient")]
    name: Option<String>,
    #[serde(deserialize_with = "lenient")]
    notes: Option<String>,
    favorite: Option<bool>,
    fields: Vec<RawField>,
    login: Option<Login>,
    card: Option<Card>,
    identity: Option<Identity>,
    #[serde(rename = "sshKey")]
    ssh_key: Option<Ssh>,
    #[serde(rename = "passwordHistory")]
    password_history: Vec<HistoryEntry>,
    #[serde(rename = "creationDate", deserialize_with = "lenient")]
    creation_date: Option<String>,
    #[serde(rename = "revisionDate", deserialize_with = "lenient")]
    revision_date: Option<String>,
    #[serde(rename = "deletedDate", deserialize_with = "lenient")]
    deleted_date: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawField {
    #[serde(deserialize_with = "lenient")]
    name: Option<String>,
    #[serde(deserialize_with = "lenient_secret")]
    value: Option<Zeroizing<String>>,
    #[serde(rename = "type", deserialize_with = "lenient")]
    kind: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Login {
    uris: Vec<Uri>,
    #[serde(deserialize_with = "lenient")]
    username: Option<String>,
    #[serde(deserialize_with = "lenient_secret")]
    password: Option<Zeroizing<String>>,
    #[serde(deserialize_with = "lenient_secret")]
    totp: Option<Zeroizing<String>>,
    #[serde(rename = "fido2Credentials")]
    fido2_credentials: Vec<Fido2>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Uri {
    #[serde(deserialize_with = "lenient")]
    uri: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Fido2 {
    #[serde(rename = "credentialId", deserialize_with = "lenient")]
    credential_id: Option<String>,
    #[serde(rename = "keyValue", deserialize_with = "lenient_secret")]
    key_value: Option<Zeroizing<String>>,
    #[serde(rename = "rpId", deserialize_with = "lenient")]
    rp_id: Option<String>,
    #[serde(rename = "userHandle", deserialize_with = "lenient")]
    user_handle: Option<String>,
    #[serde(rename = "userName", deserialize_with = "lenient")]
    user_name: Option<String>,
    #[serde(rename = "creationDate", deserialize_with = "lenient")]
    creation_date: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Card {
    #[serde(rename = "cardholderName", deserialize_with = "lenient")]
    cardholder_name: Option<String>,
    #[serde(deserialize_with = "lenient")]
    brand: Option<String>,
    #[serde(deserialize_with = "lenient_secret")]
    number: Option<Zeroizing<String>>,
    #[serde(rename = "expMonth", deserialize_with = "lenient")]
    exp_month: Option<String>,
    #[serde(rename = "expYear", deserialize_with = "lenient")]
    exp_year: Option<String>,
    #[serde(deserialize_with = "lenient_secret")]
    code: Option<Zeroizing<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Identity {
    #[serde(deserialize_with = "lenient")]
    title: Option<String>,
    #[serde(rename = "firstName", deserialize_with = "lenient")]
    first_name: Option<String>,
    #[serde(rename = "middleName", deserialize_with = "lenient")]
    middle_name: Option<String>,
    #[serde(rename = "lastName", deserialize_with = "lenient")]
    last_name: Option<String>,
    #[serde(deserialize_with = "lenient")]
    address1: Option<String>,
    #[serde(deserialize_with = "lenient")]
    address2: Option<String>,
    #[serde(deserialize_with = "lenient")]
    address3: Option<String>,
    #[serde(deserialize_with = "lenient")]
    city: Option<String>,
    #[serde(deserialize_with = "lenient")]
    state: Option<String>,
    #[serde(rename = "postalCode", deserialize_with = "lenient")]
    postal_code: Option<String>,
    #[serde(deserialize_with = "lenient")]
    country: Option<String>,
    #[serde(deserialize_with = "lenient")]
    company: Option<String>,
    #[serde(deserialize_with = "lenient")]
    email: Option<String>,
    #[serde(deserialize_with = "lenient")]
    phone: Option<String>,
    #[serde(deserialize_with = "lenient_secret")]
    ssn: Option<Zeroizing<String>>,
    #[serde(deserialize_with = "lenient")]
    username: Option<String>,
    #[serde(rename = "passportNumber", deserialize_with = "lenient_secret")]
    passport_number: Option<Zeroizing<String>>,
    #[serde(rename = "licenseNumber", deserialize_with = "lenient_secret")]
    license_number: Option<Zeroizing<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Ssh {
    #[serde(rename = "privateKey", deserialize_with = "lenient_secret")]
    private_key: Option<Zeroizing<String>>,
    #[serde(rename = "publicKey", deserialize_with = "lenient")]
    public_key: Option<String>,
    #[serde(rename = "keyFingerprint", deserialize_with = "lenient")]
    key_fingerprint: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct HistoryEntry {
    #[serde(rename = "lastUsedDate", deserialize_with = "lenient")]
    last_used_date: Option<String>,
    #[serde(deserialize_with = "lenient_secret")]
    password: Option<Zeroizing<String>>,
}

/// Bitwarden JSON: logins (with passkeys), secure notes, cards, identities
/// and SSH keys. Deleted items are skipped.
pub(crate) fn parse_bitwarden_json(b: &[u8]) -> Result<Import> {
    if b.len() > MAX_INPUT {
        return Err(Error::InvalidFormat("import file too large"));
    }
    let root: Root =
        serde_json::from_slice(b).map_err(|_| Error::InvalidFormat("bitwarden json"))?;
    if root.encrypted.as_deref() == Some("true") {
        return Err(Error::InvalidFormat(
            "encrypted Bitwarden export: export as unencrypted JSON",
        ));
    }
    if root.items.len() > MAX_RECORDS {
        return Err(Error::InvalidFormat("too many bitwarden items"));
    }
    let folders: HashMap<String, String> = root
        .folders
        .into_iter()
        .filter_map(|f| Some((f.id?, f.name?)))
        .collect();
    let mut out = Import::default();
    for (index, raw) in root.items.iter().enumerate() {
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        if raw
            .deleted_date
            .as_deref()
            .is_some_and(|d| !d.trim().is_empty())
        {
            out.skipped += 1;
            continue;
        }
        let Some(mut d) = item_draft(raw, entry, &mut out) else {
            out.skipped += 1;
            out.warnings.push(Warning {
                entry,
                code: "unsupported_entry",
            });
            continue;
        };
        if let Some(name) = raw.folder_id.as_ref().and_then(|id| folders.get(id)) {
            d.folder(name);
        }
        d.finish(entry, &mut out);
    }
    Ok(out)
}

fn rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s.trim(), &Rfc3339).ok()
}

/// Sets a date through `apply`, or keeps the text as `bad_value` under
/// `label` when it does not parse.
fn date(d: &mut Draft, label: &str, raw: Option<&str>, apply: fn(&mut Draft, OffsetDateTime)) {
    if let Some(raw) = raw.filter(|r| !r.trim().is_empty()) {
        match rfc3339(raw) {
            Some(t) => apply(d, t),
            None => d.bad_value(label, raw),
        }
    }
}

/// Base64url or base64, with or without padding.
/// A leading `b64.` marker (Bitwarden's own encoding tag) is dropped.
fn b64(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    let t = t.strip_prefix("b64.").unwrap_or(t).trim_end_matches('=');
    BASE64URL_NOPAD
        .decode(t.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(t.as_bytes()))
        .ok()
}

/// A GUID string (36 characters, dashes at 8/13/18/23, hex elsewhere) as its
/// 16 bytes. Tested before base64: a dashed GUID is also valid base64url.
fn guid(s: &str) -> Option<Vec<u8>> {
    let t = s.trim();
    if t.len() != 36 || !t.is_char_boundary(36) {
        return None;
    }
    let mut hex = String::with_capacity(32);
    for (i, c) in t.chars().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != '-' {
                return None;
            }
        } else if c.is_ascii_hexdigit() {
            hex.push(c);
        } else {
            return None;
        }
    }
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.as_bytes())
        .ok()
}

fn credential_id(s: &str) -> Option<Vec<u8>> {
    guid(s).or_else(|| b64(s))
}

fn some(s: &Option<String>) -> &str {
    s.as_deref().unwrap_or("")
}

fn secret(s: &Option<Zeroizing<String>>) -> &str {
    s.as_deref().map_or("", String::as_str)
}

/// `None` for an unsupported item type.
fn item_draft(raw: &RawItem, entry: u32, out: &mut Import) -> Option<Draft> {
    let kind = match raw.kind.as_deref()?.trim() {
        "1" => ItemType::Login,
        "2" => ItemType::SecureNote,
        "3" => ItemType::CreditCard,
        "4" => ItemType::Identity,
        "5" => ItemType::SshKey,
        _ => return None,
    };
    let mut d = Draft::new(kind);
    d.title(some(&raw.name));
    if kind == ItemType::SecureNote {
        d.set("content", some(&raw.notes));
    } else {
        d.notes(some(&raw.notes));
    }
    d.favorite(raw.favorite.unwrap_or(false));
    date(
        &mut d,
        "Création",
        raw.creation_date.as_deref(),
        Draft::created,
    );
    date(
        &mut d,
        "Révision",
        raw.revision_date.as_deref(),
        Draft::updated,
    );
    match kind {
        ItemType::Login => {
            if let Some(l) = &raw.login {
                login(&mut d, l, raw, entry, out);
            }
        }
        ItemType::CreditCard => raw.card.iter().for_each(|c| card(&mut d, c)),
        ItemType::Identity => raw.identity.iter().for_each(|i| identity(&mut d, i)),
        ItemType::SshKey => raw.ssh_key.iter().for_each(|k| ssh(&mut d, k)),
        _ => {}
    }
    custom_fields(&mut d, &raw.fields);
    for h in &raw.password_history {
        let pw = secret(&h.password);
        if pw.is_empty() {
            continue;
        }
        let when = h.last_used_date.as_deref().and_then(rfc3339);
        if let (Some(raw_date), None) = (h.last_used_date.as_deref(), when) {
            d.bad_value("Date de l'ancien mot de passe", raw_date);
        }
        d.history(pw, when.unwrap_or(OffsetDateTime::UNIX_EPOCH));
    }
    Some(d)
}

fn login(d: &mut Draft, l: &Login, raw: &RawItem, entry: u32, out: &mut Import) {
    for u in &l.uris {
        d.url(some(&u.uri));
    }
    d.set("username", some(&l.username));
    d.set("password", secret(&l.password));
    d.set("totp", secret(&l.totp));
    for p in &l.fido2_credentials {
        passkey(d, p, raw, entry, out);
    }
}

/// A passkey whose fields decode becomes a `Passkey` value; otherwise its
/// private key is kept as a hidden extra with a `field_moved` warning.
fn passkey(d: &mut Draft, p: &Fido2, raw: &RawItem, entry: u32, out: &mut Import) {
    let credential_id = credential_id(some(&p.credential_id)).filter(|v| !v.is_empty());
    let user_handle = match some(&p.user_handle).trim() {
        "" => Some(Vec::new()),
        h => b64(h),
    };
    let key = b64(secret(&p.key_value)).filter(|v| !v.is_empty());
    let own_date = p.creation_date.as_deref().filter(|r| !r.trim().is_empty());
    if let Some(r) = own_date.filter(|r| rfc3339(r).is_none()) {
        d.bad_value("Date de création du passkey", r);
    }
    let created_at = own_date
        .and_then(rfc3339)
        .or_else(|| raw.creation_date.as_deref().and_then(rfc3339))
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    match (credential_id, user_handle, key) {
        (Some(credential_id), Some(user_handle), Some(key)) => {
            d.set_value(
                "passkeys",
                FieldValue::Passkey(PasskeyCredential {
                    rp_id: some(&p.rp_id).to_owned(),
                    user_name: some(&p.user_name).to_owned(),
                    user_handle,
                    credential_id,
                    private_key: Zeroizing::new(key),
                    created_at,
                }),
            );
        }
        _ => {
            let label = format!("Passkey {}", some(&p.rp_id));
            let value = secret(&p.key_value);
            if value.trim().is_empty() {
                d.extra(&label, some(&p.credential_id), true);
            } else {
                d.extra(&label, value, true);
            }
            out.warnings.push(Warning {
                entry,
                code: "field_moved",
            });
        }
    }
}

fn card(d: &mut Draft, c: &Card) {
    d.set("cardholder", some(&c.cardholder_name));
    d.set("number", secret(&c.number));
    d.set("cvv", secret(&c.code));
    let (m, y) = (some(&c.exp_month).trim(), some(&c.exp_year).trim());
    match (m.is_empty(), y.is_empty()) {
        (false, false) => d.set("expiry", &format!("{m}/{y}")),
        (false, true) => d.extra("Expiry month", m, false),
        (true, false) => d.extra("Expiry year", y, false),
        (true, true) => {}
    }
    d.extra("Brand", some(&c.brand), false);
}

fn identity(d: &mut Draft, i: &Identity) {
    d.set("honorific", some(&i.title));
    d.set("first_name", some(&i.first_name));
    d.set("middle_name", some(&i.middle_name));
    d.set("last_name", some(&i.last_name));
    d.set("company", some(&i.company));
    d.set("email", some(&i.email));
    d.set("mobile_phone", some(&i.phone));
    let clean = |s: &Option<String>| s.as_deref().map_or("", str::trim).to_owned();
    let line2 = [clean(&i.address2), clean(&i.address3)]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    let address = Address {
        line1: clean(&i.address1),
        line2,
        city: clean(&i.city),
        postal_code: clean(&i.postal_code),
        region: clean(&i.state),
        country: clean(&i.country),
    };
    let blank = [
        &address.line1,
        &address.line2,
        &address.city,
        &address.postal_code,
        &address.region,
        &address.country,
    ]
    .iter()
    .all(|s| s.is_empty());
    if !blank {
        d.set_value("address", FieldValue::Address(address));
    }
    d.extra("SSN", secret(&i.ssn), true);
    d.extra("Passport", secret(&i.passport_number), true);
    d.extra("License", secret(&i.license_number), true);
    d.extra("Username", some(&i.username), false);
}

fn ssh(d: &mut Draft, s: &Ssh) {
    let Some(pem) = s.private_key.as_ref().filter(|p| !p.trim().is_empty()) else {
        return;
    };
    d.set_value(
        "private_key",
        FieldValue::SshKey(SshKeyValue {
            private_pem: pem.clone(),
            public_openssh: some(&s.public_key).trim().to_owned(),
            fingerprint_sha256: some(&s.key_fingerprint).trim().to_owned(),
        }),
    );
}

/// Types: 0 text, 1 hidden, 2 boolean, 3 linked (no value, ignored).
fn custom_fields(d: &mut Draft, fields: &[RawField]) {
    for f in fields {
        let kind = f.kind.as_deref().map_or("0", str::trim);
        if kind == "3" {
            continue;
        }
        let label = match some(&f.name).trim() {
            "" => "Champ",
            n => n,
        };
        d.extra(label, secret(&f.value), kind == "1");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use crate::model::{FieldValue, Item, ItemType};

    const BW: &[u8] = include_bytes!("../../tests/fixtures/import/bitwarden.json");

    fn text(item: &Item, id: &str) -> String {
        match item.field(id).map(|f| &f.value) {
            Some(FieldValue::Text(s) | FieldValue::Email(s) | FieldValue::Phone(s)) => s.clone(),
            Some(FieldValue::Password(s) | FieldValue::Concealed(s) | FieldValue::Otp(s)) => {
                s.to_string()
            }
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

    fn by_title<'a>(imp: &'a Import, title: &str) -> &'a super::super::ImportedItem {
        imp.items
            .iter()
            .find(|i| i.item.title == title)
            .expect("item present")
    }

    #[test]
    fn login_with_passkey_and_history() {
        let imp = parse_bitwarden_json(BW).unwrap();
        let li = by_title(&imp, "Example Mail");
        let item = &li.item;
        assert_eq!(item.item_type, ItemType::Login);
        assert!(item.favorite);
        assert_eq!(item.notes, "Main mailbox");
        assert_eq!(item.urls.len(), 2);
        assert_eq!(item.urls[0].url, "https://mail.example.com");
        assert!(item.urls[0].primary);
        assert_eq!(text(item, "username"), "alice@example.com");
        assert_eq!(text(item, "password"), "Bw-Invented-1");
        assert!(text(item, "totp").starts_with("otpauth://totp/"));
        assert_eq!(item.created_at.year(), 2022);
        assert_eq!(item.updated_at.year(), 2024);

        let passkeys: Vec<_> = item
            .sections
            .iter()
            .flat_map(|s| &s.fields)
            .filter(|f| f.id == "passkeys")
            .collect();
        assert_eq!(passkeys.len(), 1, "the undecodable one is moved");
        let FieldValue::Passkey(p) = &passkeys[0].value else {
            panic!("passkey")
        };
        assert_eq!(p.rp_id, "example.com");
        assert_eq!(p.user_name, "alice");
        assert_eq!(p.user_handle, b"fake-user-handle");
        assert_eq!(p.credential_id, b"fake-credential-id");
        assert_eq!(p.private_key.as_slice(), b"fake-pkcs8-key-bytes??");
        assert_eq!(p.created_at.year(), 2024);

        // The broken passkey is kept as a hidden extra and warned about.
        let extras = imported(item);
        assert!(extras.iter().any(|(l, v)| l.contains("broken.example.com")
            && matches!(v, FieldValue::Concealed(s) if s.as_str() == "bw-invented-broken-key")));
        assert!(imp.warnings.iter().any(|w| w.code == "field_moved"));

        assert_eq!(item.password_history.len(), 1);
        assert_eq!(item.password_history[0].value.as_str(), "Bw-Old-Invented-0");
        assert_eq!(item.password_history[0].replaced_at.year(), 2023);
    }

    #[test]
    fn card_identity_ssh() {
        let imp = parse_bitwarden_json(BW).unwrap();

        let card = &by_title(&imp, "Invented Card").item;
        assert_eq!(card.item_type, ItemType::CreditCard);
        assert_eq!(text(card, "cardholder"), "Alice Example");
        assert_eq!(text(card, "number"), "4111111111111111");
        assert_eq!(text(card, "cvv"), "123");
        assert!(matches!(
            card.field("expiry").map(|f| &f.value),
            Some(FieldValue::MonthYear {
                year: 2030,
                month: 9
            })
        ));
        assert!(
            imported(card)
                .iter()
                .any(|(l, v)| l == "Brand" && matches!(v, FieldValue::Text(s) if s == "Visa"))
        );
        assert_eq!(card.notes, "Card notes");

        let id = &by_title(&imp, "Alice Identity").item;
        assert_eq!(id.item_type, ItemType::Identity);
        assert_eq!(text(id, "honorific"), "Ms");
        assert_eq!(text(id, "first_name"), "Alice");
        assert_eq!(text(id, "middle_name"), "Q");
        assert_eq!(text(id, "last_name"), "Example");
        assert_eq!(text(id, "company"), "Example Corp");
        assert_eq!(text(id, "email"), "alice@example.com");
        assert_eq!(text(id, "mobile_phone"), "+1 555 0100");
        let Some(FieldValue::Address(a)) = id.field("address").map(|f| &f.value) else {
            panic!("address")
        };
        assert_eq!(a.line1, "1 Example Street");
        assert_eq!(a.line2, "Suite 2, Floor 3");
        assert_eq!(a.city, "Exampleville");
        assert_eq!(a.region, "EX");
        assert_eq!(a.postal_code, "00000");
        assert_eq!(a.country, "US");
        let extras = imported(id);
        for (label, value) in [
            ("SSN", "000-00-0000"),
            ("Passport", "X0000000"),
            ("License", "D0000000"),
        ] {
            assert!(
                extras.iter().any(|(l, v)| l == label
                    && matches!(v, FieldValue::Concealed(s) if s.as_str() == value)),
                "{label} concealed"
            );
        }
        assert!(
            extras.iter().any(
                |(l, v)| l == "Username" && matches!(v, FieldValue::Text(s) if s == "alice.id")
            )
        );

        let ssh = &by_title(&imp, "Deploy key").item;
        assert_eq!(ssh.item_type, ItemType::SshKey);
        let Some(FieldValue::SshKey(k)) = ssh.field("private_key").map(|f| &f.value) else {
            panic!("ssh")
        };
        assert!(
            k.private_pem
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert_eq!(k.public_openssh, "ssh-ed25519 AAAAfake deploy@example.com");
        assert_eq!(k.fingerprint_sha256, "SHA256:fakefingerprint");
    }

    #[test]
    fn custom_fields_hidden_are_concealed() {
        let imp = parse_bitwarden_json(BW).unwrap();
        let extras = imported(&by_title(&imp, "Example Mail").item);
        assert!(extras.iter().any(|(l, v)| l == "Recovery hint"
            && matches!(v, FieldValue::Text(s) if s == "first invented pet")));
        assert!(extras.iter().any(|(l, v)| l == "Backup token"
            && matches!(v, FieldValue::Concealed(s) if s.as_str() == "bw-invented-token")));
        assert!(
            extras
                .iter()
                .any(|(l, v)| l == "Verified" && matches!(v, FieldValue::Text(s) if s == "true"))
        );
        assert!(!extras.iter().any(|(l, _)| l == "Linked"), "links ignored");

        let hidden = br#"{"items":[{"type":1,"name":"H","login":{"username":"u"},
            "fields":[{"name":"Plain label","value":"s3cret","type":1}]}]}"#;
        let imp = parse_bitwarden_json(hidden).unwrap();
        assert!(
            imported(&imp.items[0].item)
                .iter()
                .any(|(l, v)| l == "Plain label" && matches!(v, FieldValue::Concealed(_)))
        );
    }

    #[test]
    fn encrypted_export_rejected() {
        let r = parse_bitwarden_json(br#"{"encrypted":true,"data":"2.xxx"}"#);
        assert_eq!(
            r.err(),
            Some(Error::InvalidFormat(
                "encrypted Bitwarden export: export as unencrypted JSON"
            ))
        );
        assert!(matches!(
            parse_bitwarden_json(b"not json"),
            Err(Error::InvalidFormat(_))
        ));
    }

    #[test]
    fn deleted_items_skipped() {
        let imp = parse_bitwarden_json(BW).unwrap();
        assert_eq!(imp.skipped, 1);
        assert_eq!(imp.items.len(), 5);
        assert!(imp.items.iter().all(|i| i.item.title != "Trashed login"));
    }

    #[test]
    fn folders_resolved() {
        let imp = parse_bitwarden_json(BW).unwrap();
        assert_eq!(
            by_title(&imp, "Example Mail").folder.as_deref(),
            Some("Personal")
        );
        assert_eq!(
            by_title(&imp, "Wifi instructions").folder.as_deref(),
            Some("Work")
        );
        assert_eq!(by_title(&imp, "Invented Card").folder, None);
        let note = &by_title(&imp, "Wifi instructions").item;
        assert_eq!(note.item_type, ItemType::SecureNote);
        assert_eq!(
            text(note, "content"),
            "Ask the front desk for the invented code"
        );
    }

    #[test]
    fn missing_keys_and_bad_dates_never_fail() {
        let src = br#"{"items":[{"type":1,"name":"Bare"},{"type":99,"name":"Odd"},
            {"type":1,"name":"D","login":{"username":"u"},"creationDate":"yesterday"}]}"#;
        let imp = parse_bitwarden_json(src).unwrap();
        assert_eq!(imp.items.len(), 2);
        assert_eq!(imp.skipped, 1);
        assert!(
            imp.warnings
                .iter()
                .any(|w| w.code == "unsupported_entry" && w.entry == 1)
        );
        assert!(
            imp.warnings
                .iter()
                .any(|w| w.code == "bad_date" && w.entry == 2)
        );
        assert!(
            imported(&imp.items[1].item)
                .iter()
                .any(|(_, v)| matches!(v, FieldValue::Text(s) if s == "yesterday"))
        );
    }

    #[test]
    fn guid_and_prefixed_credential_ids() {
        let key = "ZmFrZS1wa2NzOC1rZXktYnl0ZXM_Pw";
        let one = |cid: &str, date: &str| {
            let src = format!(
                r#"{{"items":[{{"type":1,"name":"P","login":{{"username":"u","fido2Credentials":[
                {{"credentialId":"{cid}","keyValue":"{key}","rpId":"example.com",
                "creationDate":"{date}"}}]}}}}]}}"#
            );
            parse_bitwarden_json(src.as_bytes()).unwrap()
        };
        let cred = |imp: &Import| match imp.items[0].item.field("passkeys").map(|f| &f.value) {
            Some(FieldValue::Passkey(p)) => p.credential_id.clone(),
            _ => panic!("passkey"),
        };
        let imp = one(
            "00112233-4455-6677-8899-aabbccddeeff",
            "2024-01-01T00:00:00Z",
        );
        assert_eq!(
            cred(&imp),
            vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        let imp = one("b64.ZmFrZS1jcmVkZW50aWFsLWlk", "2024-01-01T00:00:00Z");
        assert_eq!(cred(&imp), b"fake-credential-id");
        let imp = one("ZmFrZS1jcmVkZW50aWFsLWlk", "not a date");
        assert!(imp.warnings.iter().any(|w| w.code == "bad_date"));
    }

    #[test]
    fn empty_history_password_skipped() {
        let src = br#"{"items":[{"type":1,"name":"H","login":{"username":"u"},
            "passwordHistory":[{"lastUsedDate":"junk","password":""},{"lastUsedDate":"2023-01-02T03:04:05Z"}]}]}"#;
        let imp = parse_bitwarden_json(src).unwrap();
        assert!(imp.items[0].item.password_history.is_empty());
        assert!(imp.warnings.is_empty());
    }
}
