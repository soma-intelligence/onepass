//! Credential Exchange JSON (spec 4.3).
//!
//! Root `{ accounts[].items[] }`. Every key is optional and unknown keys
//! are ignored. A field is `{ fieldType, value }`, a string, a number or a
//! boolean: all four read the same. Containers that are `null` or of the
//! wrong type are empty. Secrets pass through `serde_json::Value` before
//! they are moved into `Zeroizing`: the parser's transient copies are the
//! limit of that guarantee.

use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::model::{FieldValue, ItemType, PasskeyCredential};

use super::build::{Draft, otpauth_from_parts};
use super::json::{Lenient, Slots};
use super::limits::{MAX_INPUT, MAX_RECORDS};
use super::{Import, Warning};

/// Text of a scalar JSON value; an object gives its `value` member.
fn scalar(v: Value) -> Option<Zeroizing<String>> {
    match v {
        Value::String(s) => Some(Zeroizing::new(s)),
        Value::Number(n) => Some(Zeroizing::new(n.to_string())),
        Value::Bool(b) => Some(Zeroizing::new(b.to_string())),
        Value::Object(mut m) => m.remove("value").and_then(scalar),
        _ => None,
    }
}

/// A CXF field: `{ fieldType, value }`, a string, a number or a boolean.
#[derive(Default)]
struct F(Option<Zeroizing<String>>);

impl<'de> Deserialize<'de> for F {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<F, D::Error> {
        Ok(F(scalar(Value::deserialize(d)?)))
    }
}

impl F {
    fn get(&self) -> &str {
        self.0.as_ref().map_or("", |s| s.as_str())
    }
}

/// A JSON array of `T`; `null` or any other type is empty, and an element
/// that does not decode is left out.
fn lenient_vec<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    d: D,
) -> std::result::Result<Vec<T>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Array(a) => a
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect(),
        _ => Vec::new(),
    })
}

/// A JSON object as `T`; anything else, or an object that does not
/// decode, is `T::default()`.
fn lenient_obj<'de, D: Deserializer<'de>, T: DeserializeOwned + Default>(
    d: D,
) -> std::result::Result<T, D::Error> {
    Ok(match Value::deserialize(d)? {
        v @ Value::Object(_) => serde_json::from_value(v).unwrap_or_default(),
        _ => T::default(),
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Root {
    accounts: Lenient<Account>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Account {
    items: Slots<RawItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawItem {
    title: F,
    favorite: F,
    #[serde(rename = "creationAt")]
    creation_at: F,
    #[serde(rename = "modifiedAt")]
    modified_at: F,
    #[serde(deserialize_with = "lenient_obj")]
    scope: Scope,
    #[serde(deserialize_with = "lenient_vec")]
    tags: Vec<F>,
    credentials: Lenient<Cred>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Scope {
    #[serde(deserialize_with = "lenient_vec")]
    urls: Vec<F>,
}

/// One credential. All credential types share this flat shape: each type
/// reads only its own members.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Cred {
    #[serde(rename = "type")]
    kind: F,
    username: F,
    password: F,
    // totp
    secret: F,
    period: F,
    digits: F,
    algorithm: F,
    issuer: F,
    // passkey
    #[serde(rename = "credentialId")]
    credential_id: F,
    #[serde(rename = "rpId")]
    rp_id: F,
    #[serde(rename = "userHandle")]
    user_handle: F,
    key: F,
    // wifi
    ssid: F,
    #[serde(rename = "networkSecurityType")]
    security: F,
    passphrase: F,
    hidden: F,
    // note
    content: F,
    // credit-card
    number: F,
    #[serde(rename = "fullName")]
    full_name: F,
    #[serde(rename = "cardType")]
    card_type: F,
    #[serde(rename = "verificationNumber")]
    verification_number: F,
    pin: F,
    #[serde(rename = "expiryDate")]
    expiry_date: F,
}

/// Base64url or base64, with or without padding.
fn b64(s: &str) -> Option<Vec<u8>> {
    let t = s.trim().trim_end_matches('=');
    BASE64URL_NOPAD
        .decode(t.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(t.as_bytes()))
        .ok()
}

/// Unix seconds (digits) or RFC 3339.
fn timestamp(s: &str) -> Option<OffsetDateTime> {
    let t = s.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        return OffsetDateTime::from_unix_timestamp(t.parse().ok()?).ok();
    }
    OffsetDateTime::parse(t, &Rfc3339).ok()
}

/// Router menu value for a CXF `networkSecurityType`.
fn security(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().as_str() {
        "unsecured" => Some("ouvert"),
        "wep" => Some("WEP"),
        "wpa-personal" => Some("WPA"),
        "wpa2-personal" => Some("WPA2"),
        "wpa3-personal" => Some("WPA3"),
        _ => None,
    }
}

fn yes_no(s: &str) -> &'static str {
    if s.trim().eq_ignore_ascii_case("true") {
        "oui"
    } else {
        "non"
    }
}

fn date(d: &mut Draft, label: &str, f: &F, apply: fn(&mut Draft, OffsetDateTime)) {
    let raw = f.get();
    if raw.trim().is_empty() {
        return;
    }
    match timestamp(raw) {
        Some(t) => apply(d, t),
        None => d.bad_value(label, raw),
    }
}

/// A TOTP credential as an `otpauth://` URI in the Login `totp` field.
fn totp(d: &mut Draft, c: &Cred) {
    let mut secret = Zeroizing::new(String::with_capacity(c.secret.get().len()));
    secret.extend(
        c.secret
            .get()
            .chars()
            .filter(|ch| !ch.is_whitespace() && *ch != '-' && *ch != '=')
            .map(|ch| ch.to_ascii_uppercase()),
    );
    if secret.is_empty() {
        return;
    }
    let algorithm = match c.algorithm.get().trim().to_ascii_uppercase().as_str() {
        "" => "SHA1".to_owned(),
        other => other.to_owned(),
    };
    let digits = c.digits.get().trim().parse().unwrap_or(6);
    let period = c.period.get().trim().parse().unwrap_or(30);
    let uri = Zeroizing::new(otpauth_from_parts(
        &secret,
        Some(c.issuer.get()),
        Some(c.username.get()),
        &algorithm,
        digits,
        period,
    ));
    d.set("totp", &uri);
}

/// A passkey whose fields decode becomes a `Passkey` value; otherwise its
/// private key is kept as a hidden extra with a `field_moved` warning.
fn passkey(d: &mut Draft, c: &Cred, created: Option<OffsetDateTime>, entry: u32, out: &mut Import) {
    let credential_id = b64(c.credential_id.get()).filter(|v| !v.is_empty());
    let user_handle = match c.user_handle.get().trim() {
        "" => Some(Vec::new()),
        h => b64(h),
    };
    let key = b64(c.key.get()).filter(|v| !v.is_empty());
    match (credential_id, user_handle, key) {
        (Some(credential_id), Some(user_handle), Some(key)) => d.set_value(
            "passkeys",
            FieldValue::Passkey(PasskeyCredential {
                rp_id: c.rp_id.get().to_owned(),
                user_name: c.username.get().to_owned(),
                user_handle,
                credential_id,
                private_key: Zeroizing::new(key),
                created_at: created.unwrap_or(OffsetDateTime::UNIX_EPOCH),
            }),
        ),
        _ => {
            let label = format!("Passkey {}", c.rp_id.get());
            let value = if c.key.get().trim().is_empty() {
                c.credential_id.get()
            } else {
                c.key.get()
            };
            d.extra(&label, value, true);
            out.warnings.push(Warning {
                entry,
                code: "field_moved",
            });
        }
    }
}

/// Wi-Fi data as the main fields of a Router.
fn wifi_fields(d: &mut Draft, c: &Cred) {
    d.set("ssid", c.ssid.get());
    d.set("wifi_password", c.passphrase.get());
    match (c.security.get().trim(), security(c.security.get())) {
        ("", _) => {}
        (_, Some(menu)) => d.set("security", menu),
        (raw, None) => d.extra("Sécurité", raw, false),
    }
    if !c.hidden.get().trim().is_empty() {
        d.set("hidden", yes_no(c.hidden.get()));
    }
}

/// Wi-Fi data of an item that is not a Router: kept in `imported`.
fn wifi_extras(d: &mut Draft, c: &Cred) {
    d.extra("SSID", c.ssid.get(), false);
    d.extra("Mot de passe Wi-Fi", c.passphrase.get(), true);
    d.extra("Sécurité Wi-Fi", c.security.get(), false);
    d.extra("Réseau Wi-Fi masqué", c.hidden.get(), false);
}

fn card_fields(d: &mut Draft, c: &Cred) {
    d.set("cardholder", c.full_name.get());
    d.set("number", c.number.get());
    d.set("cvv", c.verification_number.get());
    d.set("pin", c.pin.get());
    d.set("card_type", c.card_type.get());
    d.set("expiry", c.expiry_date.get());
}

fn card_extras(d: &mut Draft, c: &Cred) {
    d.extra("Titulaire de la carte", c.full_name.get(), false);
    d.extra("Numéro de carte", c.number.get(), true);
    d.extra("CVV", c.verification_number.get(), true);
    d.extra("PIN", c.pin.get(), true);
    d.extra("Type de carte", c.card_type.get(), false);
    d.extra("Expiration de la carte", c.expiry_date.get(), false);
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Kind {
    Login,
    Wifi,
    Card,
    Note,
    Unknown,
}

fn kind_of(c: &Cred) -> Kind {
    match c.kind.get().trim().to_ascii_lowercase().as_str() {
        "basic-auth" | "totp" | "passkey" => Kind::Login,
        "wifi" => Kind::Wifi,
        "credit-card" => Kind::Card,
        "note" => Kind::Note,
        _ => Kind::Unknown,
    }
}

/// One CXF item. Login first, then Router, CreditCard, SecureNote: the
/// data of the other credentials goes to `imported` or the notes.
fn item(raw: &RawItem, entry: u32, out: &mut Import) {
    // A credential that does not decode counts as an unknown one.
    let dropped = std::iter::repeat_n(Kind::Unknown, raw.credentials.dropped as usize);
    let kinds: Vec<Kind> = raw
        .credentials
        .list
        .iter()
        .map(kind_of)
        .chain(dropped)
        .collect();
    let has = |k: Kind| kinds.contains(&k);
    for _ in kinds.iter().filter(|k| **k == Kind::Unknown) {
        out.warnings.push(Warning {
            entry,
            code: "unsupported_entry",
        });
    }
    let primary = if has(Kind::Login) {
        Kind::Login
    } else if has(Kind::Wifi) {
        Kind::Wifi
    } else if has(Kind::Card) {
        Kind::Card
    } else if has(Kind::Note) {
        Kind::Note
    } else {
        out.skipped += 1;
        if kinds.is_empty() {
            out.warnings.push(Warning {
                entry,
                code: "unsupported_entry",
            });
        }
        return;
    };
    let mut d = Draft::new(match primary {
        Kind::Login => ItemType::Login,
        Kind::Wifi => ItemType::Router,
        Kind::Card => ItemType::CreditCard,
        _ => ItemType::SecureNote,
    });
    d.title(raw.title.get());
    d.favorite(raw.favorite.get().trim().eq_ignore_ascii_case("true"));
    for u in &raw.scope.urls {
        d.url(u.get());
    }
    for t in &raw.tags {
        d.tag(t.get());
    }
    date(&mut d, "Date de création", &raw.creation_at, Draft::created);
    date(
        &mut d,
        "Date de modification",
        &raw.modified_at,
        Draft::updated,
    );
    let created = timestamp(raw.creation_at.get());
    let (mut wifi_done, mut card_done, mut note_done) = (false, false, false);
    for (c, kind) in raw.credentials.list.iter().zip(&kinds) {
        match kind {
            Kind::Login => match c.kind.get().trim().to_ascii_lowercase().as_str() {
                "basic-auth" => {
                    d.set("username", c.username.get());
                    d.set("password", c.password.get());
                }
                "totp" => totp(&mut d, c),
                _ => passkey(&mut d, c, created, entry, out),
            },
            Kind::Wifi if primary == Kind::Wifi && !wifi_done => {
                wifi_done = true;
                wifi_fields(&mut d, c);
            }
            Kind::Wifi => wifi_extras(&mut d, c),
            Kind::Card if primary == Kind::Card && !card_done => {
                card_done = true;
                card_fields(&mut d, c);
            }
            Kind::Card => card_extras(&mut d, c),
            Kind::Note if primary == Kind::Note && !note_done => {
                note_done = true;
                d.set("content", c.content.get());
            }
            Kind::Note => d.notes(c.content.get()),
            Kind::Unknown => {}
        }
    }
    d.finish(entry, out);
}

/// Credential Exchange JSON: logins (basic-auth, TOTP, passkeys), Wi-Fi
/// routers, cards and notes.
pub(crate) fn parse_cxf(b: &[u8]) -> Result<Import> {
    if b.len() > MAX_INPUT {
        return Err(Error::InvalidFormat("import file too large"));
    }
    // A derived struct also reads a JSON array: insist on an object.
    let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    if b.iter().find(|c| !c.is_ascii_whitespace()) != Some(&b'{') {
        return Err(Error::InvalidFormat("cxf json"));
    }
    let root: Root = serde_json::from_slice(b).map_err(|_| Error::InvalidFormat("cxf json"))?;
    // Accounts that do not decode are unsupported entries.
    let mut out = Import {
        skipped: root.accounts.dropped,
        ..Import::default()
    };
    for (entry, raw) in root
        .accounts
        .list
        .iter()
        .flat_map(|a| a.items.0.iter())
        .enumerate()
    {
        if entry >= MAX_RECORDS {
            return Err(Error::InvalidFormat("too many cxf items"));
        }
        let entry = u32::try_from(entry).unwrap_or(u32::MAX);
        match raw {
            Some(raw) => item(raw, entry, &mut out),
            None => {
                out.skipped += 1;
                out.warnings.push(Warning {
                    entry,
                    code: "unsupported_entry",
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Item, ItemType, validate};
    use crate::totp::parse_otpauth;

    const CXF: &[u8] = include_bytes!("../../tests/fixtures/import/cxf.json");

    fn text(item: &Item, id: &str) -> Option<String> {
        match &item.field(id)?.value {
            FieldValue::Text(s) | FieldValue::Menu(s) | FieldValue::Url(s) => Some(s.clone()),
            FieldValue::Password(s) | FieldValue::Concealed(s) | FieldValue::Otp(s) => {
                Some(s.to_string())
            }
            _ => None,
        }
    }

    fn imported_labels(item: &Item) -> Vec<String> {
        item.sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter().map(|f| f.label.clone()))
            .collect()
    }

    fn parse(json: &str) -> Import {
        parse_cxf(json.as_bytes()).unwrap()
    }

    #[test]
    fn cxf_login_totp_passkey() {
        let imp = parse_cxf(CXF).unwrap();
        let item = &imp.items[0].item;
        assert_eq!(item.item_type, ItemType::Login);
        assert_eq!(item.title, "Example Login");
        assert!(item.favorite);
        assert_eq!(item.tags, ["work", "demo"]);
        assert_eq!(item.urls.len(), 2);
        assert_eq!(item.urls[0].url, "https://example.com/login");
        assert!(item.urls[0].primary);
        assert_eq!(item.created_at.unix_timestamp(), 1_690_000_000);
        assert_eq!(item.updated_at.unix_timestamp(), 1_700_000_000);
        assert_eq!(text(item, "username").as_deref(), Some("alice"));
        assert_eq!(text(item, "password").as_deref(), Some("Pw-Example-1"));
        let cfg = parse_otpauth(&text(item, "totp").unwrap()).unwrap();
        assert_eq!(cfg.issuer.as_deref(), Some("Example"));
        let Some(FieldValue::Passkey(p)) = item.field("passkeys").map(|f| &f.value) else {
            panic!("passkey")
        };
        assert_eq!(p.rp_id, "example.com");
        assert_eq!(p.user_name, "alice");
        assert_eq!(p.credential_id, [1, 2, 3, 4]);
        assert_eq!(p.user_handle, b"user1");
        assert_eq!(&p.private_key[..], b"keyblo");
        for i in &imp.items {
            validate(&i.item).unwrap();
            assert_eq!(i.item.vault_id.0, [0; 16]);
        }
    }

    #[test]
    fn cxf_totp_options() {
        let imp = parse(
            r#"{"accounts":[{"items":[{"title":"T","credentials":[
            {"type":"basic-auth","username":"u"},
            {"type":"totp","secret":"jbsw y3dp ehpk 3pxp","period":60,"digits":8,
             "algorithm":"sha256","issuer":"Acme","username":"u"}]}]}]}"#,
        );
        let cfg = parse_otpauth(&text(&imp.items[0].item, "totp").unwrap()).unwrap();
        assert_eq!((cfg.digits, cfg.period), (8, 60));
        assert_eq!(cfg.algorithm, crate::totp::TotpAlgorithm::Sha256);
    }

    #[test]
    fn cxf_wifi_to_router() {
        let imp = parse_cxf(CXF).unwrap();
        let item = &imp.items[1].item;
        assert_eq!(item.item_type, ItemType::Router);
        assert_eq!(item.title, "Home Wi-Fi");
        assert_eq!(text(item, "ssid").as_deref(), Some("HomeNet-Test"));
        assert_eq!(text(item, "security").as_deref(), Some("WPA3"));
        assert_eq!(
            text(item, "wifi_password").as_deref(),
            Some("wifi-pass-123")
        );
        assert_eq!(text(item, "hidden").as_deref(), Some("oui"));
    }

    #[test]
    fn cxf_wifi_security_values() {
        let sec = |s: &str| {
            let j = format!(
                r#"{{"accounts":[{{"items":[{{"title":"W","credentials":[
                {{"type":"wifi","ssid":"n","networkSecurityType":"{s}","passphrase":"p"}}]}}]}}]}}"#
            );
            text(&parse(&j).items[0].item, "security")
        };
        assert_eq!(sec("unsecured").as_deref(), Some("ouvert"));
        assert_eq!(sec("wep").as_deref(), Some("WEP"));
        assert_eq!(sec("wpa-personal").as_deref(), Some("WPA"));
        assert_eq!(sec("wpa2-personal").as_deref(), Some("WPA2"));
    }

    #[test]
    fn cxf_card() {
        let imp = parse_cxf(CXF).unwrap();
        let item = &imp.items[2].item;
        assert_eq!(item.item_type, ItemType::CreditCard);
        assert_eq!(text(item, "cardholder").as_deref(), Some("Alice Example"));
        assert_eq!(text(item, "number").as_deref(), Some("4111111111111111"));
        assert_eq!(text(item, "cvv").as_deref(), Some("123"));
        assert_eq!(text(item, "pin").as_deref(), Some("4321"));
        assert_eq!(text(item, "card_type").as_deref(), Some("Visa"));
        assert!(matches!(
            item.field("expiry").map(|f| &f.value),
            Some(FieldValue::MonthYear {
                year: 2030,
                month: 5
            })
        ));
    }

    #[test]
    fn cxf_note_alone_is_secure_note() {
        let imp = parse_cxf(CXF).unwrap();
        let item = &imp.items[3].item;
        assert_eq!(item.item_type, ItemType::SecureNote);
        assert_eq!(text(item, "content").as_deref(), Some("remember the milk"));
    }

    #[test]
    fn cxf_note_goes_to_notes_beside_login() {
        let imp = parse(
            r#"{"accounts":[{"items":[{"title":"L","credentials":[
            {"type":"basic-auth","username":"u","password":"p"},
            {"type":"note","content":"side note"}]}]}]}"#,
        );
        let item = &imp.items[0].item;
        assert_eq!(item.item_type, ItemType::Login);
        assert_eq!(item.notes, "side note");
    }

    #[test]
    fn cxf_login_wins_over_wifi() {
        let imp = parse_cxf(CXF).unwrap();
        let item = &imp.items[4].item;
        assert_eq!(item.item_type, ItemType::Login);
        assert_eq!(text(item, "username").as_deref(), Some("admin"));
        let labels = imported_labels(item);
        assert!(labels.iter().any(|l| l == "SSID"), "{labels:?}");
        assert!(labels.iter().any(|l| l.contains("Wi-Fi")), "{labels:?}");
    }

    #[test]
    fn cxf_unknown_credential_type() {
        let imp = parse_cxf(CXF).unwrap();
        // Item 6 has only an unknown credential: skipped with a warning.
        assert_eq!(imp.items.len(), 5);
        assert_eq!(imp.skipped, 1);
        assert_eq!(
            imp.warnings,
            [Warning {
                entry: 5,
                code: "unsupported_entry"
            }]
        );
        // Mixed: the item is still produced, one warning per unknown one.
        let imp = parse(
            r#"{"accounts":[{"items":[{"title":"L","credentials":[
            {"type":"basic-auth","username":"u","password":"p"},
            {"type":"api-key"},{"type":"ssh-key"}]}]}]}"#,
        );
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.skipped, 0);
        assert_eq!(imp.warnings.len(), 2);
        assert!(imp.warnings.iter().all(|w| w.code == "unsupported_entry"));
    }

    #[test]
    fn cxf_field_as_plain_string() {
        let imp = parse(
            r#"{"accounts":[{"items":[{"title":"P","credentials":[
            {"type":"basic-auth","username":"bob","password":"pw2"},
            {"type":"wifi","ssid":"Plain","hidden":true,"passphrase":12345678}]}]}]}"#,
        );
        let item = &imp.items[0].item;
        assert_eq!(text(item, "username").as_deref(), Some("bob"));
        assert_eq!(text(item, "password").as_deref(), Some("pw2"));
        // The wifi data of a Login lands in `imported`, as plain text too.
        assert!(imported_labels(item).iter().any(|l| l == "SSID"));
        let router = parse(
            r#"{"accounts":[{"items":[{"title":"R","credentials":[
            {"type":"wifi","ssid":"Plain","hidden":true,"passphrase":12345678}]}]}]}"#,
        );
        let r = &router.items[0].item;
        assert_eq!(text(r, "hidden").as_deref(), Some("oui"));
        assert_eq!(text(r, "wifi_password").as_deref(), Some("12345678"));
    }

    #[test]
    fn cxf_null_containers_and_bad_input() {
        let imp =
            parse(r#"{"accounts":[{"items":null},{"items":[{"title":"x","credentials":null}]}]}"#);
        assert!(imp.items.is_empty());
        assert_eq!(imp.skipped, 1);
        assert!(parse_cxf(b"not json").is_err());
        assert!(parse_cxf(b"[]").is_err());
        assert!(parse(r#"{"accounts":null}"#).items.is_empty());
    }

    #[test]
    fn cxf_broken_passkey_is_moved() {
        let imp = parse(
            r#"{"accounts":[{"items":[{"title":"K","credentials":[
            {"type":"basic-auth","username":"u","password":"p"},
            {"type":"passkey","credentialId":"!!","rpId":"example.com","key":"!!"}]}]}]}"#,
        );
        let item = &imp.items[0].item;
        assert!(item.field("passkeys").is_some());
        assert!(imp.warnings.iter().any(|w| w.code == "field_moved"));
    }

    #[test]
    fn undecodable_items_and_credentials_are_counted() {
        let imp = parse(
            r#"{"accounts":[3,{"items":["x",{"title":"N","credentials":[
                {"type":"note","content":"hello"},7]}]}]}"#,
        );
        assert_eq!(imp.items.len(), 1);
        assert_eq!(imp.skipped, 2);
        let codes: Vec<_> = imp.warnings.iter().map(|w| (w.entry, w.code)).collect();
        assert_eq!(
            codes,
            vec![(0, "unsupported_entry"), (1, "unsupported_entry")]
        );
        // Only an undecodable credential: skipped, one warning.
        let imp = parse(r#"{"accounts":[{"items":[{"title":"Z","credentials":[false]}]}]}"#);
        assert!(imp.items.is_empty());
        assert_eq!(imp.skipped, 1);
        assert_eq!(imp.warnings.len(), 1);
    }
}
