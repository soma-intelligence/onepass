//! `onepass://<vault>/<item>/[<section>/]<field>` secret references.
//!
//! Choices:
//! - Segments are percent-encoded. Empty segments, a query, a fragment and
//!   invalid escapes are refused. `+` is a plus, not a space.
//! - Vault and item segments match by name (case-insensitive) or by id. An
//!   id match wins over name matches. Several names matching is refused
//!   with "ambiguous reference, use the item id" (or "use the vault id").
//!   Trashed items are not resolvable; archived ones are.
//! - Section and field segments match by id first, then by label
//!   (case-insensitive). Without a section, several fields matching at the
//!   same step is refused with "ambiguous field, add the section": a
//!   reference injects a secret into a script, so it must never pick one
//!   silently. Within a named section, the first match in template order
//!   wins (repeatable fields share an id).
//! - Values: text-like kinds give their text, a number its decimal form, a
//!   date `YYYY-MM-DD`, a month and year `YYYY-MM`, an SSH key its private
//!   PEM (a reference is meant for injecting secrets). An OTP field gives
//!   the current code, from an `otpauth://` URI or a bare base32 secret,
//!   decoded as base32 on its own (never pasted into a URI).
//!   Money, address, location, file, passkey and item link fields are not
//!   text and are refused. An empty field is refused too.
//! - Without a section, the field `totp` is the code of the item's one
//!   filled OTP field, wherever it sits (`otp_field_of`). None is not
//!   found; several are "ambiguous one-time password, add the section".

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::model::{Field, FieldValue, Item, Section};
use crate::repo::Repository;
use crate::store::RecordStore;
use crate::totp::{code_at, parse_otpauth, totp_from_secret};
use crate::vault::Vault;
use crate::{Error, Result, ValidationError};

const SCHEME: &str = "onepass://";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub vault: String,
    pub item: String,
    pub section: Option<String>,
    pub field: String,
}

fn invalid(reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: "reference".to_owned(),
        reason,
    })
}

fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .ok_or_else(|| invalid("bad percent escape"))?;
            if !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(invalid("bad percent escape"));
            }
            out.push(u8::from_str_radix(hex, 16).map_err(|_| invalid("bad percent escape"))?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| invalid("segment is not valid text"))
}

/// Parse `onepass://<vault>/<item>/[<section>/]<field>`.
pub fn parse_ref(s: &str) -> Result<SecretRef> {
    let head = s
        .get(..SCHEME.len())
        .filter(|h| h.eq_ignore_ascii_case(SCHEME))
        .ok_or_else(|| invalid("scheme must be onepass://"))?;
    let rest = &s[head.len()..];
    if rest.contains(['?', '#']) {
        return Err(invalid("query and fragment are not supported"));
    }
    let raw: Vec<&str> = rest.split('/').collect();
    if !(3..=4).contains(&raw.len()) {
        return Err(invalid("expected vault/item/[section/]field"));
    }
    if raw.iter().any(|seg| seg.is_empty()) {
        return Err(invalid("empty segment"));
    }
    let mut seg = raw
        .into_iter()
        .map(percent_decode)
        .collect::<Result<Vec<_>>>()?
        .into_iter();
    let vault = seg.next().unwrap_or_default();
    let item = seg.next().unwrap_or_default();
    let mut section = None;
    let mut field = seg.next().unwrap_or_default();
    if let Some(last) = seg.next() {
        section = Some(field);
        field = last;
    }
    Ok(SecretRef {
        vault,
        item,
        section,
        field,
    })
}

/// The one entry whose id string equals `seg`, else the only one whose name
/// equals it ignoring case. Several names are ambiguous (`ambiguous`, the
/// reason given), none is not found.
fn pick<'a, T>(
    entries: &'a [T],
    seg: &str,
    ambiguous: &'static str,
    id: impl Fn(&T) -> String,
    name: impl Fn(&T) -> &str,
) -> Result<&'a T> {
    if let Some(e) = entries.iter().find(|e| id(e).eq_ignore_ascii_case(seg)) {
        return Ok(e);
    }
    let mut named = entries
        .iter()
        .filter(|e| name(e).to_lowercase() == seg.to_lowercase());
    match (named.next(), named.next()) {
        (Some(e), None) => Ok(e),
        (Some(_), Some(_)) => Err(invalid(ambiguous)),
        _ => Err(Error::NotFound),
    }
}

fn label_is(label: &str, seg: &str) -> bool {
    label.to_lowercase() == seg.to_lowercase()
}

/// Field by id, then by label, among `sections` in order: the first match.
fn find_field<'a>(sections: &[&'a Section], seg: &str) -> Option<&'a Field> {
    let all = || sections.iter().flat_map(|s| s.fields.iter());
    all()
        .find(|f| f.id == seg)
        .or_else(|| all().find(|f| label_is(&f.label, seg)))
}

/// Field of the whole item by id, then by label: the only match at the
/// first step that has one. Several are ambiguous.
fn find_unique_field<'a>(item: &'a Item, seg: &str) -> Result<Option<&'a Field>> {
    let all = || item.sections.iter().flat_map(|s| s.fields.iter());
    let by_id: Vec<&Field> = all().filter(|f| f.id == seg).collect();
    let hits = if by_id.is_empty() {
        all().filter(|f| label_is(&f.label, seg)).collect()
    } else {
        by_id
    };
    match hits.as_slice() {
        [] => Ok(None),
        [f] => Ok(Some(f)),
        _ => Err(invalid("ambiguous field, add the section")),
    }
}

/// The item's one OTP field with a value (blank values do not count),
/// wherever it sits: what `totp` resolves to. None is `NotFound`, several
/// are ambiguous.
pub fn otp_field_of(item: &Item) -> Result<&Field> {
    let mut filled = item
        .sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter(|f| matches!(&f.value, FieldValue::Otp(v) if !v.trim().is_empty()));
    match (filled.next(), filled.next()) {
        (Some(f), None) => Ok(f),
        (Some(_), Some(_)) => Err(invalid("ambiguous one-time password, add the section")),
        (None, _) => Err(Error::NotFound),
    }
}

fn locate<'a>(item: &'a Item, r: &SecretRef) -> Result<&'a Field> {
    let all: Vec<&Section> = item.sections.iter().collect();
    let found = match &r.section {
        None if r.field.eq_ignore_ascii_case("totp") => Some(otp_field_of(item)?),
        None => find_unique_field(item, &r.field)?,
        Some(sec) => {
            let by_id: Vec<&Section> = all.iter().copied().filter(|s| s.id == *sec).collect();
            let chosen = if by_id.is_empty() {
                all.iter()
                    .copied()
                    .filter(|s| label_is(&s.label, sec))
                    .collect()
            } else {
                by_id
            };
            find_field(&chosen, &r.field)
        }
    };
    found.ok_or(Error::NotFound)
}

/// An `otpauth://` URI is parsed as one; anything else is a bare base32
/// secret, decoded on its own so that no text in it can act as a URI
/// parameter.
fn otp_code(value: &str, now: u64) -> Result<Zeroizing<String>> {
    const OTPAUTH: &str = "otpauth://";
    let value = value.trim();
    let cfg = if value
        .get(..OTPAUTH.len())
        .is_some_and(|h| h.eq_ignore_ascii_case(OTPAUTH))
    {
        parse_otpauth(value)?
    } else {
        totp_from_secret(value)?
    };
    Ok(Zeroizing::new(code_at(&cfg, now)?))
}

fn render(field: &Field, now: u64) -> Result<Zeroizing<String>> {
    let text = |s: &str| Ok(Zeroizing::new(s.to_owned()));
    match &field.value {
        FieldValue::Text(s)
        | FieldValue::Url(s)
        | FieldValue::Email(s)
        | FieldValue::Phone(s)
        | FieldValue::Menu(s) => text(s),
        FieldValue::Concealed(s) | FieldValue::Password(s) | FieldValue::Mnemonic(s) => {
            Ok(s.clone())
        }
        FieldValue::Barcode { value, .. } => text(value),
        FieldValue::Number(n) => Ok(Zeroizing::new(n.to_string())),
        FieldValue::Date(d) => Ok(Zeroizing::new(format!(
            "{:04}-{:02}-{:02}",
            d.year(),
            u8::from(d.month()),
            d.day()
        ))),
        FieldValue::MonthYear { year, month } => {
            Ok(Zeroizing::new(format!("{year:04}-{month:02}")))
        }
        FieldValue::SshKey(k) => Ok(k.private_pem.clone()),
        FieldValue::Otp(s) if s.trim().is_empty() => Err(invalid("field is empty")),
        FieldValue::Otp(s) => otp_code(s, now),
        FieldValue::Empty => Err(invalid("field is empty")),
        FieldValue::Money { .. }
        | FieldValue::Address(_)
        | FieldValue::Passkey(_)
        | FieldValue::File(_)
        | FieldValue::Location(_)
        | FieldValue::ItemLink(_) => Err(invalid("field cannot be read as text")),
    }
}

impl<S: RecordStore> Repository<S> {
    /// The value a reference points at. `&mut self` because reading a
    /// vault updates the last manifest seen.
    pub fn resolve(&mut self, r: &SecretRef) -> Result<Zeroizing<String>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidFormat("system clock"))?
            .as_secs();
        self.resolve_at(r, now)
    }

    fn resolve_at(&mut self, r: &SecretRef, now: u64) -> Result<Zeroizing<String>> {
        let vaults = self.vaults()?;
        let vault: &Vault = pick(
            &vaults,
            &r.vault,
            "ambiguous reference, use the vault id",
            |v| v.id.to_string(),
            |v| &v.meta.name,
        )?;
        let items: Vec<Item> = self
            .items(vault)?
            .into_iter()
            .filter(|i| i.trashed_at.is_none())
            .collect();
        let item = pick(
            &items,
            &r.item,
            "ambiguous reference, use the item id",
            |i| i.id.to_string(),
            |i| &i.title,
        )?;
        render(locate(item, r)?, now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use time::macros::date;

    use super::*;
    use crate::account::{Account, NewAccount};
    use crate::crypto::{KdfParams, random_array};
    use crate::model::{ItemType, new_item};
    use crate::repo::DeviceState;
    use crate::store::{MemoryStore, Record, RecordKind};
    use crate::vault::VaultMeta;

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
        let v = repo
            .create_vault(VaultMeta {
                name: "Perso".into(),
                icon: "key".into(),
                color: "blue".into(),
                travel_safe: false,
                mcp_access: false,
            })
            .unwrap();
        (repo, v)
    }

    fn r(s: &str) -> SecretRef {
        parse_ref(s).unwrap()
    }

    fn set(item: &mut Item, id: &str, v: FieldValue) {
        item.field_mut(id).unwrap().value = v;
    }

    fn github(v: &Vault) -> Item {
        let mut it = new_item(ItemType::Login, v.id, "GitHub");
        set(&mut it, "username", FieldValue::Text("octo".into()));
        set(
            &mut it,
            "password",
            FieldValue::Password(Zeroizing::new("hunter2".into())),
        );
        it
    }

    #[test]
    fn parse_forms() {
        assert_eq!(
            parse_ref("onepass://Perso/GitHub/password").unwrap().field,
            "password"
        );
        assert_eq!(
            parse_ref("onepass://Perso/My%20Bank/Online/username")
                .unwrap()
                .section
                .as_deref(),
            Some("Online")
        );
        assert_eq!(
            parse_ref("onepass://Perso/My%20Bank/Online/username")
                .unwrap()
                .item,
            "My Bank"
        );
        assert!(parse_ref("https://Perso/GitHub/password").is_err());
        assert!(parse_ref("onepass://Perso/GitHub").is_err());
    }

    #[test]
    fn parse_rejects_malformed_without_panicking() {
        for bad in [
            "",
            "onepass://",
            "onepass:///GitHub/password",
            "onepass://Perso//password",
            "onepass://Perso/GitHub/",
            "onepass://Perso/GitHub/a/b/c",
            "onepass://Perso/GitHub/pass%",
            "onepass://Perso/GitHub/pass%zz",
            "onepass://Perso/GitHub/%ff",
            "onepass://Perso/GitHub/password?x=1",
            "onepass://Perso/GitHub/password#x",
            "onepass:/Perso/GitHub/password",
            "é",
        ] {
            assert!(
                matches!(parse_ref(bad), Err(Error::Validation(_))),
                "{bad:?}"
            );
        }
        assert_eq!(r("onepass://a/b%2Fc/d").item, "b/c");
        assert_eq!(r("ONEPASS://a/b/c").field, "c");
    }

    #[test]
    fn resolve_by_name_id_and_label() {
        let (mut repo, v) = fixture();
        let it = github(&v);
        let id = it.id;
        repo.save_item(&v, it).unwrap();
        for s in [
            "onepass://perso/github/password".to_owned(),
            format!("onepass://{}/{id}/password", v.id),
            "onepass://Perso/GitHub/main/password".to_owned(),
            "onepass://Perso/GitHub/Connexion/Mot%20de%20passe".to_owned(),
        ] {
            assert_eq!(&**repo.resolve(&r(&s)).unwrap(), "hunter2", "{s}");
        }
        assert_eq!(
            &**repo
                .resolve(&r("onepass://Perso/GitHub/identifiant"))
                .unwrap(),
            "octo"
        );
    }

    #[test]
    fn resolve_not_found() {
        let (mut repo, v) = fixture();
        repo.save_item(&v, github(&v)).unwrap();
        for s in [
            "onepass://Nope/GitHub/password",
            "onepass://Perso/Nope/password",
            "onepass://Perso/GitHub/nope",
            "onepass://Perso/GitHub/nosection/password",
        ] {
            assert_eq!(repo.resolve(&r(s)).unwrap_err(), Error::NotFound, "{s}");
        }
    }

    #[test]
    fn resolve_ambiguous_name_is_an_error() {
        let (mut repo, v) = fixture();
        let a = github(&v);
        let b = github(&v);
        let a_id = a.id;
        repo.save_item(&v, a).unwrap();
        repo.save_item(&v, b).unwrap();
        match repo.resolve(&r("onepass://Perso/GitHub/password")) {
            Err(Error::Validation(e)) => {
                assert_eq!(e.reason, "ambiguous reference, use the item id");
            }
            other => panic!("{other:?}"),
        }
        let by_id = format!("onepass://Perso/{a_id}/password");
        assert_eq!(&**repo.resolve(&r(&by_id)).unwrap(), "hunter2");
    }

    #[test]
    fn trashed_items_are_not_resolvable() {
        let (mut repo, v) = fixture();
        let it = github(&v);
        let id = it.id;
        repo.save_item(&v, it).unwrap();
        repo.trash_item(&v, id).unwrap();
        assert_eq!(
            repo.resolve(&r("onepass://Perso/GitHub/password"))
                .unwrap_err(),
            Error::NotFound
        );
    }

    #[test]
    fn resolve_totp_field() {
        let (mut repo, v) = fixture();
        let mut it = github(&v);
        set(
            &mut it,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        );
        repo.save_item(&v, it).unwrap();
        let code = repo.resolve(&r("onepass://Perso/GitHub/totp")).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        // Same code through the explicit section and a fixed clock.
        let at = repo
            .resolve_at(&r("onepass://Perso/GitHub/main/totp"), 59)
            .unwrap();
        let cfg = parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(&**at, code_at(&cfg, 59).unwrap().as_str());
    }

    #[test]
    fn resolve_totp_from_otpauth_uri() {
        let (mut repo, v) = fixture();
        let mut it = github(&v);
        let uri = "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&digits=8&issuer=GitHub";
        set(&mut it, "totp", FieldValue::Otp(Zeroizing::new(uri.into())));
        repo.save_item(&v, it).unwrap();
        let code = repo.resolve(&r("onepass://Perso/GitHub/totp")).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn totp_without_otp_field_is_not_found() {
        let (mut repo, v) = fixture();
        repo.save_item(&v, github(&v)).unwrap();
        assert_eq!(
            repo.resolve(&r("onepass://Perso/GitHub/totp")).unwrap_err(),
            Error::NotFound
        );
    }

    fn otp_field(id: &str, value: &str) -> Field {
        Field {
            id: id.into(),
            label: id.into(),
            kind: crate::model::FieldType::Otp,
            value: FieldValue::Otp(Zeroizing::new(value.into())),
            required: false,
            repeatable: false,
            autofill: false,
        }
    }

    fn reason<T: std::fmt::Debug>(r: Result<T>) -> &'static str {
        match r {
            Err(Error::Validation(e)) => e.reason,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn several_sectionless_matches_are_ambiguous() {
        let (mut repo, v) = fixture();
        let mut it = github(&v);
        it.sections.push(Section {
            id: "work".into(),
            label: "Travail".into(),
            fields: vec![Field {
                id: "password".into(),
                label: "Autre".into(),
                kind: crate::model::FieldType::Password,
                value: FieldValue::Password(Zeroizing::new("other".into())),
                required: false,
                repeatable: false,
                autofill: false,
            }],
        });
        repo.save_item(&v, it).unwrap();
        assert_eq!(
            reason(repo.resolve(&r("onepass://Perso/GitHub/password"))),
            "ambiguous field, add the section"
        );
        // The section settles it.
        assert_eq!(
            &**repo
                .resolve(&r("onepass://Perso/GitHub/work/password"))
                .unwrap(),
            "other"
        );
        assert_eq!(
            &**repo
                .resolve(&r("onepass://Perso/GitHub/main/password"))
                .unwrap(),
            "hunter2"
        );
    }

    #[test]
    fn ambiguous_vault_names_the_vault_id() {
        let (mut repo, v) = fixture();
        repo.save_item(&v, github(&v)).unwrap();
        repo.create_vault(VaultMeta {
            name: "perso".into(),
            icon: "key".into(),
            color: "blue".into(),
            travel_safe: false,
            mcp_access: false,
        })
        .unwrap();
        assert_eq!(
            reason(repo.resolve(&r("onepass://Perso/GitHub/password"))),
            "ambiguous reference, use the vault id"
        );
    }

    #[test]
    fn bare_otp_secret_is_decoded_not_interpolated() {
        let (mut repo, v) = fixture();
        let mut it = github(&v);
        // Appended to a URI, this would turn into an 8-digit SHA-256 code.
        set(
            &mut it,
            "totp",
            FieldValue::Otp(Zeroizing::new(
                "JBSWY3DPEHPK3PXP&digits=8&algorithm=SHA256".into(),
            )),
        );
        repo.save_item(&v, it).unwrap();
        assert_eq!(
            repo.resolve(&r("onepass://Perso/GitHub/totp")).unwrap_err(),
            Error::InvalidFormat("otp secret")
        );
        // Spaces, dashes and lower case are fine in a bare secret.
        let (mut repo, v) = fixture();
        let mut it = github(&v);
        set(
            &mut it,
            "totp",
            FieldValue::Otp(Zeroizing::new("jbsw y3dp-ehpk 3pxp".into())),
        );
        repo.save_item(&v, it).unwrap();
        let cfg = parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(
            &**repo
                .resolve_at(&r("onepass://Perso/GitHub/totp"), 59)
                .unwrap(),
            code_at(&cfg, 59).unwrap().as_str()
        );
    }

    #[test]
    fn totp_picks_the_one_filled_otp_field() {
        let (mut repo, v) = fixture();
        let mut it = github(&v);
        // The template's totp field holds only spaces; the filled one sits
        // in another section.
        set(
            &mut it,
            "totp",
            FieldValue::Otp(Zeroizing::new("  ".into())),
        );
        it.sections.push(Section {
            id: "extra".into(),
            label: "Extra".into(),
            fields: vec![otp_field("code", "JBSWY3DPEHPK3PXP")],
        });
        repo.save_item(&v, it.clone()).unwrap();
        let cfg = parse_otpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(
            &**repo
                .resolve_at(&r("onepass://Perso/GitHub/totp"), 59)
                .unwrap(),
            code_at(&cfg, 59).unwrap().as_str()
        );
        assert_eq!(otp_field_of(&it).unwrap().id, "code");

        // Two filled OTP fields: which code is meant is not clear.
        let (mut repo, v) = fixture();
        let mut it = github(&v);
        set(
            &mut it,
            "totp",
            FieldValue::Otp(Zeroizing::new("JBSWY3DPEHPK3PXP".into())),
        );
        it.sections.push(Section {
            id: "extra".into(),
            label: "Extra".into(),
            fields: vec![otp_field("code", "GEZDGNBVGY3TQOJQ")],
        });
        repo.save_item(&v, it).unwrap();
        assert_eq!(
            reason(repo.resolve(&r("onepass://Perso/GitHub/totp"))),
            "ambiguous one-time password, add the section"
        );
    }

    #[test]
    fn value_kinds() {
        let (mut repo, v) = fixture();
        let mut it = github(&v);
        set(&mut it, "pin", FieldValue::Number(-42));
        set(&mut it, "passkeys", FieldValue::Empty);
        set(
            &mut it,
            "recovery_phone",
            FieldValue::Money {
                minor_units: 1,
                currency: "EUR".into(),
            },
        );
        it.sections[0].fields.push(Field {
            id: "since".into(),
            label: "Since".into(),
            kind: crate::model::FieldType::Date,
            value: FieldValue::Date(date!(2026 - 03 - 07)),
            required: false,
            repeatable: false,
            autofill: false,
        });
        it.sections[0].fields.push(Field {
            id: "expiry".into(),
            label: "Expiry".into(),
            kind: crate::model::FieldType::MonthYear,
            value: FieldValue::MonthYear {
                year: 2030,
                month: 5,
            },
            required: false,
            repeatable: false,
            autofill: false,
        });
        repo.save_item(&v, it).unwrap();
        let get = |repo: &mut Repository<MemoryStore>, f: &str| {
            repo.resolve(&r(&format!("onepass://Perso/GitHub/{f}")))
        };
        assert_eq!(&**get(&mut repo, "pin").unwrap(), "-42");
        assert_eq!(&**get(&mut repo, "since").unwrap(), "2026-03-07");
        assert_eq!(&**get(&mut repo, "expiry").unwrap(), "2030-05");
        for f in ["passkeys", "recovery_phone", "email"] {
            match get(&mut repo, f) {
                Err(Error::Validation(e)) => assert_eq!(e.field, "reference", "{f}"),
                other => panic!("{f}: {other:?}"),
            }
        }
    }

    #[test]
    fn ssh_key_gives_the_private_pem() {
        use crate::model::SshKeyValue;
        let (mut repo, v) = fixture();
        let mut it = new_item(ItemType::SshKey, v.id, "Deploy");
        set(
            &mut it,
            "private_key",
            FieldValue::SshKey(SshKeyValue {
                private_pem: Zeroizing::new("PEM-BODY".into()),
                public_openssh: "ssh-ed25519 AAAA".into(),
                fingerprint_sha256: "SHA256:x".into(),
            }),
        );
        repo.save_item(&v, it).unwrap();
        let out = repo
            .resolve(&r("onepass://Perso/Deploy/private_key"))
            .unwrap();
        assert_eq!(&**out, "PEM-BODY");
    }

    #[test]
    fn errors_do_not_leak_values() {
        const PASSWORD: &str = "Zx9-pass-w0rd-canary";
        const SEED: &str = "JBSWY3DPEHPK3PXP";
        const BAD_SEED: &str = "bad!seed-canary";
        const TITLE: &str = "Canary Title";
        let (mut repo, v) = fixture();
        let mut it = new_item(ItemType::Login, v.id, TITLE);
        set(&mut it, "username", FieldValue::Text("u".into()));
        set(
            &mut it,
            "password",
            FieldValue::Password(Zeroizing::new(PASSWORD.into())),
        );
        set(
            &mut it,
            "totp",
            FieldValue::Otp(Zeroizing::new(SEED.into())),
        );
        set(
            &mut it,
            "recovery_phone",
            FieldValue::Money {
                minor_units: 1,
                currency: "EUR".into(),
            },
        );
        repo.save_item(&v, it).unwrap();
        let mut twin = new_item(ItemType::Login, v.id, TITLE);
        set(&mut twin, "username", FieldValue::Text("u".into()));
        set(
            &mut twin,
            "password",
            FieldValue::Password(Zeroizing::new(PASSWORD.into())),
        );
        repo.save_item(&v, twin).unwrap();
        let mut broken = new_item(ItemType::Login, v.id, "Broken");
        set(&mut broken, "username", FieldValue::Text("u".into()));
        set(
            &mut broken,
            "totp",
            FieldValue::Otp(Zeroizing::new(BAD_SEED.into())),
        );
        repo.save_item(&v, broken).unwrap();

        let mut errors = vec![
            repo.resolve(&r("onepass://Perso/Canary%20Title/password"))
                .unwrap_err(),
            repo.resolve(&r("onepass://Perso/Missing/password"))
                .unwrap_err(),
            repo.resolve(&r("onepass://Perso/Broken/totp")).unwrap_err(),
            parse_ref("onepass://Perso/Canary%20Title/pass%zz").unwrap_err(),
            parse_ref(&format!("onepass://Perso/{TITLE}/{PASSWORD}?{SEED}")).unwrap_err(),
        ];
        // Same title twice: ambiguous. Give the unique one a bad-kind read.
        assert!(matches!(&errors[0], Error::Validation(e) if e.reason.starts_with("ambiguous")));
        let mut solo = new_item(ItemType::Login, v.id, "Solo Canary");
        set(&mut solo, "username", FieldValue::Text("u".into()));
        set(
            &mut solo,
            "recovery_phone",
            FieldValue::Money {
                minor_units: 1,
                currency: "EUR".into(),
            },
        );
        set(
            &mut solo,
            "password",
            FieldValue::Password(Zeroizing::new(PASSWORD.into())),
        );
        repo.save_item(&v, solo).unwrap();
        let bad_kind = repo
            .resolve(&r("onepass://Perso/Solo%20Canary/recovery_phone"))
            .unwrap_err();
        assert!(
            matches!(&bad_kind, Error::Validation(e) if e.reason == "field cannot be read as text")
        );
        assert_eq!(errors[1], Error::NotFound);
        assert!(matches!(errors[2], Error::InvalidFormat(_)));
        errors.push(bad_kind);
        for e in &errors {
            for text in [e.to_string(), format!("{e:?}")] {
                for secret in [PASSWORD, SEED, BAD_SEED, TITLE, "Solo Canary", "Canary"] {
                    assert!(!text.contains(secret), "{text:?} leaks {secret:?}");
                }
            }
        }
    }
}
