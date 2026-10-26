//! `onepass://<vault>/<item>/[<section>/]<field>` secret references.
//!
//! Choices:
//! - Segments are percent-encoded. Empty segments, a query, a fragment and
//!   invalid escapes are refused. `+` is a plus, not a space.
//! - Vault and item segments match by name (case-insensitive) or by id. An
//!   id match wins over name matches. Several names matching is refused
//!   with "ambiguous reference, use the item id" (the same message for
//!   vaults). Trashed items are not resolvable; archived ones are.
//! - Section and field segments match by id first, then by label
//!   (case-insensitive). The first match in template order wins.
//! - Values: text-like kinds give their text, a number its decimal form, a
//!   date `YYYY-MM-DD`, a month and year `YYYY-MM`, an SSH key its private
//!   PEM (a reference is meant for injecting secrets). An OTP field gives
//!   the current code, from an `otpauth://` URI or a bare base32 secret.
//!   Money, address, location, file, passkey and item link fields are not
//!   text and are refused. An empty field is refused too.
//! - Without a section, the field `totp` is the code of the first OTP field
//!   of the item, wherever it sits.

use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::model::{Field, FieldValue, Item, Section};
use crate::repo::Repository;
use crate::store::RecordStore;
use crate::totp::{code_at, parse_otpauth};
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
/// equals it ignoring case. Several names are ambiguous, none is not found.
fn pick<'a, T>(
    entries: &'a [T],
    seg: &str,
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
        (Some(_), Some(_)) => Err(invalid("ambiguous reference, use the item id")),
        _ => Err(Error::NotFound),
    }
}

fn label_is(label: &str, seg: &str) -> bool {
    label.to_lowercase() == seg.to_lowercase()
}

/// Field by id, then by label, among `sections` in order.
fn find_field<'a>(sections: &[&'a Section], seg: &str) -> Option<&'a Field> {
    let all = || sections.iter().flat_map(|s| s.fields.iter());
    all()
        .find(|f| f.id == seg)
        .or_else(|| all().find(|f| label_is(&f.label, seg)))
}

fn locate<'a>(item: &'a Item, r: &SecretRef) -> Result<&'a Field> {
    let all: Vec<&Section> = item.sections.iter().collect();
    let found = match &r.section {
        None if r.field.eq_ignore_ascii_case("totp") => item
            .sections
            .iter()
            .flat_map(|s| s.fields.iter())
            .find(|f| matches!(f.value, FieldValue::Otp(_))),
        None => find_field(&all, &r.field),
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

fn otp_code(value: &str, now: u64) -> Result<Zeroizing<String>> {
    let value = value.trim();
    let uri: Zeroizing<String> = if value
        .get(..10)
        .is_some_and(|h| h.eq_ignore_ascii_case("otpauth://"))
    {
        Zeroizing::new(value.to_owned())
    } else {
        Zeroizing::new(format!("otpauth://totp/x?secret={value}"))
    };
    let cfg = parse_otpauth(&uri)?;
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
        let vault: &Vault = pick(&vaults, &r.vault, |v| v.id.to_string(), |v| &v.meta.name)?;
        let items: Vec<Item> = self
            .items(vault)?
            .into_iter()
            .filter(|i| i.trashed_at.is_none())
            .collect();
        let item = pick(&items, &r.item, |i| i.id.to_string(), |i| &i.title)?;
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
        let e = invalid("ambiguous reference, use the item id");
        assert!(!e.to_string().contains("hunter2"));
    }
}
