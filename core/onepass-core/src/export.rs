//! Plain and archive export of vault items (milestone 5).

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use zeroize::Zeroizing;

use crate::archive::ArchivedVault;
use crate::model::field::FieldValue;
use crate::model::item::Item;
use crate::model::templates::ItemType;
use crate::{Error, Result};

const HEADER: [&str; 10] = [
    "title", "type", "vault", "url", "username", "password", "otpauth", "notes", "tags", "extra",
];

/// Kebab-case name of an item type, as written in the `type` column.
pub fn type_name(t: ItemType) -> &'static str {
    match t {
        ItemType::Login => "login",
        ItemType::SecureNote => "secure-note",
        ItemType::Password => "password",
        ItemType::Email => "email",
        ItemType::Server => "server",
        ItemType::Database => "database",
        ItemType::Router => "router",
        ItemType::ApiCredential => "api-credential",
        ItemType::SshKey => "ssh-key",
        ItemType::CreditCard => "credit-card",
        ItemType::BankAccount => "bank-account",
        ItemType::CryptoWallet => "crypto-wallet",
        ItemType::Subscription => "subscription",
        ItemType::Identity => "identity",
        ItemType::IdCard => "id-card",
        ItemType::Passport => "passport",
        ItemType::DriverLicense => "driver-license",
        ItemType::SocialSecurityNumber => "social-security-number",
        ItemType::MedicalRecord => "medical-record",
        ItemType::Membership => "membership",
        ItemType::RewardProgram => "reward-program",
        ItemType::Insurance => "insurance",
        ItemType::Vehicle => "vehicle",
        ItemType::AccessCode => "access-code",
        ItemType::Document => "document",
        ItemType::SoftwareLicense => "software-license",
    }
}

/// WARNING: the returned bytes are PLAINTEXT, every password, one-time
/// secret, key and note of the given vaults in clear. Never write them
/// anywhere the user did not explicitly choose, and wipe them after use.
///
/// One row per item given (the caller filters trashed items), columns
/// `title,type,vault,url,username,password,otpauth,notes,tags,extra`.
/// `extra` lists the remaining non-empty fields as `id=value` lines.
/// Cells are written verbatim (no spreadsheet-formula escaping), so a value
/// starting with `=` round-trips unchanged.
///
/// Not a full backup: passkey private keys are left out (only
/// `passkey:<rp_id>` is written) and Location values are dropped. The
/// `csv` crate keeps internal buffers that are not wiped. The output reads
/// back with `import::Format::OnePassCsv`.
pub fn csv_plaintext(vaults: &[ArchivedVault]) -> Result<Zeroizing<Vec<u8>>> {
    const BAD: Error = Error::InvalidFormat("csv write");
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    {
        let mut w = csv::Writer::from_writer(&mut *buf);
        w.write_record(HEADER).map_err(|_| BAD)?;
        for v in vaults {
            for item in &v.items {
                let row = row_of(&v.meta.name, item);
                w.write_record(row.iter().map(|c| c.as_str()))
                    .map_err(|_| BAD)?;
            }
        }
        w.flush().map_err(|_| BAD)?;
    }
    Ok(buf)
}

/// Plain text of a value, `None` when empty or not exportable (files keep
/// their name, locations are dropped).
fn plain(v: &FieldValue) -> Option<Zeroizing<String>> {
    let s = match v {
        FieldValue::Text(s)
        | FieldValue::Url(s)
        | FieldValue::Email(s)
        | FieldValue::Phone(s)
        | FieldValue::Menu(s) => s.clone(),
        FieldValue::Concealed(s)
        | FieldValue::Password(s)
        | FieldValue::Otp(s)
        | FieldValue::Mnemonic(s) => s.to_string(),
        FieldValue::Date(d) => d.to_string(),
        FieldValue::MonthYear { year, month } => format!("{month:02}/{year:04}"),
        FieldValue::Number(n) => n.to_string(),
        FieldValue::Money {
            minor_units,
            currency,
        } => format!("{minor_units} {currency}"),
        FieldValue::Address(a) => [
            &a.line1,
            &a.line2,
            &a.city,
            &a.postal_code,
            &a.region,
            &a.country,
        ]
        .into_iter()
        .filter(|p| !p.is_empty())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", "),
        FieldValue::Barcode { value, .. } => value.clone(),
        FieldValue::ItemLink(id) => id.to_string(),
        FieldValue::Passkey(p) => format!("passkey:{}", p.rp_id),
        FieldValue::SshKey(k) => k.private_pem.to_string(),
        FieldValue::File(a) => a.name.clone(),
        FieldValue::Location(_) | FieldValue::Empty => return None,
    };
    (!s.is_empty()).then(|| Zeroizing::new(s))
}

/// Position of a field: section index, field index.
type Pos = (usize, usize);

fn fields(item: &Item) -> impl Iterator<Item = (Pos, &crate::model::field::Field)> {
    item.sections.iter().enumerate().flat_map(|(si, s)| {
        s.fields
            .iter()
            .enumerate()
            .map(move |(fi, f)| ((si, fi), f))
    })
}

fn row_of(vault: &str, item: &Item) -> Vec<Zeroizing<String>> {
    let z = |s: &str| Zeroizing::new(s.to_string());
    let url = item
        .urls
        .iter()
        .find(|u| u.primary)
        .or_else(|| item.urls.first());

    let mut used: Vec<Pos> = Vec::new();
    let mut take = |pred: &dyn Fn(&str, &FieldValue) -> bool| -> Option<Zeroizing<String>> {
        let (pos, v) = fields(item)
            .filter(|(pos, f)| !used.contains(pos) && pred(&f.id, &f.value))
            .find_map(|(pos, f)| plain(&f.value).map(|v| (pos, v)))?;
        used.push(pos);
        Some(v)
    };
    let username = ["username", "address", "ssid"]
        .iter()
        .find_map(|want| {
            take(&|id, v| id == *want && matches!(v, FieldValue::Text(_) | FieldValue::Email(_)))
        })
        .unwrap_or_default();
    let password = take(&|_, v| matches!(v, FieldValue::Password(_))).unwrap_or_default();
    let otp = take(&|_, v| matches!(v, FieldValue::Otp(_))).unwrap_or_default();

    let mut extra = Zeroizing::new(String::new());
    let mut line = |k: &str, v: &str| {
        if !extra.is_empty() {
            extra.push('\n');
        }
        extra.push_str(k);
        extra.push('=');
        extra.push_str(v);
    };
    for u in item.urls.iter().filter(|u| Some(*u) != url) {
        line("url", &u.url);
    }
    for (pos, f) in fields(item) {
        if used.contains(&pos) {
            continue;
        }
        if let Some(v) = plain(&f.value) {
            line(&f.id, &v);
        }
    }

    vec![
        z(&item.title),
        z(type_name(item.item_type)),
        z(vault),
        z(url.map_or("", |u| u.url.as_str())),
        username,
        password,
        otp,
        z(&item.notes),
        z(&item.tags.join(";")),
        extra,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::Id;
    use crate::import::limits::csv_records;
    use crate::model::field::{Address, FieldValue};
    use crate::model::item::{Item, ItemUrl, MatchRule};
    use crate::model::templates::new_item;
    use crate::vault::VaultMeta;

    fn meta(name: &str) -> VaultMeta {
        VaultMeta {
            name: name.into(),
            icon: String::new(),
            color: String::new(),
            travel_safe: false,
            mcp_access: false,
        }
    }

    fn set(it: &mut Item, id: &str, v: FieldValue) {
        if let Some(f) = it.field_mut(id) {
            f.value = v;
        }
    }

    fn login(title: &str, url: &str, user: &str, pw: &str) -> Item {
        let mut it = new_item(ItemType::Login, Id::new(), title);
        it.urls = vec![ItemUrl {
            label: String::new(),
            url: url.into(),
            rule: MatchRule::Domain,
            primary: true,
        }];
        set(&mut it, "username", FieldValue::Text(user.into()));
        set(
            &mut it,
            "password",
            FieldValue::Password(pw.to_string().into()),
        );
        it
    }

    fn vault(items: Vec<Item>) -> ArchivedVault {
        ArchivedVault {
            id: Id::new(),
            meta: meta("Perso"),
            items,
        }
    }

    fn read(v: &[ArchivedVault]) -> (Vec<String>, Vec<Vec<String>>) {
        let out = csv_plaintext(v).unwrap();
        csv_records(&out).unwrap()
    }

    #[test]
    fn csv_reads_back() {
        let items = vec![
            login("A", "https://a.example", "ua", "pa"),
            login("B, with \"quotes\"", "https://b.example", "ub", "pb\nline"),
            login("C", "https://c.example", "uc", "pc"),
        ];
        let (head, rows) = read(&[vault(items)]);
        assert_eq!(
            head,
            [
                "title", "type", "vault", "url", "username", "password", "otpauth", "notes",
                "tags", "extra"
            ]
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1][0], "B, with \"quotes\"");
        assert_eq!(rows[1][1], "login");
        assert_eq!(rows[1][2], "Perso");
        assert_eq!(rows[1][3], "https://b.example");
        assert_eq!(rows[1][4], "ub");
        assert_eq!(rows[1][5], "pb\nline");
        assert_eq!(rows[2][5], "pc");
    }

    #[test]
    fn csv_keeps_leading_equals() {
        let (_, rows) = read(&[vault(vec![login("A", "https://a.example", "u", "=1+2")])]);
        assert_eq!(rows[0][5], "=1+2");
    }

    #[test]
    fn csv_extra_lists_other_fields() {
        let mut it = login("A", "https://a.example", "u", "pw");
        it.tags = vec!["x".into(), "y".into()];
        it.notes = "note".into();
        set(&mut it, "email", FieldValue::Email("a@b.c".into()));
        set(
            &mut it,
            "totp",
            FieldValue::Otp("otpauth://totp/x?secret=ABC".to_string().into()),
        );
        set(
            &mut it,
            "pin",
            FieldValue::Concealed("1234".to_string().into()),
        );
        let mut card = new_item(ItemType::CreditCard, Id::new(), "Carte");
        set(
            &mut card,
            "number",
            FieldValue::Concealed("4111".to_string().into()),
        );
        set(
            &mut card,
            "expiry",
            FieldValue::MonthYear {
                year: 2030,
                month: 3,
            },
        );
        set(
            &mut card,
            "issued_on",
            FieldValue::Date(time::macros::date!(2024 - 01 - 31)),
        );
        let mut router = new_item(ItemType::Router, Id::new(), "Box");
        set(&mut router, "ssid", FieldValue::Text("home".into()));
        set(
            &mut router,
            "wifi_password",
            FieldValue::Password("wp".to_string().into()),
        );
        let (_, rows) = read(&[vault(vec![it, card, router])]);
        assert_eq!(rows[0][6], "otpauth://totp/x?secret=ABC");
        assert_eq!(rows[0][7], "note");
        assert_eq!(rows[0][8], "x;y");
        let extra = &rows[0][9];
        assert!(extra.contains("email=a@b.c"), "{extra}");
        assert!(extra.contains("pin=1234"), "{extra}");
        assert!(!extra.contains("password="), "{extra}");
        assert!(!extra.contains("username="), "{extra}");
        assert!(!extra.contains("totp="), "{extra}");
        assert!(!extra.contains("passkeys"), "{extra}");
        let cx = &rows[1][9];
        assert_eq!(rows[1][1], "credit-card");
        assert!(cx.contains("number=4111"), "{cx}");
        assert!(cx.contains("expiry=03/2030"), "{cx}");
        assert!(cx.contains("issued_on=2024-01-31"), "{cx}");
        assert_eq!(rows[2][1], "router");
        assert_eq!(rows[2][4], "home");
        assert_eq!(rows[2][5], "wp");
        assert!(!rows[2][9].contains("ssid="), "{}", rows[2][9]);
    }

    #[test]
    fn csv_extra_value_formats() {
        let mut it = new_item(ItemType::Identity, Id::new(), "I");
        it.sections[0].fields.push(crate::model::field::Field {
            id: "m".into(),
            label: "m".into(),
            kind: crate::model::field::FieldType::Money,
            value: FieldValue::Money {
                minor_units: 1250,
                currency: "EUR".into(),
            },
            required: false,
            repeatable: false,
            autofill: false,
        });
        it.sections[0].fields.push(crate::model::field::Field {
            id: "a".into(),
            label: "a".into(),
            kind: crate::model::field::FieldType::Address,
            value: FieldValue::Address(Address {
                line1: "1 rue".into(),
                line2: String::new(),
                city: "Paris".into(),
                postal_code: "75001".into(),
                region: String::new(),
                country: "FR".into(),
            }),
            required: false,
            repeatable: true,
            autofill: false,
        });
        let (_, rows) = read(&[vault(vec![it])]);
        assert_eq!(rows[0][1], "identity");
        assert!(rows[0][9].contains("m=1250 EUR"), "{}", rows[0][9]);
        assert!(
            rows[0][9].contains("a=1 rue, Paris, 75001, FR"),
            "{}",
            rows[0][9]
        );
    }

    #[test]
    fn type_names_are_kebab_and_unique() {
        let names: Vec<_> = ItemType::ALL.iter().map(|t| type_name(*t)).collect();
        assert_eq!(names.len(), 26);
        let mut u = names.clone();
        u.sort_unstable();
        u.dedup();
        assert_eq!(u.len(), 26);
        assert!(
            names
                .iter()
                .all(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
        assert!(names.contains(&"secure-note") && names.contains(&"social-security-number"));
    }
}
