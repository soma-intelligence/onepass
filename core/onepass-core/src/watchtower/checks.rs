//! Checks decided from the items alone (spec 3.2): reuse, strength, URLs,
//! Wi-Fi, SSH keys, expirations, password age, duplicates, wallets.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use data_encoding::BASE64;
use serde::{Serialize, Serializer};
use time::{Date, Month, UtcOffset};

use crate::id::Id;
use crate::model::{FieldValue, Item, ItemType};

use super::Options;
use super::host::{host_of, is_local_host, scheme_of};

/// A Watchtower check. The id ([`Check::id`]) is stable: reports and
/// `Item::watchtower_exclusions` use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    Compromised,
    Reused,
    Weak,
    ProviderExposed,
    BreachedSite,
    InsecureUrl,
    WifiInsecure,
    SshWeak,
    Expired,
    Expiring,
    #[serde(rename = "missing_2fa")]
    Missing2fa,
    PasskeyAvailable,
    OldPassword,
    Duplicate,
    WalletNoBackup,
}

impl Check {
    pub const ALL: [Check; 15] = [
        Check::Compromised,
        Check::Reused,
        Check::Weak,
        Check::ProviderExposed,
        Check::BreachedSite,
        Check::InsecureUrl,
        Check::WifiInsecure,
        Check::SshWeak,
        Check::Expired,
        Check::Expiring,
        Check::Missing2fa,
        Check::PasskeyAvailable,
        Check::OldPassword,
        Check::Duplicate,
        Check::WalletNoBackup,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Check::Compromised => "compromised",
            Check::Reused => "reused",
            Check::Weak => "weak",
            Check::ProviderExposed => "provider_exposed",
            Check::BreachedSite => "breached_site",
            Check::InsecureUrl => "insecure_url",
            Check::WifiInsecure => "wifi_insecure",
            Check::SshWeak => "ssh_weak",
            Check::Expired => "expired",
            Check::Expiring => "expiring",
            Check::Missing2fa => "missing_2fa",
            Check::PasskeyAvailable => "passkey_available",
            Check::OldPassword => "old_password",
            Check::Duplicate => "duplicate",
            Check::WalletNoBackup => "wallet_no_backup",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            Check::Compromised | Check::ProviderExposed => Severity::Critical,
            Check::Reused | Check::Weak | Check::BreachedSite | Check::Expired => Severity::High,
            Check::InsecureUrl | Check::WifiInsecure | Check::SshWeak | Check::Expiring => {
                Severity::Medium
            }
            Check::Missing2fa | Check::OldPassword | Check::WalletNoBackup => Severity::Low,
            Check::PasskeyAvailable | Check::Duplicate => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Penalty of one finding in the item health (spec 3.5).
    pub fn weight(self) -> f64 {
        match self {
            Severity::Critical => 1.0,
            Severity::High => 0.5,
            Severity::Medium => 0.25,
            Severity::Low => 0.1,
            Severity::Info => 0.0,
        }
    }

    /// [`Severity::weight`] in hundredths, for exact integer scoring.
    pub fn weight_hundredths(self) -> u32 {
        match self {
            Severity::Critical => 100,
            Severity::High => 50,
            Severity::Medium => 25,
            Severity::Low => 10,
            Severity::Info => 0,
        }
    }
}

/// Non-secret data of a finding.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Detail {
    None,
    /// Appearances in the breach corpus.
    Pwned {
        count: u64,
    },
    /// Reuse group, numbered from 1, and its number of member fields.
    Reused {
        group: u32,
        members: u32,
    },
    /// zxcvbn score, 0 to 4.
    Weak {
        score: u8,
    },
    Expiry {
        #[serde(serialize_with = "ser_date")]
        on: Date,
    },
    Breach {
        name: String,
        #[serde(serialize_with = "ser_date")]
        date: Date,
    },
    /// Items that sign in through this provider account.
    Dependents {
        #[serde(serialize_with = "ser_ids")]
        items: Vec<Id>,
    },
    KeyBits {
        algorithm: String,
        bits: u32,
    },
    /// Days since the password last changed.
    Age {
        days: u32,
    },
    /// The first item with the same host and username.
    Duplicate {
        #[serde(serialize_with = "ser_id")]
        other: Id,
    },
    /// Where the site documents its 2FA or passkey setup.
    Site {
        documentation: Option<String>,
    },
}

/// One problem found on one item (and field, when it concerns one).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    #[serde(serialize_with = "ser_id")]
    pub item_id: Id,
    #[serde(serialize_with = "ser_id")]
    pub vault_id: Id,
    pub check: Check,
    pub severity: Severity,
    pub field_id: Option<String>,
    pub detail: Detail,
}

/// Serializes an id as its hyphenated UUID text.
pub(crate) fn ser_id<S: Serializer>(id: &Id, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(id)
}

fn ser_ids<S: Serializer>(ids: &[Id], s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(ids.iter().map(Id::to_string))
}

/// Serializes a date as `YYYY-MM-DD`.
fn ser_date<S: Serializer>(d: &Date, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&format_args!(
        "{:04}-{:02}-{:02}",
        d.year(),
        u8::from(d.month()),
        d.day()
    ))
}

/// Expiration fields read after `Item::expires`, by type (spec 3.2).
const EXPIRY_FIELDS: [(ItemType, &str); 10] = [
    (ItemType::CreditCard, "expiry"),
    (ItemType::IdCard, "expiry"),
    (ItemType::Passport, "expiry"),
    (ItemType::DriverLicense, "expiry"),
    (ItemType::Membership, "expiry"),
    (ItemType::Document, "expiry"),
    (ItemType::ApiCredential, "expires_on"),
    (ItemType::Insurance, "renewal_date"),
    (ItemType::SoftwareLicense, "updates_until"),
    (ItemType::RewardProgram, "points_expiry"),
];

/// Router `security` values (lower-cased) that leave the network open.
const INSECURE_WIFI: [&str; 5] = ["wep", "ouvert", "open", "none", "aucune"];

/// Longer passwords are strong without running zxcvbn (spec ruling 15).
const MAX_ZXCVBN_CHARS: usize = 128;
/// zxcvbn scores below this are weak.
const MIN_STRONG_SCORE: u8 = 3;

const MIN_RSA_BITS: u32 = 3072;
/// DSA keys are fixed at 1024 bits in OpenSSH.
const DSA_BITS: u32 = 1024;
/// Bound on the base64 public key blob decoded for a size check.
const MAX_SSH_BLOB_B64: usize = 16 * 1024;

/// Findings of the checks that need no external source.
pub(crate) fn local_findings(items: &[&Item], opts: &Options) -> Vec<Finding> {
    let mut out = Vec::new();
    reused(items, &mut out);
    duplicates(items, &mut out);
    for item in items {
        weak(item, &mut out);
        insecure_urls(item, &mut out);
        wifi_insecure(item, &mut out);
        ssh_weak(item, &mut out);
        expirations(item, opts, &mut out);
        old_password(item, opts, &mut out);
        wallet_no_backup(item, &mut out);
    }
    out
}

pub(crate) fn excluded(item: &Item, check: Check) -> bool {
    item.watchtower_exclusions.iter().any(|e| e == check.id())
}

/// Records a finding unless the item excludes the check.
pub(crate) fn push(
    out: &mut Vec<Finding>,
    item: &Item,
    check: Check,
    field_id: Option<&str>,
    detail: Detail,
) {
    if excluded(item, check) {
        return;
    }
    out.push(Finding {
        item_id: item.id,
        vault_id: item.vault_id,
        check,
        severity: check.severity(),
        field_id: field_id.map(str::to_owned),
        detail,
    });
}

/// Non-empty `Password` fields of an item as (field id, value), in section
/// order. The values are borrowed: no copy of a password is made.
pub(crate) fn passwords(item: &Item) -> impl Iterator<Item = (&str, &str)> {
    item.sections
        .iter()
        .flat_map(|s| s.fields.iter())
        .filter_map(|f| match &f.value {
            FieldValue::Password(p) if !p.is_empty() => Some((f.id.as_str(), p.as_str())),
            _ => None,
        })
}

/// Plain text value of a template field.
fn text_of<'a>(item: &'a Item, id: &str) -> Option<&'a str> {
    match &item.field(id)?.value {
        FieldValue::Text(s) | FieldValue::Email(s) | FieldValue::Menu(s) | FieldValue::Url(s) => {
            Some(s.as_str())
        }
        _ => None,
    }
}

/// Host of the primary URL, or of the first URL when none is primary.
fn primary_host(item: &Item) -> Option<String> {
    item.urls
        .iter()
        .find(|u| u.primary)
        .or_else(|| item.urls.first())
        .and_then(|u| host_of(&u.url))
}

/// Same password in fields of at least two distinct items. Groups are
/// numbered from 1 by first appearance; each member field gets a finding.
fn reused(items: &[&Item], out: &mut Vec<Finding>) {
    let mut members: HashMap<&str, Vec<(usize, &str)>> = HashMap::new();
    let mut order: Vec<&str> = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        for (field_id, pw) in passwords(item) {
            members
                .entry(pw)
                .or_insert_with(|| {
                    order.push(pw);
                    Vec::new()
                })
                .push((idx, field_id));
        }
    }
    let mut group = 0u32;
    for pw in order {
        let Some(fields) = members.get(pw) else {
            continue;
        };
        let first = fields.first().map(|m| m.0);
        if fields.iter().all(|m| Some(m.0) == first) {
            continue;
        }
        group = group.saturating_add(1);
        let count = u32::try_from(fields.len()).unwrap_or(u32::MAX);
        for &(idx, field_id) in fields {
            if let Some(item) = items.get(idx) {
                let detail = Detail::Reused {
                    group,
                    members: count,
                };
                push(out, item, Check::Reused, Some(field_id), detail);
            }
        }
    }
}

/// zxcvbn score below 3, with the title, username and host as user inputs.
fn weak(item: &Item, out: &mut Vec<Finding>) {
    if excluded(item, Check::Weak) {
        return;
    }
    let host = primary_host(item).unwrap_or_default();
    let inputs: Vec<&str> = [
        item.title.as_str(),
        text_of(item, "username").unwrap_or(""),
        host.as_str(),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect();
    for (field_id, pw) in passwords(item) {
        if pw.chars().count() > MAX_ZXCVBN_CHARS {
            continue;
        }
        let score = u8::from(zxcvbn::zxcvbn(pw, &inputs).score());
        if score < MIN_STRONG_SCORE {
            push(
                out,
                item,
                Check::Weak,
                Some(field_id),
                Detail::Weak { score },
            );
        }
    }
}

/// Plain `http` URLs to a non-local host.
fn insecure_urls(item: &Item, out: &mut Vec<Finding>) {
    for u in &item.urls {
        let is_http = scheme_of(&u.url).is_some_and(|s| s.eq_ignore_ascii_case("http"));
        if !is_http {
            continue;
        }
        if host_of(&u.url).is_some_and(|h| !is_local_host(&h)) {
            push(out, item, Check::InsecureUrl, None, Detail::None);
        }
    }
}

/// Router with WEP or no security.
fn wifi_insecure(item: &Item, out: &mut Vec<Finding>) {
    if item.item_type != ItemType::Router {
        return;
    }
    let Some(security) = text_of(item, "security") else {
        return;
    };
    let security = security.trim().to_lowercase();
    if INSECURE_WIFI.contains(&security.as_str()) {
        push(
            out,
            item,
            Check::WifiInsecure,
            Some("security"),
            Detail::None,
        );
    }
}

/// DSA keys, and RSA keys under 3072 bits.
fn ssh_weak(item: &Item, out: &mut Vec<Finding>) {
    for f in item.sections.iter().flat_map(|s| s.fields.iter()) {
        let FieldValue::SshKey(key) = &f.value else {
            continue;
        };
        if let Some((algorithm, bits)) = weak_key(&key.public_openssh) {
            let detail = Detail::KeyBits {
                algorithm: algorithm.to_owned(),
                bits,
            };
            push(out, item, Check::SshWeak, Some(&f.id), detail);
        }
    }
}

/// Algorithm and size of a weak OpenSSH public key line.
fn weak_key(public: &str) -> Option<(&'static str, u32)> {
    let mut parts = public.split_whitespace();
    match parts.next()? {
        "ssh-dss" => Some(("ssh-dss", DSA_BITS)),
        "ssh-rsa" => {
            let bits = rsa_bits(parts.next()?)?;
            (bits < MIN_RSA_BITS).then_some(("ssh-rsa", bits))
        }
        _ => None,
    }
}

/// Modulus size of an `ssh-rsa` blob: `string "ssh-rsa"`, `mpint e`,
/// `mpint n` (RFC 4253 6.6). `None` when the blob is malformed.
fn rsa_bits(b64: &str) -> Option<u32> {
    if b64.len() > MAX_SSH_BLOB_B64 {
        return None;
    }
    let blob = BASE64.decode(b64.as_bytes()).ok()?;
    let mut rest = blob.as_slice();
    if ssh_string(&mut rest)? != b"ssh-rsa" {
        return None;
    }
    let _exponent = ssh_string(&mut rest)?;
    let modulus = ssh_string(&mut rest)?;
    // Leading zero bytes (the mpint sign byte) carry no bits.
    let start = modulus.iter().position(|&b| b != 0)?;
    let modulus = modulus.get(start..)?;
    let top = *modulus.first()?;
    let bytes = u32::try_from(modulus.len()).ok()?;
    bytes
        .checked_sub(1)?
        .checked_mul(8)?
        .checked_add(8 - top.leading_zeros())
}

/// Reads one length-prefixed SSH wire string.
fn ssh_string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, tail) = rest.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    let (value, tail) = tail.split_at_checked(len)?;
    *rest = tail;
    Some(value)
}

/// `Item::expires`, then the expiration field of the type.
fn expirations(item: &Item, opts: &Options, out: &mut Vec<Finding>) {
    if let Some(on) = item.expires {
        expiry(item, opts, None, on, out);
    }
    for (t, id) in EXPIRY_FIELDS {
        if item.item_type != t {
            continue;
        }
        if let Some(on) = item.field(id).and_then(|f| date_of(&f.value)) {
            expiry(item, opts, Some(id), on, out);
        }
    }
}

/// A `Date`, or the last day of a `MonthYear`.
fn date_of(v: &FieldValue) -> Option<Date> {
    match v {
        FieldValue::Date(d) => Some(*d),
        FieldValue::MonthYear { year, month } => {
            let month = Month::try_from(*month).ok()?;
            let year = i32::from(*year);
            Date::from_calendar_date(year, month, month.length(year)).ok()
        }
        _ => None,
    }
}

fn expiry(item: &Item, opts: &Options, field_id: Option<&str>, on: Date, out: &mut Vec<Finding>) {
    let detail = Detail::Expiry { on };
    if on < opts.today {
        push(out, item, Check::Expired, field_id, detail);
    } else if (on - opts.today).whole_days() <= i64::from(opts.expiry_warning_days) {
        push(out, item, Check::Expiring, field_id, detail);
    }
}

/// UTC date of the last password change: the latest history entry, else
/// the creation date.
pub(crate) fn password_changed_on(item: &Item) -> Date {
    let changed_at = item
        .password_history
        .iter()
        .map(|h| h.replaced_at)
        .max()
        .unwrap_or(item.created_at);
    // Imported timestamps keep their source offset; near the edges of the
    // supported range the UTC conversion does not exist. Fall back to the
    // date in the stored offset rather than panicking.
    changed_at
        .checked_to_offset(UtcOffset::UTC)
        .unwrap_or(changed_at)
        .date()
}

/// Login or Password whose password last changed `old_password_days` ago or
/// more: the latest history entry, else the creation date.
fn old_password(item: &Item, opts: &Options, out: &mut Vec<Finding>) {
    if !matches!(item.item_type, ItemType::Login | ItemType::Password) {
        return;
    }
    let Some((field_id, _)) = passwords(item).next() else {
        return;
    };
    let changed = password_changed_on(item);
    let days = (opts.today - changed).whole_days();
    if days >= i64::from(opts.old_password_days) {
        let days = u32::try_from(days).unwrap_or(u32::MAX);
        push(
            out,
            item,
            Check::OldPassword,
            Some(field_id),
            Detail::Age { days },
        );
    }
}

/// Logins with the same primary host and username (case-insensitive): the
/// later ones point to the first.
fn duplicates(items: &[&Item], out: &mut Vec<Finding>) {
    let mut first: HashMap<(String, String), Id> = HashMap::new();
    for item in items {
        if item.item_type != ItemType::Login {
            continue;
        }
        let Some(host) = primary_host(item) else {
            continue;
        };
        let user = text_of(item, "username").unwrap_or("").trim();
        if user.is_empty() {
            continue;
        }
        match first.entry((host, user.to_lowercase())) {
            Entry::Occupied(e) => {
                let detail = Detail::Duplicate { other: *e.get() };
                push(out, item, Check::Duplicate, None, detail);
            }
            Entry::Vacant(e) => {
                e.insert(item.id);
            }
        }
    }
}

/// Crypto wallet without a physical backup location.
fn wallet_no_backup(item: &Item, out: &mut Vec<Finding>) {
    if item.item_type != ItemType::CryptoWallet {
        return;
    }
    if text_of(item, "backup_location").is_none_or(|s| s.trim().is_empty()) {
        push(
            out,
            item,
            Check::WalletNoBackup,
            Some("backup_location"),
            Detail::None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Field, FieldType, FieldValue, ItemType, ItemUrl, MatchRule, PasswordHistoryEntry, Section,
        SshKeyValue, new_item,
    };
    use crate::watchtower::{Report, Sources, analyze};
    use time::macros::{date, datetime};
    use zeroize::Zeroizing;

    const TODAY: Date = date!(2026 - 10 - 15);
    const STRONG: &str = "x7#Qm!vP2$wL9@zR4kT-hN6";

    fn vault() -> Id {
        Id([7; 16])
    }

    fn item(t: ItemType, title: &str) -> Item {
        let mut i = new_item(t, vault(), title);
        i.created_at = datetime!(2026-10-01 0:00 UTC);
        i.updated_at = i.created_at;
        i
    }

    fn set(i: &mut Item, id: &str, v: FieldValue) {
        i.field_mut(id).unwrap().value = v;
    }

    fn pw(s: &str) -> FieldValue {
        FieldValue::Password(Zeroizing::new(s.into()))
    }

    fn url(u: &str) -> ItemUrl {
        ItemUrl {
            label: String::new(),
            url: u.into(),
            rule: MatchRule::Domain,
            primary: true,
        }
    }

    fn login(title: &str, user: &str, password: &str, site: &str) -> Item {
        let mut i = item(ItemType::Login, title);
        set(&mut i, "username", FieldValue::Text(user.into()));
        set(&mut i, "password", pw(password));
        if !site.is_empty() {
            i.urls.push(url(site));
        }
        i
    }

    fn run(items: &[Item]) -> Report {
        analyze(items, &Options::new(TODAY), Sources::none())
    }

    fn of(r: &Report, c: Check) -> Vec<&Finding> {
        r.findings.iter().filter(|f| f.check == c).collect()
    }

    #[test]
    fn check_ids_match_serde_and_are_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for c in Check::ALL {
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.id()));
            assert!(seen.insert(c.id()));
        }
    }

    #[test]
    fn severities_match_spec() {
        use Severity::*;
        let expected = [
            Critical, High, High, Critical, High, Medium, Medium, Medium, High, Medium, Low, Info,
            Low, Info, Low,
        ];
        for (c, s) in Check::ALL.into_iter().zip(expected) {
            assert_eq!(c.severity(), s, "{}", c.id());
        }
        assert_eq!(
            [Critical, High, Medium, Low, Info].map(Severity::weight),
            [1.0, 0.5, 0.25, 0.1, 0.0]
        );
        for s in [Critical, High, Medium, Low, Info] {
            assert_eq!(f64::from(s.weight_hundredths()) / 100.0, s.weight());
        }
    }

    #[test]
    fn weak_and_strong() {
        let weak = login("Mail", "alice", "password", "https://example.com");
        let strong = login("Bank", "alice", STRONG, "https://example.org");
        let long = login("Long", "bob", &"a".repeat(129), "https://example.net");
        let empty = login("Empty", "carol", "", "https://example.net");
        let r = run(&[weak.clone(), strong, long, empty]);
        let w = of(&r, Check::Weak);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].item_id, weak.id);
        assert_eq!(w[0].field_id.as_deref(), Some("password"));
        assert_eq!(w[0].severity, Severity::High);
        assert!(matches!(w[0].detail, Detail::Weak { score } if score < 3));
    }

    #[test]
    fn user_inputs_weaken_a_password() {
        // Strong alone, weak once the title is a user input.
        let p = "Zorglubianmagnificent";
        let alone = login("Mail", "alice", p, "");
        let with_title = login("Zorglubianmagnificent", "alice", p, "");
        let r = run(&[alone]);
        assert!(of(&r, Check::Weak).is_empty());
        let r = run(&[with_title]);
        assert_eq!(of(&r, Check::Weak).len(), 1);
    }

    #[test]
    fn reuse_is_exact_match() {
        let a = login("A", "alice", "Pw-123456", "");
        let b = login("B", "alice", "Pw-123456 ", "");
        let r = run(&[a.clone(), b.clone()]);
        assert!(of(&r, Check::Reused).is_empty());

        let c = login("C", "carol", "Pw-123456", "");
        let d = login("D", "dave", "other-Pw-1", "");
        let e = login("E", "erin", "other-Pw-1", "");
        let r = run(&[a.clone(), b, c.clone(), d.clone(), e.clone()]);
        let reused = of(&r, Check::Reused);
        assert_eq!(reused.len(), 4);
        let group_of = |id: Id| {
            reused
                .iter()
                .find(|f| f.item_id == id)
                .map(|f| f.detail.clone())
                .unwrap()
        };
        let g1 = Detail::Reused {
            group: 1,
            members: 2,
        };
        let g2 = Detail::Reused {
            group: 2,
            members: 2,
        };
        assert_eq!(group_of(a.id), g1);
        assert_eq!(group_of(c.id), g1);
        assert_eq!(group_of(d.id), g2);
        assert_eq!(group_of(e.id), g2);
        assert!(
            reused
                .iter()
                .all(|f| f.field_id.as_deref() == Some("password"))
        );
    }

    #[test]
    fn reuse_within_one_item_ignored() {
        let mut a = login("A", "alice", "Same-pw-42", "");
        a.sections.push(Section {
            id: "extra".into(),
            label: "Extra".into(),
            fields: vec![Field {
                id: "old_pw".into(),
                label: "Old".into(),
                kind: FieldType::Password,
                value: pw("Same-pw-42"),
                required: false,
                repeatable: false,
                autofill: false,
            }],
        });
        let r = run(&[a.clone()]);
        assert!(of(&r, Check::Reused).is_empty());

        // Once another item shares it, each member field is reported.
        let b = login("B", "bob", "Same-pw-42", "");
        let r = run(&[a, b]);
        let reused = of(&r, Check::Reused);
        assert_eq!(reused.len(), 3);
        assert!(reused.iter().all(|f| f.detail
            == Detail::Reused {
                group: 1,
                members: 3
            }));
    }

    #[test]
    fn http_flagged_localhost_not() {
        let mut i = login("Site", "alice", STRONG, "");
        for u in [
            "http://example.com/login",
            "HTTP://EXAMPLE.ORG",
            "https://example.net",
            "example.com",
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://[::1]:3000",
            "http://nas.local",
            "http://app.localhost",
        ] {
            i.urls.push(url(u));
        }
        let r = run(&[i]);
        let f = of(&r, Check::InsecureUrl);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| f.field_id.is_none()));
        assert!(f.iter().all(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn wep_router_flagged() {
        let router = |sec: &str| {
            let mut i = item(ItemType::Router, sec);
            set(&mut i, "ssid", FieldValue::Text("home".into()));
            set(&mut i, "security", FieldValue::Menu(sec.into()));
            i
        };
        let flagged = ["WEP", "ouvert", "Open", "none", "Aucune"].map(router);
        let fine = ["WPA3", "WPA2", "WPA"].map(router);
        let r = run(&flagged);
        let f = of(&r, Check::WifiInsecure);
        assert_eq!(f.len(), 5);
        assert!(f.iter().all(|f| f.field_id.as_deref() == Some("security")));
        assert!(run(&fine).findings.is_empty());
    }

    fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn rsa_public(modulus_bytes: usize) -> String {
        let mut n = vec![0x5a; modulus_bytes];
        n[0] = 0x80;
        // mpint: a leading zero keeps a set high bit positive.
        n.insert(0, 0);
        let mut blob = Vec::new();
        ssh_string(&mut blob, b"ssh-rsa");
        ssh_string(&mut blob, &[0x01, 0x00, 0x01]);
        ssh_string(&mut blob, &n);
        format!("ssh-rsa {} test@example.com", BASE64.encode(&blob))
    }

    fn ssh_item(public: &str) -> Item {
        let mut i = item(ItemType::SshKey, "key");
        set(
            &mut i,
            "private_key",
            FieldValue::SshKey(SshKeyValue {
                private_pem: Zeroizing::new(String::new()),
                public_openssh: public.into(),
                fingerprint_sha256: String::new(),
            }),
        );
        i
    }

    #[test]
    fn rsa_2048_flagged_ed25519_not() {
        let rsa2048 = ssh_item(&rsa_public(256));
        let rsa3072 = ssh_item(&rsa_public(384));
        let ed = ssh_item(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x@example.com",
        );
        let dsa = ssh_item("ssh-dss AAAAB3NzaC1kc3M= x@example.com");
        let garbage = ssh_item("ssh-rsa !!!not-base64");
        let r = run(&[rsa2048.clone(), rsa3072, ed, dsa.clone(), garbage]);
        let f = of(&r, Check::SshWeak);
        assert_eq!(f.len(), 2);
        let detail = |id: Id| f.iter().find(|f| f.item_id == id).unwrap().detail.clone();
        assert_eq!(
            detail(rsa2048.id),
            Detail::KeyBits {
                algorithm: "ssh-rsa".into(),
                bits: 2048
            }
        );
        assert_eq!(
            detail(dsa.id),
            Detail::KeyBits {
                algorithm: "ssh-dss".into(),
                bits: 1024
            }
        );
        assert!(
            f.iter()
                .all(|f| f.field_id.as_deref() == Some("private_key"))
        );
    }

    fn card(month: u8) -> Item {
        let mut i = item(ItemType::CreditCard, "Visa");
        set(
            &mut i,
            "expiry",
            FieldValue::MonthYear { year: 2026, month },
        );
        i
    }

    #[test]
    fn card_valid_until_month_end() {
        let october = card(10);
        let september = card(9);
        let december = card(12);
        let invalid = card(13);
        let r = run(&[october.clone(), september.clone(), december, invalid]);
        let expiring = of(&r, Check::Expiring);
        let expired = of(&r, Check::Expired);
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].item_id, october.id);
        assert_eq!(
            expiring[0].detail,
            Detail::Expiry {
                on: date!(2026 - 10 - 31)
            }
        );
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].item_id, september.id);
        assert_eq!(expired[0].field_id.as_deref(), Some("expiry"));
        assert_eq!(expired[0].severity, Severity::High);
    }

    #[test]
    fn passport_expiring() {
        let passport = |d: Date| {
            let mut i = item(ItemType::Passport, "Passeport");
            set(&mut i, "expiry", FieldValue::Date(d));
            i
        };
        let soon = passport(date!(2026 - 11 - 14));
        let today = passport(TODAY);
        let later = passport(date!(2026 - 11 - 15));
        let mut note = item(ItemType::SecureNote, "note");
        note.expires = Some(date!(2026 - 10 - 14));
        let r = run(&[soon.clone(), today.clone(), later, note.clone()]);
        let expiring: Vec<Id> = of(&r, Check::Expiring).iter().map(|f| f.item_id).collect();
        assert_eq!(expiring.len(), 2);
        assert!(expiring.contains(&soon.id) && expiring.contains(&today.id));
        let expired = of(&r, Check::Expired);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].item_id, note.id);
        assert_eq!(expired[0].field_id, None);
    }

    #[test]
    fn subscription_renewal_is_not_an_expiration() {
        let mut i = item(ItemType::Subscription, "Stream");
        set(&mut i, "service", FieldValue::Text("Stream".into()));
        if let Some(f) = i.field_mut("next_renewal") {
            f.value = FieldValue::Date(date!(2026 - 01 - 01));
        }
        assert!(run(&[i]).findings.is_empty());
    }

    #[test]
    fn old_password_uses_history_then_creation() {
        let mut never_changed = login("A", "alice", STRONG, "");
        never_changed.created_at = datetime!(2025-10-15 9:00 UTC);
        let mut changed = login("B", "bob", "Zq8!vT3#mL6@pW1", "");
        changed.created_at = datetime!(2020-01-01 0:00 UTC);
        changed.password_history = vec![
            PasswordHistoryEntry {
                value: Zeroizing::new("first-old".into()),
                replaced_at: datetime!(2021-01-01 0:00 UTC),
            },
            PasswordHistoryEntry {
                value: Zeroizing::new("second-old".into()),
                replaced_at: datetime!(2026-06-01 0:00 UTC),
            },
        ];
        let mut card = card(12);
        card.created_at = datetime!(2020-01-01 0:00 UTC);
        let r = run(&[never_changed.clone(), changed, card]);
        let old = of(&r, Check::OldPassword);
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].item_id, never_changed.id);
        assert_eq!(old[0].detail, Detail::Age { days: 365 });
        assert_eq!(old[0].field_id.as_deref(), Some("password"));
    }

    #[test]
    fn extreme_offsets_do_not_panic() {
        use time::{Date as D, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};
        let at = |d: D, h: i8| {
            PrimitiveDateTime::new(d, Time::MIDNIGHT)
                .replace_hour(23)
                .unwrap()
                .assume_offset(UtcOffset::from_hms(h, 0, 0).unwrap())
        };
        // 9999-12-31T23:00-01:00 is 10000-01-01 in UTC: out of range.
        let late: OffsetDateTime = at(date!(9999 - 12 - 31), -1);
        // -9999-01-01T00:00+01:00 is -10000-12-31 in UTC.
        let early = PrimitiveDateTime::new(D::MIN, Time::MIDNIGHT)
            .assume_offset(UtcOffset::from_hms(1, 0, 0).unwrap());
        assert!(late.checked_to_offset(UtcOffset::UTC).is_none());
        assert!(early.checked_to_offset(UtcOffset::UTC).is_none());

        let mut future = login("A", "alice", STRONG, "");
        future.created_at = late;
        let mut history = login("B", "bob", "Zq8!vT3#mL6@pW1", "");
        history.password_history = vec![PasswordHistoryEntry {
            value: Zeroizing::new("old-one".into()),
            replaced_at: late,
        }];
        let mut ancient = login("C", "carol", "Hk2$rN7!xQ4@bV9", "");
        ancient.created_at = early;
        let mut far = item(ItemType::Passport, "P");
        set(&mut far, "expiry", FieldValue::Date(D::MAX));
        far.expires = Some(D::MIN);
        let mut card = item(ItemType::CreditCard, "Visa");
        set(
            &mut card,
            "expiry",
            FieldValue::MonthYear {
                year: u16::MAX,
                month: 12,
            },
        );
        let opts = Options {
            today: D::MAX,
            expiry_warning_days: u16::MAX,
            old_password_days: 0,
        };
        let items = [future, history, ancient.clone(), far, card];
        let r = analyze(&items, &opts, Sources::none());
        let old = of(&r, Check::OldPassword);
        assert!(old.iter().any(|f| f.item_id == ancient.id));
        let opts = Options::new(D::MIN);
        let _ = analyze(&items, &opts, Sources::none());
    }

    #[test]
    fn duplicate_login_same_host_and_username() {
        let first = login("A", "Alice", STRONG, "https://www.example.com/a");
        let second = login(
            "B",
            "alice",
            "Zq8!vT3#mL6@pW1",
            "https://WWW.example.com:443/b",
        );
        let other_user = login("C", "bob", "Hk2$rN7!xQ4@bV9", "https://www.example.com");
        let other_host = login("D", "alice", "Jm5#sD8!cR2@nL6", "https://example.org");
        let r = run(&[first.clone(), second.clone(), other_user, other_host]);
        let d = of(&r, Check::Duplicate);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].item_id, second.id);
        assert_eq!(d[0].detail, Detail::Duplicate { other: first.id });
        assert_eq!(d[0].severity, Severity::Info);
    }

    #[test]
    fn wallet_without_backup_flagged() {
        let mut empty = item(ItemType::CryptoWallet, "Cold");
        set(&mut empty, "name", FieldValue::Text("Cold".into()));
        let mut kept = empty.clone();
        kept.id = Id([9; 16]);
        set(
            &mut kept,
            "backup_location",
            FieldValue::Text("Coffre".into()),
        );
        let r = run(&[empty.clone(), kept]);
        let f = of(&r, Check::WalletNoBackup);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].item_id, empty.id);
        assert_eq!(f[0].field_id.as_deref(), Some("backup_location"));
    }

    #[test]
    fn excluded_check_skipped() {
        let mut i = login("Mail", "alice", "password", "http://example.com");
        i.watchtower_exclusions = vec!["weak".into()];
        let r = run(&[i]);
        assert!(of(&r, Check::Weak).is_empty());
        assert_eq!(of(&r, Check::InsecureUrl).len(), 1);
    }

    #[test]
    fn trashed_and_archived_ignored() {
        let mut trashed = login("A", "alice", "password", "http://example.com");
        trashed.trashed_at = Some(datetime!(2026-10-10 0:00 UTC));
        let mut archived = login("B", "bob", "password", "http://example.com");
        archived.archived = true;
        let r = run(&[trashed, archived.clone()]);
        assert!(r.findings.is_empty());
        assert!(r.vaults.is_empty());
        assert_eq!(r.score, 100);

        // An archived copy does not make a live password reused.
        let live = login("C", "carol", "Shared-Pw-77x", "");
        archived.id = Id([3; 16]);
        set(&mut archived, "password", pw("Shared-Pw-77x"));
        let r = run(&[live, archived]);
        assert!(of(&r, Check::Reused).is_empty());
    }

    #[test]
    fn report_counts_scores_and_sources() {
        let a = login("A", "alice", "password", "http://example.com");
        let b = login("B", "bob", STRONG, "https://example.org");
        let r = run(&[a.clone(), b]);
        assert_eq!(r.counts.get(&Check::Weak), Some(&1));
        assert_eq!(r.counts.get(&Check::InsecureUrl), Some(&1));
        assert_eq!(r.counts.values().sum::<u32>() as usize, r.findings.len());
        // a: weak (0.5) + insecure_url (0.25); b healthy.
        assert_eq!(r.score, 63);
        assert_eq!(r.vaults.len(), 1);
        assert_eq!(r.vaults[0].items, 2);
        assert_eq!(r.pwned, crate::watchtower::PwnedStatus::Disabled);
        assert!(!r.sites_checked && !r.breaches_checked);
        let mut sorted = r.findings.clone();
        sorted.sort_by(|x, y| {
            (x.vault_id, x.item_id, x.check, &x.field_id).cmp(&(
                y.vault_id,
                y.item_id,
                y.check,
                &y.field_id,
            ))
        });
        assert_eq!(sorted, r.findings);
    }

    #[test]
    fn empty_vault_scores_100() {
        let r = run(&[]);
        assert_eq!(r.score, 100);
        assert!(r.findings.is_empty() && r.vaults.is_empty() && r.counts.is_empty());
    }

    #[test]
    fn report_has_no_secret() {
        let secrets = ["qwerty123", "Pw-123456", "hunter2-old-secret"];
        let mut a = login("A", "alice", secrets[0], "http://example.com");
        a.password_history = vec![PasswordHistoryEntry {
            value: Zeroizing::new(secrets[2].into()),
            replaced_at: datetime!(2020-01-01 0:00 UTC),
        }];
        let b = login("B", "bob", secrets[1], "");
        let c = login("C", "carol", secrets[1], "");
        let r = run(&[a, b, c]);
        assert!(!r.findings.is_empty());
        let debug = format!("{r:?}");
        let json = serde_json::to_string(&r).unwrap();
        for s in secrets {
            assert!(!debug.contains(s), "{s} in Debug");
            assert!(!json.contains(s), "{s} in JSON");
        }
        assert!(json.contains("\"check\":\"weak\""));
        assert!(json.contains("\"kind\":\"reused\""));
    }
}
