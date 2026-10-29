//! Disclosure policy: which items the extension may see, what a summary
//! holds, and which values a fill gives (spec 7.2 to 7.4).
//!
//! A summary never holds a secret. A fill gives only fields marked for
//! autofill, and the current TOTP code, never the TOTP secret.

use onepass_core::Id;
use onepass_core::fill_plan::score::{Candidate, CandidateKind, MatchQuality as PlanQuality};
use onepass_core::model::usage::last_used_on;
use onepass_core::model::{Field, FieldValue, Item, ItemType, LoginMethod, MatchRule};
use onepass_core::reference::otp_field_of;
use onepass_core::totp::{code_at, parse_otpauth, seconds_remaining, totp_from_secret};
use zeroize::Zeroizing;

use crate::AppErrorCode;
use crate::api::{AddressOut, FillField, Method, Response, SecretString, Summary, SummaryKind};
use crate::origin::{MatchQuality, Origin, item_host, matches};
use crate::provider::{ProviderId, from_core, official_hosts};
use crate::service::VaultInfo;

/// Icon colors, picked by a hash of the title.
const ICON_COLORS: [&str; 8] = [
    "#5856D6", "#007AFF", "#34C759", "#FF9500", "#FF2D55", "#AF52DE", "#30B0C7", "#FF3B30",
];

/// May the extension see this item at all? Archived, trashed, hidden from
/// autofill and crypto wallet items never leave the host.
pub fn eligible(item: &Item) -> bool {
    !item.archived
        && item.trashed_at.is_none()
        && !item.hide_from_autofill
        && item.item_type != ItemType::CryptoWallet
}

/// The summary kind of an item type the extension handles.
pub fn summary_kind(t: ItemType) -> Option<SummaryKind> {
    match t {
        ItemType::Login => Some(SummaryKind::Login),
        ItemType::CreditCard => Some(SummaryKind::Card),
        ItemType::Identity => Some(SummaryKind::Identity),
        _ => None,
    }
}

/// Best match of any of the item URLs against the page.
pub fn item_match(item: &Item, page: &Origin) -> Option<MatchQuality> {
    let mut best = None;
    for u in &item.urls {
        match matches(&u.url, u.rule, page) {
            Some(MatchQuality::ExactHost) => return Some(MatchQuality::ExactHost),
            Some(MatchQuality::Domain) => best = Some(MatchQuality::Domain),
            None => {}
        }
    }
    best
}

/// The ranking envelope of an item for `fill_plan::score::order`. No usage
/// and no typed username yet: the score is the match quality alone.
pub fn to_candidate(item: &Item, q: PlanQuality) -> Candidate {
    Candidate {
        item_id: item.id,
        kind: match item.item_type {
            ItemType::CreditCard => CandidateKind::Card,
            ItemType::Identity => CandidateKind::Identity,
            _ => CandidateKind::Login,
        },
        quality: q,
        favorite: item.favorite,
        // Nanoseconds, so two saves in one second keep their order.
        updated_at: i64::try_from(item.updated_at.unix_timestamp_nanos()).unwrap_or(i64::MAX),
        title: item.title.clone(),
        username_hash: None,
        usage: None,
        has_totp: item.item_type == ItemType::Login && otp_field(item).is_some(),
    }
}

/// `SHA-256(salt || lowercase(trim(username)))`: what `plan_fill`
/// compares with the hash the extension made of a typed username.
pub fn username_hash(salt: &[u8; 32], username: &str) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ctx.update(salt);
    ctx.update(username.trim().to_lowercase().as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Candidates of one kind for `fill_plan::plan`, with their memory of
/// `site`: `last_on_site` for the one entry used last among them (a tie
/// to the higher count, then the lowest item id), `same_shape`
/// when the entry saw `shape` (the main form's roles). A login also
/// carries the salted hash of its identifier.
pub fn plan_candidates(
    items: &[(&Item, PlanQuality)],
    site: &str,
    shape: Option<[u8; 16]>,
    salt: &[u8; 32],
) -> Vec<Candidate> {
    let last = last_used_on(items.iter().map(|(i, _)| *i), site);
    items
        .iter()
        .map(|(i, q)| {
            let mut c = to_candidate(i, *q);
            if i.item_type == ItemType::Login {
                c.username_hash = login_identifier(i).map(|u| username_hash(salt, u));
            }
            c.usage = i.usage_signal(site, last, shape);
            c
        })
        .collect()
}

/// The plan quality of a bridge match (`None` is no match: `Other`).
pub fn plan_quality(q: Option<MatchQuality>) -> PlanQuality {
    match q {
        Some(MatchQuality::ExactHost) => PlanQuality::Exact,
        Some(MatchQuality::Domain) => PlanQuality::Domain,
        None => PlanQuality::Other,
    }
}

/// Is this a login of `p`: a URL whose host is an official host of `p`?
/// URLs with rule `Never` do not count.
pub fn is_provider_account(item: &Item, p: ProviderId) -> bool {
    item.item_type == ItemType::Login
        && item.urls.iter().any(|u| {
            u.rule != MatchRule::Never
                && item_host(&u.url).is_some_and(|h| official_hosts(p).contains(&h.as_str()))
        })
}

/// Does an item URL on an official host of `p` match the provider page
/// under its own rule (path for `ExactUrl`, explicit port)?
pub fn provider_url_matches(item: &Item, p: ProviderId, page: &Origin) -> bool {
    item.urls.iter().any(|u| {
        item_host(&u.url).is_some_and(|h| official_hosts(p).contains(&h.as_str()))
            && matches(&u.url, u.rule, page).is_some()
    })
}

fn text_of(f: &Field) -> Option<&str> {
    match &f.value {
        FieldValue::Text(s)
        | FieldValue::Email(s)
        | FieldValue::Phone(s)
        | FieldValue::Url(s)
        | FieldValue::Menu(s) => {
            let t = s.trim();
            (!t.is_empty()).then_some(t)
        }
        _ => None,
    }
}

/// Non secret text of a field, whatever its autofill flag (for display).
fn display_text<'a>(item: &'a Item, id: &str) -> Option<&'a str> {
    item.field(id).and_then(text_of)
}

/// Non secret text of a field marked for autofill.
fn fillable_text(item: &Item, id: &str) -> Option<String> {
    item.field(id)
        .filter(|f| f.autofill)
        .and_then(text_of)
        .map(str::to_owned)
}

/// The identifier of a login: its `username`, else its `email`.
pub fn login_identifier(item: &Item) -> Option<&str> {
    display_text(item, "username").or_else(|| display_text(item, "email"))
}

/// Stored password of a login, whatever its autofill flag. Never sent:
/// for comparisons only.
pub fn stored_password(item: &Item) -> Option<&Zeroizing<String>> {
    match item.field("password").map(|f| &f.value) {
        Some(FieldValue::Password(s)) => Some(s),
        _ => None,
    }
}

fn last_four(number: &str) -> String {
    let digits: Vec<char> = number.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < 4 {
        return String::new();
    }
    let tail: String = digits[digits.len() - 4..].iter().collect();
    format!("\u{2022}\u{2022}\u{2022}\u{2022} {tail}")
}

/// Subtitle of a summary: identifier, last four card digits, or name.
pub fn subtitle(item: &Item) -> String {
    match item.item_type {
        ItemType::Login => login_identifier(item).unwrap_or_default().to_owned(),
        ItemType::CreditCard => match item.field("number").map(|f| &f.value) {
            Some(FieldValue::Concealed(n)) => last_four(n),
            Some(FieldValue::Text(n)) => last_four(n),
            _ => String::new(),
        },
        ItemType::Identity => {
            let first = display_text(item, "first_name").unwrap_or_default();
            let last = display_text(item, "last_name").unwrap_or_default();
            format!("{first} {last}").trim().to_owned()
        }
        _ => String::new(),
    }
}

/// First alphanumeric character of the title, upper case; `?` if none.
pub fn icon_letter(title: &str) -> String {
    title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "?".to_owned())
}

/// One of eight colors, from a FNV-1a hash of the title.
pub fn icon_color(title: &str) -> &'static str {
    let mut h: u32 = 0x811c_9dc5;
    for b in title.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    ICON_COLORS[(h % 8) as usize]
}

/// A password the extension could fill: present and marked for autofill.
fn has_password(item: &Item) -> bool {
    item.field("password")
        .is_some_and(|f| f.autofill && matches!(&f.value, FieldValue::Password(p) if !p.is_empty()))
}

/// The filled OTP field of an item, if it is marked for autofill.
pub fn otp_field(item: &Item) -> Option<&Field> {
    otp_field_of(item).ok().filter(|f| f.autofill)
}

/// Current TOTP code and seconds remaining. `Ok(None)` when the item has
/// no OTP field marked for autofill; `internal` when its value does not
/// parse. An `otpauth://` URI is parsed as one, anything else as a bare
/// base32 secret (as the `core` resolves `totp`).
pub fn totp_now(
    item: &Item,
    now: u64,
) -> std::result::Result<Option<(SecretString, u32)>, AppErrorCode> {
    const OTPAUTH: &str = "otpauth://";
    let Some(field) = otp_field(item) else {
        return Ok(None);
    };
    let FieldValue::Otp(value) = &field.value else {
        return Ok(None);
    };
    let value = value.trim();
    let cfg = if value
        .get(..OTPAUTH.len())
        .is_some_and(|h| h.eq_ignore_ascii_case(OTPAUTH))
    {
        parse_otpauth(value)
    } else {
        totp_from_secret(value)
    }
    .map_err(|_| AppErrorCode::Internal)?;
    let code = Zeroizing::new(code_at(&cfg, now).map_err(|_| AppErrorCode::Internal)?);
    Ok(Some((SecretString(code), seconds_remaining(&cfg, now))))
}

/// A summary of an item for the extension. `account_email` gives the
/// identifier of the provider account item a sign-in method points to.
pub fn summarize(
    vault: &VaultInfo,
    item: &Item,
    quality: Option<MatchQuality>,
    account_email: &dyn Fn(Id) -> Option<String>,
) -> Summary {
    let methods = item
        .login_methods
        .iter()
        .filter_map(|m| match m {
            LoginMethod::Provider {
                provider,
                account,
                relay_email,
            } => Some(Method {
                provider: from_core(provider)?,
                account_email: account_email(*account)
                    .or_else(|| relay_email.clone())
                    .unwrap_or_default(),
            }),
            _ => None,
        })
        .collect();
    Summary {
        item_id: item.id.to_string(),
        vault_id: vault.id.to_string(),
        vault_name: vault.name.clone(),
        title: item.title.clone(),
        subtitle: subtitle(item),
        kind: summary_kind(item.item_type).unwrap_or(SummaryKind::Login),
        icon_letter: icon_letter(&item.title),
        icon_color: icon_color(&item.title).to_owned(),
        has_password: has_password(item),
        has_totp: otp_field(item).is_some(),
        methods,
        match_quality: quality,
    }
}

/// Values of a login fill: only the fields asked for, only those marked
/// for autofill, and the TOTP code of the moment (a TOTP that does not
/// parse is left out).
pub fn login_secrets(item: &Item, fields: &[FillField], now: u64) -> Response {
    let username = fields
        .contains(&FillField::Username)
        .then(|| fillable_text(item, "username").or_else(|| fillable_text(item, "email")))
        .flatten();
    let password = fields
        .contains(&FillField::Password)
        .then(|| {
            item.field("password")
                .filter(|f| f.autofill)
                .and_then(|f| match &f.value {
                    FieldValue::Password(s) if !s.is_empty() => Some(SecretString(s.clone())),
                    _ => None,
                })
        })
        .flatten();
    let totp = fields
        .contains(&FillField::Totp)
        .then(|| totp_now(item, now).ok().flatten().map(|(code, _)| code))
        .flatten();
    Response::Login {
        username,
        password,
        totp,
    }
}

fn fillable_secret(item: &Item, id: &str) -> Option<SecretString> {
    item.field(id)
        .filter(|f| f.autofill)
        .and_then(|f| match &f.value {
            FieldValue::Concealed(s) | FieldValue::Password(s) if !s.trim().is_empty() => {
                Some(SecretString(s.clone()))
            }
            FieldValue::Text(s) if !s.trim().is_empty() => {
                Some(SecretString(Zeroizing::new(s.clone())))
            }
            _ => None,
        })
}

/// Values of a card fill. Month `MM` and year `YYYY`, empty when unknown.
pub fn card_values(item: &Item) -> Response {
    let (exp_month, exp_year) = match item.field("expiry").filter(|f| f.autofill) {
        Some(Field {
            value: FieldValue::MonthYear { year, month },
            ..
        }) => (format!("{month:02}"), format!("{year:04}")),
        _ => (String::new(), String::new()),
    };
    Response::Card {
        cardholder: fillable_text(item, "cardholder").unwrap_or_default(),
        number: fillable_secret(item, "number").unwrap_or_default(),
        exp_month,
        exp_year,
        cvv: fillable_secret(item, "cvv"),
    }
}

/// Values of an identity fill.
pub fn identity_values(item: &Item) -> Response {
    let birthday = item
        .field("birth_date")
        .filter(|f| f.autofill)
        .and_then(|f| match &f.value {
            FieldValue::Date(d) => Some(format!(
                "{:04}-{:02}-{:02}",
                d.year(),
                u8::from(d.month()),
                d.day()
            )),
            _ => None,
        });
    let address = item
        .field("address")
        .filter(|f| f.autofill)
        .and_then(|f| match &f.value {
            FieldValue::Address(a) => Some(AddressOut {
                line1: a.line1.clone(),
                line2: a.line2.clone(),
                city: a.city.clone(),
                postal_code: a.postal_code.clone(),
                region: a.region.clone(),
                country: a.country.clone(),
            }),
            _ => None,
        });
    Response::Identity {
        given_name: fillable_text(item, "first_name"),
        family_name: fillable_text(item, "last_name"),
        email: fillable_text(item, "email"),
        tel: fillable_text(item, "mobile_phone")
            .or_else(|| fillable_text(item, "home_phone"))
            .or_else(|| fillable_text(item, "work_phone")),
        organization: fillable_text(item, "company"),
        birthday,
        address,
    }
}

/// Value of a password or concealed field marked for autofill, for
/// `reveal`. Any other field kind (OTP secret, mnemonic, keys) is
/// `not_allowed`; a missing field is `not_found`.
pub fn reveal_value(item: &Item, field: &str) -> std::result::Result<SecretString, AppErrorCode> {
    let f = item.field(field).ok_or(AppErrorCode::NotFound)?;
    if !f.autofill {
        return Err(AppErrorCode::NotAllowed);
    }
    match &f.value {
        FieldValue::Password(s) | FieldValue::Concealed(s) => Ok(SecretString(s.clone())),
        _ => Err(AppErrorCode::NotAllowed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_letter_skips_punctuation() {
        assert_eq!(icon_letter("  (atlas) Cloud"), "A");
        assert_eq!(icon_letter("élan"), "É");
        assert_eq!(icon_letter("--"), "?");
    }

    #[test]
    fn icon_color_is_stable_and_from_the_palette() {
        assert_eq!(icon_color("Atlas Cloud"), icon_color("Atlas Cloud"));
        assert!(ICON_COLORS.contains(&icon_color("x")));
    }

    #[test]
    fn last_four_digits_only() {
        assert_eq!(
            last_four("4242 4242 4242 4242"),
            "\u{2022}\u{2022}\u{2022}\u{2022} 4242"
        );
        assert_eq!(last_four("12"), "");
    }
}
