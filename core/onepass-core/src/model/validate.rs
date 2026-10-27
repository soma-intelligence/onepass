use crate::error::{Error, Result, ValidationError};
use crate::model::checks::{bip39_valid, iban_valid, luhn_valid, national_id_valid};
use crate::model::field::{Field, FieldValue};
use crate::model::item::{Item, LoginMethod};
use crate::model::templates::ItemType;

fn invalid(field: &str, reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: field.to_owned(),
        reason,
    })
}

/// Text held by a text-like value, `None` for every other kind.
fn text_of(value: &FieldValue) -> Option<&str> {
    match value {
        FieldValue::Text(s) | FieldValue::Url(s) | FieldValue::Email(s) | FieldValue::Phone(s) => {
            Some(s)
        }
        FieldValue::Concealed(s)
        | FieldValue::Password(s)
        | FieldValue::Mnemonic(s)
        | FieldValue::Otp(s) => Some(s),
        _ => None,
    }
}

/// A value that counts as not filled in: empty, or text-like and blank.
fn is_missing(value: &FieldValue) -> bool {
    match value {
        FieldValue::Empty => true,
        other => text_of(other).is_some_and(|s| s.trim().is_empty()),
    }
}

/// A required field the item may leave blank anyway: the username of a
/// login that signs in through a provider (Google, GitHub...), which has no
/// username of its own.
fn requirement_waived(item: &Item, field: &Field) -> bool {
    item.item_type == ItemType::Login
        && field.id == "username"
        && item
            .login_methods
            .iter()
            .any(|m| matches!(m, LoginMethod::Provider { .. }))
}

/// Format check for the field, applied to non-blank text only. Returns the
/// error reason (static, never the value) when the format is wrong.
fn format_problem(item: &Item, field: &Field) -> Option<&'static str> {
    let text = text_of(&field.value)?.trim();
    if text.is_empty() {
        return None;
    }
    match (item.item_type, field.id.as_str()) {
        (ItemType::CreditCard, "number") if !luhn_valid(text) => Some("is not a valid card number"),
        (ItemType::BankAccount, "iban") if !iban_valid(text) => Some("is not a valid IBAN"),
        (ItemType::CryptoWallet, "recovery_phrase") if !bip39_valid(text) => {
            Some("is not a valid recovery phrase")
        }
        (ItemType::SocialSecurityNumber, "number") => {
            let country = item
                .sections
                .iter()
                .flat_map(|s| s.fields.iter())
                .find(|f| f.id == "country")
                .and_then(|f| text_of(&f.value))?;
            (national_id_valid(country, text) == Some(false))
                .then_some("is not a valid national number")
        }
        _ => None,
    }
}

/// Checks an item and returns the first problem found: an empty title, then
/// for each field in template order a missing required value (empty, or
/// blank text) and a wrong format (card number, IBAN, recovery phrase,
/// national number). The error names the field, never its content. A login
/// with a provider sign-in method may leave its username blank.
pub fn validate(item: &Item) -> Result<()> {
    if item.title.trim().is_empty() {
        return Err(invalid("title", "must not be empty"));
    }
    for field in item.sections.iter().flat_map(|s| s.fields.iter()) {
        if field.required && is_missing(&field.value) && !requirement_waived(item, field) {
            return Err(invalid(&field.id, "is required"));
        }
        if let Some(reason) = format_problem(item, field) {
            return Err(invalid(&field.id, reason));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ValidationError;
    use crate::id::Id;
    use crate::model::templates::{ItemType, new_item};
    use zeroize::Zeroizing;

    const ABOUT: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn tx(s: &str) -> FieldValue {
        FieldValue::Text(s.into())
    }

    fn cn(s: &str) -> FieldValue {
        FieldValue::Concealed(Zeroizing::new(s.into()))
    }

    fn card(number: FieldValue) -> Item {
        let mut item = new_item(ItemType::CreditCard, Id::new(), "Visa");
        item.field_mut("cardholder").unwrap().value = tx("Q CARON");
        item.field_mut("number").unwrap().value = number;
        item.field_mut("expiry").unwrap().value = FieldValue::MonthYear {
            year: 2030,
            month: 1,
        };
        item
    }

    fn wallet(phrase: &str) -> Item {
        let mut item = new_item(ItemType::CryptoWallet, Id::new(), "Ledger");
        item.field_mut("name").unwrap().value = tx("Ledger");
        item.field_mut("recovery_phrase").unwrap().value =
            FieldValue::Mnemonic(Zeroizing::new(phrase.into()));
        item
    }

    fn ssn(country: Option<&str>, number: &str) -> Item {
        let mut item = new_item(ItemType::SocialSecurityNumber, Id::new(), "SSN");
        item.field_mut("name").unwrap().value = tx("Q Caron");
        item.field_mut("number").unwrap().value = cn(number);
        if let Some(c) = country {
            item.field_mut("country").unwrap().value = tx(c);
        }
        item
    }

    fn failing_field(item: &Item) -> String {
        match validate(item) {
            Err(Error::Validation(ValidationError { field, .. })) => field,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn blank_required_text_counts_as_missing() {
        for blank in ["", "   ", " \t\n"] {
            let values = [
                tx(blank),
                cn(blank),
                FieldValue::Password(Zeroizing::new(blank.into())),
                FieldValue::Email(blank.into()),
                FieldValue::Url(blank.into()),
                FieldValue::Phone(blank.into()),
                FieldValue::Mnemonic(Zeroizing::new(blank.into())),
                FieldValue::Otp(Zeroizing::new(blank.into())),
            ];
            for v in values {
                let mut item = new_item(ItemType::CreditCard, Id::new(), "Visa");
                item.field_mut("cardholder").unwrap().value = v;
                assert_eq!(failing_field(&item), "cardholder");
                match validate(&item) {
                    Err(Error::Validation(e)) => assert_eq!(e.reason, "is required"),
                    other => panic!("{other:?}"),
                }
            }
        }
    }

    #[test]
    fn card_number_must_pass_luhn() {
        validate(&card(cn("4111111111111111"))).unwrap();
        validate(&card(cn("4111 1111 1111 1111"))).unwrap();
        assert_eq!(failing_field(&card(cn("4111111111111112"))), "number");
        assert_eq!(failing_field(&card(cn("   "))), "number");
    }

    #[test]
    fn iban_is_checked_only_when_present() {
        let mut item = new_item(ItemType::BankAccount, Id::new(), "BNP");
        item.field_mut("bank").unwrap().value = tx("BNP");
        item.field_mut("holder").unwrap().value = tx("Q Caron");
        validate(&item).unwrap();
        item.field_mut("iban").unwrap().value = tx("  ");
        validate(&item).unwrap();
        item.field_mut("iban").unwrap().value = tx("FR76 3000 6000 0112 3456 7890 189");
        validate(&item).unwrap();
        item.field_mut("iban").unwrap().value = tx("FR76 3000 6000 0112 3456 7890 188");
        assert_eq!(failing_field(&item), "iban");
    }

    #[test]
    fn recovery_phrase_must_be_valid_bip39() {
        validate(&wallet(ABOUT)).unwrap();
        let bad = ABOUT.replace("about", "abandon");
        assert_eq!(failing_field(&wallet(&bad)), "recovery_phrase");
        assert_eq!(failing_field(&wallet("not a phrase")), "recovery_phrase");
    }

    #[test]
    fn national_id_is_checked_for_supported_countries_only() {
        validate(&ssn(Some("US"), "078-05-1120")).unwrap();
        assert_eq!(failing_field(&ssn(Some("US"), "666-12-3456")), "number");
        validate(&ssn(Some("fr"), "2 55 08 14 168 025 38")).unwrap();
        assert_eq!(
            failing_field(&ssn(Some("FR"), "2 55 08 14 168 025 39")),
            "number"
        );
        validate(&ssn(Some("GB"), "AB123456C")).unwrap();
        assert_eq!(failing_field(&ssn(Some("GB"), "QQ123456C")), "number");
        validate(&ssn(Some("CA"), "046 454 286")).unwrap();
        assert_eq!(failing_field(&ssn(Some("CA"), "046 454 287")), "number");
        // Unsupported or missing country: no format check.
        validate(&ssn(Some("JP"), "whatever")).unwrap();
        validate(&ssn(Some(" "), "whatever")).unwrap();
        validate(&ssn(None, "whatever")).unwrap();
    }

    #[test]
    fn format_errors_never_contain_the_value() {
        let secret = "4111111111111112";
        let err = validate(&card(cn(secret))).unwrap_err();
        assert!(!err.to_string().contains(secret));
        assert!(!format!("{err:?}").contains(secret));
        let phrase = ABOUT.replace("about", "abandon");
        let err = validate(&wallet(&phrase)).unwrap_err();
        assert!(!err.to_string().contains("abandon"));
        assert!(!format!("{err:?}").contains("abandon"));
    }

    fn provider_method() -> LoginMethod {
        LoginMethod::Provider {
            provider: crate::model::item::Provider::GitHub,
            account: Id::new(),
            relay_email: None,
        }
    }

    #[test]
    fn login_needs_a_username_without_a_provider() {
        let mut item = new_item(ItemType::Login, Id::new(), "Atlas");
        assert_eq!(failing_field(&item), "username");
        item.login_methods = vec![LoginMethod::Password, LoginMethod::Passkey];
        assert_eq!(failing_field(&item), "username");
        item.field_mut("username").unwrap().value = tx("  ");
        assert_eq!(failing_field(&item), "username");
    }

    #[test]
    fn login_with_a_provider_needs_no_username() {
        let mut item = new_item(ItemType::Login, Id::new(), "Atlas");
        item.login_methods = vec![LoginMethod::Password, provider_method()];
        validate(&item).unwrap();
        item.field_mut("username").unwrap().value = tx("   ");
        validate(&item).unwrap();
        // The title is still required.
        item.title = " ".into();
        assert_eq!(failing_field(&item), "title");
    }

    #[test]
    fn provider_waiver_applies_to_login_username_only() {
        // A card with a provider method (nonsense, but possible on the wire)
        // still needs its required fields.
        let mut item = new_item(ItemType::CreditCard, Id::new(), "Visa");
        item.login_methods = vec![provider_method()];
        assert_eq!(failing_field(&item), "cardholder");
    }

    #[test]
    fn checks_do_not_apply_to_other_item_types() {
        // IdCard also has a "number" field: no Luhn there.
        let mut item = new_item(ItemType::IdCard, Id::new(), "ID");
        item.field_mut("country").unwrap().value = tx("FR");
        item.field_mut("number").unwrap().value = cn("1234");
        item.field_mut("expiry").unwrap().value =
            FieldValue::Date(time::macros::date!(2032 - 05 - 01));
        validate(&item).unwrap();
    }
}
