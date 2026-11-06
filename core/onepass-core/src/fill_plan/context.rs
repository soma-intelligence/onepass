//! What a page looks like to the planner: roles, refs and flags, never a value.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_FORMS: usize = 32;
pub const MAX_FIELDS: usize = 64;
pub const MAX_BUTTONS: usize = 32;
const MAX_REF_LEN: usize = 64;

/// Mirrors `FieldRole` in `extension/src/shared/messages.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRole {
    Username,
    Email,
    CurrentPassword,
    NewPassword,
    ConfirmPassword,
    Otp,
    CcName,
    CcNumber,
    CcExp,
    CcExpMonth,
    CcExpYear,
    CcCsc,
    GivenName,
    FamilyName,
    FullName,
    Tel,
    Organization,
    Bday,
    AddressLine1,
    AddressLine2,
    City,
    PostalCode,
    Region,
    Country,
    RememberMe,
    // Forms coverage (2026-11-06): appended, so no existing name moves.
    HonorificPrefix,
    AdditionalName,
    BirthName,
    Sex,
    BirthPlace,
    /// Detected so the address country stays out; never filled (R5).
    BirthCountry,
    Nationality,
    PassportNumber,
    PassportIssueDate,
    PassportExpiry,
    PassportIssuingCountry,
    LicenseNumber,
    LicenseIssueDate,
    LicenseExpiry,
    LicenseIssuingCountry,
    LoyaltyNumber,
    JobTitle,
    Department,
    VatNumber,
    CompanyId,
    Website,
    Unknown,
}

impl FieldRole {
    pub fn is_card(self) -> bool {
        matches!(
            self,
            Self::CcName
                | Self::CcNumber
                | Self::CcExp
                | Self::CcExpMonth
                | Self::CcExpYear
                | Self::CcCsc
        )
    }

    pub fn is_identifier(self) -> bool {
        matches!(self, Self::Username | Self::Email)
    }

    /// Name, contact, postal address, person (civility, birth,
    /// nationality) and company roles.
    pub fn is_identity_or_address(self) -> bool {
        matches!(
            self,
            Self::GivenName
                | Self::FamilyName
                | Self::FullName
                | Self::Tel
                | Self::Organization
                | Self::Bday
                | Self::AddressLine1
                | Self::AddressLine2
                | Self::City
                | Self::PostalCode
                | Self::Region
                | Self::Country
                | Self::HonorificPrefix
                | Self::AdditionalName
                | Self::BirthName
                | Self::Sex
                | Self::BirthPlace
                | Self::BirthCountry
                | Self::Nationality
                | Self::JobTitle
                | Self::Department
                | Self::VatNumber
                | Self::CompanyId
                | Self::Website
        )
    }

    /// Roles a passport, a driver license or a loyalty program fills:
    /// numbers, dates and issuing countries. Never wanted by a signup.
    pub fn is_document(self) -> bool {
        matches!(
            self,
            Self::PassportNumber
                | Self::PassportIssueDate
                | Self::PassportExpiry
                | Self::PassportIssuingCountry
                | Self::LicenseNumber
                | Self::LicenseIssueDate
                | Self::LicenseExpiry
                | Self::LicenseIssuingCountry
                | Self::LoyaltyNumber
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    Top,
    SameOriginChild,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Prefilled {
    Empty,
    Typed,
    Ours,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ButtonClass {
    Submit,
    Next,
    Pay,
    Create,
    Other,
    /// Creates a passkey ("Sign up with a passkey"), never a sign-in with one.
    Passkey,
}

/// The extension's `FormKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormKindHint {
    Login,
    Signup,
    ChangePassword,
    Otp,
    Card,
    Identity,
    Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct IntentHints {
    pub kind: Option<FormKindHint>,
    pub signup_words: bool,
    pub reset_words: bool,
    pub checkout_words: bool,
    pub ignore: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct FieldContext {
    pub field_ref: String,
    pub role: Option<FieldRole>,
    pub confidence: f32,
    pub visible: bool,
    pub prefilled: Prefilled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ButtonContext {
    pub button_ref: String,
    pub class: ButtonClass,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct FormContext {
    pub form_ref: String,
    pub intent_hints: IntentHints,
    pub step_index: Option<u8>,
    pub fields: Vec<FieldContext>,
    pub buttons: Vec<ButtonContext>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct PageContext {
    pub origin: String,
    pub top_origin: String,
    pub frame_kind: FrameKind,
    pub forms: Vec<FormContext>,
    /// Hash of a username the user typed on this page, never the text.
    pub typed_username_hash: Option<[u8; 32]>,
}

/// Why a page context was refused. Never carries data from the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    TooManyForms,
    TooManyFields,
    TooManyButtons,
    DuplicateRef,
    BadConfidence,
    BadRef,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::TooManyForms => "too many forms",
            Self::TooManyFields => "too many fields in a form",
            Self::TooManyButtons => "too many buttons in a form",
            Self::DuplicateRef => "duplicate form or field reference",
            Self::BadConfidence => "confidence is not a number between 0 and 1",
            Self::BadRef => "reference must be 1 to 64 bytes",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ContextError {}

fn check_ref(r: &str) -> Result<(), ContextError> {
    if r.is_empty() || r.len() > MAX_REF_LEN {
        return Err(ContextError::BadRef);
    }
    Ok(())
}

impl PageContext {
    /// Bounds, finite confidences, unique refs across the page.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.forms.len() > MAX_FORMS {
            return Err(ContextError::TooManyForms);
        }
        let mut form_refs: HashSet<&str> = HashSet::new();
        let mut field_refs: HashSet<&str> = HashSet::new();
        for form in &self.forms {
            check_ref(&form.form_ref)?;
            if !form_refs.insert(&form.form_ref) {
                return Err(ContextError::DuplicateRef);
            }
            if form.fields.len() > MAX_FIELDS {
                return Err(ContextError::TooManyFields);
            }
            if form.buttons.len() > MAX_BUTTONS {
                return Err(ContextError::TooManyButtons);
            }
            for field in &form.fields {
                check_ref(&field.field_ref)?;
                if !field.confidence.is_finite() || !(0.0..=1.0).contains(&field.confidence) {
                    return Err(ContextError::BadConfidence);
                }
                if !field_refs.insert(&field.field_ref) {
                    return Err(ContextError::DuplicateRef);
                }
            }
            for button in &form.buttons {
                check_ref(&button.button_ref)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn hints() -> IntentHints {
        IntentHints {
            kind: None,
            signup_words: false,
            reset_words: false,
            checkout_words: false,
            ignore: false,
        }
    }

    fn field(r: &str, role: FieldRole) -> FieldContext {
        FieldContext {
            field_ref: r.into(),
            role: Some(role),
            confidence: 0.9,
            visible: true,
            prefilled: Prefilled::Empty,
        }
    }

    fn form(r: &str, fields: Vec<FieldContext>) -> FormContext {
        FormContext {
            form_ref: r.into(),
            intent_hints: hints(),
            step_index: None,
            fields,
            buttons: vec![],
        }
    }

    fn page(forms: Vec<FormContext>) -> PageContext {
        PageContext {
            origin: "https://example.com".into(),
            top_origin: "https://example.com".into(),
            frame_kind: FrameKind::Top,
            forms,
            typed_username_hash: None,
        }
    }

    #[test]
    fn accepts_minimal_login_context() {
        let p = page(vec![form(
            "f1",
            vec![
                field("a", FieldRole::Username),
                field("b", FieldRole::CurrentPassword),
            ],
        )]);
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn rejects_33_forms() {
        let forms = (0..33).map(|i| form(&format!("f{i}"), vec![])).collect();
        assert_eq!(page(forms).validate(), Err(ContextError::TooManyForms));
    }

    #[test]
    fn rejects_65_fields() {
        let fields = (0..65)
            .map(|i| field(&format!("a{i}"), FieldRole::Username))
            .collect();
        let p = page(vec![form("f", fields)]);
        assert_eq!(p.validate(), Err(ContextError::TooManyFields));
    }

    #[test]
    fn rejects_33_buttons() {
        let mut f = form("f", vec![]);
        f.buttons = (0..33)
            .map(|i| ButtonContext {
                button_ref: format!("b{i}"),
                class: ButtonClass::Other,
            })
            .collect();
        assert_eq!(page(vec![f]).validate(), Err(ContextError::TooManyButtons));
    }

    #[test]
    fn rejects_duplicate_field_ref_across_forms() {
        let p = page(vec![
            form("f1", vec![field("a", FieldRole::Username)]),
            form("f2", vec![field("a", FieldRole::Email)]),
        ]);
        assert_eq!(p.validate(), Err(ContextError::DuplicateRef));
    }

    #[test]
    fn rejects_duplicate_field_ref_in_one_form() {
        let p = page(vec![form(
            "f",
            vec![
                field("a", FieldRole::Username),
                field("a", FieldRole::Email),
            ],
        )]);
        assert_eq!(p.validate(), Err(ContextError::DuplicateRef));
    }

    #[test]
    fn rejects_duplicate_form_ref() {
        let p = page(vec![form("f", vec![]), form("f", vec![])]);
        assert_eq!(p.validate(), Err(ContextError::DuplicateRef));
    }

    #[test]
    fn rejects_nan_confidence() {
        let mut f = field("a", FieldRole::Username);
        f.confidence = f32::NAN;
        assert_eq!(
            page(vec![form("f", vec![f])]).validate(),
            Err(ContextError::BadConfidence)
        );
    }

    #[test]
    fn rejects_confidence_above_one() {
        let mut f = field("a", FieldRole::Username);
        f.confidence = 1.5;
        assert_eq!(
            page(vec![form("f", vec![f])]).validate(),
            Err(ContextError::BadConfidence)
        );
    }

    #[test]
    fn rejects_empty_and_long_refs() {
        let p = page(vec![form("", vec![])]);
        assert_eq!(p.validate(), Err(ContextError::BadRef));
        let p = page(vec![form(
            "f",
            vec![field(&"x".repeat(65), FieldRole::Tel)],
        )]);
        assert_eq!(p.validate(), Err(ContextError::BadRef));
    }

    #[test]
    fn rejects_unknown_json_field() {
        let json = r#"{"button_ref":"b","class":"submit","extra":1}"#;
        assert!(serde_json::from_str::<ButtonContext>(json).is_err());
        let json = r#"{"origin":"https://a.b","top_origin":"https://a.b","frame_kind":"top",
            "forms":[],"typed_username_hash":null,"extra":1}"#;
        assert!(serde_json::from_str::<PageContext>(json).is_err());
    }

    /// The forms roles (spec 2026-11-06 section 10.1), in enum order.
    const FORMS_ROLES: [(&str, FieldRole); 21] = [
        ("honorific_prefix", FieldRole::HonorificPrefix),
        ("additional_name", FieldRole::AdditionalName),
        ("birth_name", FieldRole::BirthName),
        ("sex", FieldRole::Sex),
        ("birth_place", FieldRole::BirthPlace),
        ("birth_country", FieldRole::BirthCountry),
        ("nationality", FieldRole::Nationality),
        ("passport_number", FieldRole::PassportNumber),
        ("passport_issue_date", FieldRole::PassportIssueDate),
        ("passport_expiry", FieldRole::PassportExpiry),
        (
            "passport_issuing_country",
            FieldRole::PassportIssuingCountry,
        ),
        ("license_number", FieldRole::LicenseNumber),
        ("license_issue_date", FieldRole::LicenseIssueDate),
        ("license_expiry", FieldRole::LicenseExpiry),
        ("license_issuing_country", FieldRole::LicenseIssuingCountry),
        ("loyalty_number", FieldRole::LoyaltyNumber),
        ("job_title", FieldRole::JobTitle),
        ("department", FieldRole::Department),
        ("vat_number", FieldRole::VatNumber),
        ("company_id", FieldRole::CompanyId),
        ("website", FieldRole::Website),
    ];

    #[test]
    fn forms_roles_round_trip_by_snake_case_name() {
        for (name, role) in FORMS_ROLES {
            let r: FieldRole = serde_json::from_str(&format!("\"{name}\"")).unwrap();
            assert_eq!(r, role, "{name}");
            assert_eq!(serde_json::to_string(&role).unwrap(), format!("\"{name}\""));
        }
    }

    #[test]
    fn documents_and_person_roles_are_told_apart() {
        let documents = [
            FieldRole::PassportNumber,
            FieldRole::PassportIssueDate,
            FieldRole::PassportExpiry,
            FieldRole::PassportIssuingCountry,
            FieldRole::LicenseNumber,
            FieldRole::LicenseIssueDate,
            FieldRole::LicenseExpiry,
            FieldRole::LicenseIssuingCountry,
            FieldRole::LoyaltyNumber,
        ];
        for (name, role) in FORMS_ROLES {
            let doc = documents.contains(&role);
            assert_eq!(role.is_document(), doc, "{name}");
            assert_eq!(role.is_identity_or_address(), !doc, "{name}");
            assert!(!role.is_card() && !role.is_identifier(), "{name}");
        }
        for role in [
            FieldRole::GivenName,
            FieldRole::Tel,
            FieldRole::Country,
            FieldRole::Email,
            FieldRole::CcExp,
            FieldRole::Unknown,
        ] {
            assert!(!role.is_document(), "{role:?}");
        }
        assert!(!FieldRole::Email.is_identity_or_address());
    }

    #[test]
    fn shape_hash_of_existing_roles_is_unchanged() {
        use crate::model::usage::form_shape_hash;
        let roles = [
            FieldRole::Email,
            FieldRole::GivenName,
            FieldRole::FamilyName,
            FieldRole::Tel,
            FieldRole::Bday,
            FieldRole::AddressLine1,
            FieldRole::PostalCode,
            FieldRole::City,
            FieldRole::Country,
            FieldRole::CcNumber,
        ];
        let hex: String = form_shape_hash(&roles)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, "ee3cf992e4cd58dc8555e09314bc9c21");
    }

    #[test]
    fn roles_use_snake_case_names() {
        let r: FieldRole = serde_json::from_str("\"address_line1\"").unwrap();
        assert_eq!(r, FieldRole::AddressLine1);
        let r: FieldRole = serde_json::from_str("\"cc_exp_month\"").unwrap();
        assert_eq!(r, FieldRole::CcExpMonth);
    }
}
