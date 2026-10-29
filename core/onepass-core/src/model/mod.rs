//! Plaintext data model of vault items. No cryptography lives here.

pub mod checks;
pub mod events;
pub mod field;
pub mod item;
pub mod menus;
pub mod templates;
pub mod usage;
pub mod validate;

pub use events::{EventKind, ItemEvent, ItemTrailer};
pub use field::{
    Address, AttachmentRef, BarcodeFormat, Field, FieldType, FieldValue, PasskeyCredential,
    PasswordHistoryEntry, Section, SshKeyValue,
};
pub use item::{Item, ItemUrl, Location, LoginMethod, MatchRule, Provider};
pub use menus::menu_options;
pub use templates::{ItemType, new_item, template};
pub use usage::{Forgotten, SiteUsage, StepKind, UsageTrailer};
pub use validate::validate;

/// Golden encodings: postcard writes an enum variant as its index (a
/// varint, one byte below 128). Stored items depend on these numbers, so
/// a reordered or inserted variant must fail here.
#[cfg(test)]
mod wire_tests {
    use time::OffsetDateTime;
    use time::macros::date;
    use zeroize::Zeroizing;

    use super::*;
    use crate::Id;

    fn tag<T: serde::Serialize>(value: &T) -> u8 {
        postcard::to_allocvec(value).unwrap()[0]
    }

    fn check<T: serde::Serialize + std::fmt::Debug>(variants: &[T]) {
        for (i, v) in variants.iter().enumerate() {
            assert_eq!(usize::from(tag(v)), i, "{v:?}");
        }
    }

    #[test]
    fn field_type_indexes() {
        use FieldType::*;
        check(&[
            Text, Concealed, Password, Url, Email, Phone, Date, MonthYear, Number, Money, Address,
            Menu, Otp, Passkey, SshKey, File, Location, Mnemonic, Barcode, ItemLink,
        ]);
    }

    #[test]
    fn field_value_indexes() {
        let s = || Zeroizing::new(String::new());
        let at = OffsetDateTime::UNIX_EPOCH;
        let attachment = AttachmentRef {
            id: Id([0; 16]),
            name: String::new(),
            size: 0,
            mime: String::new(),
        };
        check(&[
            FieldValue::Text(String::new()),
            FieldValue::Concealed(s()),
            FieldValue::Password(s()),
            FieldValue::Url(String::new()),
            FieldValue::Email(String::new()),
            FieldValue::Phone(String::new()),
            FieldValue::Date(date!(2026 - 01 - 01)),
            FieldValue::MonthYear { year: 0, month: 0 },
            FieldValue::Number(0),
            FieldValue::Money {
                minor_units: 0,
                currency: String::new(),
            },
            FieldValue::Address(Address {
                line1: String::new(),
                line2: String::new(),
                city: String::new(),
                postal_code: String::new(),
                region: String::new(),
                country: String::new(),
            }),
            FieldValue::Menu(String::new()),
            FieldValue::Otp(s()),
            FieldValue::Passkey(PasskeyCredential {
                rp_id: String::new(),
                user_name: String::new(),
                user_handle: vec![],
                credential_id: vec![],
                private_key: Zeroizing::new(vec![]),
                created_at: at,
            }),
            FieldValue::SshKey(SshKeyValue {
                private_pem: s(),
                public_openssh: String::new(),
                fingerprint_sha256: String::new(),
            }),
            FieldValue::File(attachment),
            FieldValue::Location(Location {
                label: String::new(),
                address: None,
                lat: 0.0,
                lon: 0.0,
                radius_m: 0,
                suggest_nearby: false,
            }),
            FieldValue::Mnemonic(s()),
            FieldValue::Barcode {
                value: String::new(),
                format: BarcodeFormat::Qr,
            },
            FieldValue::ItemLink(Id([0; 16])),
            FieldValue::Empty,
        ]);
    }

    #[test]
    fn usage_indexes() {
        use crate::fill_plan::intent::Intent;
        check(&[
            StepKind::Fill,
            StepKind::Otp,
            StepKind::ProviderClick,
            StepKind::Account,
        ]);
        // Sealed inside `SiteUsage` since the usage trailer.
        use Intent::*;
        check(&[Login, Signup, Reset, Otp, Checkout, Address, Ignore]);
    }

    #[test]
    fn provider_indexes() {
        use Provider::*;
        check(&[
            Google,
            Apple,
            Microsoft,
            GitHub,
            Facebook,
            X,
            LinkedIn,
            Discord,
            Slack,
            Okta,
            EntraId,
            CustomOidc(String::new()),
            CustomSaml(String::new()),
        ]);
    }

    #[test]
    fn item_type_indexes() {
        use ItemType::*;
        check(&[
            Login,
            SecureNote,
            Password,
            Email,
            Server,
            Database,
            Router,
            ApiCredential,
            SshKey,
            CreditCard,
            BankAccount,
            CryptoWallet,
            Subscription,
            Identity,
            IdCard,
            Passport,
            DriverLicense,
            SocialSecurityNumber,
            MedicalRecord,
            Membership,
            RewardProgram,
            Insurance,
            Vehicle,
            AccessCode,
            Document,
            SoftwareLicense,
        ]);
        // `ALL` is in spec order, not wire order: same set, 26 variants.
        assert_eq!(ItemType::ALL.len(), 26);
    }
}
