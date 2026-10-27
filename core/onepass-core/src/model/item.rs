use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};

use crate::id::Id;
use crate::model::events::ItemEvent;
use crate::model::field::{AttachmentRef, Field, FieldValue, PasswordHistoryEntry, Section};
use crate::model::templates::ItemType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchRule {
    Domain,
    ExactHost,
    ExactUrl,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemUrl {
    pub label: String,
    pub url: String,
    pub rule: MatchRule,
    pub primary: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub label: String,
    pub address: Option<String>,
    pub lat: f64,
    pub lon: f64,
    pub radius_m: u32,
    pub suggest_nearby: bool,
}

/// Identity provider of a login. Postcard encodes variants by index: new variants
/// must only ever be appended at the end, never inserted or reordered
/// (pinned by `model::wire_tests`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provider {
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
    CustomOidc(String),
    CustomSaml(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginMethod {
    Password,
    Passkey,
    Provider {
        provider: Provider,
        account: Id,
        relay_email: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: Id,
    pub vault_id: Id,
    pub item_type: ItemType,
    pub title: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub color: Option<String>,
    pub custom_icon: Option<AttachmentRef>,
    pub notes: String,
    pub urls: Vec<ItemUrl>,
    pub apps: Vec<String>,
    pub locations: Vec<Location>,
    pub login_methods: Vec<LoginMethod>,
    pub sections: Vec<Section>,
    pub attachments: Vec<AttachmentRef>,
    pub expires: Option<Date>,
    pub rotate_every_days: Option<u16>,
    pub reprompt: bool,
    pub hide_from_autofill: bool,
    pub watchtower_exclusions: Vec<String>,
    pub on_watch: bool,
    pub archived: bool,
    pub trashed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Timeline (see `model::events`). Not part of the serde form of the
    /// item: sealed as a trailer after it, so older records still decode.
    #[serde(skip)]
    pub events: Vec<ItemEvent>,
}

impl Item {
    /// First field with this id, searching sections in order.
    pub fn field(&self, id: &str) -> Option<&Field> {
        self.sections
            .iter()
            .flat_map(|s| s.fields.iter())
            .find(|f| f.id == id)
    }

    pub fn field_mut(&mut self, id: &str) -> Option<&mut Field> {
        self.sections
            .iter_mut()
            .flat_map(|s| s.fields.iter_mut())
            .find(|f| f.id == id)
    }

    /// Short line shown under the title: the username of a login, empty
    /// for other types.
    pub fn subtitle(&self) -> String {
        match self.item_type {
            ItemType::Login => match self.field("username").map(|f| &f.value) {
                Some(FieldValue::Text(v) | FieldValue::Email(v)) => v.clone(),
                _ => String::new(),
            },
            _ => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::field::{Field, FieldType, Section};
    use time::macros::{date, datetime};
    use zeroize::Zeroizing;

    fn field(id: &str, kind: FieldType, value: FieldValue) -> Field {
        Field {
            id: id.into(),
            label: id.into(),
            kind,
            value,
            required: false,
            repeatable: false,
            autofill: true,
        }
    }

    fn sample_login() -> Item {
        let place = Location {
            label: "Home".into(),
            address: Some("1 Main St".into()),
            lat: 37.44,
            lon: -122.14,
            radius_m: 200,
            suggest_nearby: true,
        };
        Item {
            id: Id::new(),
            vault_id: Id::new(),
            item_type: ItemType::Login,
            title: "GitHub".into(),
            tags: vec!["dev".into()],
            favorite: true,
            color: None,
            custom_icon: None,
            notes: String::new(),
            urls: vec![ItemUrl {
                label: "site".into(),
                url: "https://github.com".into(),
                rule: MatchRule::Domain,
                primary: true,
            }],
            apps: vec![],
            locations: vec![place.clone()],
            login_methods: vec![
                LoginMethod::Password,
                LoginMethod::Provider {
                    provider: Provider::GitHub,
                    account: Id::new(),
                    relay_email: None,
                },
            ],
            sections: vec![Section {
                id: "main".into(),
                label: "Main".into(),
                fields: vec![
                    field(
                        "username",
                        FieldType::Text,
                        FieldValue::Text("quentin@example.com".into()),
                    ),
                    field(
                        "password",
                        FieldType::Password,
                        FieldValue::Password(Zeroizing::new("hunter2".into())),
                    ),
                    field(
                        "otp",
                        FieldType::Otp,
                        FieldValue::Otp(Zeroizing::new("otpauth://totp/x?secret=ABC".into())),
                    ),
                    field("place", FieldType::Location, FieldValue::Location(place)),
                ],
            }],
            attachments: vec![],
            expires: Some(date!(2030 - 01 - 31)),
            rotate_every_days: Some(90),
            reprompt: false,
            hide_from_autofill: false,
            watchtower_exclusions: vec![],
            on_watch: false,
            archived: false,
            trashed_at: None,
            created_at: datetime!(2026-10-25 12:00 UTC),
            updated_at: datetime!(2026-10-25 12:00 UTC),
            password_history: vec![PasswordHistoryEntry {
                value: Zeroizing::new("old-secret".into()),
                replaced_at: datetime!(2026-10-01 08:00 UTC),
            }],
            events: vec![],
        }
    }

    #[test]
    fn item_roundtrips_through_postcard() {
        let item = sample_login();
        let bytes = postcard::to_allocvec(&item).unwrap();
        assert_eq!(postcard::from_bytes::<Item>(&bytes).unwrap(), item);
    }

    #[test]
    fn debug_masks_secret_values() {
        let s = format!("{:?}", sample_login());
        assert!(!s.contains("hunter2"));
        assert!(!s.contains("old-secret"));
        assert!(!s.contains("secret=ABC"));
        assert!(s.contains("**"));
    }

    #[test]
    fn debug_masks_every_remaining_secret_kind() {
        use crate::model::field::{PasskeyCredential, SshKeyValue};
        let mut item = sample_login();
        item.sections.push(Section {
            id: "secrets".into(),
            label: "Secrets".into(),
            fields: vec![
                field(
                    "concealed",
                    FieldType::Concealed,
                    FieldValue::Concealed(Zeroizing::new("concealed-plain-7f3a".into())),
                ),
                field(
                    "mnemonic",
                    FieldType::Mnemonic,
                    FieldValue::Mnemonic(Zeroizing::new("mnemonic-plain-9c1d".into())),
                ),
                field(
                    "passkey",
                    FieldType::Passkey,
                    FieldValue::Passkey(PasskeyCredential {
                        rp_id: "example.com".into(),
                        user_name: "quentin".into(),
                        user_handle: vec![1, 2, 3],
                        credential_id: vec![4, 5, 6],
                        private_key: Zeroizing::new(vec![231, 232, 233, 234, 235, 236]),
                        created_at: datetime!(2026-10-25 12:00 UTC),
                    }),
                ),
                field(
                    "ssh",
                    FieldType::SshKey,
                    FieldValue::SshKey(SshKeyValue {
                        private_pem: Zeroizing::new("pem-plain-b82e".into()),
                        public_openssh: "ssh-ed25519 AAAA".into(),
                        fingerprint_sha256: "SHA256:abc".into(),
                    }),
                ),
            ],
        });
        for s in [format!("{item:?}"), format!("{item:#?}")] {
            for plain in [
                "concealed-plain-7f3a",
                "mnemonic-plain-9c1d",
                "pem-plain-b82e",
            ] {
                assert!(!s.contains(plain), "leaked {plain}");
            }
            // Six consecutive values, whitespace removed so compact and
            // pretty forms share one needle that random id bytes cannot
            // realistically produce.
            let squeezed: String = s.split_whitespace().collect();
            assert!(
                !squeezed.contains("231,232,233,234,235,236"),
                "leaked passkey private key bytes"
            );
            assert!(s.contains("**"));
        }
    }

    #[test]
    fn subtitle_uses_username() {
        assert_eq!(sample_login().subtitle(), "quentin@example.com");
    }

    #[test]
    fn field_lookup_finds_and_mutates_by_id() {
        let mut item = sample_login();
        assert!(item.field("password").is_some());
        assert!(item.field("missing").is_none());
        item.field_mut("username").unwrap().value = FieldValue::Text("bob".into());
        assert_eq!(item.subtitle(), "bob");
    }
}
