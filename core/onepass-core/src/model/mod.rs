//! Plaintext data model of vault items. No cryptography lives here.

pub mod field;
pub mod item;
pub mod templates;

pub use field::{
    Address, AttachmentRef, BarcodeFormat, Field, FieldType, FieldValue, PasskeyCredential,
    PasswordHistoryEntry, Section, SshKeyValue,
};
pub use item::{Item, ItemUrl, Location, LoginMethod, MatchRule, Provider};
pub use templates::ItemType;
