use std::fmt;

use serde::{Deserialize, Serialize};
use time::{Date, OffsetDateTime};
use zeroize::Zeroizing;

use crate::id::Id;
use crate::model::item::Location;

/// Marker printed in place of any secret value in `Debug` output.
const MASK: &str = "**";

/// Kind of a field. Postcard encodes variants by index: new variants
/// must only ever be appended at the end, never inserted or reordered
/// (pinned by `model::wire_tests`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    Text,
    Concealed,
    Password,
    Url,
    Email,
    Phone,
    Date,
    MonthYear,
    Number,
    Money,
    Address,
    Menu,
    Otp,
    Passkey,
    SshKey,
    File,
    Location,
    Mnemonic,
    Barcode,
    ItemLink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BarcodeFormat {
    Qr,
    Code128,
    Pdf417,
    Aztec,
    Ean13,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub line1: String,
    pub line2: String,
    pub city: String,
    pub postal_code: String,
    pub region: String,
    pub country: String,
}

/// Reference to an encrypted attachment blob stored apart from the item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub id: Id,
    pub name: String,
    pub size: u64,
    pub mime: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub created_at: OffsetDateTime,
}

impl fmt::Debug for PasskeyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyCredential")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("user_handle", &self.user_handle)
            .field("credential_id", &self.credential_id)
            .field("private_key", &MASK)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SshKeyValue {
    pub private_pem: Zeroizing<String>,
    pub public_openssh: String,
    pub fingerprint_sha256: String,
}

impl fmt::Debug for SshKeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshKeyValue")
            .field("private_pem", &MASK)
            .field("public_openssh", &self.public_openssh)
            .field("fingerprint_sha256", &self.fingerprint_sha256)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub value: Zeroizing<String>,
    pub replaced_at: OffsetDateTime,
}

impl fmt::Debug for PasswordHistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHistoryEntry")
            .field("value", &MASK)
            .field("replaced_at", &self.replaced_at)
            .finish()
    }
}

/// Value of a field. Postcard encodes variants by index: new variants
/// must only ever be appended at the end, never inserted or reordered
/// (pinned by `model::wire_tests`).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldValue {
    Text(String),
    Concealed(Zeroizing<String>),
    Password(Zeroizing<String>),
    Url(String),
    Email(String),
    Phone(String),
    Date(Date),
    MonthYear {
        year: u16,
        month: u8,
    },
    Number(i64),
    Money {
        minor_units: i64,
        currency: String,
    },
    Address(Address),
    Menu(String),
    Otp(Zeroizing<String>),
    Passkey(PasskeyCredential),
    SshKey(SshKeyValue),
    File(AttachmentRef),
    Location(Location),
    Mnemonic(Zeroizing<String>),
    Barcode {
        value: String,
        format: BarcodeFormat,
    },
    ItemLink(Id),
    Empty,
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Text(v) => f.debug_tuple("Text").field(v).finish(),
            FieldValue::Concealed(_) => f.debug_tuple("Concealed").field(&MASK).finish(),
            FieldValue::Password(_) => f.debug_tuple("Password").field(&MASK).finish(),
            FieldValue::Url(v) => f.debug_tuple("Url").field(v).finish(),
            FieldValue::Email(v) => f.debug_tuple("Email").field(v).finish(),
            FieldValue::Phone(v) => f.debug_tuple("Phone").field(v).finish(),
            FieldValue::Date(v) => f.debug_tuple("Date").field(v).finish(),
            FieldValue::MonthYear { year, month } => f
                .debug_struct("MonthYear")
                .field("year", year)
                .field("month", month)
                .finish(),
            FieldValue::Number(v) => f.debug_tuple("Number").field(v).finish(),
            FieldValue::Money {
                minor_units,
                currency,
            } => f
                .debug_struct("Money")
                .field("minor_units", minor_units)
                .field("currency", currency)
                .finish(),
            FieldValue::Address(v) => f.debug_tuple("Address").field(v).finish(),
            FieldValue::Menu(v) => f.debug_tuple("Menu").field(v).finish(),
            FieldValue::Otp(_) => f.debug_tuple("Otp").field(&MASK).finish(),
            FieldValue::Passkey(v) => f.debug_tuple("Passkey").field(v).finish(),
            FieldValue::SshKey(v) => f.debug_tuple("SshKey").field(v).finish(),
            FieldValue::File(v) => f.debug_tuple("File").field(v).finish(),
            FieldValue::Location(v) => f.debug_tuple("Location").field(v).finish(),
            FieldValue::Mnemonic(_) => f.debug_tuple("Mnemonic").field(&MASK).finish(),
            FieldValue::Barcode { value, format } => f
                .debug_struct("Barcode")
                .field("value", value)
                .field("format", format)
                .finish(),
            FieldValue::ItemLink(v) => f.debug_tuple("ItemLink").field(v).finish(),
            FieldValue::Empty => f.write_str("Empty"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    /// Stable per template (for example `"username"`).
    pub id: String,
    /// Translatable display label.
    pub label: String,
    pub kind: FieldType,
    pub value: FieldValue,
    pub required: bool,
    pub repeatable: bool,
    pub autofill: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Section {
    pub id: String,
    pub label: String,
    pub fields: Vec<Field>,
}
