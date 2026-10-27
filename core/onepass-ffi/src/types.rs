//! Records and enums of the UniFFI surface. Plain data, no behavior.

use std::sync::Arc;

use crate::session::Session;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiItemType {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiFieldType {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiMatchRule {
    Domain,
    ExactHost,
    ExactUrl,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiBarcodeFormat {
    Qr,
    Code128,
    Pdf417,
    Aztec,
    Ean13,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDate {
    pub year: i32,
    pub month: u8,
    pub day: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiUrl {
    pub label: String,
    pub url: String,
    pub rule: FfiMatchRule,
    pub primary: bool,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiLocation {
    pub label: String,
    pub address: Option<String>,
    pub lat: f64,
    pub lon: f64,
    pub radius_m: u32,
    pub suggest_nearby: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAddress {
    pub line1: String,
    pub line2: String,
    pub city: String,
    pub postal_code: String,
    pub region: String,
    pub country: String,
}

/// A passkey as the UI sees it: the private key and the user handle never
/// cross. `credential_id_hex` is the key used to find them again on save.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPasskey {
    pub rp_id: String,
    pub user_name: String,
    pub credential_id_hex: String,
    pub created_at: i64,
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSshKey {
    pub private_pem: String,
    pub public_openssh: String,
    pub fingerprint_sha256: String,
}

impl std::fmt::Debug for FfiSshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiSshKey")
            .field("private_pem", &"**")
            .field("public_openssh", &self.public_openssh)
            .field("fingerprint_sha256", &self.fingerprint_sha256)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAttachment {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub mime: String,
}

/// The 21 variants of the core `FieldValue`. Secret strings cross as plain
/// strings: they are decrypted for display and editing only.
#[derive(Clone, PartialEq, uniffi::Enum)]
pub enum FfiFieldValue {
    Text {
        value: String,
    },
    Concealed {
        value: String,
    },
    Password {
        value: String,
    },
    Url {
        value: String,
    },
    Email {
        value: String,
    },
    Phone {
        value: String,
    },
    Date {
        value: FfiDate,
    },
    MonthYear {
        year: u16,
        month: u8,
    },
    Number {
        value: i64,
    },
    Money {
        minor_units: i64,
        currency: String,
    },
    Address {
        value: FfiAddress,
    },
    Menu {
        value: String,
    },
    Otp {
        value: String,
    },
    Passkey {
        value: FfiPasskey,
    },
    SshKey {
        value: FfiSshKey,
    },
    File {
        value: FfiAttachment,
    },
    Location {
        value: FfiLocation,
    },
    Mnemonic {
        value: String,
    },
    Barcode {
        value: String,
        format: FfiBarcodeFormat,
    },
    ItemLink {
        item_id: String,
    },
    Empty,
}

impl std::fmt::Debug for FfiFieldValue {
    /// Never prints a secret value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Concealed { .. } => f.write_str("Concealed(**)"),
            Self::Password { .. } => f.write_str("Password(**)"),
            Self::Otp { .. } => f.write_str("Otp(**)"),
            Self::Mnemonic { .. } => f.write_str("Mnemonic(**)"),
            Self::SshKey { value } => write!(f, "SshKey({value:?})"),
            Self::Text { value } => write!(f, "Text({value:?})"),
            Self::Url { value } => write!(f, "Url({value:?})"),
            Self::Email { value } => write!(f, "Email({value:?})"),
            Self::Phone { value } => write!(f, "Phone({value:?})"),
            Self::Date { value } => write!(f, "Date({value:?})"),
            Self::MonthYear { year, month } => write!(f, "MonthYear({year}, {month})"),
            Self::Number { value } => write!(f, "Number({value})"),
            Self::Money {
                minor_units,
                currency,
            } => write!(f, "Money({minor_units}, {currency})"),
            Self::Address { value } => write!(f, "Address({value:?})"),
            Self::Menu { value } => write!(f, "Menu({value:?})"),
            Self::Passkey { value } => write!(f, "Passkey({value:?})"),
            Self::File { value } => write!(f, "File({value:?})"),
            Self::Location { value } => write!(f, "Location({value:?})"),
            Self::Barcode { value, format } => write!(f, "Barcode({value:?}, {format:?})"),
            Self::ItemLink { item_id } => write!(f, "ItemLink({item_id})"),
            Self::Empty => f.write_str("Empty"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiField {
    pub id: String,
    pub label: String,
    pub kind: FfiFieldType,
    pub value: FfiFieldValue,
    pub required: bool,
    pub repeatable: bool,
    pub autofill: bool,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiSection {
    pub id: String,
    pub label: String,
    pub fields: Vec<FfiField>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiLoginMethod {
    Password,
    Passkey,
    Provider {
        provider: String,
        account_item_id: String,
        relay_email: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiItem {
    pub id: String,
    pub vault_id: String,
    pub item_type: FfiItemType,
    pub title: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub color: Option<String>,
    pub notes: String,
    pub urls: Vec<FfiUrl>,
    pub apps: Vec<String>,
    pub locations: Vec<FfiLocation>,
    pub login_methods: Vec<FfiLoginMethod>,
    pub sections: Vec<FfiSection>,
    pub expires: Option<FfiDate>,
    pub rotate_every_days: Option<u16>,
    pub reprompt: bool,
    pub hide_from_autofill: bool,
    pub watchtower_exclusions: Vec<String>,
    pub on_watch: bool,
    pub archived: bool,
    pub trashed_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub password_history_count: u32,
    pub attachment_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVaultMeta {
    pub name: String,
    pub icon: String,
    pub color: String,
    pub travel_safe: bool,
    pub mcp_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVault {
    pub id: String,
    pub meta: FfiVaultMeta,
    pub item_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemSummary {
    pub id: String,
    pub vault_id: String,
    pub item_type: FfiItemType,
    pub title: String,
    pub subtitle: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub primary_url: Option<String>,
    pub archived: bool,
    pub trashed_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Provider of the first "sign in with" method, encoded like
    /// `FfiLoginMethod::Provider.provider` ("google", "github",
    /// "oidc:<domain>"...). `None` when the item has none.
    #[uniffi(default = None)]
    pub sign_in_provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiItemTypeInfo {
    pub item_type: FfiItemType,
    pub label: String,
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiTotpCode {
    pub code: String,
    pub remaining: u32,
    pub period: u32,
}

impl std::fmt::Debug for FfiTotpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiTotpCode")
            .field("code", &"**")
            .field("remaining", &self.remaining)
            .field("period", &self.period)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiHistoryEntry {
    pub value: String,
    pub replaced_at: i64,
}

impl std::fmt::Debug for FfiHistoryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiHistoryEntry")
            .field("value", &"**")
            .field("replaced_at", &self.replaced_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRecordChange {
    pub kind: u8,
    pub id: String,
    pub version: u64,
    pub data: Option<Vec<u8>>,
}

/// A remote deletion the store refused: record kind code (1 to 8), record id
/// (32 hex characters) and the time it was refused (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiIgnoredDeletion {
    pub kind: u8,
    pub id: String,
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiRemoteRecord {
    pub kind: u8,
    pub id: String,
    pub version: u64,
    pub data: Option<Vec<u8>>,
    pub server_meta: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiKdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

#[derive(uniffi::Record)]
pub struct FfiCreatedAccount {
    pub session: Arc<Session>,
    pub secret_key: String,
    pub account_id: String,
}

#[derive(uniffi::Record)]
pub struct FfiUnlocked {
    pub session: Arc<Session>,
    pub auk: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPasswordRecipe {
    Characters {
        length: u32,
        digits: bool,
        symbols: bool,
        avoid_ambiguous: bool,
    },
    Words {
        count: u32,
        separator: String,
        french: bool,
        capitalize: bool,
    },
    Pin {
        length: u32,
    },
}

/// What a store holds before any unlock (see `store_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiStoreState {
    /// No account: one may be created.
    Empty,
    /// An account is stored.
    Account,
    /// This device pinned an account whose records are gone: an integrity
    /// fault, never an empty store.
    PinnedButMissing,
}

impl From<onepass_core::sync::AccountState> for FfiStoreState {
    fn from(s: onepass_core::sync::AccountState) -> Self {
        use onepass_core::sync::AccountState;
        match s {
            AccountState::Empty => Self::Empty,
            AccountState::Present => Self::Account,
            AccountState::PinnedButMissing => Self::PinnedButMissing,
        }
    }
}

/// What an AutoFill identity offers the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum FfiAutofillKind {
    Password,
    OneTimeCode,
    Passkey,
}

/// One entry of the system credential identity store (see
/// `Session::autofill_identities`). Never a secret: the user handle is the
/// only passkey datum besides the credential id, and the system requires it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAutofillIdentity {
    pub kind: FfiAutofillKind,
    /// Host of the URL, or the relying party id of a passkey.
    pub service: String,
    pub user: String,
    /// `"<vault hex>:<item hex>"`.
    pub record_id: String,
    pub favorite: bool,
    /// Empty unless `kind` is `Passkey`.
    pub credential_id: Vec<u8>,
    /// Empty unless `kind` is `Passkey`.
    pub user_handle: Vec<u8>,
}

/// How well a Login matches the requested site, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, uniffi::Enum)]
pub enum FfiMatchQuality {
    ExactHost,
    Domain,
    Other,
}

/// A passkey of a candidate, without its user handle or key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPasskeyRef {
    pub rp_id: String,
    pub user_name: String,
    pub credential_id: Vec<u8>,
}

/// A Login offered for a site (see `Session::autofill_candidates`). No
/// secret value: only whether a password or a TOTP is there.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAutofillCandidate {
    pub vault_id: String,
    pub item_id: String,
    pub title: String,
    pub user: String,
    /// The URL that matched, or the first URL for `Other`.
    pub url: Option<String>,
    pub quality: FfiMatchQuality,
    pub has_password: bool,
    pub has_totp: bool,
    pub passkeys: Vec<FfiPasskeyRef>,
}

/// A passkey registration request from the system. `item_id` names the Login
/// to add it to; `None` creates a new Login in `vault_id`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPasskeyCreation {
    pub vault_id: String,
    pub item_id: Option<String>,
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub excluded_credential_ids: Vec<Vec<u8>>,
}

/// What the system needs to complete a passkey registration.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPasskeyRegistration {
    pub vault_id: String,
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// What the system needs to complete a passkey sign-in.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPasskeyAssertion {
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub credential_id: Vec<u8>,
}
