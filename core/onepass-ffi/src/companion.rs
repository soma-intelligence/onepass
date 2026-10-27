//! Companion surface: the watch key pair, the sealed watch payload, the
//! widget glance snapshot and the watch-side vault object. The decrypted
//! payload (TOTP seeds included) never leaves the Rust object.

use std::sync::Arc;

use onepass_core::Id;
use onepass_core::companion::{self, CompanionFieldKind, CompanionPayload};
use onepass_core::crypto::kem::{HybridKemPublic, HybridKemSecret};
use onepass_core::totp;
use time::OffsetDateTime;

use crate::convert::{id_hex, parse_id};
use crate::error::{OnePassError, invalid};
use crate::session::Session;
use crate::types::{FfiBarcodeFormat, FfiItemType, FfiTotpCode};

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCompanionKeyPair {
    pub secret: Vec<u8>,
    pub public: Vec<u8>,
}

impl std::fmt::Debug for FfiCompanionKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FfiCompanionKeyPair(**)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiGlanceItem {
    pub item_id: String,
    pub vault_id: String,
    pub item_type: FfiItemType,
    pub title: String,
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiGlanceCode {
    pub start: i64,
    pub code: String,
}

impl std::fmt::Debug for FfiGlanceCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiGlanceCode")
            .field("start", &self.start)
            .field("code", &"**")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiGlanceCodes {
    pub item_id: String,
    pub vault_id: String,
    pub title: String,
    pub period: u32,
    pub codes: Vec<FfiGlanceCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiGlanceSnapshot {
    pub generated_at: i64,
    pub valid_until: i64,
    pub favorites: Vec<FfiGlanceItem>,
    pub codes: Vec<FfiGlanceCodes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiCompanionFieldKind {
    Text,
    Concealed,
    Barcode { format: FfiBarcodeFormat },
}

#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCompanionField {
    pub label: String,
    pub value: String,
    pub kind: FfiCompanionFieldKind,
}

impl std::fmt::Debug for FfiCompanionField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiCompanionField")
            .field("label", &self.label)
            .field("value", &"**")
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCompanionEntry {
    pub item_id: String,
    pub vault_id: String,
    pub item_type: FfiItemType,
    pub title: String,
    pub subtitle: String,
    pub has_totp: bool,
    pub fields: Vec<FfiCompanionField>,
}

/// A fresh watch key pair (ML-KEM-1024 + X25519).
#[uniffi::export]
pub fn companion_generate_key() -> Result<FfiCompanionKeyPair, OnePassError> {
    let secret = HybridKemSecret::generate()?;
    Ok(FfiCompanionKeyPair {
        secret: secret.to_bytes().to_vec(),
        public: secret.public()?.to_bytes(),
    })
}

fn parse_ids(ids: &[String]) -> Result<Vec<Id>, OnePassError> {
    ids.iter().map(|s| parse_id(s)).collect()
}

fn time_of(unix: i64) -> Result<OffsetDateTime, OnePassError> {
    OffsetDateTime::from_unix_timestamp(unix).map_err(|_| invalid("time"))
}

#[uniffi::export]
impl Session {
    /// The watch payload sealed to `recipient_public`.
    pub fn companion_payload(
        &self,
        recipient_public: Vec<u8>,
        generation: u64,
        now_unix: i64,
        excluded_vault_ids: Vec<String>,
    ) -> Result<Vec<u8>, OnePassError> {
        let recipient = HybridKemPublic::from_bytes(&recipient_public)
            .map_err(|_| invalid("companion public key"))?;
        let excluded = parse_ids(&excluded_vault_ids)?;
        let now = time_of(now_unix)?;
        self.with(|repo| {
            let payload = companion::build_payload(repo, generation, now, &excluded)?;
            Ok(companion::seal_payload(&payload, &recipient)?)
        })
    }

    /// The widget snapshot: favorites and their TOTP codes over a window.
    pub fn glance_snapshot(
        &self,
        now_unix: i64,
        window_secs: u64,
        excluded_vault_ids: Vec<String>,
    ) -> Result<FfiGlanceSnapshot, OnePassError> {
        let excluded = parse_ids(&excluded_vault_ids)?;
        self.with(|repo| {
            let s = companion::glance_snapshot(repo, now_unix, window_secs, &excluded)?;
            Ok(FfiGlanceSnapshot {
                generated_at: s.generated_at,
                valid_until: s.valid_until,
                favorites: s
                    .favorites
                    .iter()
                    .map(|i| FfiGlanceItem {
                        item_id: id_hex(i.item_id),
                        vault_id: id_hex(i.vault_id),
                        item_type: i.item_type.into(),
                        title: i.title.clone(),
                    })
                    .collect(),
                codes: s
                    .codes
                    .iter()
                    .map(|c| FfiGlanceCodes {
                        item_id: id_hex(c.item_id),
                        vault_id: id_hex(c.vault_id),
                        title: c.title.clone(),
                        period: c.period,
                        codes: c
                            .codes
                            .iter()
                            .map(|(start, code)| FfiGlanceCode {
                                start: *start,
                                code: code.clone(),
                            })
                            .collect(),
                    })
                    .collect(),
            })
        })
    }
}

/// An opened watch payload. Holds the decrypted entries (seeds included)
/// inside Rust; Swift gets display fields and computed codes only.
#[derive(uniffi::Object)]
pub struct CompanionVault {
    payload: CompanionPayload,
}

#[uniffi::export]
impl CompanionVault {
    /// Open a sealed payload with the watch secret key.
    #[uniffi::constructor]
    pub fn open(secret: Vec<u8>, sealed: Vec<u8>) -> Result<Arc<Self>, OnePassError> {
        let secret =
            HybridKemSecret::from_bytes(&secret).map_err(|_| invalid("companion secret key"))?;
        let payload = companion::open_payload(&secret, &sealed)?;
        Ok(Arc::new(Self { payload }))
    }

    pub fn generation(&self) -> u64 {
        self.payload.generation
    }

    pub fn generated_at(&self) -> i64 {
        self.payload.generated_at
    }

    pub fn entries(&self) -> Vec<FfiCompanionEntry> {
        self.payload
            .entries
            .iter()
            .map(|e| FfiCompanionEntry {
                item_id: id_hex(e.item_id),
                vault_id: id_hex(e.vault_id),
                item_type: e.item_type.into(),
                title: e.title.clone(),
                subtitle: e.subtitle.clone(),
                has_totp: e.totp.is_some(),
                fields: e
                    .fields
                    .iter()
                    .map(|f| FfiCompanionField {
                        label: f.label.clone(),
                        value: f.value.to_string(),
                        kind: match f.kind {
                            CompanionFieldKind::Text => FfiCompanionFieldKind::Text,
                            CompanionFieldKind::Concealed => FfiCompanionFieldKind::Concealed,
                            CompanionFieldKind::Barcode(format) => FfiCompanionFieldKind::Barcode {
                                format: format.into(),
                            },
                        },
                    })
                    .collect(),
            })
            .collect()
    }

    /// The code of an item at `unix_seconds`; `None` for an unknown item or
    /// one without TOTP.
    pub fn totp(&self, item_id: String, unix_seconds: u64) -> Option<FfiTotpCode> {
        let id = parse_id(&item_id).ok()?;
        let cfg = self
            .payload
            .entries
            .iter()
            .find(|e| e.item_id == id)?
            .totp
            .as_ref()?
            .config();
        Some(FfiTotpCode {
            code: totp::code_at(&cfg, unix_seconds).ok()?,
            remaining: totp::seconds_remaining(&cfg, unix_seconds),
            period: cfg.period,
        })
    }
}
