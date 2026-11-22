//! Passport chip reading over the UniFFI surface (spec NFC documents, P1):
//! MRZ parsing, the ICAO session the NFC transport drives APDU by APDU, and
//! the chip read turned into a passport item or merged into one.
//!
//! The transport (Core NFC on iOS) is a dumb pipe: every protocol decision
//! stays in `onepass_core::scan`. Nothing here logs; `Debug` of every type
//! carrying identity data or a portrait is redacted.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use onepass_core::scan::icao::dg::{ImageFormat, Portrait};
use onepass_core::scan::icao::{
    AccessKey, ChipRead, ChipStatus, IcaoError, IcaoSession, MasterList, Step, load_master_list,
    load_master_list_pinned,
};
use onepass_core::scan::mrz::{Mrz, MrzError, parse_td3};
use onepass_core::scan::to_item::{chip_read_to_item, merge_chip_read};
use time::{Date, OffsetDateTime};

use crate::convert::{Kept, item_to_core, item_to_ffi, parse_id};
use crate::error::{OnePassError, invalid};
use crate::session::{Session, find_vault};
use crate::types::FfiItem;

/// A parsed TD3 MRZ: the printed values, filler `<` removed, and the two
/// lines after OCR correction. `Debug` shows nothing of it.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMrz {
    pub document_code: String,
    pub issuing_state: String,
    pub surname: String,
    pub given_names: String,
    pub document_number: String,
    pub nationality: String,
    /// YYMMDD.
    pub birth_date: String,
    /// One character: `F`, `M`, `X` or `<`.
    pub sex: String,
    /// YYMMDD.
    pub expiry_date: String,
    pub optional_data: String,
    /// The two lines.
    pub lines: Vec<String>,
}

impl fmt::Debug for FfiMrz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FfiMrz(..)")
    }
}

fn mrz_to_ffi(m: &Mrz) -> FfiMrz {
    FfiMrz {
        document_code: m.document_code.clone(),
        issuing_state: m.issuing_state.clone(),
        surname: m.surname.clone(),
        given_names: m.given_names.clone(),
        document_number: m.document_number.clone(),
        nationality: m.nationality.clone(),
        birth_date: m.birth_date.clone(),
        sex: m.sex.to_string(),
        expiry_date: m.expiry_date.clone(),
        optional_data: m.optional_data.clone(),
        lines: m.raw.split('\n').map(str::to_owned).collect(),
    }
}

fn mrz_error(e: MrzError) -> OnePassError {
    OnePassError::Validation {
        field: "mrz".into(),
        reason: e.to_string(),
    }
}

fn parse_lines(lines: &[String]) -> Result<Mrz, OnePassError> {
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    parse_td3(&refs).map_err(mrz_error)
}

/// Parses the two lines of a TD3 (passport) MRZ, check digits verified.
#[uniffi::export]
pub fn mrz_parse(lines: Vec<String>) -> Result<FfiMrz, OnePassError> {
    Ok(mrz_to_ffi(&parse_lines(&lines)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiImageFormat {
    Jpeg,
    Jpeg2000,
}

/// Outcome of passive authentication (`onepass_core::scan::icao::ChipStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiChipStatus {
    /// Hashes, document signer and chain to a listed CSCA all check out.
    Verified,
    /// Nothing wrong, but the chain cannot be checked (no CSCA, expired
    /// certificate, unsupported algorithm).
    Unverifiable,
    /// A hash or a signature is wrong.
    Invalid,
}

/// Why a read stopped. `LostContact` is the transport's (Core NFC), never
/// the session's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiIcaoFailure {
    /// The chip refused the keys from the MRZ (or a secure messaging MAC
    /// failed).
    AccessDenied,
    LostContact,
    NoChip,
    /// The chip offers nothing this reader speaks.
    Unsupported,
    Other,
}

/// What the chip gave: the MRZ from DG1 (equal to the scanned one), the DG2
/// portrait as stored on the chip, and the passive authentication outcome.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiChipRead {
    pub mrz: FfiMrz,
    pub portrait: Option<Vec<u8>>,
    pub portrait_format: Option<FfiImageFormat>,
    pub status: FfiChipStatus,
}

impl fmt::Debug for FfiChipRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiChipRead")
            .field("portrait_bytes", &self.portrait.as_ref().map(Vec::len))
            .field("portrait_format", &self.portrait_format)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// The read for the app. The portrait bytes move out of the core read (no
/// copy left behind in Rust); the app gets them as `Data`.
fn read_to_ffi(r: &mut ChipRead) -> FfiChipRead {
    FfiChipRead {
        mrz: mrz_to_ffi(&r.mrz),
        portrait: r.portrait.as_mut().map(|p| std::mem::take(&mut p.bytes)),
        portrait_format: r.portrait.as_ref().map(|p| match p.format {
            ImageFormat::Jpeg => FfiImageFormat::Jpeg,
            ImageFormat::Jpeg2000 => FfiImageFormat::Jpeg2000,
        }),
        status: match r.status {
            ChipStatus::Verified => FfiChipStatus::Verified,
            ChipStatus::Unverifiable => FfiChipStatus::Unverifiable,
            ChipStatus::Invalid => FfiChipStatus::Invalid,
        },
    }
}

/// Back to the core read. The MRZ is parsed again from its lines (the other
/// `FfiMrz` fields are ignored), so a read the app altered cannot carry a
/// MRZ that fails its check digits. The portrait bytes move into the core
/// `Portrait` (wiped when dropped), not copied: `r` is left without them.
fn read_to_core(r: &mut FfiChipRead) -> Result<ChipRead, OnePassError> {
    let portrait = match (&mut r.portrait, r.portrait_format) {
        (Some(bytes), Some(format)) => Some(Portrait {
            format: match format {
                FfiImageFormat::Jpeg => ImageFormat::Jpeg,
                FfiImageFormat::Jpeg2000 => ImageFormat::Jpeg2000,
            },
            bytes: std::mem::take(bytes),
        }),
        (None, None) => None,
        _ => return Err(invalid("portrait without format")),
    };
    Ok(ChipRead {
        mrz: parse_lines(&r.mrz.lines)?,
        portrait,
        status: match r.status {
            FfiChipStatus::Verified => ChipStatus::Verified,
            FfiChipStatus::Unverifiable => ChipStatus::Unverifiable,
            FfiChipStatus::Invalid => ChipStatus::Invalid,
        },
        progress_files: Vec::new(),
    })
}

/// The next move of the transport. One per APDU, moved across the FFI,
/// never stored in bulk: no box for `Done`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiIcaoStep {
    /// Send this command APDU and pass the chip's answer (data and status
    /// word) to `on_response`.
    Send {
        apdu: Vec<u8>,
    },
    Done {
        read: FfiChipRead,
    },
    Failed {
        reason: FfiIcaoFailure,
    },
}

fn failure(e: IcaoError) -> FfiIcaoFailure {
    match e {
        IcaoError::AccessDenied | IcaoError::BadMac => FfiIcaoFailure::AccessDenied,
        IcaoError::NoChip => FfiIcaoFailure::NoChip,
        // The session falls back to BAC: kept for completeness.
        IcaoError::Protocol("pace-unsupported") => FfiIcaoFailure::Unsupported,
        IcaoError::Protocol(_) | IcaoError::Crypto | IcaoError::Chip(_) => FfiIcaoFailure::Other,
    }
}

fn step_to_ffi(step: Step) -> FfiIcaoStep {
    match step {
        Step::Send(apdu) => FfiIcaoStep::Send { apdu },
        Step::Done(mut read) => FfiIcaoStep::Done {
            read: read_to_ffi(&mut read),
        },
        Step::Failed(e) => FfiIcaoStep::Failed { reason: failure(e) },
    }
}

/// One chip read: `start`, then `on_response` with each answer until `Done`
/// or `Failed`. Make a new one to read again (after a lost contact).
#[derive(uniffi::Object)]
pub struct FfiIcaoSession {
    inner: Mutex<IcaoSession>,
}

impl fmt::Debug for FfiIcaoSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FfiIcaoSession(..)")
    }
}

impl FfiIcaoSession {
    fn build(
        mrz_lines: &[String],
        master_list: MasterList,
        today: Date,
    ) -> Result<IcaoSession, OnePassError> {
        let mrz = parse_lines(mrz_lines)?;
        Ok(IcaoSession::new(AccessKey::Mrz(mrz), master_list, today))
    }

    fn strict(master_list: &[u8]) -> Result<MasterList, OnePassError> {
        load_master_list(master_list).map_err(|_| invalid("master list"))
    }

    fn wrap(session: IcaoSession) -> Arc<Self> {
        Arc::new(FfiIcaoSession {
            inner: Mutex::new(session),
        })
    }

    fn lock(&self) -> MutexGuard<'_, IcaoSession> {
        // A panic inside the core never leaves the session half written in a
        // way that matters more than the error the next step reports.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[uniffi::export]
impl FfiIcaoSession {
    /// A session for the document of these MRZ lines, its signatures checked
    /// against this CSCA master list (CMS, ICAO 9303-12) at today's date.
    #[uniffi::constructor]
    pub fn new(mrz_lines: Vec<String>, master_list: Vec<u8>) -> Result<Arc<Self>, OnePassError> {
        let ml = Self::strict(&master_list)?;
        let session = Self::build(&mrz_lines, ml, OffsetDateTime::now_utc().date())?;
        Ok(Self::wrap(session))
    }

    /// As `new`, for a master list the app ships whose signer chain the core
    /// cannot verify (the BSI list): its bytes must hash to
    /// `master_list_sha256` (32 bytes), the list signer is not checked.
    #[uniffi::constructor]
    pub fn new_pinned(
        mrz_lines: Vec<String>,
        master_list: Vec<u8>,
        master_list_sha256: Vec<u8>,
    ) -> Result<Arc<Self>, OnePassError> {
        let pin: [u8; 32] = master_list_sha256
            .try_into()
            .map_err(|_| invalid("master list digest"))?;
        let ml = load_master_list_pinned(&master_list, &pin).map_err(|_| invalid("master list"))?;
        let session = Self::build(&mrz_lines, ml, OffsetDateTime::now_utc().date())?;
        Ok(Self::wrap(session))
    }

    /// The first command.
    pub fn start(&self) -> FfiIcaoStep {
        step_to_ffi(self.lock().start())
    }

    /// The chip's answer to the last `Send`.
    pub fn on_response(&self, bytes: Vec<u8>) -> FfiIcaoStep {
        step_to_ffi(self.lock().on_response(&bytes))
    }

    /// 0 to 1, in proportion to the bytes of the files read.
    pub fn progress(&self) -> f32 {
        self.lock().progress()
    }
}

/// Fixed terminal randoms of a replayable read (test builds only).
#[cfg(feature = "scan-test-rng")]
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiIcaoTestRandom {
    pub bac_rnd_ifd: Vec<u8>,
    pub bac_k_ifd: Vec<u8>,
    pub pace_map_sk: Vec<u8>,
    pub pace_eph_sk: Vec<u8>,
}

#[cfg(feature = "scan-test-rng")]
fn parse_date(s: &str) -> Option<Date> {
    let mut parts = s.split('-');
    let y = parts.next()?.parse().ok()?;
    let m: u8 = parts.next()?.parse().ok()?;
    let d = parts.next()?.parse().ok()?;
    Date::from_calendar_date(y, time::Month::try_from(m).ok()?, d).ok()
}

/// Test builds only (`scan-test-rng`, never shipped): a session with fixed
/// randoms and date, so a recorded read replays byte for byte.
#[cfg(feature = "scan-test-rng")]
#[uniffi::export]
impl FfiIcaoSession {
    #[uniffi::constructor]
    pub fn new_replayable(
        mrz_lines: Vec<String>,
        master_list: Vec<u8>,
        today: String,
        random: FfiIcaoTestRandom,
    ) -> Result<Arc<Self>, OnePassError> {
        use onepass_core::scan::icao::session::SessionRandom;
        let today = parse_date(&today).ok_or_else(|| invalid("today"))?;
        let rng = SessionRandom {
            bac_rnd_ifd: random
                .bac_rnd_ifd
                .try_into()
                .map_err(|_| invalid("bac_rnd_ifd"))?,
            bac_k_ifd: random
                .bac_k_ifd
                .try_into()
                .map_err(|_| invalid("bac_k_ifd"))?,
            pace_map_sk: random.pace_map_sk,
            pace_eph_sk: random.pace_eph_sk,
        };
        let ml = Self::strict(&master_list)?;
        let session = Self::build(&mrz_lines, ml, today)?.with_rng(rng);
        Ok(Self::wrap(session))
    }
}

/// A conflict of a merge: the stored value (a user edit, kept) and the one
/// the chip holds. `Debug` omits both values.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiFieldConflict {
    pub field_id: String,
    pub stored: String,
    pub scanned: String,
}

impl fmt::Debug for FfiFieldConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfiFieldConflict")
            .field("field_id", &self.field_id)
            .finish_non_exhaustive()
    }
}

/// The merged item (not stored until `save_item`) and its conflicts.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiChipMerge {
    pub item: FfiItem,
    pub conflicts: Vec<FfiFieldConflict>,
}

#[uniffi::export]
impl Session {
    /// A new passport item from a chip read, in this vault. Not stored until
    /// `save_item`; the portrait is not in it (the app attaches it).
    pub fn item_from_chip(
        &self,
        vault_id: String,
        mut read: FfiChipRead,
    ) -> Result<FfiItem, OnePassError> {
        let vault_id = parse_id(&vault_id)?;
        let read = read_to_core(&mut read)?;
        let today = OffsetDateTime::now_utc().date();
        self.with(|repo| {
            find_vault(repo, vault_id)?;
            Ok(item_to_ffi(&chip_read_to_item(&read, vault_id, today)))
        })
    }

    /// A later read merged into a passport item (spec 6.1): blank identity
    /// fields filled, user edits kept and reported as conflicts, chip fields
    /// refreshed. `take_scanned`: the conflicts (field ids) settled for the
    /// chip, which take its value; while any conflict keeps the stored value,
    /// the chip status is cleared. Not stored until `save_item`.
    pub fn merge_chip(
        &self,
        item: FfiItem,
        mut read: FfiChipRead,
        take_scanned: Vec<String>,
    ) -> Result<FfiChipMerge, OnePassError> {
        let (vault_id, item_id) = (parse_id(&item.vault_id)?, parse_id(&item.id)?);
        let read = read_to_core(&mut read)?;
        let now = OffsetDateTime::now_utc();
        self.with(|repo| {
            let vault = find_vault(repo, vault_id)?;
            let stored = repo.items(&vault)?.into_iter().find(|i| i.id == item_id);
            let core = item_to_core(&item, &Kept::new(stored.as_ref(), false), now)?;
            let (merged, conflicts) = merge_chip_read(&core, &read, now.date(), &take_scanned)?;
            Ok(FfiChipMerge {
                item: item_to_ffi(&merged),
                conflicts: conflicts
                    .into_iter()
                    .map(|c| FfiFieldConflict {
                        field_id: c.field_id,
                        stored: c.stored,
                        scanned: c.scanned,
                    })
                    .collect(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const L1: &str = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
    const L2: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";

    /// The portrait moves between the core and the FFI read, never copied:
    /// the side it left holds no bytes (the core side wipes on drop).
    #[test]
    fn portrait_bytes_move_without_a_copy() {
        let mut core = ChipRead {
            mrz: parse_td3(&[L1, L2]).unwrap(),
            portrait: Some(Portrait {
                format: ImageFormat::Jpeg,
                bytes: vec![0xFF, 0xD8, 0xFF, 0x01],
            }),
            status: ChipStatus::Verified,
            progress_files: Vec::new(),
        };
        let mut ffi = read_to_ffi(&mut core);
        assert_eq!(ffi.portrait.as_deref(), Some(&[0xFF, 0xD8, 0xFF, 0x01][..]));
        assert!(core.portrait.as_ref().unwrap().bytes.is_empty());
        let back = read_to_core(&mut ffi).unwrap();
        assert_eq!(
            back.portrait.as_ref().unwrap().bytes,
            [0xFF, 0xD8, 0xFF, 0x01]
        );
        assert_eq!(ffi.portrait.as_deref(), Some(&[][..]));
    }
}
