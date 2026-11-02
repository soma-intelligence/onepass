//! The accounts of one device (multi-account spec 2026-11-02, section 4).
//!
//! One account is one store file, one keyset, one Secret Key: this module
//! never touches a key. It keeps the device's account directory, a small
//! plaintext file next to the primary store (`accounts.json`) that lists
//! the accounts the apps can open, their kind, label, color and work
//! domains, and which one is shown. It holds no secret (spec M6), and a
//! store path is always derived from a slot, never read from the file
//! (M7).
//!
//! A device with one account has no directory file: `load` returns the
//! implicit directory (the primary account alone), and nothing is written
//! until a second account is added.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};

use crate::crypto::random_array;
use crate::{Error, Id, Result};

/// The directory file, in the primary store's folder.
pub const DIRECTORY_FILE: &str = "accounts.json";
/// The folder of the added accounts' stores, in the primary store's folder.
pub const ACCOUNTS_FOLDER: &str = "accounts";
/// The store file name, for every account.
pub const STORE_FILE: &str = "vault.sqlite";
/// The slot of the account the device had before any other was added.
pub const PRIMARY_SLOT: &str = "primary";
/// Accounts on one device at most (ruling P9).
pub const MAX_ACCOUNTS: usize = 8;
/// Work domains of one account at most.
pub const MAX_WORK_DOMAINS: usize = 32;
/// Label length at most, in characters.
pub const MAX_LABEL_CHARS: usize = 64;
const MAX_SERVER_URL: usize = 2048;
const VERSION: u32 = 1;

/// Where an account lives on this device: `primary`, or 32 lowercase hex
/// characters (16 random bytes). Never a path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Slot(String);

impl Slot {
    pub fn primary() -> Slot {
        Slot(PRIMARY_SLOT.to_owned())
    }

    /// A new random slot.
    pub fn generate() -> Result<Slot> {
        Ok(Slot(HEXLOWER.encode(&random_array::<16>()?)))
    }

    pub fn parse(text: &str) -> Result<Slot> {
        let ok = text == PRIMARY_SLOT
            || (text.len() == 32
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        if ok {
            Ok(Slot(text.to_owned()))
        } else {
            Err(Error::InvalidFormat("account slot"))
        }
    }

    pub fn is_primary(&self) -> bool {
        self.0 == PRIMARY_SLOT
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Slot {
    type Error = Error;

    fn try_from(value: String) -> Result<Slot> {
        Slot::parse(&value)
    }
}

impl From<Slot> for String {
    fn from(slot: Slot) -> String {
        slot.0
    }
}

/// The profile type of an account (spec 3). It changes the look and the
/// AutoFill defaults, never a cryptographic rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AccountKind {
    Personal,
    /// A business account the user runs (own keys, own iCloud zone).
    Business,
    /// An account managed by an organisation (enterprise spec E1): its
    /// records live on the organisation's server.
    Managed {
        server_url: String,
        org_id: Id,
    },
}

/// The account's color, from a fixed palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountColor {
    Blue,
    Green,
    Orange,
    Purple,
    Pink,
    Teal,
    Indigo,
    Graphite,
}

impl AccountColor {
    /// The default color of a kind.
    pub fn default_for(kind: &AccountKind) -> AccountColor {
        match kind {
            AccountKind::Personal => AccountColor::Blue,
            AccountKind::Business => AccountColor::Orange,
            AccountKind::Managed { .. } => AccountColor::Indigo,
        }
    }
}

/// One account of the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    pub slot: Slot,
    /// The account the slot's store holds, bound at its creation or
    /// restore (M4). `None` while it is being added.
    pub account_id: Option<Id>,
    pub kind: AccountKind,
    /// Empty for the implicit primary account (the apps show the profile
    /// name).
    pub label: String,
    pub color: AccountColor,
    /// Hosts this account answers AutoFill for, with their subdomains.
    pub work_domains: Vec<String>,
    /// Unix seconds.
    pub created_at: i64,
}

/// The accounts of the device, primary first, in display order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDirectory {
    pub version: u32,
    /// The account shown at launch.
    pub active: Slot,
    /// The user chose the "All accounts" search (spec 7, ruling P4).
    pub unified_search: bool,
    pub entries: Vec<AccountEntry>,
}

impl AccountDirectory {
    /// The directory of a device with one account (no file).
    pub fn implicit() -> AccountDirectory {
        AccountDirectory {
            version: VERSION,
            active: Slot::primary(),
            unified_search: false,
            entries: vec![AccountEntry {
                slot: Slot::primary(),
                account_id: None,
                kind: AccountKind::Personal,
                label: String::new(),
                color: AccountColor::Blue,
                work_domains: Vec::new(),
                created_at: 0,
            }],
        }
    }

    /// The directory of `folder` (the primary store's folder): the file,
    /// or the implicit directory when there is none. A file that does not
    /// parse or validate is `InvalidFormat("account directory")`.
    pub fn load(folder: &Path) -> Result<AccountDirectory> {
        let path = folder.join(DIRECTORY_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AccountDirectory::implicit());
            }
            Err(_) => return Err(Error::Store("account directory read".into())),
        };
        let directory: AccountDirectory = serde_json::from_slice(&bytes)
            .map_err(|_| Error::InvalidFormat("account directory"))?;
        directory
            .validate()
            .map_err(|_| Error::InvalidFormat("account directory"))?;
        Ok(directory)
    }

    /// Writes the whole file atomically: a temporary file in the same
    /// folder, flushed, then renamed over the old one.
    pub fn save(&self, folder: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| Error::InvalidFormat("account directory"))?;
        fs::create_dir_all(folder).map_err(|_| Error::Store("account directory folder".into()))?;
        let tmp = folder.join(format!(
            ".{DIRECTORY_FILE}.{}.tmp",
            HEXLOWER.encode(&random_array::<8>()?)
        ));
        let write = || -> std::io::Result<()> {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&tmp, folder.join(DIRECTORY_FILE))
        };
        write().map_err(|_| {
            let _ = fs::remove_file(&tmp);
            Error::Store("account directory write".into())
        })
    }

    /// Every rule of spec section 4.
    pub fn validate(&self) -> Result<()> {
        if self.version != VERSION {
            return Err(Error::InvalidFormat("account directory version"));
        }
        if self.entries.is_empty() || self.entries.len() > MAX_ACCOUNTS {
            return Err(Error::InvalidFormat("account count"));
        }
        if !self.entries[0].slot.is_primary() {
            return Err(Error::InvalidFormat("primary account first"));
        }
        let mut slots = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut domains = std::collections::BTreeSet::new();
        for (i, entry) in self.entries.iter().enumerate() {
            if i > 0 && entry.slot.is_primary() {
                return Err(Error::InvalidFormat("primary account first"));
            }
            if !slots.insert(entry.slot.clone()) {
                return Err(Error::InvalidFormat("duplicate account slot"));
            }
            if let Some(id) = entry.account_id
                && !ids.insert(id)
            {
                return Err(Error::Conflict);
            }
            if !(entry.slot.is_primary() && entry.label.is_empty()) {
                check_label(&entry.label)?;
            }
            check_kind(&entry.kind)?;
            if entry.work_domains.len() > MAX_WORK_DOMAINS {
                return Err(Error::InvalidFormat("work domain count"));
            }
            for domain in &entry.work_domains {
                if normalize_domain(domain)? != *domain {
                    return Err(Error::InvalidFormat("work domain"));
                }
                if !domains.insert(domain.clone()) {
                    return Err(Error::InvalidFormat("work domain claimed twice"));
                }
            }
        }
        if !slots.contains(&self.active) {
            return Err(Error::InvalidFormat("active account"));
        }
        Ok(())
    }

    pub fn entry(&self, slot: &Slot) -> Option<&AccountEntry> {
        self.entries.iter().find(|e| &e.slot == slot)
    }

    fn entry_mut(&mut self, slot: &Slot) -> Result<&mut AccountEntry> {
        self.entries
            .iter_mut()
            .find(|e| &e.slot == slot)
            .ok_or(Error::NotFound)
    }

    /// A new account in a new random slot, at the end, not bound yet. The
    /// managed kind is accepted here: whether a server can hold it is the
    /// apps' call (spec 3.1).
    pub fn add(
        &mut self,
        kind: AccountKind,
        label: &str,
        color: AccountColor,
        now: i64,
    ) -> Result<Slot> {
        if self.entries.len() >= MAX_ACCOUNTS {
            return Err(Error::InvalidFormat("account count"));
        }
        let label = label.trim();
        check_label(label)?;
        check_kind(&kind)?;
        let slot = loop {
            let slot = Slot::generate()?;
            if self.entry(&slot).is_none() {
                break slot;
            }
        };
        self.entries.push(AccountEntry {
            slot: slot.clone(),
            account_id: None,
            kind,
            label: label.to_owned(),
            color,
            work_domains: Vec::new(),
            created_at: now,
        });
        Ok(slot)
    }

    /// Binds the account a slot's store holds (M4, M5): an account bound
    /// to another slot is `Conflict`, and so is changing a slot's binding.
    /// Binding the same id again is a no-op.
    pub fn bind(&mut self, slot: &Slot, account_id: Id) -> Result<()> {
        if self
            .entries
            .iter()
            .any(|e| &e.slot != slot && e.account_id == Some(account_id))
        {
            return Err(Error::Conflict);
        }
        let entry = self.entry_mut(slot)?;
        match entry.account_id {
            Some(bound) if bound != account_id => Err(Error::Conflict),
            _ => {
                entry.account_id = Some(account_id);
                Ok(())
            }
        }
    }

    /// The store of `slot` may be opened: its account is the one bound to
    /// the slot, or the slot is not bound yet (M4). Another account is
    /// `Conflict`.
    pub fn check_binding(&self, slot: &Slot, store_account: Option<Id>) -> Result<()> {
        let entry = self.entry(slot).ok_or(Error::NotFound)?;
        match (entry.account_id, store_account) {
            (Some(bound), Some(found)) if bound != found => Err(Error::Conflict),
            _ => Ok(()),
        }
    }

    /// Renames, recolors and sets the work domains of an account. The
    /// domains are normalized, deduplicated and must not be claimed by
    /// another account. A primary account may keep an empty label.
    pub fn update(
        &mut self,
        slot: &Slot,
        label: &str,
        color: AccountColor,
        work_domains: &[String],
    ) -> Result<()> {
        let label = label.trim();
        if !(slot.is_primary() && label.is_empty()) {
            check_label(label)?;
        }
        if work_domains.len() > MAX_WORK_DOMAINS {
            return Err(Error::InvalidFormat("work domain count"));
        }
        let mut domains: Vec<String> = Vec::new();
        for domain in work_domains {
            let domain = normalize_domain(domain)?;
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
        for other in self.entries.iter().filter(|e| &e.slot != slot) {
            if other.work_domains.iter().any(|d| domains.contains(d)) {
                return Err(Error::InvalidFormat("work domain claimed twice"));
            }
        }
        let entry = self.entry_mut(slot)?;
        entry.label = label.to_owned();
        entry.color = color;
        entry.work_domains = domains;
        Ok(())
    }

    /// Takes an added account out of the directory. The primary account is
    /// never removed (`InvalidFormat`); the active account falls back to
    /// the primary one. The caller erases the slot's files and keychain
    /// entries (M8).
    pub fn remove(&mut self, slot: &Slot) -> Result<AccountEntry> {
        if slot.is_primary() {
            return Err(Error::InvalidFormat("primary account"));
        }
        let index = self
            .entries
            .iter()
            .position(|e| &e.slot == slot)
            .ok_or(Error::NotFound)?;
        let entry = self.entries.remove(index);
        if &self.active == slot {
            self.active = Slot::primary();
        }
        Ok(entry)
    }

    pub fn set_active(&mut self, slot: &Slot) -> Result<()> {
        self.entry(slot).ok_or(Error::NotFound)?;
        self.active = slot.clone();
        Ok(())
    }

    /// Moves an account to `index` among the added ones (the primary stays
    /// first).
    pub fn reorder(&mut self, slot: &Slot, index: usize) -> Result<()> {
        if slot.is_primary() {
            return Err(Error::InvalidFormat("primary account"));
        }
        let from = self
            .entries
            .iter()
            .position(|e| &e.slot == slot)
            .ok_or(Error::NotFound)?;
        let entry = self.entries.remove(from);
        let to = index.clamp(1, self.entries.len());
        self.entries.insert(to, entry);
        Ok(())
    }

    /// The account AutoFill uses for `host` (spec 8, ruling P5): the one
    /// whose work domain is the host or a parent of it on a label
    /// boundary, the longest domain winning; otherwise the primary one.
    pub fn route(&self, host: &str) -> Slot {
        let Ok(host) = normalize_host(host) else {
            return Slot::primary();
        };
        let mut best: Option<(&Slot, usize)> = None;
        for entry in &self.entries {
            for domain in &entry.work_domains {
                let matches = host == *domain
                    || (host.len() > domain.len()
                        && host.ends_with(domain.as_str())
                        && host.as_bytes()[host.len() - domain.len() - 1] == b'.');
                if matches && best.is_none_or(|(_, len)| domain.len() > len) {
                    best = Some((&entry.slot, domain.len()));
                }
            }
        }
        best.map(|(slot, _)| slot.clone())
            .unwrap_or_else(Slot::primary)
    }
}

/// The store file of `slot` under the primary store's `folder` (M7): the
/// primary store keeps its path; an added account has its own folder.
pub fn store_path(folder: &Path, slot: &Slot) -> PathBuf {
    if slot.is_primary() {
        folder.join(STORE_FILE)
    } else {
        folder
            .join(ACCOUNTS_FOLDER)
            .join(slot.as_str())
            .join(STORE_FILE)
    }
}

fn check_label(label: &str) -> Result<()> {
    let chars = label.chars().count();
    if chars == 0 || chars > MAX_LABEL_CHARS || label.chars().any(char::is_control) {
        return Err(Error::InvalidFormat("account label"));
    }
    if label.trim() != label {
        return Err(Error::InvalidFormat("account label"));
    }
    Ok(())
}

fn check_kind(kind: &AccountKind) -> Result<()> {
    if let AccountKind::Managed { server_url, .. } = kind {
        let ok = server_url.len() <= MAX_SERVER_URL
            && server_url.starts_with("https://")
            && server_url.len() > "https://".len()
            && !server_url
                .chars()
                .any(|c| c.is_control() || c.is_whitespace());
        if !ok {
            return Err(Error::InvalidFormat("organisation server"));
        }
    }
    Ok(())
}

/// A host as typed or as the system gives it: lowercase ASCII, no
/// trailing dot, labels of letters, digits and hyphens. Non-ASCII hosts
/// come as punycode (`xn--`).
fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(Error::InvalidFormat("host"));
    }
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(Error::InvalidFormat("host"));
        }
    }
    Ok(host)
}

/// A work domain: a host of at least two labels whose last label is not
/// all digits (no top-level domain alone, no IP address, no wildcard).
pub fn normalize_domain(domain: &str) -> Result<String> {
    let domain = normalize_host(domain).map_err(|_| Error::InvalidFormat("work domain"))?;
    let labels: Vec<&str> = domain.split('.').collect();
    let last = labels.last().copied().unwrap_or_default();
    if labels.len() < 2 || last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidFormat("work domain"));
    }
    Ok(domain)
}
