//! Wi-Fi profiles of the operating system, for `onepass wifi`.
//!
//! [`Backend`] is what the CLI needs from a system: list the saved Wi-Fi
//! profiles (no secret), read one with its key, add, update and remove
//! profiles. [`windows::Netsh`] drives `netsh wlan` (per-user profiles, no
//! administrator), [`linux::NetworkManager`] talks to NetworkManager over
//! the system D-Bus, and [`fake::FileBackend`] stands in for both in tests.
//!
//! [`state::State`] is what was applied last, kept in the user's
//! configuration directory without any secret. [`agent`] installs the
//! login item that runs `onepass wifi watch`.
//!
//! Passwords never appear on a command line (the process list is readable
//! by other users), in an error message or in a `Debug` output.

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

use zeroize::Zeroizing;

pub mod agent;
pub mod exec;
pub mod fake;
pub mod linux;
pub mod state;
pub mod windows;

/// A failure, with a message that never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiError(pub String);

impl fmt::Display for WifiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WifiError {}

impl WifiError {
    pub fn new(msg: impl Into<String>) -> WifiError {
        WifiError(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, WifiError>;

/// Key management of a personal network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// WPA2 personal, pre-shared key.
    Wpa2Psk,
    /// WPA3 personal, SAE.
    Wpa3Sae,
}

/// A personal network as the system stores it.
#[derive(Clone, PartialEq, Eq)]
pub struct OsNetwork {
    pub ssid: String,
    pub psk: Zeroizing<String>,
    pub auth: Auth,
    pub hidden: bool,
}

impl fmt::Debug for OsNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsNetwork")
            .field("ssid", &self.ssid)
            .field("psk", &"[redacted]")
            .field("auth", &self.auth)
            .field("hidden", &self.hidden)
            .finish()
    }
}

/// A saved Wi-Fi profile, without its key: the system's reference
/// (Windows profile name, NetworkManager connection UUID) and its SSID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Profile {
    pub os_ref: String,
    pub ssid: String,
}

/// What reading a profile with its key gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    /// A personal network with its key.
    Personal(OsNetwork),
    /// Open, WEP or enterprise: never imported.
    NotPersonal,
    /// The system refused the key (rights, prompt dismissed) or the
    /// output could not be read.
    Unavailable,
}

/// The Wi-Fi profiles of a system.
pub trait Backend {
    /// Every saved Wi-Fi profile, without keys.
    fn list(&mut self) -> Result<Vec<Profile>>;
    /// One profile with its key.
    fn read(&mut self, profile: &Profile) -> Result<Read>;
    /// Save `net` as a new profile of the current user, joined
    /// automatically. Returns the system reference of the profile.
    fn add(&mut self, net: &OsNetwork) -> Result<String>;
    /// Replace the profile `os_ref` (made by [`Backend::add`]) with `net`.
    /// Returns the reference, which may change.
    fn update(&mut self, os_ref: &str, net: &OsNetwork) -> Result<String>;
    /// Delete the profile `os_ref`.
    fn remove(&mut self, os_ref: &str) -> Result<()>;
}
